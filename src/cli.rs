//! Command-line interface.

use std::path::PathBuf;

use clap::{ArgAction, Parser, ValueEnum};

use crate::audit::Options;
use crate::config::{parse_gpg_time, parse_ssh_time, Config};
use crate::report::Format;

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum OutputFormat {
    Human,
    Json,
    Junit,
    Sarif,
}

impl From<OutputFormat> for Format {
    fn from(f: OutputFormat) -> Format {
        match f {
            OutputFormat::Human => Format::Human,
            OutputFormat::Json => Format::Json,
            OutputFormat::Junit => Format::Junit,
            OutputFormat::Sarif => Format::Sarif,
        }
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "sigaudit",
    version,
    about = "Audit commit signatures (OpenPGP and SSH) across git branches",
    long_about = "Reads git objects directly and reports, per branch, which commits are unsigned, \
have invalid signatures, or are signed by keys that are not allowed.\n\n\
Signatures are verified the way git verifies them: OpenPGP via gpg, SSH via ssh-keygen \
against gpg.ssh.allowedSignersFile. Each signature is judged against its own commit time, so \
keys that expired or were revoked later do not retroactively invalidate old history.",
    after_help = "EXIT CODES:\n  0  every audited object passed\n  1  at least one audited object failed\n  2  usage or environment error\n  3  internal error"
)]
pub struct Cli {
    /// Repository to audit (defaults to the current directory).
    #[arg(long, short = 'C', value_name = "PATH", default_value = ".")]
    pub repo: PathBuf,

    /// Branch to audit; repeatable, globs allowed (default: all local and
    /// remote-tracking branches).
    #[arg(long = "branch", short = 'b', value_name = "GLOB")]
    pub branches: Vec<String>,

    /// Also audit annotated tags.
    #[arg(long)]
    pub tags: bool,

    /// Also audit commits not reachable from any selected branch (pre-rebase
    /// history, detached work).
    #[arg(long)]
    pub unreachable: bool,

    /// Only audit the newest N commits per branch.
    #[arg(long, value_name = "N", default_value_t = 0)]
    pub max_commits: usize,

    /// Output format.
    #[arg(long, short = 'f', value_enum, default_value_t = OutputFormat::Human)]
    pub format: OutputFormat,

    /// Write the report to this file instead of stdout.
    #[arg(long, short = 'o', value_name = "PATH")]
    pub output: Option<PathBuf>,

    /// Print only the summary (no per-commit failure list).
    #[arg(long, short = 'q')]
    pub quiet: bool,

    /// Fail (exit 1) only on these verdicts; repeatable. Default: any failure.
    #[arg(long = "fail-on", value_name = "VERDICT", action = ArgAction::Append)]
    pub fail_on: Vec<String>,

    /// OpenPGP key-validity reference time: `committer` (default), `signature`,
    /// or `now`.
    #[arg(long, value_name = "MODE")]
    pub gpg_time: Option<String>,

    /// SSH allowed_signers validity reference time: `committer` (default) or
    /// `now`.
    #[arg(long, value_name = "MODE")]
    pub ssh_time: Option<String>,

    /// OpenSSH allowed_signers file (overrides gpg.ssh.allowedSignersFile).
    #[arg(long, value_name = "PATH")]
    pub allowed_signers: Option<PathBuf>,

    /// OpenSSH revocation (KRL) file (overrides gpg.ssh.revocationFile).
    #[arg(long, value_name = "PATH")]
    pub revocation_file: Option<PathBuf>,

    /// gpg program to run (overrides gpg.program).
    #[arg(long, value_name = "PROG")]
    pub gpg_program: Option<String>,

    /// gpg home directory (overrides GNUPGHOME).
    #[arg(long, value_name = "DIR")]
    pub gpg_home: Option<PathBuf>,

    /// Minimum trust level for an OpenPGP signature to count as good
    /// (undefined, never, marginal, fully, ultimate).
    #[arg(long, value_name = "LEVEL")]
    pub min_trust_level: Option<String>,

    /// Verification threads (default: available parallelism).
    #[arg(long, value_name = "N", default_value_t = 0)]
    pub jobs: usize,
}

impl Cli {
    /// Layer CLI values over repository config.
    pub fn build_config(&self, repo: &git2::Repository) -> Result<Config, String> {
        let mut config = Config::from_repository(repo);

        if let Some(path) = &self.allowed_signers {
            config.allowed_signers = Some(path.clone());
        }
        if let Some(path) = &self.revocation_file {
            config.revocation_file = Some(path.clone());
        }
        if let Some(program) = &self.gpg_program {
            config.gpg_program = program.clone();
        }
        if let Some(home) = &self.gpg_home {
            config.gpg_home = Some(home.clone());
        }
        if let Some(level) = &self.min_trust_level {
            config.min_trust_level = Some(
                crate::config::parse_trust(level)
                    .ok_or_else(|| format!("invalid --min-trust-level: {level}"))?,
            );
        }
        if let Some(mode) = &self.gpg_time {
            config.gpg_time_mode =
                parse_gpg_time(mode).ok_or_else(|| format!("invalid --gpg-time: {mode}"))?;
        }
        if let Some(mode) = &self.ssh_time {
            config.ssh_time_mode =
                parse_ssh_time(mode).ok_or_else(|| format!("invalid --ssh-time: {mode}"))?;
        }
        Ok(config)
    }

    pub fn build_options(&self) -> Options {
        Options {
            branches: self.branches.clone(),
            include_tags: self.tags,
            include_unreachable: self.unreachable,
            max_commits: self.max_commits,
            jobs: self.jobs,
        }
    }

    /// Whether the report should be treated as an audit failure.
    ///
    /// `--fail-on` narrows the set; without it any failing verdict fails the
    /// run, which is what a "all commits must be signed" gate wants.
    pub fn is_failure(&self, report: &crate::model::Report) -> bool {
        if self.fail_on.is_empty() {
            return report.summary.failures > 0;
        }
        let wanted: Vec<crate::model::Verdict> = self
            .fail_on
            .iter()
            .filter_map(|v| parse_verdict(v))
            .collect();
        report.records.iter().any(|r| wanted.contains(&r.verdict))
    }
}

fn parse_verdict(value: &str) -> Option<crate::model::Verdict> {
    use crate::model::Verdict::*;
    match value.to_ascii_lowercase().replace('-', "_").as_str() {
        "good" => Some(Good),
        "unsigned" => Some(Unsigned),
        "bad_signature" | "bad" => Some(BadSignature),
        "unknown_key" | "unknown" => Some(UnknownKey),
        "signer_not_allowed" | "not_allowed" | "unauthorised" | "unauthorized" => {
            Some(SignerNotAllowed)
        }
        "key_expired_at_commit" | "expired" => Some(KeyExpiredAtCommit),
        "key_revoked_at_commit" | "revoked" => Some(KeyRevokedAtCommit),
        "error" => Some(Error),
        _ => None,
    }
}

pub fn write_output(path: Option<&std::path::Path>, contents: &str) -> std::io::Result<()> {
    match path {
        Some(path) => std::fs::write(path, contents),
        None => {
            use std::io::Write;
            let stdout = std::io::stdout();
            let mut lock = stdout.lock();
            lock.write_all(contents.as_bytes())?;
            lock.flush()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdict_names_are_forgiving() {
        assert_eq!(
            parse_verdict("unsigned"),
            Some(crate::model::Verdict::Unsigned)
        );
        assert_eq!(
            parse_verdict("signer-not-allowed"),
            Some(crate::model::Verdict::SignerNotAllowed)
        );
        assert_eq!(parse_verdict("bogus"), None);
    }

    #[test]
    fn format_aliases_parse() {
        assert_eq!(Format::parse("junit"), Some(Format::Junit));
        assert_eq!(Format::parse("JUnit-XML"), Some(Format::Junit));
        assert_eq!(Format::parse("sarif"), Some(Format::Sarif));
        assert_eq!(Format::parse("nope"), None);
    }
}
