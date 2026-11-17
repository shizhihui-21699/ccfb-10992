//! `commit-signature-audit` — audit commit signatures straight from git objects.

mod audit;
mod gitparse;
mod gpg;
mod report;
mod repo;
mod ssh;
mod types;

use anyhow::{anyhow, Context, Result};
use clap::{ArgAction, Parser, ValueEnum};
use std::path::PathBuf;
use std::process::ExitCode;

use audit::{Auditor, FormatMode, Verifiers};
use gpg::{GpgConfig, TrustLevel};
use repo::{RefSpec, WalkOptions};
use ssh::SshConfig;

#[derive(Debug, Parser)]
#[command(
    name = "commit-signature-audit",
    version,
    about = "Audit commit signatures (OpenPGP and SSH) directly from git objects",
    long_about = "Walks the commit graph of each selected branch, verifies every commit's gpgsig \
                  header with gpg or ssh-keygen, and reports unsigned, invalid and disallowed \
                  commits.\n\nKey validity (expiry and revocation) is judged as of the commit's \
                  own committer timestamp rather than the current time, so old history is not \
                  retroactively condemned by later key expiry or revocation."
)]
struct Cli {
    /// Repository to audit (defaults to the current directory).
    #[arg(long, short = 'C', default_value = ".", value_name = "PATH")]
    repo: PathBuf,

    /// Branch glob, repeatable (default `*`).
    #[arg(long = "branch", value_name = "GLOB", action = ArgAction::Append)]
    branches: Vec<String>,

    /// Also audit remote-tracking branches under refs/remotes.
    #[arg(long)]
    remotes: bool,

    /// Audit an arbitrary ref or commit id, repeatable.
    #[arg(long = "ref", value_name = "REF", action = ArgAction::Append)]
    refs: Vec<String>,

    /// Only follow first parents (ignores merged-in history).
    #[arg(long)]
    first_parent: bool,

    /// Leave merge commits out of the per-branch counts.
    #[arg(long)]
    skip_merges: bool,

    /// Stop after this many commits per branch.
    #[arg(long, value_name = "N")]
    max_commits: Option<usize>,

    /// Only audit commits at or after this time (epoch or YYYY-MM-DD).
    #[arg(long, value_name = "TIME")]
    since: Option<String>,

    /// Only audit commits at or before this time (epoch or YYYY-MM-DD).
    #[arg(long, value_name = "TIME")]
    until: Option<String>,

    /// `allowed_signers` file for SSH signatures.
    #[arg(long, value_name = "PATH", alias = "allowedSignersFile")]
    allowed_signers: Option<PathBuf>,

    /// gpg home directory (keyring location).
    #[arg(long, value_name = "PATH")]
    gpg_home: Option<PathBuf>,

    /// Additional gpg keyring file, repeatable.
    #[arg(long = "keyring", value_name = "PATH", action = ArgAction::Append)]
    keyrings: Vec<PathBuf>,

    /// Additional OpenPGP keyring file used only for trust (same as --keyring).
    #[arg(long = "openpgp-keyring", value_name = "PATH", action = ArgAction::Append, hide = true)]
    openpgp_keyrings: Vec<PathBuf>,

    /// gpg program to run.
    #[arg(long, default_value = "gpg", value_name = "PATH")]
    gpg_program: PathBuf,

    /// ssh-keygen program to run.
    #[arg(long, default_value = "ssh-keygen", value_name = "PATH")]
    ssh_program: PathBuf,

    /// Minimum OpenPGP trust level.
    #[arg(long, value_name = "LEVEL", default_value = "undefined")]
    min_trust: String,

    /// Require OpenPGP signatures to come from one of these fingerprints/key ids.
    #[arg(long = "trusted-fingerprint", value_name = "FPR", action = ArgAction::Append)]
    trusted_fingerprints: Vec<String>,

    /// Require SSH signatures to come from one of these principals.
    #[arg(long = "principal", value_name = "NAME", action = ArgAction::Append)]
    principals: Vec<String>,

    /// SSH signature namespace (must match the signature).
    #[arg(long, default_value = "git", value_name = "NAME")]
    namespace: String,

    /// `gpg.ssh.revocationFile` (KRL).
    #[arg(long, value_name = "PATH")]
    revocation_file: Option<PathBuf>,

    /// Restrict verification to one format instead of inferring it from the armor.
    #[arg(long, value_enum, default_value = "auto")]
    format: FormatArg,

    /// Verify each commit once even when branches share history.
    #[arg(long, default_value = "true", action = ArgAction::Set)]
    dedupe: bool,

    /// Number of commits to verify concurrently (each spawns a gpg or
    /// ssh-keygen process).  Defaults to the machine's parallelism.
    #[arg(long, short = 'j', value_name = "N")]
    jobs: Option<usize>,

    /// Output format.
    #[arg(long, short = 'o', value_enum, default_value = "table")]
    output: OutputArg,

    /// Write the report to this file instead of stdout.
    #[arg(long, value_name = "PATH")]
    out_file: Option<PathBuf>,

    /// List violating commits in the table output.
    #[arg(long)]
    list: bool,

    /// Maximum number of violating commits listed in table output.
    #[arg(long, default_value_t = 50, value_name = "N")]
    max_listed: usize,

    /// Include merge commits in the unsigned percentage.
    #[arg(long)]
    include_merges: bool,

    /// Exit non-zero when any commit is unsigned, invalid or disallowed.
    #[arg(long)]
    fail_on_violation: bool,

    /// Exit non-zero when any commit is not `valid` (same as --fail-on-violation).
    #[arg(long, hide = true)]
    strict: bool,

    /// Print progress information to stderr.
    #[arg(long, short = 'v', action = ArgAction::Count)]
    verbose: u8,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputArg {
    Table,
    Json,
    Lines,
    Junit,
    Github,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum FormatArg {
    Auto,
    Openpgp,
    Ssh,
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<ExitCode> {
    let cli = Cli::parse();

    let since = cli.since.as_deref().map(parse_time_arg).transpose()?;
    let until = cli.until.as_deref().map(parse_time_arg).transpose()?;

    let gpg = GpgConfig {
        program: cli.gpg_program.clone(),
        home: cli.gpg_home.clone(),
        keyrings: cli
            .keyrings
            .iter()
            .chain(cli.openpgp_keyrings.iter())
            .cloned()
            .collect(),
        min_trust: TrustLevel::parse(&cli.min_trust).ok_or_else(|| {
            anyhow!(
                "invalid --min-trust '{}' (expected undefined, never, marginal, fully or ultimate)",
                cli.min_trust
            )
        })?,
        trusted_fingerprints: cli.trusted_fingerprints.clone(),
    };

    let ssh_cfg = cli.allowed_signers.clone().map(|path| {
        let mut cfg = SshConfig::new(path);
        cfg.program = cli.ssh_program.clone();
        cfg.namespace = cli.namespace.clone();
        cfg.revocation_file = cli.revocation_file.clone();
        cfg.allowed_principals = cli.principals.clone();
        cfg
    });

    let format = match cli.format {
        FormatArg::Auto => FormatMode::Auto,
        FormatArg::Openpgp => FormatMode::OpenPgp,
        FormatArg::Ssh => FormatMode::Ssh,
    };

    let verifiers = Verifiers::build(gpg, ssh_cfg, format);

    let repo = repo::Repo::open(&cli.repo)?;
    if cli.verbose > 0 {
        eprintln!("repository: {}", repo.path.display());
        eprintln!("object format: {:?}", repo.hash_algo);
    }

    // Default to every local branch, but only when the caller named neither a
    // branch pattern nor an explicit ref: `--ref v1.0` should audit that ref
    // alone, not that ref plus every branch in the repository.
    let branch_globs = if !cli.branches.is_empty() {
        cli.branches.clone()
    } else if cli.refs.is_empty() {
        vec!["*".to_string()]
    } else {
        Vec::new()
    };
    let spec = RefSpec {
        branch_globs,
        include_remotes: cli.remotes,
        explicit: cli.refs.clone(),
    };
    let branch_refs = repo.select_refs(&spec)?;

    let walk = WalkOptions {
        first_parent: cli.first_parent,
        skip_merges: cli.skip_merges,
        max_commits: cli.max_commits,
        since,
        until,
    };

    if let Some(jobs) = cli.jobs {
        if jobs == 0 {
            return Err(anyhow!("--jobs must be at least 1"));
        }
        // A small pool matters here: every unit of work starts an external
        // verifier process.
        rayon::ThreadPoolBuilder::new()
            .num_threads(jobs)
            .build_global()
            .map_err(|e| anyhow!("cannot configure the worker pool: {e}"))?;
    }

    let auditor = Auditor {
        repo,
        verifiers: std::sync::Arc::new(verifiers),
        walk,
        dedupe: cli.dedupe,
    };

    if cli.verbose > 0 {
        eprintln!("auditing {} branch(es)", branch_refs.len());
    }
    let reports = auditor.run(&branch_refs)?;

    let mut warnings = Vec::new();
    if cli.allowed_signers.is_none() {
        warnings.push(
            "no --allowed-signers given: SSH signatures cannot be verified and are reported as \
             'unverifiable'"
                .to_string(),
        );
    }
    if cli.verbose > 0 {
        // Configuration problems that silently degrade a verifier.
        for (name, err) in auditor.verifiers.configuration_errors() {
            warnings.push(format!("{name}: {err}"));
        }
    }

    let report = report::Report::build(
        auditor.repo.path.display().to_string(),
        object_format_name(auditor.repo.hash_algo),
        &reports,
        chrono::Utc::now().timestamp(),
        warnings,
        cli.dedupe,
    );

    let rendered = match cli.output {
        OutputArg::Table => report::render_table(
            &report,
            &report::TableOptions {
                list: cli.list,
                max_listed: cli.max_listed,
                include_merges: cli.include_merges,
            },
        ),
        OutputArg::Json => serde_json::to_string_pretty(&report)? + "\n",
        OutputArg::Lines => report::render_lines(&report),
        OutputArg::Junit => report::render_junit(&report),
        OutputArg::Github => report::render_github(&report),
    };

    match &cli.out_file {
        Some(path) => std::fs::write(path, &rendered)
            .with_context(|| format!("cannot write report to {}", path.display()))?,
        None => print!("{rendered}"),
    }

    if (cli.fail_on_violation || cli.strict) && report.violation_count() > 0 {
        return Ok(ExitCode::from(1));
    }
    Ok(ExitCode::SUCCESS)
}

fn object_format_name(algo: gitparse::HashAlgo) -> &'static str {
    match algo {
        gitparse::HashAlgo::Sha1 => "sha1",
        gitparse::HashAlgo::Sha256 => "sha256",
    }
}

/// Accepts `YYYY-MM-DD`, `YYYY-MM-DDTHH:MM:SS`, or plain epoch seconds.
fn parse_time_arg(s: &str) -> Result<i64> {
    let s = s.trim();
    if let Ok(epoch) = s.parse::<i64>() {
        return Ok(epoch);
    }
    if let Ok(dt) = chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d") {
        return Ok(dt.and_hms_opt(0, 0, 0).unwrap().and_utc().timestamp());
    }
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(s) {
        return Ok(dt.timestamp());
    }
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S") {
        return Ok(dt.and_utc().timestamp());
    }
    Err(anyhow!(
        "cannot parse time '{s}'; use epoch seconds, YYYY-MM-DD or RFC 3339"
    ))
}
