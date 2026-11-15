//! `sigaudit` command-line entry point.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, ValueEnum};

use sigaudit::audit::{Audit, Config};
use sigaudit::report::{self, FailOn, ReportOptions};

#[derive(Parser, Debug)]
#[command(
    name = "sigaudit",
    about = "Audit Git commit signatures (OpenPGP and SSH) offline",
    version
)]
struct Cli {
    /// Repository or worktree path (defaults to the current directory).
    #[arg(long, default_value = ".")]
    repo: PathBuf,

    /// Branch to audit; repeatable. Defaults to every local branch.
    #[arg(long = "branch", value_name = "NAME")]
    branches: Vec<String>,

    /// Also audit remote-tracking branches.
    #[arg(long)]
    remote_branches: bool,

    /// Include commits pointed at by annotated tags.
    #[arg(long)]
    include_tags: bool,

    /// OpenPGP keyring file (armored, binary, or GnuPG `pubring.kbx`);
    /// repeatable.
    #[arg(long = "gpg-keyring", value_name = "PATH")]
    gpg_keyrings: Vec<PathBuf>,

    /// Trusted OpenPGP signer (substring of a user id, or a fingerprint);
    /// repeatable. When empty, every key in the keyring is trusted.
    #[arg(long = "trusted-signer", value_name = "PATTERN")]
    trusted_signers: Vec<String>,

    /// OpenSSH `allowed_signers` file used for SSH signatures.
    #[arg(long, value_name = "PATH")]
    allowed_signers: Option<PathBuf>,

    /// OpenSSH KRL (key revocation list); repeatable.
    #[arg(long = "krl", value_name = "PATH")]
    krls: Vec<PathBuf>,

    /// Emit a machine-readable JSON report on stdout.
    #[arg(long)]
    json: bool,

    /// Write the JSON report to this file (implies --json semantics for the
    /// file, but keeps the text report on stdout).
    #[arg(long, value_name = "PATH")]
    json_out: Option<PathBuf>,

    /// Treat an unsigned commit as a failure.
    #[arg(long)]
    require_signature: bool,

    /// Which verdicts fail the run. `any` additionally implies
    /// `--require-signature`.
    #[arg(long, value_enum, default_value_t = FailLevel::Untrusted)]
    fail_on: FailLevel,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
enum FailLevel {
    /// Fail only on cryptographically invalid signatures.
    Invalid,
    /// Also fail on signatures from keys or principals not trusted here.
    Untrusted,
    /// Fail on every commit that is not signed by a trusted key, including
    /// unsigned commits (implies --require-signature).
    Any,
}

impl From<FailLevel> for FailOn {
    fn from(value: FailLevel) -> Self {
        match value {
            FailLevel::Invalid => FailOn::Invalid,
            FailLevel::Untrusted => FailOn::Untrusted,
            FailLevel::Any => FailOn::Any,
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(2)
        }
    }
}

fn run(cli: Cli) -> anyhow::Result<ExitCode> {
    let config = Config {
        repo: cli.repo.clone(),
        branches: cli.branches.clone(),
        remote_branches: cli.remote_branches,
        include_tags: cli.include_tags,
        gpg_keyrings: cli.gpg_keyrings.clone(),
        allowed_signers: cli.allowed_signers.clone(),
        krls: cli.krls.clone(),
        gpg_trusted_signers: cli.trusted_signers.clone(),
    };

    let repository = canonical_repo_name(&cli.repo);
    let options = ReportOptions {
        fail_on: cli.fail_on.into(),
        // "Fail on any non-clean commit" necessarily includes unsigned ones.
        require_signature: cli.require_signature || cli.fail_on == FailLevel::Any,
        openpgp_keyrings: cli.gpg_keyrings.len(),
        openpgp_trusted_signers: cli.trusted_signers.clone(),
        ssh_allowed_signers: cli.allowed_signers.is_some(),
        ssh_krls: cli.krls.len(),
        repository: repository.clone(),
    };

    let result = Audit::load(config)?.run()?;

    if let Some(path) = &cli.json_out {
        let json = report::build_json(&result, &options);
        let text = serde_json::to_string_pretty(&json)?;
        std::fs::write(path, text)?;
    }

    let passed = if cli.json {
        let json = report::build_json(&result, &options);
        println!("{}", serde_json::to_string_pretty(&json)?);
        json.passed
    } else {
        let stdout = std::io::stdout();
        let mut lock = stdout.lock();
        report::write_text(&mut lock, &result, &options)?
    };

    for warning in &result.warnings {
        eprintln!("warning: {warning}");
    }

    Ok(if passed {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}

fn canonical_repo_name(path: &std::path::Path) -> String {
    std::fs::canonicalize(path)
        .unwrap_or_else(|_| path.to_path_buf())
        .display()
        .to_string()
}
