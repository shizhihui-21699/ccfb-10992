//! sigaudit — audit commit signatures across git branches.
//!
//! Reads git objects directly (no checkout, no worktree needed) and verifies
//! OpenPGP and SSH signatures the way git itself does.

pub mod audit;
pub mod cli;
pub mod config;
pub mod gpg;
pub mod ident;
pub mod keys;
pub mod model;
pub mod object;
pub mod report;
pub mod sigmeta;
pub mod ssh;

pub const EXIT_OK: i32 = 0;
pub const EXIT_AUDIT_FAILURE: i32 = 1;
pub const EXIT_USAGE: i32 = 2;
pub const EXIT_INTERNAL: i32 = 3;

fn main() {
    let code = run();
    std::process::exit(code);
}

fn run() -> i32 {
    use clap::Parser;

    let cli = cli::Cli::parse();

    // stderr for anything that is not the report itself, so machine formats
    // stay clean.
    let repo = match git2::Repository::open(&cli.repo) {
        Ok(r) => r,
        Err(e) => {
            // libgit2 refuses object formats it was not built for; say so
            // plainly instead of surfacing its internal class/code numbers.
            let message = if e.message().contains("unknown object format") {
                format!(
                    "{} uses an object format this build of sigaudit cannot read ({}); \
                     SHA-256 repositories are not supported",
                    cli.repo.display(),
                    e.message()
                )
            } else {
                format!("cannot open repository {}: {e}", cli.repo.display())
            };
            eprintln!("sigaudit: {message}");
            return EXIT_USAGE;
        }
    };

    let config = match cli.build_config(&repo) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("sigaudit: {e}");
            return EXIT_USAGE;
        }
    };

    if let Some(level) = &cli.min_trust_level {
        if crate::config::parse_trust(level).is_none() {
            eprintln!("sigaudit: invalid --min-trust-level: {level}");
            return EXIT_USAGE;
        }
    }

    // Warn early when the environment cannot verify the formats at all, so CI
    // logs say why rather than silently reporting unsigned/bad.
    check_environment(&config);

    let options = cli.build_options();
    let auditor = audit::Auditor::new(&repo, config);
    let report = auditor.run(&options);

    let format: report::Format = cli.format.into();
    let contents = report::render(&report, format, cli.quiet);
    if let Err(e) = cli::write_output(cli.output.as_deref(), &contents) {
        eprintln!("sigaudit: could not write report: {e}");
        return EXIT_INTERNAL;
    }

    if cli.is_failure(&report) {
        EXIT_AUDIT_FAILURE
    } else {
        EXIT_OK
    }
}

fn check_environment(config: &config::Config) {
    let gpg = gpg::GpgVerifier::new(config.gpg_program.clone(), config.effective_gpg_home());
    if !gpg.is_available() {
        eprintln!(
            "sigaudit: warning: {} is not runnable; OpenPGP signatures will be reported as \
             unverifiable",
            config.gpg_program
        );
    }
    let ssh = ssh::SshVerifier::new(config.ssh_program.clone());
    if !ssh.is_available() {
        eprintln!(
            "sigaudit: warning: {} is not runnable; SSH signatures will be reported as \
             unverifiable",
            config.ssh_program
        );
    }
}
