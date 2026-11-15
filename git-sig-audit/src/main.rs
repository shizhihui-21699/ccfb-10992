mod commit;
mod report;
mod verify;

use anyhow::{bail, Context, Result};
use clap::Parser;
use report::{BranchReport, CommitReport, Format, Report, SigReport};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;
use verify::{GpgVerifier, SshVerifier, Status, Verification};

#[derive(Parser, Debug)]
#[command(
    name = "git-sig-audit",
    version,
    about = "Audit GPG/SSH commit signatures across all branches of a git repository"
)]
struct Cli {
    /// Path to the git repository
    #[arg(default_value = ".")]
    repo: PathBuf,

    /// SSH allowed_signers file used to verify ssh-format signatures
    #[arg(long)]
    allowed_signers: Option<PathBuf>,

    /// File with allowed GPG key fingerprints (one per line, '#' comments).
    /// If omitted, whitelist checking for GPG signers is skipped.
    #[arg(long)]
    gpg_whitelist: Option<PathBuf>,

    /// Audit all refs (heads, remotes, tags) instead of just local branches
    #[arg(long)]
    all: bool,

    /// Output format
    #[arg(long, value_enum, default_value = "text")]
    format: Format,

    /// Write the report to this file instead of stdout
    #[arg(long)]
    output: Option<PathBuf>,

    /// Comma-separated statuses that fail the audit (exit code 1).
    /// Possible: unsigned,valid,valid-expired-key,valid-revoked-key,invalid,untrusted,unverifiable
    #[arg(long, default_value = "unsigned,invalid,untrusted,unverifiable")]
    fail_on: String,

    /// GnuPG home directory (defaults to $GNUPGHOME or the gpg default)
    #[arg(long)]
    gpg_homedir: Option<PathBuf>,
}

fn main() {
    let code = match run() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e:#}");
            2
        }
    };
    std::process::exit(code);
}

fn run() -> Result<i32> {
    let cli = Cli::parse();

    let mut fail_on = HashSet::new();
    for s in cli.fail_on.split(',') {
        let s = s.trim();
        if s.is_empty() {
            continue;
        }
        match Status::parse(s) {
            Some(st) => {
                fail_on.insert(st);
            }
            None => bail!("unknown status in --fail-on: {s}"),
        }
    }

    let collected = commit::collect(&cli.repo, cli.all)
        .context("failed to read repository objects")?;

    let mut gpg = GpgVerifier::new(cli.gpg_homedir.clone(), cli.gpg_whitelist.as_deref())?;
    let ssh = SshVerifier::new(cli.allowed_signers.as_deref())?;

    // Verify each unique commit once; reuse the result on every branch.
    let mut cache: HashMap<git2::Oid, Verification> = HashMap::new();
    for info in collected.commits.values() {
        let v = match &info.signature {
            None => Verification {
                status: Status::Unsigned,
                ..Default::default()
            },
            Some(sig) => match sig.kind {
                commit::SigKind::Gpg => gpg.verify(&sig.armored, &sig.payload, info.commit_time),
                commit::SigKind::Ssh => {
                    ssh.verify(&sig.armored, &sig.payload, &info.committer_email)
                }
            },
        };
        cache.insert(info.oid, v);
    }

    let mut summary: BTreeMap<String, usize> = BTreeMap::new();
    let mut passed = true;
    for (oid, v) in &cache {
        *summary.entry(v.status.as_str().to_string()).or_insert(0) += 1;
        if fail_on.contains(&v.status) {
            passed = false;
        }
        let _ = oid;
    }

    let mut branches = BTreeMap::new();
    for (name, oids) in &collected.branches {
        let mut counts: BTreeMap<String, usize> = BTreeMap::new();
        let mut commits = Vec::new();
        for oid in oids {
            let Some(info) = collected.commits.get(oid) else {
                continue;
            };
            let v = &cache[oid];
            *counts.entry(v.status.as_str().to_string()).or_insert(0) += 1;
            commits.push(CommitReport {
                oid: oid.to_string(),
                subject: info.subject.clone(),
                author: info.author.clone(),
                committer: info.committer_email.clone(),
                commit_time: info.commit_time,
                merge: info.is_merge(),
                status: v.status.as_str().to_string(),
                signature: v.kind.map(|k| SigReport {
                    kind: k.to_string(),
                    signer: v.signer.clone(),
                    uid: v.uid.clone(),
                    detail: v.detail.clone(),
                    key_expires: v.key_expires,
                    key_revoked_at: v.key_revoked_at,
                }),
            });
        }
        branches.insert(
            name.clone(),
            BranchReport {
                tip: oids.first().map(|o| o.to_string()).unwrap_or_default(),
                counts,
                commits,
            },
        );
    }

    let report = Report {
        tool: format!("git-sig-audit {}", env!("CARGO_PKG_VERSION")),
        repo: cli.repo.display().to_string(),
        generated_at: chrono::Utc::now().to_rfc3339(),
        total_unique_commits: cache.len(),
        summary,
        branches,
        fail_on: fail_on.iter().map(|s| s.as_str().to_string()).collect(),
        passed,
    };

    let rendered = match cli.format {
        Format::Json => serde_json::to_string_pretty(&report)?,
        Format::Text => report::render_text(&report),
    };
    match &cli.output {
        Some(p) => std::fs::write(p, &rendered)?,
        None => println!("{rendered}"),
    }

    Ok(if report.passed { 0 } else { 1 })
}
