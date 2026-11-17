//! Auditing a set of commits and summarising the result per branch.

use crate::gpg::GpgVerifier;
use crate::repo::{BranchRef, ObjectId, RawCommit, Repo, WalkOptions};
use crate::ssh::{SshVerifier, SshConfig};
use crate::types::{Outcome, SigKind, Status};
use rayon::prelude::*;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

/// Verifier selection, mirroring git's `gpg.format` setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormatMode {
    /// Use the armor to pick the verifier (recommended for audits).
    Auto,
    /// `gpg.format = openpgp`
    OpenPgp,
    /// `gpg.format = ssh`; SSH signatures without allowed_signers are errors.
    Ssh,
}

/// Everything needed to verify signatures.
pub struct Verifiers {
    pub gpg: GpgVerifier,
    pub ssh: Option<SshVerifier>,
    pub ssh_config_error: Option<String>,
    pub format: FormatMode,
}

impl Verifiers {
    /// Builds the verifier set, following git's rules for missing configuration.
    pub fn build(
        gpg: crate::gpg::GpgConfig,
        ssh_cfg: Option<SshConfig>,
        format: FormatMode,
    ) -> Verifiers {
        let (ssh, ssh_config_error) = match ssh_cfg {
            Some(cfg) => match SshVerifier::new(cfg) {
                Ok(v) => (Some(v), None),
                Err(e) => (None, Some(e)),
            },
            None => (
                None,
                Some(
                    "no allowed_signers file configured (set gpg.ssh.allowedSignersFile or pass \
                     --allowed-signers)"
                        .to_string(),
                ),
            ),
        };
        Verifiers {
            gpg: GpgVerifier::new(gpg),
            ssh,
            ssh_config_error,
            format,
        }
    }

    /// Configuration problems that silently degrade verification.
    pub fn configuration_errors(&self) -> Vec<(&'static str, String)> {
        let mut out = Vec::new();
        if let Some(err) = &self.ssh_config_error {
            // Only a warning when the repository has no SSH signatures; the
            // caller decides how loud to be.
            out.push(("ssh", err.clone()));
        }
        out
    }

    /// Verifies one commit and returns the verdict.
    pub fn verify(&self, commit: &RawCommit) -> Outcome {
        let parsed = &commit.parsed;

        if parsed.signature.is_none() {
            return Outcome::new(Status::Unsigned);
        }
        let signature = parsed.signature.as_deref().unwrap_or_default();
        let at = parsed.commit_time;

        let kind = match (self.format, parsed.kind) {
            // With an explicit format, git would try that verifier regardless of
            // the armor; an armor mismatch is then simply a bad signature.
            (FormatMode::OpenPgp, k) if k != Some(SigKind::OpenPgp) => {
                return unsupported(parsed.kind, "gpg.format is openpgp")
            }
            (FormatMode::Ssh, k) if k != Some(SigKind::Ssh) => {
                return unsupported(parsed.kind, "gpg.format is ssh")
            }
            (_, k) => k.unwrap_or(SigKind::Unknown),
        };

        // A commit whose committer timestamp cannot be read cannot be judged
        // "as of commit time", which is the whole point of this audit.  Git
        // refuses such objects outright; report them rather than guessing.
        if parsed.commit_time.is_none() {
            let mut outcome = Outcome::new(Status::Malformed);
            outcome.info.kind = Some(kind);
            outcome.info.detail = Some(format!(
                "cannot read the commit timestamp: {}",
                parsed.problem.as_deref().unwrap_or("committer header is missing")
            ));
            return outcome;
        }

        match kind {
            SigKind::OpenPgp => self.gpg.verify(&parsed.payload, signature, at),
            SigKind::Ssh => match &self.ssh {
                Some(ssh) => ssh.verify(&parsed.payload, signature, at),
                None => {
                    let mut outcome = Outcome::new(Status::Unverifiable);
                    outcome.info.kind = Some(SigKind::Ssh);
                    outcome.info.detail = self.ssh_config_error.clone();
                    outcome
                }
            },
            SigKind::X509 => {
                let mut outcome = Outcome::new(Status::Unverifiable);
                outcome.info.kind = Some(SigKind::X509);
                outcome.info.detail =
                    Some("X.509 signatures are not supported by this audit".to_string());
                outcome
            }
            SigKind::Unknown => {
                let mut outcome = Outcome::new(Status::Malformed);
                outcome.info.detail = Some("unrecognised signature armor".to_string());
                outcome
            }
        }
    }
}

fn unsupported(kind: Option<SigKind>, why: &str) -> Outcome {
    let mut outcome = Outcome::new(Status::Malformed);
    outcome.info.kind = kind;
    outcome.info.detail = Some(format!(
        "signature format {} does not match the configured format ({why})",
        kind.map(|k| k.as_str()).unwrap_or("unknown")
    ));
    outcome
}

/// Verdict for one commit within one branch.
#[derive(Debug, Clone)]
pub struct CommitVerdict {
    pub oid: ObjectId,
    pub short: String,
    pub author: String,
    pub committer: String,
    pub commit_time: Option<i64>,
    pub subject: String,
    pub is_merge: bool,
    pub parents: usize,
    pub outcome: Outcome,
}

/// Per-branch audit result.
#[derive(Debug)]
pub struct BranchReport {
    pub branch: BranchRef,
    pub commits: Vec<CommitVerdict>,
    /// Commits reachable from this branch that also appear on another branch.
    pub shared: usize,
}

impl BranchReport {
    pub fn counts(&self) -> BTreeMap<Status, usize> {
        let mut counts: BTreeMap<Status, usize> = BTreeMap::new();
        for c in &self.commits {
            *counts.entry(c.outcome.status).or_insert(0) += 1;
        }
        counts
    }

    pub fn violations(&self) -> impl Iterator<Item = &CommitVerdict> {
        self.commits
            .iter()
            .filter(|c| c.outcome.status.is_violation())
    }

    /// Commits that are unsigned.  Merge commits can be counted separately.
    pub fn unsigned_count(&self, include_merges: bool) -> usize {
        self.commits
            .iter()
            .filter(|c| c.outcome.status == Status::Unsigned && (include_merges || !c.is_merge))
            .count()
    }

    /// Fraction of commits that are `Valid`, ignoring merge commits when asked.
    pub fn valid_ratio(&self, include_merges: bool) -> f64 {
        let mut total = 0usize;
        let mut valid = 0usize;
        for c in &self.commits {
            if !include_merges && c.is_merge {
                continue;
            }
            total += 1;
            if c.outcome.status == Status::Valid {
                valid += 1;
            }
        }
        if total == 0 {
            1.0
        } else {
            valid as f64 / total as f64
        }
    }
}

/// Runs the audit.
pub struct Auditor {
    pub repo: Repo,
    pub verifiers: Arc<Verifiers>,
    pub walk: WalkOptions,
    /// Verify each commit once even when several branches share it.
    pub dedupe: bool,
}

impl Auditor {
    pub fn run(&self, refs: &[BranchRef]) -> anyhow::Result<Vec<BranchReport>> {
        // Collect each branch's history once, then verify the union in parallel.
        let mut per_branch: Vec<(BranchRef, Vec<ObjectId>)> = Vec::new();
        for r in refs {
            let oids = self.repo.walk(r.tip, &self.walk)?;
            per_branch.push((r.clone(), oids));
        }

        let mut outcomes: HashMap<ObjectId, Outcome> = HashMap::new();
        if self.dedupe {
            let unique: std::collections::BTreeSet<ObjectId> = per_branch
                .iter()
                .flat_map(|(_, oids)| oids.iter().copied())
                .collect();
            // `git2::Repository` is not `Sync`, so read the raw objects on this
            // thread and only the (process-spawning) verification in parallel.
            let mut pending: Vec<RawCommit> = Vec::with_capacity(unique.len());
            for oid in &unique {
                match self.repo.read_commit(*oid) {
                    Ok(c) => pending.push(c),
                    // Unreadable objects are reported per branch below.
                    Err(_) => continue,
                }
            }
            // Bind the verifiers outside the closure: capturing `self` would drag
            // the non-`Sync` `Repository` into the parallel section.
            let verifiers = Arc::clone(&self.verifiers);
            let verified: Vec<(ObjectId, Outcome)> = pending
                .into_par_iter()
                .map(|commit| {
                    let outcome = verifiers.verify(&commit);
                    (commit.oid, outcome)
                })
                .collect();
            outcomes.extend(verified);
        }

        let mut reports = Vec::new();
        for (branch, oids) in per_branch {
            let mut commits = Vec::with_capacity(oids.len());
            for oid in oids {
                let commit = match self.repo.read_commit(oid) {
                    Ok(c) => c,
                    Err(e) => {
                        // A missing or corrupt object must not abort the whole
                        // audit: record it as a violation instead.
                        commits.push(CommitVerdict {
                            oid,
                            short: oid.short(),
                            author: String::new(),
                            committer: String::new(),
                            commit_time: None,
                            subject: format!("<unreadable: {e}>"),
                            is_merge: false,
                            parents: 0,
                            outcome: {
                                let mut o = Outcome::new(Status::Malformed);
                                o.info.detail = Some(format!("cannot read object: {e}"));
                                o
                            },
                        });
                        continue;
                    }
                };
                let outcome = match outcomes.get(&oid) {
                    Some(o) => o.clone(),
                    None => self.verifiers.verify(&commit),
                };
                commits.push(verdict_from(&commit, outcome));
            }
            reports.push(BranchReport {
                branch,
                commits,
                shared: 0,
            });
        }

        // Mark how many commits each branch shares with the others.
        annotate_shared(&mut reports);
        Ok(reports)
    }
}

fn verdict_from(commit: &RawCommit, outcome: Outcome) -> CommitVerdict {
    let full = commit.oid.to_string();
    CommitVerdict {
        oid: commit.oid,
        short: full[..8.min(full.len())].to_string(),
        author: commit.meta.author.clone().unwrap_or_default(),
        committer: commit.meta.committer.clone().unwrap_or_default(),
        commit_time: commit.parsed.commit_time,
        subject: commit.meta.subject.clone(),
        is_merge: commit.is_merge,
        parents: commit.meta.parents.len(),
        outcome,
    }
}

fn annotate_shared(reports: &mut [BranchReport]) {
    let mut seen: HashMap<ObjectId, usize> = HashMap::new();
    for r in reports.iter() {
        for c in &r.commits {
            *seen.entry(c.oid).or_insert(0) += 1;
        }
    }
    for r in reports.iter_mut() {
        r.shared = r
            .commits
            .iter()
            .filter(|c| seen.get(&c.oid).copied().unwrap_or(0) > 1)
            .count();
    }
}

/// Aggregated totals across branches, counting each commit once.
#[derive(Debug, Default)]
pub struct Totals {
    pub commits: usize,
    pub merge_commits: usize,
    pub by_status: BTreeMap<Status, usize>,
}

impl Totals {
    pub fn from_reports(reports: &[BranchReport], dedupe: bool) -> Totals {
        let mut totals = Totals::default();
        let mut seen = std::collections::HashSet::new();
        for r in reports {
            for c in &r.commits {
                if dedupe && !seen.insert(c.oid) {
                    continue;
                }
                totals.commits += 1;
                if c.is_merge {
                    totals.merge_commits += 1;
                }
                *totals.by_status.entry(c.outcome.status).or_insert(0) += 1;
            }
        }
        totals
    }

    pub fn violations(&self) -> usize {
        self.by_status
            .iter()
            .filter(|(s, _)| s.is_violation())
            .map(|(_, n)| *n)
            .sum()
    }
}
