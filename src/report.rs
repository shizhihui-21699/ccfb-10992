//! Report rendering: human-readable text and a stable JSON schema for CI.

use std::io::Write;

use serde::Serialize;

use crate::audit::AuditResult;
use crate::model::{BranchReport, CommitReport, Counts, Verdict};

/// A CI-friendly summary with an explicit exit code.
#[derive(Debug, Serialize)]
pub struct JsonReport {
    pub schema_version: u32,
    pub repository: String,
    pub policy: PolicySummary,
    pub totals: Counts,
    pub unique_commits: usize,
    pub branches: Vec<BranchSummary>,
    pub commits: Vec<CommitReport>,
    pub warnings: Vec<String>,
    pub passed: bool,
}

#[derive(Debug, Serialize)]
pub struct PolicySummary {
    pub require_signature: bool,
    pub openpgp_keyrings: usize,
    pub openpgp_trusted_signers: Vec<String>,
    pub ssh_allowed_signers: bool,
    pub ssh_krls: usize,
}

#[derive(Debug, Serialize)]
pub struct BranchSummary {
    pub name: String,
    pub tip: String,
    pub counts: Counts,
    pub failure_count: usize,
}

/// Which verdicts fail the run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailOn {
    /// Only commits whose signature does not verify.
    Invalid,
    /// Also commits signed by a key/principal that is not trusted here
    /// (the default: "must be signed by a trusted key").
    Untrusted,
    /// Additionally require every commit to be signed at all.
    Any,
}

pub struct ReportOptions {
    pub fail_on: FailOn,
    pub require_signature: bool,
    pub openpgp_keyrings: usize,
    pub openpgp_trusted_signers: Vec<String>,
    pub ssh_allowed_signers: bool,
    pub ssh_krls: usize,
    pub repository: String,
}

impl ReportOptions {
    /// Whether this verdict breaches the configured policy.
    pub fn counts_as_failure(&self, verdict: Verdict) -> bool {
        match verdict {
            Verdict::Signed => false,
            // Unsigned commits only count when a signature is required.
            Verdict::Unsigned => self.require_signature,
            // A broken signature always fails: it is either an attack or a
            // corruption, and no policy should let it through.
            Verdict::Invalid => true,
            Verdict::Untrusted => matches!(self.fail_on, FailOn::Untrusted | FailOn::Any),
            // The key was valid when the commit was made, so `--fail-on
            // invalid` treats it as acceptable; stricter policies do not.
            Verdict::RevokedLater => matches!(self.fail_on, FailOn::Untrusted | FailOn::Any),
        }
    }

    fn branch_failures<'a>(
        &self,
        result: &'a AuditResult,
        branch: &'a BranchReport,
    ) -> Vec<&'a CommitReport> {
        branch
            .non_signed
            .iter()
            .filter_map(|id| result.commits.iter().find(|c| &c.commit == id))
            .filter(|c| self.counts_as_failure(c.verdict))
            .collect()
    }
}

pub fn build_json(result: &AuditResult, options: &ReportOptions) -> JsonReport {
    let failures = result
        .commits
        .iter()
        .filter(|c| options.counts_as_failure(c.verdict))
        .count();
    let passed = failures == 0;
    JsonReport {
        schema_version: 1,
        repository: options.repository.clone(),
        policy: PolicySummary {
            require_signature: options.require_signature,
            openpgp_keyrings: options.openpgp_keyrings,
            openpgp_trusted_signers: options.openpgp_trusted_signers.clone(),
            ssh_allowed_signers: options.ssh_allowed_signers,
            ssh_krls: options.ssh_krls,
        },
        totals: result.totals,
        unique_commits: result.unique_commits,
        branches: result
            .branches
            .iter()
            .map(|b| BranchSummary {
                name: b.name.clone(),
                tip: b.tip.clone(),
                counts: b.counts,
                failure_count: options.branch_failures(result, b).len(),
            })
            .collect(),
        commits: result.commits.clone(),
        warnings: result.warnings.clone(),
        passed,
    }
}

/// Write the text report to `out`, returning whether the audit passed.
pub fn write_text(
    out: &mut impl Write,
    result: &AuditResult,
    options: &ReportOptions,
) -> std::io::Result<bool> {
    writeln!(out, "Signature audit: {}", options.repository)?;
    writeln!(out)?;

    for branch in &result.branches {
        let c = &branch.counts;
        writeln!(out, "branch {} (tip {})", branch.name, short(&branch.tip))?;
        writeln!(
            out,
            "  {} commits: {} signed, {} unsigned, {} invalid, {} untrusted, {} revoked-later",
            c.total, c.signed, c.unsigned, c.invalid, c.untrusted, c.revoked_later
        )?;
        for commit in options.branch_failures(result, branch) {
            write_commit_line(out, commit, options)?;
        }
    }

    let totals = &result.totals;
    writeln!(out)?;
    writeln!(
        out,
        "total {} unique commits: {} signed, {} unsigned, {} invalid, {} untrusted, {} revoked-later",
        result.unique_commits,
        totals.signed,
        totals.unsigned,
        totals.invalid,
        totals.untrusted,
        totals.revoked_later
    )?;

    let failed: Vec<&CommitReport> = result
        .commits
        .iter()
        .filter(|c| options.counts_as_failure(c.verdict))
        .collect();
    if failed.is_empty() {
        writeln!(out, "result: PASS")?;
        Ok(true)
    } else {
        writeln!(
            out,
            "result: FAIL ({} commit(s) violate policy)",
            failed.len()
        )?;
        Ok(false)
    }
}

fn write_commit_line(
    out: &mut impl Write,
    commit: &CommitReport,
    options: &ReportOptions,
) -> std::io::Result<()> {
    let marker = if options.counts_as_failure(commit.verdict) {
        "✗"
    } else {
        "·"
    };
    writeln!(
        out,
        "  {marker} {} [{}] {}",
        &commit.commit[..12.min(commit.commit.len())],
        commit.verdict.as_str(),
        commit.subject
    )?;
    if let Some(reason) = &commit.reason {
        writeln!(out, "      {reason}")?;
    }
    if let Some(sig) = &commit.signature {
        let signer = sig
            .signer_identity
            .clone()
            .or_else(|| sig.signer_fingerprint.clone())
            .unwrap_or_else(|| "<unknown signer>".to_string());
        writeln!(
            out,
            "      {} signature by {signer}",
            match sig.kind {
                crate::model::SignatureKind::OpenPgp => "OpenPGP",
                crate::model::SignatureKind::Ssh => "SSH",
            }
        )?;
    }
    if let Some(mergetag) = &commit.mergetag {
        writeln!(
            out,
            "      mergetag: {} ({})",
            mergetag.verdict.as_str(),
            mergetag.reason.as_deref().unwrap_or("")
        )?;
    }
    Ok(())
}

fn short(id: &str) -> &str {
    &id[..12.min(id.len())]
}
