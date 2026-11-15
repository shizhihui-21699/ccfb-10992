//! Repository walking and policy evaluation.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use anyhow::Context;

use crate::model::{BranchReport, CommitReport, Counts, MergetagReport, SignatureKind, Verdict};
use crate::objects::{
    committer_timestamp, header_value, mergetag_payload, parse_signed_commit, parse_signed_tag,
};
use crate::pgp_keyring::PgpKeyring;
use crate::ssh_keys::{AllowedSigners, KrlSet};
use crate::{pgp_verify, ssh_verify};

/// Audit configuration, one-to-one with the CLI flags.
#[derive(Clone, Debug, Default)]
pub struct Config {
    /// Repository or worktree path to open.
    pub repo: PathBuf,
    /// Branches to audit; empty means every local branch.
    pub branches: Vec<String>,
    /// Also audit remote-tracking branches.
    pub remote_branches: bool,
    /// Include commits pointed at by annotated tags.
    pub include_tags: bool,
    /// Files holding OpenPGP certificates (armored or binary, keybox allowed).
    pub gpg_keyrings: Vec<PathBuf>,
    /// `gpg.format=ssh` allowlist.
    pub allowed_signers: Option<PathBuf>,
    /// Optional KRLs.
    pub krls: Vec<PathBuf>,
    /// OpenPGP signer allowlist (user-id substrings). Empty = trust keyring.
    pub gpg_trusted_signers: Vec<String>,
}

/// Everything the audit learned, ready for any reporter.
#[derive(Debug)]
pub struct AuditResult {
    pub commits: Vec<CommitReport>,
    pub branches: Vec<BranchReport>,
    pub totals: Counts,
    /// Unique commits reachable from the selected branches, after de-dup.
    pub unique_commits: usize,
    pub warnings: Vec<String>,
}

pub struct Audit {
    config: Config,
    pgp: PgpKeyring,
    signers: Option<AllowedSigners>,
    krls: KrlSet,
    warnings: Vec<String>,
    /// Reports keyed by commit id; branch walks overlap heavily.
    cache: HashMap<String, CommitReport>,
}

impl Audit {
    pub fn load(config: Config) -> anyhow::Result<Self> {
        let mut pgp = PgpKeyring::new();
        for signer in &config.gpg_trusted_signers {
            pgp.add_trusted(signer.clone());
        }
        if !config.gpg_keyrings.is_empty() {
            pgp.load_files(&config.gpg_keyrings)?;
        }

        let mut warnings = Vec::new();
        let mut signers = None;
        if let Some(path) = &config.allowed_signers {
            let parsed = AllowedSigners::read_file(path)?;
            warnings.extend(parsed.warnings.iter().cloned());
            signers = Some(parsed);
        }

        let mut krls = KrlSet::default();
        for path in &config.krls {
            krls.add(crate::ssh_keys::Krl::read_file(path)?);
        }
        warnings.extend(krls.warnings.iter().cloned());

        if signers.is_none() && pgp.is_empty() {
            anyhow::bail!(
                "no trust material configured: pass at least one --gpg-keyring or --allowed-signers"
            );
        }

        Ok(Self {
            config,
            pgp,
            signers,
            krls,
            warnings,
            cache: HashMap::new(),
        })
    }

    /// Run the audit.
    pub fn run(mut self) -> anyhow::Result<AuditResult> {
        let repo = gix::discover(&self.config.repo)
            .with_context(|| format!("opening Git repository at {}", self.config.repo.display()))?;
        let hash_index = match repo.object_hash() {
            gix::hash::Kind::Sha1 => 1,
            _ => 2,
        };

        let selected = self.select_branches(&repo)?;
        let mut branches = Vec::new();
        let mut commits: Vec<CommitReport> = Vec::new();
        let mut index: HashMap<String, usize> = HashMap::new();

        for (branch_name, tips) in &selected {
            let mut counts = Counts::default();
            let mut non_signed = Vec::new();
            let mut tip_id = String::new();

            for info in repo
                .rev_walk(tips.iter().copied())
                .all()
                .with_context(|| format!("walking branch {branch_name}"))?
            {
                let info = info?;
                let id = info.id.to_hex().to_string();
                if tip_id.is_empty() {
                    tip_id = id.clone();
                }
                let report = self.report_for(&repo, &id, hash_index)?;
                counts.record(report.verdict);
                if report.verdict.is_failure() {
                    non_signed.push(id.clone());
                }
                if let std::collections::hash_map::Entry::Vacant(slot) = index.entry(id) {
                    slot.insert(commits.len());
                    commits.push(report);
                }
            }
            branches.push(BranchReport {
                name: branch_name.clone(),
                tip: tip_id,
                counts,
                non_signed,
            });
        }

        if self.config.include_tags {
            for report in self.audit_tags(&repo, hash_index)? {
                if let std::collections::hash_map::Entry::Vacant(slot) =
                    index.entry(report.commit.clone())
                {
                    slot.insert(commits.len());
                    commits.push(report);
                }
            }
        }

        let mut totals = Counts::default();
        for report in &commits {
            totals.record(report.verdict);
        }
        let unique_commits = commits.len();

        Ok(AuditResult {
            commits,
            branches,
            totals,
            unique_commits,
            warnings: std::mem::take(&mut self.warnings),
        })
    }

    /// Reports are computed once per commit and reused, because branch walks
    /// overlap heavily in any non-trivial history.
    fn report_cache(&mut self) -> &mut HashMap<String, CommitReport> {
        &mut self.cache
    }

    fn select_branches(
        &self,
        repo: &gix::Repository,
    ) -> anyhow::Result<Vec<(String, Vec<gix::ObjectId>)>> {
        let mut selected: Vec<(String, Vec<gix::ObjectId>)> = Vec::new();
        let wanted: HashSet<&str> = self.config.branches.iter().map(|s| s.as_str()).collect();

        let mut push = |reference: gix::Reference<'_>, short: String| -> anyhow::Result<()> {
            if !wanted.is_empty() && !wanted.contains(short.as_str()) {
                return Ok(());
            }
            let mut reference = reference;
            let id = reference.peel_to_id()?.detach();
            selected.push((short, vec![id]));
            Ok(())
        };

        for reference in repo.references()?.local_branches()? {
            let reference = reference?;
            let short = reference.name().shorten().to_string();
            push(reference, short)?;
        }
        if self.config.remote_branches {
            for reference in repo.references()?.remote_branches()? {
                let reference = reference?;
                let short = reference.name().shorten().to_string();
                push(reference, short)?;
            }
        }

        if selected.is_empty() {
            if !self.config.branches.is_empty() {
                anyhow::bail!("no matching branches for {:?}", self.config.branches);
            }
            anyhow::bail!("repository has no local branches to audit");
        }
        Ok(selected)
    }

    fn report_for(
        &mut self,
        repo: &gix::Repository,
        id: &str,
        hash_index: usize,
    ) -> anyhow::Result<CommitReport> {
        if let Some(cached) = self.report_cache().get(id) {
            return Ok(cached.clone());
        }
        let object = repo
            .find_object(gix::hash::ObjectId::from_hex(id.as_bytes())?)
            .with_context(|| format!("reading commit {id}"))?;
        if object.kind != gix::object::Kind::Commit {
            anyhow::bail!("{id} is not a commit");
        }
        let raw = object.data.clone();
        let commit_time = committer_timestamp(&raw).unwrap_or(0);
        let report = self.evaluate_commit(id, &raw, hash_index, commit_time)?;
        self.report_cache().insert(id.to_string(), report.clone());
        Ok(report)
    }

    fn evaluate_commit(
        &mut self,
        id: &str,
        raw: &[u8],
        hash_index: usize,
        commit_time: i64,
    ) -> anyhow::Result<CommitReport> {
        let parents = parse_parents(raw)
            .iter()
            .map(|p| p.to_hex().to_string())
            .collect();
        let subject = subject_of(raw);
        let author = header_value(raw, b"author ");
        let committer = header_value(raw, b"committer ");

        let (verdict, signature, reason) = match parse_signed_commit(raw, hash_index) {
            None => (
                Verdict::Unsigned,
                None,
                Some("commit has no signature".to_string()),
            ),
            Some(signed) => {
                let outcome = self.verify_blob(&signed.payload, &signed.signature, commit_time);
                (outcome.verdict, Some(outcome.detail), outcome.reason)
            }
        };

        let mergetag = self.evaluate_mergetag(raw, commit_time);

        Ok(CommitReport {
            commit: id.to_string(),
            tree: header_value(raw, b"tree "),
            parents,
            author,
            committer,
            commit_time,
            subject,
            verdict,
            signature,
            reason,
            mergetag: mergetag.map(Box::new),
        })
    }

    fn evaluate_mergetag(&mut self, raw: &[u8], commit_time: i64) -> Option<MergetagReport> {
        let payload = mergetag_payload(raw)?;
        let tag = parse_signed_tag(&payload)?;
        let outcome = self.verify_blob(&tag.payload, &tag.signature, commit_time);
        Some(MergetagReport {
            tag_object: String::new(),
            verdict: outcome.verdict,
            signature: Some(outcome.detail),
            reason: outcome.reason,
        })
    }

    /// Verify a signature blob, choosing the backend by its armour.
    fn verify_blob(&mut self, payload: &[u8], signature: &[u8], commit_time: i64) -> BlobOutcome {
        match detect_backend(signature) {
            Some(Backend::Ssh) => {
                let Some(signers) = &self.signers else {
                    return BlobOutcome::invalid(
                        SignatureKind::Ssh,
                        "SSH signature found but no --allowed-signers file was configured",
                    );
                };
                let outcome =
                    ssh_verify::verify(signers, &self.krls, payload, signature, commit_time);
                if !outcome.verified {
                    return BlobOutcome::verdict(Verdict::Invalid, outcome.detail, outcome.reason);
                }
                if outcome.trusted && outcome.issue.is_none() {
                    BlobOutcome::signed(outcome.detail)
                } else {
                    BlobOutcome::verdict(Verdict::Untrusted, outcome.detail, outcome.reason)
                }
            }
            Some(Backend::OpenPgp) | None => {
                if self.pgp.is_empty() {
                    return BlobOutcome::invalid(
                        SignatureKind::OpenPgp,
                        if detect_backend(signature).is_none() {
                            "unrecognized signature format"
                        } else {
                            "OpenPGP signature found but no --gpg-keyring was configured"
                        },
                    );
                }
                if detect_backend(signature).is_none() {
                    return BlobOutcome::invalid(
                        SignatureKind::OpenPgp,
                        "unrecognized signature format",
                    );
                }
                let outcome = pgp_verify::verify(&self.pgp, payload, signature, commit_time);
                if !outcome.verified {
                    return BlobOutcome::verdict(Verdict::Invalid, outcome.detail, outcome.reason);
                }
                match outcome.issue {
                    None => BlobOutcome::signed(outcome.detail),
                    Some(crate::model::KeyIssue::RevokedAfterCommit) => {
                        BlobOutcome::verdict(Verdict::RevokedLater, outcome.detail, outcome.reason)
                    }
                    Some(_) => {
                        BlobOutcome::verdict(Verdict::Untrusted, outcome.detail, outcome.reason)
                    }
                }
            }
        }
    }

    fn audit_tags(
        &mut self,
        repo: &gix::Repository,
        hash_index: usize,
    ) -> anyhow::Result<Vec<CommitReport>> {
        let mut out = Vec::new();
        let mut tags: Vec<String> = Vec::new();
        for reference in repo.references()?.all()? {
            let reference = reference?;
            let name = reference.name().as_bstr().to_string();
            if let Some(tag) = name.strip_prefix("refs/tags/") {
                tags.push(tag.to_string());
            }
        }
        tags.sort();
        tags.dedup();

        for tag in tags {
            let reference = match repo.find_reference(&format!("refs/tags/{tag}")) {
                Ok(r) => r,
                Err(_) => continue,
            };
            let peeled = match reference.into_fully_peeled_id() {
                Ok(id) => id.detach(),
                Err(_) => continue,
            };
            let object = repo.find_object(peeled)?;
            if object.kind != gix::object::Kind::Commit {
                continue;
            }
            let commit_id = peeled.to_hex().to_string();
            if self.report_cache().contains_key(&commit_id) {
                continue;
            }
            let raw = object.data.clone();
            let time = committer_timestamp(&raw).unwrap_or(0);
            let report = self.evaluate_commit(&commit_id, &raw, hash_index, time)?;
            self.report_cache().insert(commit_id, report.clone());
            out.push(report);
        }
        Ok(out)
    }
}

#[derive(Debug)]
struct BlobOutcome {
    verdict: Verdict,
    detail: crate::model::SignatureDetail,
    reason: Option<String>,
}

impl BlobOutcome {
    fn signed(detail: crate::model::SignatureDetail) -> Self {
        Self {
            verdict: Verdict::Signed,
            detail,
            reason: None,
        }
    }

    fn verdict(
        verdict: Verdict,
        detail: crate::model::SignatureDetail,
        reason: Option<String>,
    ) -> Self {
        Self {
            verdict,
            detail,
            reason,
        }
    }

    fn invalid(kind: SignatureKind, reason: &str) -> Self {
        Self {
            verdict: Verdict::Invalid,
            detail: crate::model::SignatureDetail {
                kind,
                signer_fingerprint: None,
                signer_identity: None,
                signature_time: None,
                key_issue: None,
            },
            reason: Some(reason.to_string()),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Backend {
    OpenPgp,
    Ssh,
}

fn detect_backend(signature: &[u8]) -> Option<Backend> {
    const SSH_BEGIN: &[u8] = b"-----BEGIN SSH SIGNATURE-----";
    const PGP_BEGIN: &[u8] = b"-----BEGIN PGP SIGNATURE-----";
    const PGP_MSG: &[u8] = b"-----BEGIN PGP MESSAGE-----";

    if signature.windows(SSH_BEGIN.len()).any(|w| w == SSH_BEGIN) {
        return Some(Backend::Ssh);
    }
    if signature.windows(PGP_BEGIN.len()).any(|w| w == PGP_BEGIN)
        || signature.windows(PGP_MSG.len()).any(|w| w == PGP_MSG)
    {
        return Some(Backend::OpenPgp);
    }
    // Binary OpenPGP signature packet: old- or new-format header, tag 2.
    let first = *signature.first()?;
    if first & 0x80 == 0 {
        return None;
    }
    if first & 0x40 == 0 {
        // Old-format header: bit 5..2 hold the packet tag.
        if (first >> 2) & 0x0f == 2 {
            return Some(Backend::OpenPgp);
        }
    } else if first & 0x3f == 2 {
        return Some(Backend::OpenPgp);
    }
    None
}

fn parse_parents(raw: &[u8]) -> Vec<gix::hash::ObjectId> {
    let mut out = Vec::new();
    for line in raw.split_inclusive(|b| *b == b'\n') {
        if let Some(rest) = line.strip_prefix(b"parent ") {
            let hex = String::from_utf8_lossy(rest).trim().to_string();
            if let Ok(id) = gix::hash::ObjectId::from_hex(hex.as_bytes()) {
                out.push(id);
            }
        }
    }
    out
}

fn subject_of(raw: &[u8]) -> String {
    if let Some(pos) = raw.windows(2).position(|w| w == b"\n\n") {
        let body = &raw[pos + 2..];
        let line = body.split_inclusive(|b| *b == b'\n').next().unwrap_or(b"");
        return String::from_utf8_lossy(line).trim().to_string();
    }
    String::new()
}
