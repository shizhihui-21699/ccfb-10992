//! The audit engine: walk branches, deduplicate commits, verify each signature
//! once, and assemble a report.
//!
//! Design notes that matter for correctness:
//!
//! * **Deduplication.** A commit reachable from several branches is verified
//!   once; branch membership is recorded separately. This keeps the audit cheap
//!   without double-counting in the summary.
//! * **Merges and rebases need no special casing.** Verification is per object:
//!   a merge commit with two parents has its own signature checked like any
//!   other commit, and a rebased commit is simply a new object with its own
//!   signature (or lack of one). What does need care is *branch membership*:
//!   a rebase leaves the old commits unreachable from any branch, so they are
//!   not audited unless `--unreachable` is passed. Truncated history (shallow
//!   clones, missing parents) is counted and reported rather than silently
//!   dropped.
//! * **Two phases.** Object reading needs the libgit2 repository handle, which
//!   is not `Sync`; verification needs the external tools and is trivially
//!   parallel. So phase one reads everything serially into memory, phase two
//!   verifies with a rayon pool. That also keeps `gpg` process spawning from
//!   fighting the object database over the repo handle.
//! * **Time.** Each signature is judged against the commit's own committer
//!   timestamp by default, so a key that expired later does not retroactively
//!   invalidate history.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Mutex;

use git2::{Oid, Repository};
use rayon::prelude::*;

use crate::config::{Config, GpgTimeMode, SshTimeMode};
use crate::gpg::{GpgStatus, GpgVerifier};
use crate::ident::Ident;
use crate::keys::{KeyStore, KeyTimeStatus};
use crate::model::{
    AuditRecord, BranchReport, ObjectKind, Report, RepositoryInfo, Summary, ToolInfo, Verdict,
};
use crate::object::{
    parse_commit, parse_tag, HashAlgorithm, ParsedCommit, ParsedTag, SignatureFormat,
};
use crate::sigmeta::{self, SignatureMeta};
use crate::ssh::{SshStatus, SshVerifier};

/// A commit or tag queued for verification.
#[derive(Debug, Clone)]
struct WorkItem {
    oid: String,
    kind: ObjectKind,
    tag_name: Option<String>,
    branches: Vec<String>,
}

pub struct Auditor<'a> {
    repo: &'a Repository,
    verifier: Verifier,
}

/// Signature verification, decoupled from the repository so it can run on many
/// threads. This is the only part that shells out to gpg/ssh-keygen.
pub struct Verifier {
    config: Config,
    gpg: GpgVerifier,
    ssh: SshVerifier,
    keys: Mutex<KeyStore>,
    warnings: Mutex<Vec<String>>,
}

/// Everything the CLI can tune.
#[derive(Debug, Clone, Default)]
pub struct Options {
    /// Branch globs (`main`, `refs/heads/*`, ...).
    pub branches: Vec<String>,
    /// Also audit annotated tags.
    pub include_tags: bool,
    /// Audit commits reachable from no branch (e.g. pre-rebase history).
    pub include_unreachable: bool,
    /// Cap the number of commits per branch, newest first (0 = no cap).
    pub max_commits: usize,
    /// Threads for signature verification.
    pub jobs: usize,
}

impl<'a> Auditor<'a> {
    pub fn new(repo: &'a Repository, config: Config) -> Self {
        let verifier = Verifier::new(config);
        Auditor { repo, verifier }
    }

    pub fn run(&self, options: &Options) -> Report {
        let generated_at_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let generated_at = chrono::DateTime::from_timestamp(generated_at_unix, 0)
            .map(|d| d.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
            .unwrap_or_default();

        let algo = self.hash_algorithm();
        let mut incomplete_history = 0u64;

        // ---- Phase 1a: enumerate branches and their commits. ----
        let branches = self.selected_branches(options);
        let mut oid_branches: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut branch_reports: Vec<BranchReport> = Vec::new();
        for (name, tip) in &branches {
            let branch_oids =
                match self.walk_branch(*tip, options.max_commits, &mut incomplete_history) {
                    Ok(oids) => oids,
                    Err(e) => {
                        self.verifier
                            .warn(format!("could not walk branch {name}: {e}"));
                        Vec::new()
                    }
                };
            branch_reports.push(BranchReport {
                name: name.clone(),
                tip: tip.to_string(),
                commits: branch_oids.len() as u64,
                summary: Summary::default(),
            });
            for oid in branch_oids {
                oid_branches.entry(oid).or_default().push(name.clone());
            }
        }

        let mut work: Vec<WorkItem> = oid_branches
            .iter()
            .map(|(oid, branches)| WorkItem {
                oid: oid.clone(),
                kind: ObjectKind::Commit,
                tag_name: None,
                branches: branches.clone(),
            })
            .collect();

        // ---- Phase 1b: annotated tags. ----
        if options.include_tags {
            work.extend(self.tagged_objects());
        }

        // ---- Phase 1c: unreachable (e.g. pre-rebase) commits, on request. ----
        if options.include_unreachable {
            let extra = self.unreachable_commits(options.max_commits);
            self.verifier.warn(format!(
                "--unreachable: auditing {} commit(s) not reachable from any branch, tag or HEAD",
                extra.len()
            ));
            work.extend(extra.into_iter().map(|oid| WorkItem {
                oid,
                kind: ObjectKind::Commit,
                tag_name: None,
                branches: Vec::new(),
            }));
        }

        // Each item is read, verified, and its bytes dropped, so memory use is
        // bounded by the number of workers rather than by repository size.
        //
        // A libgit2 repository handle is not `Sync`, so workers cannot share
        // one. Instead the work is split into chunks and each chunk opens its
        // own read-only handle: few opens in total, and no shared mutable state.
        let jobs = if options.jobs > 0 {
            options.jobs
        } else {
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(4)
        };

        let repo_path = self.repo.path().to_path_buf();
        // Bind the verifier and path to locals so the closure captures only
        // `Sync` data instead of the `Auditor`, which holds the repository.
        let verifier = &self.verifier;
        let verify_chunk = |chunk: &[WorkItem]| -> Vec<AuditRecord> {
            let repo = match Repository::open(&repo_path) {
                Ok(r) => r,
                Err(e) => {
                    verifier.warn(format!("could not open the object database: {e}"));
                    return Vec::new();
                }
            };
            chunk
                .iter()
                .filter_map(|item| {
                    let odb = match repo.odb() {
                        Ok(o) => o,
                        Err(e) => {
                            verifier.warn(format!("could not open the object database: {e}"));
                            return None;
                        }
                    };
                    let oid = match Oid::from_str(&item.oid) {
                        Ok(o) => o,
                        Err(e) => {
                            verifier.warn(format!("invalid object id {}: {e}", item.oid));
                            return None;
                        }
                    };
                    let obj = match odb.read(oid) {
                        Ok(o) => o,
                        Err(e) => {
                            verifier.warn(format!("could not read object {}: {e}", item.oid));
                            return None;
                        }
                    };
                    // Trust the object database's own type over the ref spelling.
                    let kind = match obj.kind() {
                        git2::ObjectType::Tag => ObjectKind::Tag,
                        _ => item.kind,
                    };
                    let item = WorkItem {
                        kind,
                        ..item.clone()
                    };
                    Some(verifier.audit(&item, obj.data(), algo))
                })
                .collect()
        };

        let chunk_size = work.len().div_ceil(jobs.max(1)).max(64);
        let records: Vec<AuditRecord> = work
            .par_chunks(chunk_size)
            .flat_map_iter(verify_chunk)
            .collect();

        // ---- Assemble summaries. ----
        let mut summary = Summary::default();
        let mut by_format: BTreeMap<String, Summary> = BTreeMap::new();
        for r in &records {
            summary.record(r.verdict);
            let fmt = r
                .signature_format
                .clone()
                .unwrap_or_else(|| "none".to_string());
            by_format.entry(fmt).or_default().record(r.verdict);
        }

        // A commit in N branches counts once per branch in that branch's own
        // summary, but exactly once overall.
        let mut branch_summaries: HashMap<String, Summary> = HashMap::new();
        for r in &records {
            for b in &r.branches {
                branch_summaries
                    .entry(b.clone())
                    .or_default()
                    .record(r.verdict);
            }
        }
        for br in &mut branch_reports {
            br.summary = branch_summaries.remove(&br.name).unwrap_or_default();
        }

        let mut records = records;
        records.sort_by(|a, b| {
            a.verdict
                .sort_rank()
                .cmp(&b.verdict.sort_rank())
                .then_with(|| b.signed_at.cmp(&a.signed_at))
                .then_with(|| a.oid.cmp(&b.oid))
        });

        let repository = RepositoryInfo {
            path: self.repo.path().display().to_string(),
            workdir: self.repo.workdir().map(|p| p.display().to_string()),
            hash_algorithm: algo.name().to_string(),
            shallow: self.repo.is_shallow(),
            incomplete_history,
        };

        if self.verifier.config().allowed_signers.is_none() {
            self.verifier.warn(
                "gpg.ssh.allowedSignersFile is not configured: SSH commits will be reported as \
                 signer_not_allowed even when the signature is cryptographically valid"
                    .to_string(),
            );
        }
        if incomplete_history > 0 {
            self.verifier.warn(format!(
                "history is incomplete ({incomplete_history} commit(s) had missing parents, \
                 typical of a shallow clone); results cover only the objects present"
            ));
        }

        Report {
            tool: ToolInfo {
                name: env!("CARGO_PKG_NAME").to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
            },
            generated_at,
            generated_at_unix,
            repository,
            summary,
            branches: branch_reports,
            records,
            warnings: self.verifier.take_warnings(),
            by_format,
        }
    }

    fn hash_algorithm(&self) -> HashAlgorithm {
        // git records the object format as `extensions.objectFormat`; libgit2
        // exposes no direct accessor, so read the repository config the same
        // way git does. Anything but the literal "sha256" is sha1.
        if let Ok(cfg) = self.repo.config() {
            if let Ok(fmt) = cfg.get_string("extensions.objectFormat") {
                if fmt.eq_ignore_ascii_case("sha256") {
                    return HashAlgorithm::Sha256;
                }
            }
        }
        HashAlgorithm::Sha1
    }

    /// Resolve the branch selection into (short name, tip oid).
    fn selected_branches(&self, options: &Options) -> Vec<(String, Oid)> {
        let mut out: Vec<(String, Oid)> = Vec::new();
        let Ok(refs) = self.repo.references() else {
            return out;
        };
        let mut names: Vec<String> = Vec::new();
        for r in refs.flatten() {
            let Some(name) = r.name() else { continue };
            if !name.starts_with("refs/heads/") && !name.starts_with("refs/remotes/") {
                continue;
            }
            // Skip the symbolic `refs/remotes/<remote>/HEAD`.
            if name.starts_with("refs/remotes/") && name.ends_with("/HEAD") {
                continue;
            }
            names.push(name.to_string());
        }
        names.sort();
        for full in names {
            let short = full
                .strip_prefix("refs/heads/")
                .or_else(|| full.strip_prefix("refs/remotes/"))
                .unwrap_or(&full)
                .to_string();
            if !options.branches.is_empty() && !matches_any(&short, &full, &options.branches) {
                continue;
            }
            let Ok(reference) = self.repo.find_reference(&full) else {
                continue;
            };
            let Ok(commit) = reference.peel_to_commit() else {
                continue;
            };
            out.push((short, commit.id()));
        }
        out
    }

    /// Walk a branch tip, newest first, following all parents.
    ///
    /// The frontier is a max-heap keyed by committer time, which is what
    /// `git rev-list` does by default. That matters for `--max-commits`: taking
    /// the N newest commits requires visiting in time order, not arbitrary DFS
    /// order. The result is complete and deterministic, and every commit
    /// reachable from the tip appears exactly once.
    fn walk_branch(
        &self,
        tip: Oid,
        max_commits: usize,
        incomplete: &mut u64,
    ) -> Result<Vec<String>, git2::Error> {
        use std::cmp::Reverse;
        use std::collections::BinaryHeap;

        // Frontier ordering, newest first:
        //   1. committer time, descending;
        //   2. graph distance from the tip, ascending, so that among commits
        //      with the same timestamp the ones closer to the tip come first
        //      (this is the intuitive meaning of "the newest N");
        //   3. object id, for a total and reproducible order.
        // A `BinaryHeap` is a max-heap, so fields that should sort ascending are
        // wrapped in `Reverse`.
        let mut frontier: BinaryHeap<(i64, Reverse<usize>, Reverse<Oid>)> = BinaryHeap::new();
        let mut seen: HashSet<Oid> = HashSet::new();
        let mut out: Vec<String> = Vec::new();

        let tip_time = self
            .repo
            .find_commit(tip)
            .map(|c| c.time().seconds())
            .unwrap_or(0);
        frontier.push((tip_time, Reverse(0), Reverse(tip)));

        while let Some((_, Reverse(depth), Reverse(oid))) = frontier.pop() {
            if !seen.insert(oid) {
                continue;
            }
            let kind = match self.repo.odb().and_then(|odb| odb.read_header(oid)) {
                Ok((_, kind)) => kind,
                Err(_) => {
                    *incomplete += 1;
                    continue;
                }
            };
            if kind != git2::ObjectType::Commit {
                continue;
            }
            out.push(oid.to_string());
            if max_commits > 0 && out.len() >= max_commits {
                break;
            }
            match self.repo.find_commit(oid) {
                Ok(commit) => {
                    for parent in commit.parent_ids() {
                        if seen.contains(&parent) {
                            continue;
                        }
                        let when = self
                            .repo
                            .find_commit(parent)
                            .map(|p| p.time().seconds())
                            .unwrap_or(0);
                        frontier.push((when, Reverse(depth + 1), Reverse(parent)));
                    }
                }
                Err(_) => *incomplete += 1,
            }
        }
        Ok(out)
    }

    /// Annotated tags selected for auditing.
    fn tagged_objects(&self) -> Vec<WorkItem> {
        let mut out = Vec::new();
        let Ok(refs) = self.repo.references() else {
            return out;
        };
        let mut tag_refs: Vec<(String, Oid)> = Vec::new();
        for r in refs.flatten() {
            let Some(name) = r.name() else { continue };
            if !name.starts_with("refs/tags/") {
                continue;
            }
            let short = name.trim_start_matches("refs/tags/").to_string();
            if let Some(target) = r.target() {
                tag_refs.push((short, target));
            }
        }
        tag_refs.sort();
        for (short, oid) in tag_refs {
            // Only annotated tags are tag objects; lightweight tags point at
            // commits and are already covered by branch history.
            let Ok((_, kind)) = self.repo.odb().and_then(|odb| odb.read_header(oid)) else {
                continue;
            };
            if kind == git2::ObjectType::Tag {
                out.push(WorkItem {
                    oid: oid.to_string(),
                    kind: ObjectKind::Tag,
                    tag_name: Some(short),
                    branches: Vec::new(),
                });
            }
        }
        out
    }

    /// Commits that no selected branch or tag reaches.
    ///
    /// These are the leftovers of a rebase, an amended commit, or local work on
    /// a detached HEAD. They are still real objects in the database, so a
    /// signature gate that only looked at branch tips would never see them.
    ///
    /// Implementation: reverse-walk from every ref in the repository (branches,
    /// tags, notes, stash, remotes) to establish the reachable set, then report
    /// commit objects outside it. `max_commits` caps the result, not the scan,
    /// because stopping the scan early would make the reachable set
    /// inconsistent; the cap is applied after sorting so the choice is stable.
    fn unreachable_commits(&self, max_commits: usize) -> Vec<String> {
        let mut reachable: HashSet<String> = HashSet::new();
        if let Ok(refs) = self.repo.references() {
            for r in refs.flatten() {
                let Some(target) = r.target() else { continue };
                // Peel annotated tags and walk everything the ref can reach.
                for oid in self.walk_all(target) {
                    reachable.insert(oid);
                }
            }
        }
        // HEAD itself may point at an otherwise-unreferenced commit.
        if let Ok(head) = self.repo.head() {
            if let Some(target) = head.target() {
                for oid in self.walk_all(target) {
                    reachable.insert(oid);
                }
            }
        }

        let mut out: Vec<String> = Vec::new();
        let Ok(odb) = self.repo.odb() else {
            return out;
        };
        let _ = odb.foreach(|oid| {
            if let Ok((_, kind)) = odb.read_header(*oid) {
                if kind == git2::ObjectType::Commit {
                    let s = oid.to_string();
                    if !reachable.contains(&s) {
                        out.push(s);
                    }
                }
            }
            true
        });
        out.retain(|oid| oid.len() <= 64);
        out.sort();
        out.dedup();
        if max_commits > 0 {
            out.truncate(max_commits);
        }
        out
    }

    /// Every object reachable from `start`: commits, their trees and blobs, and
    /// tag targets. Used only to compute the "reachable" set.
    fn walk_all(&self, start: Oid) -> Vec<String> {
        let mut out = Vec::new();
        let mut seen: HashSet<Oid> = HashSet::new();
        let mut stack = vec![start];
        while let Some(oid) = stack.pop() {
            if !seen.insert(oid) {
                continue;
            }
            out.push(oid.to_string());
            let Ok(obj) = self.repo.find_object(oid, None) else {
                continue;
            };
            match obj.kind() {
                Some(git2::ObjectType::Tag) => {
                    // Annotated tag: follow its target, which may itself be a tag.
                    if let Some(tag) = obj.as_tag() {
                        if let Ok(target) = tag.target() {
                            stack.push(target.id());
                        }
                    }
                }
                Some(git2::ObjectType::Commit) => {
                    if let Some(commit) = obj.as_commit() {
                        for parent in commit.parent_ids() {
                            stack.push(parent);
                        }
                        stack.push(commit.tree_id());
                    }
                }
                Some(git2::ObjectType::Tree) => {
                    if let Some(tree) = obj.as_tree() {
                        for entry in tree.iter() {
                            stack.push(entry.id());
                        }
                    }
                }
                _ => {}
            }
        }
        out
    }
}

impl Verifier {
    pub fn new(config: Config) -> Self {
        let gpg = GpgVerifier::new(config.gpg_program.clone(), config.effective_gpg_home());
        let mut ssh = SshVerifier::new(config.ssh_program.clone());
        ssh.allowed_signers = config
            .allowed_signers
            .as_ref()
            .map(|p| p.display().to_string());
        ssh.revocation_file = config
            .revocation_file
            .as_ref()
            .map(|p| p.display().to_string());
        let keys = KeyStore::new(&gpg);
        Verifier {
            config,
            gpg,
            ssh,
            keys: Mutex::new(keys),
            warnings: Mutex::new(Vec::new()),
        }
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    pub fn warn(&self, message: impl Into<String>) {
        if let Ok(mut w) = self.warnings.lock() {
            let message = message.into();
            if !w.contains(&message) {
                w.push(message);
            }
        }
    }

    fn take_warnings(&self) -> Vec<String> {
        self.warnings
            .lock()
            .map(|mut w| std::mem::take(&mut *w))
            .unwrap_or_default()
    }

    fn audit(&self, item: &WorkItem, raw: &[u8], algo: HashAlgorithm) -> AuditRecord {
        match item.kind {
            ObjectKind::Commit => self.audit_commit(raw, item, algo),
            ObjectKind::Tag => {
                let tag: ParsedTag = parse_tag(raw, item.oid.clone());
                self.audit_tag(&tag, item, algo)
            }
        }
    }

    fn audit_commit(&self, raw: &[u8], item: &WorkItem, algo: HashAlgorithm) -> AuditRecord {
        let commit: ParsedCommit = parse_commit(raw, item.oid.clone(), algo);
        let committer = commit.committer.as_deref().and_then(Ident::parse);
        let author = commit.author.as_deref().and_then(Ident::parse);
        let signed_at = committer
            .as_ref()
            .map(|c| c.timestamp)
            .or_else(|| author.as_ref().map(|a| a.timestamp))
            .unwrap_or(0);

        let mut record = base_record(item, signed_at);
        record.author = commit.author.clone();
        record.committer = commit.committer.clone();
        record.parents = commit.parents.len();
        record.is_merge = commit.is_merge();

        let Some(signature) = commit.signature.as_deref() else {
            record.detail = Some("commit has no gpgsig header".to_string());
            return record;
        };
        self.verify_envelope(&mut record, signature, &commit.payload, signed_at, algo);
        record
    }

    fn audit_tag(&self, tag: &ParsedTag, item: &WorkItem, algo: HashAlgorithm) -> AuditRecord {
        let tagger = tag.tagger.as_deref().and_then(Ident::parse);
        let signed_at = tagger.as_ref().map(|t| t.timestamp).unwrap_or(0);
        let mut record = base_record(item, signed_at);
        record.tag = item.tag_name.clone().or_else(|| tag.tag_name.clone());
        record.author = tag.tagger.clone();
        record.committer = tag.tagger.clone();

        let Some(signature) = tag.signature.as_deref() else {
            record.detail = Some("annotated tag has no signature".to_string());
            return record;
        };
        self.verify_envelope(&mut record, signature, &tag.payload, signed_at, algo);
        record
    }

    /// Shared signature verification for commits and tags.
    fn verify_envelope(
        &self,
        record: &mut AuditRecord,
        signature: &[u8],
        payload: &[u8],
        commit_time: i64,
        algo: HashAlgorithm,
    ) {
        let meta: SignatureMeta = sigmeta::parse(signature);
        record.signature_format = Some(meta.format.as_str().to_string());
        record.signature_created_at = meta.signature_created_at();

        match meta.format {
            SignatureFormat::OpenPgp => {
                self.verify_openpgp(record, signature, payload, commit_time, algo, &meta)
            }
            SignatureFormat::Ssh => self.verify_ssh(record, signature, payload, commit_time, &meta),
            SignatureFormat::X509 => {
                record.verdict = Verdict::Error;
                record.detail =
                    Some("X.509 (gpgsm) signatures are not supported by this audit".to_string());
            }
            SignatureFormat::Unknown => {
                record.verdict = Verdict::BadSignature;
                record.detail = Some(
                    "signature is not a recognised OpenPGP or SSH signature envelope".to_string(),
                );
            }
        }
        record.git_letter = record.verdict.letter();
    }

    fn verify_openpgp(
        &self,
        record: &mut AuditRecord,
        signature: &[u8],
        payload: &[u8],
        commit_time: i64,
        algo: HashAlgorithm,
        meta: &SignatureMeta,
    ) {
        // Several signature packets in one envelope is exactly what git's
        // `parse_gpg_output()` refuses (it rejects multiple exclusive statuses).
        if let Some(pgp) = &meta.pgp {
            if pgp.signature_packets > 1 {
                record.verdict = Verdict::BadSignature;
                record.detail = Some(format!(
                    "signature contains {} signature packets; git rejects multiple signatures",
                    pgp.signature_packets
                ));
                return;
            }
        }

        let sig_time = meta.signature_created_at().unwrap_or(commit_time);
        let at_time = match self.config.gpg_time_mode {
            GpgTimeMode::Now => None,
            GpgTimeMode::Committer => Some(commit_time),
            GpgTimeMode::Signature => Some(sig_time),
        };

        let status = self.gpg.verify(signature, payload, at_time, algo);
        record.signer = status.signer.clone();
        record.fingerprint = status.fingerprint.clone();
        record.key_expires_at = status.key_expired_at;

        self.classify_gpg(record, &status, commit_time, at_time.is_some());
    }

    fn classify_gpg(
        &self,
        record: &mut AuditRecord,
        status: &GpgStatus,
        commit_time: i64,
        using_faked_time: bool,
    ) {
        // Several exclusive statuses mean gpg saw more than one signature in
        // the envelope. git's parse_gpg_output() jumps to its error path there:
        // it sets the result to 'E' and clears every field, which is exactly
        // what git then reports as `%G? == E`. Reproduce that rather than
        // calling it a bad signature.
        if status.exclusive_statuses > 1 {
            record.verdict = Verdict::Error;
            record.signer = None;
            record.fingerprint = None;
            record.key_expires_at = None;
            record.detail = Some(format!(
                "the signature envelope contains {} signature packets; git rejects multiple \
                 signatures as unverifiable",
                status.exclusive_statuses
            ));
            return;
        }
        // This tool applies git's `check_signature()` rule: the result must be
        // G, exactly one exclusive status seen, and the trust level must meet
        // gpg.minTrustLevel (unset = no constraint).
        //
        // Note the deliberate divergence from `git log --format=%G?`, which
        // renders a good signature as `U` whenever gpg reports TRUST_UNDEFINED
        // (i.e. the key has no trust assigned in the local keyring). That word
        // means "unknown validity" in gpg's vocabulary, not "signer not
        // allowed", so it does not make an otherwise valid signature fail here.
        // `git verify-commit` agrees: it exits 0 in exactly that case.
        let trust_ok = match self.config.min_trust_level {
            None => true,
            Some(min) => status.trust_level.map(|t| t >= min).unwrap_or(false),
        };

        match status.result {
            Some('G') if status.exclusive_statuses == 1 => {
                if trust_ok {
                    record.verdict = Verdict::Good;
                } else {
                    record.verdict = Verdict::SignerNotAllowed;
                    record.detail = Some(format!(
                        "signature is valid but its trust level ({}) is below gpg.minTrustLevel ({})",
                        status.trust_level.map(|t| t.as_str()).unwrap_or("undefined"),
                        self.config
                            .min_trust_level
                            .map(|t| t.as_str())
                            .unwrap_or("undefined")
                    ));
                }
            }
            Some('Y') | Some('X') => {
                record.verdict = Verdict::KeyExpiredAtCommit;
                record.detail =
                    Some(self.explain_expiry(record, status, commit_time, using_faked_time));
            }
            Some('R') => {
                record.verdict = Verdict::KeyRevokedAtCommit;
                record.detail = Some(self.explain_revocation(record, status, commit_time));
            }
            Some('B') => {
                record.verdict = Verdict::BadSignature;
                record.detail = Some("signature does not match the signed content".to_string());
            }
            Some('E') => {
                record.verdict = Verdict::UnknownKey;
                record.detail = Some(if status.key.is_some() {
                    "public key for this signature is not available in the gpg keyring".to_string()
                } else {
                    first_stderr_line(&status.stderr)
                        .unwrap_or_else(|| "gpg could not verify the signature".to_string())
                });
            }
            _ => {
                // No recognised signature status at all: gpg failed before it
                // reached the signature (malformed armor, unreadable input, or
                // the binary could not be run).
                record.verdict = if status.stderr.contains("could not run") {
                    Verdict::Error
                } else {
                    Verdict::BadSignature
                };
                record.detail = Some(first_stderr_line(&status.stderr).unwrap_or_else(|| {
                    "gpg produced no signature status for this object".to_string()
                }));
            }
        }
    }

    fn explain_expiry(
        &self,
        record: &AuditRecord,
        status: &GpgStatus,
        commit_time: i64,
        using_faked_time: bool,
    ) -> String {
        let mut parts = vec!["gpg reports the signing key as expired".to_string()];
        if let Some(exp) = status.key_expired_at {
            parts.push(format!("key expiry was {}", format_utc(exp)));
            if commit_time > exp {
                parts.push(format!(
                    "the commit itself is dated {} (after that expiry)",
                    format_utc(commit_time)
                ));
            } else {
                parts.push(format!(
                    "the commit is dated {}, before that expiry",
                    format_utc(commit_time)
                ));
            }
        }
        if using_faked_time {
            parts.push(format!(
                "gpg was asked about {} (the commit's own time)",
                format_utc(commit_time)
            ));
        } else {
            parts.push(
                "gpg was asked about the current time; rerun with --gpg-time=committer to judge \
                 the key as it was when the commit was made"
                    .to_string(),
            );
        }
        if record.fingerprint.is_some() && status.key_expired_at.is_none() {
            parts.push("gpg did not report an expiry timestamp for the key".to_string());
        }
        parts.join("; ")
    }

    fn explain_revocation(
        &self,
        record: &AuditRecord,
        _status: &GpgStatus,
        commit_time: i64,
    ) -> String {
        let mut parts = vec!["the signing key is revoked in the local keyring".to_string()];
        if let Some(fpr) = &record.fingerprint {
            if let Ok(mut keys) = self.keys.lock() {
                if let Some(key) = keys.get(fpr) {
                    if let Some(revoked_at) = key.revoked_at {
                        parts.push(format!(
                            "revocation certificate issued {}",
                            format_utc(revoked_at)
                        ));
                        if commit_time < revoked_at {
                            parts.push(format!(
                                "the commit predates the revocation ({}) but gpg applies \
                                 revocations regardless of signature time",
                                format_utc(commit_time)
                            ));
                        }
                    }
                }
            }
        }
        parts.join("; ")
    }

    fn verify_ssh(
        &self,
        record: &mut AuditRecord,
        signature: &[u8],
        payload: &[u8],
        commit_time: i64,
        meta: &SignatureMeta,
    ) {
        // Keyless check first: the SSHSIG namespace must be "git". This gives a
        // precise diagnostic even on a machine without ssh-keygen.
        if let Some(ssh) = &meta.ssh {
            if let Some(ns) = &ssh.namespace {
                if ns != "git" {
                    record.verdict = Verdict::BadSignature;
                    record.detail = Some(format!(
                        "SSH signature namespace is {ns:?}, expected \"git\""
                    ));
                    return;
                }
            }
        }

        let at_time = match self.config.ssh_time_mode {
            SshTimeMode::Committer => Some(commit_time),
            SshTimeMode::Now => None,
        };
        let status: SshStatus = self.ssh.verify(signature, payload, at_time);
        record.signer = status.principal.clone();
        record.fingerprint = status.fingerprint.clone();
        self.classify_ssh(record, &status, commit_time, at_time.is_some());
    }

    fn classify_ssh(
        &self,
        record: &mut AuditRecord,
        status: &SshStatus,
        commit_time: i64,
        using_verify_time: bool,
    ) {
        use crate::ssh::SshFailure;

        record.signer = status.principal.clone();
        record.fingerprint = status.fingerprint.clone();

        if status.is_git_good() {
            record.verdict = Verdict::Good;
            return;
        }

        let at = if using_verify_time {
            format!("{} (the commit's own time)", format_utc(commit_time))
        } else {
            "the current time (use --ssh-time=committer to judge the key at the commit's time)"
                .to_string()
        };

        match status.failure {
            Some(SshFailure::NoAllowedSigners) => {
                record.verdict = Verdict::Error;
                record.detail = Some(
                    "gpg.ssh.allowedSignersFile is not configured; SSH signatures cannot be \
                     validated against a whitelist"
                        .to_string(),
                );
            }
            Some(SshFailure::KeyNotAllowed) => {
                record.verdict = Verdict::SignerNotAllowed;
                // Prefer ssh-keygen's own explanation when it identifies a
                // configuration problem (e.g. an unreadable whitelist file),
                // because that needs fixing rather than ignoring.
                record.detail = Some(status.detail.clone().unwrap_or_else(|| {
                    "signature is valid but the signing key is not listed in \
                         gpg.ssh.allowedSignersFile"
                        .to_string()
                }));
            }
            Some(SshFailure::OutsideValidityWindow) => {
                // Being outside a whitelisted key's validity window is a policy
                // finding, not tampering: the signature itself is sound.
                record.verdict = Verdict::SignerNotAllowed;
                record.detail = Some(format!(
                    "signature is valid but the key's allowed_signers valid-after/valid-before \
                     window excludes {at}"
                ));
            }
            Some(SshFailure::KeyRevoked) => {
                record.verdict = Verdict::KeyRevokedAtCommit;
                record.detail = Some(format!(
                    "the signing key is revoked by gpg.ssh.revocationFile at {at}                      (SSH has no per-signature revocation time, so the KRL applies whenever \
                     it is configured)"
                ));
            }
            Some(SshFailure::BadSignature) => {
                record.verdict = Verdict::BadSignature;
                record.detail = Some(
                    status
                        .detail
                        .clone()
                        .unwrap_or_else(|| "SSH signature did not verify".to_string()),
                );
            }
            Some(SshFailure::ToolError) => {
                record.verdict = Verdict::Error;
                record.detail = status
                    .detail
                    .clone()
                    .or_else(|| Some("ssh-keygen could not be run".to_string()));
            }
            None => {
                record.verdict = Verdict::Error;
                record.detail = Some("ssh-keygen produced no usable output".to_string());
            }
        }
    }

    #[allow(dead_code)]
    fn key_status(&self, fingerprint: &str, at: i64) -> Option<KeyTimeStatus> {
        self.keys
            .lock()
            .ok()
            .and_then(|mut k| k.get(fingerprint).map(|i| i.status_at(fingerprint, at)))
    }
}

fn base_record(item: &WorkItem, signed_at: i64) -> AuditRecord {
    AuditRecord {
        kind: item.kind,
        oid: item.oid.clone(),
        tag: item.tag_name.clone(),
        author: None,
        committer: None,
        signed_at,
        signed_at_utc: format_utc(signed_at),
        parents: 0,
        is_merge: false,
        branches: item.branches.clone(),
        signature_format: None,
        verdict: Verdict::Unsigned,
        git_letter: 'N',
        signer: None,
        fingerprint: None,
        signature_created_at: None,
        key_expires_at: None,
        detail: None,
    }
}

/// First meaningful line of a verifier's stderr.
///
/// gpg writes informational chatter (notably the `--faked-system-time` warning,
/// which is emitted in whatever locale is active) to stderr ahead of the real
/// problem. Skipping lines that are obviously that chatter keeps the report
/// focused on the actual failure.
fn first_stderr_line(stderr: &str) -> Option<String> {
    stderr
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .find(|l| {
            let lower = l.to_ascii_lowercase();
            !(lower.starts_with("gpg: ")
                && (lower.contains("faked-system-time")
                    || lower.contains("虚假")
                    || lower.contains("warning")))
        })
        .map(str::to_string)
}

pub fn format_utc(epoch: i64) -> String {
    chrono::DateTime::from_timestamp(epoch, 0)
        .map(|d| d.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
        .unwrap_or_else(|| format!("@{epoch}"))
}

/// Match a branch against user globs. Both the short (`main`) and full
/// (`refs/heads/main`) spellings are accepted.
fn matches_any(short: &str, full: &str, patterns: &[String]) -> bool {
    patterns
        .iter()
        .any(|pat| pat == short || pat == full || glob_match(pat, short) || glob_match(pat, full))
}

/// Minimal glob supporting `*` and `?`, which is all branch selection needs.
fn glob_match(pat: &str, text: &str) -> bool {
    let p: Vec<char> = pat.chars().collect();
    let t: Vec<char> = text.chars().collect();
    // Classic backtracking wildcard match.
    let (mut pi, mut ti) = (0usize, 0usize);
    let mut star: Option<(usize, usize)> = None;
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some((pi, ti));
            pi += 1;
        } else if let Some((sp, st)) = star {
            pi = sp + 1;
            ti = st + 1;
            star = Some((sp, st + 1));
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_matches_branch_names() {
        assert!(glob_match("main", "main"));
        assert!(glob_match("release/*", "release/1.0"));
        assert!(!glob_match("release/*", "main"));
        assert!(glob_match("*", "anything"));
        assert!(glob_match("fe?ture", "feature"));
        assert!(glob_match("refs/heads/*", "refs/heads/main"));
        assert!(!glob_match("release/*", "release"));
    }

    #[test]
    fn branch_selection_accepts_short_and_full_names() {
        let patterns = vec!["main".to_string()];
        assert!(matches_any("main", "refs/heads/main", &patterns));
        let patterns = vec!["refs/heads/release/*".to_string()];
        assert!(matches_any(
            "release/2.0",
            "refs/heads/release/2.0",
            &patterns
        ));
        assert!(!matches_any("dev", "refs/heads/dev", &patterns));
    }

    #[test]
    fn utc_formatting_is_stable() {
        assert_eq!(format_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_utc(1_700_000_000), "2023-11-14T22:13:20Z");
    }
}
