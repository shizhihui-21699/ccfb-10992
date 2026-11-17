//! Reading git objects directly out of the repository.
//!
//! Commits are fetched from the object database (not from `git log`) and parsed
//! by [`crate::gitparse`], so the bytes handed to the signature verifiers are
//! exactly the bytes stored in the object — including any hand-crafted or
//! rewritten history.

use crate::gitparse::{self, HashAlgo};
use anyhow::{anyhow, Context, Result};
use git2::{BranchType, ObjectType, Repository, Sort};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Which refs to audit.
#[derive(Debug, Clone)]
pub struct RefSpec {
    /// Glob patterns matched against the short branch name (`main`, `release/*`).
    pub branch_globs: Vec<String>,
    pub include_remotes: bool,
    /// Explicit refs or commit ids.
    pub explicit: Vec<String>,
}

impl Default for RefSpec {
    fn default() -> Self {
        RefSpec {
            branch_globs: vec!["*".to_string()],
            include_remotes: false,
            explicit: Vec::new(),
        }
    }
}

/// How much of the graph to follow for each branch tip.
#[derive(Debug, Clone, Default)]
pub struct WalkOptions {
    /// Follow only the first parent of merge commits.
    pub first_parent: bool,
    /// Record merge commits, or leave them out of per-branch statistics.
    pub skip_merges: bool,
    pub max_commits: Option<usize>,
    pub since: Option<i64>,
    pub until: Option<i64>,
}

/// A branch (or other ref) selected for auditing.
#[derive(Debug, Clone)]
pub struct BranchRef {
    /// Display name, e.g. `main` or `origin/main`.
    pub name: String,
    /// Full ref name, e.g. `refs/heads/main`.
    pub full_name: String,
    pub tip: ObjectId,
    pub is_remote: bool,
}

/// A git object id, which is 20 bytes in SHA-1 repositories and 32 in SHA-256
/// repositories.  libgit2 cannot open SHA-256 repositories at all, so ids are
/// kept as hex strings and only converted to `git2::Oid` for libgit2 calls.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ObjectId {
    Sha1([u8; 20]),
    Sha256([u8; 32]),
}

impl ObjectId {
    pub fn parse(hex: &str) -> Result<ObjectId> {
        match hex.len() {
            40 => {
                let mut bytes = [0u8; 20];
                hex::decode_to_slice(hex, &mut bytes)
                    .map_err(|_| anyhow!("'{hex}' is not a valid SHA-1 object id"))?;
                Ok(ObjectId::Sha1(bytes))
            }
            64 => {
                let mut bytes = [0u8; 32];
                hex::decode_to_slice(hex, &mut bytes)
                    .map_err(|_| anyhow!("'{hex}' is not a valid SHA-256 object id"))?;
                Ok(ObjectId::Sha256(bytes))
            }
            n => Err(anyhow!(
                "'{hex}' has {n} hex digits; expected 40 (SHA-1) or 64 (SHA-256)"
            )),
        }
    }

    pub fn as_hex(&self) -> String {
        match self {
            ObjectId::Sha1(b) => hex::encode(b),
            ObjectId::Sha256(b) => hex::encode(b),
        }
    }

    pub fn short(&self) -> String {
        self.as_hex()[..8].to_string()
    }

    /// The libgit2 representation, for SHA-1 repositories only.
    pub fn as_git2(self) -> Option<git2::Oid> {
        match self {
            ObjectId::Sha1(b) => git2::Oid::from_bytes(&b).ok(),
            ObjectId::Sha256(_) => None,
        }
    }
}

impl std::fmt::Display for ObjectId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.as_hex())
    }
}

/// A commit read from the object database, ready to be verified.
#[derive(Debug, Clone)]
pub struct RawCommit {
    pub oid: ObjectId,
    pub parsed: gitparse::SignedCommit,
    pub meta: gitparse::CommitMeta,
    pub is_merge: bool,
}

pub struct Repo {
    inner: Option<Repository>,
    pub path: PathBuf,
    pub hash_algo: HashAlgo,
}

impl Repo {
    /// Opens the repository at (or above) `path`.
    ///
    /// libgit2 understands SHA-1 repositories only.  When it refuses the
    /// repository, we check whether `git` itself accepts it (a SHA-256 repo,
    /// for instance) and fall back to reading objects through `git cat-file`.
    pub fn open(path: &Path) -> Result<Repo> {
        if let Ok(inner) = Repository::open(path).or_else(|_| Repository::discover(path)) {
            let hash_algo = detect_hash_algo(&inner);
            let path = inner
                .workdir()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| inner.path().to_path_buf());
            return Ok(Repo {
                inner: Some(inner),
                path,
                hash_algo,
            });
        }

        // Fall back to the git CLI, but only if git recognises the repository.
        let toplevel = Command::new("git")
            .arg("-C")
            .arg(path)
            .args(["rev-parse", "--show-toplevel"])
            .output()
            .with_context(|| format!("cannot open a git repository at {}", path.display()))?;
        if !toplevel.status.success() {
            return Err(anyhow!(
                "cannot open a git repository at {}: {}",
                path.display(),
                String::from_utf8_lossy(&toplevel.stderr).trim()
            ));
        }
        let root = PathBuf::from(String::from_utf8_lossy(&toplevel.stdout).trim());
        let fmt = Command::new("git")
            .arg("-C")
            .arg(&root)
            .args(["rev-parse", "--show-object-format"])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_else(|| "sha1".to_string());
        let hash_algo = if fmt == "sha256" {
            HashAlgo::Sha256
        } else {
            HashAlgo::Sha1
        };
        Ok(Repo {
            inner: None,
            path: root,
            hash_algo,
        })
    }

    /// Enumerates the refs selected by `spec`.
    ///
    /// Duplicate tips (e.g. two branches at the same commit) are kept as
    /// separate branches so per-branch statistics stay meaningful.
    pub fn select_refs(&self, spec: &RefSpec) -> Result<Vec<BranchRef>> {
        let mut out = Vec::new();
        if !spec.branch_globs.is_empty() {
            out.extend(self.list_branches(spec)?);
        }
        for spec_ref in &spec.explicit {
            let tip = self.resolve_ref(spec_ref)?;
            out.push(BranchRef {
                name: spec_ref.clone(),
                full_name: spec_ref.clone(),
                tip,
                is_remote: false,
            });
        }

        // The same commit can be reachable from several refs, and a ref can be
        // selected both explicitly and by glob.  Keep one entry per ref name so
        // reports never list a branch twice.
        out.sort_by(|a, b| a.full_name.cmp(&b.full_name));
        out.dedup_by(|a, b| a.full_name == b.full_name);
        out.sort_by(|a, b| a.name.cmp(&b.name));
        if out.is_empty() {
            return Err(anyhow!(
                "no branches matched; pass --branch/--ref or create a branch"
            ));
        }
        Ok(out)
    }

    fn list_branches(&self, spec: &RefSpec) -> Result<Vec<BranchRef>> {
        let mut out = Vec::new();
        if let Some(repo) = &self.inner {
            let kinds: &[BranchType] = if spec.include_remotes {
                &[BranchType::Local, BranchType::Remote]
            } else {
                &[BranchType::Local]
            };
            for &kind in kinds {
                let branches = repo
                    .branches(Some(kind))
                    .context("cannot enumerate branches")?;
                for item in branches {
                    let (branch, _) = item.context("cannot read branch")?;
                    let short = match branch.name() {
                        Ok(Some(n)) => n.to_string(),
                        // A branch name that is not valid UTF-8 cannot be matched
                        // by a glob anyway; skip it rather than mangling it.
                        _ => continue,
                    };
                    if !match_any_glob(&spec.branch_globs, &short) {
                        continue;
                    }
                    let full = branch
                        .get()
                        .name()
                        .unwrap_or(&format!("refs/heads/{short}"))
                        .to_string();
                    let commit = branch
                        .get()
                        .peel_to_commit()
                        .with_context(|| format!("branch '{short}' has no commit"))?;
                    out.push(BranchRef {
                        name: short,
                        full_name: full,
                        tip: from_git2(commit.id()),
                        is_remote: kind == BranchType::Remote,
                    });
                }
            }
            return Ok(out);
        }

        // CLI backend: ask git for refs and peel them to commits.
        let mut args = vec![
            "for-each-ref",
            "--format=%(refname)%09%(objectname)%09%(objecttype)",
        ];
        if spec.include_remotes {
            args.push("refs/heads");
            args.push("refs/remotes");
        } else {
            args.push("refs/heads");
        }
        let text = self.git_stdout(&args)?;
        for line in text.lines() {
            let mut fields = line.split('\t');
            let (full, oid, kind) = match (fields.next(), fields.next(), fields.next()) {
                (Some(f), Some(o), Some(k)) => (f, o, k),
                _ => continue,
            };
            let is_remote = full.starts_with("refs/remotes/");
            let short = if is_remote {
                full.trim_start_matches("refs/remotes/").to_string()
            } else {
                full.trim_start_matches("refs/heads/").to_string()
            };
            if !match_any_glob(&spec.branch_globs, &short) {
                continue;
            }
            // Tag refs are not branches; for-each-ref already limited the walk.
            let tip = if kind == "commit" {
                ObjectId::parse(oid)?
            } else {
                self.resolve_ref(full)?
            };
            out.push(BranchRef {
                name: short,
                full_name: full.to_string(),
                tip,
                is_remote,
            });
        }
        Ok(out)
    }

    /// Resolves a ref or revision to a commit id.
    fn resolve_ref(&self, rev: &str) -> Result<ObjectId> {
        if let Some(repo) = &self.inner {
            let obj = repo
                .revparse_single(rev)
                .with_context(|| format!("cannot resolve '{rev}'"))?;
            let commit = obj
                .peel_to_commit()
                .with_context(|| format!("'{rev}' does not point at a commit"))?;
            return Ok(from_git2(commit.id()));
        }
        let text = self.git_stdout(&["rev-parse", "--verify", &format!("{rev}^{{commit}}")])?;
        ObjectId::parse(text.trim())
    }

    /// Walks the commits reachable from `tip`, returning them newest-first.
    pub fn walk(&self, tip: ObjectId, opts: &WalkOptions) -> Result<Vec<ObjectId>> {
        let mut oids = match &self.inner {
            Some(repo) => {
                let raw_tip = tip
                    .as_git2()
                    .ok_or_else(|| anyhow!("SHA-256 object ids need the git CLI backend"))?;
                let mut walk = repo.revwalk().context("cannot create revwalk")?;
                walk.set_sorting(Sort::TOPOLOGICAL | Sort::TIME)
                    .context("cannot configure revwalk")?;
                if opts.first_parent {
                    walk.simplify_first_parent()
                        .context("cannot enable first-parent walk")?;
                }
                walk.push(raw_tip)
                    .with_context(|| format!("cannot walk from {tip}"))?;
                let mut out = Vec::new();
                for step in walk {
                    let oid = step.with_context(|| format!("cannot walk history below {tip}"))?;
                    out.push(from_git2(oid));
                }
                out
            }
            None => {
                let mut args = vec!["rev-list".to_string()];
                if opts.first_parent {
                    args.push("--first-parent".to_string());
                }
                args.push(tip.as_hex());
                let text = self.git_stdout_owned(&args)?;
                text.lines()
                    .filter(|l| !l.trim().is_empty())
                    .map(|l| ObjectId::parse(l.trim()))
                    .collect::<Result<Vec<_>>>()?
            }
        };

        // Apply the filters that need commit metadata.  Doing it after the walk
        // keeps both backends identical.
        if opts.since.is_some() || opts.until.is_some() || opts.skip_merges {
            let mut kept = Vec::with_capacity(oids.len());
            for oid in oids.drain(..) {
                let commit = self.read_commit(oid)?;
                if opts.skip_merges && commit.is_merge {
                    continue;
                }
                if let Some(since) = opts.since {
                    if commit.parsed.commit_time.is_some_and(|t| t < since) {
                        continue;
                    }
                }
                if let Some(until) = opts.until {
                    if commit.parsed.commit_time.is_some_and(|t| t > until) {
                        continue;
                    }
                }
                kept.push(oid);
            }
            oids = kept;
        }

        if let Some(limit) = opts.max_commits {
            oids.truncate(limit);
        }
        Ok(oids)
    }

    /// Reads a commit's raw object bytes and splits them like git does.
    pub fn read_commit(&self, oid: ObjectId) -> Result<RawCommit> {
        let raw = match (&self.inner, oid.as_git2()) {
            (Some(repo), Some(raw_oid)) => {
                let odb = repo.odb().context("cannot open the object database")?;
                let obj = odb
                    .read(raw_oid)
                    .with_context(|| format!("cannot read object {oid}"))?;
                if obj.kind() != ObjectType::Commit {
                    return Err(anyhow!("object {oid} is not a commit"));
                }
                obj.data().to_vec()
            }
            // SHA-256 ids, or a repository libgit2 refused: shell out to git.
            _ => {
                let out = Command::new("git")
                    .arg("-C")
                    .arg(&self.path)
                    .args(["cat-file", "commit", &oid.as_hex()])
                    .output()
                    .with_context(|| format!("cannot run git cat-file for {oid}"))?;
                if !out.status.success() {
                    return Err(anyhow!(
                        "cannot read object {oid}: {}",
                        String::from_utf8_lossy(&out.stderr).trim()
                    ));
                }
                out.stdout
            }
        };
        let parsed = gitparse::parse_commit(&raw, self.hash_algo);
        let meta = gitparse::parse_meta(&parsed.payload);
        let is_merge = meta.parents.len() > 1;
        Ok(RawCommit {
            oid,
            parsed,
            meta,
            is_merge,
        })
    }

    fn git_stdout(&self, args: &[&str]) -> Result<String> {
        let owned: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        self.git_stdout_owned(&owned)
    }

    fn git_stdout_owned(&self, args: &[String]) -> Result<String> {
        let out = Command::new("git")
            .arg("-C")
            .arg(&self.path)
            .args(args)
            .output()
            .with_context(|| format!("cannot run git {}", args.join(" ")))?;
        if !out.status.success() {
            return Err(anyhow!(
                "git {} failed: {}",
                args.join(" "),
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        Ok(String::from_utf8_lossy(&out.stdout).to_string())
    }
}

/// Converts a libgit2 OID into our id type.
fn from_git2(oid: git2::Oid) -> ObjectId {
    let mut bytes = [0u8; 20];
    bytes.copy_from_slice(oid.as_bytes());
    ObjectId::Sha1(bytes)
}

fn match_any_glob(globs: &[String], name: &str) -> bool {
    globs.iter().any(|g| crate::ssh::glob_match(g, name))
}

/// Determines the repository's object format.
///
/// Git records SHA-256 repositories as `extensions.objectFormat = sha256`;
/// anything else is SHA-1.
fn detect_hash_algo(repo: &Repository) -> HashAlgo {
    if let Ok(cfg) = repo.config() {
        if let Ok(fmt) = cfg.get_string("extensions.objectformat") {
            if fmt.eq_ignore_ascii_case("sha256") {
                return HashAlgo::Sha256;
            }
        }
    }
    HashAlgo::Sha1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_id_round_trips_both_formats() {
        let sha1 = ObjectId::parse("4b825dc642cb6eb9a060e54bf8d69288fbee4904").unwrap();
        assert_eq!(sha1.as_hex(), "4b825dc642cb6eb9a060e54bf8d69288fbee4904");
        assert_eq!(sha1.short(), "4b825dc6");
        assert!(sha1.as_git2().is_some());

        let hex64 = "a".repeat(64);
        let sha256 = ObjectId::parse(&hex64).unwrap();
        assert_eq!(sha256.as_hex(), hex64);
        // libgit2 cannot represent SHA-256 ids.
        assert!(sha256.as_git2().is_none());
    }

    #[test]
    fn object_id_rejects_bad_length_and_junk() {
        assert!(ObjectId::parse("abc").is_err());
        assert!(ObjectId::parse(&"z".repeat(40)).is_err());
    }
}
