//! Reads commit objects directly from the git object database and splits
//! off the `gpgsig` header, reconstructing the exact payload bytes that
//! were signed (the commit object with the signature header removed).

use anyhow::{Context, Result};
use git2::{BranchType, ObjectType, Oid, Repository, Sort};
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigKind {
    Gpg,
    Ssh,
}

#[derive(Debug)]
pub struct Signature {
    pub kind: SigKind,
    /// Armored signature text exactly as stored in the header.
    pub armored: String,
    /// Commit object bytes with the signature header removed (what was signed).
    pub payload: Vec<u8>,
}

#[derive(Debug)]
pub struct CommitInfo {
    pub oid: Oid,
    pub parents: Vec<Oid>,
    pub author: String,
    pub committer_email: String,
    pub commit_time: i64,
    pub subject: String,
    pub signature: Option<Signature>,
}

impl CommitInfo {
    pub fn is_merge(&self) -> bool {
        self.parents.len() > 1
    }
}

pub struct Collected {
    /// ref/branch name -> commit oids reachable from its tip (topo+time order).
    pub branches: BTreeMap<String, Vec<Oid>>,
    /// oid -> parsed commit (deduplicated across branches).
    pub commits: BTreeMap<Oid, CommitInfo>,
}

/// Walk every local branch (or every ref with `all_refs`) and parse each
/// reachable commit object from the ODB. Merge commits are ordinary commits
/// with >1 parent and are visited like any other; commits left behind by a
/// rebase are still audited as long as some ref reaches them.
pub fn collect(repo_path: &Path, all_refs: bool) -> Result<Collected> {
    let repo = Repository::open(repo_path)
        .with_context(|| format!("cannot open repository at {}", repo_path.display()))?;

    let mut tips: Vec<(String, Oid)> = Vec::new();
    if all_refs {
        for reference in repo.references()? {
            let reference = reference?;
            let Some(name) = reference.name() else { continue };
            if name == "refs/HEAD" {
                continue;
            }
            if let Ok(commit) = reference.peel_to_commit() {
                tips.push((name.to_string(), commit.id()));
            }
        }
    } else {
        for branch in repo.branches(Some(BranchType::Local))? {
            let (branch, _) = branch?;
            let name = branch.name()?.unwrap_or("?").to_string();
            if let Some(oid) = branch.get().target() {
                tips.push((name, oid));
            }
        }
    }
    tips.sort();
    tips.dedup();

    let odb = repo.odb()?;
    let mut branches = BTreeMap::new();
    let mut commits = BTreeMap::new();

    for (name, tip) in tips {
        let mut walk = repo.revwalk()?;
        walk.set_sorting(Sort::TOPOLOGICAL | Sort::TIME)?;
        walk.push(tip)?;
        let mut list = Vec::new();
        for oid in walk {
            let oid = oid?;
            list.push(oid);
            if commits.contains_key(&oid) {
                continue;
            }
            let obj = odb.read(oid)?;
            if obj.kind() != ObjectType::Commit {
                continue;
            }
            let info = parse_commit(oid, obj.data())?;
            commits.insert(oid, info);
        }
        branches.insert(name, list);
    }

    Ok(Collected { branches, commits })
}

/// Parse a raw commit object, extracting metadata and any `gpgsig` header.
pub fn parse_commit(oid: Oid, raw: &[u8]) -> Result<CommitInfo> {
    let (head, body, has_body) = match find_subslice(raw, b"\n\n") {
        Some(p) => (&raw[..p], &raw[p + 2..], true),
        None => (raw, &raw[..0], false),
    };

    let mut parents = Vec::new();
    let mut author = String::new();
    let mut committer_email = String::new();
    let mut commit_time = 0i64;
    let mut sig_lines: Vec<String> = Vec::new();
    let mut in_sig = false;
    let mut payload: Vec<u8> = Vec::new();

    for line in head.split(|&b| b == b'\n') {
        if let Some(rest) = line.strip_prefix(b"gpgsig ".as_slice()) {
            in_sig = true;
            sig_lines.push(String::from_utf8_lossy(rest).into_owned());
            continue;
        }
        if in_sig {
            if let Some(rest) = line.strip_prefix(b" ".as_slice()) {
                sig_lines.push(String::from_utf8_lossy(rest).into_owned());
                continue;
            }
            in_sig = false;
        }
        payload.extend_from_slice(line);
        payload.push(b'\n');

        if let Some(rest) = line.strip_prefix(b"parent ".as_slice()) {
            if let Ok(s) = std::str::from_utf8(rest) {
                if let Ok(p) = Oid::from_str(s.trim()) {
                    parents.push(p);
                }
            }
        } else if let Some(rest) = line.strip_prefix(b"author ".as_slice()) {
            author = strip_ident_timestamp(&String::from_utf8_lossy(rest));
        } else if let Some(rest) = line.strip_prefix(b"committer ".as_slice()) {
            let s = String::from_utf8_lossy(rest);
            committer_email = extract_email(&s).unwrap_or_default();
            commit_time = extract_time(&s).unwrap_or(0);
        }
    }

    if has_body {
        payload.push(b'\n');
        payload.extend_from_slice(body);
    }

    let subject = String::from_utf8_lossy(body)
        .lines()
        .next()
        .unwrap_or("")
        .trim()
        .to_string();

    let signature = if sig_lines.is_empty() {
        None
    } else {
        let armored = sig_lines.join("\n");
        let kind = if armored.contains("BEGIN SSH SIGNATURE") {
            SigKind::Ssh
        } else {
            SigKind::Gpg
        };
        Some(Signature {
            kind,
            armored,
            payload,
        })
    };

    Ok(CommitInfo {
        oid,
        parents,
        author,
        committer_email,
        commit_time,
        subject,
        signature,
    })
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
}

/// "Name <email> 1699999999 +0800" -> "Name <email>"
fn strip_ident_timestamp(ident: &str) -> String {
    match ident.rfind('>') {
        Some(p) => ident[..=p].trim().to_string(),
        None => ident.trim().to_string(),
    }
}

fn extract_email(ident: &str) -> Option<String> {
    let start = ident.rfind('<')?;
    let end = ident.rfind('>')?;
    (end > start).then(|| ident[start + 1..end].to_string())
}

fn extract_time(ident: &str) -> Option<i64> {
    let end = ident.rfind('>')?;
    ident[end + 1..].split_whitespace().next()?.parse().ok()
}
