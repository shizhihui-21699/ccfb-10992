//! Audit result model shared by the CLI, the JSON report and the tests.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Per-commit verdict.
///
/// The letter column mirrors `git log --format=%G?` so that results can be
/// compared directly against git itself:
///
/// | letter | meaning                                   | git source            |
/// |--------|-------------------------------------------|-----------------------|
/// | G      | good signature, signer allowed            | GOODSIG + trusted     |
/// | U      | good signature, signer not allowed        | GOODSIG, TRUST_UNDEFINED |
/// | B      | bad signature                             | BADSIG                |
/// | E      | could not check (unknown key / verifier)  | ERRSIG                |
/// | Y      | signing key was expired at commit time    | EXPKEYSIG             |
/// | R      | signing key was revoked at commit time    | REVKEYSIG             |
/// | N      | no signature                              | result 'N'            |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Good,
    SignerNotAllowed,
    BadSignature,
    UnknownKey,
    KeyExpiredAtCommit,
    KeyRevokedAtCommit,
    Unsigned,
    Error,
}

impl Verdict {
    /// git's `%G?` letter for this verdict.
    pub fn letter(self) -> char {
        match self {
            Verdict::Good => 'G',
            Verdict::SignerNotAllowed => 'U',
            Verdict::BadSignature => 'B',
            Verdict::UnknownKey => 'E',
            Verdict::KeyExpiredAtCommit => 'Y',
            Verdict::KeyRevokedAtCommit => 'R',
            Verdict::Unsigned => 'N',
            Verdict::Error => 'E',
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Good => "good",
            Verdict::SignerNotAllowed => "signer_not_allowed",
            Verdict::BadSignature => "bad_signature",
            Verdict::UnknownKey => "unknown_key",
            Verdict::KeyExpiredAtCommit => "key_expired_at_commit",
            Verdict::KeyRevokedAtCommit => "key_revoked_at_commit",
            Verdict::Unsigned => "unsigned",
            Verdict::Error => "error",
        }
    }

    pub fn is_failure(self) -> bool {
        !matches!(self, Verdict::Good)
    }

    /// Stable ordering for summary output: failures first.
    pub fn sort_rank(self) -> u8 {
        match self {
            Verdict::BadSignature => 0,
            Verdict::KeyRevokedAtCommit => 1,
            Verdict::KeyExpiredAtCommit => 2,
            Verdict::UnknownKey => 3,
            Verdict::SignerNotAllowed => 4,
            Verdict::Error => 5,
            Verdict::Unsigned => 6,
            Verdict::Good => 7,
        }
    }
}

impl std::fmt::Display for Verdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectKind {
    Commit,
    Tag,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub kind: ObjectKind,
    pub oid: String,
    /// Annotated tag name, when this record describes a tag object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub committer: Option<String>,
    /// Timestamp used as "commit time" when judging key validity.
    pub signed_at: i64,
    /// Same moment rendered as RFC 3339 (UTC).
    pub signed_at_utc: String,
    pub parents: usize,
    pub is_merge: bool,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub branches: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_format: Option<String>,
    pub verdict: Verdict,
    /// git's `%G?` letter, for parity with git tooling.
    pub git_letter: char,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    /// Signature's own creation time, from the signature packet.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_created_at: Option<i64>,
    /// Key expiry as reported by gpg, when it reported one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_expires_at: Option<i64>,
    /// Human-readable explanation, always present for failures.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl AuditRecord {
    pub fn short_subject(&self) -> String {
        self.committer.clone().unwrap_or_default()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Summary {
    pub total: u64,
    pub good: u64,
    pub unsigned: u64,
    pub bad_signature: u64,
    pub unknown_key: u64,
    pub signer_not_allowed: u64,
    pub key_expired_at_commit: u64,
    pub key_revoked_at_commit: u64,
    pub error: u64,
    /// Number of failing commits, i.e. everything except `good`.
    pub failures: u64,
}

impl Summary {
    pub fn record(&mut self, verdict: Verdict) {
        self.total += 1;
        match verdict {
            Verdict::Good => self.good += 1,
            Verdict::Unsigned => self.unsigned += 1,
            Verdict::BadSignature => self.bad_signature += 1,
            Verdict::UnknownKey => self.unknown_key += 1,
            Verdict::SignerNotAllowed => self.signer_not_allowed += 1,
            Verdict::KeyExpiredAtCommit => self.key_expired_at_commit += 1,
            Verdict::KeyRevokedAtCommit => self.key_revoked_at_commit += 1,
            Verdict::Error => self.error += 1,
        }
        if verdict.is_failure() {
            self.failures += 1;
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BranchReport {
    pub name: String,
    pub tip: String,
    pub commits: u64,
    pub summary: Summary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepositoryInfo {
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workdir: Option<String>,
    pub hash_algorithm: String,
    pub shallow: bool,
    /// Commits whose parents are missing from the object database (shallow
    /// clones, partial fetches). Their history could not be fully audited.
    pub incomplete_history: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub tool: ToolInfo,
    pub generated_at: String,
    pub generated_at_unix: i64,
    pub repository: RepositoryInfo,
    pub summary: Summary,
    pub branches: Vec<BranchReport>,
    /// Sorted: failures first, then by commit time descending.
    pub records: Vec<AuditRecord>,
    /// Non-fatal problems encountered while auditing (missing verifier,
    /// unreadable ref, ...), for CI logs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    /// Per-format breakdown, e.g. `{"openpgp": {"good": 10, ...}}`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub by_format: BTreeMap<String, Summary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolInfo {
    pub name: String,
    pub version: String,
}

impl Report {
    pub fn exit_code(&self) -> i32 {
        if self.summary.failures > 0 {
            crate::EXIT_AUDIT_FAILURE
        } else {
            crate::EXIT_OK
        }
    }
}
