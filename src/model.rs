//! Audit data model shared by both signature backends.

use serde::Serialize;

/// How a commit's signature should be treated.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Signature verified and the signer is on the allowlist.
    Signed,
    /// The commit carries no signature at all.
    Unsigned,
    /// A signature is present but does not verify against the signer's key.
    Invalid,
    /// The signature verifies, but the key that produced it is not trusted by
    /// this audit (not in the allowlist / keyring, expired or revoked at the
    /// commit's time).
    Untrusted,
    /// The signature verifies and the signer is known, but the key is
    /// revoked (SSH KRL or OpenPGP revocation) *after* the commit was made.
    /// Distinguished from `Untrusted` because the commit was legitimately
    /// signed at the time it was created.
    RevokedLater,
}

impl Verdict {
    /// Does this verdict mean "this commit fails the policy"?
    pub fn is_failure(self) -> bool {
        !matches!(self, Verdict::Signed)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Signed => "signed",
            Verdict::Unsigned => "unsigned",
            Verdict::Invalid => "invalid",
            Verdict::Untrusted => "untrusted",
            Verdict::RevokedLater => "revoked-later",
        }
    }
}

/// Signature backend that produced a commit's signature.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureKind {
    OpenPgp,
    Ssh,
}

/// Why a key was considered unusable at a given time.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyIssue {
    /// No key with this fingerprint/id is known to the audit.
    UnknownKey,
    /// The key's own expiry (OpenPGP key expiration, SSH cert validity)
    /// elapsed before the commit time.
    Expired,
    /// The key was revoked by the time the commit was made.
    RevokedAtCommitTime,
    /// The key is valid, but the signer principal is not allowlisted.
    PrincipalNotAllowed,
    /// The key is valid but was revoked after the commit time.
    RevokedAfterCommit,
}

/// A single commit's audit result.
#[derive(Clone, Debug, Serialize)]
pub struct CommitReport {
    pub commit: String,
    pub tree: Option<String>,
    pub parents: Vec<String>,
    pub author: Option<String>,
    pub committer: Option<String>,
    /// Commit time in Unix seconds, as recorded in the committer ident.
    pub commit_time: i64,
    pub subject: String,
    pub verdict: Verdict,
    pub signature: Option<SignatureDetail>,
    /// Human-readable reason when `verdict` is not `Signed`.
    pub reason: Option<String>,
    /// Set for merge commits that carry an additional `mergetag`.
    pub mergetag: Option<Box<MergetagReport>>,
}

/// Details of the signature that was examined.
#[derive(Clone, Debug, Serialize)]
pub struct SignatureDetail {
    pub kind: SignatureKind,
    /// Key fingerprint, hex (OpenPGP) or `SHA256:…` (SSH).
    pub signer_fingerprint: Option<String>,
    /// Principal / user id the signature was attributed to.
    pub signer_identity: Option<String>,
    /// Signature creation time, Unix seconds, when the backend records it.
    pub signature_time: Option<i64>,
    pub key_issue: Option<KeyIssue>,
}

/// A `mergetag` header inside a merge commit, which carries a signed tag
/// object. Audit it separately because it authenticates the merged history.
#[derive(Clone, Debug, Serialize)]
pub struct MergetagReport {
    pub tag_object: String,
    pub verdict: Verdict,
    pub signature: Option<SignatureDetail>,
    pub reason: Option<String>,
}

/// Per-branch summary. A commit may appear on several branches.
#[derive(Clone, Debug, Serialize)]
pub struct BranchReport {
    pub name: String,
    /// Branch tip as reported by the ref.
    pub tip: String,
    pub counts: Counts,
    /// Commits on this branch whose verdict is not `signed`, in walking
    /// order. Whether each counts against the run depends on the `--fail-on`
    /// policy, so the reporters apply that policy rather than filtering here.
    pub non_signed: Vec<String>,
}

#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct Counts {
    pub total: usize,
    pub signed: usize,
    pub unsigned: usize,
    pub invalid: usize,
    pub untrusted: usize,
    pub revoked_later: usize,
}

impl Counts {
    pub fn record(&mut self, verdict: Verdict) {
        self.total += 1;
        match verdict {
            Verdict::Signed => self.signed += 1,
            Verdict::Unsigned => self.unsigned += 1,
            Verdict::Invalid => self.invalid += 1,
            Verdict::Untrusted => self.untrusted += 1,
            Verdict::RevokedLater => self.revoked_later += 1,
        }
    }

    pub fn merge(&mut self, other: &Counts) {
        self.total += other.total;
        self.signed += other.signed;
        self.unsigned += other.unsigned;
        self.invalid += other.invalid;
        self.untrusted += other.untrusted;
        self.revoked_later += other.revoked_later;
    }
}
