//! Core result types shared by the verifiers and the report layer.

use serde::Serialize;
use std::fmt;

/// Which signature format a commit carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SigKind {
    /// `-----BEGIN PGP SIGNATURE-----` / `-----BEGIN PGP MESSAGE-----`
    OpenPgp,
    /// `-----BEGIN SSH SIGNATURE-----`
    Ssh,
    /// `-----BEGIN SIGNED MESSAGE-----` (gpgsm). Detected but not verified.
    X509,
    /// Armored block we do not recognise.
    Unknown,
}

impl SigKind {
    pub fn as_str(self) -> &'static str {
        match self {
            SigKind::OpenPgp => "openpgp",
            SigKind::Ssh => "ssh",
            SigKind::X509 => "x509",
            SigKind::Unknown => "unknown",
        }
    }
}

impl fmt::Display for SigKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Outcome of auditing one commit.
///
/// The first three variants are the categories an audit is usually asked for
/// ("unsigned", "invalid", "signer not allowed").  The rest refine *why* a
/// signature that is cryptographically good is still not acceptable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// Cryptographically valid, signer allowed, key valid at the audit time.
    Valid,
    /// No `gpgsig` header at all.
    Unsigned,
    /// Signature present but does not verify (BADSIG / "Could not verify").
    Invalid,
    /// Crypto is good but the signer is not in the configured allow-list.
    UnknownSigner,
    /// Allowed-signers matched the key but its options forbid this use
    /// (e.g. `namespaces="release"` on a `git` signature).
    NotPermitted,
    /// Signing key had expired at the audit time.
    KeyExpired,
    /// Signing key had been revoked at (or before) the audit time.
    KeyRevoked,
    /// Signature claims a time before the signing key existed.
    KeyNotYetValid,
    /// The signature itself has expired (OpenPGP `EXPSIG`).
    SignatureExpired,
    /// Public key is not available, so nothing can be verified.
    NoPublicKey,
    /// Armor / packet stream could not be parsed.
    Malformed,
    /// The signature cannot be checked because required configuration or
    /// tooling is missing (no allowed_signers file, unsupported format).
    /// Distinct from `invalid`, which asserts the cryptography is wrong.
    Unverifiable,
}

impl Status {
    /// A commit is compliant only when this is `Valid`.
    pub fn is_violation(self) -> bool {
        self != Status::Valid
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Status::Valid => "valid",
            Status::Unsigned => "unsigned",
            Status::Invalid => "invalid",
            Status::UnknownSigner => "unknown_signer",
            Status::NotPermitted => "not_permitted",
            Status::KeyExpired => "key_expired",
            Status::KeyRevoked => "key_revoked",
            Status::KeyNotYetValid => "key_not_yet_valid",
            Status::SignatureExpired => "signature_expired",
            Status::NoPublicKey => "no_public_key",
            Status::Malformed => "malformed",
            Status::Unverifiable => "unverifiable",
        }
    }

    /// Stable ordering for deterministic summaries.
    pub const ALL: [Status; 12] = [
        Status::Valid,
        Status::Unsigned,
        Status::Invalid,
        Status::UnknownSigner,
        Status::NotPermitted,
        Status::KeyExpired,
        Status::KeyRevoked,
        Status::KeyNotYetValid,
        Status::SignatureExpired,
        Status::NoPublicKey,
        Status::Malformed,
        Status::Unverifiable,
    ];
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Everything a verifier learned about one signature.
#[derive(Debug, Clone, Default, Serialize)]
pub struct SignatureInfo {
    /// `openpgp`, `ssh`, `x509` or `unknown`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<SigKind>,
    /// Principal (SSH) or user id (OpenPGP) reported by the verifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer: Option<String>,
    /// Signing key fingerprint (SSH `SHA256:...`, OpenPGP hex).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    /// OpenPGP primary key fingerprint, when it differs from the signing key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary_fingerprint: Option<String>,
    /// Short key id (OpenPGP).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    /// OpenPGP trust level reported by gpg (`ultimate`, `fully`, ...).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust: Option<String>,
    /// True when the signing key has expired *since* the audit time.
    #[serde(default, skip_serializing_if = "is_false")]
    pub key_expired_since: bool,
    /// True when the signing key has been revoked *after* the audit time.
    #[serde(default, skip_serializing_if = "is_false")]
    pub key_revoked_since: bool,
    /// Human-readable explanation for a non-valid status.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// A verifier's verdict for a single commit.
#[derive(Debug, Clone)]
pub struct Outcome {
    pub status: Status,
    pub info: SignatureInfo,
}

impl Outcome {
    pub fn new(status: Status) -> Outcome {
        Outcome {
            status,
            info: SignatureInfo::default(),
        }
    }
}
