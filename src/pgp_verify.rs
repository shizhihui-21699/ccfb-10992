//! OpenPGP signature verification.
//!
//! Verification is fully in-process: no `gpg` invocation and no trust
//! database. The auditor instead applies explicit, auditable rules:
//!
//! * the signature must cryptographically verify against a key in the
//!   configured keyring,
//! * the signing (sub)key must have been created before the commit,
//! * its expiry and any revocation must be evaluated *at the commit time*,
//!   so a key that was fine then and expired or was revoked later does not
//!   taint the commit,
//! * the key must match the configured signer allowlist.

use anyhow::Context;
use pgp::composed::{Deserializable, DetachedSignature};
use pgp::packet::SignatureType;

use crate::model::{KeyIssue, SignatureDetail, SignatureKind};
use crate::pgp_keyring::{PgpKey, PgpKeyring, PgpValidity};

/// The outcome of checking one OpenPGP signature.
#[derive(Debug)]
pub struct PgpOutcome {
    pub verified: bool,
    pub trusted: bool,
    pub detail: SignatureDetail,
    /// `None` when fully good.
    pub issue: Option<KeyIssue>,
    pub reason: Option<String>,
}

fn issuer_fingerprint(sig: &pgp::packet::Signature) -> Option<String> {
    sig.issuer_fingerprint()
        .first()
        .map(|fp| hex::encode(fp.as_bytes()).to_lowercase())
}

fn issuer_key_id(sig: &pgp::packet::Signature) -> Option<String> {
    sig.issuer_key_id()
        .first()
        .map(|id| hex::encode(id.as_ref()).to_lowercase())
}

/// Parse every detached signature in a Git `gpgsig` blob (armored or binary).
pub fn parse_detached_signatures(blob: &[u8]) -> anyhow::Result<Vec<DetachedSignature>> {
    let text = std::str::from_utf8(blob);
    let mut out = Vec::new();
    if let Ok(text) = text {
        if text.contains("-----BEGIN PGP") {
            let (iter, _) = DetachedSignature::from_string_many(text)
                .context("parsing armored OpenPGP signature")?;
            for sig in iter {
                out.push(sig.context("parsing armored OpenPGP signature")?);
            }
            if out.is_empty() {
                anyhow::bail!("armored PGP block contained no signature packets");
            }
            return Ok(out);
        }
    }
    let iter = DetachedSignature::from_bytes_many(std::io::Cursor::new(blob))
        .context("parsing OpenPGP signature")?;
    for sig in iter {
        out.push(sig.context("parsing OpenPGP signature")?);
    }
    if out.is_empty() {
        anyhow::bail!("no OpenPGP signature packets found");
    }
    Ok(out)
}

/// Verify one detached signature over `payload` at the given commit time.
pub fn verify(
    ring: &PgpKeyring,
    payload: &[u8],
    signature_blob: &[u8],
    commit_time: i64,
) -> PgpOutcome {
    let sigs = match parse_detached_signatures(signature_blob) {
        Ok(s) => s,
        Err(e) => {
            return PgpOutcome {
                verified: false,
                trusted: false,
                detail: SignatureDetail {
                    kind: SignatureKind::OpenPgp,
                    signer_fingerprint: None,
                    signer_identity: None,
                    signature_time: None,
                    key_issue: None,
                },
                issue: None,
                reason: Some(format!("malformed OpenPGP signature: {e:#}")),
            };
        }
    };

    // Git treats multiple signature packets as suspicious (GPG allows several
    // `[GNUPG:] GOODSIG` lines only for multiple signatures); require exactly
    // one and reject ambiguity rather than picking a convenient one.
    if sigs.len() != 1 {
        return PgpOutcome {
            verified: false,
            trusted: false,
            detail: SignatureDetail {
                kind: SignatureKind::OpenPgp,
                signer_fingerprint: None,
                signer_identity: None,
                signature_time: None,
                key_issue: None,
            },
            issue: None,
            reason: Some(format!(
                "commit carries {} OpenPGP signature packets; expected exactly one",
                sigs.len()
            )),
        };
    }
    let detached = &sigs[0];
    let sig = &detached.signature;

    let typ_ok = matches!(
        sig.typ(),
        Some(SignatureType::Binary) | Some(SignatureType::Text)
    );
    if !typ_ok {
        return PgpOutcome {
            verified: false,
            trusted: false,
            detail: SignatureDetail {
                kind: SignatureKind::OpenPgp,
                signer_fingerprint: issuer_fingerprint(sig),
                signer_identity: None,
                signature_time: sig.created().map(|t| i64::from(t.as_secs())),
                key_issue: None,
            },
            issue: None,
            reason: Some(format!(
                "OpenPGP signature packet has unsupported type {:?}",
                sig.typ()
            )),
        };
    }

    let fingerprint = issuer_fingerprint(sig);
    let key_id = issuer_key_id(sig);
    let candidates = ring.lookup(fingerprint.as_deref(), key_id.as_deref());

    if candidates.is_empty() {
        return PgpOutcome {
            verified: false,
            trusted: false,
            detail: SignatureDetail {
                kind: SignatureKind::OpenPgp,
                signer_fingerprint: fingerprint.clone(),
                signer_identity: None,
                signature_time: sig.created().map(|t| i64::from(t.as_secs())),
                key_issue: Some(KeyIssue::UnknownKey),
            },
            issue: Some(KeyIssue::UnknownKey),
            reason: Some(format!(
                "signing key {} is not in the configured OpenPGP keyring",
                fingerprint.clone().unwrap_or_else(|| "<unknown>".into())
            )),
        };
    }

    // Try each candidate certificate: primary key first, then subkeys. A
    // signature is good if any of them verifies and the identity matches.
    let mut verified_with: Option<(&PgpKey, Option<usize>)> = None;
    let mut last_err = String::new();
    for key in &candidates {
        if detached.verify(&key.cert, payload).is_ok() {
            verified_with = Some((key, None));
            break;
        }
        for (idx, sub) in key.cert.public_subkeys.iter().enumerate() {
            if detached.verify(&sub.key, payload).is_ok() {
                verified_with = Some((key, Some(idx)));
                break;
            }
        }
        if verified_with.is_some() {
            break;
        }
        last_err = format!("signature does not verify against key {}", key.fingerprint);
    }

    let Some((key, subkey_index)) = verified_with else {
        return PgpOutcome {
            verified: false,
            trusted: false,
            detail: SignatureDetail {
                kind: SignatureKind::OpenPgp,
                signer_fingerprint: fingerprint.clone(),
                signer_identity: candidates.first().and_then(|k| k.identity()),
                signature_time: sig.created().map(|t| i64::from(t.as_secs())),
                key_issue: None,
            },
            issue: None,
            reason: Some(last_err),
        };
    };

    let identity = key.identity();
    let signer_fingerprint = match subkey_index {
        Some(idx) => key.subkeys[idx].fingerprint.clone(),
        None => key.fingerprint.clone(),
    };

    // Time validity, evaluated at the moment the commit was made.
    let validity = match subkey_index {
        Some(idx) => key.subkey_validity_at(&key.subkeys[idx], commit_time),
        None => key.validity_at(commit_time),
    };

    let (issue, reason) = match validity {
        PgpValidity::Valid => {
            if !ring.is_trusted(key) {
                (
                    Some(KeyIssue::PrincipalNotAllowed),
                    Some(format!(
                        "signer {} is not on the OpenPGP allowlist",
                        identity.clone().unwrap_or_else(|| key.fingerprint.clone())
                    )),
                )
            } else {
                (None, None)
            }
        }
        PgpValidity::Expired => (
            Some(KeyIssue::Expired),
            Some(format!(
                "signing key expired before the commit was made (expired at {})",
                key_expiry_for(key, subkey_index)
            )),
        ),
        PgpValidity::Revoked => (
            Some(KeyIssue::RevokedAtCommitTime),
            Some("signing key was revoked before the commit was made".to_string()),
        ),
        PgpValidity::RevokedLater => (
            Some(KeyIssue::RevokedAfterCommit),
            Some("signing key was revoked after the commit was made".to_string()),
        ),
    };

    PgpOutcome {
        verified: true,
        trusted: issue.is_none(),
        detail: SignatureDetail {
            kind: SignatureKind::OpenPgp,
            signer_fingerprint: Some(signer_fingerprint),
            signer_identity: identity,
            signature_time: sig.created().map(|t| i64::from(t.as_secs())),
            key_issue: issue.clone(),
        },
        issue,
        reason,
    }
}

fn key_expiry_for(key: &PgpKey, subkey_index: Option<usize>) -> i64 {
    match subkey_index {
        Some(idx) => key.subkeys[idx].expires,
        None => key.expires,
    }
}
