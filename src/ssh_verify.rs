//! SSH signature verification, reproducing `ssh-keygen -Y verify` semantics.
//!
//! The signature is an `SSHSIG` PEM block. The signed data is
//! `"SSHSIG" || string(namespace) || string("") || string(hashalg) || string(H(message))`
//! (OpenSSH `sshsig.c`), where the hash algorithm comes from the signature.
//! Verification proceeds in three independent stages, all of which must pass:
//!
//! 1. **Crypto**: the embedded public key must verify the signature over the
//!    reconstructed signed data, in namespace `git`.
//! 2. **Trust**: a line in `allowed_signers` must match that key (or its
//!    certificate's CA) at the commit time, in the `git` namespace.
//! 3. **Revocation**: the key (and CA) must not appear in any configured KRL.

use crate::sshsig::RawSshSig;

use crate::model::{KeyIssue, SignatureDetail, SignatureKind};
use crate::ssh_keys::{AllowedSigners, KrlSet, SignerMatch};

/// The namespace Git requires for commit signatures.
pub const GIT_NAMESPACE: &str = "git";

#[derive(Debug)]
pub struct SshOutcome {
    pub verified: bool,
    pub trusted: bool,
    pub detail: SignatureDetail,
    pub issue: Option<KeyIssue>,
    pub reason: Option<String>,
}

/// Parse a Git `gpgsig` blob holding an SSH signature.
pub fn parse_ssh_signature(blob: &[u8]) -> anyhow::Result<RawSshSig> {
    let text = std::str::from_utf8(blob)
        .map_err(|e| anyhow::anyhow!("SSH signature is not UTF-8: {e}"))?;
    RawSshSig::from_pem(text)
}

/// Verify one SSH signature over `payload` at `commit_time`.
pub fn verify(
    signers: &AllowedSigners,
    krls: &KrlSet,
    payload: &[u8],
    signature_blob: &[u8],
    commit_time: i64,
) -> SshOutcome {
    let commit_time_u = if commit_time < 0 {
        0
    } else {
        commit_time as u64
    };

    let sig = match parse_ssh_signature(signature_blob) {
        Ok(sig) => sig,
        Err(e) => {
            return SshOutcome {
                verified: false,
                trusted: false,
                detail: SignatureDetail {
                    kind: SignatureKind::Ssh,
                    signer_fingerprint: None,
                    signer_identity: None,
                    signature_time: None,
                    key_issue: None,
                },
                issue: None,
                reason: Some(format!("malformed SSH signature: {e:#}")),
            };
        }
    };

    // The namespace is part of the signed blob and is authenticated by the
    // signature itself, so a mismatch is a hard failure.
    if sig.namespace != GIT_NAMESPACE {
        return SshOutcome {
            verified: false,
            trusted: false,
            detail: SignatureDetail {
                kind: SignatureKind::Ssh,
                signer_fingerprint: Some(fingerprint_for(&sig)),
                signer_identity: None,
                signature_time: None,
                key_issue: None,
            },
            issue: None,
            reason: Some(format!(
                "SSH signature namespace is {:?}, expected {:?}",
                sig.namespace, GIT_NAMESPACE
            )),
        };
    }

    let embedded = sig.key.clone();
    let fingerprint = fingerprint_for(&sig);

    // Stage 1: crypto. `RawSshSig::verify` rebuilds the exact signed data
    // (`SSHSIG` || namespace || reserved || hashalg || H(message)) and checks
    // the signature against the embedded key.
    if let Err(e) = sig.verify(payload) {
        return SshOutcome {
            verified: false,
            trusted: false,
            detail: SignatureDetail {
                kind: SignatureKind::Ssh,
                signer_fingerprint: Some(fingerprint),
                signer_identity: None,
                signature_time: None,
                key_issue: None,
            },
            issue: None,
            reason: Some(format!("SSH signature does not verify: {e}")),
        };
    }

    // Stage 3 (checked before trust so a revoked key is reported as such even
    // when it is also absent from the allowlist).
    let revoked = krls.revokes(&embedded);

    // Stage 2: trust.
    let match_result = signers.match_signer(&embedded, GIT_NAMESPACE, commit_time_u);

    let (identity, trusted, mut issue, mut reason) = match match_result {
        SignerMatch::Key { principal, .. } => (Some(principal), true, None, None),
        SignerMatch::Certificate { principal, .. } => (principal, true, None, None),
        SignerMatch::Rejected { reason, .. } => (None, false, None, Some(reason)),
        SignerMatch::NotFound => (
            None,
            false,
            Some(KeyIssue::UnknownKey),
            Some(format!(
                "signing key {fingerprint} is not in the allowed signers file"
            )),
        ),
    };

    // A revoked key overrides allowlisting: `ssh-keygen -Y verify -r` fails
    // unconditionally when the key is revoked, regardless of validity window.
    if revoked {
        issue = Some(KeyIssue::RevokedAtCommitTime);
        reason = Some(format!(
            "signing key {fingerprint} is revoked by the configured KRL"
        ));
    }

    let trusted = trusted && !revoked;
    let detail = SignatureDetail {
        kind: SignatureKind::Ssh,
        signer_fingerprint: Some(fingerprint),
        signer_identity: identity,
        signature_time: None,
        key_issue: issue.clone(),
    };

    SshOutcome {
        verified: true,
        trusted,
        detail,
        issue,
        reason,
    }
}

fn fingerprint_for(sig: &RawSshSig) -> String {
    sig.key.fingerprint()
}
