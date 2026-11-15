//! SSHSIG wire format.
//!
//! Git stores an SSH commit signature in a `gpgsig` header with each line
//! indented by one space, so the PEM body a verifier receives is re-wrapped at
//! Git's header width rather than OpenSSH's. `ssh-key`'s PEM decoder rejects
//! that layout. The key embedded in an SSHSIG block may also be an OpenSSH
//! *certificate*, which `ssh-key` models as an opaque key in its plain
//! `PublicKey` API and refuses to decode as a whole. This module therefore
//! parses the envelope directly:
//!
//! ```text
//! byte[6]  "SSHSIG"
//! uint32   version (1)
//! string   public key   (algorithm string + key body; may be a certificate)
//! string   namespace    ("git")
//! string   reserved
//! string   hash algorithm ("sha256" / "sha512")
//! string   signature    (algorithm string + signature body)
//! ```
//!
//! The signature is checked with `ssh-key`, using the *subject* key of the
//! certificate for certificate-form signers, exactly as OpenSSH does.

use anyhow::Context;
use signature::Verifier;
use ssh_key::certificate::Certificate;
use ssh_key::public::KeyData;
use ssh_key::{Algorithm, HashAlg, PublicKey, Signature};

use crate::wire::SshReader;

pub const SSH_SIG_PREAMBLE: &[u8] = b"SSHSIG";

/// The key an SSH signature was made with: a plain public key or an OpenSSH
/// certificate.
#[derive(Debug, Clone)]
pub enum SignerKey {
    Plain(PublicKey),
    Certificate(Box<Certificate>),
}

impl SignerKey {
    /// Parse an SSH public key blob, accepting certificate-form blobs.
    pub fn from_blob(blob: &[u8]) -> anyhow::Result<Self> {
        let alg = read_algorithm(blob)?;
        if is_certificate_algorithm(&alg) {
            let cert = Certificate::from_bytes(blob)
                .map_err(|e| anyhow::anyhow!("invalid SSH certificate: {e}"))?;
            return Ok(SignerKey::Certificate(Box::new(cert)));
        }
        let key = PublicKey::from_bytes(blob)
            .map_err(|e| anyhow::anyhow!("invalid SSH public key blob: {e}"))?;
        Ok(SignerKey::Plain(key))
    }

    /// The key that actually produced the signature.
    ///
    /// For a certificate this is the certificate's subject key, since the
    /// certificate is merely an endorsement of that key by a CA.
    pub fn verification_key(&self) -> &KeyData {
        match self {
            SignerKey::Plain(key) => key.key_data(),
            SignerKey::Certificate(cert) => cert.public_key(),
        }
    }

    pub fn certificate(&self) -> Option<&Certificate> {
        match self {
            SignerKey::Plain(_) => None,
            SignerKey::Certificate(cert) => Some(cert),
        }
    }

    /// `SHA256:…` fingerprint, of the whole certificate when it is one.
    pub fn fingerprint(&self) -> String {
        ssh_key::Fingerprint::new(HashAlg::Sha256, self.verification_key()).to_string()
    }

    /// Algorithm string OpenSSH uses for this key (`…-cert-v01@openssh.com`
    /// for a certificate).
    pub fn algorithm_name(&self) -> String {
        match self {
            SignerKey::Plain(key) => key.algorithm().as_str().to_string(),
            SignerKey::Certificate(cert) => cert.algorithm().to_certificate_type(),
        }
    }

    /// Serialized key blob, as used for allowlist matching.
    pub fn to_blob(&self) -> anyhow::Result<Vec<u8>> {
        match self {
            SignerKey::Plain(key) => key
                .to_bytes()
                .map_err(|e| anyhow::anyhow!("encoding SSH public key: {e}")),
            SignerKey::Certificate(cert) => cert
                .to_bytes()
                .map_err(|e| anyhow::anyhow!("encoding SSH certificate: {e}")),
        }
    }
}

fn read_algorithm(blob: &[u8]) -> anyhow::Result<String> {
    let mut reader = SshReader::new(blob);
    let alg = reader.utf8_string().context("reading SSH key algorithm")?;
    Ok(alg.to_string())
}

fn is_certificate_algorithm(alg: &str) -> bool {
    alg.contains("-cert-v01@")
}

/// A decoded SSHSIG block.
#[derive(Debug)]
pub struct RawSshSig {
    /// The embedded key blob, exactly as it appeared.
    pub key_blob: Vec<u8>,
    /// The embedded key (plain or certificate).
    pub key: SignerKey,
    pub namespace: String,
    pub hash_alg: HashAlg,
    /// The raw signature packet (algorithm string + body).
    pub signature: Vec<u8>,
    pub version: u32,
}

impl RawSshSig {
    /// Parse an SSHSIG PEM block as Git stores it (possibly re-wrapped).
    pub fn from_pem(text: &str) -> anyhow::Result<Self> {
        let body = pem_body(text)
            .context("SSH signature is not a PEM block with -----BEGIN SSH SIGNATURE-----")?;
        let decoded = decode_base64(&body).context("decoding SSHSIG base64 body")?;
        Self::from_bytes(&decoded)
    }

    /// Parse the decoded SSHSIG payload.
    pub fn from_bytes(data: &[u8]) -> anyhow::Result<Self> {
        let mut reader = SshReader::new(data);
        let magic = reader.take_bytes(SSH_SIG_PREAMBLE.len())?;
        if magic != SSH_SIG_PREAMBLE {
            anyhow::bail!("not an SSHSIG block (bad preamble)");
        }
        let version = reader.u32()?;
        if version != 1 {
            anyhow::bail!("unsupported SSHSIG version {version}");
        }
        let key_blob = reader.string()?.to_vec();
        let namespace = reader.utf8_string()?.to_string();
        let _reserved = reader.string()?;
        let hash_alg_str = reader.utf8_string()?;
        let signature = reader.string()?.to_vec();

        if !reader.is_empty() {
            anyhow::bail!("SSHSIG block has {} trailing bytes", reader.remaining());
        }

        let hash_alg = HashAlg::new(hash_alg_str).map_err(|e| {
            anyhow::anyhow!("unsupported SSHSIG hash algorithm {hash_alg_str:?}: {e}")
        })?;
        let key = SignerKey::from_blob(&key_blob)?;

        Ok(Self {
            key_blob,
            key,
            namespace,
            hash_alg,
            signature,
            version,
        })
    }

    /// The exact bytes covered by the signature, per PROTOCOL.sshsig.
    pub fn signed_data(&self, message: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(message.len() + 64);
        out.extend_from_slice(SSH_SIG_PREAMBLE);
        crate::wire::put_string(&mut out, self.namespace.as_bytes());
        crate::wire::put_string(&mut out, &[]); // reserved
        crate::wire::put_string(&mut out, self.hash_alg.as_str().as_bytes());
        let digest = match self.hash_alg {
            HashAlg::Sha256 => crate::wire::HashKind::Sha256.digest(message),
            _ => crate::wire::HashKind::Sha512.digest(message),
        };
        crate::wire::put_string(&mut out, &digest);
        out
    }

    /// Cryptographically verify against the embedded key (certificate subject
    /// key when the signer is a certificate).
    ///
    /// RSA signatures must be `rsa-sha2-256/512` (OpenSSH's `RSA_SIGN_ALLOWED`);
    /// `ssh-key` only implements those, so no extra gate is needed.
    pub fn verify(&self, message: &[u8]) -> anyhow::Result<()> {
        let signed = self.signed_data(message);
        let sig = Signature::try_from(self.signature.as_slice())
            .context("decoding SSHSIG signature packet")?;
        let key_data = self.key.verification_key();
        <KeyData as Verifier<Signature>>::verify(key_data, &signed, &sig)
            .map_err(|e| anyhow::anyhow!("SSHSIG signature verification failed: {e}"))
    }

    /// Algorithm of the embedded key as OpenSSH names it.
    pub fn key_algorithm(&self) -> String {
        self.key.algorithm_name()
    }

    /// `Algorithm` of the embedded key, for callers that need the plain form.
    pub fn key_algorithm_enum(&self) -> Algorithm {
        match &self.key {
            SignerKey::Plain(key) => key.algorithm(),
            SignerKey::Certificate(cert) => cert.algorithm(),
        }
    }
}

/// Extract the base64 body from a PEM/armour block, tolerating arbitrary line
/// wrapping (Git re-wraps SSH signatures at its header width).
pub fn pem_body(text: &str) -> Option<String> {
    let mut in_body = false;
    let mut out = String::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("-----BEGIN ") {
            in_body = true;
            continue;
        }
        if trimmed.starts_with("-----END ") {
            break;
        }
        if in_body {
            out.push_str(trimmed);
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

fn decode_base64(body: &str) -> anyhow::Result<Vec<u8>> {
    use base64::Engine as _;
    // Git may have dropped the trailing padding when re-wrapping.
    let padded = match body.len() % 4 {
        0 => body.to_string(),
        2 => format!("{body}=="),
        3 => format!("{body}="),
        _ => anyhow::bail!("invalid base64 length in SSHSIG body"),
    };
    base64::engine::general_purpose::STANDARD
        .decode(padded.as_bytes())
        .context("invalid base64 in SSHSIG body")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pem_body_joins_wrapped_lines() {
        let text = "-----BEGIN SSH SIGNATURE-----\nAAAA\nBBBB\n-----END SSH SIGNATURE-----\n";
        assert_eq!(pem_body(text).as_deref(), Some("AAAABBBB"));
    }

    #[test]
    fn pem_body_rejects_non_pem() {
        assert!(pem_body("not a signature").is_none());
    }

    #[test]
    fn base64_accepts_missing_padding() {
        assert_eq!(decode_base64("YQ").unwrap(), b"a");
        assert_eq!(decode_base64("YWI").unwrap(), b"ab");
    }
}
