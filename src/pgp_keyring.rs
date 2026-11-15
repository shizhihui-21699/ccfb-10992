//! OpenPGP (GPG) key material: parsing keyrings and deciding whether a key was
//! valid at a given instant.

use std::collections::HashMap;

use anyhow::Context;
use pgp::composed::{Deserializable, SignedPublicKey, SignedPublicSubKey};
use pgp::packet::{Signature, SignatureType};
use pgp::types::KeyDetails as _;

/// One OpenPGP certificate plus the derived validity facts the auditor needs.
#[derive(Clone, Debug)]
pub struct PgpKey {
    /// Primary key fingerprint, lowercase hex.
    pub fingerprint: String,
    /// 8-byte key id, lowercase hex.
    pub key_id: String,
    /// Case-insensitive user-id strings (`Name <mail>`).
    pub user_ids: Vec<String>,
    /// Subkeys, each with its own fingerprint and validity.
    pub subkeys: Vec<PgpSubkey>,
    /// Primary-key creation time, Unix seconds.
    pub created: i64,
    /// Key expiration time in Unix seconds (`0` = never), based on the
    /// newest self-signature that carries one.
    pub expires: i64,
    /// Earliest revocation time, Unix seconds (`None` = not revoked).
    pub revoked_at: Option<i64>,
    /// The parsed certificate, used for signature verification.
    pub cert: SignedPublicKey,
}

#[derive(Clone, Debug)]
pub struct PgpSubkey {
    pub fingerprint: String,
    pub key_id: String,
    pub created: i64,
    pub expires: i64,
    pub revoked_at: Option<i64>,
    /// Index into `PgpKey::cert.public_subkeys`.
    pub index: usize,
}

/// Whether the key was usable at `at`, and if not, why.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PgpValidity {
    Valid,
    /// Expired before the commit time.
    Expired,
    /// Revoked at or before the commit time.
    Revoked,
    /// Revoked only after the commit time: valid when the commit was made.
    RevokedLater,
}

impl PgpKey {
    /// Evaluate a (sub)key's validity at a past instant.
    ///
    /// Mirrors GnuPG: a key expires when `expiry <= now`, and a revocation is
    /// effective from the revocation signature's creation time onward. A
    /// revocation published after the commit does not retroactively
    /// invalidate a signature that was good when made, which is why the
    /// caller can distinguish `RevokedLater`.
    pub fn validity_at(&self, at: i64) -> PgpValidity {
        if let Some(revoked) = self.revoked_at {
            if revoked <= at {
                return PgpValidity::Revoked;
            }
            return PgpValidity::RevokedLater;
        }
        if self.expires != 0 && self.expires <= at {
            return PgpValidity::Expired;
        }
        PgpValidity::Valid
    }

    pub fn subkey_validity_at(&self, subkey: &PgpSubkey, at: i64) -> PgpValidity {
        // A revocation of the primary key revokes the whole certificate.
        if let Some(revoked) = self.revoked_at {
            if revoked <= at {
                return PgpValidity::Revoked;
            }
        }
        if let Some(revoked) = subkey.revoked_at {
            if revoked <= at {
                return PgpValidity::Revoked;
            }
            return PgpValidity::RevokedLater;
        }
        if subkey.expires != 0 && subkey.expires <= at {
            return PgpValidity::Expired;
        }
        if self.expires != 0 && self.expires <= at {
            return PgpValidity::Expired;
        }
        PgpValidity::Valid
    }

    /// All user ids joined for reporting.
    pub fn identity(&self) -> Option<String> {
        self.user_ids.first().cloned()
    }

    /// The certificate's verification view for the primary key.
    pub fn primary(&self) -> &SignedPublicKey {
        &self.cert
    }

    pub fn subkey_cert(&self, subkey: &PgpSubkey) -> Option<&SignedPublicSubKey> {
        self.cert.public_subkeys.get(subkey.index)
    }
}

/// Find the newest self-signature (of any of `types`) containing a key
/// expiration subpacket, and return `created + expiration`.
///
/// OpenPGP puts `KeyExpirationTime` in a self-signature; the newest such
/// signature wins, matching GnuPG's `help_key_expire` handling in getkey.c.
fn expiry_from_signatures(created: i64, sigs: impl Iterator<Item = Signature>) -> i64 {
    let mut best: Option<(i64, u32)> = None; // (sig creation time, validity seconds)
    for sig in sigs {
        if let Some(dur) = sig.key_expiration_time() {
            let sig_created = sig.created().map(|t| i64::from(t.as_secs())).unwrap_or(0);
            if best.is_none_or(|(t, _)| sig_created >= t) {
                best = Some((sig_created, dur.as_secs()));
            }
        }
    }
    match best {
        Some((_, secs)) if secs > 0 => created.saturating_add(i64::from(secs)),
        _ => 0,
    }
}

/// The earliest creation time of a validly-signed revocation signature.
fn revocation_time<S>(sigs: &[Signature], verify: S) -> Option<i64>
where
    S: Fn(&Signature) -> bool,
{
    let mut earliest: Option<i64> = None;
    for sig in sigs {
        if sig.typ() != Some(SignatureType::KeyRevocation)
            && sig.typ() != Some(SignatureType::SubkeyRevocation)
        {
            continue;
        }
        if !verify(sig) {
            continue;
        }
        let t = sig.created().map(|t| i64::from(t.as_secs()))?;
        earliest = Some(earliest.map_or(t, |e| e.min(t)));
    }
    earliest
}

impl PgpKey {
    /// Build the derived validity view for a parsed certificate.
    ///
    /// Revocation and expiry only count when the self-signature carrying them
    /// actually verifies against the primary key, so a forged subpacket
    /// cannot convince the auditor a key is dead.
    pub fn from_cert(cert: SignedPublicKey) -> Self {
        let fingerprint = hex::encode(cert.primary_key.fingerprint().as_bytes());
        let key_id = cert.primary_key.legacy_key_id().to_string();
        let created = i64::from(cert.primary_key.created_at().as_secs());
        let primary = cert.primary_key.clone();

        let user_ids: Vec<String> = cert
            .details
            .users
            .iter()
            .map(|u| String::from_utf8_lossy(u.id.id()).to_string())
            .collect();

        let mut expiry_created = created;
        let mut expiries = Vec::new();
        for user in &cert.details.users {
            let newest = user
                .signatures
                .iter()
                .filter(|s| {
                    matches!(
                        s.typ(),
                        Some(SignatureType::CertGeneric)
                            | Some(SignatureType::CertPersona)
                            | Some(SignatureType::CertCasual)
                            | Some(SignatureType::CertPositive)
                    ) && s
                        .verify_certification(&primary, pgp::types::Tag::UserId, &user.id)
                        .is_ok()
                })
                .filter_map(|s| s.key_expiration_time().map(|d| (s, d)))
                .max_by_key(|(s, _)| s.created().map(|t| t.as_secs()).unwrap_or(0));
            if let Some((sig, dur)) = newest {
                let sig_created = sig.created().map(|t| i64::from(t.as_secs())).unwrap_or(0);
                if sig_created >= expiry_created {
                    expiry_created = sig_created;
                    expiries.push(i64::from(dur.as_secs()));
                }
            }
        }
        // Direct-key signatures can also carry it; fall back to those.
        if expiries.is_empty() {
            for sig in &cert.details.direct_signatures {
                if sig.typ() == Some(SignatureType::Key) && sig.verify_key(&primary).is_ok() {
                    if let Some(dur) = sig.key_expiration_time() {
                        let sig_created =
                            sig.created().map(|t| i64::from(t.as_secs())).unwrap_or(0);
                        if sig_created >= expiry_created {
                            expiry_created = sig_created;
                            expiries.push(i64::from(dur.as_secs()));
                        }
                    }
                }
            }
        }
        let expires = match expiries.last() {
            Some(&secs) if secs > 0 => created.saturating_add(secs),
            _ => 0,
        };

        let revoked_at = revocation_time(&cert.details.revocation_signatures, |sig| {
            sig.verify_key(&primary).is_ok()
        });

        let mut subkeys = Vec::new();
        for (index, sub) in cert.public_subkeys.iter().enumerate() {
            let sub_fpr = hex::encode(sub.key.fingerprint().as_bytes());
            let sub_id = sub.key.legacy_key_id().to_string();
            let sub_created = i64::from(sub.key.created_at().as_secs());
            let sub_expires = expiry_from_signatures(
                sub_created,
                sub.signatures
                    .iter()
                    .filter(|s| {
                        s.typ() == Some(SignatureType::SubkeyBinding)
                            && s.verify_subkey_binding(&primary, &sub.key).is_ok()
                    })
                    .cloned(),
            );
            let sub_revoked = revocation_time(&sub.signatures, |sig| {
                sig.verify_subkey_binding(&primary, &sub.key).is_ok()
            });
            subkeys.push(PgpSubkey {
                fingerprint: sub_fpr,
                key_id: sub_id,
                created: sub_created,
                expires: sub_expires,
                revoked_at: sub_revoked,
                index,
            });
        }

        PgpKey {
            fingerprint,
            key_id,
            user_ids,
            subkeys,
            created,
            expires,
            revoked_at,
            cert,
        }
    }
}

/// An in-memory OpenPGP keyring keyed by fingerprint and key id.
#[derive(Default)]
pub struct PgpKeyring {
    by_fingerprint: HashMap<String, PgpKey>,
    by_key_id: HashMap<String, Vec<String>>,
    /// User-id substrings supplied as trusted signers.
    trusted: Vec<String>,
}

impl PgpKeyring {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_trusted(&mut self, pattern: String) {
        self.trusted.push(pattern.to_lowercase());
    }

    pub fn is_empty(&self) -> bool {
        self.by_fingerprint.is_empty()
    }

    pub fn keys(&self) -> impl Iterator<Item = &PgpKey> {
        self.by_fingerprint.values()
    }

    pub fn insert(&mut self, key: PgpKey) {
        self.by_key_id
            .entry(key.key_id.clone())
            .or_default()
            .push(key.fingerprint.clone());
        for sub in &key.subkeys {
            self.by_key_id
                .entry(sub.key_id.clone())
                .or_default()
                .push(key.fingerprint.clone());
        }
        self.by_fingerprint.insert(key.fingerprint.clone(), key);
    }

    /// Look up the certificate that owns a given fingerprint (primary or
    /// subkey) and, for subkeys, which subkey matched.
    pub fn lookup(&self, fingerprint: Option<&str>, key_id: Option<&str>) -> Vec<&PgpKey> {
        if let Some(fpr) = fingerprint {
            let fpr = fpr.to_lowercase();
            if let Some(key) = self.by_fingerprint.get(&fpr) {
                return vec![key];
            }
            for key in self.by_fingerprint.values() {
                if key.subkeys.iter().any(|s| s.fingerprint == fpr) {
                    return vec![key];
                }
            }
        }
        if let Some(id) = key_id {
            let id = id.to_lowercase();
            if let Some(fprs) = self.by_key_id.get(&id) {
                // A key id may be shared by several subkeys of one certificate,
                // so identity is deduplicated by certificate fingerprint rather
                // than positionally.
                let mut out: Vec<&PgpKey> = Vec::new();
                let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
                for fpr in fprs {
                    if let Some(key) = self.by_fingerprint.get(fpr) {
                        if seen.insert(key.fingerprint.as_str()) {
                            out.push(key);
                        }
                    }
                }
                return out;
            }
        }
        Vec::new()
    }

    /// Whether a certificate is trusted under the configured allowlist.
    ///
    /// With no allowlist every key in the keyring is trusted. Otherwise a key
    /// must have a user id containing one of the configured substrings
    /// (case-insensitive). Fingerprint forms are accepted too.
    pub fn is_trusted(&self, key: &PgpKey) -> bool {
        if self.trusted.is_empty() {
            return true;
        }
        let fpr = key.fingerprint.to_lowercase();
        let key_id = key.key_id.to_lowercase();
        self.trusted.iter().any(|pattern| {
            let pattern = pattern.trim();
            if !pattern.is_empty() && (fpr.contains(pattern) || pattern.contains(&fpr)) {
                return true;
            }
            if !key_id.is_empty() && (key_id.contains(pattern) || pattern.contains(&key_id)) {
                return true;
            }
            key.user_ids
                .iter()
                .any(|uid| uid.to_lowercase().contains(pattern))
        })
    }

    /// Load every certificate in the given files. Each file may be armored or
    /// binary and may contain several certificates (e.g. an exported
    /// `pubring.gpg`).
    pub fn load_files(&mut self, paths: &[std::path::PathBuf]) -> anyhow::Result<()> {
        for path in paths {
            let bytes = std::fs::read(path)
                .with_context(|| format!("reading OpenPGP keyring {}", path.display()))?;
            let count = self
                .load_bytes(&bytes)
                .with_context(|| format!("parsing OpenPGP keyring {}", path.display()))?;
            if count == 0 {
                anyhow::bail!(
                    "no OpenPGP certificates found in {} (is it a keyring export?)",
                    path.display()
                );
            }
        }
        Ok(())
    }

    /// Parse armored or binary OpenPGP key material, returning how many
    /// certificates were added.
    pub fn load_bytes(&mut self, bytes: &[u8]) -> anyhow::Result<usize> {
        if bytes
            .windows(b"-----BEGIN PGP".len())
            .any(|w| w == b"-----BEGIN PGP")
        {
            let text = std::str::from_utf8(bytes)
                .map_err(|e| anyhow::anyhow!("armored keyring is not UTF-8: {e}"))?;
            let (iter, _headers) = SignedPublicKey::from_string_many(text)?;
            let mut n = 0;
            for key in iter {
                self.insert(PgpKey::from_cert(key?));
                n += 1;
            }
            Ok(n)
        } else if looks_like_keybox(bytes) {
            let mut n = 0;
            for raw in keybox_keyblocks(bytes)? {
                let iter = SignedPublicKey::from_bytes_many(BufReaderSlice::new(&raw))?;
                for key in iter {
                    self.insert(PgpKey::from_cert(key?));
                    n += 1;
                }
            }
            Ok(n)
        } else {
            let iter = SignedPublicKey::from_bytes_many(BufReaderSlice::new(bytes))?;
            let mut n = 0;
            for key in iter {
                self.insert(PgpKey::from_cert(key?));
                n += 1;
            }
            Ok(n)
        }
    }
}

/// `pgp` wants `BufRead`; this keeps the borrow lifetime explicit.
struct BufReaderSlice<'a> {
    inner: &'a [u8],
}

impl<'a> BufReaderSlice<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { inner: data }
    }
}

impl std::io::Read for BufReaderSlice<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = buf.len().min(self.inner.len());
        buf[..n].copy_from_slice(&self.inner[..n]);
        self.inner = &self.inner[n..];
        Ok(n)
    }
}

impl std::io::BufRead for BufReaderSlice<'_> {
    fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
        Ok(self.inner)
    }

    fn consume(&mut self, amt: usize) {
        let n = amt.min(self.inner.len());
        self.inner = &self.inner[n..];
    }
}

// --- GnuPG keybox (`pubring.kbx`) ------------------------------------------
//
// Modern GnuPG stores public keys in a `keybox` file rather than a flat
// OpenPGP keyring. The format is a sequence of length-prefixed blobs; PGP
// blobs embed the raw OpenPGP keyblock at a recorded offset. Supporting it
// means `--gpg-keyring ~/.gnupg/pubring.kbx` just works. Format reference:
// GnuPG `kbx/keybox-file.c` and `kbx/keybox-blob.c`.

const KBX_MAGIC_HEADER: u8 = 1;
const KBX_MAGIC_PGP: u8 = 2;

fn looks_like_keybox(bytes: &[u8]) -> bool {
    bytes.len() >= 32 && bytes[4] == KBX_MAGIC_HEADER && &bytes[8..12] == b"KBXf"
}

fn keybox_keyblocks(bytes: &[u8]) -> anyhow::Result<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + 5 <= bytes.len() {
        let len = u32::from_be_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]])
            as usize;
        if len < 5 || off + len > bytes.len() {
            anyhow::bail!("corrupt keybox blob at offset {off} (length {len})");
        }
        let blob_type = bytes[off + 4];
        if blob_type == KBX_MAGIC_PGP {
            // Both blob versions place the raw-keyblock offset/length at the
            // same header positions; they differ only in fingerprint width.
            let raw_off = u32::from_be_bytes([
                bytes[off + 8],
                bytes[off + 9],
                bytes[off + 10],
                bytes[off + 11],
            ]) as usize;
            let raw_len = u32::from_be_bytes([
                bytes[off + 12],
                bytes[off + 13],
                bytes[off + 14],
                bytes[off + 15],
            ]) as usize;
            let start = off + raw_off;
            let end = start + raw_len;
            if end <= bytes.len() && raw_len > 0 {
                out.push(strip_gnupg_trust_packets(&bytes[start..end]));
            }
        }
        off += len;
    }
    Ok(out)
}

/// Remove GnuPG `Trust` packets (old-format tag 12) from a keyblock.
///
/// Keybox files store trust records inline between the key packets. They are
/// not OpenPGP, and their presence makes a strict parser drop the user ID and
/// signature packets that follow, losing the identity we need for the
/// allowlist. Stripping them yields the transferable public key as GnuPG
/// would export it.
fn strip_gnupg_trust_packets(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut i = 0usize;
    while i < data.len() {
        let Some(&first) = data.get(i) else { break };
        if first & 0x80 == 0 {
            // Not a packet header: copy the remainder verbatim.
            out.extend_from_slice(&data[i..]);
            break;
        }
        let (tag, header_len, body_len) = if first & 0x40 == 0 {
            // Old-format header: tag in bits 5..2, length type in bits 1..0.
            let tag = (first >> 2) & 0x0f;
            let (hlen, len) = match first & 0x03 {
                0 => match data.get(i + 1) {
                    Some(&l) => (2usize, l as usize),
                    None => break,
                },
                1 => match data.get(i + 1..i + 3) {
                    Some(b) => (3usize, u16::from_be_bytes([b[0], b[1]]) as usize),
                    None => break,
                },
                2 => match data.get(i + 1..i + 5) {
                    Some(b) => (
                        5usize,
                        u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize,
                    ),
                    None => break,
                },
                _ => (1usize, data.len() - i - 1),
            };
            (tag, hlen, len)
        } else {
            // New-format header: tag in bits 5..0, length follows.
            match new_format_body_len(data, i) {
                Some((hlen, len)) => (first & 0x3f, hlen, len),
                None => break,
            }
        };
        let total = header_len.saturating_add(body_len);
        if total == 0 || i + total > data.len() {
            out.extend_from_slice(&data[i..]);
            break;
        }
        if tag != 12 {
            out.extend_from_slice(&data[i..i + total]);
        }
        i += total;
    }
    out
}

/// Decode a new-format packet length header, returning `(header_len, body_len)`
/// where `header_len` includes the tag octet at `start`.
fn new_format_body_len(data: &[u8], start: usize) -> Option<(usize, usize)> {
    let first = *data.get(start + 1)?;
    if first < 192 {
        Some((2, first as usize))
    } else if first < 224 {
        let second = *data.get(start + 2)?;
        Some((3, (((first as usize) - 192) << 8) + second as usize + 192))
    } else if first == 255 {
        let b = data.get(start + 2..start + 6)?;
        Some((6, u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize))
    } else {
        // Partial body lengths: the remainder is chunked; treat the rest of
        // the buffer as the body. Keybox keyblocks do not use this.
        Some((2, data.len().saturating_sub(start + 2)))
    }
}
