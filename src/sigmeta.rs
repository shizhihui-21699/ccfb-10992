//! Signature-envelope metadata, parsed without any external tool.
//!
//! Why parse this ourselves:
//!
//! * Reporting: the signature's own creation time comes from inside the
//!   signature packet. Comparing it to the commit timestamp is the cheapest way
//!   to catch a commit whose signer clock or metadata was manipulated.
//! * Robustness: the SSH signature carries its namespace; verifying that it is
//!   `git` needs no keys and no `ssh-keygen`, so a CI box without OpenSSH still
//!   gets a meaningful diagnostic instead of a blank verdict.
//!
//! Nothing here *decides* validity. Validity stays with gpg/ssh-keygen, matching
//! git's own practice; these parsers only supply facts.

use crate::object::SignatureFormat;

/// Facts extracted from an OpenPGP detached signature.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PgpSigInfo {
    /// Unix time from the signature's `creation time` hashed subpacket.
    pub created_at: Option<i64>,
    /// Signature type byte (0x00 = binary document).
    pub sig_type: Option<u8>,
    /// Public-key algorithm id.
    pub pubkey_algo: Option<u8>,
    /// Hash algorithm id.
    pub hash_algo: Option<u8>,
    /// Issuer key id from the issuer subpacket, if present.
    pub issuer_key_id: Option<String>,
    /// Number of signature packets seen in the armor payload.
    pub signature_packets: usize,
    /// Version of the first signature packet.
    pub version: Option<u8>,
}

/// Facts extracted from an SSH (SSHSIG) signature blob.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SshSigInfo {
    /// Namespace embedded in the signature, e.g. `git`.
    pub namespace: Option<String>,
    /// Hash algorithm name used over the message, e.g. `sha512`.
    pub hash_algorithm: Option<String>,
    /// SSH public key type string of the embedded key, e.g. `ssh-ed25519`.
    pub key_type: Option<String>,
    /// SSHSIG envelope version.
    pub version: Option<u32>,
}

/// Parse whatever metadata the envelope exposes.
#[derive(Debug, Clone)]
pub struct SignatureMeta {
    pub format: SignatureFormat,
    pub pgp: Option<PgpSigInfo>,
    pub ssh: Option<SshSigInfo>,
}

impl Default for SignatureMeta {
    fn default() -> Self {
        SignatureMeta {
            format: SignatureFormat::Unknown,
            pgp: None,
            ssh: None,
        }
    }
}

impl SignatureMeta {
    pub fn signature_created_at(&self) -> Option<i64> {
        self.pgp.as_ref().and_then(|p| p.created_at)
    }
}

pub fn parse(signature: &[u8]) -> SignatureMeta {
    let format = crate::object::detect_format(signature);
    match format {
        SignatureFormat::OpenPgp => SignatureMeta {
            format,
            pgp: parse_pgp(signature),
            ssh: None,
        },
        SignatureFormat::Ssh => SignatureMeta {
            format,
            pgp: None,
            ssh: parse_ssh(signature),
        },
        other => SignatureMeta {
            format: other,
            pgp: None,
            ssh: None,
        },
    }
}

// ---------------------------------------------------------------------------
// OpenPGP
// ---------------------------------------------------------------------------

/// Decode ASCII armor for a `-----BEGIN PGP SIGNATURE-----` / `MESSAGE` block.
fn dearmor(input: &[u8]) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(input).ok()?;
    let mut lines = text.lines();
    let begin = lines.next()?;
    if !begin.starts_with("-----BEGIN PGP") {
        return None;
    }
    let mut base64 = String::new();
    let mut in_headers = false;
    for line in lines {
        if line.starts_with("-----END PGP") {
            break;
        }
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            in_headers = false;
            continue;
        }
        if in_headers {
            continue;
        }
        // Armor headers sit between the BEGIN line and the first blank line.
        if base64.is_empty() && line.contains(':') {
            in_headers = true;
            continue;
        }
        if line.starts_with('=') {
            // CRC-24 checksum line.
            continue;
        }
        base64.push_str(line);
    }
    if base64.is_empty() {
        return None;
    }
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(base64)
        .ok()
}

/// Walk OpenPGP packets far enough to read signature metadata.
pub fn parse_pgp(signature: &[u8]) -> Option<PgpSigInfo> {
    let data = dearmor(signature).or_else(|| {
        // Tolerate an unarmored binary signature.
        if signature.first().map(|b| b & 0x80 != 0).unwrap_or(false) {
            Some(signature.to_vec())
        } else {
            None
        }
    })?;

    let mut info = PgpSigInfo::default();
    let mut pos = 0usize;
    while pos < data.len() {
        let hdr = data[pos];
        if hdr & 0x80 == 0 {
            break;
        }
        let (tag, body_start, body_len) = if hdr & 0x40 != 0 {
            // New-format packet header.
            let tag = hdr & 0x3f;
            let mut p = pos + 1;
            let first = *data.get(p)?;
            p += 1;
            let len = if first < 192 {
                first as usize
            } else if first < 224 {
                let second = *data.get(p)? as usize;
                p += 1;
                ((first as usize - 192) << 8) + second + 192
            } else if first == 255 {
                let bytes = data.get(p..p + 4)?;
                p += 4;
                u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize
            } else {
                // Partial body length: only the first chunk is used, which is
                // enough to read a signature packet's fixed prefix.
                1usize << (first & 0x1f)
            };
            (tag, p, len)
        } else {
            // Old-format packet header.
            let tag = (hdr >> 2) & 0x0f;
            let len_type = hdr & 0x03;
            let (mut p, len) = match len_type {
                0 => {
                    let l = *data.get(pos + 1)? as usize;
                    (pos + 2, l)
                }
                1 => {
                    let b = data.get(pos + 1..pos + 3)?;
                    (pos + 3, u16::from_be_bytes([b[0], b[1]]) as usize)
                }
                2 => {
                    let b = data.get(pos + 1..pos + 5)?;
                    (
                        pos + 5,
                        u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize,
                    )
                }
                _ => (pos + 1, data.len() - (pos + 1)),
            };
            let _ = &mut p;
            (tag, p, len)
        };

        if body_start + body_len > data.len() {
            break;
        }
        if tag == 2 {
            info.signature_packets += 1;
            if info.version.is_none() {
                parse_signature_body(&data[body_start..body_start + body_len], &mut info);
            }
        }
        pos = body_start + body_len;
    }

    if info.signature_packets == 0 {
        return None;
    }
    Some(info)
}

// ---------------------------------------------------------------------------
// OpenPGP
// ---------------------------------------------------------------------------

fn parse_signature_body(body: &[u8], info: &mut PgpSigInfo) {
    let Some(&version) = body.first() else {
        return;
    };
    info.version = Some(version);
    match version {
        3 => {
            // v3: version, hashed len(1)=5, sig type, creation time (4), keyid (8), pk algo, hash algo
            if body.len() < 19 {
                return;
            }
            info.sig_type = Some(body[2]);
            let created = u32::from_be_bytes([body[3], body[4], body[5], body[6]]);
            info.created_at = Some(created as i64);
            let keyid = &body[7..15];
            info.issuer_key_id = Some(hex::encode_upper(keyid));
            info.pubkey_algo = Some(body[15]);
            info.hash_algo = Some(body[16]);
        }
        4..=6 => {
            if body.len() < 6 {
                return;
            }
            info.sig_type = Some(body[1]);
            info.pubkey_algo = Some(body[2]);
            info.hash_algo = Some(body[3]);
            let hashed_len = u16::from_be_bytes([body[4], body[5]]) as usize;
            let hashed = body.get(6..6 + hashed_len).unwrap_or(&[]);
            parse_subpackets(hashed, info);
        }
        _ => {}
    }
}

/// Parse signature subpackets for creation time and issuer.
fn parse_subpackets(mut data: &[u8], info: &mut PgpSigInfo) {
    while !data.is_empty() {
        let first = data[0];
        let (len, header) = if first < 192 {
            (first as usize, 1)
        } else if first < 255 {
            if data.len() < 2 {
                return;
            }
            (((first as usize - 192) << 8) + data[1] as usize + 192, 2)
        } else {
            if data.len() < 5 {
                return;
            }
            (
                u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize,
                5,
            )
        };
        if len == 0 || header + len > data.len() {
            return;
        }
        let packet = &data[header..header + len];
        let ty = packet.first().copied().unwrap_or(0) & 0x7f;
        let body = &packet[1..];
        match ty {
            2 if body.len() >= 4 => {
                let ts = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
                info.created_at = Some(ts as i64);
            }
            16 if body.len() >= 8 => {
                info.issuer_key_id = Some(hex::encode_upper(&body[..8]));
            }
            33 if body.len() >= 8 => {
                // Issuer fingerprint.
                info.issuer_key_id
                    .get_or_insert_with(|| hex::encode_upper(&body[body.len() - 8..]));
            }
            _ => {}
        }
        data = &data[header + len..];
    }
}

// ---------------------------------------------------------------------------
// SSH
// ---------------------------------------------------------------------------

/// Decode the armored SSHSIG blob and read the namespace, hash and key type.
pub fn parse_ssh(signature: &[u8]) -> Option<SshSigInfo> {
    let text = std::str::from_utf8(signature).ok()?;
    let mut base64 = String::new();
    let mut inside = false;
    for line in text.lines() {
        let line = line.trim_end_matches('\r');
        if line.starts_with("-----BEGIN SSH SIGNATURE-----") {
            inside = true;
            continue;
        }
        if line.starts_with("-----END SSH SIGNATURE-----") {
            break;
        }
        if inside {
            base64.push_str(line.trim());
        }
    }
    if base64.is_empty() {
        return None;
    }
    use base64::Engine;
    let blob = base64::engine::general_purpose::STANDARD
        .decode(base64.as_bytes())
        .ok()?;
    parse_ssh_blob(&blob)
}

pub fn parse_ssh_blob(blob: &[u8]) -> Option<SshSigInfo> {
    let mut r = Reader::new(blob);
    let magic = r.bytes(6)?;
    if magic != b"SSHSIG" {
        return None;
    }
    let version = r.u32()?;
    let publickey = r.string()?;
    let namespace = r.string()?;
    let _reserved = r.string()?;
    let hash_algorithm = r.string()?;
    let _signature = r.string()?;

    let key_type = {
        let mut kr = Reader::new(publickey);
        kr.string().and_then(|b| String::from_utf8(b.to_vec()).ok())
    };

    Some(SshSigInfo {
        namespace: String::from_utf8(namespace.to_vec()).ok(),
        hash_algorithm: String::from_utf8(hash_algorithm.to_vec()).ok(),
        key_type,
        version: Some(version),
    })
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Reader { data, pos: 0 }
    }

    fn bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let slice = self.data.get(self.pos..end)?;
        self.pos = end;
        Some(slice)
    }

    fn u32(&mut self) -> Option<u32> {
        let b = self.bytes(4)?;
        Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn string(&mut self) -> Option<&'a [u8]> {
        let len = self.u32()? as usize;
        self.bytes(len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal v4 signature packet with a creation-time subpacket.
    fn v4_sig(created: u32) -> Vec<u8> {
        let mut hashed = Vec::new();
        // subpacket: length 5, type 2 (creation time), 4-byte timestamp.
        hashed.push(5u8);
        hashed.push(2u8);
        hashed.extend_from_slice(&created.to_be_bytes());
        // version 4, binary-document signature, EdDSA, SHA-512
        let mut body = vec![4u8, 0x00, 22, 10];
        body.extend_from_slice(&(hashed.len() as u16).to_be_bytes());
        body.extend_from_slice(&hashed);
        body.extend_from_slice(&[0, 0]); // unhashed subpacket count
        body.extend_from_slice(&[0x12, 0x34]); // left 16 bits of hash
        body.extend_from_slice(&[0u8; 4]); // signature material placeholder

        let mut packet = vec![0x89u8]; // old-format, tag 2, 2-byte length
        packet.extend_from_slice(&(body.len() as u16).to_be_bytes());
        packet.extend_from_slice(&body);
        packet
    }

    fn armor(packet: &[u8]) -> Vec<u8> {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode(packet);
        let mut out = String::from("-----BEGIN PGP SIGNATURE-----\n\n");
        for chunk in b64.as_bytes().chunks(64) {
            out.push_str(std::str::from_utf8(chunk).unwrap());
            out.push('\n');
        }
        out.push_str("-----END PGP SIGNATURE-----\n");
        out.into_bytes()
    }

    #[test]
    fn reads_pgp_creation_time() {
        let sig = armor(&v4_sig(1_700_000_000));
        let meta = parse(&sig);
        let pgp = meta.pgp.expect("pgp info");
        assert_eq!(pgp.created_at, Some(1_700_000_000));
        assert_eq!(pgp.version, Some(4));
        assert_eq!(pgp.sig_type, Some(0));
        assert_eq!(pgp.signature_packets, 1);
    }

    #[test]
    fn counts_multiple_signature_packets_like_git_would_see() {
        let mut two = v4_sig(1_700_000_000);
        two.extend_from_slice(&v4_sig(1_700_000_001));
        let meta = parse(&armor(&two));
        assert_eq!(meta.pgp.unwrap().signature_packets, 2);
    }

    /// Build an SSHSIG blob good enough to parse.
    fn ssh_blob(namespace: &str) -> Vec<u8> {
        fn put_string(out: &mut Vec<u8>, s: &[u8]) {
            out.extend_from_slice(&(s.len() as u32).to_be_bytes());
            out.extend_from_slice(s);
        }
        let mut pubkey = Vec::new();
        put_string(&mut pubkey, b"ssh-ed25519");
        put_string(&mut pubkey, &[0u8; 32]);

        let mut blob = Vec::new();
        blob.extend_from_slice(b"SSHSIG");
        blob.extend_from_slice(&1u32.to_be_bytes());
        put_string(&mut blob, &pubkey);
        put_string(&mut blob, namespace.as_bytes());
        put_string(&mut blob, b"");
        put_string(&mut blob, b"sha512");
        put_string(&mut blob, &[0u8; 64]);
        blob
    }

    #[test]
    fn reads_ssh_namespace_and_hash() {
        use base64::Engine;
        let blob = ssh_blob("git");
        let b64 = base64::engine::general_purpose::STANDARD.encode(&blob);
        let armored = format!(
            "-----BEGIN SSH SIGNATURE-----\n{}\n-----END SSH SIGNATURE-----\n",
            b64
        );
        let info = parse(&armored.into_bytes()).ssh.expect("ssh info");
        assert_eq!(info.namespace.as_deref(), Some("git"));
        assert_eq!(info.hash_algorithm.as_deref(), Some("sha512"));
        assert_eq!(info.key_type.as_deref(), Some("ssh-ed25519"));
        assert_eq!(info.version, Some(1));
    }

    #[test]
    fn garbage_yields_no_metadata() {
        assert!(parse(b"not a signature").pgp.is_none());
        assert!(parse(b"not a signature").ssh.is_none());
    }
}

#[cfg(test)]
mod fuzz {
    use super::*;

    /// Deterministic xorshift so the corpus is reproducible without a crate.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
        fn byte(&mut self) -> u8 {
            self.next() as u8
        }
    }

    #[test]
    fn parsers_never_panic_on_random_input() {
        let mut rng = Rng(0x2545F4914F6CDD1D);
        for len in 0..300usize {
            let mut buf = Vec::with_capacity(len);
            for _ in 0..len {
                buf.push(rng.byte());
            }
            // Raw bytes, and the same bytes wrapped in each armor header, so the
            // dearmor and packet paths are both exercised.
            let _ = parse_pgp(&buf);
            let _ = parse_ssh(&buf);
            let armored_pgp = [
                b"-----BEGIN PGP SIGNATURE-----\n\n".as_slice(),
                &buf,
                b"\n-----END PGP SIGNATURE-----\n".as_slice(),
            ]
            .concat();
            let _ = parse_pgp(&armored_pgp);
            let armored_ssh = [
                b"-----BEGIN SSH SIGNATURE-----\n".as_slice(),
                &buf,
                b"\n-----END SSH SIGNATURE-----\n".as_slice(),
            ]
            .concat();
            let _ = parse_ssh(&armored_ssh);
            let _ = parse(&buf);
        }
    }

    #[test]
    fn parsers_never_panic_on_truncated_real_prefixes() {
        // Truncate a structurally valid signature at every offset.
        let mut sig = Vec::new();
        sig.extend_from_slice(b"SSHSIG");
        sig.extend_from_slice(&1u32.to_be_bytes());
        for n in 0..80usize {
            let mut k = Vec::new();
            k.extend_from_slice(&(n as u32).to_be_bytes());
            k.extend(std::iter::repeat_n(0u8, n));
            sig.extend_from_slice(&k);
        }
        for cut in 0..sig.len() {
            let _ = parse_ssh_blob(&sig[..cut]);
        }
    }
}
