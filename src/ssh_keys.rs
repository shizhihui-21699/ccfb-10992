//! SSH signing trust material: `allowed_signers` files and KRLs.
//!
//! Git delegates SSH signature verification to `ssh-keygen -Y verify`, which
//! is *policy*, not just crypto. This module reproduces the pieces of
//! OpenSSH's `sshsig.c` that decide a signature's fate:
//!
//! * principal matching (`match_pattern_list` semantics, including `!` negation
//!   and `*`/`?` globs),
//! * per-line options `cert-authority`, `namespaces`, `valid-after` and
//!   `valid-before`,
//! * certificate authority validation (`sshkey_cert_check_authority`): CA
//!   signature, user cert type, validity window at verify time, principals,
//!   and the CA signature-algorithm allowlist,
//! * KRL revocation of plain keys, hashes, and certificates (serial, range,
//!   bitmap, key id) for a specific CA or for all CAs.
//!
//! Every file is read as untrusted input; malformed lines are reported instead
//! of aborting the audit, matching OpenSSH's "skip line, keep going" behavior
//! for unrelated lines but failing closed for lines that match the signer.

use std::path::Path;

use anyhow::Context;
use ssh_key::certificate::Certificate;
use ssh_key::{HashAlg, PublicKey};

use crate::sshsig::SignerKey;
use crate::wire::SshReader;
use ssh_encoding::Encode as _;

/// The allowlist rule a signature's signer principal was checked against.
#[derive(Clone, Debug)]
pub struct AllowedSigners {
    lines: Vec<SignerLine>,
    /// Parse diagnostics (bad lines etc.) that should reach the report.
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug)]
struct SignerLine {
    line_number: usize,
    /// Comma-separated principal patterns as written.
    principals: Vec<String>,
    options: SignerOptions,
    key: PublicKey,
}

#[derive(Clone, Debug, Default)]
struct SignerOptions {
    cert_authority: bool,
    namespaces: Option<Vec<String>>,
    valid_after: Option<u64>,
    valid_before: Option<u64>,
}

/// Result of matching a signature's embedded key against the allowlist.
#[derive(Clone, Debug)]
pub enum SignerMatch {
    /// A plain key matched; principal is the identity from the line.
    Key { principal: String, line: usize },
    /// A certificate matched a `cert-authority` line.
    Certificate {
        principal: Option<String>,
        ca_fingerprint: String,
        line: usize,
    },
    /// The key is recognized but a per-line option made it inapplicable at
    /// this verify time or namespace.
    Rejected { reason: String, line: usize },
    /// No line in the file matched this key at all.
    NotFound,
}

impl AllowedSigners {
    /// Read an `allowed_signers` file.
    ///
    /// Lines are `principal[,principal…] [options] keytype base64 [comment]`,
    /// exactly as OpenSSH's `parse_principals_key_and_options`.
    pub fn read_file(path: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading allowed signers file {}", path.display()))?;
        Ok(Self::parse(&text))
    }

    pub fn parse(text: &str) -> Self {
        let mut lines = Vec::new();
        let mut warnings = Vec::new();
        for (index, raw) in text.lines().enumerate() {
            let line_number = index + 1;
            let trimmed = raw.trim_start_matches([' ', '\t', '\n', '\r']);
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            match parse_signer_line(line_number, trimmed) {
                Ok(line) => lines.push(line),
                Err(e) => warnings.push(format!("{}:{}: {}", "allowed_signers", line_number, e)),
            }
        }
        Self { lines, warnings }
    }

    /// Number of successfully parsed signer lines (for tests/diagnostics).
    pub fn line_count(&self) -> usize {
        self.lines.len()
    }

    /// Match the signature's embedded key against the file at `verify_time`
    /// in `namespace`.
    ///
    /// Any key may be a certificate: `cert-authority` lines then match on the
    /// CA key, and the certificate is validated at verify time.
    pub fn match_signer(&self, key: &SignerKey, namespace: &str, verify_time: u64) -> SignerMatch {
        // OpenSSH tries every line until one matches; a later matching line
        // does not override an earlier rejection, but the first applicable
        // positive match wins.
        let mut first_rejection: Option<SignerMatch> = None;
        let cert_ref = key.certificate();
        let subject_data = key.verification_key();

        for line in &self.lines {
            let key_matches = if line.options.cert_authority {
                // OpenSSH compares the line's key with the *CA* that signed
                // the certificate (`sign_key->cert->signature_key`), not with
                // the certificate's own subject key.
                match cert_ref {
                    Some(c) => c.signature_key() == line.key.key_data(),
                    None => false,
                }
            } else {
                line.key.key_data() == subject_data
            };
            if !key_matches {
                continue;
            }

            // Namespace option check.
            if let Some(namespaces) = &line.options.namespaces {
                if match_pattern_list(namespace, namespaces) != 1 {
                    let reason = format!(
                        "key is not permitted for signature namespace {namespace:?} (line {})",
                        line.line_number
                    );
                    first_rejection.get_or_insert(SignerMatch::Rejected {
                        reason,
                        line: line.line_number,
                    });
                    continue;
                }
            }

            // Time validity option check.
            if let Some(after) = line.options.valid_after {
                if verify_time < after {
                    first_rejection.get_or_insert(SignerMatch::Rejected {
                        reason: format!(
                            "key is not yet valid at commit time {verify_time} (valid-after {after}, line {})",
                            line.line_number
                        ),
                        line: line.line_number,
                    });
                    continue;
                }
            }
            if let Some(before) = line.options.valid_before {
                if verify_time > before {
                    first_rejection.get_or_insert(SignerMatch::Rejected {
                        reason: format!(
                            "key had expired at commit time {verify_time} (valid-before {before}, line {})",
                            line.line_number
                        ),
                        line: line.line_number,
                    });
                    continue;
                }
            }

            if line.options.cert_authority {
                let Some(cert) = cert_ref else {
                    // A CA line with a plain key never matches; OpenSSH
                    // requires sshkey_is_cert(sign_key).
                    continue;
                };
                // CA signature must use an allowlisted algorithm.
                let ca_alg = cert.signature().algorithm().as_str().to_string();
                if !ca_signature_algorithm_allowed(&ca_alg) {
                    first_rejection.get_or_insert(SignerMatch::Rejected {
                        reason: format!(
                            "certificate signed with disallowed CA algorithm {ca_alg} (line {})",
                            line.line_number
                        ),
                        line: line.line_number,
                    });
                    continue;
                }
                let Some(principal) = match_certificate_principal(cert, line, verify_time) else {
                    first_rejection.get_or_insert(SignerMatch::Rejected {
                        reason: format!(
                            "certificate is not authorized by line {} at commit time {verify_time}",
                            line.line_number
                        ),
                        line: line.line_number,
                    });
                    continue;
                };
                return SignerMatch::Certificate {
                    principal,
                    ca_fingerprint: fingerprint(cert.signature_key(), HashAlg::Sha256),
                    line: line.line_number,
                };
            }

            // Plain key matched. OpenSSH's find-principals returns every listed
            // principal that patterns-match; verify succeeds if any do. We
            // report the first.
            let principal = line
                .principals
                .iter()
                .find(|p| match_pattern(principal_name_hint(key), p))
                .cloned()
                .or_else(|| line.principals.first().cloned())
                .unwrap_or_default();
            return SignerMatch::Key {
                principal,
                line: line.line_number,
            };
        }

        first_rejection.unwrap_or(SignerMatch::NotFound)
    }
}

/// What principal a signature is attributed to.
///
/// OpenSSH derives the identity from the *option list in the allowed_signers
/// line*, not from the key comment, so we use the comment only as a hint for
/// which listed principal to prefer.
fn principal_name_hint(key: &SignerKey) -> &str {
    match key {
        SignerKey::Plain(key) => key.comment(),
        SignerKey::Certificate(_) => "",
    }
}

fn match_certificate_principal(
    cert: &Certificate,
    line: &SignerLine,
    verify_time: u64,
) -> Option<Option<String>> {
    // CA signature over the certificate must verify first.
    if cert.verify_signature().is_err() {
        return None;
    }
    if !cert.cert_type().is_user() {
        return None;
    }
    let valid_after = cert.valid_after();
    let valid_before = cert.valid_before();
    if valid_after != 0 && verify_time < valid_after {
        return None;
    }
    if valid_before != 0 && verify_time >= valid_before {
        return None;
    }
    let cert_principals = cert.valid_principals();
    if cert_principals.is_empty() {
        return None;
    }
    for line_principal in &line.principals {
        for cert_principal in cert_principals {
            if match_pattern(cert_principal, line_principal) {
                return Some(Some(cert_principal.clone()));
            }
        }
    }
    None
}

/// OpenSSH's `SSH_ALLOWED_CA_SIGALGS` from `myproposal.h`.
fn ca_signature_algorithm_allowed(alg: &str) -> bool {
    let allowed = [
        "ssh-ed25519",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
        "sk-ssh-ed25519@openssh.com",
        "sk-ecdsa-sha2-nistp256@openssh.com",
        "webauthn-sk-ecdsa-sha2-nistp256@openssh.com",
        "rsa-sha2-512",
        "rsa-sha2-256",
        "ssh-mldsa44-ed25519",
    ];
    allowed.contains(&alg)
}

fn fingerprint(key: &ssh_key::public::KeyData, alg: HashAlg) -> String {
    ssh_key::Fingerprint::new(alg, key).to_string()
}

/// OpenSSH `match_pattern`: `*` matches any run, `?` any single character.
pub fn match_pattern(text: &str, pattern: &str) -> bool {
    // A small glob matcher, equivalent to the NFA in match.c for the subset
    // OpenSSH documents ('*' and '?'; there is no '[' class support there).
    fn helper(text: &[u8], pattern: &[u8]) -> bool {
        if pattern.is_empty() {
            return text.is_empty();
        }
        match pattern[0] {
            b'*' => {
                // Try every split; '*' matches zero or more characters.
                let mut rest = pattern;
                while rest.first() == Some(&b'*') {
                    rest = &rest[1..];
                }
                if rest.is_empty() {
                    return true;
                }
                for i in 0..=text.len() {
                    if helper(&text[i..], rest) {
                        return true;
                    }
                }
                false
            }
            b'?' => !text.is_empty() && helper(&text[1..], &pattern[1..]),
            c => text.first() == Some(&c) && helper(&text[1..], &pattern[1..]),
        }
    }
    helper(text.as_bytes(), pattern.as_bytes())
}

/// OpenSSH `match_pattern_list`: comma-separated patterns, `!` negation, and
/// the first matching negative entry wins (-1).
pub fn match_pattern_list(text: &str, patterns: &[String]) -> i32 {
    let mut got_positive = false;
    for sub in patterns {
        let (negated, pat) = match sub.strip_prefix('!') {
            Some(p) => (true, p),
            None => (false, sub.as_str()),
        };
        if pat.len() >= 1023 {
            return 0;
        }
        if match_pattern(text, pat) {
            if negated {
                return -1;
            }
            got_positive = true;
        }
    }
    if got_positive {
        1
    } else {
        0
    }
}

fn parse_signer_line(line_number: usize, line: &str) -> anyhow::Result<SignerLine> {
    // Format: `principal[,principal…] [options] keytype base64 [comment]`.
    // The options field is optional, so the key is recognised by parsing it,
    // not by counting fields (OpenSSH does the same via `sshkey_read`).
    let mut rest = line;
    let first = take_field(&mut rest).ok_or_else(|| anyhow::anyhow!("missing principal"))?;
    let principals: Vec<String> = first
        .split(',')
        .filter(|p| !p.is_empty())
        .map(|p| p.to_string())
        .collect();
    if principals.is_empty() {
        anyhow::bail!("missing principal");
    }

    rest = rest.trim_start_matches([' ', '\t']);
    let mut options = SignerOptions::default();
    let key = match PublicKey::from_openssh(rest) {
        Ok(key) => key,
        Err(_) => {
            let opts_field = take_field(&mut rest)
                .ok_or_else(|| anyhow::anyhow!("invalid line: missing options or key"))?;
            options = parse_options(opts_field, line_number)?;
            let key_text = rest.trim_start_matches([' ', '\t']);
            PublicKey::from_openssh(key_text).map_err(|e| anyhow::anyhow!("invalid key: {e}"))?
        }
    };

    Ok(SignerLine {
        line_number,
        principals,
        options,
        key,
    })
}

/// Take the next whitespace-delimited field, leaving `rest` at the first
/// character after it.
fn take_field<'a>(rest: &mut &'a str) -> Option<&'a str> {
    let text = rest.trim_start_matches([' ', '\t']);
    if text.is_empty() {
        return None;
    }
    let end = text.find([' ', '\t']).unwrap_or(text.len());
    let field = &text[..end];
    *rest = &text[end..];
    Some(field)
}

fn parse_options(field: &str, line_number: usize) -> anyhow::Result<SignerOptions> {
    let mut options = SignerOptions::default();
    for opt in split_options(field) {
        let opt = opt.trim();
        if opt.is_empty() {
            continue;
        }
        if opt == "cert-authority" {
            options.cert_authority = true;
        } else if let Some(value) = opt.strip_prefix("namespaces=") {
            let value = unquote(value);
            options.namespaces = Some(value.split(',').map(|s| s.to_string()).collect());
        } else if let Some(value) = opt.strip_prefix("valid-after=") {
            options.valid_after = Some(parse_absolute_time(unquote(value))?);
        } else if let Some(value) = opt.strip_prefix("valid-before=") {
            options.valid_before = Some(parse_absolute_time(unquote(value))?);
        } else {
            anyhow::bail!("unknown key option {opt:?} on line {line_number}");
        }
    }
    if let (Some(after), Some(before)) = (options.valid_after, options.valid_before) {
        if before <= after {
            anyhow::bail!("valid-before time is before valid-after on line {line_number}");
        }
    }
    Ok(options)
}

/// Split an option list on commas, ignoring commas inside double quotes, the
/// way OpenSSH's `opt_dequote` consumes quoted values.
fn split_options(field: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    for ch in field.chars() {
        match ch {
            '"' => {
                in_quotes = !in_quotes;
                current.push(ch);
            }
            ',' if !in_quotes => {
                out.push(std::mem::take(&mut current));
            }
            _ => current.push(ch),
        }
    }
    out.push(current);
    out
}

fn unquote(value: &str) -> &str {
    let value = value.trim();
    value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .unwrap_or(value)
}

/// OpenSSH `parse_absolute_time`: `YYYYMMDD`, `YYYYMMDDHHMM` or
/// `YYYYMMDDHHMMSS`, optionally suffixed `Z`/`UTC`, in the local timezone
/// unless a UTC suffix is present.
pub fn parse_absolute_time(s: &str) -> anyhow::Result<u64> {
    let (body, utc) = if let Some(b) = s.strip_suffix('Z') {
        (b, true)
    } else if let Some(b) = s.strip_suffix("UTC") {
        (b, true)
    } else {
        (s, false)
    };
    if !body.chars().all(|c| c.is_ascii_digit()) || body.len() < 8 {
        anyhow::bail!("invalid absolute time {s:?}");
    }
    let (y, mo, d) = (
        body[0..4].parse::<i16>()?,
        body[4..6].parse::<i8>()?,
        body[6..8].parse::<i8>()?,
    );
    let (h, mi, sec) = match body.len() {
        8 => (0, 0, 0),
        12 => (body[8..10].parse::<i8>()?, body[10..12].parse::<i8>()?, 0),
        14 => (
            body[8..10].parse::<i8>()?,
            body[10..12].parse::<i8>()?,
            body[12..14].parse::<i8>()?,
        ),
        n => anyhow::bail!("invalid absolute time length {n} in {s:?}"),
    };
    let dt: jiff::civil::DateTime = format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{sec:02}")
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid absolute time {s:?}: {e}"))?;
    let ts = if utc {
        dt.to_zoned(jiff::tz::TimeZone::UTC)
    } else {
        dt.to_zoned(jiff::tz::TimeZone::system())
    }
    .map_err(|e| anyhow::anyhow!("invalid absolute time {s:?}: {e}"))?;
    let secs = ts.timestamp().as_second();
    if secs <= 0 {
        anyhow::bail!("invalid absolute time {s:?}");
    }
    Ok(secs as u64)
}

// --- KRL -------------------------------------------------------------------

/// A parsed OpenSSH Key Revocation List.
///
/// Format reference: OpenSSH `PROTOCOL.krl`. We intentionally parse the
/// revocation payloads only; KRL signatures are optional for locally-trusted
/// files and OpenSSH does not use them for verification.
#[derive(Debug, Default)]
pub struct Krl {
    /// SHA-1 / SHA-256 digests of revoked plain key blobs.
    revoked_sha1: Vec<Vec<u8>>,
    revoked_sha256: Vec<Vec<u8>>,
    /// Explicitly revoked plain key blobs (algorithm string + body).
    revoked_keys: Vec<Vec<u8>>,
    /// Cert revocation sections keyed by CA blob (empty = wildcard CA).
    revoked_certs: Vec<CertRevocations>,
    /// Non-fatal parse warnings.
    pub warnings: Vec<String>,
}

#[derive(Debug, Default, Clone)]
struct CertRevocations {
    ca_key: Option<Vec<u8>>,
    serials: Vec<u64>,
    serial_ranges: Vec<(u64, u64)>,
    /// (offset, bitmap bytes, bit length)
    serial_bitmaps: Vec<(u64, Vec<u8>)>,
    key_ids: Vec<String>,
}

impl Krl {
    pub fn read_file(path: &Path) -> anyhow::Result<Self> {
        let bytes =
            std::fs::read(path).with_context(|| format!("reading KRL {}", path.display()))?;
        Self::parse(&bytes).with_context(|| format!("parsing KRL {}", path.display()))
    }

    pub fn parse(bytes: &[u8]) -> anyhow::Result<Self> {
        const MAGIC: u64 = 0x5353_484b_524c_0a00;
        let mut reader = SshReader::new(bytes);
        let magic = reader.u64()?;
        if magic != MAGIC {
            anyhow::bail!("not an SSH KRL (bad magic)");
        }
        let version = reader.u32()?;
        if version != 1 {
            anyhow::bail!("unsupported KRL format version {version}");
        }
        let _krl_version = reader.u64()?;
        let _generated = reader.u64()?;
        let _flags = reader.u64()?;
        let _reserved = reader.string()?;
        let _comment = reader.string()?;

        let mut krl = Krl::default();
        while !reader.is_empty() {
            let section_type = reader.u8()?;
            match section_type {
                1 => {
                    let section = SshReader::new(reader.string()?);
                    krl.parse_cert_section(section)?;
                }
                2 => {
                    let section = SshReader::new(reader.string()?);
                    let mut r = section;
                    while !r.is_empty() {
                        krl.revoked_keys.push(r.string()?.to_vec());
                    }
                }
                3 => {
                    let section = SshReader::new(reader.string()?);
                    let mut r = section;
                    while !r.is_empty() {
                        let hash = r.string()?;
                        if hash.len() != 20 {
                            anyhow::bail!("SHA-1 KRL section contains a {}-byte hash", hash.len());
                        }
                        krl.revoked_sha1.push(hash.to_vec());
                    }
                }
                4 => {
                    // Signature section: `string signing key` then `string signature`.
                    // We do not verify KRL signatures; consume to stay in sync.
                    let _sig_key = reader.string()?;
                    let _sig = reader.string()?;
                }
                5 => {
                    let section = SshReader::new(reader.string()?);
                    let mut r = section;
                    while !r.is_empty() {
                        let hash = r.string()?;
                        if hash.len() != 32 {
                            anyhow::bail!(
                                "SHA-256 KRL section contains a {}-byte hash",
                                hash.len()
                            );
                        }
                        krl.revoked_sha256.push(hash.to_vec());
                    }
                }
                255 => {
                    // Extension section: name, critical flag, contents.
                    let section = SshReader::new(reader.string()?);
                    let mut r = section;
                    let name = r.string()?;
                    let critical = r.u8()? != 0;
                    let _contents = r.string()?;
                    if critical {
                        krl.warnings.push(format!(
                            "KRL contains unsupported critical extension {:?}; ignoring it",
                            String::from_utf8_lossy(name)
                        ));
                    }
                }
                other => anyhow::bail!("unsupported KRL section type {other}"),
            }
        }
        Ok(krl)
    }

    fn parse_cert_section(&mut self, mut section: SshReader<'_>) -> anyhow::Result<()> {
        let ca_key_raw = section.string()?;
        let ca_key = if ca_key_raw.is_empty() {
            None
        } else {
            Some(ca_key_raw.to_vec())
        };
        let _reserved = section.string()?;
        let mut revocations = CertRevocations {
            ca_key,
            ..Default::default()
        };
        while !section.is_empty() {
            let sub_type = section.u8()?;
            let sub = SshReader::new(section.string()?);
            match sub_type {
                0x20 => {
                    let mut r = sub;
                    while !r.is_empty() {
                        revocations.serials.push(r.u64()?);
                    }
                }
                0x21 => {
                    let mut r = sub;
                    while !r.is_empty() {
                        let lo = r.u64()?;
                        let hi = r.u64()?;
                        revocations.serial_ranges.push((lo, hi));
                    }
                }
                0x22 => {
                    let mut r = sub;
                    while !r.is_empty() {
                        let offset = r.u64()?;
                        let bitmap = r.mpint_bytes()?.to_vec();
                        revocations.serial_bitmaps.push((offset, bitmap));
                    }
                }
                0x23 => {
                    let mut r = sub;
                    while !r.is_empty() {
                        revocations.key_ids.push(r.utf8_string()?.to_string());
                    }
                }
                0x39 => {
                    let mut r = sub;
                    let name = r.string()?;
                    let critical = r.u8()? != 0;
                    let _contents = r.string()?;
                    if critical {
                        self.warnings.push(format!(
                            "KRL certificate section contains unsupported critical extension {:?}",
                            String::from_utf8_lossy(name)
                        ));
                    }
                }
                other => anyhow::bail!("unsupported KRL certificate section {other:#x}"),
            }
        }
        self.revoked_certs.push(revocations);
        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self.revoked_keys.is_empty()
            && self.revoked_sha1.is_empty()
            && self.revoked_sha256.is_empty()
            && self.revoked_certs.is_empty()
    }

    /// Is the signature's embedded key revoked? Mirrors OpenSSH
    /// `ssh_krl_check_key`, which checks the key itself and, for a certificate,
    /// the issuing CA key too.
    pub fn revokes(&self, key: &SignerKey) -> bool {
        // A certificate is checked as a certificate (serial/key-id/section),
        // and its issuing CA key is checked as a plain key, mirroring
        // `ssh_krl_check_key`.
        let plain_data = key.verification_key();
        if let Some(plain_blob) = plain_key_blob_of_key_data(plain_data) {
            if self.revokes_plain_blob(&plain_blob) {
                return true;
            }
        }
        if let Some(cert) = key.certificate() {
            if self.revokes_cert(cert) {
                return true;
            }
            if let Some(ca_blob) = plain_key_blob_of_key_data(cert.signature_key()) {
                if self.revokes_plain_blob(&ca_blob) {
                    return true;
                }
            }
        }
        false
    }

    fn revokes_plain_blob(&self, plain_blob: &[u8]) -> bool {
        let sha1 = crate::wire::HashKind::Sha1.digest(plain_blob);
        let sha256 = crate::wire::HashKind::Sha256.digest(plain_blob);
        self.revoked_sha1.iter().any(|h| h == &sha1)
            || self.revoked_sha256.iter().any(|h| h == &sha256)
            || self.revoked_keys.iter().any(|b| b == plain_blob)
    }

    fn revokes_cert(&self, cert: &Certificate) -> bool {
        let ca_blob = plain_key_blob_of_key_data(cert.signature_key());
        for section in &self.revoked_certs {
            let ca_matches = match (&section.ca_key, &ca_blob) {
                (None, _) => true, // wildcard CA
                (Some(k), Some(b)) => k == b,
                (Some(_), None) => false,
            };
            if !ca_matches {
                continue;
            }
            // Key-id revocation applies regardless of serial.
            if section.key_ids.iter().any(|id| id == cert.key_id()) {
                return true;
            }
            // Serial 0 is ignored (OpenSSH treats it as "unspecified").
            let serial = cert.serial();
            if serial == 0 {
                continue;
            }
            if section.serials.contains(&serial) {
                return true;
            }
            if section
                .serial_ranges
                .iter()
                .any(|(lo, hi)| *lo <= serial && serial <= *hi)
            {
                return true;
            }
            for (offset, bitmap) in &section.serial_bitmaps {
                if serial < *offset {
                    continue;
                }
                // OpenSSH stores the bitmap as a big-endian integer: the byte
                // at the end of the string holds bits 0..7, with bit 0 the
                // least significant (`bitmap_from_string` in bitmap.c).
                let bit = serial - offset;
                let byte_from_end = (bit / 8) as usize;
                if byte_from_end >= bitmap.len() {
                    continue;
                }
                let byte = bitmap[bitmap.len() - 1 - byte_from_end];
                let bit_in_byte = (bit % 8) as u32;
                if (byte >> bit_in_byte) & 1 == 1 {
                    return true;
                }
            }
        }
        false
    }
}

fn plain_key_blob_of_key_data(data: &ssh_key::public::KeyData) -> Option<Vec<u8>> {
    // `KeyData::encode` is exactly `string(algorithm) || body`, which is the
    // plain key blob OpenSSH uses (see `sshkey_to_blob` / `plain_key_blob`).
    let mut blob = Vec::new();
    data.encode(&mut blob).ok()?;
    Some(blob)
}

/// Map a public key to a SHA256 fingerprint string.
pub fn sha256_fingerprint(key: &PublicKey) -> String {
    key.fingerprint(HashAlg::Sha256).to_string()
}

/// Collect KRLs parsed from files, merging their revocation sets.
#[derive(Default)]
pub struct KrlSet {
    krls: Vec<Krl>,
    pub warnings: Vec<String>,
}

impl KrlSet {
    pub fn add(&mut self, krl: Krl) {
        self.warnings.extend(krl.warnings.iter().cloned());
        self.krls.push(krl);
    }

    pub fn is_empty(&self) -> bool {
        self.krls.iter().all(|k| k.is_empty())
    }

    pub fn revokes(&self, key: &SignerKey) -> bool {
        self.krls.iter().any(|k| k.revokes(key))
    }
}

/// Count of revoked entries, for report metadata.
pub fn krl_entry_count(krl: &Krl) -> usize {
    krl.revoked_keys.len()
        + krl.revoked_sha1.len()
        + krl.revoked_sha256.len()
        + krl
            .revoked_certs
            .iter()
            .map(|c| {
                c.serials.len() + c.serial_ranges.len() + c.serial_bitmaps.len() + c.key_ids.len()
            })
            .sum::<usize>()
}
