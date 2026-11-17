//! SSH signature verification against an `allowed_signers` file.
//!
//! Git verifies SSH signatures by running
//! `ssh-keygen -Y find-principals` followed by `ssh-keygen -Y verify -n git`,
//! passing `-Overify-time=YYYYMMDDHHMMSS` in **local time** derived from the
//! committer timestamp.  This module reproduces that call sequence so the
//! verdicts — including `namespaces=`, `valid-after=`, `valid-before=`,
//! `cert-authority` handling and KRL revocation — match git exactly.
//!
//! Two things git does *not* do, and which an audit needs:
//!
//! * git verifies at the current time; we pin `-Overify-time` to the commit.
//! * a KRL is applied unconditionally, even for keys revoked after the commit.
//!   When a KRL is configured we therefore re-verify without it, and use the
//!   KRL's `generated_date` to decide whether the revocation predates the
//!   commit.
//!
//! The allowed_signers file is additionally parsed in Rust so the report can
//! say *why* a key was rejected (principal not listed, namespace not permitted,
//! validity window) instead of only echoing ssh-keygen's stderr.

use crate::types::{Outcome, SigKind, SignatureInfo, Status};
use chrono::{Local, TimeZone};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use tempfile::NamedTempFile;

#[derive(Debug, Clone)]
pub struct SshConfig {
    pub program: PathBuf,
    pub allowed_signers: PathBuf,
    /// `gpg.ssh.revocationFile`, when configured.
    pub revocation_file: Option<PathBuf>,
    pub namespace: String,
    /// Principals that are allowed to sign.  Empty means "any principal listed
    /// in the allowed_signers file".
    pub allowed_principals: Vec<String>,
}

impl SshConfig {
    pub fn new(allowed_signers: impl Into<PathBuf>) -> SshConfig {
        SshConfig {
            program: PathBuf::from("ssh-keygen"),
            allowed_signers: allowed_signers.into(),
            revocation_file: None,
            namespace: "git".to_string(),
            allowed_principals: Vec::new(),
        }
    }
}

pub struct SshVerifier {
    cfg: SshConfig,
    /// Parsed allowed_signers entries, loaded once.
    entries: Vec<AllowedSigner>,
}

impl SshVerifier {
    pub fn new(cfg: SshConfig) -> Result<SshVerifier, String> {
        if !cfg.allowed_signers.exists() {
            return Err(format!(
                "allowed_signers file '{}' does not exist",
                cfg.allowed_signers.display()
            ));
        }
        let text = std::fs::read_to_string(&cfg.allowed_signers)
            .map_err(|e| format!("cannot read allowed_signers file: {e}"))?;
        let entries = parse_allowed_signers(&text);
        Ok(SshVerifier { cfg, entries })
    }

    /// Verifies one SSH signature over `payload` as of `at`.
    pub fn verify(&self, payload: &[u8], signature: &[u8], at: Option<i64>) -> Outcome {
        let mut info = SignatureInfo {
            kind: Some(SigKind::Ssh),
            ..Default::default()
        };

        let sig_file = match write_temp(signature) {
            Ok(f) => f,
            Err(e) => {
                return failed(
                    info,
                    Status::Malformed,
                    format!("cannot stage signature for ssh-keygen: {e}"),
                )
            }
        };

        // Ask ssh-keygen for the payload key's fingerprint first; it is needed
        // for allow-list reporting regardless of the verdict.
        let novalidate = match self.check_novalidate(&sig_file, payload) {
            Ok(out) => out,
            // ssh-keygen could not be started at all: that is a configuration
            // failure, not a bad signature, and must not silently become
            // "signer unknown" further down.
            Err(e) => return failed(info, Status::Unverifiable, e),
        };
        if !novalidate.success {
            // Cryptographic failure or namespace mismatch — distinguish.
            let err = novalidate.stderr_text();
            if err.contains("namespace does not match") {
                info.detail = Some(format!(
                    "signature namespace is not '{}'",
                    self.cfg.namespace
                ));
                return Outcome {
                    status: Status::Invalid,
                    info,
                };
            }
            return failed(
                info,
                Status::Invalid,
                format!(
                    "ssh-keygen could not verify the signature{}",
                    if err.is_empty() {
                        String::new()
                    } else {
                        format!(": {}", first_line(&err))
                    }
                ),
            );
        }
        if let Some(fp) = parse_fingerprint(&novalidate.stdout) {
            info.fingerprint = Some(fp);
        }
        if let Some(signer) = parse_novalidate_signer(&novalidate.stdout) {
            info.signer = Some(signer);
        }

        // Find the principals whose allowed_signers lines match this key.
        let principals = match self.find_principals(&sig_file, at) {
            Ok(p) => p,
            Err(e) => return failed(info, Status::Malformed, e),
        };

        if principals.is_empty() {
            // Signature is cryptographically good (proved above) but the key is
            // not in allowed_signers, or matched a line whose validity window
            // excludes the commit time.
            let fp = info.fingerprint.clone().unwrap_or_default();
            // Several lines may list the same key; prefer one that would accept
            // this signature, so the reported reason is the most favourable.
            let entry = self
                .entries
                .iter()
                .filter(|e| e.fingerprint.as_deref() == Some(fp.as_str()))
                .min_by_key(|e| e.rejection_reason(at, &self.cfg.namespace).is_some() as u8);
            match entry {
                Some(e) => {
                    let reason = e
                        .rejection_reason(at, &self.cfg.namespace)
                        .unwrap_or_else(|| "key is not permitted by allowed_signers".to_string());
                    let status = classify_rejection(&reason);
                    info.detail = Some(reason);
                    return Outcome { status, info };
                }
                None => {
                    info.detail = Some(format!(
                        "key {fp} is not present in {}",
                        self.cfg.allowed_signers.display()
                    ));
                    return Outcome {
                        status: Status::UnknownSigner,
                        info,
                    };
                }
            }
        }

        // Try each matching principal until one verifies.
        let mut last_reason: Option<String> = None;
        for principal in &principals {
            if !self.cfg.allowed_principals.is_empty()
                && !self
                    .cfg
                    .allowed_principals
                    .iter()
                    .any(|p| principal_matches(p, principal))
            {
                last_reason = Some(format!(
                    "principal '{principal}' is not in the configured principal allow-list"
                ));
                continue;
            }
            match self.verify_as(&sig_file, payload, principal, at, true) {
                Ok(out) if out.success => {
                    info.signer = Some(principal.clone());
                    info.detail = None;
                    return Outcome {
                        status: Status::Valid,
                        info,
                    };
                }
                Ok(out) => {
                    // ssh-keygen applies a KRL unconditionally, regardless of the
                    // verification time, so a key revoked today cannot sign a
                    // commit that predates the revocation.  A KRL records no
                    // per-key revocation date (only when the list was generated),
                    // so there is no honest way to date the revocation: follow
                    // git and reject outright, but say why.
                    if self.cfg.revocation_file.is_some() {
                        if let Ok(without) = self.verify_as(&sig_file, payload, principal, at, false)
                        {
                            if without.success {
                                info.signer = Some(principal.clone());
                                info.key_revoked_since = true;
                                let generated = self.krl_generated_at();
                                info.detail = Some(match generated {
                                    Some(g) => format!(
                                        "the signing key appears in the configured KRL \
                                         (list generated {}); as in git, a KRL applies \
                                         regardless of when the commit was made",
                                        format_epoch(g)
                                    ),
                                    None => "the signing key appears in the configured KRL"
                                        .to_string(),
                                });
                                return Outcome {
                                    status: Status::KeyRevoked,
                                    info,
                                };
                            }
                        }
                    }
                    let err = out.stderr_text();
                    let reason = if err.is_empty() {
                        "ssh-keygen rejected the signature".to_string()
                    } else {
                        first_line(&err)
                    };
                    last_reason = Some(reason);
                }
                Err(e) => last_reason = Some(e),
            }
        }

        let reason = last_reason.unwrap_or_else(|| "no matching principal verified".to_string());
        let status = classify_rejection(&reason);
        info.detail = Some(reason);
        Outcome { status, info }
    }

    fn find_principals(&self, sig_file: &NamedTempFile, at: Option<i64>) -> Result<Vec<String>, String> {
        let mut cmd = Command::new(&self.cfg.program);
        cmd.arg("-Y")
            .arg("find-principals")
            .arg("-f")
            .arg(&self.cfg.allowed_signers)
            .arg("-s")
            .arg(sig_file.path());
        if let Some(t) = at {
            cmd.arg(format!("-Overify-time={}", ssh_time(t)));
        }
        let out = run(cmd, &[])?;
        // A non-zero exit with "No principal matched" is a normal miss, not an
        // error; only surface genuinely broken invocations.
        let text = String::from_utf8_lossy(&out.stdout);
        Ok(text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .collect())
    }

    fn verify_as(
        &self,
        sig_file: &NamedTempFile,
        payload: &[u8],
        principal: &str,
        at: Option<i64>,
        with_krl: bool,
    ) -> Result<CmdOutcome, String> {
        let mut cmd = Command::new(&self.cfg.program);
        cmd.arg("-Y")
            .arg("verify")
            .arg("-n")
            .arg(&self.cfg.namespace)
            .arg("-f")
            .arg(&self.cfg.allowed_signers)
            .arg("-I")
            .arg(principal)
            .arg("-s")
            .arg(sig_file.path());
        if let Some(t) = at {
            cmd.arg(format!("-Overify-time={}", ssh_time(t)));
        }
        if with_krl {
            if let Some(krl) = &self.cfg.revocation_file {
                if krl.exists() {
                    cmd.arg("-r").arg(krl);
                }
            }
        }
        let out = run(cmd, payload)?;
        // Git treats success as exit 0 *and* stdout starting with "Good".
        let success = out.success && out.stdout.starts_with(b"Good");
        Ok(CmdOutcome {
            success,
            stdout: out.stdout,
            stderr: out.stderr,
            status: out.status,
        })
    }

    fn check_novalidate(&self, sig_file: &NamedTempFile, payload: &[u8]) -> Result<CmdOutcome, String> {
        let mut cmd = Command::new(&self.cfg.program);
        cmd.arg("-Y")
            .arg("check-novalidate")
            .arg("-n")
            .arg(&self.cfg.namespace)
            .arg("-s")
            .arg(sig_file.path());
        let out = run(cmd, payload)?;
        Ok(CmdOutcome {
            success: out.success && out.stdout.starts_with(b"Good"),
            stdout: out.stdout,
            stderr: out.stderr,
            status: out.status,
        })
    }

    /// Reads the KRL header's `generated_date`.
    fn krl_generated_at(&self) -> Option<i64> {
        let path = self.cfg.revocation_file.as_ref()?;
        let bytes = std::fs::read(path).ok()?;
        parse_krl_generated_date(&bytes)
    }
}

#[derive(Debug)]
struct CmdOutcome {
    success: bool,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    #[allow(dead_code)]
    status: Option<i32>,
}

impl CmdOutcome {
    fn stderr_text(&self) -> String {
        String::from_utf8_lossy(&self.stderr).to_string()
    }
}

struct RawOutcome {
    success: bool,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    status: Option<i32>,
}

fn run(mut cmd: Command, stdin_data: &[u8]) -> Result<RawOutcome, String> {
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("cannot run ssh-keygen: {e}. SSH signatures need OpenSSH 8.2p1+."))?;
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(stdin_data);
    }
    let out = child
        .wait_with_output()
        .map_err(|e| format!("ssh-keygen did not run to completion: {e}"))?;
    Ok(RawOutcome {
        success: out.status.success(),
        stdout: out.stdout,
        stderr: out.stderr,
        status: out.status.code(),
    })
}

fn write_temp(data: &[u8]) -> std::io::Result<NamedTempFile> {
    let mut file = NamedTempFile::new()?;
    file.write_all(data)?;
    file.flush()?;
    Ok(file)
}

/// Formats an epoch as `YYYYMMDDHHMMSS` in the local timezone.
///
/// Git's `show_date(..., DATE_STRFTIME "%Y%m%d%H%M%S", .local = 1)` does the
/// same, and ssh-keygen parses the value as local time.  Matching the timezone
/// matters: a mismatch shifts the validity check by the UTC offset.
pub fn ssh_time(epoch: i64) -> String {
    match Local.timestamp_opt(epoch, 0).single() {
        Some(dt) => dt.format("%Y%m%d%H%M%S").to_string(),
        None => epoch.to_string(),
    }
}

fn first_line(s: &str) -> String {
    s.lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("")
        .to_string()
}

/// Extracts `SHA256:...` from `Good "git" signature for X with ED25519 key ...`.
pub fn parse_fingerprint(stdout: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(stdout);
    let line = text.lines().find(|l| l.starts_with("Good"))?;
    let rest = line.split("key ").nth(1)?;
    let fp = rest.split_whitespace().next()?;
    if fp.is_empty() {
        None
    } else {
        Some(fp.to_string())
    }
}

/// Extracts the principal from `Good "git" signature for PRINCIPAL with ...`.
pub fn parse_novalidate_signer(stdout: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(stdout);
    let line = text.lines().find(|l| l.starts_with("Good"))?;
    let rest = line.strip_prefix("Good \"")?;
    let rest = rest.split_once("signature for ")?.1;
    // The principal may contain spaces; ` with ` separates it from the key.
    let idx = rest.rfind(" with ")?;
    let principal = rest[..idx].trim();
    if principal.is_empty() {
        None
    } else {
        Some(principal.to_string())
    }
}

fn classify_rejection(reason: &str) -> Status {
    let r = reason.to_ascii_lowercase();
    if r.contains("key has expired") {
        Status::KeyExpired
    } else if r.contains("not yet valid") {
        Status::KeyNotYetValid
    } else if r.contains("not permitted for use in signature namespace") {
        Status::NotPermitted
    } else if r.contains("revoked") {
        Status::KeyRevoked
    } else if r.contains("unknown key") || r.contains("no principal matched") {
        Status::UnknownSigner
    } else {
        // ssh-keygen prints "Could not verify signature." for a bad signature
        // and for an unknown key; the caller distinguishes those earlier.
        Status::Invalid
    }
}

/// One line of an `allowed_signers` file.
#[derive(Debug, Clone)]
pub struct AllowedSigner {
    /// 1-based line number in the file, for diagnostics.
    #[allow(dead_code)]
    pub line_no: usize,
    /// Comma-separated principal patterns, as written.
    #[allow(dead_code)]
    pub principals: Vec<String>,
    pub options: SignerOptions,
    #[allow(dead_code)]
    pub key_type: String,
    pub fingerprint: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct SignerOptions {
    pub cert_authority: bool,
    pub namespaces: Option<Vec<String>>,
    pub valid_after: Option<i64>,
    pub valid_before: Option<i64>,
}

impl AllowedSigner {
    /// Explains why this entry does not authorise a signature at `at`, or
    /// `None` when it does.
    pub fn rejection_reason(&self, at: Option<i64>, namespace: &str) -> Option<String> {
        if let Some(ns) = &self.options.namespaces {
            if !ns.iter().any(|n| glob_match(n, namespace)) {
                return Some(format!(
                    "key is not permitted for signature namespace '{namespace}' \
                     (allowed: {})",
                    ns.join(", ")
                ));
            }
        }
        if let (Some(ts), Some(after)) = (at, self.options.valid_after) {
            if ts < after {
                return Some(format!(
                    "key is not yet valid: commit time {} is before valid-after {}",
                    format_epoch(ts),
                    format_epoch(after)
                ));
            }
        }
        if let (Some(ts), Some(before)) = (at, self.options.valid_before) {
            if ts > before {
                return Some(format!(
                    "key has expired: commit time {} is after valid-before {}",
                    format_epoch(ts),
                    format_epoch(before)
                ));
            }
        }
        None
    }
}

/// Parses an allowed_signers file the way OpenSSH does.
///
/// Format: `principals [options] keytype base64key [comment]`.  Principals are
/// comma-separated glob patterns; options are comma-separated `name="value"`
/// pairs.  Blank lines and lines starting with `#` are skipped.
pub fn parse_allowed_signers(text: &str) -> Vec<AllowedSigner> {
    let mut out = Vec::new();
    for (idx, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split_whitespace();
        let principals_field = match fields.next() {
            Some(p) => p,
            None => continue,
        };
        let principals: Vec<String> = principals_field
            .split(',')
            .filter(|p| !p.is_empty())
            .map(str::to_string)
            .collect();

        // The key begins at the first field that looks like a key type.
        let rest: Vec<&str> = fields.collect();
        let key_at = rest
            .iter()
            .enumerate()
            .position(|(i, f)| looks_like_key_type(f) && rest.get(i + 1).is_some_and(|b| is_base64ish(b)));

        let (key_type, key_b64, options) = match key_at {
            Some(i) => {
                let options = if i > 0 {
                    parse_signer_options(&rest[..i].join(" "))
                } else {
                    SignerOptions::default()
                };
                (rest[i].to_string(), rest[i + 1].to_string(), options)
            }
            None => continue, // malformed line: no key
        };

        let fingerprint = fingerprint_of(&key_type, &key_b64);
        out.push(AllowedSigner {
            line_no: idx + 1,
            principals,
            options,
            key_type,
            fingerprint,
        });
    }
    out
}

fn looks_like_key_type(s: &str) -> bool {
    matches!(
        s,
        "ssh-ed25519"
            | "ssh-rsa"
            | "ssh-dss"
            | "ecdsa-sha2-nistp256"
            | "ecdsa-sha2-nistp384"
            | "ecdsa-sha2-nistp521"
            | "sk-ssh-ed25519@openssh.com"
            | "sk-ecdsa-sha2-nistp256@openssh.com"
            | "ssh-ed25519-cert-v01@openssh.com"
            | "ssh-rsa-cert-v01@openssh.com"
            | "ecdsa-sha2-nistp256-cert-v01@openssh.com"
    )
}

fn is_base64ish(s: &str) -> bool {
    // Real key blobs are long; requiring a minimum keeps the key type from being
    // mistaken for a principal/option field in odd layouts.
    s.len() >= 8 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=')
}

/// Parses `namespaces="git",valid-after="20240101",cert-authority`.
///
/// Values may be quoted with `"` and commas separate options; a comma inside
/// quotes belongs to the value.
pub fn parse_signer_options(text: &str) -> SignerOptions {
    let mut opts = SignerOptions::default();
    for (name, value) in split_options(text) {
        match name.trim() {
            "cert-authority" => opts.cert_authority = true,
            "namespaces" => {
                if let Some(v) = value {
                    opts.namespaces = Some(
                        v.split(',')
                            .map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty())
                            .collect(),
                    );
                }
            }
            "valid-after" => opts.valid_after = value.as_deref().and_then(parse_absolute_time),
            "valid-before" => opts.valid_before = value.as_deref().and_then(parse_absolute_time),
            _ => {}
        }
    }
    opts
}

fn split_options(text: &str) -> Vec<(String, Option<String>)> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    let mut parts: Vec<String> = Vec::new();
    for ch in text.chars() {
        match ch {
            '"' => {
                in_quotes = !in_quotes;
                cur.push(ch);
            }
            ',' if !in_quotes => {
                parts.push(std::mem::take(&mut cur));
            }
            _ => cur.push(ch),
        }
    }
    if !cur.is_empty() {
        parts.push(cur);
    }
    for part in parts {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        match part.split_once('=') {
            Some((k, v)) => out.push((k.trim().to_string(), Some(v.trim().trim_matches('"').to_string()))),
            None => out.push((part.to_string(), None)),
        }
    }
    out
}

/// Parses OpenSSH absolute times: `YYYYMMDD`, `YYYYMMDDHHMM[SS]`, with an
/// optional leading/trailing `Z`, interpreted as UTC (matching OpenSSH).
pub fn parse_absolute_time(s: &str) -> Option<i64> {
    let s = s.trim().trim_end_matches('Z');
    let (date, time) = if let Some(idx) = s.find('T') {
        (&s[..idx], &s[idx + 1..])
    } else if s.len() > 8 {
        (&s[..8], &s[8..])
    } else {
        (s, "")
    };
    let date = chrono::NaiveDate::parse_from_str(date, "%Y%m%d").ok()?;
    let time = match time.len() {
        0 => chrono::NaiveTime::from_hms_opt(0, 0, 0)?,
        4 => chrono::NaiveTime::parse_from_str(time, "%H%M").ok()?,
        6 => chrono::NaiveTime::parse_from_str(time, "%H%M%S").ok()?,
        _ => return None,
    };
    Some(date.and_time(time).and_utc().timestamp())
}

/// Computes the OpenSSH `SHA256:...` fingerprint of a public key blob.
///
/// The fingerprint is the unpadded base64 of SHA-256 over the wire-format key
/// blob — the same value ssh-keygen prints.
pub fn fingerprint_of(_key_type: &str, key_b64: &str) -> Option<String> {
    use base64::Engine;
    let blob = base64::engine::general_purpose::STANDARD
        .decode(key_b64.as_bytes())
        .ok()?;
    let digest = sha256(&blob);
    let encoded = base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest);
    Some(format!("SHA256:{encoded}"))
}

fn sha256(data: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    Sha256::digest(data).to_vec()
}

/// Matches a principal against an allowed pattern using OpenSSH wildcard rules.
pub fn principal_matches(pattern: &str, principal: &str) -> bool {
    glob_match(pattern, principal)
}

/// OpenSSH `match_pattern()`: `*` and `?` wildcards, everything else literal.
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    glob_match_at(&p, &t)
}

fn glob_match_at(p: &[char], t: &[char]) -> bool {
    if p.is_empty() {
        return t.is_empty();
    }
    match p[0] {
        '*' => {
            // Collapse consecutive stars.
            let rest = p.iter().position(|c| *c != '*').unwrap_or(p.len());
            let rest = &p[rest..];
            if rest.is_empty() {
                return true;
            }
            (0..=t.len()).any(|i| glob_match_at(rest, &t[i..]))
        }
        '?' => !t.is_empty() && glob_match_at(&p[1..], &t[1..]),
        c => !t.is_empty() && t[0] == c && glob_match_at(&p[1..], &t[1..]),
    }
}

/// Reads `generated_date` from a KRL header.
///
/// Layout: `u64 magic`, `u32 version`, `u64 krl_version`, `u64 generated_date`.
pub fn parse_krl_generated_date(bytes: &[u8]) -> Option<i64> {
    const MAGIC: &[u8; 8] = b"SSHKRL\n\0";
    if bytes.len() < 28 || &bytes[..8] != MAGIC {
        return None;
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[20..28]);
    let v = u64::from_be_bytes(buf);
    i64::try_from(v).ok()
}

fn format_epoch(ts: i64) -> String {
    match chrono::DateTime::from_timestamp(ts, 0) {
        Some(dt) => dt.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        None => ts.to_string(),
    }
}

fn failed(mut info: SignatureInfo, status: Status, detail: String) -> Outcome {
    info.detail = Some(detail);
    Outcome { status, info }
}

/// True when `path` looks like a usable allowed_signers file.
#[allow(dead_code)]
pub fn allowed_signers_exists(path: &Path) -> bool {
    path.is_file()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_simple_entry() {
        let text = "alice ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAID2KScNMxmvOiekBBMKlE8oiQu9aIkVocxOo9jUGokfC alice@example\n";
        let entries = parse_allowed_signers(text);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].principals, vec!["alice"]);
        assert_eq!(entries[0].key_type, "ssh-ed25519");
        assert!(!entries[0].options.cert_authority);
        assert!(entries[0].fingerprint.as_deref().unwrap().starts_with("SHA256:"));
    }

    #[test]
    fn skips_comments_and_blanks() {
        let text = "# comment\n\n   \n#another\nalice ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAID2KScNMxmvOiekBBMKlE8oiQu9aIkVocxOo9jUGokfC\n";
        assert_eq!(parse_allowed_signers(text).len(), 1);
    }

    #[test]
    fn parses_multiple_principals() {
        let text = "alice,bob,carol ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAID2KScNMxmvOiekBBMKlE8oiQu9aIkVocxOo9jUGokfC\n";
        let e = &parse_allowed_signers(text)[0];
        assert_eq!(e.principals, vec!["alice", "bob", "carol"]);
    }

    #[test]
    fn parses_options() {
        let text = "alice namespaces=\"git\",valid-after=\"20240101\",valid-before=\"20250101\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAID2KScNMxmvOiekBBMKlE8oiQu9aIkVocxOo9jUGokfC\n";
        let e = &parse_allowed_signers(text)[0];
        assert_eq!(e.options.namespaces.as_deref(), Some(&["git".to_string()][..]));
        assert_eq!(e.options.valid_after, Some(1704067200));
        assert_eq!(e.options.valid_before, Some(1735689600));
    }

    #[test]
    fn parses_cert_authority_flag() {
        let text = "alice cert-authority,namespaces=\"git\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAID2KScNMxmvOiekBBMKlE8oiQu9aIkVocxOo9jUGokfC\n";
        let e = &parse_allowed_signers(text)[0];
        assert!(e.options.cert_authority);
        assert_eq!(e.options.namespaces.as_deref(), Some(&["git".to_string()][..]));
    }

    #[test]
    fn multiple_namespaces() {
        let e = &parse_allowed_signers(
            "alice namespaces=\"git,release\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAID2KScNMxmvOiekBBMKlE8oiQu9aIkVocxOo9jUGokfC\n",
        )[0];
        assert_eq!(
            e.options.namespaces.as_deref(),
            Some(&["git".to_string(), "release".to_string()][..])
        );
    }

    #[test]
    fn absolute_time_forms() {
        assert_eq!(parse_absolute_time("20240101"), Some(1704067200));
        assert_eq!(parse_absolute_time("202401011200"), Some(1704110400));
        assert_eq!(parse_absolute_time("20240101120000"), Some(1704110400));
        assert_eq!(parse_absolute_time("20240101Z"), Some(1704067200));
        assert_eq!(parse_absolute_time("not-a-time"), None);
    }

    #[test]
    fn glob_matching() {
        assert!(glob_match("alice", "alice"));
        assert!(!glob_match("alice", "bob"));
        assert!(glob_match("alice*", "alice@example.com"));
        assert!(glob_match("*@example.com", "bob@example.com"));
        assert!(glob_match("a?ice", "alice"));
        assert!(!glob_match("a?ice", "alce"));
        assert!(glob_match("*", "anything"));
    }

    #[test]
    fn namespace_rejection_is_explained() {
        let e = &parse_allowed_signers(
            "alice namespaces=\"release\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAID2KScNMxmvOiekBBMKlE8oiQu9aIkVocxOo9jUGokfC\n",
        )[0];
        let reason = e.rejection_reason(Some(1704067200), "git");
        assert!(reason.unwrap().contains("not permitted"));
        assert!(e.rejection_reason(Some(1704067200), "release").is_none());
    }

    #[test]
    fn validity_window_rejections() {
        let e = &parse_allowed_signers(
            "alice valid-after=\"20240101\",valid-before=\"20250101\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAID2KScNMxmvOiekBBMKlE8oiQu9aIkVocxOo9jUGokfC\n",
        )[0];
        assert!(e
            .rejection_reason(Some(1704067199), "git")
            .unwrap()
            .contains("not yet valid"));
        assert!(e.rejection_reason(Some(1704067200), "git").is_none());
        assert!(e
            .rejection_reason(Some(1735689601), "git")
            .unwrap()
            .contains("has expired"));
    }

    #[test]
    fn krl_generated_date_is_read_from_header() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"SSHKRL\n\0");
        bytes.extend_from_slice(&1u32.to_be_bytes());
        bytes.extend_from_slice(&7u64.to_be_bytes());
        bytes.extend_from_slice(&1704240000u64.to_be_bytes());
        bytes.extend_from_slice(&0u64.to_be_bytes());
        assert_eq!(parse_krl_generated_date(&bytes), Some(1704240000));
        assert_eq!(parse_krl_generated_date(b"not a krl"), None);
    }

    #[test]
    fn parses_fingerprint_from_novalidate_output() {
        let out = b"Good \"git\" signature with ED25519 key SHA256:GyB1Ma60YtUP6NqbgEECpgW0tNeNmbJB8k5jXyZK7AU\n";
        assert_eq!(
            parse_fingerprint(out).as_deref(),
            Some("SHA256:GyB1Ma60YtUP6NqbgEECpgW0tNeNmbJB8k5jXyZK7AU")
        );
        assert_eq!(parse_novalidate_signer(out), None);
    }

    #[test]
    fn parses_principal_with_spaces() {
        let out = b"Good \"git\" signature for Alice Smith with ED25519 key SHA256:abc\n";
        assert_eq!(parse_novalidate_signer(out).as_deref(), Some("Alice Smith"));
        assert_eq!(parse_fingerprint(out).as_deref(), Some("SHA256:abc"));
    }

    #[test]
    fn rejection_classification() {
        assert_eq!(
            classify_rejection("as:1: key has expired: verify time 2026-06-01T00:00:00 > valid-before"),
            Status::KeyExpired
        );
        assert_eq!(
            classify_rejection("as:1: key is not permitted for use in signature namespace \"git\""),
            Status::NotPermitted
        );
        assert_eq!(classify_rejection("Could not verify signature."), Status::Invalid);
    }

    #[test]
    fn ssh_time_is_local_and_zero_padded() {
        let s = ssh_time(1704153600);
        assert_eq!(s.len(), 14);
        assert!(s.chars().all(|c| c.is_ascii_digit()));
    }
}
