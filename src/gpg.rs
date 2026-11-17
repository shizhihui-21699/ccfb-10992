//! OpenPGP signature verification.
//!
//! Git shells out to `gpg --status-fd=1 --verify` and parses the `[GNUPG:]`
//! status lines; this module does the same, so cryptographic results agree with
//! `git log --show-signature` rather than with a hand-rolled OpenPGP parser.
//!
//! Where this tool deliberately differs from git: git always verifies at *the
//! current time*.  An audit needs "was this key valid when the commit was
//! made?", so verification is pinned to the commit timestamp with
//! `--faked-system-time <epoch>!` (the `!` freezes the clock).  gpg then judges
//! key expiry itself at that instant, which is exactly the wanted semantics.
//!
//! Revocation is the one case gpg cannot answer at a past time: it reports
//! `REVKEYSIG` no matter when the revocation happened.  For that we read the
//! revocation signature's own creation time from the key listing and compare it
//! with the commit time.

use crate::types::{Outcome, SigKind, SignatureInfo, Status};
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use tempfile::NamedTempFile;

/// Minimum OpenPGP trust level, mirroring git's `gpg.minTrustLevel`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TrustLevel {
    Undefined,
    Never,
    Marginal,
    Fully,
    Ultimate,
}

impl TrustLevel {
    pub fn parse(s: &str) -> Option<TrustLevel> {
        Some(match s.trim().to_ascii_lowercase().as_str() {
            "undefined" => TrustLevel::Undefined,
            "never" => TrustLevel::Never,
            "marginal" => TrustLevel::Marginal,
            "fully" => TrustLevel::Fully,
            "ultimate" => TrustLevel::Ultimate,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone)]
pub struct GpgConfig {
    pub program: PathBuf,
    pub home: Option<PathBuf>,
    pub keyrings: Vec<PathBuf>,
    pub min_trust: TrustLevel,
    /// Fingerprints allowed to sign.  Empty means "any key gpg accepts".
    pub trusted_fingerprints: Vec<String>,
}

impl Default for GpgConfig {
    fn default() -> Self {
        GpgConfig {
            program: PathBuf::from("gpg"),
            home: None,
            keyrings: Vec::new(),
            min_trust: TrustLevel::Undefined,
            trusted_fingerprints: Vec::new(),
        }
    }
}

pub struct GpgVerifier {
    cfg: GpgConfig,
    meta_cache: Mutex<HashMap<String, KeyMeta>>,
}

impl GpgVerifier {
    pub fn new(cfg: GpgConfig) -> GpgVerifier {
        GpgVerifier {
            cfg,
            meta_cache: Mutex::new(HashMap::new()),
        }
    }

    /// Verifies one signature over `payload` as of `at`.
    ///
    /// `at` is the committer timestamp.  When `None` the current time is used,
    /// which is what git does.
    pub fn verify(&self, payload: &[u8], signature: &[u8], at: Option<i64>) -> Outcome {
        let mut info = SignatureInfo {
            kind: Some(SigKind::OpenPgp),
            ..Default::default()
        };

        let sig_file = match write_temp(signature) {
            Ok(f) => f,
            Err(e) => {
                return failed(
                    info,
                    Status::Malformed,
                    format!("cannot stage signature for gpg: {e}"),
                )
            }
        };

        let at_commit = match self.run_verify(&sig_file, payload, at) {
            Ok(out) => out,
            // gpg could not be started (or died): a configuration/tooling
            // failure, not evidence that the signature is bad.
            Err(e) => return failed(info, Status::Unverifiable, e),
        };
        let parsed = match parse_status(&at_commit.stdout) {
            Ok(p) => p,
            Err(e) if e == MULTIPLE_SIGNATURES => {
                return failed(info, Status::Invalid, e.to_string())
            }
            Err(e) => return failed(info, Status::Malformed, e),
        };
        absorb(&mut info, &parsed);

        let fingerprint = parsed
            .fingerprint
            .clone()
            .or_else(|| parsed.primary_fingerprint.clone());

        if !parsed.result.crypto_good() {
            // A key that did not exist yet at the audited time makes gpg lose
            // the key entirely.  Re-check at the present time: if the crypto is
            // good now, the commit simply predates the key.
            if matches!(parsed.result, GpgResult::NoPublicKey | GpgResult::Error) && at.is_some() {
                if let Ok(now_out) = self.run_verify(&sig_file, payload, None) {
                    if let Ok(now_parsed) = parse_status(&now_out.stdout) {
                        if now_parsed.result.crypto_good() && now_parsed.result != GpgResult::Bad {
                            absorb(&mut info, &now_parsed);
                            info.detail = Some(
                                "signature verifies, but the signing key did not exist at the \
                                 commit time"
                                    .to_string(),
                            );
                            return Outcome {
                                status: Status::KeyNotYetValid,
                                info,
                            };
                        }
                    }
                }
            }
            let (status, detail) = match parsed.result {
                GpgResult::Bad => (Status::Invalid, "signature does not verify"),
                GpgResult::NoPublicKey => (
                    Status::NoPublicKey,
                    "the public key for this signature is not in the keyring",
                ),
                _ => (Status::Invalid, "gpg could not verify the signature (ERRSIG)"),
            };
            return failed(info, status, detail.to_string());
        }

        let meta = fingerprint
            .as_deref()
            .map(|f| self.key_meta(f))
            .unwrap_or_default();

        // gpg cannot judge revocation as of a past time; do it from the
        // revocation signature's creation time.
        if let Some(rev) = meta.revocation.clone() {
            match at {
                Some(ts) if rev.at <= ts => {
                    info.key_revoked_since = true;
                    info.detail = Some(format!(
                        "{} — the key was already revoked when this commit was made",
                        describe_revocation(&rev)
                    ));
                    return Outcome {
                        status: Status::KeyRevoked,
                        info,
                    };
                }
                Some(_) => {
                    // Revoked only after the fact: the signature stood when it
                    // was made.
                    info.key_revoked_since = true;
                    info.key_expired_since = expired_since(&meta, now_epoch());
                    info.detail = Some(format!(
                        "{} — revoked after this commit",
                        describe_revocation(&rev)
                    ));
                    return Outcome {
                        status: Status::Valid,
                        info,
                    };
                }
                None => {
                    if parsed.result == GpgResult::KeyRevoked {
                        info.detail = Some(describe_revocation(&rev));
                        return Outcome {
                            status: Status::KeyRevoked,
                            info,
                        };
                    }
                }
            }
        }

        info.key_expired_since = expired_since(&meta, now_epoch());

        let status = match parsed.result {
            GpgResult::Good => Status::Valid,
            GpgResult::KeyExpired => Status::KeyExpired,
            GpgResult::SignatureExpired => Status::SignatureExpired,
            GpgResult::KeyRevoked => Status::KeyRevoked,
            _ => Status::Valid,
        };
        if status != Status::Valid {
            info.detail = Some(match status {
                Status::KeyExpired => format!(
                    "the signing key expired {}, before this commit",
                    meta.expires
                        .map(format_epoch)
                        .unwrap_or_else(|| "at an unknown time".into())
                ),
                Status::SignatureExpired => "the signature itself has expired".into(),
                _ => status.as_str().to_string(),
            });
            return Outcome { status, info };
        }

        // Cryptographically good and timely: apply policy.
        if !self.cfg.trusted_fingerprints.is_empty() {
            let fped = info
                .primary_fingerprint
                .as_deref()
                .or(info.fingerprint.as_deref())
                .unwrap_or("");
            if !fingerprint_allowed(&self.cfg.trusted_fingerprints, fped) {
                info.detail = Some(format!(
                    "signer {fped} is not in the configured OpenPGP allow-list"
                ));
                return Outcome {
                    status: Status::UnknownSigner,
                    info,
                };
            }
        }
        if let Some(trust) = parsed.trust.as_deref() {
            let level = TrustLevel::parse(trust).unwrap_or(TrustLevel::Undefined);
            if level < self.cfg.min_trust {
                info.detail = Some(format!(
                    "gpg trust level '{trust}' is below the required minimum"
                ));
                return Outcome {
                    status: Status::NotPermitted,
                    info,
                };
            }
        }

        Outcome {
            status: Status::Valid,
            info,
        }
    }

    /// Runs a verification, returning raw output.
    fn run_verify(
        &self,
        sig_file: &NamedTempFile,
        payload: &[u8],
        at: Option<i64>,
    ) -> Result<CommandOutput, String> {
        let mut cmd = Command::new(&self.cfg.program);
        cmd.arg("--batch")
            .arg("--no-tty")
            .arg("--no-auto-check-trustdb")
            .arg("--status-fd=1")
            .arg("--keyid-format=long");
        self.apply_keyring_args(&mut cmd);
        if let Some(ts) = at {
            // Trailing `!` freezes the clock so validity is judged exactly here.
            cmd.arg("--faked-system-time").arg(format!("{ts}!"));
        }
        cmd.arg("--verify").arg(sig_file.path()).arg("-");
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = cmd.spawn().map_err(|e| {
            format!(
                "cannot run '{}': {e}. OpenPGP signatures need gpg on PATH.",
                self.cfg.program.display()
            )
        })?;
        if let Some(mut stdin) = child.stdin.take() {
            // gpg may exit early (e.g. unknown key); EPIPE is not an error here.
            let _ = stdin.write_all(payload);
        }
        let out = child
            .wait_with_output()
            .map_err(|e| format!("gpg did not run to completion: {e}"))?;
        Ok(CommandOutput {
            stdout: out.stdout,
            stderr: out.stderr,
        })
    }

    fn apply_keyring_args(&self, cmd: &mut Command) {
        if let Some(home) = &self.cfg.home {
            cmd.arg("--homedir").arg(home);
        }
        if !self.cfg.keyrings.is_empty() {
            cmd.arg("--no-default-keyring");
            for k in &self.cfg.keyrings {
                cmd.arg("--keyring").arg(k);
            }
        }
    }

    /// Looks up (and caches) key creation, expiry and revocation facts.
    fn key_meta(&self, fingerprint: &str) -> KeyMeta {
        if let Ok(cache) = self.meta_cache.lock() {
            if let Some(m) = cache.get(fingerprint) {
                return m.clone();
            }
        }
        let meta = self.query_key_meta(fingerprint).unwrap_or_default();
        if let Ok(mut cache) = self.meta_cache.lock() {
            cache.insert(fingerprint.to_string(), meta.clone());
        }
        meta
    }

    fn query_key_meta(&self, fingerprint: &str) -> Option<KeyMeta> {
        let mut cmd = Command::new(&self.cfg.program);
        cmd.arg("--batch")
            .arg("--no-tty")
            .arg("--with-colons")
            .arg("--with-sig-list")
            .arg("--fixed-list-mode");
        // Globals must precede the `--list-keys` action or gpg ignores them.
        self.apply_keyring_args(&mut cmd);
        cmd.arg("--list-keys").arg(fingerprint);
        let out = cmd.output().ok()?;
        if !out.status.success() {
            return None;
        }
        Some(parse_key_colons(&String::from_utf8_lossy(&out.stdout)))
    }
}

/// Key facts needed to answer "was this key valid at the commit time?".
#[derive(Debug, Clone, Default)]
pub struct KeyMeta {
    pub created: Option<i64>,
    /// `None` means the key does not expire.
    pub expires: Option<i64>,
    /// Most recent usable revocation applicable to this key.
    pub revocation: Option<Revocation>,
    pub primary_revoked: bool,
}

#[derive(Debug, Clone)]
pub struct Revocation {
    /// Creation time of the revocation signature.
    pub at: i64,
    /// OpenPGP revocation reason code, when present.
    pub reason: Option<u8>,
    /// True for a subkey revocation (class 0x28) rather than a key
    /// revocation (class 0x20).
    pub subkey: bool,
}

/// Parses `--with-colons --with-sig-list --list-keys` output.
///
/// `pub`/`sub` supply creation and expiry; `rev` records carry revocation
/// signatures whose class distinguishes a primary-key revocation (`0x20`) from
/// a subkey revocation (`0x28`).
pub fn parse_key_colons(text: &str) -> KeyMeta {
    let mut meta = KeyMeta::default();
    let mut saw_primary = false;

    for line in text.lines() {
        let f: Vec<&str> = line.split(':').collect();
        if f.len() < 2 {
            continue;
        }
        match f[0] {
            "pub" => {
                meta.created = epoch_field(f.get(5).copied());
                meta.expires = epoch_field(f.get(6).copied()).filter(|v| *v > 0);
                saw_primary = true;
            }
            "rev" => {
                let class_field = f.get(10).copied().unwrap_or("");
                let class = parse_sig_class(class_field);
                let reason = class_field
                    .split(',')
                    .nth(1)
                    .and_then(|r| u8::from_str_radix(r.trim(), 16).ok());
                let at = match epoch_field(f.get(5).copied()) {
                    Some(t) => t,
                    None => continue,
                };
                let is_subkey = class == Some(0x28);
                if !is_subkey {
                    meta.primary_revoked = true;
                }
                let rev = Revocation {
                    at,
                    reason,
                    subkey: is_subkey,
                };
                // The earliest revocation is when the key stopped being usable;
                // later ones are usually re-imports.
                match &meta.revocation {
                    Some(existing) if existing.at <= rev.at => {}
                    _ => meta.revocation = Some(rev),
                }
            }
            _ => {}
        }
    }

    if !saw_primary {
        return KeyMeta::default();
    }
    if meta.revocation.as_ref().is_some_and(|r| r.subkey) {
        // Without knowing which subkey signed, gpg's faked-time verdict stays
        // authoritative for subkey revocations.
        meta.primary_revoked = false;
    }
    meta
}

fn parse_sig_class(field: &str) -> Option<u8> {
    let hex = field.split(',').next()?.trim();
    let hex = hex.trim_end_matches(['x', 'l', 's']);
    u8::from_str_radix(hex, 16).ok()
}

fn epoch_field(s: Option<&str>) -> Option<i64> {
    let s = s?.trim();
    if s.is_empty() {
        return None;
    }
    if s.contains('T') {
        // gpgsm-style ISO timestamps: 19660205T091500
        let dt = chrono::NaiveDateTime::parse_from_str(s, "%Y%m%dT%H%M%S").ok()?;
        return Some(dt.and_utc().timestamp());
    }
    s.parse::<i64>().ok()
}

/// Marker returned by [`parse_status`] when gpg reported more than one
/// signature; callers map this to `Invalid`, matching git's `E`.
const MULTIPLE_SIGNATURES: &str =
    "gpg reported more than one signature and git rejects multi-signature commits";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum GpgResult {
    /// No exclusive status line was seen at all.
    #[default]
    None,
    Good,
    Bad,
    Error,
    SignatureExpired,
    KeyExpired,
    KeyRevoked,
    NoPublicKey,
}

impl GpgResult {
    /// True for every result that proves the cryptography checks out.
    fn crypto_good(self) -> bool {
        matches!(
            self,
            GpgResult::Good
                | GpgResult::SignatureExpired
                | GpgResult::KeyExpired
                | GpgResult::KeyRevoked
        )
        // `None` deliberately falls through: without a GOODSIG-family status
        // there is nothing proving the cryptography checks out.
    }
}

#[derive(Debug, Default)]
struct ParsedStatus {
    result: GpgResult,
    signer: Option<String>,
    key_id: Option<String>,
    fingerprint: Option<String>,
    primary_fingerprint: Option<String>,
    trust: Option<String>,
}

/// Parses git-style `[GNUPG:]` status output.
///
/// Mirrors `parse_gpg_output()`: the exclusive result is the last one seen, and
/// seeing more than one means multiple signatures — which git rejects too.
fn parse_status(stdout: &[u8]) -> Result<ParsedStatus, String> {
    let text = String::from_utf8_lossy(stdout);
    let mut parsed = ParsedStatus::default();
    let mut exclusive_seen = 0usize;

    for line in text.lines() {
        let line = match line.strip_prefix("[GNUPG:] ") {
            Some(l) => l,
            None => continue,
        };
        let (tag, rest) = match line.split_once(' ') {
            Some((t, r)) => (t, r),
            None => (line, ""),
        };

        let exclusive = match tag {
            "GOODSIG" => Some(GpgResult::Good),
            "BADSIG" => Some(GpgResult::Bad),
            "ERRSIG" => Some(GpgResult::Error),
            "EXPSIG" => Some(GpgResult::SignatureExpired),
            "EXPKEYSIG" => Some(GpgResult::KeyExpired),
            "REVKEYSIG" => Some(GpgResult::KeyRevoked),
            _ => None,
        };
        if let Some(result) = exclusive {
            exclusive_seen += 1;
            parsed.result = result;
            // "<keyid> <uid>"
            let (keyid, uid) = match rest.split_once(' ') {
                Some((k, u)) => (k, Some(u)),
                None => (rest, None),
            };
            parsed.key_id = Some(keyid.to_string()).filter(|s| !s.is_empty());
            parsed.signer = uid.map(str::trim).filter(|s| !s.is_empty()).map(str::to_string);
            continue;
        }
        match tag {
            "NO_PUBKEY" => parsed.result = GpgResult::NoPublicKey,
            "VALIDSIG" => {
                // VALIDSIG <fpr> <sig_ts> <sig_epoch> <expire_ts> ... <primary_fpr>
                let fields: Vec<&str> = rest.split_whitespace().collect();
                if let Some(f) = fields.first() {
                    parsed.fingerprint = Some((*f).to_string());
                }
                if fields.len() > 9 {
                    parsed.primary_fingerprint = Some(fields[9].to_string());
                }
            }
            "TRUST_ULTIMATE" | "TRUST_FULLY" | "TRUST_MARGINAL" | "TRUST_NEVER"
            | "TRUST_UNDEFINED" => {
                parsed.trust = Some(tag.trim_start_matches("TRUST_").to_ascii_lowercase());
            }
            _ => {}
        }
    }

    if exclusive_seen > 1 {
        // Git treats several signature results as an error rather than picking
        // one (`parse_gpg_output` sets result 'E'), so do the same.
        return Err(MULTIPLE_SIGNATURES.to_string());
    }
    Ok(parsed)
}

fn absorb(info: &mut SignatureInfo, parsed: &ParsedStatus) {
    info.signer = parsed.signer.clone();
    info.key_id = parsed.key_id.clone();
    info.fingerprint = parsed.fingerprint.clone();
    info.primary_fingerprint = parsed.primary_fingerprint.clone();
    info.trust = parsed.trust.clone();
}

fn expired_since(meta: &KeyMeta, now: i64) -> bool {
    matches!(meta.expires, Some(exp) if exp > 0 && exp < now)
}

fn fingerprint_allowed(allowed: &[String], fp: &str) -> bool {
    let fp = normalize_fpr(fp);
    if fp.is_empty() {
        return false;
    }
    allowed.iter().any(|a| {
        let a = normalize_fpr(a);
        // Full fingerprints and long key ids match as a suffix, mirroring how
        // gpg accepts key ids on the command line.
        a == fp || (a.len() >= 16 && fp.ends_with(&a)) || (fp.len() >= 16 && a.ends_with(&fp))
    })
}

fn normalize_fpr(s: &str) -> String {
    s.trim()
        .trim_start_matches("0x")
        .trim_start_matches("0X")
        .to_ascii_uppercase()
}

fn describe_revocation(rev: &Revocation) -> String {
    let reason = match rev.reason {
        Some(0) => "no reason given",
        Some(1) => "key superseded (soft)",
        Some(2) => "key material compromised",
        Some(3) => "key retired (soft)",
        Some(_) => "other reason",
        None => "reason not recorded",
    };
    let what = if rev.subkey { "subkey" } else { "key" };
    format!("{what} revocation dated {}, {reason}", format_epoch(rev.at))
}

fn failed(mut info: SignatureInfo, status: Status, detail: String) -> Outcome {
    info.detail = Some(detail);
    Outcome { status, info }
}

fn format_epoch(ts: i64) -> String {
    match chrono::DateTime::from_timestamp(ts, 0) {
        Some(dt) => dt.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        None => ts.to_string(),
    }
}

fn now_epoch() -> i64 {
    chrono::Utc::now().timestamp()
}

fn write_temp(data: &[u8]) -> std::io::Result<NamedTempFile> {
    let mut file = NamedTempFile::new()?;
    file.write_all(data)?;
    file.flush()?;
    Ok(file)
}

#[derive(Debug, Default)]
struct CommandOutput {
    #[allow(dead_code)]
    stdout: Vec<u8>,
    #[allow(dead_code)]
    stderr: Vec<u8>,
}

/// Exposed for tests and for callers that want the keyring layout.
#[allow(dead_code)]
pub fn keyring_paths(home: &Path) -> Vec<PathBuf> {
    vec![home.join("pubring.kbx"), home.join("pubring.gpg")]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_good_signature_status() {
        let out = b"[GNUPG:] NEWSIG\n\
                    [GNUPG:] GOODSIG 6F702E3002D1977F K <k@example.com>\n\
                    [GNUPG:] VALIDSIG EC68DB6360E77D82E074AFA46F702E3002D1977F 2024-01-03 1704240000 0 4 0 22 10 00 EC68DB6360E77D82E074AFA46F702E3002D1977F\n\
                    [GNUPG:] TRUST_ULTIMATE 0 pgp\n";
        let p = parse_status(out).unwrap();
        assert_eq!(p.result, GpgResult::Good);
        assert_eq!(p.key_id.as_deref(), Some("6F702E3002D1977F"));
        assert_eq!(p.signer.as_deref(), Some("K <k@example.com>"));
        assert_eq!(
            p.fingerprint.as_deref(),
            Some("EC68DB6360E77D82E074AFA46F702E3002D1977F")
        );
        assert_eq!(
            p.primary_fingerprint.as_deref(),
            Some("EC68DB6360E77D82E074AFA46F702E3002D1977F")
        );
        assert_eq!(p.trust.as_deref(), Some("ultimate"));
    }

    #[test]
    fn parses_terminal_results() {
        for (tag, expect) in [
            ("EXPKEYSIG", GpgResult::KeyExpired),
            ("REVKEYSIG", GpgResult::KeyRevoked),
            ("EXPSIG", GpgResult::SignatureExpired),
            ("BADSIG", GpgResult::Bad),
        ] {
            let out = format!("[GNUPG:] {tag} ABC K <k@example.com>\n");
            assert_eq!(parse_status(out.as_bytes()).unwrap().result, expect);
        }
    }

    #[test]
    fn no_public_key_is_not_crypto_good() {
        let out = b"[GNUPG:] ERRSIG ABC 22 10 00 1704240000 9 FPR\n[GNUPG:] NO_PUBKEY ABC\n";
        let p = parse_status(out).unwrap();
        assert_eq!(p.result, GpgResult::NoPublicKey);
        assert!(!p.result.crypto_good());
    }

    #[test]
    fn multiple_exclusive_results_are_rejected() {
        let out = b"[GNUPG:] GOODSIG A x\n[GNUPG:] BADSIG B y\n";
        assert!(parse_status(out).is_err());
    }

    #[test]
    fn parses_revocation_time_from_rev_records() {
        let colon = "\
pub:r:255:22:A9ABED34F1B5A72C:1704067200:::-:::sc:::::ed25519:::0:
fpr:::::::::7F29A968109FAF5363C8BD62A9ABED34F1B5A72C:
uid:r::::1704067200::HASH::Rev <r@example.com>::::::::::0:
rev:::22:A9ABED34F1B5A72C:1717200000::::Rev <r@example.com>:20x,02::7F29A968109FAF5363C8BD62A9ABED34F1B5A72C:::10:
";
        let meta = parse_key_colons(colon);
        assert_eq!(meta.created, Some(1704067200));
        let rev = meta.revocation.expect("revocation");
        assert_eq!(rev.at, 1717200000);
        assert!(!rev.subkey);
        assert_eq!(rev.reason, Some(2));
        assert!(meta.primary_revoked);
    }

    #[test]
    fn subkey_revocation_is_flagged_as_subkey() {
        let colon = "\
pub:u:255:22:AAAA:1704067200:::-:::sc:::::ed25519:::0:
sub:u:255:22:BBBB:1704153600:::-:::s:::::ed25519::::
rev:::22:BBBB:1717200000::::x:28x,00::AAAA:::10:
";
        let meta = parse_key_colons(colon);
        let rev = meta.revocation.expect("revocation");
        assert!(rev.subkey);
        assert_eq!(rev.at, 1717200000);
        assert!(!meta.primary_revoked);
    }

    #[test]
    fn earliest_revocation_wins() {
        let colon = "\
pub:r:255:22:AAAA:1704067200:::-:::sc:::::ed25519:::0:
rev:::22:AAAA:1717200000::::x:20x,00::AAAA:::10:
rev:::22:AAAA:1727200000::::x:20x,00::AAAA:::10:
";
        let meta = parse_key_colons(colon);
        assert_eq!(meta.revocation.unwrap().at, 1717200000);
    }

    #[test]
    fn expiry_absent_means_no_expiry() {
        let colon = "pub:u:255:22:AAAA:1704067200:::-:::sc:::::ed25519:::0:\n";
        let meta = parse_key_colons(colon);
        assert_eq!(meta.expires, None);
        assert!(!meta.primary_revoked);
    }

    #[test]
    fn fingerprint_allow_list_matches_full_and_suffix() {
        let allowed = vec!["0x7F29A968109FAF5363C8BD62A9ABED34F1B5A72C".to_string()];
        assert!(fingerprint_allowed(
            &allowed,
            "7f29a968109faf5363c8bd62a9abed34f1b5a72c"
        ));
        assert!(fingerprint_allowed(&allowed, "0xA9ABED34F1B5A72C"));
        assert!(!fingerprint_allowed(
            &allowed,
            "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF"
        ));
        assert!(!fingerprint_allowed(&allowed, ""));
    }

    #[test]
    fn key_meta_without_primary_is_empty() {
        let meta = parse_key_colons("rev:::22:AAAA:1717200000::::x:20x,00::AAAA:::10:\n");
        assert!(meta.revocation.is_none());
        assert!(!meta.primary_revoked);
    }
}
