//! OpenPGP verification by driving `gpg`, mirroring git's
//! `verify_gpg_signed_buffer()` + `parse_gpg_output()`.
//!
//! git shells out to `gpg --status-fd=1 --verify <tmpfile> -` with the payload
//! on stdin and parses the `[GNUPG:]` status lines. We do the same, and then
//! additionally layer in the "was the key valid at commit time" question that
//! git deliberately leaves to wall-clock time.
//!
//! git's own result letters (from `parse_gpg_output`):
//!   G GOODSIG, B BADSIG, E ERRSIG, X EXPSIG, Y EXPKEYSIG, R REVKEYSIG.
//! `check_signature()` then treats the signature as failed unless result == G
//! *and* the trust level meets `gpg.minTrustLevel` (default: undefined). That
//! is why an expired-but-good signature surfaces as `%G? == Y`.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use crate::object::HashAlgorithm;

/// git's signature trust levels, in ascending order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TrustLevel {
    Undefined = 0,
    Never = 1,
    Marginal = 2,
    Fully = 3,
    Ultimate = 4,
}

impl TrustLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            TrustLevel::Undefined => "undefined",
            TrustLevel::Never => "never",
            TrustLevel::Marginal => "marginal",
            TrustLevel::Fully => "fully",
            TrustLevel::Ultimate => "ultimate",
        }
    }

    fn parse_git(level: &str) -> Option<TrustLevel> {
        match level {
            "UNDEFINED" => Some(TrustLevel::Undefined),
            "NEVER" => Some(TrustLevel::Never),
            "MARGINAL" => Some(TrustLevel::Marginal),
            "FULLY" => Some(TrustLevel::Fully),
            "ULTIMATE" => Some(TrustLevel::Ultimate),
            _ => None,
        }
    }
}

/// Raw `gpg` status output translated to git's vocabulary.
#[derive(Debug, Clone, Default)]
pub struct GpgStatus {
    /// git's single-letter result (G/B/E/X/Y/R), if any status was seen.
    pub result: Option<char>,
    pub signer: Option<String>,
    /// Long key id from the GOODSIG family / ERRSIG.
    pub key: Option<String>,
    /// Fingerprint of the signing (sub)key, from VALIDSIG.
    pub fingerprint: Option<String>,
    /// Fingerprint of the primary key, from VALIDSIG's 10th field when present.
    pub primary_fingerprint: Option<String>,
    pub trust_level: Option<TrustLevel>,
    /// Unix time at which gpg says the key expired (`KEYEXPIRED`).
    pub key_expired_at: Option<i64>,
    /// True if gpg emitted `KEYREVOKED`.
    pub key_revoked: bool,
    /// True if gpg emitted `REVKEYSIG`.
    pub revoked_signature: bool,
    /// True if gpg emitted `EXPKEYSIG`/`EXPSIG`.
    pub expired_signature: bool,
    /// Number of exclusive statuses (`GOODSIG`, `BADSIG`, ...) seen. git
    /// refuses signatures with more than one.
    pub exclusive_statuses: usize,
    pub status_lines: Vec<String>,
    pub stderr: String,
    pub exit_ok: bool,
}

impl GpgStatus {
    /// git's `parse_gpg_output()` verdict: a signature is good only when all
    /// exclusive statuses agree and exactly one was seen.
    pub fn is_git_good(&self) -> bool {
        self.result == Some('G') && self.exclusive_statuses == 1
    }
}

#[derive(Debug, Clone)]
pub struct GpgVerifier {
    pub program: String,
    pub home: Option<String>,
}

impl GpgVerifier {
    pub fn new(program: impl Into<String>, home: Option<String>) -> Self {
        GpgVerifier {
            program: program.into(),
            home,
        }
    }

    /// Verify `payload` against a detached armored `signature`.
    ///
    /// `at_time`, when set, is enforced by gpg's `--faked-system-time`, which
    /// makes gpg itself decide whether the key was live at that instant — the
    /// same rule git applies when verifying a historic tag with `-Overify-time`
    /// style semantics. It also keeps us honest about revocation: gpg applies a
    /// revocation certificate from the moment it was issued, so a commit made
    /// before the revocation still verifies as good.
    pub fn verify(
        &self,
        signature: &[u8],
        payload: &[u8],
        at_time: Option<i64>,
        _algo: HashAlgorithm,
    ) -> GpgStatus {
        let tmp = match tempfile::Builder::new().prefix("sigaudit-sig-").tempfile() {
            Ok(t) => t,
            Err(e) => {
                return GpgStatus {
                    stderr: format!("could not create temp file for signature: {e}"),
                    ..Default::default()
                }
            }
        };
        if let Err(e) = tmp.as_file().write_all(signature) {
            return GpgStatus {
                stderr: format!("could not write signature to temp file: {e}"),
                ..Default::default()
            };
        }

        let mut cmd = Command::new(&self.program);
        cmd.arg("--keyid-format=long");
        if let Some(home) = &self.home {
            cmd.arg("--homedir").arg(home);
        }
        if let Some(at) = at_time {
            // The trailing `!` forces gpg to accept the seconds value exactly
            // instead of rounding it against the current time.
            cmd.arg("--faked-system-time").arg(format!("{at}!"));
        }
        // Every option must come before the input files: gpg stops option
        // parsing once it sees `--verify`, and anything after the `-` operand
        // is treated as another data file.
        cmd.arg("--status-fd=1").arg("--batch").arg("--no-tty");
        if at_time.is_some() {
            // A faked clock makes gpg distrust its cached trustdb, which is fine
            // here: we judge cryptographic validity, not web-of-trust standing.
            cmd.arg("--no-auto-check-trustdb");
        }
        cmd.arg("--verify")
            .arg(tmp.path())
            .arg("-")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                return GpgStatus {
                    stderr: format!("could not run {}: {e}", self.program),
                    ..Default::default()
                }
            }
        };
        if let Some(mut stdin) = child.stdin.take() {
            // gpg may exit before consuming all input; a broken pipe is not an
            // error we care about.
            let _ = stdin.write_all(payload);
        }
        let output = match child.wait_with_output() {
            Ok(o) => o,
            Err(e) => {
                return GpgStatus {
                    stderr: format!("could not wait for {}: {e}", self.program),
                    ..Default::default()
                }
            }
        };

        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        let mut status = parse_status(&stdout);
        status.stderr = stderr;
        status.exit_ok = output.status.success();
        status
    }

    /// Whether the gpg binary responds at all; used for a clear error message.
    pub fn is_available(&self) -> bool {
        Command::new(&self.program)
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
}

/// Parse `[GNUPG:] ...` status lines with the same precedence as git.
pub fn parse_status(stdout: &str) -> GpgStatus {
    let mut st = GpgStatus::default();
    for raw in stdout.split_inclusive('\n') {
        let line = raw.strip_suffix('\n').unwrap_or(raw);
        let Some(rest) = line.strip_prefix("[GNUPG:] ") else {
            continue;
        };
        st.status_lines.push(rest.to_string());
        let (keyword, args) = match rest.find(' ') {
            Some(i) => (&rest[..i], &rest[i + 1..]),
            None => (rest, ""),
        };
        match keyword {
            "GOODSIG" | "BADSIG" | "EXPSIG" | "EXPKEYSIG" | "REVKEYSIG" | "ERRSIG" => {
                st.exclusive_statuses += 1;
                let result = match keyword {
                    "GOODSIG" => 'G',
                    "BADSIG" => 'B',
                    "EXPSIG" => 'X',
                    "EXPKEYSIG" => 'Y',
                    "REVKEYSIG" => 'R',
                    _ => 'E',
                };
                // git keeps the last exclusive result, but rejects the whole
                // signature when more than one is seen.
                st.result = Some(result);
                if keyword == "EXPKEYSIG" || keyword == "EXPSIG" {
                    st.expired_signature = true;
                }
                if keyword == "REVKEYSIG" {
                    st.revoked_signature = true;
                }
                let mut parts = args.splitn(2, ' ');
                st.key = parts.next().map(str::to_string).filter(|s| !s.is_empty());
                if let Some(signer) = parts.next() {
                    if !signer.is_empty() {
                        st.signer = Some(signer.to_string());
                    }
                }
            }
            "VALIDSIG" => {
                let fields: Vec<&str> = args.split(' ').collect();
                if let Some(fpr) = fields.first() {
                    st.fingerprint = Some((*fpr).to_string());
                }
                // git skips 9 interim fields and takes the next one as the
                // primary key fingerprint (present only for OpenPGP sigs).
                if fields.len() >= 10 {
                    st.primary_fingerprint = Some(fields[9].to_string());
                }
            }
            // git's status table matches on the "TRUST_" prefix, so the
            // keywords here are TRUST_UNDEFINED, TRUST_FULLY, and friends.
            k if k.starts_with("TRUST_") => {
                // git strips the "TRUST_" prefix and compares the remainder
                // against its table (UNDEFINED, NEVER, MARGINAL, FULLY,
                // ULTIMATE); the rest of the line is not involved.
                let level = &k["TRUST_".len()..];
                if let Some(t) = TrustLevel::parse_git(level) {
                    // Later TRUST_ lines win, matching git's loop order.
                    st.trust_level = Some(t);
                }
            }
            "KEYEXPIRED" => {
                if let Ok(ts) = args.trim().parse::<i64>() {
                    st.key_expired_at = Some(ts);
                }
            }
            "KEYREVOKED" => st.key_revoked = true,
            "NO_PUBKEY" if st.key.is_none() => {
                st.key = Some(args.trim().to_string());
            }
            _ => {}
        }
    }
    st
}

/// Resolve which gpg home git itself would use.
pub fn resolve_gpg_home(explicit: Option<&Path>) -> Option<String> {
    if let Some(p) = explicit {
        return Some(p.display().to_string());
    }
    std::env::var("GNUPGHOME").ok().filter(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_good_status() {
        let out = "[GNUPG:] NEWSIG\n\
                   [GNUPG:] KEY_CONSIDERED ABCD 0\n\
                   [GNUPG:] GOODSIG 1234567890ABCDEF Alice <alice@example.com>\n\
                   [GNUPG:] VALIDSIG ABCDEF0123456789ABCDEF0123456789ABCDEF01 2024-01-01 1700000000 0 4 0 22 10 00 ABCDEF0123456789ABCDEF0123456789ABCDEF01\n\
                   [GNUPG:] TRUST_FULLY 0 pgp\n";
        let st = parse_status(out);
        assert_eq!(st.result, Some('G'));
        assert_eq!(st.exclusive_statuses, 1);
        assert_eq!(st.signer.as_deref(), Some("Alice <alice@example.com>"));
        assert_eq!(st.key.as_deref(), Some("1234567890ABCDEF"));
        assert_eq!(
            st.fingerprint.as_deref(),
            Some("ABCDEF0123456789ABCDEF0123456789ABCDEF01")
        );
        assert_eq!(
            st.primary_fingerprint.as_deref(),
            Some("ABCDEF0123456789ABCDEF0123456789ABCDEF01")
        );
        assert_eq!(st.trust_level, Some(TrustLevel::Fully));
        assert!(st.is_git_good());
    }

    #[test]
    fn parses_expired_key_signature() {
        let out = "[GNUPG:] EXPKEYSIG 1234567890ABCDEF Alice <a@b>\n\
                   [GNUPG:] VALIDSIG FPRFPR 2024-01-01 1700000000 0 4 0 22 10 00 FPRFPR\n\
                   [GNUPG:] KEYEXPIRED 1700000000\n";
        let st = parse_status(out);
        assert_eq!(st.result, Some('Y'));
        assert!(!st.is_git_good());
        assert!(st.expired_signature);
        assert_eq!(st.key_expired_at, Some(1_700_000_000));
    }

    #[test]
    fn rejects_multiple_exclusive_statuses() {
        let out = "[GNUPG:] GOODSIG 1 A <a@b>\n[GNUPG:] GOODSIG 2 B <b@c>\n";
        let st = parse_status(out);
        assert_eq!(st.exclusive_statuses, 2);
        assert!(!st.is_git_good(), "git rejects multiple signatures");
    }

    #[test]
    fn revoked_key_reports_revoked_signature() {
        let out = "[GNUPG:] REVKEYSIG 1 A <a@b>\n[GNUPG:] KEYREVOKED\n";
        let st = parse_status(out);
        assert_eq!(st.result, Some('R'));
        assert!(st.revoked_signature);
        assert!(st.key_revoked);
        assert!(!st.is_git_good());
    }
}
