//! SSH signature verification by driving `ssh-keygen`, mirroring git's
//! `verify_ssh_signed_buffer()` + `parse_ssh_output()`.
//!
//! git's flow, reproduced here:
//!
//!   1. `ssh-keygen -Y find-principals -f <allowed_signers> -s <sig>
//!      [-Overify-time=...]` — which principals (if any) may claim this key at
//!      that instant. This step does *not* check the signature against the
//!      payload; it only matches keys, honouring `valid-after`/`valid-before`.
//!   2. If no principal matched, git falls back to `-Y check-novalidate` purely
//!      to describe the signature, and then treats it as **not good**. That is
//!      why `git log --format=%G?` prints `U` for "cryptographically fine but
//!      the key is not whitelisted".
//!   3. Otherwise `-Y verify -n git -f <allowed> -I <principal> -s <sig>` for
//!      each principal until one prints a first line starting with `Good`.
//!
//! `-Overify-time` is what makes "was this key allowed at commit time"
//! answerable: ssh-keygen evaluates `valid-after`/`valid-before` and KRL
//! revocation against that timestamp.
//!
//! The distinction that matters for reporting is between *why* step 3 failed:
//! a whitelist/window problem is a policy finding, while "incorrect signature"
//! is a tampering finding. So the raw outputs are kept separately and the
//! caller chooses the message; this module never guesses.

use std::io::Write;
use std::process::{Command, Stdio};

/// Why verification did not succeed, when it did not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SshFailure {
    /// The payload does not match the signature, the signature is malformed,
    /// or the namespace differs.
    BadSignature,
    /// The key is fine and cryptographically valid, but no allowed_signers
    /// principal matches it.
    KeyNotAllowed,
    /// A matching entry exists but its valid-after/valid-before window excludes
    /// the verification time.
    OutsideValidityWindow,
    /// A configured revocation file (KRL) revokes the key.
    KeyRevoked,
    /// ssh-keygen could not be run, or produced output we cannot interpret.
    ToolError,
    /// gpg.ssh.allowedSignersFile is not configured.
    NoAllowedSigners,
}

#[derive(Debug, Clone, Default)]
pub struct SshStatus {
    /// True only for git's `G`: a whitelisted principal verified.
    pub good: bool,
    /// The signature is cryptographically valid for this payload (checked with
    /// `check-novalidate`, or implied by a successful `verify`).
    pub crypto_valid: bool,
    /// At least one allowed_signers principal matched the key.
    pub principal_found: bool,
    pub principal: Option<String>,
    /// Signing key fingerprint (`SHA256:...`).
    pub fingerprint: Option<String>,
    /// Key type token as printed by ssh-keygen, e.g. `ED25519`.
    pub key_type: Option<String>,
    pub failure: Option<SshFailure>,
    /// The most specific diagnostic available, chosen from the raw outputs.
    pub detail: Option<String>,

    // Raw outputs, kept so callers and tests can see exactly what ssh-keygen
    // said rather than trusting our summary of it.
    pub find_principals_stderr: String,
    pub verify_stdout: String,
    pub verify_stderr: String,
    pub novalidate_stdout: String,
    pub novalidate_stderr: String,
}

impl SshStatus {
    pub fn is_git_good(&self) -> bool {
        self.good
    }
}

#[derive(Debug, Clone)]
pub struct SshVerifier {
    pub program: String,
    pub allowed_signers: Option<String>,
    pub revocation_file: Option<String>,
}

impl SshVerifier {
    pub fn new(program: impl Into<String>) -> Self {
        SshVerifier {
            program: program.into(),
            allowed_signers: None,
            revocation_file: None,
        }
    }

    pub fn is_available(&self) -> bool {
        // `ssh-keygen` with no arguments prints usage and exits non-zero, and
        // `-h` waits on stdin for a key, so probe with a bogus option, which
        // terminates immediately either way.
        Command::new(&self.program)
            .arg("-Z")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|_| true)
            .unwrap_or(false)
    }

    /// Verify `signature` over `payload` in the `git` namespace.
    pub fn verify(&self, signature: &[u8], payload: &[u8], at_time: Option<i64>) -> SshStatus {
        let mut status = SshStatus::default();

        let Some(allowed) = self.allowed_signers.as_deref() else {
            status.failure = Some(SshFailure::NoAllowedSigners);
            status.detail = Some("gpg.ssh.allowedSignersFile is not configured".to_string());
            return status;
        };

        let sig_file = match tempfile::Builder::new()
            .prefix("sigaudit-sshsig-")
            .tempfile()
        {
            Ok(f) => f,
            Err(e) => {
                status.failure = Some(SshFailure::ToolError);
                status.detail = Some(format!("could not create temp file for signature: {e}"));
                return status;
            }
        };
        if let Err(e) = sig_file.as_file().write_all(signature) {
            status.failure = Some(SshFailure::ToolError);
            status.detail = Some(format!("could not write signature to temp file: {e}"));
            return status;
        }
        // ssh-keygen re-opens signature files by path.
        let _ = sig_file.as_file().sync_all();
        let sig_path = sig_file.path().to_path_buf();
        let verify_time_arg = at_time.map(format_verify_time);

        // --- Step 1: which principals may claim this key? -------------------
        let (principals, fp_stderr) =
            match self.find_principals(allowed, &sig_path, verify_time_arg.as_deref()) {
                Ok(v) => v,
                Err(e) => {
                    status.failure = Some(SshFailure::ToolError);
                    status.detail = Some(e);
                    return status;
                }
            };
        status.find_principals_stderr = fp_stderr;

        if principals.is_empty() {
            // A whitelist file that cannot be opened is a configuration error,
            // not a policy decision. git treats it as "no principal matched"
            // (so `%G?` shows U); we keep that verdict but say why.
            if status
                .find_principals_stderr
                .contains("Unable to open allowed keys file")
                || status
                    .find_principals_stderr
                    .contains("No such file or directory")
            {
                status.detail = Some(format!(
                    "allowed_signers file {allowed:?} could not be read: {}",
                    status
                        .find_principals_stderr
                        .lines()
                        .map(str::trim)
                        .find(|l| l.starts_with("Unable to open"))
                        .unwrap_or("unreadable")
                ));
            }
            // --- Step 2: no principal. Describe the signature, then fail. ---
            let (stdout, stderr, ok) =
                self.check_novalidate(&sig_path, payload, verify_time_arg.as_deref());
            status.novalidate_stdout = stdout;
            status.novalidate_stderr = stderr;
            status.crypto_valid = ok;

            if !ok {
                status.failure = Some(SshFailure::BadSignature);
                status.detail = Some(describe_bad_signature(&status));
                return status;
            }

            // The crypto is fine; the key simply is not allowed here.
            let config_error = status.detail.take();
            status.failure = Some(if window_error(&status.find_principals_stderr) {
                SshFailure::OutsideValidityWindow
            } else {
                SshFailure::KeyNotAllowed
            });
            status.detail = Some(config_error.unwrap_or_else(|| {
                match status.failure {
                    Some(SshFailure::OutsideValidityWindow) => {
                        "signature is valid but the key's allowed_signers \
                     valid-after/valid-before window excludes this commit time"
                            .to_string()
                    }
                    _ => "signature is valid but the signing key is not listed in \
                      gpg.ssh.allowedSignersFile"
                        .to_string(),
                }
            }));
            return status;
        }

        // --- Step 3: verify against each matching principal. ----------------
        for principal in &principals {
            let (stdout, stderr, ok) = self.verify_with_principal(
                allowed,
                principal,
                &sig_path,
                payload,
                verify_time_arg.as_deref(),
            );
            status.verify_stdout = stdout;
            status.verify_stderr = stderr;
            status.principal = Some(principal.clone());

            // git only accepts a run whose first line starts with "Good".
            if ok && status.verify_stdout.starts_with("Good") {
                status.good = true;
                status.crypto_valid = true;
                status.principal_found = true;
                status.fingerprint = extract_fingerprint(&status.verify_stdout);
                status.key_type = extract_key_type(&status.verify_stdout);
                return status;
            }

            // A matched principal whose verify step fails is either a payload
            // mismatch, a namespace mismatch, or a KRL revocation.
            status.principal_found = true;
        }

        // Every matching principal failed verification.
        status.crypto_valid = false;
        if window_error(&status.verify_stderr) {
            status.failure = Some(SshFailure::OutsideValidityWindow);
            status.detail = Some(
                "signature could not be verified because the key's allowed_signers window \
                 excludes the verification time"
                    .to_string(),
            );
        } else if self.revocation_file.is_some()
            && (status.verify_stderr.contains("revoked")
                || status.verify_stdout.contains("revoked"))
        {
            status.failure = Some(SshFailure::KeyRevoked);
            status.detail =
                Some("the signing key is revoked by gpg.ssh.revocationFile".to_string());
        } else {
            status.failure = Some(SshFailure::BadSignature);
            status.detail = Some(describe_bad_signature(&status));
        }
        status
    }

    fn find_principals(
        &self,
        allowed: &str,
        sig_path: &std::path::Path,
        verify_time: Option<&str>,
    ) -> Result<(Vec<String>, String), String> {
        let mut cmd = Command::new(&self.program);
        cmd.arg("-Y").arg("find-principals").arg("-f").arg(allowed);
        cmd.arg("-s").arg(sig_path);
        if let Some(t) = verify_time {
            cmd.arg(format!("-Overify-time={t}"));
        }
        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let out = cmd
            .output()
            .map_err(|e| format!("could not run {}: {e}", self.program))?;
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        // A non-zero exit that is *not* "no principal matched" means the tool
        // itself failed (bad option, unreadable file).
        if !out.status.success()
            && !stderr.contains("No principal matched")
            && (stderr.contains("usage:") || stderr.contains("Unknown option"))
        {
            return Err(format!(
                "{} does not support -Y find-principals (OpenSSH 8.2p1 or newer is \
                 required): {}",
                self.program,
                stderr.trim()
            ));
        }
        let principals = stdout
            .lines()
            .map(|l| l.trim_end_matches('\r').to_string())
            .filter(|l| !l.is_empty())
            .collect();
        Ok((principals, stderr))
    }

    fn verify_with_principal(
        &self,
        allowed: &str,
        principal: &str,
        sig_path: &std::path::Path,
        payload: &[u8],
        verify_time: Option<&str>,
    ) -> (String, String, bool) {
        let mut cmd = Command::new(&self.program);
        cmd.arg("-Y").arg("verify").arg("-n").arg("git");
        cmd.arg("-f").arg(allowed);
        cmd.arg("-I").arg(principal);
        cmd.arg("-s").arg(sig_path);
        if let Some(t) = verify_time {
            cmd.arg(format!("-Overify-time={t}"));
        }
        if let Some(krl) = self.revocation_file.as_deref() {
            if std::path::Path::new(krl).exists() {
                cmd.arg("-r").arg(krl);
            }
        }
        self.run_with_stdin(cmd, payload)
    }

    /// git's fallback when no principal matched: describe the signature.
    fn check_novalidate(
        &self,
        sig_path: &std::path::Path,
        payload: &[u8],
        verify_time: Option<&str>,
    ) -> (String, String, bool) {
        let mut cmd = Command::new(&self.program);
        cmd.arg("-Y").arg("check-novalidate").arg("-n").arg("git");
        cmd.arg("-s").arg(sig_path);
        if let Some(t) = verify_time {
            cmd.arg(format!("-Overify-time={t}"));
        }
        self.run_with_stdin(cmd, payload)
    }

    fn run_with_stdin(&self, mut cmd: Command, payload: &[u8]) -> (String, String, bool) {
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let Ok(mut child) = cmd.spawn() else {
            return (
                String::new(),
                format!("could not run {}", self.program),
                false,
            );
        };
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(payload);
        }
        match child.wait_with_output() {
            Ok(o) => (
                String::from_utf8_lossy(&o.stdout).into_owned(),
                String::from_utf8_lossy(&o.stderr).into_owned(),
                o.status.success(),
            ),
            Err(e) => (
                String::new(),
                format!("could not wait for {}: {e}", self.program),
                false,
            ),
        }
    }
}

fn window_error(stderr: &str) -> bool {
    stderr.contains("key is not yet valid") || stderr.contains("key has expired")
}

/// The most specific available reason for a failed signature check.
fn describe_bad_signature(status: &SshStatus) -> String {
    let combined = format!(
        "{}\n{}\n{}",
        status.novalidate_stdout, status.novalidate_stderr, status.verify_stderr
    );
    if combined.contains("namespace does not match") {
        return "SSH signature namespace is not \"git\"".to_string();
    }
    if combined.contains("incorrect signature") {
        return "signature does not match the signed content".to_string();
    }
    for line in combined.lines().map(str::trim) {
        if !line.is_empty() && !line.eq_ignore_ascii_case("Could not verify signature.") {
            return line.to_string();
        }
    }
    "SSH signature did not verify".to_string()
}

/// ssh-keygen's `-Overify-time` takes `YYYYMMDDHHMMSS` in UTC.
pub fn format_verify_time(epoch: i64) -> String {
    chrono::DateTime::from_timestamp(epoch, 0)
        .unwrap_or_else(|| chrono::DateTime::from_timestamp(0, 0).unwrap())
        .format("%Y%m%d%H%M%S")
        .to_string()
}

/// git's `parse_ssh_output()`: the fingerprint is everything after the last
/// `"key "` token on the first line (e.g. `SHA256:...`).
fn extract_fingerprint(stdout: &str) -> Option<String> {
    let first = stdout.lines().next()?;
    let idx = first.rfind("key ")?;
    Some(first[idx + 4..].trim().to_string())
}

fn extract_key_type(stdout: &str) -> Option<String> {
    let first = stdout.lines().next()?;
    // "Good \"git\" signature for X with RSA key SHA256:..." -> RSA
    let before = &first[..first.rfind("key ")?];
    let last = before.split_whitespace().last()?;
    if last == "with" {
        return None;
    }
    Some(last.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_fingerprint_and_type() {
        let line = "Good \"git\" signature for alice@example.com with ED25519 key SHA256:abc123";
        assert_eq!(extract_fingerprint(line).as_deref(), Some("SHA256:abc123"));
        assert_eq!(extract_key_type(line).as_deref(), Some("ED25519"));
    }

    #[test]
    fn handles_unknown_principal_form() {
        let line = "Good \"git\" signature with RSA key SHA256:def456";
        assert_eq!(extract_fingerprint(line).as_deref(), Some("SHA256:def456"));
        assert_eq!(extract_key_type(line).as_deref(), Some("RSA"));
    }

    #[test]
    fn verify_time_is_utc_basic_iso() {
        assert_eq!(format_verify_time(1700000000), "20231114221320");
    }

    #[test]
    fn window_errors_are_recognised() {
        assert!(window_error(
            "allowed:1: key is not yet valid: verify time 2026 < valid-after 2027"
        ));
        assert!(window_error(
            "allowed:1: key has expired: verify time 2026 > 2025"
        ));
        assert!(!window_error("No principal matched."));
    }

    #[test]
    fn bad_signature_messages_are_specific() {
        let mut st = SshStatus {
            verify_stderr: "Couldn't verify signature: namespace does not match".into(),
            ..Default::default()
        };
        assert!(describe_bad_signature(&st).contains("namespace"));
        st = SshStatus {
            verify_stdout: "Could not verify signature.".into(),
            verify_stderr: "Signature verification failed: incorrect signature".into(),
            ..Default::default()
        };
        assert!(describe_bad_signature(&st).contains("does not match"));
    }
}
