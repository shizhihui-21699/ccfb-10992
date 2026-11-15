//! Signature verification, deliberately mirroring git's own behavior:
//! GPG signatures are checked by shelling out to `gpg --status-fd` and
//! parsing its status lines; SSH signatures by `ssh-keygen -Y verify`
//! against an allowed_signers file with namespace "git" and the committer
//! email as identity — exactly what git does.
//!
//! Key expiry / revocation is judged at *commit time*: a signature made
//! while the key was still valid counts as valid (flagged), a commit dated
//! after the key expired or was revoked counts as invalid.

use anyhow::{Context, Result};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Status {
    #[default]
    Unsigned,
    Valid,
    /// Signature valid; key has expired *since* the commit was made.
    ValidExpiredKey,
    /// Signature valid; key was revoked *after* the commit was made.
    ValidRevokedKey,
    Invalid,
    /// Cryptographically valid, but the signer is not in the whitelist.
    Untrusted,
    /// Could not be checked (missing public key, no allowed_signers, ...).
    Unverifiable,
}

impl Status {
    pub const ALL: [Status; 7] = [
        Status::Unsigned,
        Status::Valid,
        Status::ValidExpiredKey,
        Status::ValidRevokedKey,
        Status::Invalid,
        Status::Untrusted,
        Status::Unverifiable,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Status::Unsigned => "unsigned",
            Status::Valid => "valid",
            Status::ValidExpiredKey => "valid-expired-key",
            Status::ValidRevokedKey => "valid-revoked-key",
            Status::Invalid => "invalid",
            Status::Untrusted => "untrusted",
            Status::Unverifiable => "unverifiable",
        }
    }

    pub fn parse(s: &str) -> Option<Status> {
        Status::ALL.iter().copied().find(|st| st.as_str() == s)
    }
}

#[derive(Debug, Clone, Default)]
pub struct Verification {
    pub status: Status,
    pub kind: Option<&'static str>,
    /// GPG fingerprint or SSH principal (committer email).
    pub signer: Option<String>,
    /// GPG uid from GOODSIG, if any.
    pub uid: Option<String>,
    pub detail: Option<String>,
    pub key_expires: Option<i64>,
    pub key_revoked_at: Option<i64>,
}

// ---------------------------------------------------------------- GPG ----

#[derive(Debug, Clone, Default)]
struct KeyInfo {
    created: Option<i64>,
    expires: Option<i64>,
    revoked_at: Option<i64>,
    primary_fpr: Option<String>,
}

pub struct GpgVerifier {
    homedir: Option<PathBuf>,
    whitelist: Option<HashSet<String>>,
    key_cache: HashMap<String, KeyInfo>,
}

impl GpgVerifier {
    pub fn new(homedir: Option<PathBuf>, whitelist_file: Option<&Path>) -> Result<Self> {
        let whitelist = match whitelist_file {
            Some(p) => {
                let text = std::fs::read_to_string(p)
                    .with_context(|| format!("cannot read GPG whitelist {}", p.display()))?;
                let set = text
                    .lines()
                    .map(|l| l.split('#').next().unwrap_or("").trim())
                    .filter(|l| !l.is_empty())
                    .map(|l| l.replace(' ', "").to_uppercase())
                    .collect();
                Some(set)
            }
            None => None,
        };
        Ok(Self {
            homedir,
            whitelist,
            key_cache: HashMap::new(),
        })
    }

    fn gpg_cmd(&self) -> Command {
        let mut c = Command::new("gpg");
        c.arg("--batch").arg("--yes");
        if let Some(h) = &self.homedir {
            c.arg("--homedir").arg(h);
        }
        c
    }

    pub fn verify(&mut self, armored: &str, payload: &[u8], commit_time: i64) -> Verification {
        let mut v = Verification {
            kind: Some("gpg"),
            ..Default::default()
        };

        let dir = match tempfile::tempdir() {
            Ok(d) => d,
            Err(e) => {
                v.status = Status::Unverifiable;
                v.detail = Some(format!("tempdir: {e}"));
                return v;
            }
        };
        let sig_path = dir.path().join("sig.asc");
        let payload_path = dir.path().join("payload.bin");
        if std::fs::write(&sig_path, armored)
            .and_then(|_| std::fs::write(&payload_path, payload))
            .is_err()
        {
            v.status = Status::Unverifiable;
            v.detail = Some("cannot write temp files".into());
            return v;
        }

        let out = match self
            .gpg_cmd()
            .arg("--status-fd")
            .arg("1")
            .arg("--verify")
            .arg(&sig_path)
            .arg(&payload_path)
            .output()
        {
            Ok(o) => o,
            Err(e) => {
                v.status = Status::Unverifiable;
                v.detail = Some(format!("cannot run gpg: {e}"));
                return v;
            }
        };

        let stdout = String::from_utf8_lossy(&out.stdout);
        let mut fpr: Option<String> = None;
        let mut bad = false;
        let mut expkey = false;
        let mut revkey = false;
        let mut no_pubkey = false;
        let mut errsig: Option<String> = None;

        for line in stdout.lines() {
            let Some(rest) = line.strip_prefix("[GNUPG:] ") else {
                continue;
            };
            let code = rest.split_whitespace().next().unwrap_or("");
            match code {
                "VALIDSIG" => {
                    fpr = rest.split_whitespace().nth(1).map(str::to_string);
                }
                "GOODSIG" => {
                    v.uid = rest.splitn(3, ' ').nth(2).map(str::to_string);
                }
                "BADSIG" => bad = true,
                "EXPKEYSIG" => expkey = true,
                "REVKEYSIG" => revkey = true,
                "NO_PUBKEY" => no_pubkey = true,
                "ERRSIG" => errsig = Some(rest.to_string()),
                _ => {}
            }
        }

        v.signer = fpr.clone();

        if bad {
            v.status = Status::Invalid;
            v.detail = Some("bad signature: commit content does not match signature".into());
            return v;
        }
        if no_pubkey {
            v.status = Status::Unverifiable;
            v.detail = Some("public key not in keyring".into());
            return v;
        }
        let Some(fpr) = fpr else {
            v.status = Status::Unverifiable;
            v.detail = Some(
                errsig.unwrap_or_else(|| "gpg produced no VALIDSIG status".into()),
            );
            return v;
        };

        let ki = self.key_info(&fpr);
        v.key_expires = ki.expires;
        v.key_revoked_at = ki.revoked_at;

        if expkey {
            match ki.expires {
                Some(exp) if commit_time <= exp => {
                    v.status = Status::ValidExpiredKey;
                    v.detail = Some(format!(
                        "key expired at {exp} but commit predates expiry (valid at commit time)"
                    ));
                }
                Some(exp) => {
                    v.status = Status::Invalid;
                    v.detail = Some(format!(
                        "commit time {commit_time} is after key expiration {exp}"
                    ));
                    return v;
                }
                None => {
                    v.status = Status::Unverifiable;
                    v.detail = Some("key expired but expiration date unknown".into());
                    return v;
                }
            }
        } else if revkey {
            match ki.revoked_at {
                Some(rev) if commit_time < rev => {
                    v.status = Status::ValidRevokedKey;
                    v.detail = Some(format!(
                        "key revoked at {rev} but commit predates revocation (valid at commit time)"
                    ));
                }
                Some(rev) => {
                    v.status = Status::Invalid;
                    v.detail = Some(format!(
                        "commit time {commit_time} is after key revocation {rev}"
                    ));
                    return v;
                }
                // Revoked but no revocation date: conservative, treat as invalid.
                None => {
                    v.status = Status::Invalid;
                    v.detail = Some("signing key is revoked (revocation date unknown)".into());
                    return v;
                }
            }
        } else {
            v.status = Status::Valid;
        }

        // Whitelist applies to cryptographically valid signatures.
        if let Some(wl) = &self.whitelist {
            let ok = wl.contains(&fpr)
                || ki
                    .primary_fpr
                    .as_ref()
                    .is_some_and(|p| wl.contains(p));
            if !ok {
                v.status = Status::Untrusted;
                v.detail = Some(format!("signer key {fpr} not in GPG whitelist"));
            }
        }
        v
    }

    /// Fetch creation/expiration/revocation info for a key (cached).
    fn key_info(&mut self, fpr: &str) -> KeyInfo {
        if let Some(k) = self.key_cache.get(fpr) {
            return k.clone();
        }
        let mut ki = KeyInfo::default();

        if let Ok(out) = self
            .gpg_cmd()
            .arg("--with-colons")
            .arg("--list-keys")
            .arg(fpr)
            .output()
        {
            let text = String::from_utf8_lossy(&out.stdout);
            let mut cur_created = None;
            let mut cur_expires = None;
            let mut cur_is_pub = false;
            for line in text.lines() {
                let f: Vec<&str> = line.split(':').collect();
                match f.first().copied() {
                    Some("pub") | Some("sub") => {
                        cur_is_pub = f[0] == "pub";
                        cur_created = f.get(5).and_then(|s| s.parse().ok());
                        cur_expires = f
                            .get(6)
                            .and_then(|s| s.parse::<i64>().ok())
                            .filter(|&t| t > 0);
                    }
                    Some("fpr") => {
                        if let Some(fp) = f.get(9) {
                            if cur_is_pub && ki.primary_fpr.is_none() {
                                ki.primary_fpr = Some(fp.to_string());
                            }
                            if *fp == fpr {
                                ki.created = cur_created;
                                ki.expires = cur_expires;
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        // Revocation date: `rev` records in --list-sigs. A key revocation
        // appears right after the pub block (before the first uid); a subkey
        // revocation after its sub block.
        if let Ok(out) = self
            .gpg_cmd()
            .arg("--with-colons")
            .arg("--list-sigs")
            .arg(fpr)
            .output()
        {
            let text = String::from_utf8_lossy(&out.stdout);
            let mut in_primary_scope = true; // before first uid
            let mut current_sub_matches = false;
            let mut last_was_fpr_for_target = false;
            for line in text.lines() {
                let tag = line.split(':').next().unwrap_or("");
                match tag {
                    "uid" => in_primary_scope = false,
                    "sub" => current_sub_matches = false,
                    "fpr" => {
                        let fp = line.split(':').nth(9).unwrap_or("");
                        if fp == fpr {
                            current_sub_matches = true;
                            last_was_fpr_for_target = true;
                        }
                    }
                    "rev" => {
                        let in_scope = in_primary_scope
                            || current_sub_matches
                            || last_was_fpr_for_target;
                        if in_scope {
                            if let Some(ts) = line
                                .split(':')
                                .nth(5)
                                .and_then(|s| s.parse::<i64>().ok())
                            {
                                ki.revoked_at =
                                    Some(ki.revoked_at.map_or(ts, |r: i64| r.min(ts)));
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        self.key_cache.insert(fpr.to_string(), ki.clone());
        ki
    }
}

// ---------------------------------------------------------------- SSH ----

pub struct SshVerifier {
    allowed_signers: Option<PathBuf>,
    principals: HashSet<String>,
}

impl SshVerifier {
    pub fn new(allowed_signers: Option<&Path>) -> Result<Self> {
        let mut principals = HashSet::new();
        if let Some(p) = allowed_signers {
            let text = std::fs::read_to_string(p)
                .with_context(|| format!("cannot read allowed_signers {}", p.display()))?;
            for line in text.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                // Format: principals[,...] [options] keytype base64 [comment]
                if let Some(first) = line.split_whitespace().next() {
                    for pr in first.split(',') {
                        if !pr.is_empty() {
                            principals.insert(pr.to_string());
                        }
                    }
                }
            }
        }
        Ok(Self {
            allowed_signers: allowed_signers.map(Path::to_path_buf),
            principals,
        })
    }

    pub fn verify(&self, armored: &str, payload: &[u8], committer_email: &str) -> Verification {
        let mut v = Verification {
            kind: Some("ssh"),
            signer: Some(committer_email.to_string()),
            ..Default::default()
        };

        let Some(path) = &self.allowed_signers else {
            v.status = Status::Unverifiable;
            v.detail = Some("SSH signature but no --allowed-signers file configured".into());
            return v;
        };

        // git verifies with the committer email as identity; a principal not
        // present in allowed_signers can never validate -> signer not trusted.
        if !self.principals.contains(committer_email) {
            v.status = Status::Untrusted;
            v.detail = Some(format!(
                "committer <{committer_email}> has no entry in allowed_signers"
            ));
            return v;
        }

        let dir = match tempfile::tempdir() {
            Ok(d) => d,
            Err(e) => {
                v.status = Status::Unverifiable;
                v.detail = Some(format!("tempdir: {e}"));
                return v;
            }
        };
        let sig_path = dir.path().join("sig");
        if std::fs::write(&sig_path, armored).is_err() {
            v.status = Status::Unverifiable;
            v.detail = Some("cannot write temp files".into());
            return v;
        }

        // Like git, feed the signed payload to ssh-keygen on stdin.
        let mut child = match Command::new("ssh-keygen")
            .arg("-Y")
            .arg("verify")
            .arg("-f")
            .arg(path)
            .arg("-I")
            .arg(committer_email)
            .arg("-n")
            .arg("git")
            .arg("-s")
            .arg(&sig_path)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                v.status = Status::Unverifiable;
                v.detail = Some(format!("cannot run ssh-keygen: {e}"));
                return v;
            }
        };
        if let Some(mut stdin) = child.stdin.take() {
            use std::io::Write;
            let _ = stdin.write_all(payload);
        }
        let out = match child.wait_with_output() {
            Ok(o) => o,
            Err(e) => {
                v.status = Status::Unverifiable;
                v.detail = Some(format!("ssh-keygen failed: {e}"));
                return v;
            }
        };

        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        if out.status.success() {
            v.status = Status::Valid;
            if !stderr.is_empty() {
                v.detail = Some(stderr);
            }
        } else {
            v.status = Status::Invalid;
            v.detail = Some(if stderr.is_empty() {
                "ssh-keygen rejected the signature".into()
            } else {
                stderr
            });
        }
        v
    }
}
