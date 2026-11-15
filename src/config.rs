//! Effective verifier configuration.
//!
//! Defaults come from the repository's own git config, exactly as git would see
//! it, so `sigaudit` agrees with `git verify-commit` and `git log --format=%G?`
//! in the same checkout. Every value can be overridden from the command line,
//! which matters in CI where there is no local config file.

use std::path::{Path, PathBuf};

use crate::gpg::TrustLevel;

#[derive(Debug, Clone)]
pub struct Config {
    /// `gpg.program` / `gpg.openpgp.program` (default `gpg`).
    pub gpg_program: String,
    /// `gpg.ssh.program` (default `ssh-keygen`).
    pub ssh_program: String,
    /// `gpg.ssh.allowedSignersFile`.
    pub allowed_signers: Option<PathBuf>,
    /// `gpg.ssh.revocationFile`.
    pub revocation_file: Option<PathBuf>,
    /// `gpg.minTrustLevel`, applied the way git applies it: a signature whose
    /// trust level is below this counts as failed.
    pub min_trust_level: Option<TrustLevel>,
    /// Verify OpenPGP signatures at the commit's own timestamp instead of
    /// "now" (see docs: `--gpg-time=committer`).
    pub gpg_time_mode: GpgTimeMode,
    /// Verify SSH signatures at the commit's own timestamp.
    pub ssh_time_mode: SshTimeMode,
    /// Extra `--homedir` for gpg.
    pub gpg_home: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpgTimeMode {
    /// Ask gpg about key validity *now* (git's `verify-commit` behaviour).
    /// An expired key therefore yields Y even for an old commit.
    Now,
    /// Ask gpg about key validity at the committer timestamp: a key that was
    /// live when the commit was made stays good after it later expires.
    Committer,
    /// Ask about the signature's own embedded creation time.
    Signature,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SshTimeMode {
    /// Evaluate allowed_signers validity windows at the commit time.
    Committer,
    /// Evaluate them at "now".
    Now,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            gpg_program: "gpg".to_string(),
            ssh_program: "ssh-keygen".to_string(),
            allowed_signers: None,
            revocation_file: None,
            min_trust_level: None,
            gpg_time_mode: GpgTimeMode::Committer,
            ssh_time_mode: SshTimeMode::Committer,
            gpg_home: None,
        }
    }
}

impl Config {
    /// Read git config from the repository, keeping defaults where unset.
    pub fn from_repository(repo: &git2::Repository) -> Config {
        let mut cfg = Config::default();
        let Ok(config) = repo.config() else {
            return cfg;
        };

        if let Ok(v) = config.get_string("gpg.program") {
            if !v.is_empty() {
                cfg.gpg_program = v;
            }
        }
        if let Ok(v) = config.get_string("gpg.openpgp.program") {
            if !v.is_empty() {
                cfg.gpg_program = v;
            }
        }
        if let Ok(v) = config.get_string("gpg.ssh.program") {
            if !v.is_empty() {
                cfg.ssh_program = v;
            }
        }
        cfg.allowed_signers = config
            .get_string("gpg.ssh.allowedSignersFile")
            .ok()
            .filter(|s| !s.is_empty())
            .map(|s| resolve_path(repo, &s));
        cfg.revocation_file = config
            .get_string("gpg.ssh.revocationFile")
            .ok()
            .filter(|s| !s.is_empty())
            .map(|s| resolve_path(repo, &s));
        if let Ok(v) = config.get_string("gpg.minTrustLevel") {
            cfg.min_trust_level = parse_trust(&v);
        }
        if let Ok(v) = config.get_string("sigaudit.gpgTime") {
            if let Some(mode) = parse_gpg_time(&v) {
                cfg.gpg_time_mode = mode;
            }
        }
        cfg
    }

    /// The gpg homedir to use: explicit CLI value, else `GNUPGHOME`.
    pub fn effective_gpg_home(&self) -> Option<String> {
        crate::gpg::resolve_gpg_home(self.gpg_home.as_deref())
    }

    pub fn allowed_signers_display(&self) -> String {
        match &self.allowed_signers {
            Some(p) => p.display().to_string(),
            None => "(unset)".to_string(),
        }
    }
}

/// git resolves config paths relative to the working directory, then the
/// repository root; mirror the repo-root half of that.
fn resolve_path(repo: &git2::Repository, value: &str) -> PathBuf {
    let p = Path::new(value);
    if p.is_absolute() {
        return p.to_path_buf();
    }
    if let Some(workdir) = repo.workdir() {
        let candidate = workdir.join(p);
        if candidate.exists() {
            return candidate;
        }
    }
    p.to_path_buf()
}

pub fn parse_trust(value: &str) -> Option<TrustLevel> {
    match value.to_ascii_lowercase().as_str() {
        "undefined" => Some(TrustLevel::Undefined),
        "never" => Some(TrustLevel::Never),
        "marginal" => Some(TrustLevel::Marginal),
        "fully" => Some(TrustLevel::Fully),
        "ultimate" => Some(TrustLevel::Ultimate),
        _ => None,
    }
}

pub fn parse_gpg_time(value: &str) -> Option<GpgTimeMode> {
    match value.to_ascii_lowercase().as_str() {
        "now" => Some(GpgTimeMode::Now),
        "committer" | "commit" => Some(GpgTimeMode::Committer),
        "signature" | "sig" => Some(GpgTimeMode::Signature),
        _ => None,
    }
}

pub fn parse_ssh_time(value: &str) -> Option<SshTimeMode> {
    match value.to_ascii_lowercase().as_str() {
        "now" => Some(SshTimeMode::Now),
        "committer" | "commit" => Some(SshTimeMode::Committer),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trust_names_are_case_insensitive() {
        assert_eq!(parse_trust("FULLY"), Some(TrustLevel::Fully));
        assert_eq!(parse_trust("marginal"), Some(TrustLevel::Marginal));
        assert_eq!(parse_trust("bogus"), None);
    }

    #[test]
    fn gpg_time_mode_names() {
        assert_eq!(parse_gpg_time("committer"), Some(GpgTimeMode::Committer));
        assert_eq!(parse_gpg_time("NOW"), Some(GpgTimeMode::Now));
        assert_eq!(parse_gpg_time("nope"), None);
    }
}
