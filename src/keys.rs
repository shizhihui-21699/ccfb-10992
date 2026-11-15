//! Public-key metadata extraction.
//!
//! Two reasons we need this:
//!
//! 1. Reporting. A verdict of `Y` ("expired at commit time") is much more
//!    useful with the actual expiry instant and signer uid attached.
//! 2. Judging expiry ourselves when the verifier's clock cannot be faked.
//!    gpg honours `--faked-system-time`, so for OpenPGP we let gpg decide. But
//!    when the user asks for "now" semantics we still want to *explain* an
//!    `EXPKEYSIG`, which requires reading the key's expiry from key metadata.
//!
//! Fingerprints are the only reliable join key: gpg's VALIDSIG reports the
//! signing subkey, while the expiry that matters is often the primary's.

use std::collections::HashMap;
use std::process::{Command, Stdio};

use crate::gpg::GpgVerifier;

#[derive(Debug, Clone, Default)]
pub struct KeyInfo {
    pub fingerprint: String,
    pub key_id: String,
    /// Primary key creation time.
    pub created_at: Option<i64>,
    /// Primary key expiry, if it expires.
    pub expires_at: Option<i64>,
    /// Primary key has been revoked.
    pub revoked: bool,
    /// Creation time of the (earliest) key revocation signature.
    pub revoked_at: Option<i64>,
    /// Primary key is (currently) expired.
    pub expired: bool,
    /// Ownertrust letter from the colons listing (`u`, `f`, `m`, `n`, ...).
    pub ownertrust: Option<char>,
    /// Best uid on the key.
    pub uid: Option<String>,
    /// Signing subkeys known for this key.
    pub subkeys: Vec<SubkeyInfo>,
}

#[derive(Debug, Clone, Default)]
pub struct SubkeyInfo {
    pub fingerprint: String,
    pub key_id: String,
    pub created_at: Option<i64>,
    pub expires_at: Option<i64>,
    pub revoked: bool,
    pub revoked_at: Option<i64>,
    pub expired: bool,
    pub can_sign: bool,
}

/// How a key was usable at a particular instant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyTimeStatus {
    Valid,
    Expired,
    Revoked,
    NotYetCreated,
    Unknown,
}

impl KeyInfo {
    /// Effective (created_at, expires_at, revoked, revoked_at) for the key that
    /// actually made a signature.
    ///
    /// `fingerprint` is the VALIDSIG fingerprint, i.e. the signing subkey; if it
    /// matches the primary we use primary metadata, otherwise we find the
    /// subkey. A revoked primary invalidates its subkeys too, which is what gpg
    /// enforces.
    pub fn signing_key(&self, fingerprint: &str) -> (Option<i64>, Option<i64>, bool, Option<i64>) {
        let want = normalize_fpr(fingerprint);
        if want.is_empty() || normalize_fpr(&self.fingerprint) == want {
            return (
                self.created_at,
                self.expires_at,
                self.revoked,
                self.revoked_at,
            );
        }
        for sub in &self.subkeys {
            if normalize_fpr(&sub.fingerprint) == want {
                let revoked = sub.revoked || self.revoked;
                let revoked_at = earliest(sub.revoked_at, self.revoked_at);
                return (sub.created_at, sub.expires_at, revoked, revoked_at);
            }
        }
        (
            self.created_at,
            self.expires_at,
            self.revoked,
            self.revoked_at,
        )
    }

    /// Was the signing key usable at `at`?
    ///
    /// Expiry is inclusive the way gpg treats it: a key is still usable at the
    /// exact expiry second and expired one second later (verified against gpg
    /// 2.5). Revocation, by contrast, takes effect from the instant its
    /// certificate was issued — gpg applies any revocation in the keyring no
    /// matter the wall clock, so the timestamp comparison is ours to make.
    pub fn status_at(&self, fingerprint: &str, at: i64) -> KeyTimeStatus {
        let (created, expires, revoked, revoked_at) = self.signing_key(fingerprint);
        match created {
            Some(c) if at < c => return KeyTimeStatus::NotYetCreated,
            None => return KeyTimeStatus::Unknown,
            _ => {}
        }
        if revoked {
            return match revoked_at {
                Some(r) if at >= r => KeyTimeStatus::Revoked,
                // Revoked, but the certificate postdates the commit.
                Some(_) => KeyTimeStatus::Valid,
                // Unknown when: an audit tool should not silently pass this.
                None => KeyTimeStatus::Revoked,
            };
        }
        if let Some(e) = expires {
            if at > e {
                return KeyTimeStatus::Expired;
            }
        }
        KeyTimeStatus::Valid
    }
}

fn earliest(a: Option<i64>, b: Option<i64>) -> Option<i64> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.min(y)),
        (x, None) => x,
        (None, y) => y,
    }
}

fn normalize_fpr(fpr: &str) -> String {
    fpr.chars()
        .filter(|c| c.is_ascii_hexdigit())
        .flat_map(|c| c.to_uppercase())
        .collect()
}

/// A store of key metadata, loaded lazily and cached per fingerprint.
#[derive(Debug, Default)]
pub struct KeyStore {
    keys: HashMap<String, Option<KeyInfo>>,
    pub program: String,
    pub home: Option<String>,
}

impl KeyStore {
    pub fn new(verifier: &GpgVerifier) -> Self {
        KeyStore {
            keys: HashMap::new(),
            program: verifier.program.clone(),
            home: verifier.home.clone(),
        }
    }

    /// Look up a key by the fingerprint reported in VALIDSIG. The `--with-colons`
    /// listing is keyed by primary fingerprint, so we resolve via `--list-keys
    /// <fpr>` which gpg handles for subkeys too.
    pub fn get(&mut self, fingerprint: &str) -> Option<&KeyInfo> {
        let key = normalize_fpr(fingerprint);
        if key.is_empty() {
            return None;
        }
        if !self.keys.contains_key(&key) {
            let info = self.load(&key);
            self.keys.insert(key.clone(), info);
        }
        self.keys.get(&key).and_then(|v| v.as_ref())
    }

    fn load(&self, fingerprint: &str) -> Option<KeyInfo> {
        let mut cmd = Command::new(&self.program);
        if let Some(home) = &self.home {
            cmd.arg("--homedir").arg(home);
        }
        cmd.arg("--batch")
            .arg("--no-tty")
            .arg("--with-colons")
            .arg("--fixed-list-mode")
            .arg("--with-sig-list")
            .arg("--list-keys")
            .arg(fingerprint)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let out = cmd.output().ok()?;
        let text = String::from_utf8_lossy(&out.stdout);
        parse_colons(&text)
    }
}

/// Parse `gpg --with-colons --list-keys` output into a `KeyInfo`.
///
/// Records are ordered: `pub`, then its `fpr`, then `uid`s (each optionally
/// followed by `rev`/`sig` records), then one `sub` + `fpr` pair per subkey.
/// We track which key record (primary vs subkey) the following `fpr` belongs to.
pub fn parse_colons(text: &str) -> Option<KeyInfo> {
    let mut primary: Option<KeyInfo> = None;
    let mut awaiting_fpr_for: Option<Target> = None;
    let mut current_sub: Option<SubkeyInfo> = None;
    let mut last_target = Target::Primary;

    for line in text.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() < 10 {
            continue;
        }
        let validity = fields[1];
        match fields[0] {
            "pub" => {
                primary = Some(KeyInfo {
                    key_id: fields[4].to_string(),
                    created_at: parse_num(fields[5]),
                    expires_at: parse_num(fields[6]),
                    ownertrust: fields.get(8).and_then(|s| s.chars().next()),
                    revoked: validity.starts_with('r'),
                    expired: validity.starts_with('e'),
                    ..Default::default()
                });
                awaiting_fpr_for = Some(Target::Primary);
                last_target = Target::Primary;
            }
            "sub" => {
                if let Some(sub) = current_sub.take() {
                    if let Some(p) = primary.as_mut() {
                        p.subkeys.push(sub);
                    }
                }
                current_sub = Some(SubkeyInfo {
                    key_id: fields[4].to_string(),
                    created_at: parse_num(fields[5]),
                    expires_at: parse_num(fields[6]),
                    revoked: validity.starts_with('r'),
                    expired: validity.starts_with('e'),
                    can_sign: fields.get(11).map(|c| c.contains('s')).unwrap_or(false),
                    ..Default::default()
                });
                awaiting_fpr_for = Some(Target::Subkey);
                last_target = Target::Subkey;
            }
            "fpr" => {
                let fpr = fields[9].trim().to_string();
                match awaiting_fpr_for {
                    Some(Target::Primary) => {
                        if let Some(p) = primary.as_mut() {
                            p.fingerprint = fpr;
                        }
                    }
                    Some(Target::Subkey) => {
                        if let Some(s) = current_sub.as_mut() {
                            s.fingerprint = fpr;
                        }
                    }
                    Some(Target::Uid) | None => {}
                }
                awaiting_fpr_for = None;
            }
            "uid" => {
                if let Some(p) = primary.as_mut() {
                    // Prefer the first valid uid as the display name.
                    if p.uid.is_none() {
                        p.uid = Some(unquote_colons(fields[9]));
                    }
                }
                last_target = Target::Uid;
            }
            "rev" => {
                // Field 6 is the revocation signature's creation time; field 11 is
                // the OpenPGP signature class, which says what is revoked:
                //   0x20  key revocation (the whole primary key)
                //   0x28  subkey revocation
                //   0x30  certification (uid) revocation -- not a key revocation
                // Relying on the class is what makes this correct: a uid revocation
                // also lands after a `uid` record, so position alone is ambiguous.
                // When field 11 is absent, fall back to position.
                let created = parse_num(fields[5]);
                let sig_class = fields.get(10).unwrap_or(&"");
                let target = if sig_class.starts_with("20") {
                    Target::Primary
                } else if sig_class.starts_with("28") {
                    Target::Subkey
                } else if sig_class.starts_with("30") {
                    Target::Uid
                } else {
                    last_target
                };
                match target {
                    Target::Subkey => {
                        if let Some(s) = current_sub.as_mut() {
                            s.revoked = true;
                            s.revoked_at = earliest(s.revoked_at, created);
                        }
                    }
                    Target::Primary => {
                        if let Some(p) = primary.as_mut() {
                            p.revoked = true;
                            p.revoked_at = earliest(p.revoked_at, created);
                        }
                    }
                    Target::Uid => {}
                }
            }
            _ => {}
        }
    }
    if let Some(sub) = current_sub.take() {
        if let Some(p) = primary.as_mut() {
            p.subkeys.push(sub);
        }
    }
    primary
}

#[derive(Clone, Copy)]
enum Target {
    Primary,
    Subkey,
    Uid,
}

fn parse_num(s: &str) -> Option<i64> {
    if s.is_empty() {
        None
    } else {
        s.parse().ok()
    }
}

/// gpg quotes colons and control characters C-style in field 10.
fn unquote_colons(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 3 < bytes.len() && bytes[i + 1] == b'x' {
            let hex = &s[i + 2..i + 4];
            if let Ok(v) = u8::from_str_radix(hex, 16) {
                out.push(v as char);
                i += 4;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
tru::1:1794763849:0:3:1:5
pub:u:255:22:A95299E4745F44C1:1704067200:1735603200::u:::scSC:::::ed25519:::0:
fpr:::::::::2F9022039E09ED73B0BCFC39A95299E4745F44C1:
uid:u::::1704067200::HASH::Sub <sub@example.com>::::::::::0:
sub:u:255:22:1E98D390E9454942:1704067200:1735603200:::::s:
fpr:::::::::BC1F9B1507E9DD8D912EEC5A1E98D390E9454942:
";

    #[test]
    fn parses_primary_and_subkey_windows() {
        let key = parse_colons(SAMPLE).unwrap();
        assert_eq!(key.fingerprint, "2F9022039E09ED73B0BCFC39A95299E4745F44C1");
        assert_eq!(key.created_at, Some(1_704_067_200));
        assert_eq!(key.expires_at, Some(1_735_603_200));
        assert_eq!(key.uid.as_deref(), Some("Sub <sub@example.com>"));
        assert_eq!(key.subkeys.len(), 1);
        assert_eq!(
            key.subkeys[0].fingerprint,
            "BC1F9B1507E9DD8D912EEC5A1E98D390E9454942"
        );
        assert_eq!(key.subkeys[0].expires_at, Some(1_735_603_200));
        assert!(key.subkeys[0].can_sign);
    }

    #[test]
    fn signing_subkey_uses_its_own_window() {
        let key = parse_colons(SAMPLE).unwrap();
        let (created, expires, revoked, _) =
            key.signing_key("BC1F9B1507E9DD8D912EEC5A1E98D390E9454942");
        assert_eq!(created, Some(1_704_067_200));
        assert_eq!(expires, Some(1_735_603_200));
        assert!(!revoked);
    }

    #[test]
    fn revoked_primary_marks_subkey_unusable() {
        let text = "\
pub:r:255:22:A95299E4745F44C1:1704067200:::-:::scSC:::::ed25519:::0:
fpr:::::::::2F9022039E09ED73B0BCFC39A95299E4745F44C1:
uid:r::::1704067200::HASH::Sub <sub@example.com>::::::::::0:
rev:::22:A95299E4745F44C1:1748736000::::Sub <sub@example.com>:20x,00::2F9022039E09ED73B0BCFC39A95299E4745F44C1:
sub:u:255:22:1E98D390E9454942:1704067200::::::s:
fpr:::::::::BC1F9B1507E9DD8D912EEC5A1E98D390E9454942:
";
        let key = parse_colons(text).unwrap();
        assert!(key.revoked);
        assert_eq!(key.revoked_at, Some(1_748_736_000));
        let (_, _, revoked, _) = key.signing_key("BC1F9B1507E9DD8D912EEC5A1E98D390E9454942");
        assert!(revoked, "a revoked primary invalidates its subkeys too");
    }

    #[test]
    fn revoked_subkey_is_detected() {
        let text = "\
pub:u:255:22:A52D36F0850ECAC5:1704067200:::-:::scSC:::::ed25519:::0:
fpr:::::::::A8617BB0BB90DE266A1D8320A52D36F0850ECAC5:
uid:u::::1704067200::HASH::SR <sr@example.com>::::::::::0:
sub:r:255:22:57DDC1DD1DD02C2C:1704067200::::::s:
fpr:::::::::A99C387291D98CFA2C29FCF657DDC1DD1DD02C2C:
rev:::22:A52D36F0850ECAC5:1748736000::::SR <sr@example.com>:28x,00::A8617BB0BB90DE266A1D8320A52D36F0850ECAC5:
";
        let key = parse_colons(text).unwrap();
        assert!(!key.revoked);
        assert!(key.subkeys[0].revoked);
        assert_eq!(key.subkeys[0].revoked_at, Some(1_748_736_000));
        let (_, _, revoked, _) = key.signing_key("A99C387291D98CFA2C29FCF657DDC1DD1DD02C2C");
        assert!(revoked);
    }

    #[test]
    fn fingerprint_matching_is_case_and_space_insensitive() {
        let key = parse_colons(SAMPLE).unwrap();
        let (_, expires, _, _) = key.signing_key("bc1f9b15 07e9dd8d 912eec5a 1e98d390 e9454942");
        assert_eq!(expires, Some(1_735_603_200));
    }

    #[test]
    fn unquotes_c_style_colons_in_uid() {
        assert_eq!(unquote_colons(r"Odd\x3aName"), "Odd:Name");
    }

    #[test]
    fn status_at_honours_inclusive_expiry() {
        let key = parse_colons(SAMPLE).unwrap();
        let fpr = "BC1F9B1507E9DD8D912EEC5A1E98D390E9454942";
        assert_eq!(key.status_at(fpr, 1_735_603_199), KeyTimeStatus::Valid);
        assert_eq!(
            key.status_at(fpr, 1_735_603_200),
            KeyTimeStatus::Valid,
            "gpg still accepts the key at the exact expiry second"
        );
        assert_eq!(key.status_at(fpr, 1_735_603_201), KeyTimeStatus::Expired);
        assert_eq!(
            key.status_at(fpr, 1_700_000_000),
            KeyTimeStatus::NotYetCreated
        );
    }

    #[test]
    fn status_at_uses_revocation_certificate_time() {
        let text = "\
pub:r:255:22:A52D36F0850ECAC5:1704067200:::-:::scSC:::::ed25519:::0:
fpr:::::::::A8617BB0BB90DE266A1D8320A52D36F0850ECAC5:
uid:r::::1704067200::HASH::R <r@example.com>::::::::::0:
rev:::22:A52D36F0850ECAC5:1748736000::::R <r@example.com>:20x,00::A8617BB0BB90DE266A1D8320A52D36F0850ECAC5:
";
        let key = parse_colons(text).unwrap();
        let fpr = "A8617BB0BB90DE266A1D8320A52D36F0850ECAC5";
        assert_eq!(
            key.status_at(fpr, 1_720_000_000),
            KeyTimeStatus::Valid,
            "a commit made before the revocation certificate still verifies"
        );
        assert_eq!(key.status_at(fpr, 1_748_736_000), KeyTimeStatus::Revoked);
    }
}
