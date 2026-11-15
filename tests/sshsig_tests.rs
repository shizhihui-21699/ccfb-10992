//! SSHSIG parsing and KRL revocation, exercised against signatures produced
//! by the real `ssh-keygen` in the fixture repository.

mod common;

use common::fixture;
use sigaudit::ssh_keys::{AllowedSigners, Krl, KrlSet, SignerMatch};
use sigaudit::sshsig::{RawSshSig, SignerKey};

fn signature_for(subject: &str) -> String {
    let f = fixture();
    let log = std::process::Command::new("git")
        .args(["log", "--all", "--format=%H %s"])
        .current_dir(f.repo())
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&log.stdout);
    let id = text
        .lines()
        .find(|l| l.contains(subject))
        .unwrap()
        .split(' ')
        .next()
        .unwrap()
        .to_string();
    let commit = std::process::Command::new("git")
        .args(["cat-file", "commit", &id])
        .current_dir(f.repo())
        .output()
        .unwrap()
        .stdout;
    let start = commit
        .windows(29)
        .position(|w| w == b"-----BEGIN SSH SIGNATURE-----")
        .expect("ssh signature");
    let end = commit
        .windows(27)
        .position(|w| w == b"-----END SSH SIGNATURE-----")
        .unwrap()
        + 27;
    String::from_utf8_lossy(&commit[start..end]).to_string()
}

fn signature_time_for(subject: &str) -> i64 {
    let f = fixture();
    let log = std::process::Command::new("git")
        .args(["log", "--all", "--format=%H %ct %s"])
        .current_dir(f.repo())
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&log.stdout);
    let line = text.lines().find(|l| l.contains(subject)).unwrap();
    line.split(' ').nth(1).unwrap().parse().unwrap()
}

#[test]
fn wrapped_ssh_signature_parses() {
    // Git re-wraps SSH signatures at its header width; the parser must join
    // the lines back together and still verify.
    let text = signature_for("SSH signed by alice (allowlisted)");
    let sig = RawSshSig::from_pem(&text).expect("parse");
    assert_eq!(sig.namespace, "git");
    assert_eq!(sig.version, 1);
    assert!(matches!(sig.key, SignerKey::Plain(_)));
    let payload = payload_of("SSH signed by alice (allowlisted)");
    sig.verify(&payload).expect("verify");
}

#[test]
fn plain_allowlisted_key_matches() {
    let f = fixture();
    let text = signature_for("SSH signed by alice (allowlisted)");
    let sig = RawSshSig::from_pem(&text).unwrap();
    let signers = AllowedSigners::read_file(&f.allowed_signers()).unwrap();
    let matched = signers.match_signer(
        &sig.key,
        "git",
        signature_time_for("SSH signed by alice (allowlisted)") as u64,
    );
    match matched {
        SignerMatch::Key { principal, .. } => assert_eq!(principal, "alice@example.com"),
        other => panic!("expected plain key match, got {other:?}"),
    }
}

#[test]
fn certificate_signer_is_parsed_and_matched_via_ca() {
    let f = fixture();
    let text = signature_for("SSH signed by carol via CA certificate");
    let sig = RawSshSig::from_pem(&text).expect("parse certificate signature");
    assert_eq!(sig.key_algorithm(), "ssh-ed25519-cert-v01@openssh.com");
    let cert = sig.key.certificate().expect("certificate");
    assert_eq!(cert.serial(), 42);
    assert_eq!(cert.valid_principals(), ["carol@example.com"]);
    // Verify against the certificate subject key.
    let payload = payload_of("SSH signed by carol via CA certificate");
    sig.verify(&payload)
        .expect("certificate signature verifies");
    let signers = AllowedSigners::read_file(&f.allowed_signers()).unwrap();
    match signers.match_signer(
        &sig.key,
        "git",
        signature_time_for("SSH signed by carol via CA certificate") as u64,
    ) {
        SignerMatch::Certificate { principal, .. } => {
            assert_eq!(principal.as_deref(), Some("carol@example.com"))
        }
        other => panic!("expected CA match, got {other:?}"),
    }
}

#[test]
fn namespace_option_excludes_the_signer() {
    let f = fixture();
    // bob's line is restricted to namespaces="other", so a `git` signature
    // must be rejected even though the key is listed.
    let text = signature_for("SSH signed by bob (not allowlisted)");
    let sig = RawSshSig::from_pem(&text).unwrap();
    let signers = AllowedSigners::read_file(&f.allowed_signers()).unwrap();
    match signers.match_signer(&sig.key, "git", 1_700_000_000) {
        SignerMatch::Rejected { reason, .. } => assert!(reason.contains("namespace")),
        other => panic!("expected namespace rejection, got {other:?}"),
    }
    // In the permitted namespace the same line does match.
    match signers.match_signer(&sig.key, "other", 1_700_000_000) {
        SignerMatch::Key { principal, .. } => assert_eq!(principal, "bob@example.com"),
        other => panic!("expected match in `other`, got {other:?}"),
    }
}

#[test]
fn krl_revokes_explicit_plain_key() {
    let f = fixture();
    let krl = Krl::read_file(&f.krl("alice-revoked.krl")).expect("parse KRL");
    let text = signature_for("SSH signed by alice (allowlisted)");
    let sig = RawSshSig::from_pem(&text).unwrap();
    assert!(krl.revokes(&sig.key), "alice's key should be revoked");
}

#[test]
fn krl_revokes_certificate_by_serial() {
    let f = fixture();
    let krl = Krl::read_file(&f.krl("dave-cert-revoked.krl")).expect("parse KRL");
    let text = signature_for("SSH signed by dave via revoked certificate");
    let sig = RawSshSig::from_pem(&text).unwrap();
    assert!(
        krl.revokes(&sig.key),
        "dave's certificate (serial 77) should be revoked"
    );
    // The same KRL must not revoke carol's certificate (serial 42).
    let text = signature_for("SSH signed by carol via CA certificate");
    let sig = RawSshSig::from_pem(&text).unwrap();
    assert!(
        !krl.revokes(&sig.key),
        "carol's certificate should not be revoked"
    );
}

#[test]
fn krl_set_is_union_of_files() {
    let f = fixture();
    let mut set = KrlSet::default();
    set.add(Krl::read_file(&f.krl("alice-revoked.krl")).unwrap());
    set.add(Krl::read_file(&f.krl("bob-revoked.krl")).unwrap());
    let alice = RawSshSig::from_pem(&signature_for("SSH signed by alice (allowlisted)")).unwrap();
    let bob = RawSshSig::from_pem(&signature_for("SSH signed by bob (not allowlisted)")).unwrap();
    assert!(set.revokes(&alice.key));
    assert!(set.revokes(&bob.key));
}

fn payload_of(subject: &str) -> Vec<u8> {
    // Recompute the signed payload exactly as the auditor does.
    let f = fixture();
    let log = std::process::Command::new("git")
        .args(["log", "--all", "--format=%H %s"])
        .current_dir(f.repo())
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&log.stdout);
    let id = text
        .lines()
        .find(|l| l.contains(subject))
        .unwrap()
        .split(' ')
        .next()
        .unwrap();
    let raw = std::process::Command::new("git")
        .args(["cat-file", "commit", id])
        .current_dir(f.repo())
        .output()
        .unwrap()
        .stdout;
    sigaudit::objects::parse_signed_commit(&raw, 1)
        .expect("signed")
        .payload
}

#[test]
fn krl_revokes_certificate_via_bitmap_section() {
    // The bitmap KRL revokes serials 40 and 42 with an OpenSSH-style bitmap
    // (big-endian integer, bit 0 = least significant). Carol's certificate is
    // serial 42, so it must be revoked; her neighbour serial 41 is not.
    let f = fixture();
    let krl = Krl::read_file(&f.krl("bitmap-revoked.krl")).expect("parse bitmap KRL");
    let carol =
        RawSshSig::from_pem(&signature_for("SSH signed by carol via CA certificate")).unwrap();
    assert!(
        krl.revokes(&carol.key),
        "carol's certificate (serial 42) should be revoked by the bitmap"
    );
    // Dave's certificate is serial 77 and must not be affected.
    let dave =
        RawSshSig::from_pem(&signature_for("SSH signed by dave via revoked certificate")).unwrap();
    assert!(
        !krl.revokes(&dave.key),
        "dave's certificate (serial 77) must not match a bitmap starting at 40"
    );
}

#[test]
fn bitmap_offset_boundary_is_respected() {
    // A certificate with a serial below the bitmap offset is never revoked.
    let f = fixture();
    let krl = Krl::read_file(&f.krl("bitmap-revoked.krl")).unwrap();
    let alice = RawSshSig::from_pem(&signature_for("SSH signed by alice (allowlisted)")).unwrap();
    assert!(!krl.revokes(&alice.key));
}
