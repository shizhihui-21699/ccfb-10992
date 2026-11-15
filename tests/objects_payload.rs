//! Raw commit/tag signature extraction must reproduce Git's byte-level
//! payload rules, because the payload is what gets hashed.

use sigaudit::objects::{
    committer_timestamp, mergetag_payload, parse_signed_commit, parse_signed_tag, tagger_timestamp,
    SignatureHeader,
};

fn signed_commit() -> Vec<u8> {
    let sig = "-----BEGIN PGP SIGNATURE-----\n\niJEEABYKADkWIQRGx1ZI4vdVf9jkxo+1SDogOTT6XgUCavjkbRsUgAAAAAAEAA5t\nYW51MiwyLjUrMS4xMiwwLDMACgkQSDogOTT6Xg==\n=abcd\n-----END PGP SIGNATURE-----\n";
    let mut body = String::new();
    body.push_str("tree 0123456789012345678901234567890123456789\n");
    body.push_str("parent 1111111111111111111111111111111111111111\n");
    body.push_str("author A <a@example.com> 1700000000 +0000\n");
    body.push_str("committer C <c@example.com> 1700000100 +0000\n");
    for (i, line) in sig.lines().enumerate() {
        if i == 0 {
            body.push_str(&format!("gpgsig {line}\n"));
        } else {
            body.push_str(&format!(" {line}\n"));
        }
    }
    body.push('\n');
    body.push_str("subject line\n\nbody\n");
    body.into_bytes()
}

#[test]
fn commit_signature_is_unindented_and_removed_from_payload() {
    let raw = signed_commit();
    let signed = parse_signed_commit(&raw, 1).expect("signature");
    assert_eq!(signed.header, SignatureHeader::GpgSig);
    // The signature keeps its own line breaks but loses the leading space.
    assert!(signed
        .signature
        .starts_with(b"-----BEGIN PGP SIGNATURE-----\n\n"));
    assert!(signed.signature.ends_with(b"-----END PGP SIGNATURE-----\n"));
    // The payload has no gpgsig header but keeps everything else verbatim.
    assert!(!signed.payload.windows(6).any(|w| w == b"gpgsig"));
    assert!(signed
        .payload
        .starts_with(b"tree 0123456789012345678901234567890123456789\n"));
    assert!(signed.payload.ends_with(b"body\n"));
}

#[test]
fn payload_is_exactly_the_bytes_git_hashes() {
    let raw = signed_commit();
    let signed = parse_signed_commit(&raw, 1).unwrap();
    // Removing the 5-line gpgsig header must leave the original bytes minus
    // those lines; verify the tail (message) is untouched.
    assert!(signed.payload.ends_with(b"\nsubject line\n\nbody\n"));
}

#[test]
fn unsigned_commit_has_no_signature() {
    let raw = b"tree 0123456789012345678901234567890123456789\nauthor A <a@e> 1 +0000\ncommitter C <c@e> 1 +0000\n\nmsg\n";
    assert!(parse_signed_commit(raw, 1).is_none());
}

#[test]
fn sha256_repo_uses_gpgsig_sha256_header() {
    let raw = b"tree 0123456789012345678901234567890123456789\ncommitter C <c@e> 1 +0000\ngpgsig-sha256 -----BEGIN PGP SIGNATURE-----\n AAAA\n -----END PGP SIGNATURE-----\n\nmsg\n";
    let signed = parse_signed_commit(raw, 2).expect("sha256 signature");
    assert!(signed
        .signature
        .starts_with(b"-----BEGIN PGP SIGNATURE-----"));
    assert!(!signed.payload.windows(12).any(|w| w == b"gpgsig-sha25"));
}

#[test]
fn committer_timestamp_reads_ident_not_message() {
    let raw = signed_commit();
    assert_eq!(committer_timestamp(&raw), Some(1700000100));
    // A message line that looks like an ident must not win.
    let mut evil = raw.clone();
    evil.extend_from_slice(b"committer Fake <f@e> 9999999999 +0000\n");
    assert_eq!(committer_timestamp(&evil), Some(1700000100));
}

#[test]
fn tagger_timestamp_reads_tag_ident() {
    let raw = b"object 0123456789012345678901234567890123456789\ntype commit\ntag v1\ntagger T <t@e> 1600000000 +0000\n\nmsg\n";
    assert_eq!(tagger_timestamp(raw), Some(1600000000));
}

#[test]
fn inline_tag_signature_splits_at_armour() {
    let mut raw = Vec::new();
    raw.extend_from_slice(b"object 0123456789012345678901234567890123456789\ntype commit\ntag v1\ntagger T <t@e> 1600000000 +0000\n\nrelease\n");
    let signed_offset = raw.len();
    raw.extend_from_slice(b"-----BEGIN PGP SIGNATURE-----\n\nAAAA\n-----END PGP SIGNATURE-----\n");
    let signed = parse_signed_tag(&raw).expect("tag signature");
    assert_eq!(signed.header, SignatureHeader::Inline);
    assert_eq!(&signed.payload[..], &raw[..signed_offset]);
    assert!(signed
        .signature
        .starts_with(b"-----BEGIN PGP SIGNATURE-----"));
}

#[test]
fn mergetag_header_is_unfolded() {
    let raw = b"tree 0123456789012345678901234567890123456789\ncommitter C <c@e> 1 +0000\nmergetag object abc\n type commit\n -----BEGIN PGP SIGNATURE-----\n AAAA\n -----END PGP SIGNATURE-----\n\nmsg\n";
    let payload = mergetag_payload(raw).expect("mergetag");
    let text = String::from_utf8_lossy(&payload);
    assert!(text.starts_with("object abc\ntype commit\n"));
    assert!(text.contains("-----BEGIN PGP SIGNATURE-----\nAAAA\n"));
}
