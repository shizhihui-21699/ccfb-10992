//! The payload the auditor extracts must be byte-identical to the buffer Git
//! hands to `gpg`/`ssh-keygen` (commit buffer with the signature header
//! removed).
mod common;

use common::fixture;

#[test]
fn payload_matches_git_cat_file_minus_signature_header() {
    let f = fixture();
    let log = std::process::Command::new("git")
        .args(["log", "--all", "--format=%H"])
        .current_dir(f.repo())
        .output()
        .unwrap();
    let mut checked = 0;
    for line in String::from_utf8_lossy(&log.stdout).lines() {
        let raw = std::process::Command::new("git")
            .args(["cat-file", "commit", line])
            .current_dir(f.repo())
            .output()
            .unwrap()
            .stdout;
        let Some(signed) = sigaudit::objects::parse_signed_commit(&raw, 1) else {
            continue;
        };
        // Recompute the payload the way Git's `parse_buffer_signed_by_header`
        // does, independently of the library implementation.
        let mut expected = Vec::new();
        let mut in_sig = false;
        for ln in raw.split_inclusive(|b| *b == b'\n') {
            let starts_sig = ln.starts_with(b"gpgsig ");
            if in_sig && ln.first() == Some(&b' ') {
                continue;
            }
            if starts_sig {
                in_sig = true;
                continue;
            }
            in_sig = false;
            expected.extend_from_slice(ln);
        }
        assert_eq!(signed.payload, expected, "payload mismatch for {line}");
        checked += 1;
    }
    assert!(
        checked >= 10,
        "expected several signed commits, checked {checked}"
    );
}
