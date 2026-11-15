//! Unit tests for the OpenSSH-compatible policy primitives.

use sigaudit::ssh_keys::{krl_entry_count, match_pattern, match_pattern_list, AllowedSigners, Krl};

#[test]
fn glob_star_matches_any_run() {
    assert!(match_pattern("alice@example.com", "alice@example.com"));
    assert!(match_pattern("alice@example.com", "*@example.com"));
    assert!(match_pattern("alice@example.com", "alice@*"));
    assert!(match_pattern("anything", "*"));
    assert!(match_pattern("", "*"));
}

#[test]
fn glob_question_matches_one_char() {
    assert!(match_pattern("a", "?"));
    assert!(!match_pattern("", "?"));
    assert!(match_pattern("bob", "b?b"));
    assert!(!match_pattern("bb", "b?b"));
}

#[test]
fn glob_is_anchored() {
    assert!(!match_pattern("xalice@example.com", "alice@example.com"));
    assert!(!match_pattern(
        "alice@example.com.evil",
        "alice@example.com"
    ));
}

#[test]
fn pattern_list_positive_match() {
    let patterns = vec![
        "alice@example.com".to_string(),
        "bob@example.com".to_string(),
    ];
    assert_eq!(match_pattern_list("bob@example.com", &patterns), 1);
    assert_eq!(match_pattern_list("carol@example.com", &patterns), 0);
}

#[test]
fn pattern_list_negation_wins() {
    // OpenSSH returns -1 as soon as a negated subpattern matches, even if a
    // later positive one would too.
    let patterns = vec![
        "!alice@evil.com".to_string(),
        "*@evil.com".to_string(),
        "alice@example.com".to_string(),
    ];
    assert_eq!(match_pattern_list("alice@evil.com", &patterns), -1);
    assert_eq!(match_pattern_list("bob@evil.com", &patterns), 1);
    assert_eq!(match_pattern_list("alice@example.com", &patterns), 1);
}

#[test]
fn pattern_list_without_positive_does_not_match() {
    let patterns = vec!["!bob@example.com".to_string()];
    assert_eq!(match_pattern_list("alice@example.com", &patterns), 0);
}

#[test]
fn allowed_signers_parses_options_and_keys() {
    let text = "\
# comment line

alice@example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN796jTiQfZfG1KaT0PtFDJ/XFSqti a
bob@example.com,robert@example.com namespaces=\"git,other\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN796jTiQfZfG1KaT0PtFDJ/XFSqti b
";
    let signers = AllowedSigners::parse(text);
    assert!(signers.warnings.is_empty(), "{:?}", signers.warnings);
    // Two lines parse; malformed key material would have produced warnings.
    assert_eq!(signers.line_count(), 2);
}

#[test]
fn malformed_signer_line_is_a_warning_not_a_failure() {
    let text = "alice@example.com not-a-key\nbob@example.com ssh-ed25519 AAAA\n";
    let signers = AllowedSigners::parse(text);
    assert!(!signers.warnings.is_empty());
}

#[test]
fn krl_rejects_non_krl_data() {
    assert!(Krl::parse(b"not a krl at all").is_err());
}

#[test]
fn krl_parses_empty_revocation_list() {
    // A well-formed KRL header with no sections.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&0x5353_484b_524c_0a00u64.to_be_bytes());
    bytes.extend_from_slice(&1u32.to_be_bytes()); // format version
    bytes.extend_from_slice(&0u64.to_be_bytes()); // krl version
    bytes.extend_from_slice(&0u64.to_be_bytes()); // generated
    bytes.extend_from_slice(&0u64.to_be_bytes()); // flags
    bytes.extend_from_slice(&0u32.to_be_bytes()); // reserved (empty string)
    bytes.extend_from_slice(&0u32.to_be_bytes()); // comment (empty string)
    let krl = Krl::parse(&bytes).expect("parse");
    assert!(krl.is_empty());
    assert_eq!(krl_entry_count(&krl), 0);
}

#[test]
fn krl_section_truncation_is_an_error() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&0x5353_484b_524c_0a00u64.to_be_bytes());
    bytes.extend_from_slice(&1u32.to_be_bytes());
    bytes.extend_from_slice(&0u64.to_be_bytes());
    bytes.extend_from_slice(&0u64.to_be_bytes());
    bytes.extend_from_slice(&0u64.to_be_bytes());
    bytes.extend_from_slice(&0u32.to_be_bytes());
    bytes.extend_from_slice(&0u32.to_be_bytes());
    // Explicit-key section claiming 100 bytes of payload with none present.
    bytes.push(2);
    bytes.extend_from_slice(&100u32.to_be_bytes());
    assert!(Krl::parse(&bytes).is_err());
}

#[test]
fn quoted_namespace_with_comma_stays_one_value() {
    // `namespaces="git,other"` is a single quoted option whose value contains
    // a comma; splitting on the comma blindly would corrupt the option list.
    let text = "k@example.com namespaces=\"git,other\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN796jTiQfZfG1KaT0PtFDJ/XFSqti k\n";
    let signers = AllowedSigners::parse(text);
    assert!(signers.warnings.is_empty(), "{:?}", signers.warnings);
    assert_eq!(signers.line_count(), 1);
}
