//! End-to-end tests against a repository built by `scripts/build_fixtures.sh`
//! with real git/gpg/ssh-keygen signatures.

mod common;

use common::fixture;
use sigaudit::audit::{Audit, Config};
use sigaudit::model::Verdict;
use sigaudit::report::FailOn;

fn audit(config: Config) -> sigaudit::audit::AuditResult {
    Audit::load(config)
        .expect("load audit")
        .run()
        .expect("run audit")
}

fn base_config() -> Config {
    let f = fixture();
    Config {
        repo: f.repo(),
        branches: vec![],
        remote_branches: false,
        include_tags: false,
        gpg_keyrings: f.gpg_keyrings(),
        allowed_signers: Some(f.allowed_signers()),
        krls: vec![],
        gpg_trusted_signers: vec!["alice@example.com".into(), "expired@example.com".into()],
    }
}

fn find<'a>(
    result: &'a sigaudit::audit::AuditResult,
    id: &str,
) -> &'a sigaudit::model::CommitReport {
    result
        .commits
        .iter()
        .find(|c| c.commit == id)
        .unwrap_or_else(|| panic!("commit {} not in report", id))
}

#[test]
fn trusted_openpgp_signature_is_signed() {
    let f = fixture();
    let result = audit(base_config());
    let alice = find(&result, &f.commit("alice_commit"));
    assert_eq!(alice.verdict, Verdict::Signed, "{:?}", alice.reason);
    let sig = alice.signature.as_ref().unwrap();
    assert_eq!(
        sig.signer_fingerprint.as_deref(),
        Some(f.commit("alice_fpr_lower").as_str())
    );
}

#[test]
fn unsigned_commit_is_reported_unsigned() {
    fixture();
    let result = audit(base_config());
    let c = result
        .commits
        .iter()
        .find(|c| c.subject == "unsigned commit")
        .unwrap();
    assert_eq!(c.verdict, Verdict::Unsigned);
    assert!(c.signature.is_none());
}

#[test]
fn signature_by_untrusted_key_is_untrusted() {
    fixture();
    let result = audit(base_config());
    let untrusted = result
        .commits
        .iter()
        .find(|c| c.subject == "signed by bob (not allowlisted)")
        .unwrap();
    assert_eq!(
        untrusted.verdict,
        Verdict::Untrusted,
        "{:?}",
        untrusted.reason
    );
}

#[test]
fn corrupted_signature_is_invalid() {
    let f = fixture();
    let result = audit(base_config());
    let corrupt = find(&result, &f.commit("corrupt_commit"));
    assert_eq!(corrupt.verdict, Verdict::Invalid, "{:?}", corrupt.reason);
}

#[test]
fn expired_key_still_valid_at_commit_time_is_accepted() {
    let f = fixture();
    let result = audit(base_config());
    let c = find(&result, &f.commit("expired_valid_commit"));
    assert_eq!(c.verdict, Verdict::Signed, "{:?}", c.reason);
}

#[test]
fn expired_key_after_expiry_is_rejected() {
    let f = fixture();
    let result = audit(base_config());
    let c = find(&result, &f.commit("expired_stale_commit"));
    assert_eq!(c.verdict, Verdict::Untrusted, "{:?}", c.reason);
    assert!(c.reason.as_deref().unwrap().contains("expired"));
}

#[test]
fn ssh_signature_from_plain_allowlisted_key_is_signed() {
    fixture();
    let result = audit(base_config());
    let c = result
        .commits
        .iter()
        .find(|c| c.subject == "SSH signed by alice (allowlisted)")
        .unwrap();
    assert_eq!(c.verdict, Verdict::Signed, "{:?}", c.reason);
}

#[test]
fn ssh_signature_via_certificate_authority_is_signed() {
    let f = fixture();
    let result = audit(base_config());
    let c = find(&result, &f.commit("carol_cert_commit"));
    assert_eq!(c.verdict, Verdict::Signed, "{:?}", c.reason);
}

#[test]
fn ssh_krl_revocation_makes_signature_untrusted() {
    let f = fixture();
    let mut config = base_config();
    config.krls = vec![f.krl("dave-cert-revoked.krl"), f.krl("alice-revoked.krl")];
    let result = audit(config);
    let dave = find(&result, &f.commit("dave_cert_commit"));
    assert_eq!(dave.verdict, Verdict::Untrusted, "{:?}", dave.reason);
    assert!(dave.reason.as_deref().unwrap().contains("revoked"));
    let alice_ssh = result
        .commits
        .iter()
        .find(|c| c.subject == "SSH signed by alice (allowlisted)")
        .unwrap();
    assert_eq!(
        alice_ssh.verdict,
        Verdict::Untrusted,
        "{:?}",
        alice_ssh.reason
    );
}

#[test]
fn merge_commit_is_audited_and_signed() {
    fixture();
    let result = audit(base_config());
    let merge = result
        .commits
        .iter()
        .find(|c| c.subject == "signed merge by alice")
        .unwrap();
    assert_eq!(merge.verdict, Verdict::Signed, "{:?}", merge.reason);
    assert_eq!(merge.parents.len(), 2);
}

#[test]
fn branch_restriction_selects_only_that_branch() {
    fixture();
    let mut config = base_config();
    config.branches = vec!["clean-only".into()];
    let result = audit(config);
    assert_eq!(result.branches.len(), 1);
    assert_eq!(result.branches[0].name, "clean-only");
    assert!(result.branches[0].counts.total >= 1);
}

#[test]
fn overlapping_branches_deduplicate_commits() {
    fixture();
    let result = audit(base_config());
    assert!(result.branches.len() >= 2);
    assert!(result.unique_commits < result.branches.iter().map(|b| b.counts.total).sum());
    // Every commit id is unique in the report.
    let mut ids: Vec<_> = result.commits.iter().map(|c| &c.commit).collect();
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), result.commits.len());
}

#[test]
fn every_branch_commit_count_matches_walk() {
    fixture();
    let result = audit(base_config());
    for branch in &result.branches {
        assert_eq!(
            branch.counts.total,
            branch.counts.signed
                + branch.counts.unsigned
                + branch.counts.invalid
                + branch.counts.untrusted
                + branch.counts.revoked_later
        );
    }
}

#[test]
fn json_report_has_stable_schema_and_passed_flag() {
    let f = fixture();
    let result = audit(base_config());
    let options = sigaudit::report::ReportOptions {
        fail_on: FailOn::Untrusted,
        require_signature: false,
        openpgp_keyrings: f.gpg_keyrings().len(),
        openpgp_trusted_signers: vec!["alice@example.com".into()],
        ssh_allowed_signers: true,
        ssh_krls: 0,
        repository: "fixture".into(),
    };
    let json = sigaudit::report::build_json(&result, &options);
    assert_eq!(json.schema_version, 1);
    assert!(!json.passed);
    let serialized = serde_json::to_value(&json).unwrap();
    for field in ["totals", "branches", "commits", "warnings", "policy"] {
        assert!(serialized.get(field).is_some(), "missing {field}");
    }
}

#[test]
fn fail_on_policy_is_consistent_between_text_and_json() {
    // On the clean-only branch there is one valid and one unsigned commit.
    // `--require-signature` must flip the result in both the exit flag and the
    // per-branch failure list.
    fixture();
    let mut config = base_config();
    config.branches = vec!["clean-only".into()];
    let result = audit(config);

    let lenient = sigaudit::report::ReportOptions {
        fail_on: FailOn::Untrusted,
        require_signature: false,
        openpgp_keyrings: 0,
        openpgp_trusted_signers: vec![],
        ssh_allowed_signers: true,
        ssh_krls: 0,
        repository: "fixture".into(),
    };
    let strict = sigaudit::report::ReportOptions {
        require_signature: true,
        ..lenient_options(&lenient)
    };

    let lenient_json = sigaudit::report::build_json(&result, &lenient);
    assert!(lenient_json.passed);
    assert_eq!(lenient_json.branches[0].failure_count, 0);

    let strict_json = sigaudit::report::build_json(&result, &strict);
    assert!(!strict_json.passed);
    assert_eq!(strict_json.branches[0].failure_count, 1);
    assert!(strict_json
        .commits
        .iter()
        .any(|c| c.verdict == Verdict::Unsigned));
}

#[test]
fn invalid_signature_always_fails_even_under_invalid_policy() {
    let f = fixture();
    let result = audit(base_config());
    let corrupt = find(&result, &f.commit("corrupt_commit"));
    assert_eq!(corrupt.verdict, Verdict::Invalid);
    let options = sigaudit::report::ReportOptions {
        fail_on: FailOn::Invalid,
        require_signature: false,
        openpgp_keyrings: 0,
        openpgp_trusted_signers: vec![],
        ssh_allowed_signers: true,
        ssh_krls: 0,
        repository: "fixture".into(),
    };
    assert!(!sigaudit::report::build_json(&result, &options).passed);
}

fn lenient_options(base: &sigaudit::report::ReportOptions) -> sigaudit::report::ReportOptions {
    sigaudit::report::ReportOptions {
        fail_on: base.fail_on,
        require_signature: base.require_signature,
        openpgp_keyrings: base.openpgp_keyrings,
        openpgp_trusted_signers: base.openpgp_trusted_signers.clone(),
        ssh_allowed_signers: base.ssh_allowed_signers,
        ssh_krls: base.ssh_krls,
        repository: base.repository.clone(),
    }
}
