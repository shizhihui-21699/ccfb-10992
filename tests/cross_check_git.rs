//! Cross-check the auditor against `git verify-commit`.
//!
//! `git verify-commit` is the reference implementation for "is this commit's
//! signature good". The only intentional divergence is time handling: Git asks
//! GnuPG about *now*, while this tool evaluates expiry/revocation at the
//! commit time. The one commit that exercises that difference is asserted
//! explicitly.

mod common;

use common::fixture;
use sigaudit::audit::{Audit, Config};
use sigaudit::model::Verdict;

fn git_verifies(commit: &str) -> bool {
    let f = fixture();
    let status = std::process::Command::new("git")
        .env("GNUPGHOME", f.root.join("gnupg"))
        .args([
            "-c",
            &format!(
                "gpg.ssh.allowedSignersFile={}",
                f.allowed_signers().display()
            ),
            "verify-commit",
            commit,
        ])
        .current_dir(f.repo())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .expect("running git verify-commit");
    status.success()
}

fn our_verdict(commit: &str) -> Verdict {
    let f = fixture();
    let config = Config {
        repo: f.repo(),
        branches: vec!["main".into()],
        remote_branches: false,
        include_tags: false,
        gpg_keyrings: f.gpg_keyrings(),
        allowed_signers: Some(f.allowed_signers()),
        krls: vec![],
        gpg_trusted_signers: vec!["alice@example.com".into(), "expired@example.com".into()],
    };
    let result = Audit::load(config).unwrap().run().unwrap();
    result
        .commits
        .iter()
        .find(|c| c.commit == commit)
        .unwrap_or_else(|| panic!("{commit} missing"))
        .verdict
}

/// Commits where `git` and this tool must agree on yes/no, ignoring the
/// distinction between the different failure verdicts.
#[test]
fn verdicts_match_git_for_signature_correctness() {
    let f = fixture();
    let log = std::process::Command::new("git")
        .args(["log", "--format=%H"])
        .current_dir(f.repo())
        .output()
        .unwrap();
    let output = String::from_utf8_lossy(&log.stdout);
    let mut compared = 0;
    for commit in output.lines() {
        if commit == f.commit("expired_valid_commit") {
            // Time-of-check difference, asserted separately.
            continue;
        }
        let git_ok = git_verifies(commit);
        let ours = our_verdict(commit);
        let our_ok = match ours {
            // A valid signature that is merely untrusted for policy reasons
            // still "verifies" as far as Git is concerned.
            Verdict::Signed => true,
            Verdict::Untrusted => git_ok,
            Verdict::Unsigned | Verdict::Invalid | Verdict::RevokedLater => false,
        };
        assert_eq!(
            git_ok,
            our_ok,
            "verdict mismatch for {commit} ({:?}): git_ok={git_ok}, ours={ours:?}",
            subject(commit)
        );
        compared += 1;
    }
    assert!(
        compared >= 10,
        "expected to compare a full history, got {compared}"
    );
}

/// A key that expired after the commit was signed must still be accepted,
/// whereas `git verify-commit` (which asks GnuPG about "now") rejects it.
#[test]
fn expired_key_is_accepted_at_commit_time_unlike_git_now() {
    let f = fixture();
    let commit = f.commit("expired_valid_commit");
    assert_eq!(our_verdict(&commit), Verdict::Signed);
    assert!(
        !git_verifies(&commit),
        "git rejects the expired key at verification time; that is the documented difference"
    );
}

fn subject(commit: &str) -> String {
    let f = fixture();
    let out = std::process::Command::new("git")
        .args(["log", "-1", "--format=%s", commit])
        .current_dir(f.repo())
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}
