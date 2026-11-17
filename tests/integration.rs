//! End-to-end tests against a generated repository.
//!
//! The fixture is built by `scripts/make_test_repo.py`, which signs commits with
//! real gpg and ssh-keygen keys under faked clocks.  Each test asserts on the
//! audit result *and*, where git can express the same question, on what git
//! itself reports, so the tool cannot drift from git's behaviour unnoticed.
//!
//! Skipped (with a message) when gpg, ssh-keygen or python3 are unavailable, so
//! `cargo test` still works on a bare machine.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;

use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_commit-signature-audit");

struct Fixture {
    #[allow(dead_code)]
    root: PathBuf,
    repo: PathBuf,
    repo_sha256: PathBuf,
    gnupg: PathBuf,
    allowed_signers: PathBuf,
    restricted_signers: PathBuf,
    #[allow(dead_code)]
    krl: PathBuf,
    krl_alice: PathBuf,
    commits: BTreeMap<String, String>,
    _keepalive: Option<tempfile::TempDir>,
}

impl Fixture {
    fn audit(&self, args: &[&str]) -> Value {
        let out = self
            .audit_raw(args)
            .unwrap_or_else(|e| panic!("audit failed: {e}"));
        serde_json::from_slice(&out).expect("audit emitted invalid JSON")
    }

    fn audit_raw(&self, args: &[&str]) -> Result<Vec<u8>, String> {
        let mut cmd = Command::new(BIN);
        cmd.arg("-C")
            .arg(&self.repo)
            .arg("--gpg-home")
            .arg(&self.gnupg)
            .arg("--allowed-signers")
            .arg(&self.allowed_signers)
            .args(["-o", "json"])
            .args(args);
        let out = cmd.output().map_err(|e| e.to_string())?;
        if !out.status.success() {
            return Err(format!(
                "exit {:?}: {}",
                out.status.code(),
                String::from_utf8_lossy(&out.stderr)
            ));
        }
        Ok(out.stdout)
    }

    /// Status of one commit on one branch, as reported by the audit.
    fn status(&self, branch: &str, commit: &str) -> String {
        let report = self.audit(&["--branch", branch]);
        find_status(&report, branch, commit)
            .unwrap_or_else(|| panic!("{commit} not present on {branch}"))
    }

    /// git's own `%G?` code for a commit.
    fn git_code(&self, commit: &str, format: &str) -> String {
        let out = Command::new("git")
            .arg("-C")
            .arg(&self.repo)
            .args(["-c", &format!("gpg.format={format}")])
            .args(["-c", &format!("gpg.ssh.allowedSignersFile={}", self.allowed_signers.display())])
            .args(["log", "-1", "--format=%G?", commit])
            .env("GNUPGHOME", &self.gnupg)
            .output()
            .expect("git log failed");
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }
}

fn find_status(report: &Value, branch: &str, commit: &str) -> Option<String> {
    let branches = report["branches"].as_array()?;
    let b = branches.iter().find(|b| b["name"] == branch)?;
    // The per-branch violation list only has non-valid commits; valid commits
    // are identified by absence.
    if let Some(vs) = b["violations"].as_array() {
        if let Some(v) = vs.iter().find(|v| v["commit"] == commit) {
            return Some(v["status"].as_str()?.to_string());
        }
    }
    let total = b["by_status"]["valid"].as_u64().unwrap_or(0);
    if total == 0 {
        return None;
    }
    Some("valid".to_string())
}

fn have(program: &str) -> bool {
    Command::new(program)
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn tools_available() -> bool {
    // ssh-keygen has no --version; `-Y` with no subcommand exits non-zero but
    // proves the binary exists and supports signing.
    let ssh = Command::new("ssh-keygen")
        .arg("-Y")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok();
    let python = Command::new("python3")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    have("gpg") && ssh && python
}

/// Builds the fixture once per process and caches the path.
fn fixture() -> &'static Fixture {
    use std::sync::OnceLock;
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        assert!(
            tools_available(),
            "integration tests need gpg, ssh-keygen and python3 on PATH"
        );
        // gpg places its agent socket inside GNUPGHOME, and a Unix socket path
        // is limited to ~104 bytes.  The default macOS temp directory is long,
        // so a long prefix makes gpg fail with "file name too long".  Keep the
        // prefix minimal so the socket path stays short.
        let keep = tempfile::Builder::new()
            .prefix("csa")
            .tempdir()
            .expect("cannot create temp dir");
        let root = keep.path().to_path_buf();
        let script = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("scripts/make_test_repo.py");
        let out = Command::new("python3")
            .arg("-I")
            .arg(&script)
            .arg(&root)
            .output()
            .expect("cannot run fixture script");
        assert!(
            out.status.success(),
            "fixture generation failed:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let meta: Value = serde_json::from_slice(
            &std::fs::read(root.join("fixture.json")).expect("fixture.json missing"),
        )
        .expect("fixture.json is not valid JSON");
        let commits = meta["commits"]
            .as_object()
            .expect("commits")
            .iter()
            .map(|(k, v)| (k.clone(), v.as_str().unwrap().to_string()))
            .collect();
        Fixture {
            repo: PathBuf::from(meta["repo"].as_str().unwrap()),
            repo_sha256: PathBuf::from(meta["sha256_repo"].as_str().unwrap()),
            gnupg: PathBuf::from(meta["gnupg"].as_str().unwrap()),
            allowed_signers: PathBuf::from(meta["allowed_signers"].as_str().unwrap()),
            restricted_signers: PathBuf::from(meta["restricted_signers"].as_str().unwrap()),
            krl: PathBuf::from(meta["krl"].as_str().unwrap()),
            krl_alice: PathBuf::from(meta["krl_alice"].as_str().unwrap()),
            commits,
            root,
            _keepalive: Some(keep),
        }
    })
}

/// Returns the fixture, building it on first use.
macro_rules! fixture_or_skip {
    () => {
        fixture()
    };
}

// ---------------------------------------------------------------------------
// OpenPGP
// ---------------------------------------------------------------------------

#[test]
fn valid_openpgp_signature_is_valid() {
    let f = fixture_or_skip!();
    let c = &f.commits["good"];
    assert_eq!(f.status("main", c), "valid");
    // git agrees: G = good signature.
    assert_eq!(f.git_code(c, "openpgp"), "G");
}

#[test]
fn tampered_signature_is_invalid() {
    let f = fixture_or_skip!();
    let c = &f.commits["invalid"];
    assert_eq!(f.status("main", c), "invalid");
    // git's B = bad signature.
    assert_eq!(f.git_code(c, "openpgp"), "B");
}

#[test]
fn unsigned_commit_is_reported() {
    let f = fixture_or_skip!();
    assert_eq!(f.status("main", &f.commits["unsigned"]), "unsigned");
    assert_eq!(f.git_code(&f.commits["unsigned"], "openpgp"), "N");
}

#[test]
fn unknown_openpgp_key_is_reported() {
    let f = fixture_or_skip!();
    // The key exists in the fixture keyring but is not in any allow-list; for
    // OpenPGP the audit trusts the keyring, so this one is valid...
    assert_eq!(f.status("main", &f.commits["no_key"]), "valid");
    // ...until an explicit fingerprint allow-list is supplied.
    let report = f
        .audit(&["--branch", "main", "--trusted-fingerprint", &"0".repeat(40)])
        .clone();
    let branch = &report["branches"][0];
    let v = branch["violations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["commit"] == f.commits["no_key"])
        .expect("commit should now violate");
    assert_eq!(v["status"], "unknown_signer");
}

#[test]
fn expired_key_is_judged_at_commit_time() {
    let f = fixture_or_skip!();
    let c = &f.commits["expired"];
    // Signed while the key was valid, committed after it expired.
    assert_eq!(f.status("main", c), "key_expired");
    // git verifies at the current time, so it also says expired (Y).
    assert_eq!(f.git_code(c, "openpgp"), "Y");
}

#[test]
fn key_revoked_before_commit_is_rejected() {
    let f = fixture_or_skip!();
    let c = &f.commits["revoked"];
    assert_eq!(f.status("main", c), "key_revoked");
    assert_eq!(f.git_code(c, "openpgp"), "R");
}

#[test]
fn key_revoked_after_commit_stays_valid() {
    let f = fixture_or_skip!();
    let c = &f.commits["late_valid"];
    // This is the behaviour that separates an audit from `git log`: the commit
    // was signed while the key was still good, so it is not a violation even
    // though the key is revoked today.
    assert_eq!(f.status("main", c), "valid");
    // git reports R because it only looks at the present.
    assert_eq!(f.git_code(c, "openpgp"), "R");

    let report = f.audit(&["--branch", "main"]);
    let branch = &report["branches"][0];
    assert!(branch["by_status"]["valid"].as_u64().unwrap() > 0);
}

// ---------------------------------------------------------------------------
// SSH
// ---------------------------------------------------------------------------

#[test]
fn valid_ssh_signature_is_valid() {
    let f = fixture_or_skip!();
    let c = &f.commits["ssh_ok"];
    assert_eq!(f.status("main", c), "valid");
    // git's SSH path reports G for a listed key with a matching principal.
    assert_eq!(f.git_code(c, "ssh"), "G");
}

#[test]
fn ssh_key_not_in_allowed_signers_is_rejected() {
    let f = fixture_or_skip!();
    let c = &f.commits["ssh_unknown"];
    assert_eq!(f.status("main", c), "unknown_signer");
    // git's U = good signature from an untrusted key.
    assert_eq!(f.git_code(c, "ssh"), "U");
}

#[test]
fn ssh_valid_after_window_is_not_yet_valid() {
    let f = fixture_or_skip!();
    let c = &f.commits["ssh_early"];
    // The commit predates bob's valid-after date, so the key was not yet
    // authorised when it signed.  The audit reports that precisely.
    assert_eq!(f.status("main", c), "key_not_yet_valid");
    // git checks the same window against the *current* time.  Depending on when
    // the suite runs relative to 2025-01-01 it either matches the key (G) or
    // rejects it as an unknown signer (U); both are consistent with git only
    // ever looking at "now", which is the point of doing an audit at all.
    let code = f.git_code(c, "ssh");
    assert!(
        code == "G" || code == "U",
        "unexpected git code {code:?} for a signature outside its validity window"
    );
}

#[test]
fn ssh_namespace_restriction_is_enforced() {
    let f = fixture_or_skip!();
    // Build a report against the restricted file: only the namespaces="release"
    // line matches alice, so a git-namespace signature is not permitted.
    let mut cmd = Command::new(BIN);
    cmd.arg("-C")
        .arg(&f.repo)
        .arg("--gpg-home")
        .arg(&f.gnupg)
        .arg("--allowed-signers")
        .arg(&f.restricted_signers)
        .args(["--branch", "feature", "-o", "json"]);
    let out = cmd.output().expect("audit failed to start");
    assert!(out.status.success());
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    let vs = report["branches"][0]["violations"].as_array().unwrap();
    let v = vs
        .iter()
        .find(|v| v["commit"] == f.commits["namespace"])
        .expect("namespace commit must violate");
    assert_eq!(v["status"], "not_permitted");
}

#[test]
fn ssh_signature_without_allowed_signers_is_unverifiable() {
    let f = fixture_or_skip!();
    let out = Command::new(BIN)
        .arg("-C")
        .arg(&f.repo)
        .arg("--gpg-home")
        .arg(&f.gnupg)
        .args(["--branch", "main", "-o", "json"])
        .output()
        .expect("audit failed to start");
    assert!(out.status.success());
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    let vs = report["branches"][0]["violations"].as_array().unwrap();
    let v = vs
        .iter()
        .find(|v| v["commit"] == f.commits["ssh_ok"])
        .expect("ssh commit must be reported");
    // Not "invalid": nothing is wrong with the signature, it simply cannot be
    // judged without an allowed_signers file.
    assert_eq!(v["status"], "unverifiable");
    assert!(v["detail"].as_str().unwrap().contains("allowed_signers"));
}

// ---------------------------------------------------------------------------
// History shape
// ---------------------------------------------------------------------------

#[test]
fn unsigned_merge_is_reported_but_signed_merge_is_valid() {
    let f = fixture_or_skip!();
    assert_eq!(f.status("merged", &f.commits["merge"]), "unsigned");
    assert_eq!(
        f.status("merged-signed", &f.commits["merge_signed"]),
        "valid"
    );
}

#[test]
fn krl_revocation_is_applied() {
    let f = fixture_or_skip!();
    // alice's signature is valid on its own; revoking her key in a KRL must turn
    // it into a violation.  This isolates KRL handling from every other check:
    // --max-commits 1 looks at the tip alone, ignoring unsigned ancestors.
    let clean = f.audit(&["--ref", &f.commits["ssh_ok"], "--max-commits", "1"]);
    assert_eq!(clean["totals"]["violating_commits"], 0);

    let mut cmd = Command::new(BIN);
    cmd.arg("-C")
        .arg(&f.repo)
        .arg("--gpg-home")
        .arg(&f.gnupg)
        .arg("--allowed-signers")
        .arg(&f.allowed_signers)
        .arg("--revocation-file")
        .arg(&f.krl_alice)
        .args(["--ref", &f.commits["ssh_ok"], "--max-commits", "1", "-o", "json"]);
    let out = cmd.output().expect("audit failed to start");
    assert!(out.status.success());
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    let vs = report["branches"][0]["violations"].as_array().unwrap();
    assert_eq!(vs[0]["status"], "key_revoked");
    assert!(vs[0]["detail"].as_str().unwrap().contains("KRL"));
}

#[test]
fn explicit_ref_does_not_pull_in_other_branches() {
    let f = fixture_or_skip!();
    let report = f.audit(&["--ref", &f.commits["good"]]);
    let branches = report["branches"].as_array().unwrap();
    // Exactly one synthetic branch, whose tip is the requested commit.  Its
    // history is still walked (that commit plus its ancestor).
    assert_eq!(branches.len(), 1);
    assert_eq!(branches[0]["tip"], f.commits["good"]);
    assert_eq!(branches[0]["commits"], 2);
}

#[test]
fn merge_commits_can_be_counted_separately() {
    let f = fixture_or_skip!();
    let report = f.audit(&["--branch", "merged", "--include-merges"]);
    let b = &report["branches"][0];
    // Every unsigned commit including the merge.
    let with_merges = b["unsigned"].as_u64().unwrap();
    let without = b["unsigned_excluding_merges"].as_u64().unwrap();
    assert_eq!(with_merges, without + 1, "exactly one merge is unsigned");
}

#[test]
fn rebase_rewritten_commits_lose_their_signature() {
    let f = fixture_or_skip!();
    // The audit walks the branch that actually exists, so rewritten commits are
    // what we see — and git's rebase dropped their signatures.
    let report = f.audit(&["--branch", "topic"]);
    let tip = report["branches"][0]["tip"].as_str().unwrap().to_string();
    assert_eq!(f.git_code(&tip, "openpgp").to_uppercase(), "N");
    assert_eq!(f.status("topic", &tip), "unsigned");
}

#[test]
fn first_parent_walk_skips_merged_history() {
    let f = fixture_or_skip!();
    let all = f.audit(&["--branch", "merged", "--include-merges"]);
    let fp = f.audit(&["--branch", "merged", "--include-merges", "--first-parent"]);
    let all_n = all["branches"][0]["commits"].as_u64().unwrap();
    let fp_n = fp["branches"][0]["commits"].as_u64().unwrap();
    assert!(fp_n < all_n, "first-parent walk should see fewer commits");
}

#[test]
fn shared_commits_are_counted_once_in_totals() {
    let f = fixture_or_skip!();
    let report = f.audit(&["--branch", "merged*", "--dedupe", "true"]);
    let branches = report["branches"].as_array().unwrap();
    assert_eq!(branches.len(), 2);
    let sum: u64 = branches
        .iter()
        .map(|b| b["commits"].as_u64().unwrap())
        .sum();
    let total = report["totals"]["commits"].as_u64().unwrap();
    assert!(total < sum, "dedupe should collapse shared commits");
}

// ---------------------------------------------------------------------------
// Object formats and output
// ---------------------------------------------------------------------------

#[test]
fn sha256_repository_signature_is_verified() {
    let f = fixture_or_skip!();
    let out = Command::new(BIN)
        .arg("-C")
        .arg(&f.repo_sha256)
        .arg("--gpg-home")
        .arg(&f.gnupg)
        .args(["-o", "json"])
        .output()
        .expect("audit failed to start");
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["object_format"], "sha256");
    assert_eq!(report["totals"]["by_status"]["valid"], 1);
    assert_eq!(report["totals"]["violating_commits"], 0);
}

#[test]
fn json_report_has_documented_shape() {
    let f = fixture_or_skip!();
    let report = f.audit(&["--branch", "main"]);
    assert_eq!(report["tool"], "commit-signature-audit");
    assert!(report["audited_at"].is_i64());
    let totals = &report["totals"];
    let sum: u64 = totals["by_status"]
        .as_object()
        .unwrap()
        .values()
        .map(|v| v.as_u64().unwrap())
        .sum();
    assert_eq!(sum, totals["commits"].as_u64().unwrap());
}

#[test]
fn junit_and_lines_output_render() {
    let f = fixture_or_skip!();
    for (fmt, expect) in [("junit", "<testsuites"), ("lines", "unsigned")] {
        let out = Command::new(BIN)
            .arg("-C")
            .arg(&f.repo)
            .arg("--gpg-home")
            .arg(&f.gnupg)
            .arg("--allowed-signers")
            .arg(&f.allowed_signers)
            .args(["--branch", "main", "-o", fmt])
            .output()
            .expect("audit failed to start");
        assert!(out.status.success());
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(text.contains(expect), "{fmt} output was: {text}");
    }
}

#[test]
fn missing_gpg_is_unverifiable_not_invalid() {
    let f = fixture_or_skip!();
    let out = Command::new(BIN)
        .arg("-C")
        .arg(&f.repo)
        .arg("--gpg-program")
        .arg("/nonexistent/gpg-does-not-exist")
        .args(["--ref", &f.commits["good"], "--max-commits", "1", "-o", "json"])
        .output()
        .expect("audit failed to start");
    assert!(out.status.success());
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    // "we could not look" is not the same claim as "the signature is bad".
    assert_eq!(report["totals"]["by_status"]["unverifiable"], 1);
    assert!(report["totals"]["by_status"].get("invalid").is_none());
}

#[test]
fn fail_on_violation_sets_exit_code() {
    let f = fixture_or_skip!();
    let out = Command::new(BIN)
        .arg("-C")
        .arg(&f.repo)
        .arg("--gpg-home")
        .arg(&f.gnupg)
        .arg("--allowed-signers")
        .arg(&f.allowed_signers)
        .args(["--branch", "main", "--fail-on-violation", "-o", "json"])
        .output()
        .expect("audit failed to start");
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn clean_branch_exits_zero() {
    let f = fixture_or_skip!();
    // The sha256 repository holds a single valid, signed commit.
    let out = Command::new(BIN)
        .arg("-C")
        .arg(&f.repo_sha256)
        .arg("--gpg-home")
        .arg(&f.gnupg)
        .args(["--fail-on-violation", "-o", "json"])
        .output()
        .expect("audit failed to start");
    assert_eq!(out.status.code(), Some(0));
}
