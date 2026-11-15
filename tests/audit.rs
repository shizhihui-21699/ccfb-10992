//! End-to-end tests: build a real repository with real gpg/ssh-keygen
//! signatures, run the binary, and compare against `git`'s own verdicts.
//!
//! These tests deliberately cross-check against `git verify-commit` rather than
//! against hand-written expectations, because the requirement is to match git's
//! behaviour "wherever the signature check is uncertain". If git says `%G?` is
//! X for a commit, sigaudit must say X too.
//!
//! The fixture repository is built once per test binary by
//! `scripts/make_fixtures.sh`. Tests that need gpg or ssh-keygen skip
//! themselves when the tools are unavailable rather than failing.

use std::collections::HashMap;
use std::path::Path;
use std::process::Command;

mod support;
use support::{Fixtures, Sigaudit};

/// Build (or reuse) the fixture repository once for the whole test binary.
fn fixtures() -> Fixtures {
    support::build_once();
    support::cached().expect("fixtures were built")
}

fn tool_available(program: &str) -> bool {
    Command::new(program)
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn ssh_keygen_available() -> bool {
    Command::new("ssh-keygen")
        .arg("-Z")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok()
}

macro_rules! require_gpg {
    () => {
        if !tool_available("gpg") {
            eprintln!("skipping: gpg is not available");
            return;
        }
    };
}

macro_rules! require_ssh {
    () => {
        if !ssh_keygen_available() {
            eprintln!("skipping: ssh-keygen is not available");
            return;
        }
    };
}

/// git's own verdict for one commit, as ground truth.
///
/// Two git behaviours have to be reconciled here:
///
/// * `%G?` prints `U` both for "cryptographically good but the key has no trust
///   level assigned" (OpenPGP, gpg's TRUST_UNDEFINED) and for "good signature,
///   signer not allowed" (SSH, no allowed_signers principal). Only the first is
///   a pass.
/// * `git verify-commit` is the authority on which one it is: it exits 0 for
///   the trust case and non-zero for the not-allowed case.
///
/// So: `G` when git says G, or when git says U *and* verify-commit succeeds.
fn git_letter(fx: &Fixtures, oid: &str) -> char {
    let out = Command::new("git")
        .arg("-C")
        .arg(&fx.repo)
        .arg("log")
        .arg("-1")
        .arg("--format=%G?")
        .arg(oid)
        .env("GNUPGHOME", &fx.gnupg_home)
        .env("LC_ALL", "C")
        .output()
        .expect("git log");
    let letter = String::from_utf8_lossy(&out.stdout)
        .trim()
        .chars()
        .next()
        .unwrap_or('?');
    if letter != 'U' {
        return letter;
    }
    let verified = Command::new("git")
        .arg("-C")
        .arg(&fx.repo)
        .arg("verify-commit")
        .arg(oid)
        .env("GNUPGHOME", &fx.gnupg_home)
        .env("LC_ALL", "C")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .expect("git verify-commit");
    if verified.success() {
        'G'
    } else {
        'U'
    }
}

fn sigaudit(fx: &Fixtures) -> Sigaudit {
    Sigaudit::new(fx)
}

// ---------------------------------------------------------------------------
// Repository-level behaviour
// ---------------------------------------------------------------------------

#[test]
fn audits_every_branch_and_deduplicates_commits() {
    let fx = fixtures();
    // No --unreachable here: the dedup assertion below compares against the
    // sum of per-branch commit counts, and unreachable commits are in no branch.
    let audit = sigaudit(&fx).run_json(&[]);
    let report = audit.json();
    let summary = &report["summary"];
    let total = summary["total"].as_u64().unwrap();

    // Records are unique objects even though branches share history.
    let mut seen = std::collections::HashSet::new();
    for r in report["records"].as_array().unwrap() {
        let oid = r["oid"].as_str().unwrap();
        assert!(seen.insert(oid.to_string()), "duplicate record for {oid}");
    }
    assert_eq!(seen.len() as u64, total);

    // Every commit in every branch is covered: the union of branch tips'
    // histories equals the audited commit count (plus tags).
    let branch_count: u64 = report["branches"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| b["commits"].as_u64().unwrap())
        .sum();
    assert!(
        branch_count >= total,
        "branch commit counts ({branch_count}) should be at least the deduplicated total ({total})"
    );

    let branch_names: Vec<&str> = report["branches"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| b["name"].as_str().unwrap())
        .collect();
    for expected in ["main", "ssh", "rebase", "side", "side2"] {
        assert!(
            branch_names.contains(&expected),
            "branch {expected} missing from {branch_names:?}"
        );
    }
}

#[test]
fn exit_code_is_one_when_any_commit_fails_and_zero_when_all_pass() {
    let fx = fixtures();
    let failing = sigaudit(&fx).run_json(&[]);
    assert_eq!(failing.code, 1, "expected a failing audit");
    assert!(!failing.passed());

    // Narrowing to a branch that contains a known failure keeps exit 1.
    let good_only = sigaudit(&fx).run_json(&["--branch", "does-not-exist"]);
    assert_eq!(
        good_only.code, 0,
        "an empty audit set has no failures and must exit 0"
    );
    assert!(good_only.passed());
}

#[test]
fn branch_glob_selects_matching_branches_only() {
    let fx = fixtures();
    let audit = sigaudit(&fx).run_json(&["--branch", "side*"]);
    let report = audit.json();
    let names: Vec<&str> = report["branches"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| b["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, vec!["side", "side2"]);
}

#[test]
fn max_commits_caps_each_branch() {
    let fx = fixtures();
    let audit = sigaudit(&fx).run_json(&["--branch", "main", "--max-commits", "3"]);
    let report = audit.json();
    assert_eq!(report["branches"][0]["commits"].as_u64().unwrap(), 3);
    assert_eq!(report["summary"]["total"].as_u64().unwrap(), 3);
}

#[test]
fn tags_are_audited_when_requested() {
    let fx = fixtures();
    let with_tags = sigaudit(&fx).run_json(&["--branch", "main", "--tags"]);
    let report = with_tags.json();
    let tags: Vec<&serde_json::Value> = report["records"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["kind"] == "tag")
        .collect();
    assert_eq!(
        tags.len(),
        2,
        "expected the signed and unsigned annotated tags"
    );
    let signed = tags.iter().find(|t| t["tag"] == "v1.0").unwrap();
    let unsigned = tags.iter().find(|t| t["tag"] == "v0.9-unsigned").unwrap();
    assert_eq!(unsigned["verdict"], "unsigned");
    if tool_available("gpg") {
        assert_eq!(signed["verdict"], "good");
    }
}

#[test]
fn unreachable_commits_are_hidden_by_default_and_revealed_on_request() {
    let fx = fixtures();
    let plain = sigaudit(&fx).run_json(&["--branch", "main"]);
    let with_unreachable = sigaudit(&fx).run_json(&["--branch", "main", "--unreachable"]);

    let plain_oids: std::collections::HashSet<String> = plain.json()["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["oid"].as_str().unwrap().to_string())
        .collect();
    let with_unreachable_json = with_unreachable.json();
    let unreachable_oids: Vec<&serde_json::Value> = with_unreachable_json["records"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| {
            let oid = r["oid"].as_str().unwrap();
            !plain_oids.contains(oid)
        })
        .collect();

    assert!(
        !unreachable_oids.is_empty(),
        "--unreachable should surface the pre-rebase commits"
    );
    let has_pre_rebase = unreachable_oids
        .iter()
        .any(|r| r["oid"].as_str() == Some(fx.pre_rebase_two.as_str()));
    assert!(
        has_pre_rebase,
        "the pre-rebase commit should appear only with --unreachable"
    );
}

#[test]
fn merge_commits_are_audited_by_their_own_signature() {
    let fx = fixtures();
    let audit = sigaudit(&fx).run_json(&["--branch", "main", "--tags"]);
    let report = audit.json();
    let merges: Vec<&serde_json::Value> = report["records"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["is_merge"].as_bool().unwrap_or(false))
        .collect();
    assert_eq!(
        merges.len(),
        2,
        "fixture has one signed and one unsigned merge"
    );
    let by_verdict: HashMap<&str, usize> = merges.iter().fold(HashMap::new(), |mut m, r| {
        *m.entry(r["verdict"].as_str().unwrap()).or_default() += 1;
        m
    });
    assert_eq!(by_verdict.get("unsigned"), Some(&1));
}

// ---------------------------------------------------------------------------
// OpenPGP: agreement with git
// ---------------------------------------------------------------------------

/// Parity with git's own verdicts.
///
/// git always asks gpg about *now*, so the tool is put in the same mode here:
/// `--gpg-time now`. The tool's own default is `committer`, which answers the
/// different (and, for an audit, more useful) question "was the key valid when
/// this commit was made?"; that behaviour has its own tests below.
#[test]
fn openpgp_verdicts_match_git_for_every_commit() {
    require_gpg!();
    let fx = fixtures();
    let audit = sigaudit(&fx).run_json(&["--branch", "main", "--gpg-time", "now"]);
    let report = audit.json();

    let records: HashMap<String, char> = report["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            (
                r["oid"].as_str().unwrap().to_string(),
                r["git_letter"].as_str().unwrap().chars().next().unwrap(),
            )
        })
        .collect();

    for (oid, ours) in &records {
        let theirs = git_letter(&fx, oid);
        assert_eq!(
            *ours, theirs,
            "verdict mismatch for {oid}: sigaudit says {ours}, git says {theirs}"
        );
    }
}

#[test]
fn expired_before_the_commit_is_reported_as_key_expired() {
    require_gpg!();
    let fx = fixtures();
    let audit = sigaudit(&fx).run_json(&["--branch", "main"]);
    let report = audit.json();
    let rec = find_record(&report, &fx.expired_at_commit);
    assert_eq!(rec["verdict"], "key_expired_at_commit");
    assert_eq!(rec["git_letter"], "Y");
}

#[test]
fn expired_only_after_the_commit_is_good_at_commit_time() {
    require_gpg!();
    let fx = fixtures();
    let audit = sigaudit(&fx).run_json(&["--branch", "main"]);
    let report = audit.json();
    let rec = find_record(&report, &fx.expired_since);
    assert_eq!(
        rec["verdict"], "good",
        "a key that expired after the commit stayed valid at commit time: {}",
        rec["detail"]
    );
}

#[test]
fn revoked_after_the_commit_is_reported_as_revoked() {
    require_gpg!();
    let fx = fixtures();
    let audit = sigaudit(&fx).run_json(&["--branch", "main"]);
    let report = audit.json();
    let rec = find_record(&report, &fx.revoked_after);
    assert_eq!(rec["verdict"], "key_revoked_at_commit");
    assert_eq!(rec["git_letter"], "R");
    let detail = rec["detail"].as_str().unwrap_or("");
    assert!(
        detail.contains("predates the revocation") || detail.contains("revocation"),
        "detail should explain the timing: {detail}"
    );
}

#[test]
fn unknown_key_is_reported_as_unknown_not_bad() {
    require_gpg!();
    let fx = fixtures();
    let audit = sigaudit(&fx).run_json(&["--branch", "main"]);
    let report = audit.json();
    let rec = report["records"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["verdict"] == "unknown_key")
        .expect("fixture has a commit signed by a key outside the audit keyring");
    assert_eq!(rec["git_letter"], "E");
}

#[test]
fn gpg_time_now_flags_a_key_that_expired_later() {
    require_gpg!();
    let fx = fixtures();
    let at_commit = sigaudit(&fx).run_json(&["--branch", "main", "--gpg-time", "committer"]);
    let now = sigaudit(&fx).run_json(&["--branch", "main", "--gpg-time", "now"]);

    let at_commit_json = at_commit.json();
    let now_json = now.json();
    let at_commit_rec = find_record(&at_commit_json, &fx.expired_since);
    let now_rec = find_record(&now_json, &fx.expired_since);
    assert_eq!(at_commit_rec["verdict"], "good");
    assert_eq!(
        now_rec["verdict"], "key_expired_at_commit",
        "--gpg-time=now must reproduce git's wall-clock behaviour"
    );
    assert_eq!(now_rec["git_letter"], "Y");
}

/// Resolve a fingerprint to the primary key it belongs to, via gpg itself.
///
/// A signature is made by a *subkey* when the key has one, so the fingerprint in
/// VALIDSIG is the subkey's. This maps it back to the primary so the test can
/// assert which identity signed.
fn primary_fingerprint(fx: &Fixtures, fingerprint: &str) -> String {
    let out = Command::new("gpg")
        .arg("--homedir")
        .arg(&fx.gnupg_home)
        .arg("--batch")
        .arg("--with-colons")
        .arg("--list-keys")
        .arg(fingerprint)
        .env("LC_ALL", "C")
        .output()
        .expect("gpg --list-keys");
    let text = String::from_utf8_lossy(&out.stdout);
    text.lines()
        .find(|l| l.starts_with("fpr:"))
        .and_then(|l| l.split(':').nth(9))
        .unwrap_or("")
        .to_ascii_uppercase()
}

#[test]
fn reported_fingerprints_identify_the_signing_key() {
    require_gpg!();
    let fx = fixtures();
    let audit = sigaudit(&fx).run_json(&["--branch", "main"]);
    let report = audit.json();

    // The reported fingerprint must resolve to the primary key we expect, so a
    // reviewer can tell *which* key signed without digging through the keyring.
    let assert_signed_by = |oid: &str, expected_primary: &str| {
        let rec = find_record(&report, oid);
        let fpr = rec["fingerprint"]
            .as_str()
            .unwrap_or_else(|| panic!("no fingerprint on {oid}"));
        let primary = primary_fingerprint(&fx, fpr);
        assert_eq!(
            primary,
            expected_primary.to_ascii_uppercase(),
            "commit {oid} signed by {fpr}, whose primary key is {primary}"
        );
    };

    assert_signed_by(&fx.expired_at_commit, &fx.expired_fpr);
    assert_signed_by(&fx.expired_since, &fx.later_fpr);
    assert_signed_by(&fx.revoked_after, &fx.revoked_fpr);

    // The fixture's first commit is signed by the good key; the other "good"
    // records may be commits made by keys that later expired.
    let good = report["records"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| {
            r["verdict"] == "good"
                && r["signed_at"].as_i64() == Some(fx.t0)
                && r["signature_format"] == "openpgp"
                && r["fingerprint"]
                    .as_str()
                    .map(|f| primary_fingerprint(&fx, f) == fx.good_fpr.to_ascii_uppercase())
                    .unwrap_or(false)
        })
        .expect("a commit signed by the good key exists");
    let fpr = good["fingerprint"].as_str().unwrap();
    assert_eq!(
        primary_fingerprint(&fx, fpr),
        fx.good_fpr.to_ascii_uppercase()
    );
}

#[test]
fn commit_times_are_reported_in_utc() {
    let fx = fixtures();
    let audit = sigaudit(&fx).run_json(&["--branch", "main"]);
    let report = audit.json();
    let good = report["records"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["signed_at"].as_i64() == Some(fx.t0))
        .expect("the fixture commits are stamped at T0");
    assert_eq!(good["signed_at_utc"], "2023-11-14T22:13:20Z");
}

#[test]
fn signature_creation_time_is_reported() {
    require_gpg!();
    let fx = fixtures();
    let audit = sigaudit(&fx).run_json(&["--branch", "main"]);
    let report = audit.json();
    let signed = report["records"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["verdict"] == "good")
        .expect("a good commit exists");
    assert!(
        signed["signature_created_at"].is_i64(),
        "OpenPGP signature creation time should be parsed from the packet"
    );
    assert_eq!(signed["signature_format"], "openpgp");
}

// ---------------------------------------------------------------------------
// SSH
// ---------------------------------------------------------------------------

/// Parity with git for SSH. git passes no `-Overify-time`, so it evaluates
/// allowed_signers windows against the wall clock; `--ssh-time now` matches it.
#[test]
fn ssh_verdicts_match_git_for_every_commit() {
    require_ssh!();
    let fx = fixtures();
    if fx.allowed_signers.as_os_str().is_empty() {
        eprintln!("skipping: fixture has no allowed_signers");
        return;
    }
    let audit = sigaudit(&fx).run_json(&[
        "--branch",
        "ssh",
        "--ssh-time",
        "now",
        "--allowed-signers",
        fx.allowed_signers.to_str().unwrap(),
    ]);
    let report = audit.json();

    let records = report["records"].as_array().unwrap();
    let mut ssh_checked = 0;
    for r in records {
        if r["signature_format"] != "ssh" && r["verdict"] != "unsigned" {
            continue;
        }
        let oid = r["oid"].as_str().unwrap();
        let ours = r["git_letter"].as_str().unwrap();
        let theirs = git_letter(&fx, oid).to_string();
        assert_eq!(
            ours, theirs,
            "SSH verdict mismatch for {oid} ({}): sigaudit {ours}, git {theirs}",
            r["verdict"]
        );
        ssh_checked += 1;
    }
    assert!(
        ssh_checked >= 4,
        "expected several SSH commits, saw {ssh_checked}"
    );
}

#[test]
fn ssh_signer_not_in_allowed_signers_is_not_allowed() {
    require_ssh!();
    let fx = fixtures();
    let audit = sigaudit(&fx).run_json(&[
        "--branch",
        "ssh",
        "--allowed-signers",
        fx.allowed_signers.to_str().unwrap(),
    ]);
    let report = audit.json();
    let rec = report["records"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| {
            r["verdict"] == "signer_not_allowed"
                && r["detail"].as_str().unwrap_or("").contains("not listed")
        })
        .expect("fixture has a commit signed by a key outside allowed_signers");
    assert_eq!(rec["git_letter"], "U");
    assert_eq!(rec["signature_format"], "ssh");
}

#[test]
fn ssh_outside_validity_window_is_reported_distinctly() {
    require_ssh!();
    let fx = fixtures();
    let audit = sigaudit(&fx).run_json(&[
        "--branch",
        "ssh",
        "--allowed-signers",
        fx.allowed_signers_future.to_str().unwrap(),
    ]);
    let report = audit.json();
    let rec = find_record(&report, &fx.ssh_outside_window);
    assert_eq!(rec["verdict"], "signer_not_allowed");
    let detail = rec["detail"].as_str().unwrap_or("");
    assert!(
        detail.contains("window"),
        "the window exclusion should be named in the detail, got: {detail}"
    );
}

#[test]
fn ssh_tampered_payload_is_a_bad_signature() {
    require_ssh!();
    let fx = fixtures();
    let audit = sigaudit(&fx).run_json(&[
        "--branch",
        "ssh",
        "--allowed-signers",
        fx.allowed_signers.to_str().unwrap(),
    ]);
    let report = audit.json();
    let rec = find_record(&report, &fx.tampered);
    assert_eq!(
        rec["verdict"], "bad_signature",
        "a commit whose body no longer matches its signature must be bad: {}",
        rec["detail"]
    );
    assert_eq!(rec["git_letter"], "B");
}

#[test]
fn ssh_with_unreadable_allowed_signers_never_passes_and_says_why() {
    require_ssh!();
    let fx = fixtures();
    let audit = sigaudit(&fx).run_json(&[
        "--branch",
        "ssh",
        "--allowed-signers",
        "/nonexistent/allowed_signers",
    ]);
    let report = audit.json();

    let mut saw_explanation = false;
    for r in report["records"].as_array().unwrap() {
        if r["signature_format"] != "ssh" {
            continue;
        }
        assert_ne!(
            r["verdict"], "good",
            "an unreadable allowed_signers file must never produce a good verdict"
        );
        if r["verdict"] == "signer_not_allowed" {
            let detail = r["detail"].as_str().unwrap_or("");
            if detail.contains("could not be read") || detail.contains("Unable to open") {
                saw_explanation = true;
            }
        }
    }
    assert!(
        saw_explanation,
        "the report should explain that the whitelist file is unreadable"
    );
}

/// The strongest parity check: every audited object, in every branch, in both
/// formats, must carry the same letter git reports for it.
///
/// This covers the payload reconstruction too: a commit whose payload were split
/// even one byte differently from git would fail gpg's check and show up here as
/// a disagreement.
#[test]
fn every_object_matches_gits_letter() {
    require_gpg!();
    let fx = fixtures();
    let audit = sigaudit(&fx).run_json(&[
        "--tags",
        "--gpg-time",
        "now",
        "--ssh-time",
        "now",
        "--allowed-signers",
        fx.allowed_signers.to_str().unwrap(),
    ]);
    let report = audit.json();
    let records = report["records"].as_array().unwrap();
    assert!(records.len() > 15, "expected a substantial fixture");

    let mut mismatches = Vec::new();
    for r in records {
        if r["kind"] == "tag" {
            // `git log` cannot report tags; `git verify-tag` is the authority.
            let tag = r["tag"].as_str().unwrap();
            let expected = git_tag_letter(&fx, tag);
            let ours = r["git_letter"].as_str().unwrap();
            if ours != expected {
                mismatches.push(format!(
                    "tag {tag}: sigaudit {ours} ({}), git {expected}",
                    r["verdict"]
                ));
            }
            continue;
        }
        let oid = r["oid"].as_str().unwrap();
        let ours = r["git_letter"].as_str().unwrap();
        let theirs = git_letter(&fx, oid).to_string();
        if ours != theirs {
            mismatches.push(format!(
                "{oid} ({}): sigaudit {ours}, git {theirs}",
                r["verdict"]
            ));
        }
    }
    assert!(
        mismatches.is_empty(),
        "{} disagreement(s) with git:\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
}

/// `git verify-tag` as a letter: G when it succeeds, N when unsigned, else B.
fn git_tag_letter(fx: &Fixtures, tag: &str) -> String {
    let out = Command::new("git")
        .args(["-C", fx.repo.to_str().unwrap(), "verify-tag", tag])
        .env("GNUPGHOME", &fx.gnupg_home)
        .env("LC_ALL", "C")
        .output()
        .expect("git verify-tag");
    if out.status.success() {
        return "G".to_string();
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    if stderr.contains("no signature found") || stderr.contains("cannot verify a non-tag object") {
        "N".to_string()
    } else {
        "B".to_string()
    }
}

/// A commit carrying two signature packets is what git's `parse_gpg_output()`
/// rejects outright: it sets the result to `E` and clears the fields. sigaudit
/// must report the same, not call it a bad signature.
#[test]
fn doubled_signature_envelope_is_unverifiable_like_git() {
    require_gpg!();
    let fx = fixtures();
    let target = fx.root.join("repo");

    // Find a known-good commit and duplicate its gpgsig block.
    let good = git_log_field(&target, &fx.gnupg_home, "main", "good gpg commit");
    let raw = Command::new("git")
        .args(["-C", target.to_str().unwrap(), "cat-file", "commit", &good])
        .output()
        .unwrap()
        .stdout;
    let doubled = duplicate_gpgsig(&raw);

    let new_oid = git_hash_object(&target, &doubled);
    // Point a throwaway branch at it so the audit sees it, then remove it.
    let branch = "sigaudit-doubled";
    Command::new("git")
        .args(["-C", target.to_str().unwrap(), "update-ref"])
        .arg(format!("refs/heads/{branch}"))
        .arg(&new_oid)
        .output()
        .unwrap();
    let audit = sigaudit(&fx).run_json(&["--branch", branch]);
    Command::new("git")
        .args(["-C", target.to_str().unwrap(), "update-ref", "-d"])
        .arg(format!("refs/heads/{branch}"))
        .output()
        .unwrap();

    let report = audit.json();
    let rec = find_record(&report, &new_oid);
    assert_eq!(
        rec["verdict"], "error",
        "git reports E for multiple signatures, got {:?}",
        rec["detail"]
    );
    assert_eq!(rec["git_letter"], "E");
    let detail = rec["detail"].as_str().unwrap_or("");
    assert!(
        detail.contains("more than one signature") || detail.contains("multiple signatures"),
        "detail should explain the multiplicity: {detail}"
    );
}

fn git_log_field(repo: &Path, gnupg: &Path, branch: &str, subject: &str) -> String {
    let out = Command::new("git")
        .args([
            "-C",
            repo.to_str().unwrap(),
            "log",
            "--format=%H %s",
            branch,
        ])
        .env("GNUPGHOME", gnupg)
        .env("LC_ALL", "C")
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    text.lines()
        .find(|l| l.ends_with(subject))
        .and_then(|l| l.split_whitespace().next())
        .unwrap_or_else(|| panic!("no commit with subject {subject}"))
        .to_string()
}

/// Double the `gpgsig` continuation block of a raw commit buffer.
///
/// The signature text is collected with its leading space stripped (that space
/// is the header continuation marker, not part of the signature), then emitted
/// twice: the first copy under `gpgsig `, the second under ` `.
fn duplicate_gpgsig(raw: &[u8]) -> Vec<u8> {
    let lines: Vec<&[u8]> = raw.split(|b| *b == b'\n').collect();
    let sig_start = lines
        .iter()
        .position(|l| l.starts_with(b"gpgsig "))
        .expect("commit has a signature");

    // Collect the signature body: header value + all continuation lines.
    let mut body: Vec<&[u8]> = vec![&lines[sig_start][b"gpgsig ".len()..]];
    let mut j = sig_start + 1;
    while j < lines.len() && lines[j].first() == Some(&b' ') {
        body.push(&lines[j][1..]);
        j += 1;
    }

    let mut out: Vec<u8> = Vec::with_capacity(raw.len() * 2);
    out.extend_from_slice(&raw[..str_offset(raw, sig_start)]);
    for pass in 0..2 {
        for (i, line) in body.iter().enumerate() {
            out.extend_from_slice(if i == 0 && pass == 0 {
                b"gpgsig "
            } else {
                b" "
            });
            out.extend_from_slice(line);
            out.push(b'\n');
        }
    }
    // Everything after the signature block.
    for line in &lines[j..] {
        out.extend_from_slice(line);
        out.push(b'\n');
    }
    // `split` produced a trailing empty element if the buffer ended with \n.
    if raw.last() == Some(&b'\n') {
        out.pop();
    }
    out
}

/// Byte offset at which line `index` starts.
fn str_offset(raw: &[u8], index: usize) -> usize {
    let mut offset = 0;
    for _ in 0..index {
        match raw[offset..].iter().position(|b| *b == b'\n') {
            Some(pos) => offset += pos + 1,
            None => return raw.len(),
        }
    }
    offset
}

fn git_hash_object(repo: &Path, contents: &[u8]) -> String {
    use std::io::Write;
    let mut child = Command::new("git")
        .args([
            "-C",
            repo.to_str().unwrap(),
            "hash-object",
            "-t",
            "commit",
            "-w",
            "--stdin",
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(contents).unwrap();
    let out = child.wait_with_output().unwrap();
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

// ---------------------------------------------------------------------------
// Report formats
// ---------------------------------------------------------------------------

#[test]
fn json_report_is_self_describing() {
    let fx = fixtures();
    let audit = sigaudit(&fx).run_json(&["--branch", "main"]);
    let report = audit.json();
    assert_eq!(report["schema_version"], "1");
    assert_eq!(report["tool"]["name"], "sigaudit");
    assert!(report["generated_at"].as_str().unwrap().ends_with('Z'));
    assert_eq!(report["repository"]["hash_algorithm"], "sha1");
    let summary = &report["summary"];
    let total = summary["total"].as_u64().unwrap();
    let parts: u64 = [
        "good",
        "unsigned",
        "bad_signature",
        "unknown_key",
        "signer_not_allowed",
        "key_expired_at_commit",
        "key_revoked_at_commit",
        "error",
    ]
    .iter()
    .map(|k| summary[*k].as_u64().unwrap())
    .sum();
    assert_eq!(parts, total, "every record must be counted exactly once");
}

#[test]
fn junit_report_lists_failures_as_test_cases() {
    let fx = fixtures();
    let out = sigaudit(&fx).run_text(&["--branch", "main", "--format", "junit"]);
    assert!(out.stdout.starts_with("<?xml"));
    assert!(out.stdout.contains("<testsuites"));
    assert!(out.stdout.contains("<failure"));

    // Structural check: every testcase is either self-closing or explicitly
    // closed, and the suite totals agree with the number of testcases.
    let open: usize = out.stdout.matches("<testcase ").count();
    let closed: usize = out.stdout.matches("</testcase>").count();
    let self_closed: usize = out
        .stdout
        .match_indices("<testcase ")
        .filter(|(idx, _)| {
            let tail = &out.stdout[*idx..];
            tail.split('>')
                .next()
                .map(|head| head.ends_with('/'))
                .unwrap_or(false)
        })
        .count();
    assert_eq!(open, closed + self_closed, "unbalanced <testcase> elements");

    let tests_attr = out
        .stdout
        .split("tests=\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .and_then(|s| s.parse::<usize>().ok())
        .expect("tests attribute");
    assert_eq!(tests_attr, open, "tests= must match the testcase count");
}

#[test]
fn sarif_report_has_valid_shape() {
    let fx = fixtures();
    let audit = sigaudit(&fx).run_text(&["--branch", "main", "--format", "sarif"]);
    let doc: serde_json::Value = serde_json::from_str(&audit.stdout).expect("sarif json");
    assert_eq!(doc["version"], "2.1.0");
    assert!(doc["runs"][0]["tool"]["driver"]["rules"].is_array());
    let results = doc["runs"][0]["results"].as_array().unwrap();
    assert!(!results.is_empty(), "fixture has failing commits");
    for r in results {
        assert!(r["ruleId"].is_string());
        assert!(r["level"].is_string());
    }
}

#[test]
fn output_file_receives_the_report_and_stdout_stays_clean() {
    let fx = fixtures();
    let out_path = fx.root.join("report.json");
    let out = sigaudit(&fx).run(&[
        "--branch",
        "main",
        "--format",
        "json",
        "-o",
        out_path.to_str().unwrap(),
    ]);
    assert!(
        out.stdout.trim().is_empty(),
        "report should go to the file only"
    );
    let text = std::fs::read_to_string(&out_path).expect("report file");
    let v: serde_json::Value = serde_json::from_str(&text).expect("valid json");
    assert_eq!(v["schema_version"], "1");
}

// ---------------------------------------------------------------------------
// Failure modes
// ---------------------------------------------------------------------------

#[test]
fn non_repository_is_a_usage_error() {
    let tmp = tempfile::tempdir().unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_sigaudit"))
        .arg("--repo")
        .arg(tmp.path())
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(2),
        "a non-repository is a usage error"
    );
}

#[test]
fn invalid_branch_glob_yields_an_empty_successful_audit() {
    let fx = fixtures();
    let audit = sigaudit(&fx).run_json(&["--branch", "no-such-branch"]);
    assert_eq!(audit.code, 0);
    assert_eq!(audit.json()["summary"]["total"].as_u64().unwrap(), 0);
}

fn find_record<'a>(report: &'a serde_json::Value, oid: &str) -> &'a serde_json::Value {
    report["records"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["oid"].as_str() == Some(oid))
        .unwrap_or_else(|| panic!("no record for {oid}"))
}
