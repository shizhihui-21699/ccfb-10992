//! Report rendering: human summary, JSON, JUnit XML and SARIF.
//!
//! CI integration is the point of these formats:
//!
//! * **JSON** is the canonical machine format, with a stable schema version.
//! * **JUnit XML** is understood by GitLab, Jenkins, Buildkite and GitHub
//!   Actions reporters: one test case per failing commit.
//! * **SARIF** is what GitHub code scanning ingests, so findings annotate lines
//!   in the security tab.
//!
//! All formats are written to stdout (or a file) and are pure functions of the
//! `Report`, which keeps them easy to snapshot-test.

use std::fmt::Write as _;

use crate::model::{AuditRecord, Report, Summary, Verdict};

pub const SCHEMA_VERSION: &str = "1";
pub const SARIF_SCHEMA: &str =
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Human,
    Json,
    Junit,
    Sarif,
}

impl Format {
    pub fn parse(value: &str) -> Option<Format> {
        match value.to_ascii_lowercase().as_str() {
            "human" | "text" => Some(Format::Human),
            "json" => Some(Format::Json),
            "junit" | "junit-xml" => Some(Format::Junit),
            "sarif" => Some(Format::Sarif),
            _ => None,
        }
    }
}

pub fn render(report: &Report, format: Format, quiet: bool) -> String {
    match format {
        Format::Human => render_human(report, quiet),
        Format::Json => render_json(report),
        Format::Junit => render_junit(report),
        Format::Sarif => render_sarif(report),
    }
}

// ---------------------------------------------------------------------------
// Human
// ---------------------------------------------------------------------------

pub fn render_human(report: &Report, quiet: bool) -> String {
    let mut out = String::new();
    let s = &report.summary;
    let _ = writeln!(
        out,
        "sigaudit {} — signature audit of {}",
        report.tool.version, report.repository.path
    );
    if let Some(wd) = &report.repository.workdir {
        let _ = writeln!(out, "worktree: {wd}");
    }
    let _ = writeln!(
        out,
        "object format: {}   shallow: {}{}",
        report.repository.hash_algorithm,
        report.repository.shallow,
        if report.repository.incomplete_history > 0 {
            format!(
                "   incomplete history: {} commit(s) missing parents",
                report.repository.incomplete_history
            )
        } else {
            String::new()
        }
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "Branches ({}):", report.branches.len());
    for b in &report.branches {
        let _ = writeln!(
            out,
            "  {:<28} {:>6} commits   {} failing   tip {}",
            b.name,
            b.commits,
            b.summary.failures,
            short_oid(&b.tip)
        );
    }
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "Totals: {} object(s) audited, {} good, {} failing",
        s.total, s.good, s.failures
    );
    let _ = writeln!(out, "  {}", summary_line(s));

    if !quiet {
        let failures: Vec<&AuditRecord> = report
            .records
            .iter()
            .filter(|r| r.verdict.is_failure())
            .collect();
        if !failures.is_empty() {
            let _ = writeln!(out);
            let _ = writeln!(out, "Failures:");
            for r in failures {
                let _ = writeln!(
                    out,
                    "  {} [{}] {} {}",
                    short_oid(&r.oid),
                    r.git_letter,
                    r.verdict,
                    location(r)
                );
                if let Some(detail) = &r.detail {
                    let _ = writeln!(out, "       {detail}");
                }
            }
        }
    }

    if !report.warnings.is_empty() {
        let _ = writeln!(out);
        let _ = writeln!(out, "Warnings:");
        for w in &report.warnings {
            let _ = writeln!(out, "  - {w}");
        }
    }
    out
}

/// One line of non-zero counters, leading with the headline numbers.
fn summary_line(s: &Summary) -> String {
    let mut parts = vec![format!("good={}", s.good)];
    if s.failures > 0 {
        parts.push(format!("failures={}", s.failures));
    }
    let counters = [
        ("unsigned", s.unsigned),
        ("bad_signature", s.bad_signature),
        ("unknown_key", s.unknown_key),
        ("signer_not_allowed", s.signer_not_allowed),
        ("key_expired_at_commit", s.key_expired_at_commit),
        ("key_revoked_at_commit", s.key_revoked_at_commit),
        ("error", s.error),
    ];
    for (name, value) in counters {
        if value > 0 {
            parts.push(format!("{name}={value}"));
        }
    }
    parts.join(" ")
}

fn location(r: &AuditRecord) -> String {
    match r.kind {
        crate::model::ObjectKind::Commit => {
            if r.is_merge {
                format!(
                    "merge ({}) by {}",
                    r.signed_at_utc,
                    short_ident(&r.committer)
                )
            } else {
                format!("{} by {}", r.signed_at_utc, short_ident(&r.committer))
            }
        }
        crate::model::ObjectKind::Tag => format!(
            "tag {} ({})",
            r.tag.as_deref().unwrap_or("?"),
            r.signed_at_utc
        ),
    }
}

fn short_ident(ident: &Option<String>) -> String {
    ident
        .as_deref()
        .and_then(crate::ident::Ident::parse)
        .map(|i| format!("{} <{}>", i.name, i.email))
        .unwrap_or_else(|| "(unknown committer)".to_string())
}

pub fn short_oid(oid: &str) -> &str {
    if oid.len() > 12 {
        &oid[..12]
    } else {
        oid
    }
}

// ---------------------------------------------------------------------------
// JSON
// ---------------------------------------------------------------------------

pub fn render_json(report: &Report) -> String {
    // A tiny wrapper keeps a schema version next to the payload without making
    // the model carry it.
    #[derive(serde::Serialize)]
    struct Envelope<'a> {
        schema_version: &'a str,
        #[serde(flatten)]
        report: &'a Report,
    }
    let env = Envelope {
        schema_version: SCHEMA_VERSION,
        report,
    };
    serde_json::to_string_pretty(&env).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
}

// ---------------------------------------------------------------------------
// JUnit
// ---------------------------------------------------------------------------

pub fn render_junit(report: &Report) -> String {
    let s = &report.summary;
    let mut out = String::new();
    let _ = writeln!(out, r#"<?xml version="1.0" encoding="UTF-8"?>"#);
    let _ = writeln!(
        out,
        r#"<testsuites name="sigaudit" tests="{}" failures="{}" errors="{}">"#,
        s.total, s.failures, s.error
    );
    let _ = writeln!(
        out,
        r#"  <testsuite name="commit-signatures" tests="{}" failures="{}" errors="{}">"#,
        s.total, s.failures, s.error
    );

    for r in &report.records {
        let name = format!("{} {} {}", r.git_letter, short_oid(&r.oid), r.verdict);
        let classname = match r.kind {
            crate::model::ObjectKind::Commit => "sigaudit.commit",
            crate::model::ObjectKind::Tag => "sigaudit.tag",
        };
        if r.verdict.is_failure() {
            let message = r.detail.clone().unwrap_or_else(|| r.verdict.to_string());
            let _ = writeln!(
                out,
                r#"    <testcase name="{}" classname="{}" time="0"><failure message="{}">{}</failure></testcase>"#,
                xml_escape(&name),
                classname,
                xml_escape(&message),
                xml_escape(&body(r))
            );
        } else {
            let _ = writeln!(
                out,
                r#"    <testcase name="{}" classname="{}" time="0"/>"#,
                xml_escape(&name),
                classname
            );
        }
    }

    let _ = writeln!(out, "  </testsuite>");
    let _ = writeln!(out, "</testsuites>");
    out
}

fn body(r: &AuditRecord) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "object: {} ({})", r.oid, kind_str(r));
    if let Some(tag) = &r.tag {
        let _ = writeln!(s, "tag: {tag}");
    }
    let _ = writeln!(s, "verdict: {} (%G? = {})", r.verdict, r.git_letter);
    let _ = writeln!(s, "time: {}", r.signed_at_utc);
    if let Some(c) = &r.committer {
        let _ = writeln!(s, "committer: {c}");
    }
    if !r.branches.is_empty() {
        let _ = writeln!(s, "branches: {}", r.branches.join(", "));
    }
    if let Some(f) = &r.signature_format {
        let _ = writeln!(s, "format: {f}");
    }
    if let Some(signer) = &r.signer {
        let _ = writeln!(s, "signer: {signer}");
    }
    if let Some(fpr) = &r.fingerprint {
        let _ = writeln!(s, "fingerprint: {fpr}");
    }
    s
}

fn kind_str(r: &AuditRecord) -> &'static str {
    match r.kind {
        crate::model::ObjectKind::Commit => "commit",
        crate::model::ObjectKind::Tag => "tag",
    }
}

pub fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            // XML 1.0 forbids most control characters outright.
            c if (c as u32) < 0x20 && c != '\t' && c != '\n' && c != '\r' => {
                out.push_str(&format!("&#x{:X};", c as u32))
            }
            c => out.push(c),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// SARIF
// ---------------------------------------------------------------------------

pub fn render_sarif(report: &Report) -> String {
    use serde_json::json;

    let mut rules = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for r in &report.records {
        if r.verdict == Verdict::Good || seen.contains(r.verdict.as_str()) {
            continue;
        }
        seen.insert(r.verdict.as_str().to_string());
        rules.push(json!({
            "id": r.verdict.as_str(),
            "name": rule_name(r.verdict),
            "shortDescription": { "text": rule_description(r.verdict) },
            "defaultConfiguration": { "level": rule_level(r.verdict) },
        }));
    }

    let results: Vec<serde_json::Value> = report
        .records
        .iter()
        .filter(|r| r.verdict.is_failure())
        .map(|r| {
            let mut message = format!("{} {} ({})", r.verdict, short_oid(&r.oid), r.signed_at_utc);
            if let Some(d) = &r.detail {
                let _ = write!(message, ": {d}");
            }
            json!({
                "ruleId": r.verdict.as_str(),
                "level": rule_level(r.verdict),
                "message": { "text": message },
                "properties": {
                    "oid": r.oid,
                    "gitResult": r.git_letter.to_string(),
                    "branches": r.branches,
                    "signer": r.signer,
                    "fingerprint": r.fingerprint,
                    "signatureFormat": r.signature_format,
                },
            })
        })
        .collect();

    let doc = json!({
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "sigaudit",
                    "version": report.tool.version,
                    "informationUri": "https://example.invalid/sigaudit",
                    "rules": rules,
                }
            },
            "results": results,
            "invocations": [{
                "executionSuccessful": true,
                "properties": { "repository": report.repository.path },
            }],
        }],
    });
    serde_json::to_string_pretty(&doc).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
}

fn rule_name(v: Verdict) -> &'static str {
    match v {
        Verdict::Unsigned => "UnsignedCommit",
        Verdict::BadSignature => "BadSignature",
        Verdict::UnknownKey => "UnknownSigningKey",
        Verdict::SignerNotAllowed => "SignerNotAllowed",
        Verdict::KeyExpiredAtCommit => "KeyExpiredAtCommit",
        Verdict::KeyRevokedAtCommit => "KeyRevokedAtCommit",
        Verdict::Error => "VerificationError",
        Verdict::Good => "Good",
    }
}

fn rule_description(v: Verdict) -> &'static str {
    match v {
        Verdict::Unsigned => "The object carries no signature.",
        Verdict::BadSignature => "The signature does not match the signed content.",
        Verdict::UnknownKey => "The signing key is not available to the verifier.",
        Verdict::SignerNotAllowed => {
            "The signature is cryptographically valid but the signer is not whitelisted."
        }
        Verdict::KeyExpiredAtCommit => "The signing key had expired at the commit's time.",
        Verdict::KeyRevokedAtCommit => "The signing key was revoked at the commit's time.",
        Verdict::Error => "The signature could not be checked.",
        Verdict::Good => "The signature is valid and the signer is allowed.",
    }
}

fn rule_level(v: Verdict) -> &'static str {
    match v {
        Verdict::Good => "none",
        Verdict::Unsigned | Verdict::SignerNotAllowed => "warning",
        _ => "error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::*;

    fn sample_report() -> Report {
        let mut summary = Summary::default();
        summary.record(Verdict::Good);
        summary.record(Verdict::Unsigned);
        let mut by_format = std::collections::BTreeMap::new();
        let mut f = Summary::default();
        f.record(Verdict::Good);
        by_format.insert("openpgp".to_string(), f);

        Report {
            tool: ToolInfo {
                name: "sigaudit".into(),
                version: "0.1.0".into(),
            },
            generated_at: "2024-01-01T00:00:00Z".into(),
            generated_at_unix: 1_704_067_200,
            repository: RepositoryInfo {
                path: "/repo/.git/".into(),
                workdir: Some("/repo".into()),
                hash_algorithm: "sha1".into(),
                shallow: false,
                incomplete_history: 0,
            },
            summary,
            branches: vec![BranchReport {
                name: "main".into(),
                tip: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
                commits: 2,
                summary: Summary::default(),
            }],
            records: vec![AuditRecord {
                kind: ObjectKind::Commit,
                oid: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
                tag: None,
                author: Some("A <a@example.com> 1700000000 +0000".into()),
                committer: Some("A <a@example.com> 1700000000 +0000".into()),
                signed_at: 1_700_000_000,
                signed_at_utc: "2023-11-14T22:13:20Z".into(),
                parents: 1,
                is_merge: false,
                branches: vec!["main".into()],
                signature_format: None,
                verdict: Verdict::Unsigned,
                git_letter: 'N',
                signer: None,
                fingerprint: None,
                signature_created_at: None,
                key_expires_at: None,
                detail: Some("commit has no gpgsig header <&>".into()),
            }],
            warnings: vec!["a warning".into()],
            by_format,
        }
    }

    #[test]
    fn human_report_mentions_each_failure() {
        let out = render_human(&sample_report(), false);
        assert!(out.contains("unsigned"));
        assert!(out.contains("commit has no gpgsig header"));
        assert!(out.contains("main"));
    }

    #[test]
    fn json_round_trips_with_schema_version() {
        let out = render_json(&sample_report());
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["schema_version"], "1");
        assert_eq!(v["summary"]["total"], 2);
        assert_eq!(v["records"][0]["git_letter"], "N");
    }

    #[test]
    fn junit_is_well_formed_and_counts_failures() {
        let out = render_junit(&sample_report());
        assert!(out.contains(r#"failures="1""#));
        assert!(out.contains("&lt;&amp;&gt;"), "detail must be XML-escaped");
        assert!(!out.contains("<&>"));
    }

    #[test]
    fn sarif_has_rule_and_result_for_failures() {
        let out = render_sarif(&sample_report());
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["version"], "2.1.0");
        let results = v["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0]["ruleId"], "unsigned");
    }

    #[test]
    fn xml_escaping_handles_quotes_and_control_chars() {
        assert_eq!(xml_escape("a\"b'c"), "a&quot;b&apos;c");
        assert_eq!(xml_escape("\u{1}"), "&#x1;");
        assert_eq!(xml_escape("tab\tok"), "tab\tok");
    }
}
