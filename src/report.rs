//! Report rendering: human-readable table, JSON, and CI-friendly outputs.

use crate::audit::{BranchReport, CommitVerdict, Totals};
use crate::repo::ObjectId;
use crate::types::Status;
use serde::Serialize;
use std::collections::BTreeMap;

/// Root of the JSON document.
#[derive(Debug, Serialize)]
pub struct Report {
    pub tool: &'static str,
    pub version: &'static str,
    /// Audit time, seconds since the epoch.
    pub audited_at: i64,
    pub repository: String,
    pub object_format: &'static str,
    pub totals: TotalsJson,
    pub branches: Vec<BranchJson>,
    /// Every non-valid commit, newest first, deduplicated across branches.
    pub violations: Vec<ViolationJson>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct TotalsJson {
    /// Commits audited, each counted once even if several branches reach it.
    pub commits: usize,
    pub merge_commits: usize,
    pub violating_commits: usize,
    /// Counts keyed by status, in a stable order.
    pub by_status: BTreeMap<&'static str, usize>,
}

#[derive(Debug, Serialize)]
pub struct BranchJson {
    pub name: String,
    pub ref_name: String,
    pub tip: String,
    pub is_remote: bool,
    pub commits: usize,
    /// Commits also reachable from another audited branch.
    pub shared_with_other_branches: usize,
    pub unsigned: usize,
    pub unsigned_excluding_merges: usize,
    pub valid_ratio: f64,
    pub by_status: BTreeMap<&'static str, usize>,
    /// Violating commits on this branch, newest first.
    pub violations: Vec<ViolationJson>,
}

#[derive(Debug, Serialize)]
pub struct ViolationJson {
    pub commit: String,
    pub short: String,
    pub status: &'static str,
    pub branches: Vec<String>,
    pub author: String,
    pub committer: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit_time: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit_time_iso: Option<String>,
    pub subject: String,
    pub is_merge: bool,
    pub parents: usize,
    #[serde(flatten)]
    pub signature: crate::types::SignatureInfo,
}

impl Report {
    pub fn build(
        repository: String,
        object_format: &'static str,
        reports: &[BranchReport],
        audited_at: i64,
        warnings: Vec<String>,
        dedupe: bool,
    ) -> Report {
        let totals = Totals::from_reports(reports, dedupe);

        // Gather violating commits across branches, keyed by commit id so a
        // commit on ten branches is reported once with all its branches.
        let mut by_commit: BTreeMap<ObjectId, (CommitVerdict, Vec<String>)> = BTreeMap::new();
        for r in reports {
            for v in r.violations() {
                let entry = by_commit
                    .entry(v.oid)
                    .or_insert_with(|| (v.clone(), Vec::new()));
                // The same ref can be selected twice (e.g. by name and by glob);
                // report each branch once.
                if !entry.1.contains(&r.branch.name) {
                    entry.1.push(r.branch.name.clone());
                }
            }
        }
        let mut all_violations: Vec<ViolationJson> = by_commit
            .into_values()
            .map(|(c, branches)| violation_json(&c, branches))
            .collect();
        // Newest first; commits without a timestamp go last.
        all_violations.sort_by(|a, b| {
            b.commit_time
                .unwrap_or(i64::MIN)
                .cmp(&a.commit_time.unwrap_or(i64::MIN))
                .then_with(|| a.short.cmp(&b.short))
        });

        let branches = reports
            .iter()
            .map(|r| {
                let counts = r.counts();
                let mut by_status = BTreeMap::new();
                for s in Status::ALL {
                    if let Some(n) = counts.get(&s) {
                        by_status.insert(s.as_str(), *n);
                    }
                }
                BranchJson {
                    name: r.branch.name.clone(),
                    ref_name: r.branch.full_name.clone(),
                    tip: r.branch.tip.to_string(),
                    is_remote: r.branch.is_remote,
                    commits: r.commits.len(),
                    shared_with_other_branches: r.shared,
                    unsigned: r.unsigned_count(true),
                    unsigned_excluding_merges: r.unsigned_count(false),
                    valid_ratio: r.valid_ratio(false),
                    by_status,
                    violations: r
                        .violations()
                        .map(|c| violation_json(c, vec![r.branch.name.clone()]))
                        .collect(),
                }
            })
            .collect();

        let mut by_status = BTreeMap::new();
        for s in Status::ALL {
            if let Some(n) = totals.by_status.get(&s) {
                by_status.insert(s.as_str(), *n);
            }
        }

        Report {
            tool: "commit-signature-audit",
            version: env!("CARGO_PKG_VERSION"),
            audited_at,
            repository,
            object_format,
            totals: TotalsJson {
                commits: totals.commits,
                merge_commits: totals.merge_commits,
                violating_commits: totals.violations(),
                by_status,
            },
            branches,
            violations: all_violations,
            warnings,
        }
    }

    /// Number of violating commits across the audited history.
    pub fn violation_count(&self) -> usize {
        self.totals.violating_commits
    }
}

fn violation_json(c: &CommitVerdict, branches: Vec<String>) -> ViolationJson {
    ViolationJson {
        commit: c.oid.to_string(),
        short: c.short.clone(),
        status: c.outcome.status.as_str(),
        branches,
        author: c.author.clone(),
        committer: c.committer.clone(),
        commit_time: c.commit_time,
        commit_time_iso: c.commit_time.map(iso_time),
        subject: c.subject.clone(),
        is_merge: c.is_merge,
        parents: c.parents,
        signature: c.outcome.info.clone(),
    }
}

fn iso_time(ts: i64) -> String {
    match chrono::DateTime::from_timestamp(ts, 0) {
        Some(dt) => dt.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        None => ts.to_string(),
    }
}

/// Renders the human-readable report.
pub struct TableOptions {
    /// List every violating commit rather than only counting them.
    pub list: bool,
    pub max_listed: usize,
    /// Include merge commits in the unsigned ratio.
    pub include_merges: bool,
}

pub fn render_table(report: &Report, opts: &TableOptions) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "Commit signature audit — {}\n",
        report.repository
    ));
    out.push_str(&format!(
        "{} commits audited ({} merges), {} violating\n\n",
        report.totals.commits, report.totals.merge_commits, report.totals.violating_commits
    ));

    out.push_str(&format!("{:<28} {:>8} {:>10} {:>9} {:>8}\n", "BRANCH", "COMMITS", "UNSIGNED", "INVALID*", "VALID%"));
    out.push_str(&format!("{}\n", "-".repeat(68)));
    for b in &report.branches {
        let invalid = b
            .by_status
            .iter()
            .filter(|(k, _)| !matches!(**k, "valid" | "unsigned"))
            .map(|(_, v)| *v)
            .sum::<usize>();
        let unsigned = if opts.include_merges {
            b.unsigned
        } else {
            b.unsigned_excluding_merges
        };
        out.push_str(&format!(
            "{:<28} {:>8} {:>10} {:>9} {:>7.1}%\n",
            truncate(&b.name, 28),
            b.commits,
            unsigned,
            invalid,
            b.valid_ratio * 100.0
        ));
    }
    out.push_str("\n* commits with a signature that is invalid or not from an allowed signer.");

    if !report.totals.by_status.is_empty() {
        out.push_str("\n\nBy status:\n");
        let width = report
            .totals
            .by_status
            .keys()
            .map(|k| k.len())
            .max()
            .unwrap_or(0);
        for (status, n) in &report.totals.by_status {
            out.push_str(&format!("  {status:<width$}  {n}\n", width = width));
        }
    }

    if opts.list && !report.violations.is_empty() {
        out.push_str("\nViolating commits (newest first):\n");
        for v in report.violations.iter().take(opts.max_listed) {
            out.push_str(&format!(
                "  {} [{}] {}\n",
                v.short,
                v.status,
                truncate(&v.subject, 60)
            ));
            if let Some(detail) = &v.signature.detail {
                out.push_str(&format!("      {detail}\n"));
            }
            if v.branches.len() > 1 {
                out.push_str(&format!("      branches: {}\n", v.branches.join(", ")));
            }
        }
        if report.violations.len() > opts.max_listed {
            out.push_str(&format!(
                "  ... and {} more\n",
                report.violations.len() - opts.max_listed
            ));
        }
    }

    if !report.warnings.is_empty() {
        out.push_str("\nWarnings:\n");
        for w in &report.warnings {
            out.push_str(&format!("  - {w}\n"));
        }
    }
    out
}

/// Renders one line per violation, for CI logs.
pub fn render_lines(report: &Report) -> String {
    let mut out = String::new();
    for v in &report.violations {
        out.push_str(&format!(
            "{} {} {} \"{}\"",
            v.short, v.status, v.branches.join(","), v.subject
        ));
        if let Some(d) = &v.signature.detail {
            out.push_str(&format!(" ({d})"));
        }
        out.push('\n');
    }
    out
}

/// Renders a JUnit XML report so CI systems can show per-branch failures.
pub fn render_junit(report: &Report) -> String {
    let mut out = String::new();
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    out.push_str(&format!(
        "<testsuites name=\"commit-signature-audit\" tests=\"{}\" failures=\"{}\">\n",
        report.branches.len(),
        report
            .branches
            .iter()
            .filter(|b| !b.violations.is_empty())
            .count()
    ));
    out.push_str(&format!(
        "  <testsuite name=\"{}\" tests=\"{}\" failures=\"{}\">\n",
        xml_escape(&report.repository),
        report.branches.len(),
        report
            .branches
            .iter()
            .filter(|b| !b.violations.is_empty())
            .count()
    ));
    for b in &report.branches {
        if b.violations.is_empty() {
            out.push_str(&format!(
                "    <testcase name=\"{}\" classname=\"commit-signature-audit\"/>\n",
                xml_escape(&b.name)
            ));
            continue;
        }
        out.push_str(&format!(
            "    <testcase name=\"{}\" classname=\"commit-signature-audit\">\n",
            xml_escape(&b.name)
        ));
        for v in &b.violations {
            out.push_str(&format!(
                "      <failure message=\"{}\">{}</failure>\n",
                xml_escape(&format!("{} {} {}", v.short, v.status, v.subject)),
                xml_escape(
                    &v.signature
                        .detail
                        .clone()
                        .unwrap_or_else(|| v.status.to_string())
                )
            ));
        }
        out.push_str("    </testcase>\n");
    }
    out.push_str("  </testsuite>\n</testsuites>\n");
    out
}

/// Renders `annotations` for GitHub Actions, one per violation.
pub fn render_github(report: &Report) -> String {
    let mut out = String::new();
    for v in &report.violations {
        let msg = format!(
            "commit {} ({}) is {}: {}{}",
            v.short,
            v.branches.join(","),
            v.status,
            v.subject,
            v.signature
                .detail
                .as_deref()
                .map(|d| format!(" — {d}"))
                .unwrap_or_default()
        );
        out.push_str(&format!(
            "::error title=Unsigned or invalid commit::{}\n",
            escape_github(&msg)
        ));
    }
    out
}

fn escape_github(s: &str) -> String {
    s.replace('%', "%25")
        .replace('\r', "%0D")
        .replace('\n', "%0A")
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::BranchReport;
    use crate::repo::BranchRef;
    use crate::types::{Outcome, SignatureInfo, Status};
    
    fn oid(n: u8) -> ObjectId {
        let mut bytes = [0u8; 20];
        bytes[19] = n;
        ObjectId::Sha1(bytes)
    }

    fn verdict(n: u8, status: Status, merge: bool, subject: &str) -> CommitVerdict {
        CommitVerdict {
            oid: oid(n),
            short: format!("{n:08}"),
            author: "A <a@example.com> 1704067200 +0000".into(),
            committer: "C <c@example.com> 1704067200 +0000".into(),
            commit_time: Some(1704067200),
            subject: subject.into(),
            is_merge: merge,
            parents: if merge { 2 } else { 1 },
            outcome: Outcome {
                status,
                info: SignatureInfo::default(),
            },
        }
    }

    fn branch(name: &str, commits: Vec<CommitVerdict>) -> BranchReport {
        BranchReport {
            branch: BranchRef {
                name: name.into(),
                full_name: format!("refs/heads/{name}"),
                tip: oid(1),
                is_remote: false,
            },
            commits,
            shared: 0,
        }
    }

    fn sample() -> Report {
        let reports = vec![
            branch(
                "main",
                vec![
                    verdict(3, Status::Unsigned, false, "third"),
                    verdict(2, Status::Valid, false, "second"),
                    verdict(1, Status::Invalid, true, "merge"),
                ],
            ),
            branch(
                "feature",
                vec![
                    verdict(2, Status::Valid, false, "second"),
                    verdict(4, Status::UnknownSigner, false, "fourth"),
                ],
            ),
        ];
        Report::build(
            "repo".into(),
            "sha1",
            &reports,
            1704240000,
            vec![],
            true,
        )
    }

    #[test]
    fn totals_dedupe_across_branches() {
        let r = sample();
        // unique commits: 1,2,3,4
        assert_eq!(r.totals.commits, 4);
        assert_eq!(r.totals.violating_commits, 3); // unsigned, invalid, unknown_signer
    }

    #[test]
    fn violations_are_merged_per_commit() {
        let r = sample();
        assert_eq!(r.violations.len(), 3);
    }

    #[test]
    fn table_mentions_each_branch() {
        let r = sample();
        let out = render_table(
            &r,
            &TableOptions {
                list: true,
                max_listed: 10,
                include_merges: true,
            },
        );
        assert!(out.contains("main"));
        assert!(out.contains("feature"));
        assert!(out.contains("Violating commits"));
    }

    #[test]
    fn junit_is_well_formed_enough() {
        let r = sample();
        let xml = render_junit(&r);
        assert!(xml.starts_with("<?xml"));
        assert!(xml.contains("<testsuites"));
        assert!(xml.ends_with("</testsuites>\n"));
        assert!(xml.contains("failures=\"2\""));
    }

    #[test]
    fn github_annotations_escape_newlines() {
        let mut r = sample();
        r.violations[0].signature.detail = Some("line1\nline2".into());
        let out = render_github(&r);
        assert!(out.contains("::error title=Unsigned or invalid commit::"));
        assert!(!out.contains('\n') || out.trim_end().lines().all(|l| l.starts_with("::error")));
    }

    #[test]
    fn valid_ratio_ignores_merges() {
        let b = branch(
            "m",
            vec![
                verdict(1, Status::Valid, false, "a"),
                verdict(2, Status::Unsigned, false, "b"),
                verdict(3, Status::Unsigned, true, "merge"),
            ],
        );
        // 1 of 2 non-merge commits valid.
        assert!((b.valid_ratio(false) - 0.5).abs() < f64::EPSILON);
        assert!((b.valid_ratio(true) - 1.0 / 3.0).abs() < 1e-9);
        assert_eq!(b.unsigned_count(false), 1);
        assert_eq!(b.unsigned_count(true), 2);
    }

    #[test]
    fn json_serializes_status_names() {
        let r = sample();
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("\"unknown_signer\""));
        assert!(json.contains("\"by_status\""));
    }
}
