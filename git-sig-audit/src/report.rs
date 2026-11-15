//! CI-friendly reporting: JSON for machines, compact text for humans.

use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Serialize)]
pub struct SigReport {
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_expires: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_revoked_at: Option<i64>,
}

#[derive(Serialize)]
pub struct CommitReport {
    pub oid: String,
    pub subject: String,
    pub author: String,
    pub committer: String,
    pub commit_time: i64,
    pub merge: bool,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<SigReport>,
}

#[derive(Serialize)]
pub struct BranchReport {
    pub tip: String,
    pub counts: BTreeMap<String, usize>,
    pub commits: Vec<CommitReport>,
}

#[derive(Serialize)]
pub struct Report {
    pub tool: String,
    pub repo: String,
    pub generated_at: String,
    pub total_unique_commits: usize,
    /// status -> count over unique commits (a commit on several branches counts once).
    pub summary: BTreeMap<String, usize>,
    pub branches: BTreeMap<String, BranchReport>,
    /// statuses that trigger a non-zero exit code.
    pub fail_on: Vec<String>,
    pub passed: bool,
}

#[derive(Clone, Debug, clap::ValueEnum)]
pub enum Format {
    Text,
    Json,
}

pub fn render_text(report: &Report) -> String {
    let mut out = String::new();
    out.push_str(&format!("commit signature audit — {}\n", report.repo));
    out.push_str(&format!(
        "{} unique commits across {} refs\n\n",
        report.total_unique_commits,
        report.branches.len()
    ));

    for (name, br) in &report.branches {
        out.push_str(&format!("== {name} ({})\n", &br.tip[..br.tip.len().min(12)]));
        let counts: Vec<String> = br
            .counts
            .iter()
            .map(|(k, v)| format!("{k}: {v}"))
            .collect();
        out.push_str(&format!("   {}\n", counts.join("  ")));
        for c in &br.commits {
            if c.status == "valid" {
                continue;
            }
            let merge = if c.merge { " [merge]" } else { "" };
            out.push_str(&format!(
                "   {:<18} {} {}{}\n",
                c.status,
                &c.oid[..12],
                c.subject,
                merge
            ));
            if let Some(sig) = &c.signature {
                if let Some(d) = &sig.detail {
                    out.push_str(&format!("       {}\n", d));
                }
            }
        }
        out.push('\n');
    }

    let summary: Vec<String> = report
        .summary
        .iter()
        .map(|(k, v)| format!("{k}: {v}"))
        .collect();
    out.push_str(&format!("summary: {}\n", summary.join("  ")));
    out.push_str(if report.passed {
        "result: PASS\n"
    } else {
        "result: FAIL\n"
    });
    out
}
