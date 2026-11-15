//! Shared helpers for the integration tests: building the fixture repository
//! once, caching it, and invoking the binary.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::sync::OnceLock;

/// Paths and identifiers produced by `scripts/make_fixtures.sh`, read back from
/// the manifest it writes.
#[derive(Debug, Clone)]
pub struct Fixtures {
    pub root: PathBuf,
    pub repo: PathBuf,
    pub gnupg_home: PathBuf,
    pub allowed_signers: PathBuf,
    pub allowed_signers_future: PathBuf,
    pub good_fpr: String,
    pub expired_fpr: String,
    pub later_fpr: String,
    pub revoked_fpr: String,
    pub expired_at_commit: String,
    pub expired_since: String,
    pub revoked_after: String,
    pub ssh_outside_window: String,
    pub tampered: String,
    pub pre_rebase_two: String,
    pub t0: i64,
}

pub struct RunResult {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl RunResult {
    /// True when the audit ran and found nothing to fail on.
    pub fn passed(&self) -> bool {
        self.code == 0
    }
}

impl RunResult {
    pub fn json(&self) -> serde_json::Value {
        serde_json::from_str(&self.stdout).unwrap_or_else(|e| {
            panic!(
                "report is not valid JSON ({e})\nstdout:\n{}\nstderr:\n{}",
                self.stdout, self.stderr
            )
        })
    }
}

/// Invokes the built binary with the fixture repository and keyring wired up.
pub struct Sigaudit {
    fixtures: Fixtures,
}

impl Sigaudit {
    pub fn new(fx: &Fixtures) -> Self {
        Sigaudit {
            fixtures: fx.clone(),
        }
    }

    pub fn run(&self, args: &[&str]) -> RunResult {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_sigaudit"));
        cmd.arg("--repo").arg(&self.fixtures.repo);
        cmd.args(args);
        cmd.env("GNUPGHOME", &self.fixtures.gnupg_home);
        // Keep gpg's diagnostics in a stable language so output assertions do
        // not depend on the developer's locale.
        cmd.env("LC_ALL", "C");
        cmd.env("LANG", "C");
        let out = cmd.output().expect("could not run sigaudit");
        RunResult {
            code: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        }
    }

    /// Run with `--format json`, tolerating exit code 1 (audit failures are a
    /// successful *run* with a failing verdict set).
    pub fn run_json(&self, args: &[&str]) -> RunResult {
        let mut full: Vec<&str> = args.to_vec();
        full.extend(["--format", "json"]);
        let r = self.run(&full);
        assert!(
            r.code == 0 || r.code == 1,
            "sigaudit crashed (exit {}) running {args:?}\nstderr:\n{}",
            r.code,
            r.stderr
        );
        r
    }

    pub fn run_text(&self, args: &[&str]) -> RunResult {
        let r = self.run(args);
        assert!(
            r.code == 0 || r.code == 1,
            "sigaudit crashed (exit {}) running {args:?}\nstderr:\n{}",
            r.code,
            r.stderr
        );
        r
    }
}

static CACHE: Mutex<Option<Fixtures>> = Mutex::new(None);
static BUILD_LOCK: OnceLock<()> = OnceLock::new();

/// Build the fixture repository once per test binary, caching it under
/// `target/test-fixtures` so repeated runs do not pay gpg's key-generation cost.
pub fn build_once() {
    BUILD_LOCK.get_or_init(|| {
        let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let dest = manifest_dir.join("target").join("test-fixtures");

        // Reuse an existing build when it is newer than the generator script.
        let script = manifest_dir.join("scripts").join("make_fixtures.sh");
        let env_file = dest.join("fixtures.env");
        let fresh = env_file.exists()
            && std::fs::metadata(&env_file)
                .and_then(|m| m.modified())
                .ok()
                .zip(std::fs::metadata(&script).and_then(|m| m.modified()).ok())
                .map(|(fixtures, script)| fixtures >= script)
                .unwrap_or(false);

        if !fresh {
            let status = Command::new("bash")
                .arg(&script)
                .arg(&dest)
                .status()
                .expect("could not run scripts/make_fixtures.sh");
            assert!(status.success(), "fixture generation failed");
        }

        let parsed = parse_manifest(&env_file);
        *CACHE.lock().unwrap() = Some(parsed);
    });
}

pub fn cached() -> Option<Fixtures> {
    CACHE.lock().ok().and_then(|c| c.clone())
}

fn parse_manifest(path: &Path) -> Fixtures {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("could not read {}: {e}", path.display()));
    let mut map = std::collections::HashMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            map.insert(k.to_string(), v.to_string());
        }
    }
    let get = |k: &str| -> String {
        map.get(k)
            .unwrap_or_else(|| panic!("fixture manifest is missing {k}"))
            .clone()
    };
    let num = |k: &str| -> i64 { get(k).parse().unwrap_or(0) };

    Fixtures {
        root: path.parent().unwrap().to_path_buf(),
        repo: PathBuf::from(get("REPO")),
        gnupg_home: PathBuf::from(get("GNUPGHOME")),
        allowed_signers: PathBuf::from(get("ALLOWED_SIGNERS")),
        allowed_signers_future: PathBuf::from(get("ALLOWED_SIGNERS_FUTURE")),
        good_fpr: get("GOOD_FPR"),
        expired_fpr: get("EXPIRED_FPR"),
        later_fpr: get("LATER_FPR"),
        revoked_fpr: get("REVOKED_FPR"),
        expired_at_commit: get("EXPIRED_AT_COMMIT"),
        expired_since: get("EXPIRED_SINCE"),
        revoked_after: get("REVOKED_AFTER"),
        ssh_outside_window: get("SSH_OUTSIDE_WINDOW"),
        tampered: get("TAMPERED"),
        pre_rebase_two: get("PRE_REBASE_TWO"),
        t0: num("T0"),
    }
}
