//! Shared helper: build the fixture repository once per test binary.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

#[allow(dead_code)]
pub struct Fixture {
    pub root: PathBuf,
    pub expect: serde_json::Value,
}

#[allow(dead_code)]
impl Fixture {
    pub fn repo(&self) -> PathBuf {
        self.root.join("repo")
    }

    pub fn gpg_keyrings(&self) -> Vec<PathBuf> {
        ["alice", "bob", "expired", "malory"]
            .iter()
            .map(|n| self.root.join(format!("{n}.pub.asc")))
            .collect()
    }

    pub fn allowed_signers(&self) -> PathBuf {
        self.root.join("ssh/allowed_signers")
    }

    pub fn krl(&self, name: &str) -> PathBuf {
        self.root.join(format!("ssh/{name}"))
    }

    pub fn commit(&self, key: &str) -> String {
        self.expect[key].as_str().unwrap().to_string()
    }
}

/// Build the fixture in a stable temp directory. The generation script is
/// idempotent and cheap enough to run once per test binary.
pub fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/build_fixtures.sh");
        let root = std::env::var_os("SIGAUDIT_FIXTURE_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("fixture"));
        let status = std::process::Command::new("bash")
            .arg(&script)
            .arg(&root)
            .status()
            .expect("running fixture builder");
        assert!(status.success(), "fixture builder failed: {status}");
        let expect: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(root.join("expect.json")).unwrap())
                .unwrap();
        Fixture { root, expect }
    })
}
