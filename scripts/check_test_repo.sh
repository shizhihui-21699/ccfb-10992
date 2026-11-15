#!/usr/bin/env bash
# End-to-end check: builds the test repo, runs the audit, asserts every
# commit lands in its expected status bucket.
# Usage: check_test_repo.sh [target-dir] [path-to-git-sig-audit-binary]
set -euo pipefail

ROOT="${1:-/tmp/sig-audit-test}"
BIN="${2:-git-sig-audit}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

"$SCRIPT_DIR/make_test_repo.sh" "$ROOT" >/dev/null

set +e
GNUPGHOME="$ROOT/gnupg" "$BIN" "$ROOT/repo" \
  --allowed-signers "$ROOT/allowed_signers" \
  --gpg-whitelist "$ROOT/gpg_whitelist.txt" \
  --format json > "$ROOT/report.json"
AUDIT_EXIT=$?
set -e

python3 -I - "$ROOT/report.json" "$AUDIT_EXIT" <<'EOF'
import json, sys

report, audit_exit = json.load(open(sys.argv[1])), int(sys.argv[2])
main = {c["subject"]: c for c in report["branches"]["main"]["commits"]}
rebased = {c["subject"]: c for c in report["branches"]["rebase-me"]["commits"]}
old = {c["subject"]: c for c in report["branches"]["rebase-old"]["commits"]}

expected_main = {
    "unsigned commit": "unsigned",
    "signed by alice (valid)": "valid",
    "signed by bob (not in whitelist)": "untrusted",
    "tampered after signing": "invalid",
    "eve signed while key valid (expired since)": "valid-expired-key",
    "eve commit dated after key expiry": "invalid",
    "mallory signed before revocation": "valid-revoked-key",
    "mallory commit dated after revocation": "invalid",
    "ssh signed by carol (valid)": "valid",
    "ssh signed by dave (not in allowed_signers)": "untrusted",
    "signed merge of feature": "valid",
    "unsigned merge of feature2": "unsigned",
    "main moved on": "unsigned",
}

failures = []
for subject, want in expected_main.items():
    got = main.get(subject, {}).get("status")
    if got != want:
        failures.append(f"main: {subject!r}: want {want}, got {got}")

# rebase drops signatures; the pre-rebase commits stay signed on rebase-old
for subject in ("pre-rebase signed one", "pre-rebase signed two"):
    if rebased.get(subject, {}).get("status") != "unsigned":
        failures.append(f"rebase-me: {subject!r}: want unsigned, got {rebased.get(subject, {}).get('status')}")
    if old.get(subject, {}).get("status") != "valid":
        failures.append(f"rebase-old: {subject!r}: want valid, got {old.get(subject, {}).get('status')}")

# merge commits are flagged
for subject in ("signed merge of feature", "unsigned merge of feature2"):
    if not main.get(subject, {}).get("merge"):
        failures.append(f"main: {subject!r}: merge flag not set")

# violations present -> exit code must be 1
if audit_exit != 1:
    failures.append(f"exit code: want 1, got {audit_exit}")

if failures:
    print("CHECK FAILED:")
    for f in failures:
        print("  " + f)
    sys.exit(1)
print(f"all checks passed ({len(expected_main) + 4} assertions)")
EOF
