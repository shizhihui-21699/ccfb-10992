#!/usr/bin/env bash
# Build a Git fixture repository with a known mix of signed, unsigned,
# invalid, untrusted, expired and revoked commits, for exercising sigaudit.
#
# The fixture is generated with the real tools (git, gpg, ssh-keygen) so the
# auditor is tested against genuine artifacts rather than hand-rolled bytes.
#
# Usage: build_fixtures.sh <output-dir>
#
# Layout of <output-dir>:
#   repo/                 the Git repository under audit
#   gnupg/                throwaway GnuPG home the fixture was signed with
#   ssh/                  SSH signing keys, allowed_signers and KRLs
#   *.pub.asc             armored OpenPGP certificates
#   expect.json           commits whose verdict the tests assert on
set -euo pipefail

ROOT=${1:?usage: build_fixtures.sh <output-dir>}
rm -rf "$ROOT"
mkdir -p "$ROOT"
ROOT=$(cd "$ROOT" && pwd)

export LC_ALL=C
export TZ=UTC

# Deterministic timeline (Unix seconds).
T_VALID=1500003600       # expired-key key is valid around here
T_EXPIRED_KEY=1500000000 # when the expired key was created
T_NOW=1700000000         # "present": other commits, all signed keys valid
T_KEY_EXPIRY=$((T_EXPIRED_KEY + 86400))
T_AFTER_EXPIRY=$((T_KEY_EXPIRY + 400000))

REPO="$ROOT/repo"
GNUPG_HOME="$ROOT/gnupg"
SSH_DIR="$ROOT/ssh"
mkdir -p "$REPO" "$GNUPG_HOME" "$SSH_DIR"
chmod 700 "$GNUPG_HOME"
export GNUPGHOME="$GNUPG_HOME"

# A gpg wrapper so a signature can be produced "at" a chosen time even when
# the key has since expired. Git calls this via `gpg.program`.
cat > "$ROOT/gpg-at" <<'WRAP'
#!/bin/sh
# SIGAUDIT_GPG_TIME pins gpg's idea of "now" so signatures can be made while a
# key was still valid.
if [ -n "${SIGAUDIT_GPG_TIME:-}" ]; then
  exec gpg --faked-system-time "${SIGAUDIT_GPG_TIME}!" "$@"
fi
exec gpg "$@"
WRAP
chmod +x "$ROOT/gpg-at"

git init -q -b main "$REPO"
cd "$REPO"
git config user.name "Fixture Bot"
git config user.email "fixture@example.com"
git config commit.gpgsign false

commit_at() { # <time> <message>
  local when=$1 msg=$2 n
  n=$(git rev-list --count HEAD 2>/dev/null || echo 0)
  printf 'content %s\n' "$n" > "file-$n.txt"
  git add "file-$n.txt"
  GIT_AUTHOR_DATE="@$when +0000" GIT_COMMITTER_DATE="@$when +0000" \
    git commit -q -m "$msg"
}

signed_commit_at() { # <time> <key> <message>
  local when=$1 key=$2 msg=$3
  GIT_AUTHOR_DATE="@$when +0000" GIT_COMMITTER_DATE="@$when +0000" \
    git -c user.signingkey="$key" commit -q -S --allow-empty -m "$msg"
}

# --- OpenPGP keys ----------------------------------------------------------
gpg_gen_at() { # <identity> <time>
  gpg --batch --pinentry-mode loopback --passphrase '' \
      --faked-system-time "$2" \
      --quick-generate-key "$1" ed25519 sign 0 >/dev/null 2>&1
}
fpr_of() {
  gpg --batch --list-keys --with-colons "$1" 2>/dev/null |
    awk -F: '/^fpr:/{print $10; exit}'
}

echo "== OpenPGP keys"
gpg_gen_at "Alice <alice@example.com>" "$T_NOW"
gpg_gen_at "Bob <bob@example.com>" "$T_NOW"
gpg_gen_at "Malory <malory@example.com>" "$T_NOW"
ALICE_FPR=$(fpr_of "alice@example.com")
BOB_FPR=$(fpr_of "bob@example.com")
MALORY_FPR=$(fpr_of "malory@example.com")

# A key created long ago that expired one day later.
gpg_gen_at "Expired <expired@example.com>" "$T_EXPIRED_KEY"
EXPIRED_FPR=$(fpr_of "expired@example.com")
gpg --batch --pinentry-mode loopback --passphrase '' \
    --faked-system-time "$((T_EXPIRED_KEY + 3600))" \
    --quick-set-expire "$EXPIRED_FPR" 1d >/dev/null 2>&1

for spec in alice:"$ALICE_FPR" bob:"$BOB_FPR" malory:"$MALORY_FPR" expired:"$EXPIRED_FPR"; do
  name=${spec%%:*}
  gpg --armor --export "$name@example.com" > "$ROOT/$name.pub.asc"
done

git config gpg.program "$ROOT/gpg-at"

# --- SSH keys --------------------------------------------------------------
echo "== SSH keys"
ssh-keygen -q -t ed25519 -N '' -C "alice-sshd" -f "$SSH_DIR/alice_ed25519"
ssh-keygen -q -t rsa -b 2048 -N '' -C "bob-sshd" -f "$SSH_DIR/bob_rsa"
ssh-keygen -q -t ed25519 -N '' -C "carol-sshd" -f "$SSH_DIR/carol_ed25519"
ssh-keygen -q -t ed25519 -N '' -C "dave-sshd" -f "$SSH_DIR/dave_ed25519"
ssh-keygen -q -t ed25519 -N '' -C "ca" -f "$SSH_DIR/ca_key"

# Carol gets a CA-signed user certificate with an explicit serial and a
# validity window anchored around the fixture timeline (ssh-keygen takes
# absolute times as YYYYMMDD[HHMMSS], which keeps the fixture reproducible).
ssh-keygen -q -s "$SSH_DIR/ca_key" -I "carol-id" -n "carol@example.com" \
    -z 42 -V "20200101:20300101" "$SSH_DIR/carol_ed25519.pub"
# Dave gets a certificate we revoke via a KRL; same window.
ssh-keygen -q -s "$SSH_DIR/ca_key" -I "dave-id" -n "dave@example.com" \
    -z 77 -V "20200101:20300101" "$SSH_DIR/dave_ed25519.pub"

# --- history ---------------------------------------------------------------
echo "== history"

# 1. unsigned
commit_at "$((T_NOW - 9000))" "unsigned commit"

# 2. signed by Alice (trusted)
signed_commit_at "$((T_NOW - 8000))" "$ALICE_FPR" "signed by alice (trusted)"

# 3. signed by Bob (valid crypto, not on the allowlist)
signed_commit_at "$((T_NOW - 7000))" "$BOB_FPR" "signed by bob (not allowlisted)"

# 4. signed by the expired key while it was still valid; the commit is dated
#    before expiry so the audit must accept it.
SIGAUDIT_GPG_TIME=$T_VALID signed_commit_at "$((T_EXPIRED_KEY + 100))" \
    "$EXPIRED_FPR" "signed by expired key while valid"
EXPIRED_VALID_COMMIT=$(git rev-parse HEAD)

# 5. signed by the expired key while valid, but the commit claims a time after
#    the key expired: the audit must reject it as expired-at-commit-time.
SIGAUDIT_GPG_TIME=$T_VALID signed_commit_at "$T_AFTER_EXPIRY" \
    "$EXPIRED_FPR" "signed before expiry, committed after it"
EXPIRED_STALE_COMMIT=$(git rev-parse HEAD)

# 6. SSH-signed by alice-sshd (allowlisted)
GIT_AUTHOR_DATE="@$((T_NOW - 6000)) +0000" GIT_COMMITTER_DATE="@$((T_NOW - 6000)) +0000" \
  git -c gpg.format=ssh -c user.signingkey="$SSH_DIR/alice_ed25519" \
  commit -q -S --allow-empty -m "SSH signed by alice (allowlisted)"

# 7. SSH-signed by carol through her CA certificate
GIT_AUTHOR_DATE="@$((T_NOW - 5000)) +0000" GIT_COMMITTER_DATE="@$((T_NOW - 5000)) +0000" \
  git -c gpg.format=ssh -c user.signingkey="$SSH_DIR/carol_ed25519-cert.pub" \
  commit -q -S --allow-empty -m "SSH signed by carol via CA certificate"
CAROL_CERT_COMMIT=$(git rev-parse HEAD)

# 8. SSH-signed by bob, not in allowed_signers
GIT_AUTHOR_DATE="@$((T_NOW - 4000)) +0000" GIT_COMMITTER_DATE="@$((T_NOW - 4000)) +0000" \
  git -c gpg.format=ssh -c user.signingkey="$SSH_DIR/bob_rsa" \
  commit -q -S --allow-empty -m "SSH signed by bob (not allowlisted)"

# 9. SSH-signed by dave through a certificate that we revoke below
GIT_AUTHOR_DATE="@$((T_NOW - 3500)) +0000" GIT_COMMITTER_DATE="@$((T_NOW - 3500)) +0000" \
  git -c gpg.format=ssh -c user.signingkey="$SSH_DIR/dave_ed25519-cert.pub" \
  commit -q -S --allow-empty -m "SSH signed by dave via revoked certificate"
DAVE_CERT_COMMIT=$(git rev-parse HEAD)

# 10. signed merge commit by Alice
git checkout -q -b side
GIT_AUTHOR_DATE="@$((T_NOW - 3000)) +0000" GIT_COMMITTER_DATE="@$((T_NOW - 3000)) +0000" \
  git commit -q --allow-empty -m "side branch work"
git checkout -q main
GIT_AUTHOR_DATE="@$((T_NOW - 2500)) +0000" GIT_COMMITTER_DATE="@$((T_NOW - 2500)) +0000" \
  git -c user.signingkey="$ALICE_FPR" merge -q --no-ff -S -m "signed merge by alice" side

# 11. a commit we will corrupt the signature of
signed_commit_at "$((T_NOW - 2000))" "$ALICE_FPR" "commit we corrupt the signature of"
CORRUPT_COMMIT=$(git rev-parse HEAD)
python3 - "$REPO" "$CORRUPT_COMMIT" <<'PY'
import subprocess, sys
repo, commit = sys.argv[1], sys.argv[2]
raw = subprocess.run(["git", "cat-file", "commit", commit], cwd=repo,
                     check=True, capture_output=True).stdout
# Alter the commit message *after* signing. The signature covers the whole
# commit buffer, so this leaves the armour intact (no CRC failure) while the
# cryptographic check must fail.
marker = b"\n\n"
sep = raw.index(marker)
mutated = bytearray(raw)
mutated[sep + 2] = ord('X') if mutated[sep + 2] != ord('X') else ord('Y')
new = subprocess.run(["git", "hash-object", "-t", "commit", "-w", "--stdin"],
                     cwd=repo, check=True, input=bytes(mutated),
                     capture_output=True).stdout.decode().strip()
subprocess.run(["git", "update-ref", "HEAD", new], cwd=repo, check=True)
PY
# The rewrite replaced HEAD's commit object with the corrupted twin; the
# current branch now points at it, so `main` reaches the corrupted commit.
# Do not reset, which would undo the corruption.
CORRUPT_COMMIT=$(git rev-parse HEAD)
git checkout -q main 2>/dev/null || true

# 12. a rebased branch: rewrite the last two commits with new content but
#     re-use signatures (git rebase --exec would re-sign; here we just make a
#     fresh linear branch so the auditor sees rewritten history).
git checkout -q -b rebased HEAD~5
signed_commit_at "$((T_NOW - 1500))" "$ALICE_FPR" "rebased commit A"
signed_commit_at "$((T_NOW - 1000))" "$ALICE_FPR" "rebased commit B"
git checkout -q main

# 13. an annotated signed tag pointing at the alice-signed commit
ALICE_COMMIT=$(git rev-list main --grep='signed by alice (trusted)' -n1)
[ -n "$ALICE_COMMIT" ] || { echo "fixture: alice commit not found" >&2; exit 1; }
GIT_COMMITTER_DATE="@$((T_NOW - 500)) +0000" \
  git -c user.signingkey="$ALICE_FPR" tag -s -m "release tag" v1 "$ALICE_COMMIT" 2>/dev/null || true

# A branch containing only cleanly signed history, for "should pass" checks.
git branch clean-only "$ALICE_COMMIT"

# --- SSH trust files -------------------------------------------------------
echo "== SSH trust material"
cat > "$SSH_DIR/allowed_signers" <<EOF
alice@example.com $(cat "$SSH_DIR/alice_ed25519.pub")
bob@example.com namespaces="other" $(cat "$SSH_DIR/bob_rsa.pub")
carol@example.com cert-authority $(cat "$SSH_DIR/ca_key.pub")
dave@example.com cert-authority $(cat "$SSH_DIR/ca_key.pub")
EOF

# KRL revoking alice's plain key: her good SSH commit becomes untrusted.
rm -f "$SSH_DIR/alice-revoked.krl"
ssh-keygen -k -f "$SSH_DIR/alice-revoked.krl" "$SSH_DIR/alice_ed25519.pub" >/dev/null 2>&1

# KRL revoking dave's certificate by serial 77.
rm -f "$SSH_DIR/dave-cert-revoked.krl"
ssh-keygen -k -f "$SSH_DIR/dave-cert-revoked.krl" "$SSH_DIR/dave_ed25519-cert.pub" >/dev/null 2>&1

# KRL revoking bob's plain key.
rm -f "$SSH_DIR/bob-revoked.krl"
ssh-keygen -k -f "$SSH_DIR/bob-revoked.krl" "$SSH_DIR/bob_rsa.pub" >/dev/null 2>&1

# A KRL that revokes certificate serials via a *bitmap* section. ssh-keygen -k
# cannot be forced to emit one, so it is assembled here; the bit layout is
# OpenSSH's (big-endian integer, bit 0 least significant), which
# `ssh-keygen -Q` confirms below.
python3 - "$SSH_DIR" "$SSH_DIR/ca_key.pub" <<'PYBITMAP'
import base64, struct, sys
ssh_dir, ca_pub_path = sys.argv[1], sys.argv[2]

def s(b):
    return struct.pack('>I', len(b)) + b

ca_blob = base64.b64decode(open(ca_pub_path).read().split()[1])
# Revoke the certificate with serial 42 (carol's) via a bitmap starting at 40:
# bits 0 and 2 set -> serials 40 and 42.
offset = 40
bitmap = bytes([0b00000101])
section = s(ca_blob) + s(b'') + bytes([0x22]) + s(struct.pack('>Q', offset) + s(bitmap))
krl = (
    struct.pack('>Q', 0x5353484b524c0a00)
    + struct.pack('>I', 1)
    + struct.pack('>Q', 1)
    + struct.pack('>Q', 0)
    + struct.pack('>Q', 0)
    + s(b'')
    + s(b'bitmap test')
    + bytes([1])
    + s(section)
)
open(f"{ssh_dir}/bitmap-revoked.krl", 'wb').write(krl)
PYBITMAP
# Sanity check with the reference implementation. Capture the output first:
# `ssh-keygen -Q` exits non-zero when it reports REVOKED, so a pipeline would
# be affected by `set -o pipefail`.
bitmap_check=$(ssh-keygen -Q -f "$SSH_DIR/bitmap-revoked.krl" "$SSH_DIR/carol_ed25519-cert.pub" 2>&1 || true)
if [[ "$bitmap_check" == *REVOKED* ]]; then
  echo "fixture: bitmap KRL verified by ssh-keygen"
else
  echo "fixture: bitmap KRL did NOT revoke carol's cert, aborting" >&2
  exit 1
fi

# --- expectations ----------------------------------------------------------
cat > "$ROOT/expect.json" <<EOF
{
  "alice_fpr": "$ALICE_FPR",
  "alice_fpr_lower": "$(echo "$ALICE_FPR" | tr 'A-Z' 'a-z')",
  "bob_fpr": "$BOB_FPR",
  "malory_fpr": "$MALORY_FPR",
  "expired_fpr": "$EXPIRED_FPR",
  "expired_valid_commit": "$EXPIRED_VALID_COMMIT",
  "expired_stale_commit": "$EXPIRED_STALE_COMMIT",
  "corrupt_commit": "$CORRUPT_COMMIT",
  "carol_cert_commit": "$CAROL_CERT_COMMIT",
  "dave_cert_commit": "$DAVE_CERT_COMMIT",
  "alice_commit": "$ALICE_COMMIT",
  "main_tip": "$(git rev-parse main)"
}
EOF

echo "== fixture ready at $ROOT"
