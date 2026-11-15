#!/usr/bin/env bash
# Builds a test repository covering every audit scenario:
#   unsigned / valid GPG / GPG signer not in whitelist / tampered (invalid sig)
#   GPG key expired (commit before and after expiry)
#   GPG key revoked (commit before and after revocation)
#   SSH valid / SSH signer not in allowed_signers
#   signed merge commit / rebased branch (signatures dropped)
#
# Usage: make_test_repo.sh [target-dir]
# Prints the repo path and helper file locations at the end.
set -euo pipefail

ROOT="${1:-/tmp/sig-audit-test}"
rm -rf "$ROOT"
mkdir -p "$ROOT"

export GNUPGHOME="$ROOT/gnupg"
mkdir -p "$GNUPGHOME"
chmod 700 "$GNUPGHOME"

GPG="gpg --batch --yes --pinentry-mode loopback"

gen_key() { # name email expire fake_time
  if [ -n "${4:-}" ]; then
    $GPG --faked-system-time "$4" --generate-key <<EOF
%no-protection
Key-Type: eddsa
Key-Curve: ed25519
Name-Real: $1
Name-Email: $2
Expire-Date: $3
%commit
EOF
  else
    $GPG --generate-key <<EOF
%no-protection
Key-Type: eddsa
Key-Curve: ed25519
Name-Real: $1
Name-Email: $2
Expire-Date: $3
%commit
EOF
  fi
}

echo "== generating GPG keys =="
gen_key "Alice Auditor" alice@example.com 0 ""
gen_key "Bob Outsider" bob@example.com 0 ""
gen_key "Eve Expiring" eve@example.com 1y "20200101T000000"   # expires 2021-01-01
gen_key "Mallory Revoked" mallory@example.com 0 "20200101T000000"

fpr_of() { $GPG --with-colons --list-keys "$1" | awk -F: '/^fpr:/ {print $10; exit}'; }
ALICE_FPR=$(fpr_of alice@example.com)
BOB_FPR=$(fpr_of bob@example.com)
EVE_FPR=$(fpr_of eve@example.com)
MALLORY_FPR=$(fpr_of mallory@example.com)

# NOTE: Mallory's key is revoked only AFTER all commits are created (below) —
# gpg refuses to sign with a revoked key even under --faked-system-time.

# gpg wrapper so git signs inside our test keyring; FAKE_TIME env fakes signing time.
cat > "$ROOT/gpg-wrapper.sh" <<EOF
#!/bin/sh
export GNUPGHOME="$GNUPGHOME"
if [ -n "\${FAKE_TIME:-}" ]; then
  exec gpg --faked-system-time "\$FAKE_TIME" "\$@"
fi
exec gpg "\$@"
EOF
chmod +x "$ROOT/gpg-wrapper.sh"

echo "== generating SSH keys =="
ssh-keygen -q -t ed25519 -N "" -C carol@example.com -f "$ROOT/carol"
ssh-keygen -q -t ed25519 -N "" -C dave@example.com -f "$ROOT/dave"
echo "carol@example.com $(cat "$ROOT/carol.pub")" > "$ROOT/allowed_signers"

# GPG whitelist: Alice, Eve, Mallory are trusted; Bob is deliberately absent.
cat > "$ROOT/gpg_whitelist.txt" <<EOF
# trusted signers
$ALICE_FPR
$EVE_FPR
$MALLORY_FPR
EOF

# ---------------------------------------------------------------- repo ----
REPO="$ROOT/repo"
git init -q -b main "$REPO"
cd "$REPO"
git config user.name "Alice Auditor"
git config user.email "alice@example.com"
git config gpg.program "$ROOT/gpg-wrapper.sh"
git config commit.gpgsign false

i=0
commit() { # message [extra git commit args...]
  local msg="$1"; shift
  i=$((i+1))
  echo "$msg" >> "file_$i.txt"
  git add "file_$i.txt"
  GIT_AUTHOR_DATE="${AUTHOR_DATE:-}" GIT_COMMITTER_DATE="${COMMITTER_DATE:-}" \
    git commit -q "$@" -m "$msg"
}

# 1. unsigned
commit "unsigned commit"

# 2. valid GPG signature (Alice, whitelisted)
commit "signed by alice (valid)" -S --gpg-sign="$ALICE_FPR"

# 3. valid signature but signer NOT in whitelist (Bob)
commit "signed by bob (not in whitelist)" -S --gpg-sign="$BOB_FPR"

# 4. tampered commit: valid signature, then message rewritten keeping gpgsig
commit "tamper me" -S --gpg-sign="$ALICE_FPR"
T=$(git rev-parse HEAD)
git cat-file commit "$T" > "$ROOT/c1.txt"
sed 's/tamper me/tampered after signing/' "$ROOT/c1.txt" > "$ROOT/c2.txt"
NEW=$(git hash-object -t commit -w "$ROOT/c2.txt")
git reset -q --hard "$NEW"

# 5. expired key: signed 2020-06 while key valid, commit dated 2020-06 -> valid at commit time
AUTHOR_DATE="2020-06-01T12:00:00" COMMITTER_DATE="2020-06-01T12:00:00" \
  FAKE_TIME=20200601T120000 \
  commit "eve signed while key valid (expired since)" -S --gpg-sign="$EVE_FPR"

# 6. expired key: commit dated 2022, after expiry 2021-01 -> invalid
AUTHOR_DATE="2022-06-01T12:00:00" COMMITTER_DATE="2022-06-01T12:00:00" \
  FAKE_TIME=20200601T120000 \
  commit "eve commit dated after key expiry" -S --gpg-sign="$EVE_FPR"

# 7. revoked key: commit dated 2020, before revocation (2026) -> valid at commit time
AUTHOR_DATE="2020-06-01T12:00:00" COMMITTER_DATE="2020-06-01T12:00:00" \
  FAKE_TIME=20200601T120000 \
  commit "mallory signed before revocation" -S --gpg-sign="$MALLORY_FPR"

# 8. revoked key: commit dated 2027, after revocation -> invalid
AUTHOR_DATE="2027-06-01T12:00:00" COMMITTER_DATE="2027-06-01T12:00:00" \
  FAKE_TIME=20200601T120000 \
  commit "mallory commit dated after revocation" -S --gpg-sign="$MALLORY_FPR"

# 9. SSH signature, principal in allowed_signers (Carol)
i=$((i+1)); echo "ssh signed by carol (valid)" >> "file_$i.txt"; git add "file_$i.txt"
GIT_AUTHOR_NAME="Carol" GIT_COMMITTER_NAME="Carol" \
GIT_AUTHOR_EMAIL="carol@example.com" GIT_COMMITTER_EMAIL="carol@example.com" \
  git -c gpg.format=ssh -c user.signingkey="$ROOT/carol" commit -q -S \
  -m "ssh signed by carol (valid)"

# 10. SSH signature, principal NOT in allowed_signers (Dave)
i=$((i+1)); echo "ssh signed by dave (not in allowed_signers)" >> "file_$i.txt"; git add "file_$i.txt"
GIT_AUTHOR_NAME="Dave" GIT_COMMITTER_NAME="Dave" \
GIT_AUTHOR_EMAIL="dave@example.com" GIT_COMMITTER_EMAIL="dave@example.com" \
  git -c gpg.format=ssh -c user.signingkey="$ROOT/dave" commit -q -S \
  -m "ssh signed by dave (not in allowed_signers)"

# 11. signed merge commit
git checkout -q -b feature HEAD~2
commit "feature work, signed" -S --gpg-sign="$ALICE_FPR"
git checkout -q main
git merge -q --no-ff -S --gpg-sign="$ALICE_FPR" feature -m "signed merge of feature"

# 12. unsigned merge commit
git checkout -q -b feature2 HEAD~1
commit "feature2 work"
git checkout -q main
git merge -q --no-ff feature2 -m "unsigned merge of feature2"

# 13. rebase: signed commits lose their signatures
git checkout -q -b rebase-old main
commit "pre-rebase signed one" -S --gpg-sign="$ALICE_FPR"
commit "pre-rebase signed two" -S --gpg-sign="$ALICE_FPR"
git checkout -q -b rebase-me
git checkout -q main
commit "main moved on"
git checkout -q rebase-me
git rebase -q main >/dev/null 2>&1
git checkout -q main

# Revoke Mallory's key *now* (2026): commits dated 2020 predate the revocation,
# the commit dated 2027 postdates it.
echo "== revoking Mallory's key =="
printf 'y\n0\n\ny\n' | gpg --homedir "$GNUPGHOME" --no-tty --yes --command-fd 0 \
  --pinentry-mode loopback --generate-revocation "$MALLORY_FPR" > "$ROOT/mallory.rev" 2>/dev/null
$GPG --import "$ROOT/mallory.rev" >/dev/null 2>&1

echo
echo "== test repo ready =="
echo "repo:             $REPO"
echo "allowed_signers:  $ROOT/allowed_signers"
echo "gpg whitelist:    $ROOT/gpg_whitelist.txt"
echo "GNUPGHOME:        $GNUPGHOME"
echo
echo "run:"
echo "  GNUPGHOME=$GNUPGHOME git-sig-audit $REPO \\"
echo "    --allowed-signers $ROOT/allowed_signers \\"
echo "    --gpg-whitelist $ROOT/gpg_whitelist.txt --format json"
