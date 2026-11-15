#!/usr/bin/env bash
# Build a throwaway git repository full of signed/unsigned commits for testing
# sigaudit. Everything is generated locally: no network, no real identities.
#
# Each interesting verdict gets exactly one commit, and wherever it matters the
# answer to "was the key valid at commit time" differs from "is it valid now".
#
# Branches:
#   main   good GPG commit, unsigned commit, unknown-key commit,
#          key-expired-before-the-commit, key-expired-only-since,
#          key-revoked-after-the-commit, signed merge, unsigned merge
#   ssh    allowed, unsigned, not-allowed key, key outside its
#          allowed_signers window, tampered signature
#   rebase two commits that get rebased away, so the originals dangle
#   tags   a signed annotated tag and an unsigned one
#
# Every key gets its own keyring; the audit keyring is assembled by exporting
# the public halves. That keeps key generation simple -- no key is ever
# re-expired in place, which gpg objects to once a newer self-signature exists.
#
# Usage: scripts/make_fixtures.sh <dest-dir>
# Set KEEP=1 to keep the temporary keyrings for debugging.

set -euo pipefail

DEST="${1:?usage: make_fixtures.sh <dest-dir>}"
KEEP="${KEEP:-0}"

rm -rf "$DEST"
mkdir -p "$DEST"
DEST="$(cd "$DEST" && pwd)"

# gpg-agent's socket path is length-limited on macOS, so keep the work dir short.
WORK="$(mktemp -d /tmp/sigaudit-fix.XXXXXX)"
cleanup() {
    if [ "$KEEP" = "1" ]; then
        echo "fixtures kept: $WORK" >&2
    else
        rm -rf "$WORK"
    fi
}
trap cleanup EXIT

T0=1700000000                       # 2023-11-14T22:13:20Z
GIT_DATE="2023-11-14T22:13:20 +0000"
KEY_CREATED=1600000000              # 2020-09-13
EXPIRED_BEFORE_COMMIT=1696118400    # 2023-10-01, before every commit
EXPIRED_AFTER_COMMIT=1701388800     # 2023-12-01, after every commit
REVOKED_AT=1717200000               # 2024-06-01, after every commit

gpg_bang() { echo "$1!"; }

new_home() {
    local home="$WORK/gpg-$1"
    mkdir -m 700 "$home"
    echo "$home"
}

# make_key <home> <uid> <usage> <expire> <created-epoch> [sign-subkey]
# With <sign-subkey> = "subkey", the primary only certifies and a separate
# signing subkey is added, like a default GnuPG identity.
make_key() {
    local home="$1" uid="$2" usage="$3" expire="$4" created="$5" layout="${6:-primary}"
    # NB: gpg reads a bare number in the expire field as "seconds from now",
    # not an absolute time. Durations ("180d") and ISO stamps
    # ("20231201T000000") are the two unambiguous forms.

    local primary_usage="$usage"
    if [ "$layout" = "subkey" ]; then
        primary_usage="cert"
    fi
    GNUPGHOME="$home" gpg --batch --pinentry-mode loopback --passphrase '' \
        --faked-system-time "$(gpg_bang "$created")" \
        --quick-generate-key "$uid" ed25519 "$primary_usage" "$expire" >/dev/null 2>&1
    if [ "$layout" = "subkey" ]; then
        local fpr
        fpr="$(fpr_of "$home")"
        GNUPGHOME="$home" gpg --batch --pinentry-mode loopback --passphrase '' \
            --faked-system-time "$(gpg_bang "$created")" \
            --quick-add-key "$fpr" ed25519 sign "$expire" >/dev/null 2>&1
    fi
}

fpr_of() {
    GNUPGHOME="$1" gpg --batch --with-colons --list-keys 2>/dev/null |
        awk -F: '/^fpr:/{print $10; exit}'
}

git_commit() { # <repo> <message> <date> [extra git-commit args...]
    local repo="$1" msg="$2" date="$3"
    shift 3
    (
        cd "$repo"
        # One file per commit keeps branches from conflicting when they are
        # merged; the content never matters, only the object graph does.
        # A counter file name avoids both merge conflicts and `date` (which the
        # tests must not depend on).
        local file="note-$RANDOM-$RANDOM.txt"
        printf '%s\n' "$msg" >"$file"
        git add "$file"
        GIT_AUTHOR_DATE="$date" GIT_COMMITTER_DATE="$date" \
            git commit -q -m "$msg" "$@"
    )
}

# ---------------------------------------------------------------------------
# 1. Keyrings, one per scenario
# ---------------------------------------------------------------------------
GOOD_HOME="$(new_home good)"
make_key "$GOOD_HOME" 'Good Signer <good@example.com>' sign 0 "$KEY_CREATED" subkey
GOOD_FPR="$(fpr_of "$GOOD_HOME")"

# Never imported into the audit keyring, so its commits are "unknown key".
UNKNOWN_HOME="$(new_home unknown)"
make_key "$UNKNOWN_HOME" 'Unknown Signer <unknown@example.com>' sign 0 "$KEY_CREATED"

# Expired before the commits it signs: signed while valid, then the key's
# expiry is rewritten to an earlier instant in its own keyring.
EXPIRED_HOME="$(new_home expired)"
make_key "$EXPIRED_HOME" 'Expired Before <expired-before@example.com>' sign 0 "$KEY_CREATED"
EXPIRED_FPR="$(fpr_of "$EXPIRED_HOME")"

# Expires after the commits: the classic "expired now, was fine then" case.
# Created without expiry so it can sign under the real clock, then shortened
# below to EXPIRED_AFTER_COMMIT -- after its commits are made.
LATER_HOME="$(new_home later)"
make_key "$LATER_HOME" 'Expired Since <expired-since@example.com>' sign 0 "$KEY_CREATED"
LATER_FPR="$(fpr_of "$LATER_HOME")"

# Revoked after the commits: the key signs while valid, and its revocation
# certificate is dated REVOKED_AT (after every commit). The certificate is
# generated below, once the commits exist, because gpg refuses to sign with an
# already-revoked key.
REVOKED_HOME="$(new_home revoked)"
make_key "$REVOKED_HOME" 'Revoked Signer <revoked@example.com>' sign 0 "$KEY_CREATED"
REVOKED_FPR="$(fpr_of "$REVOKED_HOME")"

# ---------------------------------------------------------------------------
# 2. SSH keys and allowed_signers
# ---------------------------------------------------------------------------
ssh-keygen -q -t ed25519 -N '' -C 'alice-ssh' -f "$WORK/alice" </dev/null
ssh-keygen -q -t ed25519 -N '' -C 'bob-ssh' -f "$WORK/bob" </dev/null
ALICE_FPR="$(ssh-keygen -lf "$WORK/alice.pub" | awk '{print $2}')"

cat >"$WORK/allowed_signers" <<EOF
alice@example.com $(cat "$WORK/alice.pub")
EOF
cat >"$WORK/allowed_signers_future" <<EOF
alice@example.com valid-after="20300101" $(cat "$WORK/alice.pub")
EOF

# ---------------------------------------------------------------------------
# 3. Repository
# ---------------------------------------------------------------------------
REPO="$DEST/repo"
mkdir -p "$REPO"
cd "$REPO"
git init -q -b main .
git config user.name 'Test Committer'
git config user.email 'committer@example.com'
git config commit.gpgsign false
git config tag.gpgsign false
git config gpg.program gpg
git config gpg.format openpgp
: >log.txt

# --- main ---------------------------------------------------------------
export GNUPGHOME="$GOOD_HOME"
git config user.signingkey "$GOOD_FPR"

git_commit "$REPO" "good gpg commit" "$GIT_DATE" -S
git_commit "$REPO" "unsigned commit" "$GIT_DATE"

export GNUPGHOME="$UNKNOWN_HOME"
git config user.signingkey "$(fpr_of "$UNKNOWN_HOME")"
git_commit "$REPO" "signed by a key absent from the audit keyring" "$GIT_DATE" -S

export GNUPGHOME="$EXPIRED_HOME"
git config user.signingkey "$EXPIRED_FPR"
git_commit "$REPO" "signed by a key that expired before the commit" "$GIT_DATE" -S
EXPIRED_AT_COMMIT="$(git rev-parse HEAD)"
# Move that key's expiry to before the commit we just made. The clock must be
# faked to a moment BEFORE the new expiry: gpg refuses to write a self-signature
# dated later than its clock, and quietly clamps the value otherwise.
GNUPGHOME="$EXPIRED_HOME" gpg --batch --pinentry-mode loopback --passphrase '' \
    --faked-system-time "$(gpg_bang "$((EXPIRED_BEFORE_COMMIT - 86400 * 30))")" \
    --quick-set-expire "$EXPIRED_FPR" 20231001T000000 >/dev/null 2>&1

export GNUPGHOME="$LATER_HOME"
git config user.signingkey "$LATER_FPR"
git_commit "$REPO" "signed by a key that expired only after the commit" "$GIT_DATE" -S
EXPIRED_SINCE="$(git rev-parse HEAD)"
# Only now give the key its (post-commit) expiry, in its own keyring, so the
# exported public key carries it. Fake a clock just before it, as above.
GNUPGHOME="$LATER_HOME" gpg --batch --pinentry-mode loopback --passphrase '' \
    --faked-system-time "$(gpg_bang "$((T0 + 60))")" \
    --quick-set-expire "$LATER_FPR" 20231201T000000 >/dev/null 2>&1

export GNUPGHOME="$REVOKED_HOME"
git config user.signingkey "$REVOKED_FPR"
git_commit "$REPO" "signed by a key revoked after the commit" "$GIT_DATE" -S
REVOKED_AFTER="$(git rev-parse HEAD)"
# Now revoke it, with a certificate dated REVOKED_AT. No --batch: --gen-revoke
# refuses to run under it and reads its answers from the command fd instead.
printf 'y\n0\nrevoked for tests\n\ny\n' |
    GNUPGHOME="$REVOKED_HOME" gpg --yes --no-tty --command-fd 0 \
        --pinentry-mode loopback --passphrase '' \
        --faked-system-time "$(gpg_bang "$REVOKED_AT")" \
        --armor --output "$WORK/revoked.asc" --gen-revoke "$REVOKED_FPR" >/dev/null 2>&1
GNUPGHOME="$REVOKED_HOME" gpg --batch --import "$WORK/revoked.asc" >/dev/null 2>&1

export GNUPGHOME="$GOOD_HOME"
git config user.signingkey "$GOOD_FPR"

# --- merges -------------------------------------------------------------
git checkout -q -b side HEAD~1
git_commit "$REPO" "side branch signed commit" "$GIT_DATE" -S
git checkout -q main
GIT_AUTHOR_DATE="$GIT_DATE" GIT_COMMITTER_DATE="$GIT_DATE" \
    git merge -q --no-ff -S -m "signed merge commit" side

git checkout -q -b side2 HEAD
git_commit "$REPO" "side2 unsigned commit" "$GIT_DATE"
git checkout -q main
GIT_AUTHOR_DATE="$GIT_DATE" GIT_COMMITTER_DATE="$GIT_DATE" \
    git merge -q --no-ff -m "unsigned merge commit" side2

# --- ssh branch ---------------------------------------------------------
git checkout -q -b ssh main~3
git config user.name 'SSH Committer'
git config user.email 'alice@example.com'
git config gpg.format ssh
git config user.signingkey "$WORK/alice.pub"

git_commit "$REPO" "ssh signed allowed" "$GIT_DATE" -S
git_commit "$REPO" "ssh unsigned" "$GIT_DATE"

git config user.signingkey "$WORK/bob.pub"
git_commit "$REPO" "ssh signed but not allowed" "$GIT_DATE" -S

git config user.signingkey "$WORK/alice.pub"
git_commit "$REPO" "ssh signed outside the allowed window" "$GIT_DATE" -S
SSH_OUTSIDE_WINDOW="$(git rev-parse HEAD)"

git_commit "$REPO" "ssh commit with a tampered signature" "$GIT_DATE" -S
TAMPERED="$(git rev-parse HEAD)"

# Tamper with the signed content while leaving the gpgsig header intact: append
# a line to the commit message. The signature still parses, but no longer
# matches the payload, so the verifier must report a bad signature.
(
    cd "$REPO"
    git cat-file commit "$TAMPERED" >"$WORK/tampered.raw"
    printf 'this line was added after signing\n' >>"$WORK/tampered.raw"
    NEW="$(git hash-object -t commit -w --stdin <"$WORK/tampered.raw")"
    git update-ref "refs/heads/ssh" "$NEW"
    echo "$NEW" >"$WORK/tampered.oid"
)

# --- rebase branch ------------------------------------------------------
git checkout -q -b rebase main~5
git config user.name 'Rebase Committer'
git config user.email 'rebase@example.com'
git config gpg.format openpgp
export GNUPGHOME="$GOOD_HOME"
git config user.signingkey "$GOOD_FPR"
git_commit "$REPO" "pre-rebase commit one" "$GIT_DATE" -S
git_commit "$REPO" "pre-rebase commit two" "$GIT_DATE"
PRE_REBASE_TWO="$(git rev-parse HEAD)"
GIT_AUTHOR_DATE="$GIT_DATE" GIT_COMMITTER_DATE="$GIT_DATE" \
    git rebase -q --onto main main~5 rebase >/dev/null 2>&1
# The rebase copies both commits, so the originals are now unreachable.

# The audit keyring's whitelist. Set at the end and pointed at the *copied*
# file: the work dir is deleted when this script exits, so pointing at
# "$WORK/allowed_signers" would leave the repo with a dangling config path.
git config --local gpg.ssh.allowedSignersFile "$DEST/allowed_signers"

# --- tags ---------------------------------------------------------------
git checkout -q main
export GNUPGHOME="$GOOD_HOME"
git config user.signingkey "$GOOD_FPR"
GIT_COMMITTER_DATE="$GIT_DATE" git tag -s v1.0 -m "signed annotated tag" -u "$GOOD_FPR" HEAD
GIT_COMMITTER_DATE="$GIT_DATE" git tag -a v0.9-unsigned -m "unsigned annotated tag" HEAD~1

# ---------------------------------------------------------------------------
# 4. Assemble the audit keyring: public halves of every key whose commits
#    should be fully resolvable (the "unknown" key is deliberately left out).
# ---------------------------------------------------------------------------
mkdir -p "$DEST/gnupg"
chmod 700 "$DEST/gnupg"
for home in "$GOOD_HOME" "$EXPIRED_HOME" "$LATER_HOME" "$REVOKED_HOME"; do
    GNUPGHOME="$home" gpg --batch --export 2>/dev/null |
        GNUPGHOME="$DEST/gnupg" gpg --batch --import >/dev/null 2>&1
done
chmod 700 "$DEST/gnupg"

cp "$WORK/allowed_signers" "$DEST/allowed_signers"
cp "$WORK/allowed_signers_future" "$DEST/allowed_signers_future"
cp "$WORK/alice.pub" "$DEST/alice.pub"

# ---------------------------------------------------------------------------
# 5. Manifest for the tests
# ---------------------------------------------------------------------------
cat >"$DEST/fixtures.env" <<EOF
# generated by scripts/make_fixtures.sh
REPO=$REPO
GNUPGHOME=$DEST/gnupg
GOOD_FPR=$GOOD_FPR
EXPIRED_FPR=$EXPIRED_FPR
LATER_FPR=$LATER_FPR
REVOKED_FPR=$REVOKED_FPR
ALLOWED_SIGNERS=$DEST/allowed_signers
ALLOWED_SIGNERS_FUTURE=$DEST/allowed_signers_future
ALICE_PUB=$DEST/alice.pub
ALICE_FPR=$ALICE_FPR
EXPIRED_AT_COMMIT=$EXPIRED_AT_COMMIT
EXPIRED_SINCE=$EXPIRED_SINCE
REVOKED_AFTER=$REVOKED_AFTER
SSH_OUTSIDE_WINDOW=$SSH_OUTSIDE_WINDOW
TAMPERED=$(cat "$WORK/tampered.oid" 2>/dev/null || echo "")
PRE_REBASE_TWO=$PRE_REBASE_TWO
T0=$T0
EXPIRED_AT_COMMIT_EPOCH=$EXPIRED_BEFORE_COMMIT
EXPIRED_SINCE_EPOCH=$EXPIRED_AFTER_COMMIT
REVOKED_AT=$REVOKED_AT
EOF

echo "fixtures ready in $DEST" >&2
