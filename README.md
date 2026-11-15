# sigaudit

Offline commit-signature auditing for Git repositories. It reads Git objects
directly (no checkout, no `git log` parsing) and verifies commit signatures
with OpenPGP (GPG) and SSH (`sshsig`) keys, reporting per branch which commits
are unsigned, invalidly signed, or signed by a key that is not allowlisted.

Verification happens in-process with `pgp` and `ssh-key`; `gpg` and
`ssh-keygen` are never invoked, so the result does not depend on the local
trust database, the user's GnuPG home, or an SSH agent.

## What it checks

For every commit reachable from the selected branches:

| Verdict | Meaning |
|---|---|
| `signed` | Signature verifies, and the signing key/principal is trusted at the commit time. |
| `unsigned` | The commit has no signature. |
| `invalid` | A signature is present but does not verify (corrupted, wrong key, bad armour). |
| `untrusted` | Signature verifies, but the key is not allowlisted, or the key had expired or was revoked **at the commit time**. |
| `revoked-later` | Signature verifies and the key was valid when the commit was made, but it has been revoked since. Reported separately so a revocation does not retroactively fail old commits. |

### Details that are easy to get wrong

* **Exact signed payload.** Git signs the commit object with the signature
  header removed (`parse_buffer_signed_by_header`). Anchored/rebased history
  and merge commits therefore require parsing the raw object bytes, which this
  tool does rather than trusting a structured commit parser.
* **Time of validity.** OpenPGP key expiry and revocation are evaluated at the
  commit's committer timestamp, not "now". A key that expired last week does not
  invalidate a commit signed while it was valid.
* **Committer identity.** A commit whose *committer* date is inside the key's
  validity window passes even if the signature was made earlier; this matches
  what `git verify-commit` reports.
* **Merge commits.** Merge commits are audited like any other commit. A merge
  that records a signed tag (`mergetag`) additionally has that tag's signature
  audited independently.
* **SSH certificates.** When an SSH signature was made with a certificate,
  the certificate is validated against the `cert-authority` line of
  `allowed_signers`: CA signature, user-certificate type, validity window,
  principals, and OpenSSH's CA signature-algorithm allowlist.
* **KRL revocation.** Explicit keys, SHA-1/SHA-256 fingerprints, and
  certificate revocations by key id, serial, serial range, or serial bitmap are
  understood, for a specific CA or for all CAs (`PROTOCOL.krl`).
* **`allowed_signers` options.** `cert-authority`, `namespaces=`, `valid-after=`
  and `valid-before=` are enforced with OpenSSH's principal-pattern semantics
  (globs and `!` negation).

## Usage

```console
$ sigaudit \
    --repo . \
    --gpg-keyring keys/alice.pub.asc \
    --gpg-keyring keys/bob.pub.asc \
    --trusted-signer alice@example.com \
    --allowed-signers .github/allowed_signers \
    --krl keys/revoked.krl \
    --json > audit.json
```

* `--repo` — any worktree or bare repository (default: `.`).
* `--branch` — repeatable; defaults to every local branch. Add
  `--remote-branches` to include remote-tracking branches.
* `--gpg-keyring` — armored or binary OpenPGP certificates, or a GnuPG
  `pubring.kbx` keybox. Repeatable.
* `--trusted-signer` — a user-id substring or fingerprint that is trusted.
  With none given, every key in the keyrings is trusted.
* `--allowed-signers` — the SSH allowlist file.
* `--krl` — an OpenSSH KRL. Repeatable.
* `--include-tags` — also audit commits referenced by annotated tags.
* `--json`, `--json-out PATH` — machine-readable output for CI.
* `--require-signature` — make an unsigned commit a failure.
* `--fail-on invalid|untrusted|any` — which verdicts fail the run (default:
  `untrusted`).

Exit status: `0` when the policy passes, `1` when it fails, `2` on errors
(bad keyring, broken repository, …).

## CI

The text report is meant for humans; `--json` is stable and versioned
(`schema_version: 1`) for machines:

```json
{
  "schema_version": 1,
  "repository": "/path/to/repo",
  "policy": { "require_signature": false, "ssh_allowed_signers": true, "ssh_krls": 1 },
  "totals": { "total": 12, "signed": 6, "unsigned": 2, "invalid": 1, "untrusted": 3, "revoked_later": 0 },
  "unique_commits": 12,
  "branches": [ { "name": "main", "tip": "…", "counts": { }, "failure_count": 4 } ],
  "commits": [ { "commit": "…", "verdict": "untrusted", "reason": "…", "signature": { } } ],
  "warnings": [],
  "passed": false
}
```

Each commit entry carries its parents, author/committer, commit time, subject,
the verdict, an optional `signature` detail block, and an optional `mergetag`
block for merges that embed a signed tag.

## Building

```console
cargo build --release
cargo test
```

The end-to-end tests build a fixture repository with the real `git`, `gpg` and
`ssh-keygen` binaries, so those must be on `PATH`. The tests cover trusted and
untrusted OpenPGP signatures, corrupted signatures, SSH signatures from plain
keys and from CA-signed certificates, key expiry before and after the commit,
KRL revocation of keys and certificates, and merges with signed tags.

## Layout

| Path | Purpose |
|---|---|
| `src/objects.rs` | Byte-exact commit/tag signature extraction (Git's payload rules). |
| `src/pgp_keyring.rs` | OpenPGP certificate loading (armor, binary, GnuPG keybox) and validity. |
| `src/pgp_verify.rs` | OpenPGP detached-signature verification with time-aware key checks. |
| `src/ssh_keys.rs` | `allowed_signers` parsing and KRL revocation. |
| `src/sshsig.rs` | SSHSIG envelope parsing, including certificate signers and Git's re-wrapping. |
| `src/ssh_verify.rs` | SSH signature verification and trust/revocation policy. |
| `src/audit.rs` | Repository walking, deduplication, and verdict computation. |
| `src/report.rs` | Text and JSON reporters. |
| `scripts/build_fixtures.sh` | Builds the fixture repository used by the tests. |
