# commit-signature-audit

Audit commit signatures straight out of git's object database, per branch, for
OpenPGP and SSH signatures — and judge key validity **as of each commit's own
timestamp** rather than today.

```
commit-signature-audit -C ./repo --allowed-signers allowed_signers --list
```

```
Commit signature audit — /srv/repo/
11 commits audited (1 merges), 4 violating

BRANCH                        COMMITS   UNSIGNED  INVALID*   VALID%
--------------------------------------------------------------------
main                               11          2         2    54.5%

By status:
  invalid        1
  key_expired    1
  unknown_signer 1
  unsigned       2
  valid          6
```

## Why not `git log --show-signature`?

`git log` has exactly one notion of "now": gpg and ssh-keygen are asked whether a
key is valid **at the moment you run the command**. For an audit that is wrong in
two directions:

* a commit signed years ago by a key that has since expired is reported as
  expired, even though the signature was perfectly good when it was made;
* an unsigned or badly-signed commit is not distinguished from one whose signer
  is simply not in your allow-list.

This tool reconstructs the exact bytes git would hand to the verifier (see
[How commits are read](#how-commits-are-read)), then pins the verifier's clock to
the commit's committer timestamp:

| format | mechanism |
| --- | --- |
| OpenPGP | `gpg --faked-system-time <commit-epoch>!` |
| SSH | `ssh-keygen -Y verify -Overify-time=<commit time, local>` |

The trailing `!` freezes gpg's clock, so key creation and expiry are judged at
exactly that instant. Ordinary key expiry therefore needs no
reimplementation — gpg answers it correctly at the pinned time.

### Revocation is the one case gpg cannot date

`--faked-system-time` does **not** make gpg ignore a revocation that happened
after the commit; it reports `REVKEYSIG` regardless. So for OpenPGP the tool
reads the revocation signature's own creation time out of the key listing
(`gpg --with-colons --with-sig-list`) and compares it with the commit time:

* revoked **at or before** the commit → `key_revoked` (a violation);
* revoked **after** the commit → the commit stays `valid`, with
  `"revoked after this commit"` recorded in the report.

SSH KRLs contain no per-key revocation date, only the date the list was
generated, so there is nothing honest to compare. The tool therefore follows git
and applies a configured KRL unconditionally (`key_revoked`), and says so in the
detail text. Point `gpg.ssh.revocationFile`/`--revocation-file` at a KRL only if
you want that hard-line behaviour.

## Statuses

| status | meaning |
| --- | --- |
| `valid` | signature verifies, signer allowed, key valid at the commit time |
| `unsigned` | no `gpgsig` header for the repository's hash format |
| `invalid` | the signature does not verify (bad signature, wrong content) |
| `unknown_signer` | cryptographically good, signer not in the allow-list |
| `not_permitted` | listed, but the entry forbids this use (`namespaces=`, `valid-after`/`valid-before`, minimum gpg trust) |
| `key_expired` | signing key had expired by the commit time |
| `key_revoked` | signing key was revoked by the commit time (or is in the KRL) |
| `key_not_yet_valid` | signature predates the key, or predates `valid-after` |
| `signature_expired` | the signature itself has expired (OpenPGP `EXPSIG`) |
| `no_public_key` | public key unavailable, so nothing can be verified |
| `malformed` | armor or packets could not be parsed |
| `unverifiable` | cannot be checked for want of configuration (e.g. SSH with no `allowed_signers`) |

`unverifiable` is deliberately distinct from `invalid`: it says "we could not
look", not "we looked and it failed". Both are violations by default.

## How commits are read

Commit objects are read from the object database and parsed byte-for-byte like
git's `parse_buffer_signed_by_header()` / `remove_signature()` in `commit.c`:

* the signature is stripped from the payload, so the verified bytes are the
  commit git would hash;
* continuation lines are the ones beginning with a space — a tab is *not* a
  continuation, exactly as in git;
* a `gpgsig` header may appear anywhere in the header block;
* SHA-1 repositories use `gpgsig`, SHA-256 repositories use `gpgsig-sha256`; a
  signature for the other algorithm is excluded from the payload, so such a
  commit reads as unsigned — the same conclusion git reaches;
* a commit carrying several signatures is reported `invalid`, matching git's
  `%G? = E`.

libgit2 cannot open SHA-256 repositories, so when it refuses the repository the
tool falls back to `git cat-file` for object access. Both paths read raw objects;
neither uses `git log` for verification.

## Allow-lists

### OpenPGP

By default any key in the gpg keyring is accepted, exactly as git does. Harden
with:

* `--trusted-fingerprint <FPR>` (repeatable) — restrict signers; accepts full
  fingerprints or long key ids;
* `--min-trust <level>` — mirror git's `gpg.minTrustLevel`;
* `--gpg-home` / `--keyring` — choose which keyring is consulted.

### SSH

`--allowed-signers <file>` is required to verify SSH signatures. The file is
parsed in Rust for reporting, but every verdict comes from `ssh-keygen`, so the
following behave exactly as in git:

* principals, including comma-separated and glob patterns (`alice*`);
* `namespaces="git,release"`, `valid-after=`, `valid-before=`;
* `cert-authority` and certificate handling;
* `-Overify-time` being interpreted in **local** time, matching git's
  `show_date(..., .local = 1)` — a timezone mismatch would shift the validity
  check by the UTC offset.

`--principal <name>` additionally requires the signing principal to match.

## Reports for CI

```
-o table    # default, human readable
-o json     # full machine-readable document
-o lines    # one line per violation, for log scraping
-o junit    # JUnit XML: one test case per branch
-o github   # ::error:: annotations
```

`--fail-on-violation` exits 1 when any commit is not `valid`; it is not implied,
so the report is always produced first. `--out-file` writes to a file instead of
stdout. `--max-commits`, `--since`, `--until`, `--first-parent`, `--skip-merges`
and `--jobs` control scope and cost.

The JSON document is stable and versioned:

```json
{
  "tool": "commit-signature-audit",
  "audited_at": 1704240000,
  "object_format": "sha1",
  "totals": {"commits": 11, "merge_commits": 1, "violating_commits": 4,
             "by_status": {"valid": 6, "unsigned": 2}},
  "branches": [{"name": "main", "tip": "…", "commits": 11, "unsigned": 2,
                "unsigned_excluding_merges": 2, "valid_ratio": 0.6,
                "by_status": {"…": 0}, "violations": []}],
  "violations": [{"commit": "…", "short": "…", "status": "key_expired",
                  "branches": ["main"], "subject": "…",
                  "kind": "open_pgp", "signer": "…",
                  "fingerprint": "…", "detail": "…"}],
  "warnings": []
}
```

`totals` counts each commit once even when several branches reach it; each
branch's own counts are independent. `--dedupe false` re-verifies shared commits
per branch.

## Testing

```
cargo test                     # 44 unit + 24 integration tests
```

The integration tests build a throwaway repository with
`scripts/make_test_repo.py`, which signs real commits with real gpg and
ssh-keygen keys under faked clocks. It covers: valid and tampered OpenPGP,
valid/invalid/unlisted SSH, namespace restrictions, `valid-after` windows,
expired keys, keys revoked before *and* after the commit, KRLs, unsigned and
signed merges, rebase-rewritten history, SHA-256 repositories, and first-parent
walks. Wherever git can answer the same question the tests assert on git's own
`%G?` code as well, so the tool cannot drift from git unnoticed.

Requirements: `git`, `gpg`, `ssh-keygen` (OpenSSH 8.2p1+), and `python3` for the
fixtures.

## Known limits

* X.509 (`gpgsm`) signatures are detected and reported `unverifiable`.
* SSH certificates are handled through `ssh-keygen` (so `cert-authority` works),
  but the Rust-side allow-list parser does not model certificate principals;
  rejection reasons for certificates come from ssh-keygen's own message.
* Revocations that carry no signature timestamp cannot be dated; gpg's verdict
  at the commit time is used instead.
