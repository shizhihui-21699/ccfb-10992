# sigaudit

Audit commit signatures across every branch of a git repository. Reads git
objects directly (no checkout required), supports **OpenPGP** and **SSH**
signatures, and reports per branch which commits are unsigned, invalid, or
signed by a key that is not allowed.

Designed as a CI gate: exit code `1` when any commit fails, plus JSON, JUnit XML
and SARIF reports.

```
sigaudit --repo /path/to/repo --format junit --output sigaudit.xml
```

## What it checks

| verdict | `%G?` | meaning |
|---|---|---|
| `good` | `G` | signature verifies and the signer is allowed |
| `signer_not_allowed` | `U` | valid signature, key not in `allowed_signers` (SSH) or below the trust floor (OpenPGP) |
| `bad_signature` | `B` | signature does not match the signed content |
| `unknown_key` | `E` | signing key is not in the verifier's keyring |
| `key_expired_at_commit` | `Y` | the signing key was already expired at the commit's own time |
| `key_revoked_at_commit` | `R` | the signing key was revoked at or before the commit's own time |
| `unsigned` | `N` | no `gpgsig` header |
| `error` | `E` | the signature could not be checked at all (verifier missing, unsupported format) |

The `%G?` column is the letter `sigaudit` reports in its `git_letter` field, so
output can be diffed against `git log --format=%G?`.

## How verification works

Signatures are verified by the same programs git uses, with the same arguments,
so results agree with git by construction:

* **OpenPGP** — `gpg --status-fd=1 --verify <sigfile> -` with the signed payload
  on stdin, parsing the `[GNUPG:]` status lines exactly as git's
  `parse_gpg_output()` does. Commits carrying more than one signature packet are
  rejected, as git rejects multiple exclusive statuses.
* **SSH** — `ssh-keygen -Y find-principals` then `-Y verify -n git` against
  `gpg.ssh.allowedSignersFile`, falling back to `-Y check-novalidate` for a
  diagnostic when no principal matches. This mirrors `verify_ssh_signed_buffer()`.

The signed payload is reconstructed from the raw object bytes exactly as git
does it: for commits, the `gpgsig` header and its continuation lines are removed
(`parse_buffer_signed_by_header()`); for annotated tags, the payload is
everything before the armor line with any `gpgsig` headers stripped
(`parse_signature()` / `remove_signature()`). Commits in the repository's *other*
hash algorithm (a `gpgsig-sha256` header in a SHA-1 repo) are excluded from the
payload, as git excludes them.

### Key validity at commit time

Key expiry and revocation are judged **at the commit's own committer timestamp**
by default, not "now". This is the difference between

```
key_expired_at_commit     # the key was already dead when this commit was made
```
and a key that simply expired afterwards, which stays `good`.

Implementation:

* OpenPGP: gpg is asked with `--faked-system-time <commit-time>`, so gpg itself
  decides whether the key was live then. gpg treats a key as usable *at* its
  expiry second and expired one second later; `sigaudit` inherits that rule.
* SSH: `ssh-keygen -Overify-time=<commit-time>` evaluates `valid-after` /
  `valid-before` windows in the `allowed_signers` file against that instant.
  OpenSSH KRLs carry no per-signature revocation time, so a configured
  `gpg.ssh.revocationFile` applies whenever it is present.

Use `--gpg-time now` / `--ssh-time now` to reproduce `git verify-commit`'s
wall-clock behaviour instead.

### Malformed signatures

git calls `die()` when it meets a `gpgsig` value it cannot even attribute to a
format (`bad/incompatible signature`), aborting the whole command. `sigaudit`
reports such an object as `bad_signature` with a detail line instead, so one
corrupt object cannot abort an audit of a large history. It is never reported as
good.

### Deliberate difference from `git log --format=%G?`

git prints `U` for any OpenPGP signature whose key has no trust level assigned
(gpg's `TRUST_UNDEFINED`), while `git verify-commit` exits 0 in that same case.
`sigaudit` reports those as `good`, because "unknown trust" is not "forbidden
signer". If you want git's spelling, `git_letter` is still in the report and the
distinction is documented in `src/audit.rs`.

## Configuration

Every setting defaults to what the repository's own git config says, so a local
run agrees with `git verify-commit` in the same checkout. Each can be overridden
on the command line, which is what CI needs.

| git config | CLI override |
|---|---|
| `gpg.program`, `gpg.openpgp.program` | `--gpg-program` |
| `gpg.ssh.program` | — |
| `gpg.ssh.allowedSignersFile` | `--allowed-signers` |
| `gpg.ssh.revocationFile` | `--revocation-file` |
| `gpg.minTrustLevel` | `--min-trust-level` |
| `GNUPGHOME` | `--gpg-home` |

## History handling

* **All branches** by default, local and remote-tracking. `--branch` accepts
  globs: `--branch 'release/*'`.
* **Deduplication** — a commit reachable from several branches is verified once;
  per-branch summaries still count it for each branch that contains it.
* **Merges** — audited by their own signature. A signed merge whose parents are
  unsigned is `good`; an unsigned merge is `unsigned`.
* **Rebases** — a rebase creates new commits and leaves the originals
  unreachable. Those are not audited by default (they are no longer history);
  `--unreachable` includes them, which is useful for finding pre-rebase history
  that never passed a signature gate.
* **Shallow clones** — commits whose parents are missing are counted in
  `repository.incomplete_history` and a warning is emitted, rather than silently
  truncating the audit.
* **Annotated tags** — audited with `--tags`; lightweight tags are covered by
  branch history.
* **Ordering** — branches are walked newest-first by committer time, so
  `--max-commits N` really means "the N newest".

## Reports

* `--format human` (default) — summary, per-branch counts, failure list.
* `--format json` — canonical machine format; `schema_version` is `1`.
* `--format junit` — one `<testcase>` per object, `<failure>` for each failing
  commit. Consumed by GitLab, Jenkins, Buildkite and `dorny/test-reporter`.
* `--format sarif` — SARIF 2.1.0 for GitHub code scanning.

`-o FILE` writes the report to a file and leaves stdout empty, so logs stay
clean.

## Exit codes

| code | meaning |
|---|---|
| 0 | every audited object passed |
| 1 | at least one audited object failed |
| 2 | usage or environment error |
| 3 | internal error (report could not be written) |

`--fail-on <verdict>` narrows what counts as a failure, for example
`--fail-on bad_signature --fail-on key_revoked_at_commit`.

## Building and testing

```
cargo build --release
cargo test
```

The integration tests build a throwaway repository with real gpg and ssh-keygen
signatures (`scripts/make_fixtures.sh`) and assert that every verdict matches
git's own, using `git verify-commit`'s exit code to disambiguate the two
meanings git gives to `U`. Tests skip themselves if `gpg` or `ssh-keygen` is
unavailable.

Requirements at runtime: `git` is not needed, but `gpg` (for OpenPGP) and
OpenSSH 8.2+ (`ssh-keygen -Y`, for SSH) are. SHA-256 repositories are not
supported (the bundled libgit2 rejects that object format); pointing at one
produces a clear message and exit code 2.
