#!/usr/bin/env python3
"""Build a throwaway git repository covering every signature case the audit cares about.

Run with:  python3 -I make-test-repo.py <work-dir>

Everything is deterministic: gpg runs with --faked-system-time, git commits are
written with fixed timestamps, and commit objects carrying signatures are
assembled byte-for-byte so we control exactly what git stores.

The generated repository, its gpg home and its allowed_signers file are all
self-contained under <work-dir>.
"""

import json
import os
import pty
import select
import shutil
import subprocess
import sys
import time
from pathlib import Path

# Deterministic identity and times.
NAME = "Audit Test"
EMAIL = "audit@example.com"
KEYS = {
    # name: (uid, created, expires_days)
    "good": ("Good Signer <good@example.com>", "20220101T000000", "0"),
    "expiring": ("Expiring Signer <exp@example.com>", "20220101T000000", "180d"),
    "revoked": ("Revoked Signer <rev@example.com>", "20220101T000000", "0"),
    "unknown": ("Unknown Signer <unknown@example.com>", "20220101T000000", "0"),
    # Revoked part way through the history, so earlier commits must stay valid.
    "revoked_late": ("Late Revocation <late@example.com>", "20220101T000000", "0"),
}


def run(cmd, **kw):
    return subprocess.run(cmd, check=True, capture_output=True, text=True, **kw)


def epoch(stamp: str) -> int:
    """YYYYMMDDTHHMMSS (UTC) -> epoch seconds."""
    out = run(["date", "-u", "-j", "-f", "%Y%m%dT%H%M%S", stamp, "+%s"])
    return int(out.stdout.strip())


class Fixture:
    def __init__(self, work: Path):
        self.work = work
        self.repo = work / "repo"
        self.gnupg = work / "gnupg"
        self.sshdir = work / "ssh"
        self.fprs = {}
        for d in (self.repo, self.gnupg, self.sshdir):
            d.mkdir(parents=True, exist_ok=True)
        self.gnupg.chmod(0o700)
        self.env = dict(os.environ, GNUPGHOME=str(self.gnupg), GPG_TTY="/dev/null")

    # -- gpg ---------------------------------------------------------------
    def gpg(self, *args, at=None, check=True):
        cmd = ["gpg", "--batch", "--yes", "--pinentry-mode", "loopback",
               "--passphrase", "", "--no-auto-check-trustdb"]
        if at:
            cmd += ["--faked-system-time", at]
        cmd += list(args)
        proc = subprocess.run(cmd, capture_output=True, text=True, env=self.env)
        if check and proc.returncode != 0:
            raise RuntimeError(
                f"gpg failed ({proc.returncode}): {' '.join(cmd)}\n"
                f"stdout: {proc.stdout}\nstderr: {proc.stderr}"
            )
        return proc

    def make_keys(self):
        for name, (uid, created, expiry) in KEYS.items():
            self.gpg("--quick-generate-key", uid, "ed25519", "sign", expiry, at=created)
            listing = self.gpg("--with-colons", "--list-keys", uid).stdout
            for line in listing.splitlines():
                if line.startswith("fpr:"):
                    self.fprs[name] = line.split(":")[9]
                    break
            assert name in self.fprs, f"no fingerprint for {name}"

    def import_revocation(self, key: str, at: str):
        """Import a key's revocation certificate at a given faked time.

        `--gen-revoke`/`--edit-key` date the revocation signature at the moment
        they run, and the pre-generated certificate carries the key's *creation*
        date.  Importing it while the clock is faked to `at` does not change the
        packet, so for a date-stamped revocation we re-sign through a pty with
        `gpg --edit-key` (see `revoke_key_interactively`).
        """
        self.revoke_key_interactively(key, at)

    def revoke_key_interactively(self, key: str, at: str):
        """Revoke a primary key with gpg --edit-key under a faked clock.

        gpg refuses to run --edit-key without a terminal, so drive it through a
        pty.  The resulting revocation signature carries `at` as its creation
        time, which is exactly what the audit uses to decide whether the key was
        revoked before or after a given commit.
        """
        fpr = self.fprs[key]
        answers = [b"revkey\n", b"y\n", b"0\n", b"injected-by-fixture\n", b"\n",
                   b"y\n", b"save\n", b"y\n"]
        pid, fd = pty.fork()
        if pid == 0:  # child
            os.execvpe(
                "gpg",
                ["gpg", "--pinentry-mode", "loopback", "--passphrase", "",
                 "--faked-system-time", at, "--command-fd", "0",
                 "--status-fd", "2", "--edit-key", fpr],
                self.env,
            )
        answered = 0
        deadline = time.time() + 30
        while time.time() < deadline:
            try:
                ready, _, _ = select.select([fd], [], [], 0.4)
            except OSError:
                break
            if fd in ready:
                try:
                    data = os.read(fd, 4096)
                except OSError:
                    break
                if not data:
                    break
                if answered < len(answers):
                    time.sleep(0.15)
                    try:
                        os.write(fd, answers[answered])
                    except OSError:
                        break
                    answered += 1
            try:
                done, _ = os.waitpid(pid, os.WNOHANG)
                if done:
                    break
            except ChildProcessError:
                break
        os.close(fd)

    # -- git ---------------------------------------------------------------
    def git(self, *args, at=None, stdin=None, check=True):
        cmd = ["git", "-C", str(self.repo), *args]
        env = dict(self.env)
        if at:
            ts = f"@{epoch(at)} +0000"
            env["GIT_AUTHOR_DATE"] = ts
            env["GIT_COMMITTER_DATE"] = ts
        return subprocess.run(cmd, capture_output=True, text=True, env=env,
                              input=stdin, check=check)

    def init_repo(self):
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.name", NAME)
        self.git("config", "user.email", EMAIL)
        self.git("config", "commit.gpgsign", "false")
        self.write_file("initial\n")
        self.git("add", "log.txt")
        self.git("commit", "-q", "-m", "initial commit", at="20220101T000000")

    def write_file(self, text):
        with open(self.repo / "log.txt", "a") as fh:
            fh.write(text)

    def commit_tree(self):
        """Stage current log.txt and return the resulting tree id."""
        self.git("add", "log.txt")
        return self.git("write-tree").stdout.strip()

    def head(self, ref="HEAD"):
        return self.git("rev-parse", ref).stdout.strip()

    # -- object crafting ---------------------------------------------------
    def payload(self, tree, parents, at, message):
        stamp = epoch(at)
        lines = [f"tree {tree}"]
        lines += [f"parent {p}" for p in parents]
        lines += [
            f"author {NAME} <{EMAIL}> {stamp} +0000",
            f"committer {NAME} <{EMAIL}> {stamp} +0000",
            "",
            message,
            "",
        ]
        return "\n".join(lines)

    def sign(self, payload: str, key: str, at: str) -> str:
        """Detach-sign payload text with `key`, pretending it is `at`."""
        src = self.work / "payload.txt"
        src.write_text(payload)
        sig = self.work / "payload.asc"
        self.gpg("--local-user", f"{self.fprs[key]}!", "--digest-algo", "SHA256",
                 "--armor", "--detach-sign", "--output", str(sig), str(src), at=at)
        return sig.read_text()

    def splice(self, payload: str, armor: str) -> str:
        """Insert an OpenPGP armor as a gpgsig header, indented like git does."""
        lines = payload.split("\n")
        # Header block ends at the first empty line.
        idx = lines.index("")
        armor_lines = armor.rstrip("\n").split("\n")
        sig_block = ["gpgsig " + armor_lines[0]] + [" " + l for l in armor_lines[1:]]
        return "\n".join(lines[:idx] + sig_block + lines[idx:])

    def store(self, text: str) -> str:
        return self.git("hash-object", "-t", "commit", "-w", "--stdin",
                        stdin=text).stdout.strip()

    def signed_commit(self, parents, at, message, key, sign_at=None, tree=None):
        tree = tree or self.commit_tree()
        payload = self.payload(tree, parents, at, message)
        armor = self.sign(payload, key, sign_at or at)
        return self.store(self.splice(payload, armor))

    def unsigned_commit(self, parents, at, message, tree=None):
        tree = tree or self.commit_tree()
        return self.store(self.payload(tree, parents, at, message))

    def invalid_commit(self, parents, at, message):
        """Sign one payload, then store a different one: a real BADSIG."""
        tree = self.commit_tree()
        original = self.payload(tree, parents, at, message)
        armor = self.sign(original, "good", at)
        tampered = original.replace(message, message + " (tampered)")
        return self.store(self.splice(tampered, armor))

    def build_sha256_repo(self):
        """A SHA-256 repository, where signatures live in gpgsig-sha256."""
        repo = self.work / "repo-sha256"
        env = dict(self.env)
        env["GIT_AUTHOR_DATE"] = env["GIT_COMMITTER_DATE"] = "@1640995200 +0000"
        run(["git", "init", "-q", "--object-format=sha256", "-b", "main", str(repo)], env=env)
        run(["git", "-C", str(repo), "config", "user.name", NAME], env=env)
        run(["git", "-C", str(repo), "config", "user.email", EMAIL], env=env)
        (repo / "log.txt").write_text("sha256 root\n")
        run(["git", "-C", str(repo), "add", "log.txt"], env=env)
        run(["git", "-C", str(repo), "commit", "-q", "-m", "initial sha256 commit"], env=env)

        tree = run(["git", "-C", str(repo), "rev-parse", "HEAD^{tree}"], env=env).stdout.strip()
        stamp = epoch("20230201T000000")
        payload = "\n".join([
            f"tree {tree}",
            f"author {NAME} <{EMAIL}> {stamp} +0000",
            f"committer {NAME} <{EMAIL}> {stamp} +0000",
            "",
            "signed sha256 commit",
            "",
        ])
        src = self.work / "sha256-payload.txt"
        src.write_text(payload)
        sig = self.work / "sha256-payload.asc"
        self.gpg("--local-user", f"{self.fprs['good']}!", "--digest-algo", "SHA256",
                 "--armor", "--detach-sign", "--output", str(sig), str(src),
                 at="20230201T000000")
        # SHA-256 repositories use a gnupg-style header named gpgsig-sha256.
        lines = payload.split("\n")
        idx = lines.index("")
        armor = sig.read_text().rstrip("\n").split("\n")
        block = ["gpgsig-sha256 " + armor[0]] + [" " + l for l in armor[1:]]
        obj = "\n".join(lines[:idx] + block + lines[idx:])
        oid = run(["git", "-C", str(repo), "hash-object", "-t", "commit", "-w", "--stdin"],
                  input=obj, env=env).stdout.strip()
        run(["git", "-C", str(repo), "update-ref", "refs/heads/main", oid], env=env)
        self.sha256_commit = oid
        self.sha256_repo = repo

    def set_branch(self, name, oid):
        self.git("update-ref", f"refs/heads/{name}", oid)

    def checkout(self, name):
        self.git("checkout", "-q", "-B", name)


def main():
    work = Path(sys.argv[1]).resolve()
    if work.exists():
        shutil.rmtree(work)
    fx = Fixture(work)
    fx.make_keys()
    fx.init_repo()

    # ---- SSH keys --------------------------------------------------------
    ssh_key = fx.sshdir / "id_ed25519"
    run(["ssh-keygen", "-t", "ed25519", "-N", "", "-C", "alice@example.com",
         "-f", str(ssh_key), "-q"])
    ssh_pub = Path(str(ssh_key) + ".pub").read_text().strip()
    ssh_key2 = fx.sshdir / "id_bob"
    run(["ssh-keygen", "-t", "ed25519", "-N", "", "-C", "bob@example.com",
         "-f", str(ssh_key2), "-q"])
    ssh_pub2 = Path(str(ssh_key2) + ".pub").read_text().strip()

    def ssh_sign(payload: str, key: Path) -> str:
        msg = fx.work / "sshmsg"
        msg.write_text(payload)
        sig_path = Path(str(msg) + ".sig")
        # ssh-keygen prompts before overwriting an existing .sig, which would
        # hang a non-interactive run.
        sig_path.unlink(missing_ok=True)
        subprocess.run(["ssh-keygen", "-Y", "sign", "-n", "git", "-f", str(key), "-q",
                        str(msg)], check=True, capture_output=True, text=True,
                       stdin=subprocess.DEVNULL)
        sig = sig_path.read_text()
        # ssh-keygen signs the file contents; the payload text is the message.
        return sig

    def ssh_commit(parents, at, message, key):
        tree = fx.commit_tree()
        payload = fx.payload(tree, parents, at, message)
        armor = ssh_sign(payload, key)
        return fx.store(fx.splice(payload, armor))

    # A KRL revoking bob's key, and a second one revoking alice (whose key is
    # otherwise fully valid) so KRL handling can be tested in isolation.
    krl = fx.work / "revoked_keys.krl"
    bob_pub = Path(str(ssh_key2) + ".pub")
    subprocess.run(["ssh-keygen", "-k", "-f", str(krl), str(bob_pub)],
                   check=True, capture_output=True, text=True)
    krl_alice = fx.work / "revoked_alice.krl"
    alice_pub = Path(str(ssh_key) + ".pub")
    subprocess.run(["ssh-keygen", "-k", "-f", str(krl_alice), str(alice_pub)],
                   check=True, capture_output=True, text=True)

    allowed = fx.work / "allowed_signers"
    key_body = " ".join(ssh_pub.split()[:2])
    key_body2 = " ".join(ssh_pub2.split()[:2])
    allowed.write_text(
        f"alice {key_body}\n"
        # alice's key is restricted to the release namespace after 2023.
        f"alice namespaces=\"release\" {key_body}\n"
        # bob is listed but with a validity window that excludes the commits.
        f"bob valid-after=\"20250101\" {key_body2}\n"
    )

    # ---- main: the interesting linear history ---------------------------
    fx.checkout("main")
    start = fx.head()

    # 2. good OpenPGP signature
    c_good = fx.signed_commit([start], "20220201T000000", "good gpg signature", "good")

    # 3. good SSH signature (alice, namespace unrestricted line)
    c_ssh_ok = ssh_commit([c_good], "20220301T000000", "good ssh signature", ssh_key)

    # 4. SSH signature by bob, whose entry is only valid from 2025
    c_ssh_early = ssh_commit([c_ssh_ok], "20220401T000000", "ssh signed before valid-after", ssh_key2)

    # 5. SSH key not in allowed_signers at all
    stranger = fx.sshdir / "id_stranger"
    run(["ssh-keygen", "-t", "ed25519", "-N", "", "-C", "stranger", "-f", str(stranger), "-q"])
    c_ssh_unknown = ssh_commit([c_ssh_early], "20220501T000000", "ssh key not listed", stranger)

    # 6. signature that does not verify
    c_invalid = fx.invalid_commit([c_ssh_unknown], "20220601T000000", "tampered commit")

    # 7. OpenPGP key unknown to the audit keyring is applied later by --keyring.
    c_nokey = fx.signed_commit([c_invalid], "20220701T000000", "signed by unlisted key", "unknown")

    # 8. key expired before the commit was made: sign while it was valid, but
    #    date the commit after expiry.  This is the case the audit exists for.
    c_expired = fx.signed_commit([c_nokey], "20220801T000000", "signed by expired key",
                                 "expiring", sign_at="20220601T000000")

    # 9. key revoked before the commit: same trick, commit dated after revocation.
    c_revoked = fx.signed_commit([c_expired], "20220901T000000", "signed by revoked key",
                                 "revoked", sign_at="20220501T000000")

    # 10. key revoked *after* the commit: valid when signed, revoked later.
    c_revoked_later = fx.signed_commit([c_revoked], "20220415T000000",
                                       "signed before key revocation", "revoked",
                                       sign_at="20220415T000000")

    # 10b. the reverse case, with a revocation that really does postdate the
    #      commit: this one must still be reported as valid.
    c_late_valid = fx.signed_commit([c_revoked_later], "20221101T000000",
                                    "signed well before late revocation", "revoked_late",
                                    sign_at="20221101T000000")
    fx.set_branch("main", c_late_valid)

    # 11. plain unsigned commit
    c_unsigned = fx.unsigned_commit([c_late_valid], "20230101T000000", "unsigned commit")

    fx.set_branch("main", c_unsigned)

    # ---- merge commits --------------------------------------------------
    base = c_unsigned
    side_tree = fx.commit_tree()
    side = fx.unsigned_commit([base], "20221101T000000", "side branch work", tree=side_tree)
    # An unsigned merge (the common GitHub case).
    merge_payload_tree = fx.commit_tree()
    merge = fx.store(fx.payload(merge_payload_tree, [base, side], "20221102T000000",
                                "Merge branch 'side'"))
    fx.set_branch("merged", merge)

    # A signed merge.
    merge2_payload = fx.payload(fx.commit_tree(), [merge, base], "20221103T000000",
                                "Merge with signature")
    merge2 = fx.store(fx.splice(merge2_payload, fx.sign(merge2_payload, "good", "20221103T000000")))
    fx.set_branch("merged-signed", merge2)

    # ---- namespace restriction ------------------------------------------
    fx.checkout("feature")
    f_base = fx.head()
    # Same alice key, but the only matching line restricts it to "release".
    restricted = fx.work / "restricted_signers"
    restricted.write_text(f"alice namespaces=\"release\" {key_body}\n")
    tree = fx.commit_tree()
    payload = fx.payload(tree, [base], "20221201T000000", "namespace restricted")
    c_ns = fx.store(fx.splice(payload, ssh_sign(payload, ssh_key)))
    fx.set_branch("feature", c_ns)

    # ---- rebased history ------------------------------------------------
    # A topic branch forked from an *older* base, so rebasing it really replays
    # its commits.  git's rebase recreates commits and drops gpgsig headers, so
    # the original commits are signed and their replacements are not.
    fx.git("checkout", "-q", "-B", "rebase-base", c_good)
    fx.git("checkout", "-q", "-B", "topic")
    orig1 = fx.signed_commit([c_good], "20230101T000000", "topic commit one", "good")
    fx.write_file("topic change\n")
    orig2 = fx.signed_commit([orig1], "20230102T000000", "topic commit two", "good")
    fx.set_branch("topic", orig2)

    # Replay the topic onto main's tip; --no-gpg-sign is the default, so the
    # rewritten commits inherit no signature.
    fx.git("checkout", "-q", "topic", at="20230103T000000")
    fx.git("rebase", "--onto", c_unsigned, "rebase-base", "topic", at="20230103T000000")
    rebased_tip = fx.head("topic")
    rebased_oids = fx.git("rev-list", "--reverse", f"{c_unsigned}..topic").stdout.split()

    # ---- SHA-256 object format ------------------------------------------
    # A separate repository: git refuses to change a repository's hash format.
    fx.build_sha256_repo()

    # Revocations can only be applied once every signature has been produced:
    # gpg refuses to sign with a revoked key at any --faked-system-time.
    fx.import_revocation("revoked", "20220601T000000")
    fx.import_revocation("revoked_late", "20221201T000000")

    # Write out metadata the test suite needs.
    meta = {
        "repo": str(fx.repo),
        "gnupg": str(fx.gnupg),
        "ssh": str(fx.sshdir),
        "allowed_signers": str(allowed),
        "restricted_signers": str(restricted),
        "krl": str(krl),
        "krl_alice": str(krl_alice),
        "fingerprints": fx.fprs,
        "commits": {
            "good": c_good,
            "ssh_ok": c_ssh_ok,
            "ssh_early": c_ssh_early,
            "ssh_unknown": c_ssh_unknown,
            "invalid": c_invalid,
            "no_key": c_nokey,
            "expired": c_expired,
            "revoked": c_revoked,
            "revoked_later": c_revoked_later,
            "late_valid": c_late_valid,
            "unsigned": c_unsigned,
            "merge": merge,
            "merge_signed": merge2,
            "namespace": c_ns,
            "rebase_original_one": orig1,
            "rebase_original_two": orig2,
            "rebase_tip": rebased_tip,
        },
        "rebase_rewritten": rebased_oids,
        "sha256_repo": str(fx.sha256_repo),
        "sha256_commit": fx.sha256_commit,
        "ssh_keys": {"alice": str(ssh_key), "bob": str(ssh_key2), "stranger": str(stranger)},
    }
    (work / "fixture.json").write_text(json.dumps(meta, indent=2) + "\n")
    print(work / "fixture.json")


if __name__ == "__main__":
    main()
