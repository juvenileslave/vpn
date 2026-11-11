"""Unit tests for check_secrets.py using temporary Git repositories."""

from __future__ import annotations

import base64
import io
import os
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))

import check_secrets  # noqa: E402

BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
# Изолирует временные репозитории от пользовательской конфигурации Git.
GIT_ENV = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
GIT_ENV.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")


def bech32(length: int) -> str:
    return "".join(secrets.choice(BECH32) for _ in range(length))


def fake_age_identity() -> str:
    # Собирается во время выполнения: в Git нет даже поддельного ключа.
    return "-".join(["AGE", "SECRET", "KEY", "1" + bech32(58).upper()])


def fake_private_key_block() -> str:
    body = base64.b64encode(secrets.token_bytes(48)).decode()
    label = " ".join(["OPENSSH", "PRIVATE", "KEY"])
    return f"-----BEGIN {label}-----\n{body}\n-----END {label}-----\n"


def sops_document(recipients: int = 1) -> str:
    age_entries = "".join(
        f"        - recipient: age1{bech32(58)}\n"
        "          enc: |\n"
        "            -----BEGIN AGE ENCRYPTED FILE-----\n"
        f"            {base64.b64encode(secrets.token_bytes(48)).decode()}\n"
        "            -----END AGE ENCRYPTED FILE-----\n"
        for _ in range(recipients)
    )
    age_block = "    age:\n" + age_entries if recipients else "    age: []\n"
    token = base64.b64encode(secrets.token_bytes(12)).decode()
    return (
        f"db_password: ENC[AES256_GCM,data:{token},iv:{token},tag:{token},type:str]\n"
        "name: example\n"
        "sops:\n"
        + age_block
        + '    lastmodified: "2026-01-01T00:00:00Z"\n'
        f"    mac: ENC[AES256_GCM,data:{token},iv:{token},tag:{token},type:str]\n"
        "    version: 3.13.3\n"
    )


class CheckSecretsTest(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.git("init", "--quiet")

    def git(self, *args: str) -> None:
        subprocess.run(
            ["git", "-c", "user.name=test", "-c", "user.email=test@example.invalid",
             "-c", "commit.gpgsign=false", *args],
            cwd=self.root, env=GIT_ENV, check=True, capture_output=True,
        )

    def write(self, name: str, content: str) -> None:
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def add(self, name: str, content: str, *, force: bool = False) -> None:
        self.write(name, content)
        self.git("add", *(["--force"] if force else []), "--", name)

    def run_check(self) -> tuple[int, str, str]:
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = check_secrets.main(["--root", str(self.root)])
        return code, stdout.getvalue(), stderr.getvalue()

    def assertFinding(self, rule: str, name: str) -> str:
        code, _, stderr = self.run_check()
        self.assertEqual(code, 1)
        self.assertIn(f"{rule}: {name!r}", stderr)
        return stderr

    def test_clean_index_passes(self) -> None:
        self.add("README.md", "public\n")
        self.git("commit", "--quiet", "-m", "init")
        code, stdout, stderr = self.run_check()
        self.assertEqual((code, stderr), (0, ""))
        self.assertIn("1", stdout)

    def test_plaintext_file_under_secrets_fails(self) -> None:
        self.add("secrets/panel.sops.yaml", "db_password: plaintext\n", force=True)
        self.git("commit", "--quiet", "-m", "leak")
        self.assertFinding("private-path", "secrets/panel.sops.yaml")

    def test_valid_envelope_under_secrets_still_fails_path_policy(self) -> None:
        self.add("secrets/panel.sops.yaml", sops_document(), force=True)
        stderr = self.assertFinding("private-path", "secrets/panel.sops.yaml")
        self.assertNotIn("sops-envelope", stderr)

    def test_valid_envelope_at_allowed_path_passes(self) -> None:
        self.add("ansible/vars/panel.sops.yaml", sops_document(recipients=2))
        self.add("ansible/vars/node.sops.yml", sops_document())
        code, _, stderr = self.run_check()
        self.assertEqual((code, stderr), (0, ""))

    def test_envelope_without_recipients_fails(self) -> None:
        self.add("ansible/vars/panel.sops.yaml", sops_document(recipients=0))
        self.assertFinding("sops-envelope", "ansible/vars/panel.sops.yaml")

    def test_plaintext_sops_named_file_fails(self) -> None:
        self.add("ansible/vars/panel.sops.yml", "db_password: plaintext\n")
        self.assertFinding("sops-envelope", "ansible/vars/panel.sops.yml")

    def test_envelope_without_mac_or_lastmodified_fails(self) -> None:
        for field in ("    mac:", "    lastmodified:"):
            with self.subTest(field=field):
                document = "".join(
                    line for line in sops_document().splitlines(keepends=True)
                    if not line.startswith(field)
                )
                self.add("vars.sops.yaml", document)
                self.assertFinding("sops-envelope", "vars.sops.yaml")

    def test_sops_configuration_is_not_an_envelope(self) -> None:
        self.add(".sops.yaml", "creation_rules:\n  - path_regex: x\n    age: []\n")
        code, _, stderr = self.run_check()
        self.assertEqual((code, stderr), (0, ""))

    def test_tracked_age_identity_fails(self) -> None:
        self.add("docs/notes.md", f"# key\n{fake_age_identity()}\n")
        self.git("commit", "--quiet", "-m", "leak")
        self.assertFinding("age-secret-key", "docs/notes.md")

    def test_tracked_private_key_block_fails(self) -> None:
        self.add("deploy/known.txt", fake_private_key_block())
        self.assertFinding("private-key-block", "deploy/known.txt")

    def test_ignored_but_tracked_file_fails(self) -> None:
        self.add(".gitignore", "notes.txt\n")
        self.add("ops/notes.txt", fake_age_identity() + "\n", force=True)
        self.git("commit", "--quiet", "-m", "tracked before ignore")
        self.assertFinding("age-secret-key", "ops/notes.txt")

    def test_staged_new_file_is_visible_and_untracked_is_not(self) -> None:
        self.add("README.md", "public\n")
        self.git("commit", "--quiet", "-m", "init")
        self.write("secrets/local.yaml", fake_age_identity() + "\n")
        self.write("draft.txt", fake_age_identity() + "\n")
        code, _, _ = self.run_check()
        self.assertEqual(code, 0)
        self.git("add", "draft.txt")
        self.assertFinding("age-secret-key", "draft.txt")

    def test_index_content_is_checked_not_worktree(self) -> None:
        self.add("config.txt", fake_age_identity() + "\n")
        self.write("config.txt", "cleaned in worktree only\n")
        self.assertFinding("age-secret-key", "config.txt")

    def test_output_contains_rule_and_path_only(self) -> None:
        identity = fake_age_identity()
        block = fake_private_key_block()
        self.add("secrets/plain.yaml", f"password: {identity}\n", force=True)
        self.add("notes.md", f"{identity}\n{block}")
        self.add("vars.sops.yaml", f"token: {identity}\n")
        code, stdout, stderr = self.run_check()
        self.assertEqual(code, 1)
        output = stdout + stderr
        for secret in (identity, identity[:20], block.splitlines()[1], "password"):
            self.assertNotIn(secret, output)
        findings = [line for line in stderr.splitlines() if ": '" in line]
        self.assertEqual(findings, [
            "age-secret-key: 'notes.md'",
            "private-key-block: 'notes.md'",
            "private-path: 'secrets/plain.yaml'",
            "age-secret-key: 'vars.sops.yaml'",
            "sops-envelope: 'vars.sops.yaml'",
        ])


if __name__ == "__main__":
    unittest.main()
