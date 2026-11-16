"""Unit tests for the bootstrap-only validation filters (no host changes)."""

from __future__ import annotations

import base64
import importlib.util
import os
from pathlib import Path
import struct
import unittest

PLUGIN = Path(__file__).resolve().parents[1] / "filter_plugins" / "bootstrap.py"
_spec = importlib.util.spec_from_file_location("bootstrap_filters", PLUGIN)
bootstrap = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bootstrap)

PRIVATE_MARKER = "-----BEGIN OPENSSH " + "PRIVATE KEY-----"


def _string(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


def ed25519_key(comment: str = "test") -> str:
    blob = _string(b"ssh-ed25519") + _string(os.urandom(32))
    return f"ssh-ed25519 {base64.b64encode(blob).decode()} {comment}"


class AdminValidationTest(unittest.TestCase):
    def test_valid_admin_uses_the_base_rules(self):
        self.assertEqual(
            bootstrap.admin_errors([{"name": "opsadmin", "authorized_keys": [ed25519_key()]}]),
            [],
        )

    def test_reserved_and_malformed_admins_are_rejected(self):
        for user in (
            {"name": "root", "authorized_keys": [ed25519_key()]},
            {"name": "opsadmin", "authorized_keys": [PRIVATE_MARKER]},
            {"name": "opsadmin", "authorized_keys": [ed25519_key()], "unexpected": True},
        ):
            with self.subTest(user=user["name"]):
                self.assertNotEqual(bootstrap.admin_errors([user]), [])


class KeyMatchTest(unittest.TestCase):
    def test_derived_key_must_match_a_declared_key(self):
        declared = ed25519_key("opsadmin@workstation")
        public_line = " ".join(declared.split()[:2])
        self.assertTrue(bootstrap.key_matches(public_line, [declared]))
        self.assertFalse(bootstrap.key_matches(ed25519_key(), [declared]))
        self.assertFalse(bootstrap.key_matches("not-a-key", [declared]))
        self.assertFalse(bootstrap.key_matches(public_line, []))


class SshOptionsTest(unittest.TestCase):
    def test_safe_options_are_accepted(self):
        value = ('-o ProxyJump=ops@jump.example.com:2222 '
                 '-o UserKnownHostsFile=/tmp/known_hosts '
                 '-o ConnectTimeout=10')
        self.assertEqual(bootstrap.ssh_args_problems(value), [])
        self.assertEqual(bootstrap.ssh_args(value)[0], "-o")
        self.assertIn("ProxyJump=ops@jump.example.com:2222", bootstrap.ssh_args(value))

    def test_quoted_proxy_command_is_not_mistaken_for_a_port_flag(self):
        value = '-o "ProxyCommand=ssh -p 2200 jump nc %h %p"'
        self.assertEqual(bootstrap.ssh_args_problems(value), [])

    def test_weakening_and_override_options_are_rejected(self):
        cases = (
            "-o StrictHostKeyChecking=no",
            "-o StrictHostKeyChecking=off",
            "-oStrictHostKeyChecking=false",
            "-oStrictHostKeyChecking=accept-new",
            "-o UserKnownHostsFile=/dev/null",
            "-o UserKnownHostsFile=none",
            "-o GlobalKnownHostsFile=/dev/null",
            '-o "PasswordAuthentication yes"',
            "-o PreferredAuthentications=password,publickey",
            "-i /tmp/other_key",
            "-o IdentityFile=/tmp/other_key",
            "-F /tmp/ssh_config",
            "-p 2222",
            "-p2222",
            "-l root",
            "-o User=root",
            "-o Port=2222",
            "-o Hostname=evil.example.com",
        )
        for value in cases:
            with self.subTest(value=value):
                self.assertNotEqual(bootstrap.ssh_args_problems(value), [])

    def test_non_string_and_bad_quoting_are_rejected(self):
        self.assertNotEqual(bootstrap.ssh_args_problems(42), [])
        self.assertNotEqual(bootstrap.ssh_args_problems("-o 'unterminated"), [])


class ListenerTest(unittest.TestCase):
    def test_private_panel_is_accepted(self):
        ss = "\n".join([
            "tcp LISTEN 0 4096 127.0.0.1:3000 0.0.0.0:*",
            "tcp LISTEN 0 4096 0.0.0.0:22 0.0.0.0:*",
        ])
        self.assertEqual(bootstrap.listener_problems(ss, "127.0.0.1", 3000, [5432, 6379]), [])

    def test_netid_less_ss_output_is_parsed(self):
        # ``ss -H -l -n -t`` prints no Netid column; this is the real layout.
        ss = "\n".join([
            "LISTEN 0      4096   127.0.0.1:3000       0.0.0.0:*",
            "LISTEN 0      4096         0.0.0.0:22         0.0.0.0:*",
        ])
        self.assertEqual(bootstrap.listener_problems(ss, "127.0.0.1", 3000, [5432, 6379]), [])
        wildcard = "LISTEN 0      1                  *:3000            *:*"
        self.assertNotEqual(bootstrap.listener_problems(wildcard, "127.0.0.1", 3000), [])
        published_db = ss + "\nLISTEN 0 4096 0.0.0.0:6379 0.0.0.0:*"
        problems = bootstrap.listener_problems(published_db, "127.0.0.1", 3000, [5432, 6379])
        self.assertTrue(any("6379" in problem for problem in problems))

    def test_ipv6_loopback_is_accepted(self):
        ss = "tcp LISTEN 0 4096 [::1]:3000 [::]:*"
        self.assertEqual(bootstrap.listener_problems(ss, "::1", 3000), [])

    def test_wildcard_missing_and_database_ports_are_rejected(self):
        wildcard = "tcp LISTEN 0 4096 0.0.0.0:3000 0.0.0.0:*"
        self.assertNotEqual(bootstrap.listener_problems(wildcard, "127.0.0.1", 3000), [])
        self.assertNotEqual(bootstrap.listener_problems("", "127.0.0.1", 3000), [])
        published_db = "\n".join([
            "tcp LISTEN 0 4096 127.0.0.1:3000 0.0.0.0:*",
            "tcp LISTEN 0 4096 0.0.0.0:5432 0.0.0.0:*",
        ])
        problems = bootstrap.listener_problems(published_db, "127.0.0.1", 3000, [5432, 6379])
        self.assertTrue(any("5432" in problem for problem in problems))

    def test_panel_url_brackets_ipv6(self):
        self.assertEqual(bootstrap.panel_url("127.0.0.1", 3000), "http://127.0.0.1:3000/")
        self.assertEqual(bootstrap.panel_url("::1", 3000), "http://[::1]:3000/")


if __name__ == "__main__":
    unittest.main()
