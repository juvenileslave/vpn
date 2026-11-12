"""Run the real base playbook against localhost for validation-only scenarios.

Every scenario here must stop in validation/preflight or run with all
management disabled, so the host is not modified. Requires passwordless
sudo (or root) and a Debian/Ubuntu host.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

from test_filters import PRIVATE_MARKER, ed25519_key

ANSIBLE_DIR = Path(__file__).resolve().parents[3]
PLAYBOOK = ANSIBLE_DIR / "playbooks" / "base.yml"
ANSIBLE_PLAYBOOK = Path(sys.executable).with_name("ansible-playbook")
RECAP = re.compile(r"^localhost\s*:\s*ok=(\d+)\s+changed=(\d+)\s+unreachable=(\d+)\s+failed=(\d+)", re.M)
DISABLED = {
    "base_chrony_enabled": False,
    "base_unattended_upgrades_enabled": False,
    "base_bbr_enabled": False,
    "base_swap_enabled": False,
    "base_ssh_enabled": False,
    "base_firewall_enabled": False,
}
OWNED_PATHS = [
    "/etc/ssh/sshd_config.d/00-vpn-base.conf",
    "/etc/vpn-base",
    "/etc/systemd/system/vpn-base-firewall.service",
    "/etc/sudoers.d/vpn-base",
    "/etc/apt/apt.conf.d/52vpn-base-unattended-upgrades",
    "/etc/sysctl.d/90-vpn-base-bbr.conf",
]


def setUpModule():
    if sys.platform != "linux":
        raise unittest.SkipTest("Local Ansible scenarios require a Debian/Ubuntu Linux host")
    release = dict(line.split("=", 1) for line in Path("/etc/os-release").read_text().splitlines()
                   if "=" in line)
    if release.get("ID", "").strip('"') not in ("debian", "ubuntu"):
        raise unittest.SkipTest("Local Ansible scenarios require Debian or Ubuntu")
    if os.geteuid() != 0:
        try:
            result = subprocess.run(["sudo", "-n", "true"], capture_output=True, timeout=5)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            raise unittest.SkipTest("Local Ansible scenarios require root or passwordless sudo")
        if result.returncode != 0:
            raise unittest.SkipTest("Local Ansible scenarios require root or passwordless sudo")


def run_playbook(extra_vars: dict, *args: str) -> tuple[int, str, tuple[int, ...]]:
    with tempfile.TemporaryDirectory() as tmp:
        vars_file = Path(tmp) / "vars.json"
        vars_file.write_text(json.dumps(extra_vars), encoding="utf-8")
        env = dict(os.environ, ANSIBLE_CONFIG=str(ANSIBLE_DIR / "ansible.cfg"),
                   ANSIBLE_NOCOLOR="1", ANSIBLE_FORCE_COLOR="0")
        result = subprocess.run(
            [str(ANSIBLE_PLAYBOOK), "-i", "localhost,", "-c", "local",
             "-e", "ansible_python_interpreter=/usr/bin/python3",
             "-e", f"@{vars_file}", str(PLAYBOOK), *args],
            cwd=ANSIBLE_DIR, env=env, capture_output=True, text=True, timeout=600,
        )
    output = result.stdout + result.stderr
    match = RECAP.search(output)
    recap = tuple(int(value) for value in match.groups()) if match else ()
    return result.returncode, output, recap


class RejectionTest(unittest.TestCase):
    def setUp(self):
        self.before = {path: os.path.exists(path) for path in OWNED_PATHS}

    def tearDown(self):
        self.assertEqual({path: os.path.exists(path) for path in OWNED_PATHS}, self.before)

    def assert_rejected(self, extra_vars: dict, message: str):
        rc, output, recap = run_playbook(dict(DISABLED, **extra_vars))
        self.assertNotEqual(rc, 0, output)
        self.assertTrue(recap, output)
        self.assertEqual(recap[1], 0, "no task may report changed")
        self.assertEqual(recap[3], 1, output)
        self.assertIn(message, output)
        return output

    def test_invalid_admin_name(self):
        self.assert_rejected(
            {"base_admin_users": [{"name": "root", "authorized_keys": [ed25519_key()]}]},
            "base_admin_users[0].name")

    def test_private_key_material_is_rejected_and_not_echoed(self):
        secret = PRIVATE_MARKER + " c2VjcmV0LW1hdGVyaWFs"
        output = self.assert_rejected(
            {"base_admin_users": [{"name": "opsadmin", "authorized_keys": [secret]}]},
            "base_admin_users[0].authorized_keys[0]")
        self.assertNotIn("c2VjcmV0LW1hdGVyaWFs", output)

    def test_ssh_without_admin_key(self):
        self.assert_rejected({"base_ssh_enabled": True}, "base_ssh_enabled:")

    def test_firewall_without_cidrs(self):
        self.assert_rejected({"base_firewall_enabled": True}, "base_ssh_trusted_cidrs")

    def test_cidr_with_host_bits(self):
        self.assert_rejected(
            {"base_firewall_enabled": True, "base_ssh_trusted_cidrs": ["192.0.2.1/24"]},
            "base_ssh_trusted_cidrs[0]")

    def test_world_cidr(self):
        self.assert_rejected(
            {"base_firewall_enabled": True, "base_ssh_trusted_cidrs": ["::/0"]},
            "base_ssh_trusted_cidrs[0]")

    def test_string_toggle(self):
        self.assert_rejected({"base_firewall_enabled": "false"}, "base_firewall_enabled")

    def test_invalid_restricted_ports_fail_before_mutation_without_echo(self):
        for cidr in ("198.51.100.77/24", "0.0.0.0/0", "2001:db8::/31", "invalid"):
            with self.subTest(cidr=cidr):
                output = self.assert_rejected({"base_firewall_source_ports": [
                    {"proto": "tcp", "port": 8443, "source_cidrs": [cidr]}]},
                    "base_firewall_source_ports[0].source_cidrs[0]")
                self.assertNotIn(cidr, output)
        self.assert_rejected({"base_firewall_source_ports": [
            {"proto": "tcp", "port": 8443, "source_cidrs": []}]}, "source_cidrs")
        self.assert_rejected({
            "base_firewall_source_ports": [{"proto": "tcp", "port": 8443,
                                            "source_cidrs": ["198.51.100.77/32"]}],
            "base_firewall_vpn_ports": [{"proto": "tcp", "port": 8443}],
        }, "конфликт")


class DisabledManagementTest(unittest.TestCase):
    def test_all_management_disabled_is_a_no_op(self):
        before = {path: os.path.exists(path) for path in OWNED_PATHS}
        rc, output, recap = run_playbook(dict(DISABLED, base_firewall_source_ports=[
            {"proto": "tcp", "port": 8443, "source_cidrs": ["192.0.2.2/32"]}]))
        self.assertEqual(rc, 0, output)
        self.assertEqual(recap[1:], (0, 0, 0), output)
        self.assertEqual({path: os.path.exists(path) for path in OWNED_PATHS}, before)

    def test_check_mode_is_a_no_op(self):
        rc, output, recap = run_playbook(dict(DISABLED), "--check", "--diff")
        self.assertEqual(rc, 0, output)
        self.assertEqual(recap[1:], (0, 0, 0), output)


if __name__ == "__main__":
    unittest.main()
