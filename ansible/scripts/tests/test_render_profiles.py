"""Render the exit/transit Xray profiles with the real playbook and check the JSON.

Every case runs ``ansible-playbook playbooks/profiles.yml`` against the
synthetic example inventory with ``connection: local``; nothing leaves the
machine. Secrets are generated per run and never written inside the repository.

The runtime check (``xray -test -config``) uses the pinned official archive.
Download it to ``.cache/xray/`` (Git-ignored) or point ``XRAY_ARCHIVE`` at it;
its SHA-256 is verified before use. Without the archive that check is skipped
and must be reported as not run. See docs/PROFILES.md.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import platform
import secrets
import shutil
import subprocess
import sys
import tempfile
from typing import Any
import unittest
import uuid
import zipfile

REPO = Path(__file__).resolve().parents[3]
ANSIBLE_DIR = REPO / "ansible"
PLAYBOOK = ANSIBLE_DIR / "playbooks" / "profiles.yml"
INVENTORY = ANSIBLE_DIR / "inventories" / "example" / "hosts.yml"

XRAY_VERSION = "v26.11.9"
# Official release assets and SHA2-256 from their published .dgst files.
XRAY_ARCHIVES = {
    ("Linux", "x86_64"): (
        "Xray-linux-64.zip",
        "b651f7e1d9966ee2c1b1ee1bf8b52c72771824d3065dce96bbc8bcc19ed95f82",
    ),
    ("Darwin", "arm64"): (
        "Xray-macos-arm64-v8a.zip",
        "233f0c66681cd0726f81a6b2b6ed6a5710869e312047b522e46ed53035bebd26",
    ),
}

EXIT_DIRECT_PORT = 8443
TRANSIT_PORT = 8444
EXAMPLE_SLOTS = 3
EXPECTED_STRATEGY = {
    "v4_prefer": ("UseIPv4v6", ["geoip:private"]),
    "v6_prefer": ("UseIPv6v4", ["geoip:private"]),
    "v4_only": ("ForceIPv4", ["geoip:private", "::/0"]),
}


def ansible_playbook() -> str | None:
    sibling = Path(sys.executable).with_name("ansible-playbook")
    return str(sibling) if sibling.is_file() else shutil.which("ansible-playbook")


def make_vars(slots: int = EXAMPLE_SLOTS, **overrides: Any) -> dict[str, Any]:
    values: dict[str, Any] = {
        "exit_direct_port": EXIT_DIRECT_PORT,
        "transit_port": TRANSIT_PORT,
        "reality_private_key": base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode(),
        "reality_short_ids": [secrets.token_hex(4), secrets.token_hex(8)],
        "exit_direct_client_ids": [str(uuid.uuid4()) for _ in range(2)],
        "transit_client_ids": [str(uuid.uuid4()) for _ in range(slots)],
    }
    values.update(overrides)
    return values


def secret_values(values: dict[str, Any]) -> list[str]:
    found = [values.get("reality_private_key")]
    for key in ("reality_short_ids", "exit_direct_client_ids", "transit_client_ids"):
        if isinstance(values.get(key), list):
            found.extend(values[key])
    return [value for value in found if isinstance(value, str) and len(value) >= 8]


def find_key(node: Any, key: str) -> bool:
    if isinstance(node, dict):
        return key in node or any(find_key(value, key) for value in node.values())
    if isinstance(node, list):
        return any(find_key(value, key) for value in node)
    return False


class RenderCase(unittest.TestCase):
    playbook: str

    @classmethod
    def setUpClass(cls) -> None:
        playbook = ansible_playbook()
        if playbook is None:
            raise unittest.SkipTest("ansible-playbook not found; run make -C ansible bootstrap")
        cls.playbook = playbook

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)

    def render(self, values: dict[str, Any], out: Path) -> subprocess.CompletedProcess[str]:
        vars_file = self.tmp / f"vars-{secrets.token_hex(4)}.json"
        vars_file.write_text(json.dumps({**values, "profiles_output_dir": str(out)}), encoding="utf-8")
        vars_file.chmod(0o600)
        home = self.tmp / "ansible-home"
        env = {
            **os.environ,
            "ANSIBLE_CONFIG": str(ANSIBLE_DIR / "ansible.cfg"),
            "ANSIBLE_HOME": str(home),
            "ANSIBLE_LOCAL_TEMP": str(home / "tmp"),
            "ANSIBLE_NOCOLOR": "1",
        }
        result = subprocess.run(
            [self.playbook, "-i", str(INVENTORY), str(PLAYBOOK), "-e", f"@{vars_file}"],
            cwd=ANSIBLE_DIR, env=env, capture_output=True, text=True, timeout=300, check=False,
        )
        output = result.stdout + result.stderr
        for value in secret_values(values):
            self.assertNotIn(value, output, "a secret value leaked into Ansible output")
        return result

    def render_ok(self, values: dict[str, Any], out: Path) -> tuple[dict[str, Any], dict[str, Any]]:
        result = self.render(values, out)
        self.assertEqual(result.returncode, 0, result.stdout[-4000:] + result.stderr[-4000:])
        return tuple(json.loads((out / f"{name}.json").read_text(encoding="utf-8")) for name in ("exit", "transit"))


class RenderProfilesTest(RenderCase):
    def assert_stream(self, inbound: dict[str, Any], values: dict[str, Any]) -> None:
        stream = inbound["streamSettings"]
        self.assertEqual(stream["network"], "xhttp")
        self.assertEqual(stream["security"], "reality")
        self.assertEqual(
            stream["xhttpSettings"],
            {"path": "/xhttp", "mode": "stream-one", "xPaddingBytes": "100-1000"},
        )
        reality = stream["realitySettings"]
        self.assertEqual(reality["dest"], "127.0.0.1:8445")
        self.assertEqual(reality["serverNames"], ["www.example.com"])
        self.assertEqual(reality["privateKey"], values["reality_private_key"])
        self.assertEqual(reality["shortIds"], values["reality_short_ids"])
        self.assertIs(reality["show"], False)
        self.assertTrue(inbound["sniffing"]["enabled"])
        self.assertEqual(inbound["settings"]["decryption"], "none")

    def assert_egress(self, profile: dict[str, Any], family: str) -> None:
        strategy, blocked = EXPECTED_STRATEGY[family]
        egress, block = profile["outbounds"]
        self.assertEqual((egress["tag"], egress["protocol"]), ("egress", "freedom"))
        self.assertEqual(egress["streamSettings"]["sockopt"]["domainStrategy"], strategy)
        self.assertEqual(egress["settings"]["finalRules"], [{"action": "block", "ip": blocked}])
        self.assertNotIn("domainStrategy", egress["settings"])
        self.assertEqual((block["tag"], block["protocol"]), ("block", "blackhole"))
        routing = profile["routing"]
        self.assertEqual(routing["domainStrategy"], "IPIfNonMatch")
        self.assertEqual(routing["rules"], [
            {"type": "field", "ip": ["geoip:private"], "outboundTag": "block"},
            {"type": "field", "protocol": ["bittorrent"], "outboundTag": "block"},
        ])

    def test_example_inventory_render(self) -> None:
        values = make_vars()
        exit_profile, transit = self.render_ok(values, self.tmp / "out")

        (direct,) = exit_profile["inbounds"]
        self.assertEqual(
            (direct["tag"], direct["protocol"], direct["listen"], direct["port"]),
            ("direct", "vless", "0.0.0.0", EXIT_DIRECT_PORT),
        )
        self.assert_stream(direct, values)
        self.assertEqual([c["id"] for c in direct["settings"]["clients"]], values["exit_direct_client_ids"])

        self.assertEqual(
            [(i["tag"], i["protocol"], i["listen"], i["port"]) for i in transit["inbounds"]],
            [("transit-v4", "vless", "0.0.0.0", TRANSIT_PORT), ("transit-v6", "vless", "::", TRANSIT_PORT)],
        )
        self.assertEqual([i["streamSettings"]["sockopt"]["v6only"] for i in transit["inbounds"]], [False, True])
        for inbound in transit["inbounds"]:
            self.assert_stream(inbound, values)
            clients = inbound["settings"]["clients"]
            self.assertEqual(len(clients), EXAMPLE_SLOTS)
            self.assertEqual([c["email"] for c in clients], ["egress-0", "egress-1", "egress-2"])
            self.assertEqual([c["id"] for c in clients], values["transit_client_ids"])

        for profile in (exit_profile, transit):
            self.assertFalse(find_key(profile, "flow"), "no client may carry flow")
            self.assert_egress(profile, "v4_prefer")

    def test_egress_family_mapping(self) -> None:
        for family in EXPECTED_STRATEGY:
            with self.subTest(family=family):
                profiles = self.render_ok(make_vars(egress_family=family), self.tmp / family)
                for profile in profiles:
                    self.assert_egress(profile, family)

    def test_transit_users_follow_egress_slots(self) -> None:
        for slots in (1, 6):
            with self.subTest(slots=slots):
                _, transit = self.render_ok(make_vars(slots=slots, egress_slots=slots), self.tmp / f"s{slots}")
                for inbound in transit["inbounds"]:
                    emails = [c["email"] for c in inbound["settings"]["clients"]]
                    self.assertEqual(emails, [f"egress-{n}" for n in range(slots)])

    def test_second_render_is_byte_identical(self) -> None:
        values = make_vars()
        out = self.tmp / "out"
        self.render_ok(values, out)
        first = {name: (out / f"{name}.json").read_bytes() for name in ("exit", "transit")}
        second = self.render(values, out)
        self.assertEqual(second.returncode, 0, second.stdout[-4000:])
        self.assertRegex(second.stdout, r"exit-example\s*:\s*ok=\d+\s+changed=0\b")
        other = self.tmp / "other"
        self.render_ok(values, other)
        for name, data in first.items():
            self.assertEqual((out / f"{name}.json").read_bytes(), data)
            self.assertEqual((other / f"{name}.json").read_bytes(), data)
            self.assertTrue(data.endswith(b"}\n") or data.endswith(b"}"))
            self.assertEqual((out / f"{name}.json").stat().st_mode & 0o777, 0o600)


class InvalidInputTest(RenderCase):
    CASES = {
        "port zero": ({"exit_direct_port": 0}, "exit_direct_port must be an integer from 1 through 65535 (got 0)"),
        "port too large": ({"transit_port": 70000}, "transit_port must be an integer from 1 through 65535 (got 70000)"),
        "port not a number": ({"transit_port": "84a4"}, 'transit_port must be an integer from 1 through 65535 (got "84a4")'),
        "port missing": ({"exit_direct_port": None}, "exit_direct_port must be an integer from 1 through 65535 (got \"<undefined>\")"),
        "same ports": ({"transit_port": EXIT_DIRECT_PORT}, "exit_direct_port and transit_port must differ"),
        "target on listener": ({"exit_direct_port": 8445}, "points at a local profile listener"),
        "slots zero": ({"egress_slots": 0}, "egress_slots must be an integer from 1 through 6"),
        "slots seven": ({"egress_slots": 7}, "egress_slots must be an integer from 1 through 6"),
        "slots vs ids": ({"egress_slots": 4}, "transit_client_ids must contain exactly egress_slots (4) UUIDs"),
        "family": ({"egress_family": "v6_only"}, 'egress_family must be one of v4_prefer, v6_prefer, v4_only (got "v6_only")'),
        "xhttp mode": ({"xhttp_mode": "packet-up"}, "the exit profiles require xhttp_mode stream-one"),
        "short id": ({"reality_short_ids": ["xyz"]}, "reality_short_ids must be a non-empty list"),
        "client uuid": ({"exit_direct_client_ids": ["not-a-uuid"]}, "exit_direct_client_ids must be a non-empty list"),
        "private key": ({"reality_private_key": "short"}, "reality_private_key must be supplied"),
    }

    def test_invalid_inputs_fail_before_rendering(self) -> None:
        for name, (overrides, message) in self.CASES.items():
            with self.subTest(case=name):
                values = make_vars(**overrides)
                if overrides.get("exit_direct_port", 1) is None:
                    del values["exit_direct_port"]
                out = self.tmp / name.replace(" ", "-")
                result = self.render(values, out)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, " ".join(result.stdout.split()))
                self.assertFalse(out.exists(), "nothing may be written when validation fails")


class XrayRuntimeTest(RenderCase):
    """``xray -test -config`` with the pinned, checksum-verified official binary."""

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        asset = XRAY_ARCHIVES.get((platform.system(), platform.machine()))
        if asset is None:
            raise unittest.SkipTest(f"no pinned Xray {XRAY_VERSION} archive for this platform; runtime check not run")
        name, digest = asset
        archive = Path(os.environ.get("XRAY_ARCHIVE", REPO / ".cache" / "xray" / name))
        if not archive.is_file():
            raise unittest.SkipTest(f"{archive} not found; xray -test runtime check not run (see docs/PROFILES.md)")
        actual = hashlib.sha256(archive.read_bytes()).hexdigest()
        if actual != digest:
            raise AssertionError(f"{archive}: SHA-256 {actual} does not match pinned {XRAY_VERSION} digest {digest}")
        tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(tmp.cleanup)
        cls.xray_dir = Path(tmp.name)
        with zipfile.ZipFile(archive) as bundle:
            for member in ("xray", "geoip.dat", "geosite.dat"):
                bundle.extract(member, cls.xray_dir)
        (cls.xray_dir / "xray").chmod(0o755)
        version = subprocess.run([str(cls.xray_dir / "xray"), "version"], capture_output=True, text=True, check=True)
        if not version.stdout.startswith(f"Xray {XRAY_VERSION.lstrip('v')} "):
            raise AssertionError(f"unexpected Xray version: {version.stdout.splitlines()[:1]}")

    def test_rendered_profiles_pass_xray_test(self) -> None:
        env = {**os.environ, "XRAY_LOCATION_ASSET": str(self.xray_dir)}
        for family in EXPECTED_STRATEGY:
            out = self.tmp / family
            self.render_ok(make_vars(egress_family=family), out)
            for name in ("exit", "transit"):
                with self.subTest(family=family, profile=name):
                    result = subprocess.run(
                        [str(self.xray_dir / "xray"), "-test", "-config", str(out / f"{name}.json")],
                        env=env, capture_output=True, text=True, timeout=60, check=False,
                    )
                    output = result.stdout + result.stderr
                    self.assertEqual(result.returncode, 0, output[-4000:])
                    self.assertIn("Configuration OK", output)
                    self.assertNotIn("deprecated", output.lower())


if __name__ == "__main__":
    unittest.main()
