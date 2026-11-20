"""Offline managed-state drift and composed entrypoint tests.

The expected state is derived from the validated inventory; the observed
snapshot is synthetic. No host, panel, DNS or Docker daemon is contacted.
"""

from __future__ import annotations

import copy
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

import yaml

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))

import validate_inventory  # noqa: E402

EXAMPLE = SCRIPTS.parent / "inventories" / "example" / "hosts.yml"
ENTRYPOINT = SCRIPTS.parent / "playbooks" / "site.yml"


class ManagedStateDriftTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        inventory = validate_inventory.validate(EXAMPLE)
        self.assertEqual(inventory.errors, [])
        self.state = validate_inventory.expected_state(inventory)

    def run_main(self, *arguments: str) -> tuple[int, str, str]:
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = validate_inventory.main(["--inventory", str(EXAMPLE), *arguments])
        return code, stdout.getvalue(), stderr.getvalue()

    def write_snapshot(self, state: dict, name: str = "observed.json") -> Path:
        path = self.root / name
        path.write_text(json.dumps(state, indent=2, sort_keys=True), encoding="utf-8")
        return path

    def test_expected_state_is_deterministic_and_contract_only(self) -> None:
        again = validate_inventory.expected_state(validate_inventory.validate(EXAMPLE))
        self.assertEqual(self.state, again)
        self.assertEqual(self.state["panel_host"], "cp-example")
        self.assertEqual(
            self.state["subscription"],
            {
                "host": "sub.example.com",
                "path": "/sub/",
                "server_name": "sub.example.com",
                "path_prefix": "/sub/",
                "sub_public_domain": "sub.example.com/sub",
            },
        )
        self.assertEqual(set(self.state["nodes"]), {"exit-example", "relay-example"})
        self.assertEqual(self.state["nodes"]["exit-example"]["api_port"], 2223)
        self.assertEqual(validate_inventory.state_drift(self.state, self.state), [])

    def test_written_baseline_is_byte_stable_and_has_no_drift(self) -> None:
        path = self.root / "state" / "expected.json"
        first_code, _, first_err = self.run_main("--write-expected", str(path))
        self.assertEqual(first_code, 0, first_err)
        first = path.read_bytes()
        second_code, _, second_err = self.run_main("--write-expected", str(path))
        self.assertEqual(second_code, 0, second_err)
        self.assertEqual(first, path.read_bytes())
        code, stdout, stderr = self.run_main("--state", str(path))
        self.assertEqual(code, 0, stderr)
        self.assertIn("State OK", stdout)

    def test_yaml_snapshot_is_accepted(self) -> None:
        path = self.root / "observed.yml"
        path.write_text(yaml.safe_dump(self.state), encoding="utf-8")
        code, stdout, stderr = self.run_main("--state", str(path))
        self.assertEqual(code, 0, stderr)
        self.assertIn("State OK", stdout)

    def test_drift_is_reported_by_path_without_values(self) -> None:
        observed = copy.deepcopy(self.state)
        observed["nodes"]["exit-example"]["api_port"] = 2222
        observed["nodes"]["relay-example"].pop("cover_tls_port")
        observed["subscription"]["host"] = "drift.example.com"
        observed["nodes"]["extra-example"] = copy.deepcopy(observed["nodes"]["exit-example"])
        path = self.write_snapshot(observed)
        code, _, stderr = self.run_main("--state", str(path))
        self.assertEqual(code, 1)
        self.assertIn("State drift:", stderr)
        self.assertIn("nodes.exit-example.api_port: mismatch", stderr)
        self.assertIn("nodes.relay-example.cover_tls_port: missing", stderr)
        self.assertIn("subscription.host: mismatch", stderr)
        self.assertIn("nodes.extra-example: extra", stderr)
        for value in ("2222", "drift.example.com"):
            self.assertNotIn(value, stderr, "drift output must not disclose values")

    def test_extra_leaf_field_is_drift(self) -> None:
        observed = copy.deepcopy(self.state)
        observed["subscription"]["one_off_setting"] = "manual"
        code, _, stderr = self.run_main("--state", str(self.write_snapshot(observed)))
        self.assertEqual(code, 1)
        self.assertIn("subscription.one_off_setting: extra", stderr)

    def test_invalid_snapshot_schema_is_refused(self) -> None:
        for snapshot, fragment in (
            ({"schema": 2}, "schema must be 1"),
            ({"schema": 1, "subscription": []}, "section 'subscription'"),
            ([], "must be a mapping"),
        ):
            with self.subTest(snapshot=snapshot):
                code, _, stderr = self.run_main("--state", str(self.write_snapshot(snapshot)))
                self.assertEqual(code, 2)
                self.assertIn("Invalid state snapshot", stderr)
                self.assertIn(fragment, stderr)

    def test_invalid_inventory_refuses_before_drift(self) -> None:
        broken = self.root / "broken"
        (broken / "group_vars").mkdir(parents=True)
        (broken / "hosts.yml").write_text("all: {children: {}}\n", encoding="utf-8")
        stderr = io.StringIO()
        with redirect_stderr(stderr), redirect_stdout(io.StringIO()):
            code = validate_inventory.main([
                "--inventory", str(broken / "hosts.yml"),
                "--state", str(self.write_snapshot(self.state)),
            ])
        self.assertEqual(code, 1)
        self.assertIn("Inventory invalid", stderr.getvalue())
        self.assertNotIn("State drift", stderr.getvalue())

    def test_profiles_fixture_topology_composes_with_validator(self) -> None:
        sys.path.insert(0, str(SCRIPTS.parent / "roles" / "profiles" / "tests"))
        from fixtures import bundle, inputs  # noqa: E402

        topology, secret = inputs()
        common = yaml.safe_load((EXAMPLE.parent / "group_vars" / "all.yml").read_text())
        root = self.root / "composed" / "example"
        (root / "group_vars").mkdir(parents=True)
        (root / "host_vars").mkdir()
        hosts = {
            "exit": {"exit-test": {key: value for key, value in topology["exit"].items()
                                   if key not in common}},
            "relay": {"relay-test": {key: value for key, value in topology["relay"].items()
                                     if key not in common}},
            "cp": {"cp-test": {
                "ansible_host": "203.0.113.30", "public_ipv4": "203.0.113.30",
                "public_ipv6": "2001:db8:30::30", "node_role": "control_plane",
            }},
        }
        (root / "hosts.yml").write_text(
            yaml.safe_dump({"all": {"children": {
                group: {"hosts": members} for group, members in hosts.items()
            }}}),
            encoding="utf-8",
        )
        (root / "group_vars" / "all.yml").write_text(yaml.safe_dump(common), encoding="utf-8")
        (root / "group_vars" / "cp.yml").write_text(
            yaml.safe_dump({"panel_bind": "127.0.0.1"}), encoding="utf-8"
        )
        inventory = validate_inventory.validate(root / "hosts.yml")
        self.assertEqual(inventory.errors, [])
        state = validate_inventory.expected_state(inventory)
        self.assertEqual(state["panel_host"], "cp-test")
        _, files = bundle.render(topology=topology, secret=secret)
        firewall = json.loads(files["firewall.json"])
        for kind, host in (("exit", "exit-test"), ("relay", "relay-test")):
            node = state["nodes"][host]
            self.assertEqual(node["api_port"], topology[kind]["node_api_port"])
            self.assertEqual(node["cover_tls_port"], topology[kind]["cover_tls_port"])
            self.assertEqual(node["reality_sni"], topology[kind]["reality_sni"])
            self.assertEqual(
                sorted(f"{item['proto']}/{item['port']}"
                       for item in firewall[kind]["base_firewall_vpn_ports"]),
                node["base_firewall_vpn_ports"],
            )

    def test_composed_entrypoint_syntax(self) -> None:
        playbook = Path(sys.executable).with_name("ansible-playbook")
        if not playbook.exists():
            self.skipTest("run make -C ansible bootstrap")
        environment = {
            **os.environ,
            "ANSIBLE_CONFIG": str(SCRIPTS.parent / "ansible.cfg"),
            "ANSIBLE_LOCAL_TEMP": str(self.root / "ansible-tmp"),
            "ANSIBLE_NOCOLOR": "1",
        }
        result = subprocess.run(
            [str(playbook), "-i", str(EXAMPLE), str(ENTRYPOINT), "--syntax-check"],
            cwd=SCRIPTS.parent,
            env=environment,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
