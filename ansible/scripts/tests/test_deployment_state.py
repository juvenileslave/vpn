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
import shutil
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
                "overlay_ipv6": "fd00:db8:1::30/128", "overlay_ipv4": "10.250.0.30/32",
                "overlay_allowed_ips": ["fd00:db8:1::30/128", "10.250.0.30/32"],
                "base_firewall_vpn_ports": [{"proto": "udp", "port": common["overlay_port"]}],
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

    def test_drift_ignores_list_order(self) -> None:
        observed = copy.deepcopy(self.state)
        observed["nodes"]["exit-example"]["node_port_allow"].reverse()
        observed["nodes"]["exit-example"]["base_firewall_vpn_ports"].reverse()
        code, _, stderr = self.run_main("--state", str(self.write_snapshot(observed)))
        self.assertEqual(code, 0, stderr)

    def test_panel_host_selection_matches_placement(self) -> None:
        playbook = Path(sys.executable).with_name("ansible-playbook")
        if not playbook.exists():
            self.skipTest("run make -C ansible bootstrap")
        environment = {
            **os.environ,
            "ANSIBLE_CONFIG": str(SCRIPTS.parent / "ansible.cfg"),
            "ANSIBLE_LOCAL_TEMP": str(self.root / "ansible-tmp"),
            "ANSIBLE_NOCOLOR": "1",
        }
        exit_root = self.root / "exit-placements" / "example"
        shutil.copytree(EXAMPLE.parent, exit_root)
        hosts = yaml.safe_load((exit_root / "hosts.yml").read_text())
        hosts["all"]["children"]["cp"] = {}
        (exit_root / "hosts.yml").write_text(yaml.safe_dump(hosts), encoding="utf-8")
        all_vars = yaml.safe_load((exit_root / "group_vars" / "all.yml").read_text())
        all_vars["cp_placement"] = "exit"
        (exit_root / "group_vars" / "all.yml").write_text(
            yaml.safe_dump(all_vars), encoding="utf-8"
        )
        (exit_root / "host_vars" / "cp-example.yml").unlink()
        playbooks = (
            "cp_proxy.yml", "panel_proxy.yml", "remnawave_panel.yml",
            "backup.yml", "victoriametrics.yml",
        )
        for case, inventory, expected_host in (
            ("dedicated", EXAMPLE, "cp-example"),
            ("exit", exit_root / "hosts.yml", "exit-example"),
        ):
            for name in playbooks:
                with self.subTest(placement=case, playbook=name):
                    result = subprocess.run(
                        [str(playbook), "-i", str(inventory),
                         str(SCRIPTS.parent / "playbooks" / name), "--list-hosts"],
                        cwd=SCRIPTS.parent,
                        env=environment,
                        capture_output=True,
                        text=True,
                        timeout=120,
                        check=False,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn(expected_host, result.stdout)
                    self.assertNotIn("hosts (0)", result.stdout)

    def test_role_defaults_match_expected_publication(self) -> None:
        playbook = Path(sys.executable).with_name("ansible-playbook")
        if not playbook.exists():
            self.skipTest("run make -C ansible bootstrap")
        output = self.root / "rendered-defaults.json"
        render = self.root / "render-defaults.yml"
        defaults = (
            SCRIPTS.parent / "roles" / "remnawave_panel" / "defaults" / "main.yml",
            SCRIPTS.parent / "roles" / "cp_proxy" / "defaults" / "main.yml",
        )
        render.write_text(yaml.safe_dump([{
            "hosts": "cp-example",
            "connection": "local",
            "gather_facts": False,
            "vars_files": [str(path) for path in defaults],
            "tasks": [{
                "name": "Render publication defaults",
                "ansible.builtin.copy": {
                    "content": (
                        "{{ {'sub_public_domain': remnawave_panel_sub_public_domain,"
                        " 'server_name': cp_proxy_server_name,"
                        " 'path_prefix': cp_proxy_path_prefix,"
                        " 'upstream': cp_proxy_upstream,"
                        " 'panel_bind': panel_bind, 'panel_port': panel_port}"
                        " | to_json }}"
                    ),
                    "dest": str(output),
                    "mode": "0600",
                },
            }],
        }]), encoding="utf-8")
        environment = {
            **os.environ,
            "ANSIBLE_CONFIG": str(SCRIPTS.parent / "ansible.cfg"),
            "ANSIBLE_LOCAL_TEMP": str(self.root / "ansible-tmp"),
            "ANSIBLE_NOCOLOR": "1",
        }
        result = subprocess.run(
            [str(playbook), "-i", str(EXAMPLE), str(render)],
            cwd=SCRIPTS.parent,
            env=environment,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        rendered = json.loads(output.read_text())
        self.assertEqual(
            rendered["sub_public_domain"], self.state["subscription"]["sub_public_domain"]
        )
        self.assertEqual(rendered["server_name"], self.state["subscription"]["server_name"])
        self.assertEqual(rendered["path_prefix"], self.state["subscription"]["path_prefix"])
        bind, port = rendered["panel_bind"], rendered["panel_port"]
        upstream = f"[{bind}]:{port}" if ":" in bind else f"{bind}:{port}"
        self.assertEqual(rendered["upstream"], upstream)

    def run_guard(
        self,
        name: str,
        override: str,
        placement: str | None,
        host: str = "cp-example",
        inventory: str | None = None,
    ) -> subprocess.CompletedProcess:
        playbook = Path(sys.executable).with_name("ansible-playbook")
        if not playbook.exists():
            self.skipTest("run make -C ansible bootstrap")
        play = self.root / f"guard-{name}.yml"
        play.write_text(yaml.safe_dump([{
            "hosts": host,
            "connection": "local",
            "gather_facts": False,
            "vars": {"panel_hosts_override": override},
            "tasks": [{
                "name": "Include only the panel-host guard",
                "ansible.builtin.include_tasks": str(
                    SCRIPTS.parent / "playbooks" / "tasks" / "require_panel_host.yml"
                ),
            }],
        }]), encoding="utf-8")
        command = [str(playbook), "-i", inventory or str(EXAMPLE)]
        if placement is not None:
            command.extend(["-e", f"cp_placement={placement}"])
        command.append(str(play))
        return subprocess.run(
            command,
            cwd=SCRIPTS.parent,
            env={
                **os.environ,
                "ANSIBLE_CONFIG": str(SCRIPTS.parent / "ansible.cfg"),
                "ANSIBLE_LOCAL_TEMP": str(self.root / "ansible-tmp"),
                "ANSIBLE_NOCOLOR": "1",
            },
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )

    def test_guard_accepts_dedicated_without_exit_group(self) -> None:
        # CI's dedicated metrics-only inventory declares cp without exit.
        root = self.root / "dedicated-no-exit" / "example"
        shutil.copytree(EXAMPLE.parent, root)
        hosts = yaml.safe_load((root / "hosts.yml").read_text())
        hosts["all"]["children"]["exit"] = {}
        hosts["all"]["children"]["relay"] = {}
        (root / "hosts.yml").write_text(yaml.safe_dump(hosts), encoding="utf-8")
        for name in ("exit-example.yml", "relay-example.yml"):
            (root / "host_vars" / name).unlink()
        result = self.run_guard(
            "dedicated-no-exit", override="", placement=None,
            inventory=str(root / "hosts.yml"),
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_guard_refuses_contradicting_placement_without_override(self) -> None:
        result = self.run_guard("contradicting", override="", placement="exit")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("не соответствует выбранной группе", result.stdout + result.stderr)

    def test_guard_accepts_matching_placement_without_override(self) -> None:
        result = self.run_guard("matching", override="", placement="dedicated")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_guard_is_skipped_for_explicit_override(self) -> None:
        # The CI ad-hoc inventory has no cp_placement and only localhost.
        missing_placement = self.run_guard(
            "adhoc", override="all", placement=None,
            host="localhost", inventory="localhost,",
        )
        self.assertEqual(missing_placement.returncode, 0,
                         missing_placement.stdout + missing_placement.stderr)
        # With cp_placement defined, an explicit override still skips the guard:
        # the operator owns consistency, as documented.
        contradicting = self.run_guard("override", override="all", placement="exit")
        self.assertEqual(contradicting.returncode, 0,
                         contradicting.stdout + contradicting.stderr)

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
