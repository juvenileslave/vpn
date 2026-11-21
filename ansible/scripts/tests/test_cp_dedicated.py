"""Offline dedicated control-plane contract regression tests (issue #76).

All checks are static or run against temporary synthetic inventories and
templates. No remote host, DNS, ACME, Docker daemon or live database is used.
"""

from __future__ import annotations

import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

import jinja2
import yaml

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))

import validate_inventory  # noqa: E402

ANSIBLE_ROOT = SCRIPTS.parent
EXAMPLE = ANSIBLE_ROOT / "inventories" / "example" / "hosts.yml"
PLAYBOOKS = ANSIBLE_ROOT / "playbooks"
PANEL_COMPOSE_TEMPLATE = (
    ANSIBLE_ROOT / "roles" / "remnawave_panel" / "templates" / "compose.yaml.j2"
)
PANEL_PROXY_TEMPLATE = (
    ANSIBLE_ROOT / "roles" / "panel_proxy" / "templates" / "panel_proxy.conf.j2"
)


class DedicatedControlPlaneTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.inventory = validate_inventory.validate(EXAMPLE)
        self.assertEqual(self.inventory.errors, [])
        self.state = validate_inventory.expected_state(self.inventory)

    def ansible_playbook(self) -> Path:
        playbook = Path(sys.executable).with_name("ansible-playbook")
        if not playbook.exists():
            self.skipTest("run make -C ansible bootstrap")
        return playbook

    def run_playbook(self, args: list[str]) -> subprocess.CompletedProcess:
        playbook = self.ansible_playbook()
        environment = {
            **os.environ,
            "ANSIBLE_CONFIG": str(ANSIBLE_ROOT / "ansible.cfg"),
            "ANSIBLE_LOCAL_TEMP": str(self.root / "ansible-tmp"),
            "ANSIBLE_NOCOLOR": "1",
        }
        return subprocess.run(
            [str(playbook), *args],
            cwd=ANSIBLE_ROOT,
            env=environment,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )

    def test_dedicated_topology_contract(self) -> None:
        cp_hosts = list(self.inventory.groups["cp"])
        exit_hosts = list(self.inventory.groups["exit"])
        self.assertEqual(cp_hosts, ["cp-example"])
        self.assertEqual(len(exit_hosts), 1)
        self.assertNotIn("cp-example", exit_hosts)
        self.assertEqual(self.inventory.placement, "dedicated")
        self.assertEqual(self.state["panel_host"], "cp-example")

    def test_panel_access_templates_are_loopback_only(self) -> None:
        env = jinja2.Environment(
            autoescape=False,
            undefined=jinja2.StrictUndefined,
        )
        env.filters["to_json"] = json.dumps

        compose_template = env.from_string(
            PANEL_COMPOSE_TEMPLATE.read_text(encoding="utf-8")
        )
        for bind in ("127.0.0.1", "::1"):
            with self.subTest(template="compose.yaml.j2", panel_bind=bind):
                rendered = compose_template.render(
                    remnawave_panel_project="remnawave",
                    remnawave_panel_images={
                        "remnawave_panel": "remnawave/backend",
                        "postgres": "postgres",
                        "valkey": "valkey/valkey",
                    },
                    image_tags={
                        "remnawave_panel": "3.4.10",
                        "postgres": "18.6",
                        "valkey": "9.1.3-alpine",
                    },
                    remnawave_panel_front_end_domain="127.0.0.1",
                    remnawave_panel_sub_public_domain="sub.example.com/sub",
                    panel_bind=bind,
                    panel_port=3000,
                    remnawave_panel_label_key="io.github.juvenileslave.vpn.managed-by",
                    remnawave_panel_label_value="remnawave_panel",
                )
                compose = yaml.safe_load(rendered)
                services = compose["services"]
                panel_ports = services["remnawave"]["ports"]
                self.assertEqual(len(panel_ports), 1)
                self.assertTrue(
                    ipaddress.ip_address(panel_ports[0]["host_ip"]).is_loopback
                )
                self.assertEqual(str(panel_ports[0]["published"]), "3000")
                self.assertNotIn("ports", services["remnawave-db"])
                self.assertNotIn("ports", services["remnawave-redis"])
                self.assertTrue(compose["networks"]["backend"]["internal"])

        proxy_template = env.from_string(
            PANEL_PROXY_TEMPLATE.read_text(encoding="utf-8")
        )
        for listen_address, upstream in (
            ("127.0.0.1", "127.0.0.1:3000"),
            ("[::1]", "[::1]:3000"),
        ):
            with self.subTest(template="panel_proxy.conf.j2", listen=listen_address):
                rendered = proxy_template.render(
                    panel_proxy_marker="Managed by Ansible role panel_proxy",
                    panel_proxy_listen_address=listen_address,
                    panel_proxy_port=7443,
                    panel_proxy_server_name="localhost",
                    panel_proxy_client_max_body_size="16m",
                    panel_proxy_upstream=upstream,
                    panel_proxy_forwarded_proto="https",
                    panel_proxy_client_type="browser",
                    panel_proxy_proxy_connect_timeout="10s",
                    panel_proxy_proxy_send_timeout="60s",
                    panel_proxy_proxy_read_timeout="60s",
                )
                active_lines = [
                    line.strip()
                    for line in rendered.splitlines()
                    if line.strip() and not line.strip().startswith("#")
                ]
                listen_lines = [
                    line for line in active_lines if line.startswith("listen ")
                ]
                self.assertEqual(len(listen_lines), 1)
                match = re.fullmatch(
                    r"listen\s+(\[[^\]]+\]|[^:\s]+):(\d+);", listen_lines[0]
                )
                self.assertIsNotNone(match, listen_lines[0])
                listen_ip = ipaddress.ip_address(match.group(1).strip("[]"))
                self.assertTrue(listen_ip.is_loopback)
                self.assertFalse(
                    any("ssl_" in line for line in active_lines),
                    "panel_proxy must not declare ssl_* directives",
                )
                self.assertIn(f"proxy_pass http://{upstream};", active_lines)

    def test_node_management_acl_and_private_api_port(self) -> None:
        cp_values = self.inventory.effective("cp", "cp-example")
        cp_cidrs = {
            str(ipaddress.ip_network(f"{cp_values['public_ipv4'][0]}/32", strict=True)),
            str(ipaddress.ip_network(f"{cp_values['public_ipv6'][0]}/128", strict=True)),
        }
        for group, host in (("exit", "exit-example"), ("relay", "relay-example")):
            with self.subTest(group=group, host=host):
                node_state = self.state["nodes"][host]
                allow_set = set(node_state["node_port_allow"])
                self.assertTrue(cp_cidrs.issubset(allow_set))
                self.assertFalse(
                    all(
                        ipaddress.ip_network(cidr, strict=True).is_loopback
                        for cidr in allow_set
                    )
                )

                api_port = node_state["api_port"]
                vpn_ports = node_state["base_firewall_vpn_ports"]
                self.assertFalse(
                    any(entry.split("/", 1)[1] == str(api_port) for entry in vpn_ports),
                    f"node_api_port {api_port} must not appear in base_firewall_vpn_ports",
                )

                node_values = self.inventory.effective(group, host)
                source_rules = node_values["base_firewall_source_ports"][0]
                matches = [
                    rule
                    for rule in source_rules
                    if isinstance(rule, dict) and rule.get("port") == api_port
                ]
                self.assertEqual(len(matches), 1)
                self.assertEqual(matches[0].get("proto"), "tcp")
                rule_cidrs = {
                    str(ipaddress.ip_network(cidr, strict=True))
                    for cidr in matches[0]["source_cidrs"]
                }
                self.assertEqual(rule_cidrs, allow_set)

    def test_dns_boundary_independent_of_exit_addresses(self) -> None:
        dns_root = self.root / "dns-boundary" / "example"
        shutil.copytree(EXAMPLE.parent, dns_root)
        hosts_path = dns_root / "hosts.yml"
        hosts = yaml.safe_load(hosts_path.read_text(encoding="utf-8"))
        exit_host = hosts["all"]["children"]["exit"]["hosts"]["exit-example"]
        exit_host["ansible_host"] = "192.0.2.99"
        exit_host["public_ipv4"] = "192.0.2.99"
        exit_host["public_ipv6"] = "2001:db8:10::99"
        hosts_path.write_text(yaml.safe_dump(hosts), encoding="utf-8")
        exit_vars_path = dns_root / "host_vars" / "exit-example.yml"
        exit_vars = yaml.safe_load(exit_vars_path.read_text(encoding="utf-8"))
        exit_vars["ansible_host"] = "192.0.2.99"
        exit_vars["public_ipv4"] = "192.0.2.99"
        exit_vars["public_ipv6"] = "2001:db8:10::99"
        exit_vars_path.write_text(yaml.safe_dump(exit_vars), encoding="utf-8")

        mutated = validate_inventory.validate(hosts_path)
        self.assertEqual(mutated.errors, [])
        mutated_state = validate_inventory.expected_state(mutated)
        self.assertEqual(mutated_state["panel_host"], "cp-example")
        self.assertEqual(mutated_state["panel_host"], self.state["panel_host"])
        self.assertEqual(mutated_state["subscription"], self.state["subscription"])

    def test_dedicated_playbooks_select_cp_without_exit_or_relay(self) -> None:
        self.ansible_playbook()
        cp_only = self.root / "cp-only" / "example"
        shutil.copytree(EXAMPLE.parent, cp_only)
        hosts_path = cp_only / "hosts.yml"
        hosts = yaml.safe_load(hosts_path.read_text(encoding="utf-8"))
        hosts["all"]["children"]["exit"] = {}
        hosts["all"]["children"]["relay"] = {}
        hosts_path.write_text(yaml.safe_dump(hosts), encoding="utf-8")
        for host_vars in ("exit-example.yml", "relay-example.yml"):
            path = cp_only / "host_vars" / host_vars
            if path.exists():
                path.unlink()

        for name in ("backup.yml", "panel_proxy.yml", "cp_proxy.yml"):
            with self.subTest(playbook=name):
                result = self.run_playbook([
                    "-i", str(hosts_path),
                    str(PLAYBOOKS / name),
                    "--list-hosts",
                ])
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("cp-example", result.stdout)
                self.assertNotIn("exit-example", result.stdout)
                self.assertNotIn("hosts (0)", result.stdout)

    def test_restore_playbook_guards_confirmation_and_artifact(self) -> None:
        self.ansible_playbook()
        no_confirm = self.run_playbook([
            "-i", "localhost,",
            "-c", "local",
            str(PLAYBOOKS / "restore.yml"),
            "-e", "cp_restore_hosts=localhost",
        ])
        self.assertNotEqual(no_confirm.returncode, 0)
        self.assertIn("cp_restore_confirm", no_confirm.stdout + no_confirm.stderr)

        no_artifact = self.run_playbook([
            "-i", "localhost,",
            "-c", "local",
            str(PLAYBOOKS / "restore.yml"),
            "-e", "cp_restore_hosts=localhost",
            "-e", "cp_restore_confirm=true",
        ])
        self.assertNotEqual(no_artifact.returncode, 0)

    def test_rollback_exit_placement_contract_and_selection(self) -> None:
        exit_root = self.root / "rollback-exit" / "example"
        shutil.copytree(EXAMPLE.parent, exit_root)
        hosts_path = exit_root / "hosts.yml"
        hosts = yaml.safe_load(hosts_path.read_text(encoding="utf-8"))
        hosts["all"]["children"]["cp"] = {}
        hosts_path.write_text(yaml.safe_dump(hosts), encoding="utf-8")
        all_vars_path = exit_root / "group_vars" / "all.yml"
        all_vars = yaml.safe_load(all_vars_path.read_text(encoding="utf-8"))
        all_vars["cp_placement"] = "exit"
        all_vars_path.write_text(yaml.safe_dump(all_vars), encoding="utf-8")
        cp_host_vars = exit_root / "host_vars" / "cp-example.yml"
        if cp_host_vars.exists():
            cp_host_vars.unlink()

        rolled_back = validate_inventory.validate(hosts_path)
        self.assertEqual(rolled_back.errors, [])
        self.assertEqual(rolled_back.placement, "exit")
        rolled_back_state = validate_inventory.expected_state(rolled_back)
        self.assertEqual(rolled_back_state["panel_host"], "exit-example")

        self.ansible_playbook()
        for name in ("backup.yml", "cp_proxy.yml", "panel_proxy.yml"):
            with self.subTest(playbook=name):
                result = self.run_playbook([
                    "-i", str(hosts_path),
                    str(PLAYBOOKS / name),
                    "--list-hosts",
                ])
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("exit-example", result.stdout)
                self.assertNotIn("cp-example", result.stdout)
                self.assertNotIn("hosts (0)", result.stdout)


if __name__ == "__main__":
    unittest.main()
