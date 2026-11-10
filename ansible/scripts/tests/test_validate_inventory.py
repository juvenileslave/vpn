"""Unit tests for validate_inventory.py using temporary YAML fixtures."""

from __future__ import annotations

import copy
import io
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
import sys
import tempfile
import unittest

import yaml

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))

import validate_inventory  # noqa: E402

EXAMPLE = SCRIPTS.parent / "inventories" / "example" / "hosts.yml"

HOSTS = {
    "exit-a": {"ansible_host": "192.0.2.10", "public_ipv4": "192.0.2.10",
               "public_ipv6": "2001:db8:10::10", "node_role": "exit"},
    "relay-a": {"ansible_host": "198.51.100.20", "public_ipv4": "198.51.100.20",
                "public_ipv6": "2001:db8:20::20", "node_role": "relay"},
    "cp-a": {"ansible_host": "203.0.113.30", "public_ipv4": "203.0.113.30",
             "public_ipv6": "2001:db8:30::30", "node_role": "control_plane"},
}
ALL_VARS = {
    "cp_placement": "dedicated",
    "client_family": "v4",
    "s2s_family": "v6_prefer",
    "egress_family": "v4_prefer",
    "egress_slots": 3,
    "slot_fanout": "sni",
    "node_port_allow": ["203.0.113.30/32", "2001:db8:30::30/128", "10.0.0.0/8"],
    "reality_sni": "www.example.com",
    "reality_target": "127.0.0.1:8445",
    "xhttp_path": "/xhttp",
    "xhttp_mode": "stream-one",
    "image_tags": {},
}
GROUP_VARS = {
    "exit": {"node_role": "exit", "egress_family": "v4_prefer", "egress_slots": 3},
    "relay": {"node_role": "relay", "client_family": "v4", "s2s_family": "v6_prefer"},
    "cp": {"node_role": "control_plane", "panel_bind": "127.0.0.1"},
}


class ValidateInventoryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.hosts = copy.deepcopy(HOSTS)
        self.groups = {"exit": ["exit-a"], "relay": ["relay-a"], "cp": ["cp-a"]}
        self.all_vars = copy.deepcopy(ALL_VARS)
        self.group_vars = copy.deepcopy(GROUP_VARS)
        self.host_vars: dict[str, dict] = {}

    def write(self, directory: str = "example") -> Path:
        root = Path(tempfile.mkdtemp(dir=self.tmp.name)) / directory
        (root / "group_vars").mkdir(parents=True)
        children = {
            group: {"hosts": {host: self.hosts[host] for host in members}} if members else {}
            for group, members in self.groups.items()
        }
        dump(root / "hosts.yml", {"all": {"children": children}})
        dump(root / "group_vars" / "all.yml", self.all_vars)
        for group, values in self.group_vars.items():
            dump(root / "group_vars" / f"{group}.yml", values)
        if self.host_vars:
            (root / "host_vars").mkdir()
            for host, values in self.host_vars.items():
                dump(root / "host_vars" / f"{host}.yml", values)
        return root / "hosts.yml"

    def errors(self, directory: str = "example") -> list[str]:
        return validate_inventory.validate(self.write(directory)).errors

    def assertInvalid(self, fragment: str, directory: str = "example") -> None:
        errors = self.errors(directory)
        self.assertTrue(any(fragment in error for error in errors), f"{fragment!r} not in {errors}")

    def test_shipped_example_is_valid(self) -> None:
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            code = validate_inventory.main(["--inventory", str(EXAMPLE)])
        self.assertEqual(code, 0)
        self.assertIn("Inventory OK", stdout.getvalue())

    def test_valid_dedicated_topology(self) -> None:
        self.host_vars = {host: dict(values) for host, values in self.hosts.items()}
        self.assertEqual(self.errors(), [])

    def test_dedicated_requires_cp_host(self) -> None:
        self.groups["cp"] = []
        self.assertInvalid("dedicated requires exactly one cp host")

    def test_dedicated_cp_must_differ_from_exit(self) -> None:
        self.groups["cp"] = ["exit-a"]
        self.assertInvalid("already in group exit")

    def test_valid_exit_topology(self) -> None:
        self.all_vars["cp_placement"] = "exit"
        self.groups["cp"] = []
        self.assertEqual(self.errors(), [])

    def test_exit_topology_requires_empty_cp(self) -> None:
        self.all_vars["cp_placement"] = "exit"
        self.assertInvalid("requires an empty cp group")

    def test_exactly_one_relay(self) -> None:
        self.hosts["relay-b"] = dict(self.hosts["relay-a"], ansible_host="198.51.100.21",
                                     public_ipv4="198.51.100.21", public_ipv6="2001:db8:20::21")
        self.groups["relay"].append("relay-b")
        self.assertInvalid("group relay must contain exactly one host, found 2")

    def test_missing_ipv6(self) -> None:
        del self.hosts["relay-a"]["public_ipv6"]
        self.assertInvalid("host relay-a: public_ipv6 is missing")

    def test_wrong_address_family(self) -> None:
        self.hosts["exit-a"]["public_ipv6"] = "192.0.2.11"
        self.assertInvalid("must be an IPv6 address")

    def test_invalid_enum(self) -> None:
        self.group_vars["relay"]["s2s_family"] = "v6_always"
        self.assertInvalid("s2s_family: must be one of v6_prefer, v4_only, v6_only")

    def test_invalid_xhttp_mode(self) -> None:
        self.all_vars["xhttp_mode"] = "xmux"
        self.assertInvalid("xhttp_mode: must be one of")

    def test_cp_placement_only_in_all(self) -> None:
        self.group_vars["exit"]["cp_placement"] = "exit"
        self.assertInvalid("cp_placement must be set only in group_vars/all")

    def test_address_outside_documentation_ranges(self) -> None:
        self.hosts["exit-a"]["public_ipv4"] = "10.20.30.40"
        self.hosts["exit-a"]["ansible_host"] = "10.20.30.40"
        self.assertInvalid("outside the documentation ranges")

    def test_ipv6_outside_documentation_ranges(self) -> None:
        self.hosts["cp-a"]["public_ipv6"] = "fd00::30"
        self.assertInvalid("outside the documentation ranges")

    def test_non_example_inventory_skips_documentation_rule(self) -> None:
        self.hosts["exit-a"]["public_ipv4"] = "10.20.30.40"
        self.hosts["exit-a"]["ansible_host"] = "10.20.30.40"
        self.all_vars["reality_sni"] = "www.example.org"
        self.assertEqual(self.errors("staging"), [])

    def test_ansible_host_must_match_public_ipv4(self) -> None:
        self.hosts["relay-a"]["ansible_host"] = "198.51.100.99"
        self.assertInvalid("ansible_host must equal the documentation public_ipv4")

    def test_duplicate_address(self) -> None:
        self.hosts["cp-a"]["public_ipv6"] = "2001:db8:10::10"
        self.assertInvalid("duplicates the address")

    def test_duplicate_address_normalized(self) -> None:
        self.hosts["cp-a"]["public_ipv6"] = "2001:0db8:0010:0000:0000:0000:0000:0010"
        self.assertInvalid("duplicates the address")

    def test_host_vars_conflict_with_hosts_file(self) -> None:
        self.host_vars = {"exit-a": dict(self.hosts["exit-a"], public_ipv6="2001:db8:10::11")}
        self.assertInvalid("conflicts with")

    def test_node_role_must_match_group(self) -> None:
        self.hosts["cp-a"]["node_role"] = "exit"
        self.assertInvalid("node_role must be 'control_plane' for group cp")

    def test_unknown_group(self) -> None:
        path = self.write()
        data = yaml.safe_load(path.read_text())
        data["all"]["children"]["edge"] = {}
        dump(path, data)
        errors = validate_inventory.validate(path).errors
        self.assertTrue(any("unknown group" in error for error in errors), errors)

    def test_invalid_cidr(self) -> None:
        self.all_vars["node_port_allow"] = ["203.0.113.30/33"]
        self.assertInvalid("invalid CIDR")

    def test_cidr_with_host_bits(self) -> None:
        self.all_vars["node_port_allow"] = ["192.0.2.1/24"]
        self.assertInvalid("invalid CIDR")

    def test_cidr_outside_example_ranges(self) -> None:
        self.all_vars["node_port_allow"] = ["100.64.0.0/10"]
        self.assertInvalid("documentation or private ranges")

    def test_node_port_allow_must_be_list(self) -> None:
        self.all_vars["node_port_allow"] = "203.0.113.30/32"
        self.assertInvalid("must be a list of CIDRs")

    def test_invalid_xhttp_path(self) -> None:
        self.all_vars["xhttp_path"] = "xhttp"
        self.assertInvalid("xhttp_path: must start with /")

    def test_egress_slots_range(self) -> None:
        for value in (0, 7, "3", True):
            with self.subTest(value=value):
                self.group_vars["exit"]["egress_slots"] = value
                self.assertInvalid("integer from 1 through 6")

    def test_reality_sni(self) -> None:
        for value, fragment in (("", "non-empty DNS name"), ("bad_host.example.com", "non-empty DNS name"),
                                ("www.example.org", "must end with .example.com")):
            with self.subTest(value=value):
                self.all_vars["reality_sni"] = value
                self.assertInvalid(fragment)

    def test_reality_target(self) -> None:
        for value in ("127.0.0.1", "127.0.0.1:0", "127.0.0.1:65536", "::1:8445"):
            with self.subTest(value=value):
                self.all_vars["reality_target"] = value
                self.assertTrue(any("reality_target" in e for e in self.errors()))
        self.all_vars["reality_target"] = "[::1]:8445"
        self.assertEqual(self.errors(), [])

    def test_image_tags_must_be_mapping(self) -> None:
        self.all_vars["image_tags"] = ["xray:1.0"]
        self.assertInvalid("image_tags: must be a mapping")

    def test_main_reports_errors_and_exits_1(self) -> None:
        self.all_vars["xhttp_path"] = "xhttp"
        path = self.write()
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            code = validate_inventory.main(["--inventory", str(path)])
        self.assertEqual(code, 1)
        self.assertIn("group_vars/all.yml: xhttp_path", stderr.getvalue())

    def test_invalid_yaml(self) -> None:
        path = self.write()
        path.write_text("all: [unclosed\n", encoding="utf-8")
        self.assertTrue(any("invalid YAML" in e for e in validate_inventory.validate(path).errors))


def dump(path: Path, data: object) -> None:
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
