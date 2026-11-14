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
ALL_VARS = yaml.safe_load((EXAMPLE.parent / "group_vars/all.yml").read_text())
GROUP_VARS = {
    "exit": {"node_role": "exit", "egress_family": "v4_prefer", "egress_slots": 3},
    "relay": {"node_role": "relay", "client_family": "v4", "s2s_family": "v6_prefer"},
    "cp": {"node_role": "control_plane", "panel_bind": "127.0.0.1"},
}
GROUP_VARS["exit"].update(yaml.safe_load((EXAMPLE.parent / "host_vars/exit-example.yml").read_text()))
GROUP_VARS["relay"].update(yaml.safe_load((EXAMPLE.parent / "host_vars/relay-example.yml").read_text()))
# Test host identities remain in HOSTS, not in group defaults.
for variables in GROUP_VARS.values():
    for key in ("ansible_host", "public_ipv4", "public_ipv6"):
        variables.pop(key, None)


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

    def test_regular_inventory_rejects_unusable_relay_sources(self) -> None:
        original = copy.deepcopy(self.group_vars)
        for key, address in (("relay_egress_ipv4", "127.0.0.1"), ("relay_egress_ipv4", "169.254.1.1"), ("relay_egress_ipv4", "224.0.0.1"), ("relay_egress_ipv4", "0.0.0.0"), ("relay_egress_ipv6", "::1"), ("relay_egress_ipv6", "fe80::1"), ("relay_egress_ipv6", "ff02::1"), ("relay_egress_ipv6", "::"), ("relay_egress_ipv6", "::ffff:192.0.2.20"), ("relay_egress_ipv6", "192.0.2.20")):
            with self.subTest(key=key, address=address):
                self.group_vars = copy.deepcopy(original)
                self.group_vars["relay"][key] = address
                self.assertInvalid(key, "private")

    def test_observatory_ports_rejected_by_inventory(self) -> None:
        for explicit in ("wrong", "0", "70000", ""):
            with self.subTest(port=explicit):
                self.all_vars["profiles_probe_url"] = "http://probe.example.com:" + explicit + "/generate_204"
                self.assertInvalid("profiles_probe_url")

    def test_invalid_enum(self) -> None:
        self.group_vars["relay"]["s2s_family"] = "v6_always"
        self.assertInvalid("s2s_family: must be one of v6_prefer, v4_only, v6_only")

    def test_invalid_xhttp_mode(self) -> None:
        self.all_vars["xhttp_mode"] = "xmux"
        self.assertInvalid("xhttp_mode: must be one of")

    def test_cp_placement_must_be_scalar(self) -> None:
        self.all_vars["cp_placement"] = ["exit"]
        errors = self.errors()
        self.assertTrue(any("cp_placement: must be one of" in error for error in errors), errors)

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
        self.assertInvalid("reality_target")
        self.all_vars["reality_target"] = "127.0.0.1:9443"
        self.assertEqual(self.errors(), [])

    def test_shared_defaults_and_per_host_overrides(self) -> None:
        for key in ("cover_tls_port", "reality_max_time_diff_ms"):
            self.all_vars.pop(key, None)
            for values in self.group_vars.values():
                values.pop(key, None)
        self.assertEqual(self.errors(), [])
        self.all_vars.update(cover_tls_port=9443, reality_max_time_diff_ms=300000)
        self.assertEqual(self.errors(), [])
        self.host_vars = {
            "exit-a": {"cover_tls_port": 10443, "reality_max_time_diff_ms": 150000, "reality_target": "127.0.0.1:10443"},
            "relay-a": {"cover_tls_port": 11443, "reality_max_time_diff_ms": 600000, "reality_target": "127.0.0.1:11443"},
        }
        self.assertEqual(self.errors(), [])
        self.host_vars["exit-a"]["reality_target"] = "127.0.0.1:9443"
        self.assertInvalid("reality_target")

    def test_explicit_bad_defaults_are_not_treated_as_omitted(self) -> None:
        original = copy.deepcopy(self.group_vars)
        for group in ("exit", "relay"):
            for key in ("cover_tls_port", "reality_max_time_diff_ms"):
                for value in (None, True, "9443", 0, -1):
                    with self.subTest(group=group, key=key, value=value):
                        self.group_vars = copy.deepcopy(original)
                        self.group_vars[group][key] = value
                        self.assertInvalid(key)

    def test_source_acl_matches_explicit_egress_not_public_address(self) -> None:
        self.group_vars["relay"]["relay_egress_ipv4"] = "198.51.100.99"
        self.assertInvalid("transit source ACL")

    def test_normalized_transit_ipv6_identity(self) -> None:
        self.group_vars["relay"]["relay_egress_ipv6"] = "2001:0db8:0020:0000:0000:0000:0000:0020"
        rule = self.group_vars["exit"]["base_firewall_source_ports"][0]
        rule["source_cidrs"][1] = "2001:0db8:0020:0000:0000:0000:0000:0020/128"
        self.assertEqual(self.errors(), [])

    def test_invalid_transit_source_type_is_a_diagnostic(self) -> None:
        self.group_vars["exit"]["base_firewall_source_ports"][0]["source_cidrs"] = [{}]
        self.assertTrue(self.errors())

    def test_management_origin_and_public_conflicts(self) -> None:
        for value in (True, "8445", 22, 2222, 8443):
            with self.subTest(value=value):
                self.group_vars["exit"]["cover_tls_port"] = value
                self.assertTrue(self.errors())

    def test_fixed_self_steal_options_rejected_by_inventory(self) -> None:
        original = copy.deepcopy(self.all_vars)
        original_groups = copy.deepcopy(self.group_vars)
        for key, values in (("slot_fanout", ("sni",)), ("s2s_family", ("v4_only", "v6_only")), ("xhttp_mode", ("auto", "packet-up", "stream-up"))):
            for value in values:
                with self.subTest(key=key, value=value):
                    self.all_vars = copy.deepcopy(original)
                    self.group_vars = copy.deepcopy(original_groups)
                    self.all_vars[key] = value
                    if key == "s2s_family":
                        self.group_vars["relay"][key] = value
                    self.assertInvalid(key)

    def test_exact_loopback_management_is_allowed(self) -> None:
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
