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
               "public_ipv6": "2001:db8:10::10", "node_role": "exit",
               "overlay_ipv6": "fd00:db8:1::10/128", "overlay_ipv4": "10.250.0.10/32"},
    "relay-a": {"ansible_host": "198.51.100.20", "public_ipv4": "198.51.100.20",
                "public_ipv6": "2001:db8:20::20", "node_role": "relay",
                "overlay_ipv6": "fd00:db8:1::20/128", "overlay_ipv4": "10.250.0.20/32"},
    "cp-a": {"ansible_host": "203.0.113.30", "public_ipv4": "203.0.113.30",
             "public_ipv6": "2001:db8:30::30", "node_role": "control_plane",
             "overlay_ipv6": "fd00:db8:1::30/128", "overlay_ipv4": "10.250.0.30/32"},
}
ALL_VARS = yaml.safe_load((EXAMPLE.parent / "group_vars/all.yml").read_text())
GROUP_VARS = {
    "exit": {"node_role": "exit", "egress_family": "v4_prefer", "egress_slots": 3},
    "relay": {"node_role": "relay", "client_family": "v4", "s2s_family": "v6_prefer"},
    "cp": {"node_role": "control_plane", "panel_bind": "127.0.0.1"},
}
GROUP_VARS["exit"].update(yaml.safe_load((EXAMPLE.parent / "host_vars/exit-example.yml").read_text()))
GROUP_VARS["relay"].update(yaml.safe_load((EXAMPLE.parent / "host_vars/relay-example.yml").read_text()))
GROUP_VARS["cp"].update(yaml.safe_load((EXAMPLE.parent / "host_vars/cp-example.yml").read_text()))
# Test host identities remain in HOSTS, not in group defaults.
for variables in GROUP_VARS.values():
    for key in ("ansible_host", "public_ipv4", "public_ipv6", "overlay_ipv6", "overlay_ipv4"):
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
        self.all_vars["base_ssh_enabled"] = True
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
        self.all_vars["base_ssh_enabled"] = True
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

    def test_exit_transit_port_cannot_be_public(self) -> None:
        transit = self.group_vars["exit"]["transit_port"]
        self.group_vars["exit"]["base_firewall_source_ports"] = [
            rule for rule in self.group_vars["exit"]["base_firewall_source_ports"]
            if rule["port"] != transit
        ]
        self.group_vars["exit"]["base_firewall_vpn_ports"].append(
            {"proto": "tcp", "port": transit}
        )
        self.assertInvalid("transit_port")

    def test_normalized_transit_ipv6_identity(self) -> None:
        self.group_vars["relay"]["relay_egress_ipv6"] = "2001:0db8:0020:0000:0000:0000:0000:0020"
        rule = self.group_vars["exit"]["base_firewall_source_ports"][0]
        rule["source_cidrs"][1] = "2001:0db8:0020:0000:0000:0000:0000:0020/128"
        self.assertEqual(self.errors(), [])

    def test_invalid_transit_source_type_is_a_diagnostic(self) -> None:
        self.group_vars["exit"]["base_firewall_source_ports"][0]["source_cidrs"] = [{}]
        self.assertTrue(self.errors())

    def test_management_origin_and_public_conflicts(self) -> None:
        # The conflict must follow the declared API port; the example no longer
        # reuses the upstream 2222 value.
        api_port = self.all_vars["node_api_port"]
        for value in (True, "8445", 22, api_port, 8443):
            with self.subTest(value=value):
                self.group_vars["exit"]["cover_tls_port"] = value
                self.assertTrue(self.errors())
        self.group_vars["exit"]["cover_tls_port"] = api_port
        self.assertInvalid("listener/SSH/API/origin/HTTP01 ports collide")

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

    def test_base_firewall_false_requires_explicit_temporary_exception(self) -> None:
        self.all_vars["base_firewall_enabled"] = False
        self.assertInvalid("outside an explicit temporary base_firewall_bootstrap_exception")

    def test_missing_base_firewall_authority_is_refused(self) -> None:
        del self.all_vars["base_firewall_enabled"]
        self.assertInvalid("base_firewall_enabled is required")

    def test_base_firewall_authority_must_be_boolean(self) -> None:
        for value in ("true", 1, None):
            with self.subTest(value=value):
                self.all_vars["base_firewall_enabled"] = value
                self.assertInvalid("must be true or false")

    def test_temporary_bootstrap_exception_is_acl_scoped(self) -> None:
        self.all_vars["base_firewall_enabled"] = False
        self.all_vars["base_firewall_bootstrap_exception"] = {
            "temporary": True,
            "source_cidrs": copy.deepcopy(self.all_vars["node_port_allow"]),
        }
        self.assertEqual(self.errors(), [])

    def test_bootstrap_exception_must_be_temporary_and_match_node_acl(self) -> None:
        self.all_vars["base_firewall_enabled"] = False
        original = copy.deepcopy(self.all_vars["node_port_allow"])
        for exception, fragment in (
            ({"temporary": False, "source_cidrs": original}, "must be true"),
            ({"temporary": True, "source_cidrs": []}, "nonempty list of CIDRs"),
            ({"temporary": True, "source_cidrs": ["0.0.0.0/0"]}, "unsafe or wide"),
            ({"temporary": True, "source_cidrs": ["203.0.113.99/32"]}, "must equal node_port_allow"),
            ({"temporary": True, "source_cidrs": original, "extra": True}, "expected a mapping"),
        ):
            with self.subTest(exception=exception):
                self.all_vars["base_firewall_bootstrap_exception"] = exception
                self.assertInvalid(fragment)

    def test_stale_bootstrap_exception_is_refused(self) -> None:
        self.all_vars["base_firewall_bootstrap_exception"] = {
            "temporary": True,
            "source_cidrs": copy.deepcopy(self.all_vars["node_port_allow"]),
        }
        self.assertInvalid("must be absent when base_firewall_enabled is true")

    def test_management_authority_cannot_be_redeclared_in_host_vars(self) -> None:
        self.host_vars = {"exit-a": {"node_api_port": self.all_vars["node_api_port"]}}
        self.assertInvalid("must have one authority")

    def test_node_api_port_is_required_without_fallback(self) -> None:
        del self.all_vars["node_api_port"]
        self.assertInvalid("node_api_port is required; there is no implicit 2222 fallback")

    def test_node_api_port_must_be_covered_by_the_declared_acl(self) -> None:
        self.group_vars["exit"]["base_firewall_source_ports"] = [
            rule for rule in self.group_vars["exit"]["base_firewall_source_ports"]
            if rule["port"] != self.all_vars["node_api_port"]
        ]
        self.assertInvalid("exactly one base_firewall_source_ports rule, found 0")

    def test_node_api_acl_must_equal_node_port_allow(self) -> None:
        rule = next(
            item for item in self.group_vars["exit"]["base_firewall_source_ports"]
            if item["port"] == self.all_vars["node_api_port"]
        )
        rule["source_cidrs"] = ["203.0.113.99/32"]
        self.assertInvalid("node API source_cidrs must equal node_port_allow")

    def test_node_api_port_cannot_be_public(self) -> None:
        self.group_vars["exit"]["base_firewall_vpn_ports"].append(
            {"proto": "tcp", "port": self.all_vars["node_api_port"]}
        )
        self.assertInvalid("must not be declared as a public")

    def test_node_port_allow_rejects_missing_wide_and_any(self) -> None:
        cases = (
            ([], "must not be empty"),
            (["0.0.0.0/0"], "unsafe or wide management CIDR"),
            (["::/0"], "unsafe or wide management CIDR"),
            (["any"], "must be a CIDR such as"),
            (["192.0.2.1/24"], "invalid CIDR"),
            (["127.0.0.1/32", "127.0.0.1/32"], "duplicate CIDR"),
        )
        for value, fragment in cases:
            with self.subTest(value=value):
                self.all_vars["node_port_allow"] = value
                self.assertInvalid(fragment)

    def test_duplicate_matching_api_source_rules_are_refused(self) -> None:
        rules = self.group_vars["exit"]["base_firewall_source_ports"]
        rule = next(item for item in rules if item["port"] == self.all_vars["node_api_port"])
        rules.append(copy.deepcopy(rule))
        self.assertInvalid("found 2")

    def test_node_api_port_must_differ_from_ssh(self) -> None:
        self.all_vars["node_api_port"] = self.all_vars["base_ssh_port"]
        self.assertInvalid("must differ from base_ssh_port")

    def test_management_authority_cannot_be_redeclared_in_group_vars(self) -> None:
        self.group_vars["exit"]["node_api_port"] = self.all_vars["node_api_port"]
        self.assertInvalid("must have one authority")

    def test_dedicated_remote_cp_rejects_loopback_only_management(self) -> None:
        self.all_vars["cp_placement"] = "dedicated"
        self.all_vars["node_port_allow"] = ["127.0.0.1/32", "::1/128"]
        for group in ("exit", "relay"):
            rule = next(
                item for item in self.group_vars[group]["base_firewall_source_ports"]
                if item["port"] == self.all_vars["node_api_port"]
            )
            rule["source_cidrs"] = ["127.0.0.1/32", "::1/128"]
        self.assertInvalid("dedicated remote CP cannot use loopback-only")

    def test_valid_dedicated_management_path(self) -> None:
        self.all_vars["cp_placement"] = "dedicated"
        self.all_vars["node_port_allow"] = ["10.250.0.30/32", "fd00:db8:1::30/128"]
        for group in ("exit", "relay"):
            rule = next(
                item for item in self.group_vars[group]["base_firewall_source_ports"]
                if item["port"] == self.all_vars["node_api_port"]
            )
            rule["source_cidrs"] = ["10.250.0.30/32", "fd00:db8:1::30/128"]
        self.assertEqual(self.errors(), [])

    def test_subscription_publication_has_one_authority(self) -> None:
        for key, value, fragment in (
            ("cp_proxy_server_name", "sub.example.com", "subscription_public_host"),
            ("cp_proxy_path_prefix", "/sub/", "subscription_public_host"),
            ("cp_proxy_upstream", "127.0.0.1:3000", "panel_bind:panel_port"),
            ("remnawave_panel_sub_public_domain", "sub.example.com/sub",
             "subscription_public_host"),
        ):
            with self.subTest(key=key):
                self.all_vars[key] = value
                self.assertInvalid(f"must be derived from {fragment}")

    def test_subscription_publication_requires_declared_authority(self) -> None:
        for key in ("subscription_public_host", "subscription_public_path"):
            with self.subTest(key=key):
                original = self.all_vars.pop(key)
                self.assertInvalid("is required for the panel host")
                self.all_vars[key] = original
        self.assertEqual(self.errors(), [])

    def test_subscription_publication_values(self) -> None:
        cases = (
            ("subscription_public_host", "sub", "lowercase DNS name"),
            ("subscription_public_host", "Sub.Example.com", "lowercase DNS name"),
            ("subscription_public_host", "sub.example.org", ".example.com"),
            ("subscription_public_host", "192.0.2.5", "lowercase DNS name"),
            ("subscription_public_path", "sub/", "must look like /sub/"),
            ("subscription_public_path", "/sub", "must look like /sub/"),
            ("subscription_public_path", "/sub/../x/", "dot segments"),
            ("subscription_public_path", "/api/", "must not expose"),
            ("subscription_public_path", "/admin/", "must not expose"),
            ("subscription_public_path", "/.well-known/", "must not expose"),
        )
        for key, value, fragment in cases:
            with self.subTest(key=key, value=value):
                self.all_vars[key] = value
                self.assertInvalid(fragment)

    def test_regular_inventory_may_use_a_real_subscription_host(self) -> None:
        self.all_vars["subscription_public_host"] = "subscribe.vpn.invalid"
        self.all_vars["base_ssh_enabled"] = True
        self.assertEqual(self.errors("staging"), [])

    def test_example_node_api_port_must_not_reuse_upstream_default(self) -> None:
        self.all_vars["node_api_port"] = 2222
        self.assertInvalid("must not reuse the upstream example 2222")
        self.all_vars["node_api_port"] = 2223
        self.assertEqual(self.errors(), [])

    def test_valid_overlay_ipv6_only_without_fallback(self) -> None:
        self.all_vars["overlay_ipv4_fallback"] = False
        del self.all_vars["overlay_ipv4_prefix"]
        for host in self.hosts.values():
            host.pop("overlay_ipv4", None)
        for group in ("exit", "relay", "cp"):
            self.group_vars[group]["overlay_allowed_ips"] = [
                cidr for cidr in self.group_vars[group]["overlay_allowed_ips"] if ":" in cidr
            ]
        self.all_vars["node_port_allow"] = ["127.0.0.1/32", "::1/128", "fd00:db8:1::30/128"]
        for group in ("exit", "relay"):
            rule = next(
                item for item in self.group_vars[group]["base_firewall_source_ports"]
                if item["port"] == self.all_vars["node_api_port"]
            )
            rule["source_cidrs"] = ["127.0.0.1/32", "::1/128", "fd00:db8:1::30/128"]
        self.assertEqual(self.errors(), [])

    def test_overlay_default_routes_are_forbidden(self) -> None:
        for route in ("0.0.0.0/0", "::/0"):
            with self.subTest(route=route):
                self.group_vars["exit"]["overlay_allowed_ips"] = [
                    "fd00:db8:1::10/128", "10.250.0.10/32", route
                ]
                self.assertInvalid("default route is forbidden in overlay_allowed_ips")

    def test_overlay_allowed_ips_rejects_public_wide_and_overlapping_routes(self) -> None:
        cases = (
            (["fd00:db8:1::10/128", "10.250.0.10/32", "2001:db8:10::/64"], "must be inside ULA fc00::/7"),
            (["fd00:db8:1::10/128", "10.250.0.10/32", "192.0.2.0/24"], "must be inside RFC 1918"),
            (["fd00:db8:1::10/128", "10.250.0.10/32", "fd00:db8::/48"], "prefix is too wide"),
            (["fd00:db8:1::10/128", "10.250.0.10/32", "10.250.0.0/16"], "prefix is too wide"),
            (["fd00:db8:1::10/128", "10.250.0.10/32", "fd00:db8:1::20/128"], "overlaps peer"),
        )
        for routes, fragment in cases:
            with self.subTest(routes=routes):
                self.group_vars["exit"]["overlay_allowed_ips"] = routes
                self.assertInvalid(fragment)

    def test_overlay_address_outside_prefix_or_non_host_cidr(self) -> None:
        self.hosts["exit-a"]["overlay_ipv6"] = "fd00:db8:2::10/128"
        self.assertInvalid("must be inside overlay_ipv6_prefix")
        self.hosts["exit-a"]["overlay_ipv6"] = "fd00:db8:1::/64"
        self.assertInvalid("must be a /128 host address")
        self.hosts["exit-a"]["overlay_ipv6"] = "fd00:db8:1::10/128"

        self.hosts["relay-a"]["overlay_ipv4"] = "10.251.0.20/32"
        self.assertInvalid("must be inside overlay_ipv4_prefix")
        self.hosts["relay-a"]["overlay_ipv4"] = "10.250.0.0/32"
        self.assertInvalid("usable host address inside overlay_ipv4_prefix")
        self.hosts["relay-a"]["overlay_ipv4"] = "10.250.0.255/32"
        self.assertInvalid("usable host address inside overlay_ipv4_prefix")

    def test_overlay_duplicate_addresses_are_rejected(self) -> None:
        self.hosts["cp-a"]["overlay_ipv6"] = "fd00:0db8:0001::10/128"
        self.assertInvalid("duplicates the overlay address")
        self.hosts["cp-a"]["overlay_ipv6"] = "fd00:db8:1::30/128"

        self.hosts["cp-a"]["overlay_ipv4"] = "10.250.0.20/32"
        self.assertInvalid("duplicates the overlay address")

    def test_overlay_partial_ipv4_fallback_is_rejected(self) -> None:
        del self.hosts["cp-a"]["overlay_ipv4"]
        self.assertInvalid("overlay_ipv4 is required when overlay_ipv4_fallback is true")

        self.hosts["cp-a"]["overlay_ipv4"] = "10.250.0.30/32"
        self.all_vars["overlay_ipv4_fallback"] = False
        del self.all_vars["overlay_ipv4_prefix"]
        del self.hosts["exit-a"]["overlay_ipv4"]
        del self.hosts["relay-a"]["overlay_ipv4"]
        self.assertInvalid("overlay_ipv4 must not be set when overlay_ipv4_fallback is false")

    def test_overlay_udp_port_must_be_declared_publicly_once(self) -> None:
        self.group_vars["exit"]["base_firewall_vpn_ports"] = [
            item for item in self.group_vars["exit"]["base_firewall_vpn_ports"]
            if item["port"] != self.all_vars["overlay_port"]
        ]
        self.assertInvalid("overlay_port requires exactly one udp entry")

        self.group_vars["exit"]["base_firewall_vpn_ports"].append(
            {"proto": "tcp", "port": self.all_vars["overlay_port"]}
        )
        self.assertInvalid("must be declared as udp only")

        self.group_vars["cp"]["base_firewall_vpn_ports"] = []
        self.assertInvalid("host cp-a: overlay_port requires exactly one udp entry")

    def test_dedicated_cp_node_port_allow_requires_overlay_and_rejects_public_ip(self) -> None:
        def set_allow(cidrs: list[str]) -> None:
            self.all_vars["node_port_allow"] = list(cidrs)
            for group in ("exit", "relay"):
                rule = next(
                    item for item in self.group_vars[group]["base_firewall_source_ports"]
                    if item["port"] == self.all_vars["node_api_port"]
                )
                rule["source_cidrs"] = list(cidrs)

        set_allow(["127.0.0.1/32", "::1/128", "10.250.0.30/32"])
        self.assertInvalid("must include CP overlay IPv6 address")

        set_allow(["127.0.0.1/32", "::1/128", "fd00:db8:1::30/128"])
        self.assertInvalid("must include CP overlay IPv4 fallback address")

        set_allow(["127.0.0.1/32", "::1/128", "10.250.0.0/24", "10.250.0.30/32", "fd00:db8:1::30/128"])
        self.assertInvalid("must only allow loopback and exact CP overlay addresses")

        set_allow(["127.0.0.1/32", "::1/128", "10.250.0.30/32", "fd00:db8:1::/64", "fd00:db8:1::30/128"])
        self.assertInvalid("must only allow loopback and exact CP overlay addresses")

        set_allow(["127.0.0.1/32", "::1/128", "10.250.0.30/32", "fd00:db8:1::30/128", "10.250.0.20/32"])
        self.assertInvalid("must only allow loopback and exact CP overlay addresses")

        set_allow(["127.0.0.1/32", "::1/128", "10.250.0.30/32", "fd00:db8:1::30/128", "fd00:db8:1::20/128"])
        self.assertInvalid("must only allow loopback and exact CP overlay addresses")

        set_allow(["127.0.0.1/32", "::1/128", "10.250.0.30/32", "fd00:db8:1::30/128", "192.168.100.0/24"])
        self.assertInvalid("must only allow loopback and exact CP overlay addresses")

        set_allow(["127.0.0.1/32", "::1/128", "10.250.0.30/32", "fd00:db8:1::30/128", "198.51.100.10/32"])
        self.assertInvalid("must only allow loopback and exact CP overlay addresses")

        set_allow(["10.250.0.30/32", "fd00:db8:1::30/128", "203.0.113.30/32"])
        self.assertInvalid("must use CP overlay addresses, not CP public IP")

        set_allow(["10.250.0.30/32", "fd00:db8:1::30/128", "2001:db8:30::30/128"])
        self.assertInvalid("must use CP overlay addresses, not CP public IP")

    def test_overlay_key_material_and_in_checkout_key_paths_are_rejected(self) -> None:
        for key in ("overlay_private_key", "overlay_preshared_key"):
            with self.subTest(key=key):
                self.host_vars = {"exit-a": {key: "placeholder-refused-by-validator"}}
                self.assertInvalid("overlay private key material must not be stored in inventory")

        self.host_vars = {"exit-a": {"overlay_public_key": "placeholder-public-key"}}
        self.assertInvalid("overlay key material is forbidden in the example inventory")

        repo_key = str(validate_inventory.REPO_ROOT / "ansible" / "wg-exit.key")
        for bad_path, fragment in (
            ("keys/wg-exit.key", "absolute controller-side path"),
            ("/etc/vpn/../wg-exit.key", "'..' path traversal"),
            (repo_key, "outside the repository checkout"),
        ):
            with self.subTest(path=bad_path):
                self.host_vars = {"exit-a": {"overlay_private_key_file": bad_path}}
                self.assertInvalid(fragment)

        self.all_vars["base_ssh_enabled"] = True
        self.host_vars = {"exit-a": {"overlay_private_key_file": "/etc/vpn-secrets/wg-exit.key"}}
        self.assertEqual(self.errors("staging"), [])

    def test_overlay_port_collisions_are_rejected(self) -> None:
        cases = (
            (22, "must differ from base_ssh_port"),
            (2223, "must differ from node_api_port"),
            (9443, "collides with cover_tls_port"),
            (8443, "collides with exit_direct_port"),
            (8444, "collides with transit_port"),
            (10443, "collides with relay_slot_ports"),
            (80, "collides with HTTP-01 port 80"),
        )
        for port, fragment in cases:
            with self.subTest(port=port):
                self.all_vars["overlay_port"] = port
                for group in ("exit", "relay", "cp"):
                    self.group_vars[group]["base_firewall_vpn_ports"] = [
                        item for item in self.group_vars[group]["base_firewall_vpn_ports"]
                        if item["proto"] != "udp"
                    ] + [{"proto": "udp", "port": port}]
                self.assertInvalid(fragment)

    def test_overlay_wrong_address_families_are_rejected(self) -> None:
        self.all_vars["overlay_ipv6_prefix"] = "10.250.0.0/24"
        self.assertInvalid("must be an IPv6 CIDR prefix")
        self.all_vars["overlay_ipv6_prefix"] = "2001:db8:1::/64"
        self.assertInvalid("must be inside ULA fc00::/7")
        self.all_vars["overlay_ipv6_prefix"] = "fd00:db8:1::/64"

        self.all_vars["overlay_ipv4_prefix"] = "fd00:db8:1::/64"
        self.assertInvalid("must be an IPv4 CIDR prefix")
        self.all_vars["overlay_ipv4_prefix"] = "192.0.2.0/24"
        self.assertInvalid("must be inside RFC 1918")
        self.all_vars["overlay_ipv4_prefix"] = "10.250.0.0/24"

        self.hosts["exit-a"]["overlay_ipv6"] = "10.250.0.10/32"
        self.assertInvalid("must be an IPv6 /128 host CIDR")
        self.hosts["exit-a"]["overlay_ipv6"] = "::ffff:10.250.0.10/128"
        self.assertInvalid("unusable IPv6 overlay host address")
        self.hosts["exit-a"]["overlay_ipv6"] = "fd00:db8:1::10/128"

        self.hosts["exit-a"]["overlay_ipv4"] = "fd00:db8:1::10/128"
        self.assertInvalid("must be an IPv4 /32 host CIDR")

    def test_break_glass_ssh_must_be_nonempty_and_independent_of_overlay(self) -> None:
        self.all_vars["base_ssh_trusted_cidrs"] = []
        self.assertInvalid("non-empty list of break-glass CIDRs")

        self.all_vars["base_ssh_trusted_cidrs"] = ["fd00:db8:1::/64"]
        self.assertInvalid("must not overlap or be derived from overlay prefixes")

        self.all_vars["base_ssh_trusted_cidrs"] = ["10.250.0.0/24"]
        self.assertInvalid("must not overlap or be derived from overlay prefixes")

    def test_overlay_authority_cannot_be_redeclared_outside_all(self) -> None:
        self.host_vars = {"exit-a": {"overlay_port": 51820}}
        self.assertInvalid("must have one authority")
        self.assertInvalid("overlay_port must be set only in group_vars/all")

    def test_overlay_backend_and_interface_validation(self) -> None:
        self.all_vars["overlay_backend"] = "ipsec"
        self.assertInvalid("must be one of wireguard")
        self.all_vars["overlay_backend"] = "wireguard"

        for iface in ("lo", "0wg", "interface_name_too_long"):
            with self.subTest(iface=iface):
                self.all_vars["overlay_interface"] = iface
                self.assertInvalid("valid Linux interface name")

    def test_valid_direct_ssh_contract_in_regular_inventory(self) -> None:
        self.all_vars["base_ssh_enabled"] = True
        self.all_vars["ansible_port"] = 22
        self.all_vars["base_ssh_trusted_cidrs"] = ["192.0.2.10/32", "2001:db8:10::10/128"]
        self.assertEqual(self.errors("staging"), [])

    def test_regular_inventory_requires_base_ssh_enabled_true(self) -> None:
        self.assertInvalid("base_ssh_enabled is required", "staging")
        self.all_vars["base_ssh_enabled"] = False
        self.assertInvalid("base_ssh_enabled must be true", "staging")
        self.assertInvalid("base_ssh_enabled must be true", "example")
        self.all_vars["base_ssh_enabled"] = "true"
        self.assertInvalid("must be true or false", "staging")

    def test_ssh_break_glass_requires_root_login_no(self) -> None:
        del self.all_vars["base_ssh_permit_root_login"]
        self.assertInvalid("base_ssh_permit_root_login is required")
        for bad in ("prohibit-password", "yes", False, None):
            with self.subTest(value=bad):
                self.all_vars["base_ssh_permit_root_login"] = bad
                self.assertInvalid("base_ssh_permit_root_login must be 'no'")

    def test_ssh_break_glass_trusted_cidrs_contract_without_echo(self) -> None:
        del self.all_vars["base_ssh_trusted_cidrs"]
        self.assertInvalid("base_ssh_trusted_cidrs is required")
        self.all_vars["base_ssh_trusted_cidrs"] = []
        self.assertInvalid("must not be empty")
        self.all_vars["base_ssh_trusted_cidrs"] = "192.0.2.0/24"
        self.assertInvalid("must be a list of CIDRs")
        cases = (
            (["192.0.2.0/23"], "слишком широкая SSH-сеть"),
            (["2001:db8::/48"], "слишком широкая SSH-сеть"),
            (["0.0.0.0/0"], "слишком широкая сеть"),
            (["127.0.0.1/32"], "loopback"),
            (["::1/128"], "loopback"),
            (["192.0.2.0/24", "192.0.2.0/24"], "duplicate CIDR"),
            (["2001:db8:10::/64", "2001:0db8:0010::/64"], "duplicate CIDR"),
        )
        for cidrs, fragment in cases:
            with self.subTest(cidrs=cidrs):
                self.all_vars["base_ssh_trusted_cidrs"] = cidrs
                errors = self.errors()
                self.assertTrue(any(fragment in err for err in errors), errors)
                for cidr in cidrs:
                    self.assertFalse(any(cidr in err for err in errors), errors)

    def test_ssh_port_and_ansible_port_contract(self) -> None:
        self.all_vars["ansible_port"] = 22
        self.assertEqual(self.errors(), [])
        self.all_vars["ansible_port"] = 2222
        self.assertInvalid("ansible_port must equal base_ssh_port")
        self.all_vars["ansible_port"] = "22"
        self.assertInvalid("must be an integer port 1-65535")
        del self.all_vars["ansible_port"]
        self.all_vars["base_ssh_port"] = 2222
        self.assertInvalid("ansible_port is required and must equal base_ssh_port")
        self.all_vars["ansible_port"] = 2222
        self.assertEqual(self.errors(), [])
        del self.all_vars["ansible_port"]
        self.all_vars["base_ssh_port"] = 22
        for bad_port in ("22", True, 0, 65536):
            with self.subTest(port=bad_port):
                self.all_vars["base_ssh_port"] = bad_port
                self.assertInvalid("must be an integer port 1-65535")
        del self.all_vars["base_ssh_port"]
        self.assertInvalid("base_ssh_port is required")

    def test_ssh_port_cannot_be_exposed_via_public_or_source_firewall_rules(self) -> None:
        self.group_vars["exit"]["base_firewall_vpn_ports"].append({"proto": "tcp", "port": 22})
        self.assertInvalid("base_ssh_port must not be declared as a public")
        self.group_vars["exit"]["base_firewall_vpn_ports"].pop()
        self.group_vars["exit"]["base_firewall_source_ports"].append(
            {"proto": "tcp", "port": 22, "source_cidrs": ["192.0.2.0/24"]}
        )
        self.assertInvalid("governed only by base_ssh_trusted_cidrs")
        self.group_vars["exit"]["base_firewall_source_ports"].pop()
        self.host_vars = {"cp-a": {
            "base_firewall_vpn_ports": [{"proto": "tcp", "port": 22}],
        }}
        self.assertInvalid("base_ssh_port must not be declared as a public")
        self.host_vars = {"cp-a": {
            "base_firewall_source_ports": [
                {"proto": "tcp", "port": 22, "source_cidrs": ["192.0.2.0/24"]},
            ],
        }}
        self.assertInvalid("governed only by base_ssh_trusted_cidrs")
        for bad_rules, fragment in (
            ([{"proto": "tcp", "port": "22"}], "must be an integer port 1-65535"),
            (["tcp/22"], "expected a mapping with proto and port"),
            ([{"proto": "TCP", "port": 22}], "must be 'tcp' or 'udp'"),
            ("tcp/22", "must be a list"),
        ):
            with self.subTest(bad_rules=bad_rules):
                self.host_vars = {"cp-a": {"base_firewall_vpn_ports": bad_rules}}
                self.assertInvalid(fragment)
                self.host_vars = {"cp-a": {"base_firewall_source_ports": bad_rules}}
                self.assertInvalid(fragment)

    def test_proxy_variables_do_not_satisfy_direct_ssh_contract(self) -> None:
        self.all_vars["relay_proxy_command"] = "ssh -W %h:%p 198.51.100.20"
        self.all_vars["ansible_ssh_common_args"] = "-o ProxyJump=ops@198.51.100.20"
        self.assertInvalid("base_ssh_enabled is required", "staging")
        del self.all_vars["base_ssh_trusted_cidrs"]
        self.assertInvalid("base_ssh_trusted_cidrs is required")

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
