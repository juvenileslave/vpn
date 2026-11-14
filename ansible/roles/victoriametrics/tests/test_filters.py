"""Unit tests for the victoriametrics role validation filters."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest

PLUGIN = Path(__file__).resolve().parents[1] / "filter_plugins" / "victoriametrics.py"
_spec = importlib.util.spec_from_file_location("victoriametrics_filters", PLUGIN)
filters = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(filters)

LOOPBACK = {"address": "127.0.0.1", "version": 4, "loopback": True, "private": True}
PRIVATE4 = {"address": "10.203.46.1", "version": 4, "loopback": False, "private": True}
PRIVATE6 = {"address": "fd46:203::1", "version": 6, "loopback": False, "private": True}


def rule(sources, port=8428, proto="tcp"):
    return {"proto": proto, "port": port, "source_cidrs": list(sources)}


class ListenAddressTests(unittest.TestCase):
    def test_accepts_literal_unicast(self):
        loopback = {"127.0.0.1", "::1"}
        for value in ["127.0.0.1", "::1", "192.0.2.10", "2001:db8:10::10", "10.0.0.5"]:
            with self.subTest(value=value):
                result = filters.victoriametrics_ip(value)
                self.assertEqual(result["address"], value)
                self.assertEqual(result["loopback"], value in loopback)

    def test_rejects_wildcards_hostnames_and_zones(self):
        for value in ["0.0.0.0", "::", "vm.example.com", "fe80::1%eth0", "", "127.0.0.1:8428", None, 42]:
            with self.subTest(value=value):
                with self.assertRaises(filters.AnsibleFilterError):
                    filters.victoriametrics_ip(value)

    def test_rejects_multicast(self):
        with self.assertRaises(filters.AnsibleFilterError):
            filters.victoriametrics_ip("224.0.0.1")

    def test_canonicalizes_ipv6(self):
        result = filters.victoriametrics_ip("2001:0DB8:10::10")
        self.assertEqual(result["address"], "2001:db8:10::10")
        self.assertEqual(result["version"], 6)

    def test_private_flag_matches_rfc1918_and_ula(self):
        for value in ["10.0.0.1", "172.16.0.1", "192.168.0.1", "fd00::1"]:
            with self.subTest(value=value):
                self.assertTrue(filters.victoriametrics_ip(value)["private"])
        for value in ["192.0.2.1", "8.8.8.8", "2001:db8::1", "169.254.0.1", "127.0.0.1"]:
            with self.subTest(value=value):
                self.assertFalse(filters.victoriametrics_ip(value)["private"])


class AclTests(unittest.TestCase):
    def test_loopback_needs_no_acl_and_forbids_one(self):
        self.assertTrue(filters.victoriametrics_acl_ok(LOOPBACK, 8428, [], [], [], 22, False))
        self.assertTrue(filters.victoriametrics_acl_ok(LOOPBACK, 8428, None, [], [], 22, False))
        self.assertFalse(filters.victoriametrics_acl_ok(LOOPBACK, 8428, ["10.0.0.5/32"], [], [], 22, True))

    def test_private_listen_with_exact_rule(self):
        self.assertTrue(filters.victoriametrics_acl_ok(
            PRIVATE4, 8428, ["10.0.0.5/32"], [rule(["10.0.0.5/32"])], [], 22, True))
        self.assertTrue(filters.victoriametrics_acl_ok(
            PRIVATE6, 8428, ["fd00::5/128"], [rule(["fd00::5/128"])], [], 22, True))

    def test_missing_firewall_or_rule_is_refused(self):
        cases = [
            dict(firewall=False, rules=[rule(["10.0.0.5/32"])]),
            dict(firewall=True, rules=[]),
            dict(firewall=True, rules=[rule(["10.0.0.6/32"])]),
            dict(firewall=True, rules=[rule(["10.0.0.5/32", "10.0.0.6/32"])]),
            dict(firewall=True, rules=[rule(["10.0.0.5/32"], proto="udp")]),
            dict(firewall=True, rules=[rule(["10.0.0.5/32"]), rule(["10.0.0.5/32"])]),
            dict(firewall=True, rules=[rule(["10.0.0.5/32"], port=8429)]),
        ]
        for case in cases:
            with self.subTest(case=case):
                self.assertFalse(filters.victoriametrics_acl_ok(
                    PRIVATE4, 8428, ["10.0.0.5/32"], case["rules"], [], 22, case["firewall"]))

    def test_public_listen_and_wrong_family_are_refused(self):
        public = {"address": "203.0.113.30", "version": 4, "loopback": False, "private": False}
        self.assertFalse(filters.victoriametrics_acl_ok(
            public, 8428, ["10.0.0.5/32"], [rule(["10.0.0.5/32"])], [], 22, True))
        self.assertFalse(filters.victoriametrics_acl_ok(
            PRIVATE4, 8428, ["fd00::5/128"], [rule(["fd00::5/128"])], [], 22, True))
        self.assertFalse(filters.victoriametrics_acl_ok(
            PRIVATE6, 8428, ["10.0.0.5/32"], [rule(["10.0.0.5/32"])], [], 22, True))

    def test_wide_public_or_duplicate_sources_are_refused(self):
        for sources in [[], None, "10.0.0.5/32", ["0.0.0.0/0"], ["::/0"], ["10.0.0.0/8"],
                        ["192.0.2.1/32"], ["203.0.113.0/24"], ["127.0.0.1/32"],
                        ["10.0.0.5/32", "10.0.0.5/32"], ["garbage"]]:
            with self.subTest(sources=sources):
                rules = [rule(sources)] if isinstance(sources, list) else []
                self.assertFalse(filters.victoriametrics_acl_ok(
                    PRIVATE4, 8428, sources, rules, [], 22, True))

    def test_port_conflicts(self):
        self.assertFalse(filters.victoriametrics_acl_ok(
            PRIVATE4, 22, ["10.0.0.5/32"], [rule(["10.0.0.5/32"], port=22)], [], 22, True))
        self.assertFalse(filters.victoriametrics_acl_ok(
            PRIVATE4, 8428, ["10.0.0.5/32"], [rule(["10.0.0.5/32"])],
            [{"proto": "tcp", "port": 8428}], 22, True))
        for port in [True, "8428", 0, 65536]:
            with self.subTest(port=port):
                self.assertFalse(filters.victoriametrics_acl_ok(
                    PRIVATE4, port, ["10.0.0.5/32"], [], [], 22, True))


class TargetsTests(unittest.TestCase):
    def test_renders_host_port_pairs(self):
        self.assertEqual(
            filters.victoriametrics_targets(["exit-a", "relay-a"], 9100),
            ["exit-a:9100", "relay-a:9100"],
        )

    def test_rejects_bad_nodes_and_ports(self):
        with self.assertRaises(filters.AnsibleFilterError):
            filters.victoriametrics_targets("exit-a", 9100)
        with self.assertRaises(filters.AnsibleFilterError):
            filters.victoriametrics_targets([""], 9100)
        with self.assertRaises(filters.AnsibleFilterError):
            filters.victoriametrics_targets(["a b"], 9100)
        for port in ["9100", True, 0, 65536, None]:
            with self.subTest(port=port):
                with self.assertRaises(filters.AnsibleFilterError):
                    filters.victoriametrics_targets(["exit-a"], port)


class PanelTargetTests(unittest.TestCase):
    def test_splits_url(self):
        self.assertEqual(
            filters.victoriametrics_panel_target("http://127.0.0.1:3001/metrics"),
            {"scheme": "http", "hostport": "127.0.0.1:3001", "path": "/metrics"},
        )
        self.assertEqual(
            filters.victoriametrics_panel_target("https://panel:8443"),
            {"scheme": "https", "hostport": "panel:8443", "path": "/metrics"},
        )
        self.assertEqual(
            filters.victoriametrics_panel_target("http://127.0.0.1:3001/custom/path"),
            {"scheme": "http", "hostport": "127.0.0.1:3001", "path": "/custom/path"},
        )

    def test_rejects_non_http_urls(self):
        for value in ["ftp://x/metrics", "127.0.0.1:3001", "", None, "https:///metrics"]:
            with self.subTest(value=value):
                with self.assertRaises(filters.AnsibleFilterError):
                    filters.victoriametrics_panel_target(value)

    def test_ipv6_endpoint(self):
        self.assertEqual(
            filters.victoriametrics_panel_target("http://[::1]:3001/metrics"),
            {"scheme": "http", "hostport": "[::1]:3001", "path": "/metrics"},
        )

    def test_rejects_embedded_credentials_without_echoing_them(self):
        url = "http://synthetic-user:synthetic-password@127.0.0.1:3001/metrics"
        with self.assertRaises(filters.AnsibleFilterError) as caught:
            filters.victoriametrics_panel_target(url)
        self.assertNotIn("synthetic-user", str(caught.exception))
        self.assertNotIn("synthetic-password", str(caught.exception))

    def test_rejects_parameters_fragments_and_invalid_ports(self):
        for url in ["http://panel/metrics?token=synthetic", "http://panel/metrics#fragment",
                    "http://panel:0/metrics", "http://panel:65536/metrics", "http://panel:bad/metrics",
                    "http://panel/metrics\n"]:
            with self.subTest(url=url):
                with self.assertRaises(filters.AnsibleFilterError):
                    filters.victoriametrics_panel_target(url)


class RetentionTests(unittest.TestCase):
    def test_accepts_explicit_units(self):
        for value in ["30d", "24h", "1M", "1y", "2w", "86400s", "1.5d"]:
            with self.subTest(value=value):
                self.assertTrue(filters.victoriametrics_duration_ok(value))

    def test_rejects_bare_numbers_and_garbage(self):
        for value in ["30", "", "1m", "1M2d", "d30", "-5d", "0d", "3600s", "23h", "0.5d",
                      "0.1w", "0.01M", "0.001y", "infd", "1e6d", "1_000d", None, 30]:
            with self.subTest(value=value):
                self.assertFalse(filters.victoriametrics_duration_ok(value))


if __name__ == "__main__":
    unittest.main()
