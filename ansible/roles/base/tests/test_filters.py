"""Unit tests for the base role validation filters (no network, no host changes)."""

from __future__ import annotations

import base64
import importlib.util
import os
from pathlib import Path
import struct
import unittest

PLUGIN = Path(__file__).resolve().parents[1] / "filter_plugins" / "vpn_base.py"
_spec = importlib.util.spec_from_file_location("vpn_base", PLUGIN)
vpn_base = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(vpn_base)

# Assembled at runtime so repository secret scanners do not see a key header.
PRIVATE_MARKER = "-----BEGIN OPENSSH " + "PRIVATE KEY-----"


def _string(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


def ed25519_key(comment: str = "test") -> str:
    blob = _string(b"ssh-ed25519") + _string(os.urandom(32))
    return f"ssh-ed25519 {base64.b64encode(blob).decode()} {comment}"


def rsa_key(bits: int) -> str:
    modulus = (1 << (bits - 1)) | 1
    blob = (_string(b"ssh-rsa") + _string(b"\x01\x00\x01")
            + _string(b"\x00" + modulus.to_bytes(bits // 8, "big")))
    return f"ssh-rsa {base64.b64encode(blob).decode()}"


def valid_config(**overrides) -> dict:
    config = {
        "base_admin_users": [],
        "base_admin_sudo_nopasswd": True,
        "base_ssh_enabled": False,
        "base_ssh_port": 22,
        "base_ssh_permit_root_login": "no",
        "base_ssh_trusted_cidrs": [],
        "base_firewall_enabled": False,
        "base_firewall_vpn_ports": [],
        "base_firewall_source_ports": [],
        "base_firewall_allow_icmp_echo": True,
        "base_firewall_allow_dhcpv6_client": True,
        "base_firewall_acknowledged_closed_ports": [],
        "base_chrony_enabled": True,
        "base_chrony_pools": [],
        "base_unattended_upgrades_enabled": True,
        "base_unattended_origins_patterns": ["origin=Debian,codename=${distro_codename}-security"],
        "base_bbr_enabled": True,
        "base_bbr_qdisc": "fq",
        "base_swap_enabled": False,
        "base_swap_file": "/swapfile",
        "base_swap_size_mb": 1024,
    }
    config.update(overrides)
    return config


class PublicKeyTest(unittest.TestCase):
    def test_accepts_ed25519_and_long_rsa(self):
        self.assertIsNone(vpn_base.public_key_error(ed25519_key()))
        self.assertIsNone(vpn_base.public_key_error(rsa_key(4096)))

    def test_rejects_unsafe_keys(self):
        key = ed25519_key()
        body = key.split()[1]
        cases = [
            rsa_key(2048),
            "ssh-dss " + body,
            f'command="/bin/sh" {key}',
            "ssh-ed25519 not-base64!",
            "ssh-rsa " + body,  # declared type differs from blob
            key + "\nssh-ed25519 " + body,
            PRIVATE_MARKER,
            "ssh-ed25519",
            None,
        ]
        for case in cases:
            with self.subTest(case=str(case)[:30]):
                self.assertIsNotNone(vpn_base.public_key_error(case))

    def test_missing_keys_preserves_existing_lines(self):
        old, new = ed25519_key("old"), ed25519_key("new")
        existing = f'# comment\nfrom="192.0.2.0/24" {old.replace("old", "renamed")}\n'
        self.assertEqual(vpn_base.missing_keys(existing, [old, new, new]), [new])
        self.assertEqual(vpn_base.missing_keys("", [old]), [old])


class NetworkTest(unittest.TestCase):
    def test_cidrs(self):
        for good in ("192.0.2.0/24", "198.51.100.7/32", "2001:db8::/48", "10.0.0.0/8"):
            self.assertIsNone(vpn_base.cidr_error(good), good)
        for bad in ("0.0.0.0/0", "::/0", "192.0.2.1/24", "192.0.2.1", "10.0.0.0/7",
                    "2001:db8::/31", "127.0.0.0/8", "224.0.0.0/8", "::ffff:192.0.2.0/120",
                    "example", 24):
            self.assertIsNotNone(vpn_base.cidr_error(bad), bad)

    def test_split_and_source(self):
        cidrs = ["192.0.2.0/24", "2001:db8::/48", "192.0.2.0/24"]
        self.assertEqual(vpn_base.split_cidrs(cidrs),
                         {"v4": ["192.0.2.0/24"], "v6": ["2001:db8::/48"]})
        self.assertTrue(vpn_base.ssh_source_allowed("192.0.2.9", cidrs))
        self.assertTrue(vpn_base.ssh_source_allowed("::ffff:192.0.2.9", cidrs))
        self.assertTrue(vpn_base.ssh_source_allowed("2001:db8::5", cidrs))
        self.assertTrue(vpn_base.ssh_source_allowed("127.0.0.1", cidrs))
        self.assertFalse(vpn_base.ssh_source_allowed("198.51.100.1", cidrs))

    def test_uncovered_listeners(self):
        ss = "\n".join([
            "tcp LISTEN 0 4096 0.0.0.0:22 0.0.0.0:*",
            "tcp LISTEN 0 4096 [::]:443 [::]:*",
            "tcp LISTEN 0 4096 127.0.0.1:8080 0.0.0.0:*",
            "tcp LISTEN 0 4096 [::1]:9090 [::]:*",
            "udp UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:*",
            "udp UNCONN 0 0 10.0.0.5%eth0:68 0.0.0.0:*",
            "udp UNCONN 0 0 *:51820 *:*",
            "tcp LISTEN 0 4096 *:2053 *:*",
            "udp UNCONN 0 0 [fe80::1]%eth0:546 [::]:*",
        ])
        ports = [{"proto": "tcp", "port": 443}]
        self.assertEqual(vpn_base.uncovered_listeners(ss, 22, ports, []),
                         ["tcp/2053", "udp/51820"])
        self.assertEqual(vpn_base.uncovered_listeners(ss, 22, ports, ["tcp/2053", "udp/51820"]), [])
        self.assertEqual(vpn_base.uncovered_listeners(ss, 22, ports, ["tcp/2053", "udp/51820"],
                                                      allow_dhcpv6_client=False), ["udp/546"])

    def test_restricted_listeners_are_managed_without_public_exposure(self):
        ss = "tcp LISTEN 0 4096 [::]:8443 [::]:*\nudp UNCONN 0 0 *:8444 *:*"
        restricted = [
            {"proto": "tcp", "port": 8443, "source_cidrs": ["192.0.2.2/32"]},
            {"proto": "udp", "port": 8444, "source_cidrs": ["2001:db8::2/128"]},
        ]
        self.assertEqual(vpn_base.uncovered_listeners(ss, 22, [], [],
                                                    source_ports=restricted), [])

    def test_sshd_effective(self):
        parsed = vpn_base.sshd_effective("port 22\nport 2222\nPasswordAuthentication no\n")
        self.assertEqual(parsed["port"], ["22", "2222"])
        self.assertEqual(parsed["passwordauthentication"], ["no"])


class InputTest(unittest.TestCase):
    def test_enabled_configuration_is_valid(self):
        config = valid_config(
            base_ssh_enabled=True,
            base_firewall_enabled=True,
            base_admin_users=[{"name": "opsadmin", "authorized_keys": [ed25519_key()]}],
            base_ssh_trusted_cidrs=["192.0.2.0/24", "2001:db8::/48"],
            base_firewall_vpn_ports=[{"proto": "tcp", "port": 443}, {"proto": "udp", "port": 443}],
            base_firewall_acknowledged_closed_ports=["tcp/8080"],
        )
        self.assertEqual(vpn_base.input_errors(config), [])

    def test_source_ports_allow_safe_management_subnets_and_separate_protocols(self):
        config = valid_config(base_firewall_source_ports=[
            {"proto": "tcp", "port": 8443,
             "source_cidrs": ["192.0.2.0/24", "2001:db8::/48"]},
            {"proto": "udp", "port": 22, "source_cidrs": ["198.51.100.2/32"]},
        ], base_firewall_vpn_ports=[{"proto": "udp", "port": 8443}])
        self.assertEqual(vpn_base.input_errors(config), [])

    def test_colocated_loopback_is_only_a_source_acl_exception(self):
        for cidr in ("127.0.0.1/32", "::1/128"):
            self.assertIsNone(vpn_base.source_cidr_error(cidr))
            self.assertIsNotNone(vpn_base.cidr_error(cidr))
        self.assertEqual(vpn_base.input_errors(valid_config(base_firewall_source_ports=[
            {"proto": "tcp", "port": 2222, "source_cidrs": ["127.0.0.1/32", "::1/128"]}
        ])), [])

    def test_restricted_dhcpv6_conflict_is_rejected_for_each_declared_family(self):
        for sources in (["198.51.100.77/32"], ["2001:db8:100::77/128"],
                        ["198.51.100.77/32", "2001:db8:100::77/128"]):
            for enabled in (False, True):
                with self.subTest(sources=sources, firewall_enabled=enabled):
                    config = valid_config(
                        base_firewall_enabled=enabled,
                        base_ssh_trusted_cidrs=["192.0.2.0/24"],
                        base_firewall_allow_dhcpv6_client=True,
                        base_firewall_source_ports=[
                            {"proto": "udp", "port": 546, "source_cidrs": sources}])
                    errors = vpn_base.input_errors(config)
                    self.assertTrue(any("base_firewall_source_ports[0]" in error
                                        and "base_firewall_allow_dhcpv6_client" in error
                                        for error in errors))
                    self.assertFalse(any(source in error for source in sources for error in errors))
                    config["base_firewall_allow_dhcpv6_client"] = False
                    self.assertEqual(vpn_base.input_errors(config), [])
                    config["base_firewall_allow_dhcpv6_client"] = True
                    config["base_firewall_source_ports"][0]["proto"] = "tcp"
                    self.assertEqual(vpn_base.input_errors(config), [])

    def test_source_port_rejections_do_not_echo_sources(self):
        source = "198.51.100.77/32"
        valid = {"proto": "tcp", "port": 8443, "source_cidrs": [source]}
        cases = [None, {}, "8443", [None], [dict(valid, unknown=True)],
                 [dict(valid, proto=True)], [dict(valid, proto=[])],
                 [dict(valid, port=True)], [dict(valid, port="8443")],
                 [dict(valid, port=0)], [dict(valid, port=65536)],
                 [dict(valid, port=22)], [valid, valid],
                 [dict(valid, source_cidrs=[])], [dict(valid, source_cidrs=source)],
                 [dict(valid, source_cidrs=[source, source])]]
        for bad_cidr in (None, True, 123, "invalid", "0.0.0.0/0", "::/0",
                         "10.0.0.0/7", "2001:db8::/31", "192.0.2.1/24",
                         "127.0.0.0/8", "127.0.0.2/32", "::/127", "224.0.0.0/8",
                         "::ffff:192.0.2.2/128"):
            cases.append([dict(valid, source_cidrs=[bad_cidr])])
        for index, entries in enumerate(cases):
            with self.subTest(index=index):
                errors = vpn_base.input_errors(valid_config(base_firewall_source_ports=entries))
                self.assertTrue(errors)
                self.assertTrue(any("base_firewall_source_ports" in error for error in errors))
                self.assertFalse(any(source in error for error in errors))
        errors = vpn_base.input_errors(valid_config(
            base_firewall_source_ports=[valid],
            base_firewall_vpn_ports=[{"proto": "tcp", "port": 8443}]))
        self.assertTrue(any("конфликт" in error for error in errors))

    def test_rejections(self):
        key = ed25519_key()
        admin = {"name": "opsadmin", "authorized_keys": [key]}
        cases = {
            "toggle string": valid_config(base_firewall_enabled="false"),
            "root admin": valid_config(base_admin_users=[{"name": "root", "authorized_keys": [key]}]),
            "bad name": valid_config(base_admin_users=[{"name": "Ops Admin"}]),
            "duplicate": valid_config(base_admin_users=[admin, admin]),
            "unknown field": valid_config(base_admin_users=[dict(admin, groups=["docker"])]),
            "ssh no admin": valid_config(base_ssh_enabled=True),
            "ssh admin without sudo": valid_config(
                base_ssh_enabled=True, base_admin_users=[dict(admin, sudo=False)]),
            "firewall no cidrs": valid_config(base_firewall_enabled=True),
            "host bits": valid_config(base_ssh_trusted_cidrs=["192.0.2.1/24"]),
            "world": valid_config(base_ssh_trusted_cidrs=["0.0.0.0/0"]),
            "ssh as vpn port": valid_config(base_firewall_vpn_ports=[{"proto": "tcp", "port": 22}]),
            "bad port": valid_config(base_firewall_vpn_ports=[{"proto": "tcp", "port": 70000}]),
            "bool port": valid_config(base_firewall_vpn_ports=[{"proto": "udp", "port": True}]),
            "bad proto": valid_config(base_firewall_vpn_ports=[{"proto": "sctp", "port": 1}]),
            "bad ack": valid_config(base_firewall_acknowledged_closed_ports=["8080"]),
            "root login yes": valid_config(base_ssh_permit_root_login="yes"),
            "pool injection": valid_config(base_chrony_pools=["pool.example.com\nallow all"]),
            "origin injection": valid_config(base_unattended_origins_patterns=['a"; Evil "b']),
            "no origins": valid_config(base_unattended_origins_patterns=[]),
            "relative swap": valid_config(base_swap_file="swapfile"),
            "dotdot swap": valid_config(base_swap_file="/var/../swapfile"),
            "small swap": valid_config(base_swap_size_mb=1),
            "qdisc": valid_config(base_bbr_qdisc="cake"),
        }
        for name, config in cases.items():
            with self.subTest(name):
                errors = vpn_base.input_errors(config)
                self.assertTrue(errors)
                self.assertFalse(any(key.split()[1] in error for error in errors))


if __name__ == "__main__":
    unittest.main()
