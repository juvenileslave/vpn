"""Policy/transaction tests; not a substitute for the real disposable runtime."""
import base64
import copy
import json
from pathlib import Path
import tempfile
import unittest

from fixtures import bundle, inputs


class BundlePolicyTest(unittest.TestCase):
    def setUp(self):
        self.topology, self.secret = inputs(3)

    def rejected(self, change):
        topology, secret = copy.deepcopy(self.topology), copy.deepcopy(self.secret)
        change(topology, secret)
        with self.assertRaises(bundle.Invalid):
            bundle.render(topology, secret)

    def test_transit_source_agreement_and_non_public_management(self):
        self.rejected(lambda t, s: t["relay"].update(relay_egress_ipv4="198.51.100.99"))
        self.rejected(lambda t, s: t["exit"]["base_firewall_source_ports"][0].update(source_cidrs=["198.51.100.0/24", "2001:db8:20::20/128"]))
        self.rejected(lambda t, s: t["exit"]["base_firewall_vpn_ports"].append({"proto": "tcp", "port": 2222}))
        self.rejected(lambda t, s: t["exit"]["base_firewall_vpn_ports"].append({"proto": "tcp", "port": 8444}))
        self.rejected(lambda t, s: t["exit"]["base_firewall_source_ports"].append({"proto": "tcp", "port": t["exit"]["cover_tls_port"], "source_cidrs": ["192.0.2.1/32"]}))
        self.rejected(lambda t, s: t["exit"]["base_firewall_source_ports"][0].update(port=True))
        self.rejected(lambda t, s: t["exit"].update(node_port_allow=["0.0.0.0/0"]))
        self.rejected(lambda t, s: t["exit"].update(node_port_allow=["127.0.0.0/8"]))

    def test_credentials_time_window_and_fixed_profile(self):
        self.rejected(lambda t, s: s["profiles_credentials"]["exit"].update(short_ids=["abcd"]))
        self.rejected(lambda t, s: s["profiles_credentials"]["exit"].update(short_ids=["a" * 16, "a" * 16]))
        self.rejected(lambda t, s: s["profiles_credentials"].update(relay=s["profiles_credentials"]["exit"]))
        self.rejected(lambda t, s: s.update(profiles_user_slots=[0, 1, True]))
        self.rejected(lambda t, s: t.update(xhttp_mode="packet-up"))
        self.rejected(lambda t, s: t["exit"].update(reality_max_time_diff_ms=True))
        self.rejected(lambda t, s: t["exit"].update(reality_target="foreign.example.com:443"))
        self.rejected(lambda t, s: t["relay"].update(relay_slot_ports=[22, 9444, 9445]))
        self.rejected(lambda t, s: t.update(slot_fanout="sni"))

    def test_fixed_slot_policy_has_no_default_egress_leak(self):
        self.secret["profiles_user_slots"] = [0, 1, 2]
        _, files = bundle.render(self.topology, self.secret)
        exit_config = json.loads(files["exit.json"])
        rules = exit_config["routing"]["rules"]
        by_user = {rule["user"][0]: rule["outboundTag"] for rule in rules if "user" in rule}
        self.assertEqual(by_user, {"egress-0": "egress-0", "egress-1": "block", "egress-2": "block"})
        self.assertEqual(rules[-1]["outboundTag"], "block")
        relay = json.loads(files["relay.json"])
        self.assertNotIn("freedom", [item["protocol"] for item in relay["outbounds"]])
        self.assertEqual(relay["routing"]["rules"][-1]["outboundTag"], "block")
        self.secret["profiles_upstreams"] = {"1": {"protocol": "socks", "settings": {"servers": [{"address": "192.0.2.99", "port": 1080}]}}}
        _, files = bundle.render(self.topology, self.secret)
        rules = json.loads(files["exit.json"])["routing"]["rules"]
        self.assertEqual(next(rule["outboundTag"] for rule in rules if rule.get("user") == ["egress-1"]), "egress-1")
        self.rejected(lambda t, s: s.update(profiles_upstreams={"1": {"protocol": "freedom", "settings": {}}}))
        self.rejected(lambda t, s: s["profiles_upstreams"]["1"]["settings"]["servers"][0].update(port=True))
        self.rejected(lambda t, s: s.update(profiles_upstreams={"1": {"protocol": "vless", "settings": {"vnext": [{"address": "192.0.2.99", "port": 443, "users": [{"id": "invalid"}]}]}}}))

    def test_loopback_upstreams_rejected_before_writes(self):
        for protocol, field in (("socks", "servers"), ("http", "servers"), ("vless", "vnext")):
            for address in ("127.0.0.1", "127.9.8.7", "127.0.0.1.", "127.1", "2130706433", "0x7f000001", "::1", "::ffff:127.0.0.1", "::ffff:7f00:1", "localhost", "LOCALHOST.", "proxy.localhost.", "localhost.localdomain", "ip6-localhost", "ip6-loopback"):
                with self.subTest(protocol=protocol, address=address):
                    record = {"address": address, "port": 1080}
                    if protocol == "vless":
                        record["users"] = [{"id": self.secret["relay_client_ids"][0]}]
                    self.rejected(lambda t, s: s.update(profiles_upstreams={"1": {"protocol": protocol, "settings": {field: [record]}}}))
        self.rejected(lambda t, s: s.update(profiles_upstreams={"1": {"protocol": "wireguard", "settings": {"secretKey": "01" * 32, "peers": [{"publicKey": "02" * 32, "endpoint": "[::ffff:127.0.0.1]:1080"}]}}}))

    def test_upstream_rotation_versions_candidate_and_invalid_rotation_preserves_it(self):
        wireguard = {"protocol": "wireguard", "settings": {"secretKey": base64.b64encode(bytes(range(32))).decode(), "peers": [{"publicKey": base64.urlsafe_b64encode(bytes(range(255, 223, -1))).rstrip(b"=").decode(), "preSharedKey": "", "endpoint": "192.0.2.99:51820"}]}}
        hysteria = {"protocol": "hysteria", "settings": {"version": 2, "address": "proxy.example.net", "port": 443}, "streamSettings": {"network": "hysteria", "security": "tls", "hysteriaSettings": {"version": 2, "auth": "synthetic-auth"}}}
        for upstream in (wireguard, hysteria):
            with self.subTest(protocol=upstream["protocol"]), tempfile.TemporaryDirectory() as temporary:
                secret = copy.deepcopy(self.secret)
                secret["profiles_upstreams"] = {"1": copy.deepcopy(upstream)}
                identity, files = bundle.render(copy.deepcopy(self.topology), secret)
                root = Path(temporary).resolve() / "bundle"
                bundle.write_bundle(root, identity, files)
                previous = (root / "candidate").resolve()
                previous_bytes = (previous / "exit.json").read_bytes()
                rotated = secret["profiles_upstreams"]["1"]
                credentials = rotated["settings"] if rotated["protocol"] == "wireguard" else rotated["streamSettings"]["hysteriaSettings"]
                key = "secretKey" if rotated["protocol"] == "wireguard" else "auth"
                credentials[key] = "03" * 32 if key == "secretKey" else "rotated-synthetic-auth"
                rotated_identity, rotated_files = bundle.render(copy.deepcopy(self.topology), secret)
                self.assertNotEqual(rotated_identity, identity)
                bundle.write_bundle(root, rotated_identity, rotated_files)
                current = (root / "candidate").resolve()
                self.assertEqual(current.name, rotated_identity)
                self.assertEqual((previous / "exit.json").read_bytes(), previous_bytes)
                current_bytes = (current / "exit.json").read_bytes()
                credentials[key] = ""
                with self.assertRaises(bundle.Invalid):
                    bad_identity, bad_files = bundle.render(copy.deepcopy(self.topology), secret)
                    bundle.write_bundle(root, bad_identity, bad_files)
                self.assertEqual((root / "candidate").resolve(), current)
                self.assertEqual((current / "exit.json").read_bytes(), current_bytes)

    def test_malformed_wireguard_and_hysteria_never_write(self):
        wireguard = {"protocol": "wireguard", "settings": {"secretKey": "01" * 32, "address": ["10.0.0.2/32"], "peers": [{"publicKey": "02" * 32, "endpoint": "proxy.example.net:51820"}]}}
        hysteria = {"protocol": "hysteria", "settings": {"version": 2, "address": "proxy.example.net", "port": 443}, "streamSettings": {"network": "hysteria", "security": "tls", "hysteriaSettings": {"version": 2, "auth": "synthetic-auth"}}}
        invalid = []
        for key in (None, True, "", "fixture", "0" * 63, "g" * 64, base64.b64encode(b"x" * 31).decode()):
            for field in ("secretKey", "publicKey", "preSharedKey"):
                if field == "preSharedKey" and key == "":
                    continue  # Explicitly omitting an optional PSK is valid.
                upstream = copy.deepcopy(wireguard)
                (upstream["settings"] if field == "secretKey" else upstream["settings"]["peers"][0])[field] = key
                invalid.append(upstream)
        for peers in (None, [], [{}], [None], [{"publicKey": "02" * 32}], [{"endpoint": "proxy.example.net:51820"}]):
            upstream = copy.deepcopy(wireguard)
            upstream["settings"]["peers"] = peers
            invalid.append(upstream)
        for endpoint in (None, "", "proxy.example.net", "proxy.example.net:", "proxy.example.net:wrong", "proxy.example.net:0", "proxy.example.net:65536", "proxy.example.net:-1", "2001:db8::99:51820", "[2001:db8::99]", "user@proxy.example.net:51820", "@proxy.example.net:51820", ":@proxy.example.net:51820", "proxy.example.net:51820/path", "bad host:51820"):
            upstream = copy.deepcopy(wireguard)
            upstream["settings"]["peers"][0]["endpoint"] = endpoint
            invalid.append(upstream)
        for addresses in (None, [], "10.0.0.2", [True], ["bad-address"], ["10.0.0.2/33"], ["fe80::2%eth0"]):
            upstream = copy.deepcopy(wireguard)
            upstream["settings"]["address"] = addresses
            invalid.append(upstream)
        for field, values in (("version", (None, True, "2", 1, 3)), ("address", (None, True, "", "bad host", "https://proxy.example.net", "[bad]")), ("port", (None, True, "443", 0, 65536))):
            for value in values:
                upstream = copy.deepcopy(hysteria)
                upstream["settings"][field] = value
                invalid.append(upstream)
        for field, value in (("network", None), ("network", "quic"), ("network", "tcp"), ("security", "none"), ("security", True), ("hysteriaSettings", None), ("tlsSettings", "invalid")):
            upstream = copy.deepcopy(hysteria)
            upstream["streamSettings"][field] = value
            invalid.append(upstream)
        for field, values in (("version", (None, True, "2", 1)), ("auth", (None, True, ""))):
            for value in values:
                upstream = copy.deepcopy(hysteria)
                upstream["streamSettings"]["hysteriaSettings"][field] = value
                invalid.append(upstream)
        invalid.extend(({"protocol": "wireguard", "settings": {"foo": "bar"}}, {"protocol": "hysteria", "settings": {"servers": [{"address": "proxy.example.net", "port": 443, "auth": "obsolete-shape"}]}}))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "bundle"
            for index, upstream in enumerate(invalid):
                with self.subTest(case=index, protocol=upstream["protocol"]):
                    secret = copy.deepcopy(self.secret)
                    secret["profiles_upstreams"] = {"1": upstream}
                    with self.assertRaises(bundle.Invalid):
                        identity, files = bundle.render(copy.deepcopy(self.topology), secret)
                        bundle.write_bundle(root, identity, files)
                    self.assertFalse(root.exists())

    def test_effective_defaults_have_one_identity_and_preserve_overrides(self):
        omitted, explicit = copy.deepcopy(self.topology), copy.deepcopy(self.topology)
        for kind in ("exit", "relay"):
            for key, default in (("cover_tls_port", 9443), ("reality_max_time_diff_ms", 300000)):
                omitted[kind].pop(key, None)
                explicit[kind][key] = default
        omitted_id, omitted_files = bundle.render(omitted, self.secret)
        explicit_id, explicit_files = bundle.render(explicit, self.secret)
        self.assertEqual(omitted_id, explicit_id)
        self.assertEqual(omitted_files, explicit_files)
        effective = json.loads(omitted_files["inputs.private.json"])["topology"]
        for kind in ("exit", "relay"):
            self.assertEqual(effective[kind]["cover_tls_port"], 9443)
            self.assertEqual(effective[kind]["reality_max_time_diff_ms"], 300000)
        for kind in ("exit", "relay"):
            for key, value, output_key in (("cover_tls_port", 20000, "dest"), ("reality_max_time_diff_ms", 150000, "maxTimeDiff")):
                with self.subTest(kind=kind, key=key):
                    override = copy.deepcopy(explicit)
                    override[kind][key] = value
                    override_id, files = bundle.render(override, self.secret)
                    self.assertNotEqual(override_id, explicit_id)
                    self.assertEqual(override[kind][key], value)
                    expected = "127.0.0.1:" + str(value) if key == "cover_tls_port" else value
                    config = json.loads(files[kind + ".json"])
                    self.assertTrue(all(item["streamSettings"]["realitySettings"][output_key] == expected for item in config["inbounds"]))
        for kind in ("exit", "relay"):
            for key in ("cover_tls_port", "reality_max_time_diff_ms"):
                for value in (None, True, "9443", 0, -1):
                    with self.subTest(kind=kind, key=key, value=value):
                        self.rejected(lambda t, s: t[kind].update({key: value}))

    def test_observatory_port_validation(self):
        for authority in ("probe.example.com:wrong", "probe.example.com:0", "probe.example.com:70000", "probe.example.com:-1", "probe.example.com:", "[2001:db8::1]:70000"):
            with self.subTest(authority=authority):
                self.rejected(lambda t, s: t.update(profiles_probe_url="http://" + authority + "/generate_204"))
        for url in ("http://probe.example.com/generate_204", "https://probe.example.com:65535/generate_204"):
            topology = copy.deepcopy(self.topology)
            topology["profiles_probe_url"] = url
            bundle.render(topology, self.secret)

    def test_explicit_relay_address_contract(self):
        for key, address in (("relay_egress_ipv4", "127.0.0.1"), ("relay_egress_ipv4", "169.254.1.1"), ("relay_egress_ipv4", "224.0.0.1"), ("relay_egress_ipv4", "0.0.0.0"), ("relay_egress_ipv6", "::1"), ("relay_egress_ipv6", "fe80::1"), ("relay_egress_ipv6", "ff02::1"), ("relay_egress_ipv6", "::"), ("relay_egress_ipv6", "::ffff:192.0.2.20"), ("relay_egress_ipv6", "192.0.2.20")):
            with self.subTest(key=key, address=address):
                topology = copy.deepcopy(self.topology)
                topology["relay"][key] = address
                version = 4 if key.endswith("4") else 6
                rule = topology["exit"]["base_firewall_source_ports"][0]
                rule["source_cidrs"][version == 6] = address + ("/32" if version == 4 else "/128")
                with self.assertRaises(bundle.Invalid):
                    bundle.validate_addresses(topology["exit"], topology["relay"])
        normalized = copy.deepcopy(self.topology)
        normalized["relay"]["relay_egress_ipv6"] = "2001:0db8:0020:0000:0000:0000:0000:0020"
        normalized["relay"]["public_ipv6"] = "2001:0db8:0020:0000:0000:0000:0000:0020"
        self.assertEqual(bundle.validate_addresses(normalized["exit"], normalized["relay"]),
                         {"198.51.100.20/32", "2001:db8:20::20/128"})
        normalized["relay"]["public_ipv6"] = "2001:0db8:0010:0000:0000:0000:0000:0010"
        with self.assertRaises(bundle.Invalid):
            bundle.validate_addresses(normalized["exit"], normalized["relay"])

    def test_permission_only_drift_repaired_without_bytes_or_pointer_change(self):
        identity, files = bundle.render(self.topology, self.secret)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve() / "bundle"
            bundle.write_bundle(root, identity, files)
            target = (root / "candidate").resolve()
            (root / "current").symlink_to("versions/" + identity)
            before = {name: (target / name).read_bytes() for name in files}
            drift = [root, root / "versions", target, target / "clients", target / "inputs.private.json"]
            for path in drift:
                path.chmod(0o755 if path.is_dir() else 0o644)
            self.assertTrue(bundle.write_bundle(root, identity, files, check=True))
            self.assertEqual((target / "inputs.private.json").stat().st_mode & 0o777, 0o644)
            self.assertTrue(bundle.write_bundle(root, identity, files))
            self.assertFalse(bundle.write_bundle(root, identity, files))
            for path in drift:
                self.assertEqual(path.stat().st_mode & 0o777, 0o700 if path.is_dir() else 0o600)
            self.assertEqual(before, {name: (target / name).read_bytes() for name in files})
            self.assertEqual((root / "current").resolve(), target)
            self.assertEqual((root / "candidate").resolve(), target)

    def test_immutable_output_rejects_tampering_and_unsafe_paths(self):
        identity, files = bundle.render(self.topology, self.secret)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve() / "bundle"
            self.assertTrue(bundle.write_bundle(root, identity, files))
            self.assertFalse(bundle.write_bundle(root, identity, files))
            target = (root / "candidate").resolve()
            (target / "exit.json").write_text("{}")
            with self.assertRaises(bundle.Invalid):
                bundle.write_bundle(root, identity, files)
            self.assertEqual((root / "candidate").resolve(), target)
            other = Path(temporary).resolve() / "linked"
            other.symlink_to(root, target_is_directory=True)
            with self.assertRaises(bundle.Invalid):
                bundle.write_bundle(other, identity, files)


if __name__ == "__main__":
    unittest.main()
