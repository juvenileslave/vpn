"""Policy/transaction tests; not a substitute for the real disposable runtime."""
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
