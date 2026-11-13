"""Consumer-visible local playbook tests; runtime acceptance is a separate driver."""
from __future__ import annotations
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "ansible/roles/profiles/tests"))
from fixtures import bundle, inputs, secret_strings  # noqa: E402


class BundleConsumerTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.topology, self.secret = inputs()
        self.output = self.root / "output"
        self.playbook = Path(sys.executable).with_name("ansible-playbook")
        if not self.playbook.exists():
            self.skipTest("run make -C ansible bootstrap")

    def play(self, topology=None, secret=None, check=False):
        topology, secret = topology or self.topology, secret or self.secret
        inventory = {"all": {"vars": {key: value for key, value in topology.items() if key not in ("exit", "relay")}, "children": {kind: {"hosts": {kind + "-test": topology[kind]}} for kind in ("exit", "relay")}}}
        (self.root / "inventory.yml").write_text(yaml.safe_dump(inventory))
        variables = {**secret, "profiles_output_dir": str(self.output)}
        (self.root / "vars.json").write_text(json.dumps(variables))
        (self.root / "vars.json").chmod(0o600)
        result = subprocess.run([str(self.playbook), "-i", str(self.root / "inventory.yml"), str(ROOT / "ansible/playbooks/profiles.yml"), "-e", "@" + str(self.root / "vars.json"), *( ["--check"] if check else [])], cwd=ROOT / "ansible", env={**os.environ, "ANSIBLE_CONFIG": str(ROOT / "ansible/ansible.cfg"), "ANSIBLE_LOCAL_TEMP": str(self.root / "ansible-tmp"), "ANSIBLE_NOCOLOR": "1"}, capture_output=True, text=True, timeout=180, check=False)
        for value in secret_strings(secret):
            self.assertNotIn(value, result.stdout + result.stderr, "secret leaked")
        return result

    def test_coherent_versioned_candidate_and_idempotence(self):
        first = self.play()
        self.assertEqual(first.returncode, 0, "local bundle playbook failed; output withheld")
        candidate = (self.output / "candidate").resolve()
        manifest = json.loads((candidate / "manifest.json").read_text())
        self.assertEqual(manifest["bundle_id"], candidate.name)
        self.assertFalse((self.output / "current").exists(), "offline files cannot claim runtime usability")
        self.assertFalse((candidate / "transit.json").exists())
        self.assertEqual(set(manifest["hosts"]), {"exit", "relay"})
        self.assertEqual(len(list((candidate / "clients").glob("*.json"))), 4)
        for value in secret_strings(self.secret):
            self.assertNotIn(value, (candidate / "manifest.json").read_text())
        previous = {str(path.relative_to(candidate)): path.read_bytes() for path in candidate.rglob("*") if path.is_file()}
        second = self.play()
        self.assertEqual(second.returncode, 0)
        self.assertRegex(second.stdout, r"exit-test\s*:\s*ok=\d+\s+changed=0\b")
        self.assertEqual(previous, {str(path.relative_to(candidate)): path.read_bytes() for path in candidate.rglob("*") if path.is_file()})
        for path in candidate.rglob("*"):
            self.assertEqual(path.stat().st_mode & 0o777, 0o700 if path.is_dir() else 0o600)

    def test_invalid_inputs_preserve_existing_usable_output(self):
        self.assertEqual(self.play().returncode, 0)
        checked = (self.output / "candidate").resolve()
        (self.output / "current").symlink_to(checked)
        cases = [
            ("exit", "exit_direct_port", True), ("exit", "transit_port", 0),
            ("exit", "cover_tls_port", 8443), ("exit", "reality_target", "foreign.example.com:443"),
            ("exit", "reality_sni", ""), ("exit", "remnawave_node_network_mode", "bridge"),
            ("exit", "reality_max_time_diff_ms", 0), ("relay", "relay_slot_ports", [True, 9444, 9445]),
            ("relay", "relay_egress_ipv6", "2001:db8::99"),
            ("exit", "base_firewall_source_ports", []),
            (None, "slot_fanout", "sni"), (None, "s2s_family", "v4_only"),
        ]
        cases.extend((None, "profiles_probe_url", "http://probe.example.com:" + invalid + "/generate_204") for invalid in ("wrong", "0", "70000", ""))
        for host, key, value in cases:
            with self.subTest(key=key):
                topology = copy.deepcopy(self.topology)
                (topology[host] if host else topology)[key] = value
                self.assertNotEqual(self.play(topology).returncode, 0)
                self.assertEqual((self.output / "current").resolve(), checked)
                self.assertEqual((self.output / "candidate").resolve(), checked)
                self.assertEqual(len(list((self.output / "versions").iterdir())), 1)

    def test_loopback_upstream_preserves_usable_candidate(self):
        self.assertEqual(self.play().returncode, 0)
        checked = (self.output / "candidate").resolve()
        (self.output / "current").symlink_to(checked)
        previous = {str(path.relative_to(checked)): path.read_bytes() for path in checked.rglob("*") if path.is_file()}
        for address in ("127.0.0.1", "::1", "::ffff:127.0.0.1", "proxy.localhost."):
            secret = copy.deepcopy(self.secret)
            secret["profiles_upstreams"] = {"1": {"protocol": "socks", "settings": {"servers": [{"address": address, "port": 1080}]}}}
            self.assertNotEqual(self.play(secret=secret).returncode, 0)
            self.assertEqual((self.output / "current").resolve(), checked)
            self.assertEqual((self.output / "candidate").resolve(), checked)
            self.assertEqual(len(list((self.output / "versions").iterdir())), 1)
            self.assertEqual(previous, {str(path.relative_to(checked)): path.read_bytes() for path in checked.rglob("*") if path.is_file()})

    def test_actual_wireguard_and_hysteria_schemas_reach_candidate(self):
        upstreams = [
            {"protocol": "wireguard", "settings": {"secretKey": "01" * 32, "address": ["10.0.0.2/32", "fd00::2/128"], "peers": [{"publicKey": "02" * 32, "endpoint": "[2001:db8::99]:51820"}]}},
            {"protocol": "hysteria", "settings": {"version": 2, "address": "proxy.example.net", "port": 443}, "streamSettings": {"network": "hysteria", "security": "tls", "hysteriaSettings": {"version": 2, "auth": "synthetic-auth"}}},
        ]
        for upstream in upstreams:
            with self.subTest(protocol=upstream["protocol"]):
                secret = copy.deepcopy(self.secret)
                secret["profiles_upstreams"] = {"1": upstream}
                self.assertEqual(self.play(secret=secret).returncode, 0)
                candidate = (self.output / "candidate").resolve()
                config = json.loads((candidate / "exit.json").read_text())
                self.assertEqual(next(item for item in config["outbounds"] if item["tag"] == "egress-1"), {**upstream, "tag": "egress-1"})

    def test_malformed_protocol_inputs_preserve_candidate_and_prevent_first_write(self):
        invalid = [
            {"protocol": "wireguard", "settings": {"foo": "bar"}},
            {"protocol": "wireguard", "settings": {"secretKey": "bad-key", "peers": [{"publicKey": "02" * 32, "endpoint": "proxy.example.net:51820"}]}},
            {"protocol": "wireguard", "settings": {"secretKey": "01" * 32, "peers": [{"publicKey": "02" * 32, "endpoint": "proxy.example.net"}]}},
            {"protocol": "hysteria", "settings": {"version": 2, "address": "proxy.example.net", "port": True}, "streamSettings": {"network": "hysteria", "security": "tls", "hysteriaSettings": {"version": 2, "auth": "synthetic-auth"}}},
            {"protocol": "hysteria", "settings": {"version": 2, "address": "proxy.example.net", "port": 443}, "streamSettings": {"network": "hysteria", "security": "tls", "hysteriaSettings": {"version": 2}}},
            {"protocol": "hysteria", "settings": {"servers": [{"address": "proxy.example.net", "port": 443, "auth": "obsolete-shape"}]}},
        ]
        for upstream in invalid:
            secret = copy.deepcopy(self.secret)
            secret["profiles_upstreams"] = {"1": upstream}
            self.assertNotEqual(self.play(secret=secret).returncode, 0)
            self.assertFalse(self.output.exists())
        self.assertEqual(self.play().returncode, 0)
        candidate = (self.output / "candidate").resolve()
        (self.output / "current").symlink_to(candidate)
        previous = {str(path.relative_to(candidate)): path.read_bytes() for path in candidate.rglob("*") if path.is_file()}
        for upstream in invalid:
            secret = copy.deepcopy(self.secret)
            secret["profiles_upstreams"] = {"1": upstream}
            self.assertNotEqual(self.play(secret=secret).returncode, 0)
            self.assertEqual((self.output / "candidate").resolve(), candidate)
            self.assertEqual((self.output / "current").resolve(), candidate)
            self.assertEqual(len(list((self.output / "versions").iterdir())), 1)
            self.assertEqual(previous, {str(path.relative_to(candidate)): path.read_bytes() for path in candidate.rglob("*") if path.is_file()})

    def test_omitted_and_explicit_defaults_share_candidate_and_keep_overrides(self):
        omitted = copy.deepcopy(self.topology)
        for kind in ("exit", "relay"):
            omitted[kind].pop("cover_tls_port", None)
            omitted[kind].pop("reality_max_time_diff_ms", None)
        self.assertEqual(self.play(omitted).returncode, 0)
        candidate = (self.output / "candidate").resolve()
        previous = {str(path.relative_to(candidate)): path.read_bytes() for path in candidate.rglob("*") if path.is_file()}
        explicit = copy.deepcopy(omitted)
        for kind in ("exit", "relay"):
            explicit[kind].update(cover_tls_port=9443, reality_max_time_diff_ms=300000)
        result = self.play(explicit)
        self.assertEqual(result.returncode, 0)
        self.assertRegex(result.stdout, r"exit-test\s*:\s*ok=\d+\s+changed=0\b")
        self.assertEqual((self.output / "candidate").resolve(), candidate)
        self.assertEqual(previous, {str(path.relative_to(candidate)): path.read_bytes() for path in candidate.rglob("*") if path.is_file()})
        override = copy.deepcopy(explicit)
        override["exit"].update(cover_tls_port=10443, reality_max_time_diff_ms=150000)
        override["relay"].update(cover_tls_port=11443, reality_max_time_diff_ms=600000)
        self.assertEqual(self.play(override).returncode, 0)
        changed = (self.output / "candidate").resolve()
        self.assertNotEqual(changed, candidate)
        private = json.loads((changed / "inputs.private.json").read_text())["topology"]
        for kind, listener, time_diff in (("exit", 10443, 150000), ("relay", 11443, 600000)):
            self.assertEqual(private[kind]["cover_tls_port"], listener)
            self.assertEqual(private[kind]["reality_max_time_diff_ms"], time_diff)
            reality = json.loads((changed / (kind + ".json")).read_text())["inbounds"][0]["streamSettings"]["realitySettings"]
            self.assertEqual(reality["dest"], "127.0.0.1:" + str(listener))
            self.assertEqual(reality["maxTimeDiff"], time_diff)

    def test_permission_repair_is_consumer_visible_and_idempotent(self):
        self.assertEqual(self.play().returncode, 0)
        checked = (self.output / "candidate").resolve()
        (self.output / "current").symlink_to(checked)
        private = checked / "inputs.private.json"
        previous = private.read_bytes()
        private.chmod(0o644)
        (checked / "clients").chmod(0o755)
        self.output.chmod(0o755)
        repaired = self.play()
        self.assertEqual(repaired.returncode, 0)
        self.assertRegex(repaired.stdout, r"exit-test\s*:\s*ok=\d+\s+changed=1\b")
        self.assertEqual(private.read_bytes(), previous)
        self.assertEqual(private.stat().st_mode & 0o777, 0o600)
        self.assertEqual((checked / "clients").stat().st_mode & 0o777, 0o700)
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o700)
        self.assertEqual((self.output / "current").resolve(), checked)
        self.assertEqual((self.output / "candidate").resolve(), checked)
        self.assertRegex(self.play().stdout, r"exit-test\s*:\s*ok=\d+\s+changed=0\b")

    def test_credentials_rejected_before_writes(self):
        for key, value in (("private_key", "invalid"), ("public_key", "invalid"), ("short_ids", ["abcd"])):
            with self.subTest(key=key):
                secret = copy.deepcopy(self.secret)
                secret["profiles_credentials"]["exit"][key] = value
                self.assertNotEqual(self.play(secret=secret).returncode, 0)
                self.assertFalse(self.output.exists())
        secret = copy.deepcopy(self.secret)
        secret["transit_client_ids"][0] = secret["exit_direct_client_ids"][0]
        self.assertNotEqual(self.play(secret=secret).returncode, 0)
        self.assertFalse(self.output.exists())

    def test_check_mode_and_independent_revocation(self):
        self.assertEqual(self.play(check=True).returncode, 0)
        self.assertFalse(self.output.exists())
        self.assertEqual(self.play().returncode, 0)
        old = (self.output / "candidate").resolve()
        revoked = self.secret["relay_client_ids"][0]
        self.secret["profiles_revoked_client_ids"] = [revoked]
        self.assertEqual(self.play().returncode, 0)
        active = (self.output / "candidate").resolve()
        self.assertNotEqual(active, old)
        self.assertFalse((active / "clients/relay-0.json").exists())
        self.assertNotIn(revoked, (active / "relay.json").read_text())
        restored_input = json.loads((old / "inputs.private.json").read_text())
        restored_input["secrets"]["profiles_revoked_client_ids"] = [revoked]
        _, restored = bundle.render(**{"topology": restored_input["topology"], "secret": restored_input["secrets"]})
        self.assertNotIn(revoked, restored["relay.json"])


if __name__ == "__main__":
    unittest.main()
