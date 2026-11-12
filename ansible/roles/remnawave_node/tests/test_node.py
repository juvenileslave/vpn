"""Node-role input policy tests; real API evidence lives in runtime_vm.sh."""
import base64
import importlib.util
import json
from pathlib import Path
import unittest

ROLE = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


acl = load('node_acl', ROLE / 'filter_plugins/remnawave_node.py')
life = load('node_lifecycle', ROLE / 'files/lifecycle.py')


class NodeInputTests(unittest.TestCase):
    def allowed(self, sources=None, rules=None, port=2222, public=None, placement='exit', source='127.0.0.1', address='127.0.0.1'):
        sources = ['127.0.0.1/32', '::1/128'] if sources is None else sources
        rules = [{'proto': 'tcp', 'port': port, 'source_cidrs': sources}] if rules is None else rules
        return acl.acl_valid(sources, rules, port, public or [], 22, placement, source, address)

    def test_exact_loopback_colocated(self):
        self.assertTrue(self.allowed())
        self.assertTrue(self.allowed(source='::1', address='::1'))

    def test_real_private_dedicated_path(self):
        self.assertTrue(self.allowed(['10.203.46.2/32'], placement='dedicated', source='10.203.46.2', address='10.203.46.1'))
        self.assertTrue(self.allowed(['fd46:203::2/128'], placement='dedicated', source='fd46:203::2', address='fd46:203::1'))

    def test_missing_wide_noncanonical_duplicate_sources(self):
        for sources in [[], ['0.0.0.0/0'], ['::/0'], ['127.0.0.0/8'], ['10.0.0.0/8'], ['10.203.46.3/24'], ['::1/128', '::1/128']]:
            with self.subTest(sources=sources):
                self.assertFalse(self.allowed(sources))

    def test_strict_port_type_and_conflict(self):
        for port in [True, '2222', 0, 65536, 22]:
            self.assertFalse(self.allowed(port=port))
        self.assertFalse(self.allowed(public=[{'proto': 'tcp', 'port': 2222}]))
        self.assertFalse(self.allowed(rules=[]))
        self.assertFalse(self.allowed(rules=[{'proto': 'udp', 'port': 2222, 'source_cidrs': ['127.0.0.1/32']}]))

    def test_no_bridged_panel_loopback_assumption(self):
        self.assertFalse(self.allowed(source='172.18.0.2'))
        self.assertFalse(self.allowed(placement='dedicated'))
        self.assertFalse(self.allowed(['10.203.46.2/32'], placement='dedicated', source='10.203.46.3', address='10.203.46.1'))
        self.assertFalse(self.allowed(['10.203.46.2/32'], placement='dedicated', source='10.203.46.2', address='8.8.8.8'))
        self.assertTrue(self.allowed(['172.18.0.2/32'], source='172.18.0.2', address='172.18.0.1'))

    def test_payload_is_encoded_pki_not_random_password(self):
        for secret in ['password', '', base64.b64encode(b'{}').decode(), base64.b64encode(b'[]').decode()]:
            with self.subTest(secret=secret):
                with self.assertRaises(life.Rejected) as caught:
                    life.payload(secret)
                self.assertEqual(str(caught.exception), 'invalid node secret structure')

    def test_payload_normalizes_pem_without_echo(self):
        data = {k: 'synthetic\\nmaterial' for k in ['caCertPem', 'nodeCertPem', 'nodeKeyPem', 'jwtPublicKey']}
        secret = base64.b64encode(json.dumps(data).encode()).decode()
        self.assertEqual(life.payload(secret)['caCertPem'], 'synthetic\nmaterial\n')
        self.assertEqual(set(life.payload(secret)), set(data))


if __name__ == '__main__':
    unittest.main()
