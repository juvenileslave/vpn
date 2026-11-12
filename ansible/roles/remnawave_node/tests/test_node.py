"""Node-role input policy tests; real API evidence lives in runtime_vm.sh."""
import base64
import importlib.util
import copy
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
runtime = load('node_runtime', ROLE / 'tests/runtime_vm.py')


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


class ActiveAclTests(unittest.TestCase):
    sources = ['10.203.46.2/32', 'fd46:203::2/128']

    @staticmethod
    def match(left, right, op='=='):
        return {'match': {'left': left, 'right': right, 'op': op}}

    @staticmethod
    def header(proto, field):
        return {'payload': {'protocol': proto, 'field': field}}

    def rule(self, *expressions):
        return {'rule': {'family': 'inet', 'table': 'vpn_base', 'chain': 'input', 'expr': [*expressions, {'accept': None}]}}

    def model(self):
        return [
            {'chain': {'family': 'inet', 'table': 'vpn_base', 'name': 'input', 'type': 'filter', 'hook': 'input', 'policy': 'drop'}},
            self.rule(self.match({'meta': {'key': 'iif'}}, 'lo')),
            self.rule(self.match({'ct': {'key': 'state'}}, ['established', 'related'], 'in')),
            self.rule(self.match(self.header('ip', 'saddr'), '10.203.46.2'), self.match(self.header('tcp', 'dport'), 2222)),
            self.rule(self.match(self.header('ip6', 'saddr'), {'prefix': {'addr': 'fd46:203::2', 'len': 128}}), self.match(self.header('tcp', 'dport'), 2222)),
            self.rule(self.match(self.header('udp', 'dport'), 546), self.match(self.header('udp', 'sport'), 547), self.match(self.header('ip6', 'saddr'), {'prefix': {'addr': 'fe80::', 'len': 10}})),
            self.rule(self.match(self.header('icmpv6', 'type'), {'set': ['nd-neighbor-solicit', 'nd-neighbor-advert']}), self.match(self.header('ip6', 'hoplimit'), 255)),
        ]

    def test_supported_base_semantics(self):
        life.acl_model(self.model(), 2222, self.sources)
        model = self.model()
        model[3]['rule']['expr'][1]['match']['right'] = {'set': [2222, {'range': [2224, 2225]}]}
        life.acl_model(model, 2222, self.sources)

    def test_inverted_or_missing_operators_fail_with_correct_source_rules(self):
        for left, right in [(self.header('tcp', 'dport'), 2223), ({'meta': {'key': 'iif'}}, 'lo'), ({'ct': {'key': 'state'}}, 'established'), (self.header('icmp', 'type'), 'echo-request'), (self.header('ip', 'saddr'), '10.203.46.2')]:
            for op in ['!=', '<', '>=', 'in', None]:
                if left == {'ct': {'key': 'state'}} and op == 'in':
                    continue
                with self.subTest(left=left, op=op):
                    model = self.model() + [self.rule(self.match(left, right, op))]
                    with self.assertRaises(life.Rejected):
                        life.acl_model(model, 2222, self.sources)

    def test_unknown_and_broad_accept_paths_fail(self):
        for extra in [self.rule(), self.rule(self.match(self.header('tcp', 'dport'), 2222)), self.rule(self.match(self.header('tcp', 'dport'), '@ports')), self.rule(self.match({'meta': {'key': 'mark'}}, 1)), {'rule': {'chain': 'input', 'expr': [{'jump': {'target': 'other'}}]}}]:
            with self.subTest(extra=extra), self.assertRaises(life.Rejected):
                life.acl_model(self.model() + [extra], 2222, self.sources)

    def test_inverted_exact_source_rule_and_conditional_loopback_fail(self):
        model = self.model()
        model[3]['rule']['expr'][0]['match']['op'] = '!='
        with self.assertRaises(life.Rejected):
            life.acl_model(model, 2222, self.sources)
        model = self.model()
        model[1]['rule']['expr'].insert(1, self.match(self.header('tcp', 'dport'), 2222))
        with self.assertRaises(life.Rejected):
            life.acl_model(model, 2222, self.sources)


class OwnershipAndProbeTests(unittest.TestCase):
    def test_effective_probe_follows_selected_release(self):
        self.assertEqual(life.effective_probe({'port': 2224, 'config': {}}), {'port': 2224, 'require_xray': False})
        self.assertEqual(life.effective_probe({'port': 2222, 'config': {'inbounds': []}}), {'port': 2222, 'require_xray': True})

    def test_directory_is_bound_to_compose_release_and_mounts(self):
        working = '/opt/synthetic-node/releases/' + 'a' * 64
        info = {'Config': {'Labels': {'com.docker.compose.project': life.PROJECT, 'com.docker.compose.service': 'remnanode', life.LABEL: 'remnawave_node', 'com.docker.compose.project.working_dir': working}}, 'Mounts': [{'Destination': '/run/vpn-node/' + name, 'Source': working + '/' + name, 'RW': False} for name in ['probe.json', 'health.cjs']]}
        self.assertEqual(life.container_directory(info), Path('/opt/synthetic-node'))
        for key in ['directory', 'mount', 'writable', 'label']:
            bad = copy.deepcopy(info)
            if key == 'directory':
                bad['Config']['Labels']['com.docker.compose.project.working_dir'] = '/opt/another'
            elif key == 'mount':
                bad['Mounts'][0]['Source'] = '/opt/another/probe.json'
            elif key == 'writable':
                bad['Mounts'][0]['RW'] = True
            else:
                bad['Config']['Labels'][life.LABEL] = 'unrelated'
            with self.subTest(key=key), self.assertRaises(life.Rejected):
                life.container_directory(bad)


class RuntimeDiagnosticTests(unittest.TestCase):
    def test_only_safe_task_and_numeric_recap_escape_capture(self):
        raw = '\n'.join([
            'TASK [remnawave_node : Validate candidate PKI compose and active base ACL] *****',
            'fatal: [node]: FAILED! => {"msg":"sensitive-placeholder"}',
            'node : ok=4 changed=0 unreachable=0 failed=1 skipped=0 rescued=0 ignored=0',
        ])
        safe = runtime.safe_failure_context(raw)
        self.assertIn('failed task: Validate candidate PKI compose and active base ACL', safe)
        self.assertIn('failed=1', safe)
        self.assertNotIn('sensitive-placeholder', safe)
        self.assertNotIn('FAILED!', safe)

    def test_unknown_task_names_and_untrusted_recaps_are_withheld(self):
        raw = 'TASK [sensitive-placeholder] *****\nfatal: [node]: sensitive-placeholder\nnode : ok=1 sensitive-placeholder'
        self.assertEqual(runtime.safe_failure_context(raw), 'captured output withheld (no safe task/recap)')


if __name__ == '__main__':
    unittest.main()
