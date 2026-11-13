#!/usr/bin/env python3
"""Real-image acceptance scenarios, only in explicitly disposable CI guests."""
import base64
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import yaml


SAFE_TASKS = {
    'Validate node inputs before host mutation',
    'Validate candidate PKI compose and active base ACL',
    'Roll out with authenticated health gate and credential-safe restoration',
    'Perform genuine mTLS and JWT health operation from the CP source',
    'Restore checked deployment without undoing credential revocation',
    'Fail closed when restored local or control-plane health is unavailable',
    'Reject restoration after stopping only the transaction-owned node',
    'Stop rollout after a failed gate even when restoration succeeded',
    'Render owned nftables table', 'Verify owned table is loaded',
}


def safe_failure_context(output):
    """Only repository-authored task labels and numeric recaps can leave capture."""
    output = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', output)
    context = []
    task = None
    for line in output.splitlines():
        heading = re.fullmatch(r'TASK \[(.+)\] \*+', line.strip())
        if heading:
            name = heading[1].rsplit(' : ', 1)[-1]
            task = name if name in SAFE_TASKS else None
        elif line.startswith('fatal:') and task:
            context.append('failed task: ' + task)
        recap = re.fullmatch(r'(node|cp|bridge_cp|bad_cp)\s*:\s*((?:(?:ok|changed|unreachable|failed|skipped|rescued|ignored)=\d+\s*)+)', line.strip())
        if recap:
            context.append('recap ' + recap[1] + ': ' + recap[2].strip())
    return '; '.join(context) or 'captured output withheld (no safe task/recap)'


def command(args, expected=0, timeout=600):
    result = subprocess.run([str(a) for a in args], capture_output=True, timeout=timeout, check=False)
    if (result.returncode == 0) != (expected == 0):
        # Never echo raw Ansible/Docker/API output, exception bodies or arguments.
        detail = safe_failure_context(result.stdout.decode(errors='replace')) if Path(str(args[0])).name == 'ansible-playbook' else 'captured output withheld'
        raise AssertionError('unexpected command result: ' + Path(str(args[0])).name + '; ' + detail)
    return result.stdout.decode()


def guard():
    if os.geteuid() != 0 or sys.platform != 'linux' or any(os.environ.get(k) != v for k, v in {
        'VPN_REMNAWAVE_NODE_DISPOSABLE_GUEST': 'yes', 'GITHUB_ACTIONS': 'true',
        'RUNNER_ENVIRONMENT': 'github-hosted',
    }.items()):
        raise SystemExit('refusing non-disposable runtime')


def write_json(path, value):
    path.write_text(json.dumps(value))
    path.chmod(0o600)


def fixture(directory):
    directory.mkdir(mode=0o700)
    command(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-noenc', '-keyout', directory / 'ca.key', '-out', directory / 'ca.pem', '-days', '2', '-subj', '/CN=Disposable Node CA', '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign'])
    for name, usage in [('node', 'serverAuth'), ('client', 'clientAuth'), ('target', 'serverAuth')]:
        command(['openssl', 'req', '-new', '-newkey', 'rsa:2048', '-noenc', '-keyout', directory / (name + '.key'), '-out', directory / (name + '.csr'), '-subj', '/CN=Disposable ' + name])
        ext = directory / (name + '.ext')
        ext.write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=' + usage + '\nsubjectAltName=IP:127.0.0.1\n')
        command(['openssl', 'x509', '-req', '-in', directory / (name + '.csr'), '-CA', directory / 'ca.pem', '-CAkey', directory / 'ca.key', '-CAcreateserial', '-out', directory / (name + '.pem'), '-days', '2', '-extfile', ext])
    command(['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', directory / 'jwt.key'])
    public = command(['openssl', 'pkey', '-in', directory / 'jwt.key', '-pubout'])
    payload = {'caCertPem': (directory / 'ca.pem').read_text(), 'nodeCertPem': (directory / 'node.pem').read_text(), 'nodeKeyPem': (directory / 'node.key').read_text(), 'jwtPublicKey': public}
    secret = base64.b64encode(json.dumps(payload).encode()).decode()
    credentials = {'clientCertPem': (directory / 'client.pem').read_text(), 'clientKeyPem': (directory / 'client.key').read_text(), 'jwtPrivateKeyPem': (directory / 'jwt.key').read_text()}
    (directory / 'secret').write_text(secret)
    (directory / 'secret').chmod(0o600)
    write_json(directory / 'credentials.json', credentials)
    for p in directory.iterdir():
        p.chmod(0o600)
    return secret, credentials


def config(port, marker='first'):
    return {'log': {'loglevel': 'warning'}, 'inbounds': [{'tag': 'loopback-' + marker, 'listen': '127.0.0.1', 'port': port, 'protocol': 'dokodemo-door', 'settings': {'address': '127.0.0.1', 'port': 18146, 'network': 'tcp'}}], 'outbounds': [{'protocol': 'freedom', 'tag': 'direct'}]}


def main(root):
    guard()
    role = root / 'ansible/roles/remnawave_node'
    spec = importlib.util.spec_from_file_location('node_lifecycle', role / 'files/lifecycle.py')
    life = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(life)
    prefix = 'vpn-node-' + str(os.getpid())
    namespaces = [prefix + '-cp', prefix + '-bad']
    deployment = Path('/opt/' + prefix)
    unrelated = prefix + '-unrelated'
    bridge = prefix + '-bridge'
    bridge_cp = prefix + '-bridge-cp'
    bridge_bad = prefix + '-bridge-bad'
    alternate = Path('/opt/' + prefix + '-other')
    with tempfile.TemporaryDirectory(prefix=prefix + '-', dir='/run') as temp:
        td = Path(temp)
        secret, credentials = fixture(td / 'pki')
        inventory = td / 'inventory.yml'
        variables = td / 'vars.json'
        node_play = td / 'node.yml'
        base_play = td / 'base.yml'
        docker_play = td / 'docker.yml'
        node_play.write_text(yaml.safe_dump([{'name': 'Disposable node', 'hosts': 'node', 'gather_facts': False, 'roles': [str(role)]}]))
        base_play.write_text(yaml.safe_dump([{'name': 'Accepted base firewall', 'hosts': 'node', 'gather_facts': False, 'tasks': [{'ansible.builtin.include_role': {'name': str(root / 'ansible/roles/base'), 'tasks_from': 'firewall.yml'}}]}]))
        docker_play.write_text(yaml.safe_dump([{'name': 'Accepted pinned Docker', 'hosts': 'node', 'gather_facts': True, 'roles': [str(root / 'ansible/roles/docker')]}]))
        wrapper = td / 'cp-python'
        wrapper.write_text('#!/bin/sh\nexec ip netns exec ' + namespaces[0] + ' /usr/bin/python3 "$@"\n')
        wrapper.chmod(0o700)
        bridge_wrapper = td / 'bridge-python'
        bridge_wrapper.write_text('#!/bin/sh\npid=$(docker inspect --format "{{.State.Pid}}" ' + bridge_cp + ') || exit 1\nexec nsenter --net=/proc/$pid/ns/net /usr/bin/python3 "$@"\n')
        bridge_wrapper.chmod(0o700)
        bad_wrapper = td / 'bad-python'
        bad_wrapper.write_text('#!/bin/sh\nexec ip netns exec ' + namespaces[1] + ' /usr/bin/python3 "$@"\n')
        bad_wrapper.chmod(0o700)
        inventory.write_text(yaml.safe_dump({'all': {'hosts': {'node': {'ansible_connection': 'local', 'ansible_python_interpreter': '/usr/bin/python3'}, 'cp': {'ansible_connection': 'local', 'ansible_python_interpreter': str(wrapper)}, 'bridge_cp': {'ansible_connection': 'local', 'ansible_python_interpreter': str(bridge_wrapper)}, 'bad_cp': {'ansible_connection': 'local', 'ansible_python_interpreter': str(bad_wrapper)}}}}))
        allowed = ['10.203.48.2/32', 'fd46:205::2/128']
        settings = {'docker_allow_version_change': True, 'cp_placement': 'exit', 'node_api_port': 2222, 'node_port_allow': allowed, 'base_ssh_port': 22, 'base_ssh_trusted_cidrs': ['192.0.2.10/32'], 'base_firewall_vpn_ports': [], 'base_firewall_source_ports': [{'proto': 'tcp', 'port': port, 'source_cidrs': allowed} for port in [2222, 2224]], 'remnawave_node_dir': str(deployment), 'remnawave_node_secret_key_file': str(td / 'pki/secret'), 'remnawave_node_management_credentials_file': str(td / 'pki/credentials.json'), 'remnawave_node_management_delegate': 'bridge_cp', 'remnawave_node_management_address': '10.203.48.1', 'remnawave_node_management_source': '10.203.48.2', 'remnawave_node_timeout': 30, 'remnawave_node_xray_config': config(19146)}

        def play(path, values=None, expected=0, check=False):
            write_json(variables, settings if values is None else values)
            args = [root / '.venv/bin/ansible-playbook', '-i', inventory, path, '-e', '@' + str(variables)]
            if check:
                args.append('--check')
            return command(args, expected)

        def bridge_args(name):
            pid = int(command(['docker', 'inspect', '--format', '{{.State.Pid}}', name]).strip())
            assert pid > 0, 'CP namespace container is not running'
            return ['nsenter', '--net=/proc/' + str(pid) + '/ns/net']

        def cp_health(version=4, colocated=False, port=2222, require_xray=True):
            address, source = (('10.203.48.1', '10.203.48.2') if version == 4 else ('fd46:205::1', 'fd46:205::2')) if colocated else (('10.203.46.1', '10.203.46.2') if version == 4 else ('fd46:203::1', 'fd46:203::2'))
            obj = {'secret': secret, 'credentials': credentials, 'address': address, 'source': source, 'port': port, 'require_xray': require_xray}
            probe = td / 'cp-probe'
            probe.mkdir(mode=0o700, exist_ok=True)
            write_json(probe / 'input.json', obj)
            namespace = bridge_args(bridge_cp) if colocated else ['ip', 'netns', 'exec', namespaces[0]]
            command([*namespace, 'python3', role / 'files/lifecycle.py', 'probe', probe])

        def denied(namespace, address, port, colocated=False):
            # Assert failed TCP connection, not merely an HTTP auth error.
            code = 'import socket,sys; s=socket.socket(socket.AF_INET6 if ":" in sys.argv[1] else socket.AF_INET); s.settimeout(2); result=s.connect_ex((sys.argv[1],int(sys.argv[2]))); sys.exit(0 if result else 1)'
            prefix_args = bridge_args(namespace) if colocated else ['ip', 'netns', 'exec', namespace]
            command([*prefix_args, 'python3', '-c', code, address, str(port)])

        def observed():
            inspect = json.loads(command(['docker', 'inspect', unrelated]))[0]
            return {'id': inspect['Id'], 'started': inspect['State']['StartedAt'], 'networks': inspect['NetworkSettings']['Networks'], 'forward4': command(['sysctl', '-n', 'net.ipv4.ip_forward']), 'forward6': command(['sysctl', '-n', 'net.ipv6.conf.all.forwarding'])}

        class Target(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'host-loopback-via-embedded-xray')

            def log_message(self, *_args):
                pass

        target = None
        occupied = None
        registry = None
        created_containers = []
        created_bridge = False
        created_namespaces = []
        allow_deployment_cleanup = False
        try:
            play(docker_play)
            existing = subprocess.run(['docker', 'inspect', life.CONTAINER], capture_output=True, check=False)
            assert existing.returncode != 0 and not deployment.exists(), 'disposable singleton is already occupied'
            allow_deployment_cleanup = True
            command(['docker', 'pull', '--quiet', life.IMAGE])
            command(['docker', 'run', '--detach', '--name', unrelated, '--network=none', '--entrypoint=sleep', life.IMAGE, '3600'])
            created_containers.append(unrelated)
            command(['docker', 'network', 'create', '--driver=bridge', '--ipv6', '--subnet=10.203.48.0/29', '--gateway=10.203.48.1', '--subnet=fd46:205::/64', '--gateway=fd46:205::1', bridge])
            created_bridge = True
            for name, suffix in [(bridge_cp, '2'), (bridge_bad, '3')]:
                command(['docker', 'run', '--detach', '--name', name, '--network', bridge, '--ip=10.203.48.' + suffix, '--ip6=fd46:205::' + suffix, '--entrypoint=sleep', life.IMAGE, '3600'])
                created_containers.append(name)
            before = observed()
            for index, ns in enumerate(namespaces):
                command(['ip', 'netns', 'add', ns])
                created_namespaces.append(ns)
                host = prefix[-8:] + str(index)
                command(['ip', 'link', 'add', host, 'type', 'veth', 'peer', 'name', 'eth0', 'netns', ns])
                subnet = 46 + index
                for family, host_addr, peer_addr in [('-4', f'10.203.{subnet}.1/30', f'10.203.{subnet}.2/30'), ('-6', f'fd46:{203 + index}::1/64', f'fd46:{203 + index}::2/64')]:
                    command(['ip', family, 'addr', 'add', host_addr, 'dev', host])
                    command(['ip', '-n', ns, family, 'addr', 'add', peer_addr, 'dev', 'eth0'])
                command(['ip', 'link', 'set', host, 'up'])
                command(['ip', '-n', ns, 'link', 'set', 'eth0', 'up'])
                command(['ip', '-n', ns, 'link', 'set', 'lo', 'up'])
            time.sleep(2)  # IPv6 duplicate-address detection in disposable links.
            target = HTTPServer(('127.0.0.1', 18146), Target)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(td / 'pki/target.pem', td / 'pki/target.key')
            target.socket = ctx.wrap_socket(target.socket, server_side=True)
            threading.Thread(target=target.serve_forever, daemon=True).start()
            play(base_play)
            try:
                life.active_acl(2222, settings['node_port_allow'])
            except life.Rejected as error:
                raise AssertionError('accepted #49 active INPUT/source ACL prerequisite failed: ' + str(error)) from None
            play(node_play, check=True)
            assert not deployment.exists(), 'check mode activated node'
            api_only = dict(settings, node_api_port=2224, remnawave_node_xray_config={})
            play(node_play, api_only)
            cp_health(4, colocated=True, port=2224, require_xray=False)
            with life.resource_lock(deployment) as record:
                registry = record
            play(node_play)
            play(node_play, dict(settings, remnawave_node_state='rollback'))
            cp_health(4, colocated=True, port=2224, require_xray=False)
            cp_health(6, colocated=True, port=2224, require_xray=False)
            assert not life.core_running(), 'API-only rollback falsely retained the candidate Xray requirement'
            play(node_play)
            cp_health(4, colocated=True)
            cp_health(6, colocated=True)
            cp_info = json.loads(command(['docker', 'inspect', bridge_cp]))[0]
            assert cp_info['HostConfig']['NetworkMode'] == bridge and not cp_info['HostConfig'].get('PortBindings')
            assert cp_info['NetworkSettings']['Networks'][bridge]['IPAddress'] == '10.203.48.2'
            assert cp_info['NetworkSettings']['Networks'][bridge]['GlobalIPv6Address'] == 'fd46:205::2'
            assert os.readlink('/proc/' + str(cp_info['State']['Pid']) + '/ns/net') != os.readlink('/proc/self/ns/net')
            for address in ['10.203.48.1', 'fd46:205::1']:
                denied(bridge_bad, address, 2222, colocated=True)
                denied(bridge_cp, address, 18146, colocated=True)
            current = life.owned_container()
            assert current['HostConfig']['NetworkMode'] == 'host'
            host_net = os.readlink('/proc/self/ns/net')
            node_net = os.readlink('/proc/' + str(current['State']['Pid']) + '/ns/net')
            assert host_net == node_net, 'node is outside host namespace'
            assert 'host-loopback-via-embedded-xray' in command(['curl', '--silent', '--show-error', '--fail', '--cacert', td / 'pki/ca.pem', 'https://127.0.0.1:19146/'])
            assert re.search(r'changed=0\b', play(node_play)), 'reapplication is not idempotent'
            assert life.owned_container()['Id'] == current['Id'], 'idempotent apply recreated container'
            for expression in [['tcp', 'dport', '!=', '2223', 'accept'], ['iif', '!=', 'lo', 'accept'], ['ct', 'state', '!=', 'established', 'accept']]:
                try:
                    command(['nft', 'add', 'rule', 'inet', 'vpn_base', 'input', *expression])
                    try:
                        life.active_acl(2222, settings['node_port_allow'])
                    except life.Rejected:
                        pass
                    else:
                        raise AssertionError('inverted real nft accept bypassed the active gate')
                    play(node_play, expected=1, check=True)
                    assert life.owned_container()['Id'] == current['Id'], 'ACL rejection mutated the running node'
                finally:
                    command(['systemctl', 'restart', 'vpn-base-firewall.service'])
            play(node_play, dict(settings, remnawave_node_dir=str(alternate)), expected=1)
            assert not alternate.exists(), 'mismatched directory mutated the daemon singleton'
            ready = td / 'lock-ready'
            hold = 'import importlib.util,pathlib,sys,time; s=importlib.util.spec_from_file_location("node",sys.argv[1]); m=importlib.util.module_from_spec(s); s.loader.exec_module(m)\nwith m.resource_lock(pathlib.Path(sys.argv[2])):\n pathlib.Path(sys.argv[3]).touch(); time.sleep(60)'
            locker = subprocess.Popen(['python3', '-c', hold, str(role / 'files/lifecycle.py'), str(deployment), str(ready)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                deadline = time.monotonic() + 10
                while not ready.exists() and locker.poll() is None and time.monotonic() < deadline:
                    time.sleep(0.05)
                assert ready.exists(), 'daemon resource lock fixture failed'
                play(node_play, expected=1)
                play(node_play, dict(settings, remnawave_node_dir=str(alternate)), expected=1)
                assert life.owned_container()['Id'] == current['Id'], 'concurrent transaction changed the singleton'
            finally:
                locker.terminate()
                locker.wait(timeout=10)
            print('active nft inverted accepts rejected; daemon singleton concurrent/mismatched-directory mutation denied')
            command(['docker', 'exec', life.CONTAINER, '/command/s6-svc', '-wd', '-T', '10000', '-d', '/run/service/xray'])
            assert not life.core_running(), 'core-stop fixture did not stop Xray'
            play(node_play)
            assert life.core_running(), 'reapplication trusted stale cached health'
            command(['docker', 'restart', life.CONTAINER])
            play(node_play)
            assert life.core_running(), 'Docker restart did not restore bootstrap config'
            for address in ['10.203.46.1', 'fd46:203::1']:
                denied(namespaces[0], address, 2222)
                denied(namespaces[0], address, 18146)
            negative = td / 'negative.json'
            write_json(negative, {'secret': secret, 'credentials': credentials})
            rejection = 'import importlib.util,json,sys; s=importlib.util.spec_from_file_location("node",sys.argv[1]); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); o=json.load(open(sys.argv[2])); m.api(o["secret"],o["credentials"],sys.argv[3],2222,source=sys.argv[4],**{sys.argv[5]:True})'
            for address, source in [('10.203.48.1', '10.203.48.2'), ('fd46:205::1', 'fd46:205::2')]:
                for failure in ['bad_jwt', 'no_cert']:
                    command([*bridge_args(bridge_cp), 'python3', '-c', rejection, role / 'files/lifecycle.py', negative, address, source, failure], expected=1)
            for mutate in ['wide', 'empty', 'conflict', 'bad-secret', 'wrong-key', 'bad-config']:
                bad = copy.deepcopy(settings)
                if mutate == 'wide':
                    bad['node_port_allow'] = ['0.0.0.0/0']
                elif mutate == 'empty':
                    bad['node_port_allow'] = []
                elif mutate == 'conflict':
                    bad['base_firewall_vpn_ports'] = [{'proto': 'tcp', 'port': 2222}]
                elif mutate == 'bad-secret':
                    bad['remnawave_node_secret_key_file'] = ''
                    bad['remnawave_node_secret_key'] = 'invalid'
                elif mutate == 'wrong-key':
                    corrupted = life.payload(secret)
                    corrupted['nodeKeyPem'] = credentials['clientKeyPem']
                    bad['remnawave_node_secret_key_file'] = ''
                    bad['remnawave_node_secret_key'] = base64.b64encode(json.dumps(corrupted).encode()).decode()
                else:
                    bad['remnawave_node_xray_config']['inbounds'][0]['protocol'] = 'not-a-protocol'
                checked = json.loads((deployment / 'state.json').read_text())['checked']
                play(node_play, bad, expected=1)
                assert json.loads((deployment / 'state.json').read_text())['checked'] == checked
                life.health({'secret': secret, 'credentials': credentials, 'port': 2222}, True)
            print('exit placement: real Docker bridge CP IPv4/IPv6 mTLS/JWT API, API-only effective-port rollback, namespace/TLS and preactivation rejection observed')

            settings.update({'cp_placement': 'dedicated', 'node_port_allow': ['10.203.46.2/32', 'fd46:203::2/128'], 'remnawave_node_management_delegate': 'cp', 'remnawave_node_management_address': '10.203.46.1', 'remnawave_node_management_source': '10.203.46.2'})
            for rule in settings['base_firewall_source_ports']:
                rule['source_cidrs'] = settings['node_port_allow']
            play(base_play)
            play(node_play)
            cp_health(4)
            cp_health(6)
            for address, source in [('10.203.46.1', '10.203.46.2'), ('fd46:203::1', 'fd46:203::2')]:
                for failure in ['bad_jwt', 'no_cert']:
                    command(['ip', 'netns', 'exec', namespaces[0], 'python3', '-c', rejection, role / 'files/lifecycle.py', negative, address, source, failure], expected=1)
            for address in ['10.203.47.1', 'fd46:204::1']:
                denied(namespaces[1], address, 2222)
                denied(namespaces[1], address, 18146)
            old_id = life.owned_container()['Id']
            restart = dict(settings, remnawave_node_state='restarted')
            play(node_play, restart)
            assert life.owned_container()['Id'] != old_id
            cp_health()
            settings['remnawave_node_xray_config'] = config(19147, 'second')
            play(node_play)
            assert 'host-loopback-via-embedded-xray' in command(['curl', '--silent', '--fail', '--cacert', td / 'pki/ca.pem', 'https://127.0.0.1:19147/'])
            play(node_play, dict(settings, remnawave_node_state='rollback'))
            assert 'host-loopback-via-embedded-xray' in command(['curl', '--silent', '--fail', '--cacert', td / 'pki/ca.pem', 'https://127.0.0.1:19146/'])
            cp_health()
            occupied = socket.socket()
            occupied.bind(('127.0.0.1', 19148))
            occupied.listen()
            bad = dict(settings, remnawave_node_xray_config=config(19148, 'unhealthy'))
            play(node_play, bad, expected=1)
            cp_health()
            assert 'host-loopback-via-embedded-xray' in command(['curl', '--silent', '--fail', '--cacert', td / 'pki/ca.pem', 'https://127.0.0.1:19146/'])
            state = json.loads((deployment / 'state.json').read_text())
            assert not state['pending'] and 'restoration' not in state, 'successful restoration lost its CP completion gate'
            checked = state['checked']
            # Both automatic abort and rescue-initiated abort must stop the owned
            # node if the actual delegate cannot reach its declared source path.
            for candidate in [bad, dict(settings, remnawave_node_xray_config=config(19149, 'cp-gate'))]:
                unreachable = dict(candidate, remnawave_node_management_delegate='bad_cp')
                play(node_play, unreachable, expected=1)
                assert not life.owned_container()['State']['Running'], 'CP-inaccessible restoration stayed running'
                after_abort = json.loads((deployment / 'state.json').read_text())
                assert after_abort['checked'] == checked and not after_abort['pending']
                assert observed() == before, 'fail-closed restoration touched unrelated resources'
                recovery = dict(settings, remnawave_node_xray_config=config(19146))
                play(node_play, recovery)
                cp_health(4)
                cp_health(6)
            print('automatic and rescue restoration: real inaccessible CP gate stopped only the owned node; allowed CP recovery observed')
            print('dedicated placement: allowed IPv4/IPv6 CP, unauthorized source denial, recreate and checked rollback observed')
            print('host and node namespace identity equal; private TLS reached by embedded Xray; no credentials logged')
            sockets = command(['ss', '-H', '-ltn'])
            loopback_sockets = [line for line in sockets.splitlines() if ':18146' in line or ':19146' in line]
            assert len(loopback_sockets) == 2 and all('127.0.0.1:' in line for line in loopback_sockets)
            assert any(':2222' in line for line in sockets.splitlines()), 'management socket absent'
            print('socket observations: API TCP/2222 source-restricted; TLS TCP/18146 and Xray TCP/19146 bind only 127.0.0.1')
            assert observed() == before, 'unrelated service or forwarding state changed'
            # Independent credential rotation/revocation must not resurrect the
            # previous CA/JWT during an unhealthy rollout.
            new_secret, new_creds = fixture(td / 'rotated')
            revoked = dict(bad, remnawave_node_secret_key_file=str(td / 'rotated/secret'), remnawave_node_management_credentials_file=str(td / 'rotated/credentials.json'))
            play(node_play, revoked, expected=1)
            assert not life.owned_container()['State']['Running'], 'revoked checked credentials were reactivated'
            assert observed() == before
            print('independent credential rotation: unhealthy rollout stopped without restoring revoked credentials; unrelated service/forwarding preserved')
        finally:
            if occupied:
                occupied.close()
            if target:
                target.shutdown()
                target.server_close()
            try:
                if life.owned_container(deployment):
                    subprocess.run(['docker', 'rm', '--force', life.CONTAINER], capture_output=True, check=False)
            except (life.Rejected, OSError):
                pass  # A pre-existing/mismatched singleton is never removed.
            for name in created_containers:
                subprocess.run(['docker', 'rm', '--force', name], capture_output=True, check=False)
            if created_bridge:
                subprocess.run(['docker', 'network', 'rm', bridge], capture_output=True, check=False)
            for ns in created_namespaces:
                subprocess.run(['ip', 'netns', 'delete', ns], capture_output=True, check=False)
            if allow_deployment_cleanup and deployment.exists():
                try:
                    with life.resource_lock(deployment) as record:
                        registry = record
                except (life.Rejected, OSError):
                    pass
                else:
                    shutil.rmtree(deployment)
            if registry and registry.exists() and json.loads(registry.read_text()) == {'directory': str(deployment), 'project': life.PROJECT}:
                registry.unlink()


if __name__ == '__main__':
    main(Path(sys.argv[1]).resolve())
