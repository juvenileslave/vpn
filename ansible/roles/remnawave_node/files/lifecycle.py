#!/usr/bin/env python3
"""Pinned RemnaNode transaction. Outputs only safe status labels, never credentials."""
import base64
import contextlib
import fcntl
import hashlib
import http.client
import ipaddress
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
import time

IMAGE = 'ghcr.io/remnawave/node:3.4.5@sha256:8f5a41708dfa86acc2561a520c9b40e2ff30812a16c28cf6bba6c365ca0f7d65'
PROJECT = 'vpn-remnanode'
CONTAINER = 'vpn-remnanode'
LABEL = 'io.github.juvenileslave.vpn.managed-by'
NODE_VERSION = '3.4.5'
CORE_VERSION = '26.11.9'


class Rejected(Exception):
    pass


def run(args, data=None, timeout=180):
    result = subprocess.run(args, input=data, capture_output=True, timeout=timeout, check=False)
    if result.returncode:
        raise Rejected('external operation failed: ' + Path(args[0]).name)
    return result.stdout


def dump(path, value):
    path.write_text(json.dumps(value, sort_keys=True))
    path.chmod(0o600)


def pem(value):
    return value.replace('\\n', '\n').replace('\r\n', '\n').strip() + '\n'


def payload(secret):
    try:
        obj = json.loads(base64.b64decode(secret, validate=True))
        keys = {'caCertPem', 'nodeCertPem', 'nodeKeyPem', 'jwtPublicKey'}
        if not isinstance(obj, dict) or set(obj) != keys or not all(isinstance(v, str) for v in obj.values()):
            raise ValueError()
        return {k: pem(v) for k, v in obj.items()}
    except (ValueError, TypeError):
        raise Rejected('invalid node secret structure') from None


def public_key(keyfile):
    return run(['openssl', 'pkey', '-in', str(keyfile), '-pubout', '-outform', 'DER'])


def certificate_key(certfile):
    pub = run(['openssl', 'x509', '-in', str(certfile), '-pubkey', '-noout'])
    return run(['openssl', 'pkey', '-pubin', '-outform', 'DER'], pub)


@contextlib.contextmanager
def credentials_files(secret, credentials):
    p = payload(secret)
    if not isinstance(credentials, dict) or set(credentials) != {'clientCertPem', 'clientKeyPem', 'jwtPrivateKeyPem'}:
        raise Rejected('invalid management credential structure')
    with tempfile.TemporaryDirectory(prefix='vpn-node-pki-', dir='/run') as td:
        directory = Path(td)
        for key, value in dict(p, **credentials).items():
            if not isinstance(value, str):
                raise Rejected('invalid PEM value')
            f = directory / key
            f.write_text(pem(value))
            f.chmod(0o600)
        ca = str(directory / 'caCertPem')
        run(['openssl', 'verify', '-check_ss_sig', '-CAfile', ca, ca])
        for cert, purpose in [('nodeCertPem', 'sslserver'), ('clientCertPem', 'sslclient')]:
            run(['openssl', 'verify', '-purpose', purpose, '-CAfile', ca, str(directory / cert)])
        if certificate_key(directory / 'nodeCertPem') != public_key(directory / 'nodeKeyPem'):
            raise Rejected('node certificate and key mismatch')
        if certificate_key(directory / 'clientCertPem') != public_key(directory / 'clientKeyPem'):
            raise Rejected('client certificate and key mismatch')
        pub = run(['openssl', 'pkey', '-pubin', '-in', str(directory / 'jwtPublicKey'), '-outform', 'DER'])
        if pub != public_key(directory / 'jwtPrivateKeyPem'):
            raise Rejected('JWT keypair mismatch')
        # RS256 requires an RSA key; do not accept a generic parseable key.
        run(['openssl', 'rsa', '-pubin', '-in', str(directory / 'jwtPublicKey'), '-noout'])
        yield directory


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=')


def api(secret, credentials, address, port, path='/node/xray/healthcheck', body=None, source=None, bad_jwt=False, no_cert=False):
    with credentials_files(secret, credentials) as d:
        context = ssl.create_default_context(cafile=str(d / 'caCertPem'))
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        # Official node certificates have random CN and no IP SAN. Verify the
        # CA chain AND exact exported node certificate instead of an invented
        # hostname. CERT_REQUIRED remains enabled throughout.
        context.check_hostname = False
        if not no_cert:
            context.load_cert_chain(str(d / 'clientCertPem'), str(d / 'clientKeyPem'))
        header = b64(b'{"alg":"RS256","typ":"JWT"}')
        claims = b64(json.dumps({'iat': int(time.time()), 'exp': int(time.time()) + 60}).encode())
        unsigned = header + b'.' + claims
        signature = run(['openssl', 'dgst', '-sha256', '-sign', str(d / 'jwtPrivateKeyPem')], unsigned)
        token = (unsigned + b'.' + b64(signature)).decode()
        if bad_jwt:
            token = token[:-10] + 'AAAAAAAAAA'
        source_address = (source, 0) if source else None
        conn = http.client.HTTPSConnection(address, port, context=context, source_address=source_address, timeout=6)
        try:
            conn.connect()
            expected = ssl.PEM_cert_to_DER_cert((d / 'nodeCertPem').read_text())
            if conn.sock.getpeercert(binary_form=True) != expected:
                raise Rejected('node TLS certificate pin mismatch')
            conn.request('POST' if body is not None else 'GET', path, body=json.dumps(body) if body is not None else None,
                         headers={'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'})
            response = conn.getresponse()
            raw = response.read(16 * 1024 * 1024)
            if response.status not in (200, 201):
                raise Rejected('management operation rejected')
            return json.loads(raw)['response']
        finally:
            conn.close()


def health(obj, require_xray=False, address='127.0.0.1', source=None):
    r = api(obj['secret'], obj['credentials'], address, obj['port'], source=source)
    if r.get('isAlive') is not True or r.get('nodeVersion') != NODE_VERSION or r.get('xrayVersion') != CORE_VERSION:
        raise Rejected('node health or embedded version mismatch')
    if require_xray and r.get('xrayInternalStatusCached') is not True:
        raise Rejected('embedded Xray is not active')
    return r


def core_running():
    try:
        state = run(['docker', 'exec', CONTAINER, '/command/s6-svstat', '-o', 'up,pid', '/run/service/xray']).decode().strip().split()
        return len(state) == 2 and state[0] == 'true' and int(state[1]) > 0
    except (Rejected, ValueError):
        return False


def start(obj):
    config = obj.get('config', {})
    if not config:
        return
    # We own bootstrap configuration, not the panel hashed-set reconciliation.
    # Force restart only after a change/recreate or loss of Xray, never each apply.
    body = {'internals': {'forceRestart': True, 'hashes': {'emptyConfig': hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest(),
            'inbounds': [{'tag': i['tag'], 'usersCount': len(i.get('settings', {}).get('clients', [])), 'hash': hashlib.sha256(json.dumps(i, sort_keys=True).encode()).hexdigest()} for i in config.get('inbounds', [])]}}, 'xrayConfig': config}
    r = api(obj['secret'], obj['credentials'], '127.0.0.1', obj['port'], '/node/xray/start', body)
    if r.get('isStarted') is not True or r.get('error') is not None or r.get('version') != CORE_VERSION:
        raise Rejected('embedded Xray startup failed')


def values(rhs):
    if isinstance(rhs, list):
        return rhs
    if isinstance(rhs, dict) and 'set' in rhs:
        return rhs['set']
    return [rhs]


def network(value):
    if isinstance(value, dict) and 'prefix' in value:
        v = value['prefix']
        return ipaddress.ip_network(str(v['addr']) + '/' + str(v['len']), strict=True)
    return ipaddress.ip_network(value, strict=True)


def acl_model(model, port, sources):
    """Validate supported nft JSON semantics; unknown verdict paths fail closed."""
    chains = [x['chain'] for x in model if 'chain' in x and x['chain']['name'] == 'input']
    if len(chains) != 1 or any(chains[0].get(k) != v for k, v in {'family': 'inet', 'table': 'vpn_base', 'type': 'filter', 'hook': 'input', 'policy': 'drop'}.items()):
        raise Rejected('active base INPUT gate absent')
    found = set()
    lo = False
    for item in model:
        rule = item.get('rule', {})
        if rule.get('chain') != 'input':
            continue
        expressions = rule.get('expr', [])
        if any(set(x) - {'match', 'accept', 'drop', 'reject', 'counter', 'limit', 'log'} for x in expressions):
            raise Rejected('unsupported base INPUT verdict path')
        if not any('accept' in x for x in expressions):
            continue
        matches = [x['match'] for x in expressions if 'match' in x]
        for match in matches:
            left = match.get('left', {})
            ct_state = left == {'ct': {'key': 'state'}}
            if match.get('op') != '==' and not (ct_state and match.get('op') == 'in'):
                raise Rejected('unsupported comparison in base INPUT accept')
            if left == {'meta': {'key': 'iif'}}:
                if match.get('right') != 'lo':
                    raise Rejected('unsupported interface accept in base INPUT')
            elif ct_state:
                states = values(match.get('right'))
                if not states or not all(isinstance(s, str) and s in {'established', 'related'} for s in states):
                    raise Rejected('unsupported conntrack accept in base INPUT')
            elif set(left) == {'payload'}:
                header = left['payload']
                supported = {'ip': {'saddr'}, 'ip6': {'saddr', 'hoplimit'}, 'tcp': {'dport', 'sport'}, 'udp': {'dport', 'sport'}, 'icmp': {'type'}, 'icmpv6': {'type'}}
                if set(header) != {'protocol', 'field'} or header.get('field') not in supported.get(header.get('protocol'), set()):
                    raise Rejected('unsupported payload accept in base INPUT')
            elif left == {'meta': {'key': 'l4proto'}}:
                if match.get('right') not in {'tcp', 'udp', 'icmp', 'ipv6-icmp'}:
                    raise Rejected('unsupported protocol accept in base INPUT')
            else:
                raise Rejected('unsupported match in base INPUT accept')
        loopback = [m for m in matches if m['left'] == {'meta': {'key': 'iif'}}]
        if loopback:
            if len(matches) != 1 or any('limit' in x for x in expressions):
                raise Rejected('base loopback invariant is conditional')
            lo = True
            continue
        if any(m['left'] == {'ct': {'key': 'state'}} for m in matches):
            continue
        if any(m['left'].get('payload', {}).get('protocol') in {'icmp', 'icmpv6'} or (m['left'] == {'meta': {'key': 'l4proto'}} and m['right'] in {'icmp', 'ipv6-icmp'}) for m in matches):
            continue
        dports = [m for m in matches if m['left'].get('payload', {}).get('field') == 'dport']
        if len(dports) != 1:
            raise Rejected('base INPUT accept lacks a supported destination port')
        dport = dports[0]
        ports = values(dport.get('right'))
        if not ports:
            raise Rejected('empty destination-port accept')
        potentially_api = False
        for value in ports:
            if type(value) is int and 1 <= value <= 65535:
                potentially_api |= value == port
            elif isinstance(value, dict) and set(value) == {'range'} and isinstance(value['range'], list) and len(value['range']) == 2 and all(type(v) is int for v in value['range']) and 1 <= value['range'][0] <= value['range'][1] <= 65535:
                potentially_api |= value['range'][0] <= port <= value['range'][1]
            else:
                raise Rejected('unsupported destination-port operand')
        if dport['left']['payload']['protocol'] != 'tcp' or not potentially_api:
            continue
        source_matches = [m for m in matches if m['left'].get('payload', {}).get('field') == 'saddr']
        if len(source_matches) != 1:
            raise Rejected('node API accept lacks exact source restriction')
        source = source_matches[0]
        try:
            networks = [network(v) for v in values(source['right'])]
        except (ValueError, TypeError, KeyError):
            raise Rejected('unsupported API source operand') from None
        family = 4 if source['left']['payload']['protocol'] == 'ip' else 6
        if not networks or any(n.version != family for n in networks):
            raise Rejected('API source family mismatch')
        found.update(networks)
    if not lo or found != {ipaddress.ip_network(s, strict=True) for s in sources}:
        raise Rejected('active API ACL disagrees with node_port_allow')


def active_acl(port, sources):
    acl_model(json.loads(run(['nft', '-j', 'list', 'table', 'inet', 'vpn_base']))['nftables'], port, sources)


def compose(directory, *args):
    return run(['docker', 'compose', '--project-name', PROJECT, '--project-directory', str(directory), '--file', str(directory / 'compose.yaml'), *args])


def container_directory(info):
    labels = info['Config'].get('Labels', {})
    if labels.get('com.docker.compose.project') != PROJECT or labels.get('com.docker.compose.service') != 'remnanode' or labels.get(LABEL) != 'remnawave_node':
        raise Rejected('existing container is not owned by this role')
    working = labels.get('com.docker.compose.project.working_dir', '')
    if not re.fullmatch(r'/opt/[A-Za-z0-9_-]+/releases/[a-f0-9]{64}', working):
        raise Rejected('owned container has no checked release directory')
    for filename in ['probe.json', 'health.cjs']:
        mounts = [m for m in info.get('Mounts', []) if m.get('Destination') == '/run/vpn-node/' + filename]
        if len(mounts) != 1 or mounts[0].get('Source') != working + '/' + filename or mounts[0].get('RW') is not False:
            raise Rejected('owned container release mounts disagree')
    return Path(working).parents[1]


def owned_container(directory=None):
    result = subprocess.run(['docker', 'inspect', CONTAINER], capture_output=True, check=False)
    if result.returncode:
        return None
    info = json.loads(result.stdout)[0]
    actual = container_directory(info)
    if directory is not None and actual != Path(directory):
        raise Rejected('singleton node belongs to another deployment directory')
    return info


def directory_owned(directory):
    marker = directory / 'owned.json'
    if directory.is_symlink() or (directory.exists() and (marker.is_symlink() or not marker.is_file())):
        raise Rejected('existing deployment directory is not owned')
    if directory.exists() and json.loads(marker.read_text()) != {'role': 'remnawave_node', 'project': PROJECT}:
        raise Rejected('deployment ownership marker mismatch')


@contextlib.contextmanager
def resource_lock(directory):
    """One transaction per Docker daemon, across all allowed /opt directories."""
    if not re.fullmatch(r'/opt/[A-Za-z0-9_-]+', str(directory)):
        raise Rejected('invalid deployment directory')
    daemon_id = run(['docker', 'info', '--format', '{{.ID}}']).decode().strip()
    if not daemon_id or daemon_id == '<no value>':
        raise Rejected('Docker daemon identity unavailable')
    key = hashlib.sha256(daemon_id.encode()).hexdigest()
    locks = Path('/run/vpn-remnanode')
    if locks.is_symlink():
        raise Rejected('singleton lock directory is a symlink')
    locks.mkdir(mode=0o700, exist_ok=True)
    locks.chmod(0o700)
    lock_path = locks / (key + '.lock')
    if lock_path.is_symlink():
        raise Rejected('singleton lock is a symlink')
    with lock_path.open('a') as lock:
        lock_path.chmod(0o600)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Rejected('singleton node transaction is already executing') from None
        records = Path('/var/lib/vpn-remnanode')
        record = records / (key + '.json')
        if records.is_symlink() or record.is_symlink():
            raise Rejected('singleton ownership record is a symlink')
        if record.exists() and json.loads(record.read_text()) != {'directory': str(directory), 'project': PROJECT}:
            raise Rejected('Docker daemon singleton is owned by another directory')
        directory_owned(directory)
        owned_container(directory)
        yield record


def claim_resource(record, root):
    record.parent.mkdir(mode=0o700, exist_ok=True)
    record.parent.chmod(0o700)
    dump(record, {'directory': str(root), 'project': PROJECT})


def validate(stage, obj):
    if type(obj.get('port')) is not int or not 1 <= obj['port'] <= 65535 or not re.fullmatch(r'/opt/[A-Za-z0-9_-]+', obj.get('directory', '')):
        raise Rejected('invalid deployment path or port')
    with credentials_files(obj['secret'], obj['credentials']):
        pass
    config = obj.get('config', {})
    if not isinstance(config, dict) or config.get('geodata', {}).get('core') is not None:
        raise Rejected('invalid config or custom core forbidden')
    tags = set()
    for inbound in config.get('inbounds', []):
        tag = inbound.get('tag')
        if not isinstance(tag, str) or not tag or tag in tags or inbound.get('port') == obj['port']:
            raise Rejected('duplicate inbound tag or management listener conflict')
        tags.add(tag)
    (stage / 'node.env').write_text('NODE_PORT=' + str(obj['port']) + '\nSECRET_KEY=' + obj['secret'] + '\n')
    (stage / 'node.env').chmod(0o600)
    dump(stage / 'probe.json', {k: obj[k] for k in ['secret', 'credentials', 'port']})
    dump(stage / 'config.json', config)
    compose(stage, 'config', '--quiet')
    model = json.loads(compose(stage, 'config', '--format=json'))
    services = model.get('services', {})
    node = services.get('remnanode', {})
    if set(services) != {'remnanode'} or node.get('image') != IMAGE or node.get('network_mode') != 'host' or node.get('ports') or node.get('privileged') or node.get('cap_add') or model.get('networks'):
        raise Rejected('compose policy violation')
    if node.get('environment', {}).get('CUSTOM_CORE_URL') or node.get('environment', {}).get('SNI_VERIFICATION') != 'false':
        raise Rejected('unapproved upstream runtime override')
    active_acl(obj['port'], obj['sources'])
    owned_container(obj['directory'])
    directory_owned(Path(obj['directory']))


def atomic_state(root, state):
    dump(root / 'state.tmp', state)
    os.replace(root / 'state.tmp', root / 'state.json')


def read_state(root):
    f = root / 'state.json'
    return json.loads(f.read_text()) if f.exists() else {'checked': None, 'previous': None, 'pending': None}


def release_input(root, name):
    return json.loads((root / 'releases' / name / 'input.json').read_text())


def auth_id(obj):
    return hashlib.sha256(json.dumps(payload(obj['secret']), sort_keys=True).encode()).hexdigest()


def activate(root, name, obj, force=False):
    active_acl(obj['port'], obj['sources'])
    directory = root / 'releases' / name
    compose(directory, 'up', '--detach', '--wait', '--wait-timeout=' + str(obj['timeout']), '--quiet-pull', *(['--force-recreate'] if force else []))
    end = time.monotonic() + obj['timeout']
    while True:
        try:
            r = health(obj)
            if obj.get('config') and (force or not r['xrayInternalStatusCached'] or not core_running()):
                start(obj)
            health(obj, bool(obj.get('config')))
            if obj.get('config') and not core_running():
                raise Rejected('embedded Xray s6 service is not running')
            return
        except (Rejected, OSError, ValueError, http.client.HTTPException):
            if time.monotonic() >= end:
                raise Rejected('authenticated rollout health gate failed') from None
            time.sleep(2)


def effective_probe(obj):
    return {'port': obj['port'], 'require_xray': bool(obj.get('config'))}


def restored_input(root, name, current):
    old = release_input(root, name)
    if auth_id(old) != auth_id(current):
        raise Rejected('restoration would restore revoked credentials')
    # Current credentials, source authority and timeout never come from history.
    for key in ['credentials', 'sources', 'timeout']:
        old[key] = current[key]
    dump(root / 'releases' / name / 'probe.json', {k: old[k] for k in ['secret', 'credentials', 'port']})
    return old


def pending_owned(state, owner):
    if state.get('pending') and state.get('pending_owner') != str(owner):
        raise Rejected('operation does not own pending transaction')


def clear_pending(root, state):
    state['pending'] = None
    state.pop('pending_owner', None)
    state.pop('restoration', None)
    atomic_state(root, state)


def stop_owned(root):
    if owned_container(root):
        run(['docker', 'stop', CONTAINER])
        return True
    return False


def abort(root, current, owner):
    state = read_state(root)
    pending_owned(state, owner)
    if not state.get('pending'):
        return {'changed': False, 'restored': False}
    outcome = state.get('restoration')
    if outcome:
        if outcome.get('stopped'):
            raise Rejected('failed restoration has already stopped the owned node')
        old = restored_input(root, outcome['release'], current)
        active_acl(old['port'], old['sources'])
        health(old, bool(old.get('config')))
        return {'changed': False, 'restored': True, 'probe': effective_probe(old)}
    checked = state.get('checked')
    try:
        if not checked:
            raise Rejected('no checked deployment to restore')
        old = restored_input(root, checked, current)
        activate(root, checked, old, force=True)
    except Exception:
        stop_owned(root)
        state['restoration'] = {'stopped': True}
        atomic_state(root, state)
        raise Rejected('restoration unavailable or unhealthy; owned node stopped') from None
    # Keep the failed candidate and its owner until the real CP gate finishes.
    state['restoration'] = {'release': checked, 'stopped': False}
    atomic_state(root, state)
    return {'changed': True, 'restored': True, 'probe': effective_probe(old)}


def deploy(stage, obj, registry):
    validate(stage, obj)
    root = Path(obj['directory'])
    state = read_state(root)
    if state.get('pending'):
        raise Rejected('an uncommitted transaction exists; recover it with its original input before retrying')
    root.mkdir(mode=0o700, exist_ok=True)
    root.chmod(0o700)
    dump(root / 'owned.json', {'role': 'remnawave_node', 'project': PROJECT})
    claim_resource(registry, root)
    (root / 'releases').mkdir(mode=0o700, exist_ok=True)
    wanted = {k: obj[k] for k in ['secret', 'credentials', 'config', 'port', 'sources']}
    wanted['compose'] = (stage / 'compose.yaml').read_text()
    wanted['health'] = (stage / 'health.cjs').read_text()
    name = hashlib.sha256(json.dumps(wanted, sort_keys=True).encode()).hexdigest()
    current = obj
    if obj['state'] == 'rollback':
        name = state.get('previous')
        if not name:
            raise Rejected('no previous checked deployment')
        obj = restored_input(root, name, current)
        obj['state'] = 'rollback'
    else:
        target = root / 'releases' / name
        if not target.exists():
            target.mkdir(mode=0o700)
            for filename in ['compose.yaml', 'node.env', 'probe.json', 'config.json', 'health.cjs', 'input.json']:
                shutil.copyfile(stage / filename, target / filename)
                (target / filename).chmod(0o600)
    target = root / 'releases' / name
    if obj.get('config'):
        run(['docker', 'run', '--rm', '--network=none', '--entrypoint=/usr/local/bin/xray', '--mount=type=bind,src=' + str(target / 'config.json') + ',dst=/run/config.json,readonly', IMAGE, 'run', '-test', '-config', '/run/config.json'])
    info = owned_container(root)
    force = obj['state'] in {'restarted', 'rollback'}
    unchanged = state.get('checked') == name and not force and info and info['State'].get('Running') and info['State'].get('Health', {}).get('Status') == 'healthy'
    if unchanged:
        try:
            health(obj, bool(obj.get('config')))
            if obj.get('config') and not core_running():
                raise Rejected('cached health disagrees with live core')
        except (Rejected, OSError, ValueError, http.client.HTTPException):
            unchanged = False
            force = True
    state['pending'] = name
    state['pending_owner'] = str(stage)
    atomic_state(root, state)
    if not unchanged:
        try:
            activate(root, name, obj, force=force)
        except Exception:
            abort(root, current, stage)
            raise Rejected('rollout failed; restoration awaits the current-credential CP gate') from None
    return {'changed': not unchanged, 'restored': obj['state'] == 'rollback', 'probe': effective_probe(obj)}


def main():
    action, stage_arg = sys.argv[1:]
    stage = Path(stage_arg)
    obj = json.loads((stage / 'input.json').read_text())
    if action == 'probe':
        health(obj, obj.get('require_xray', False), obj['address'], obj['source'])
        result = {'healthy': True}
    else:
        root = Path(obj['directory'])
        with resource_lock(root) as registry:
            if action == 'validate':
                validate(stage, obj)
                result = {'valid': True}
            elif action == 'deploy':
                result = deploy(stage, obj, registry)
            elif action == 'abort':
                result = abort(root, obj, stage)
            elif action in {'commit', 'finish-abort', 'stop'}:
                state = read_state(root)
                pending_owned(state, stage)
                if action == 'stop':
                    # A rescue must never stop the singleton owned by another run.
                    stopped = False
                    if state.get('pending'):
                        stopped = stop_owned(root)
                        clear_pending(root, state)
                    result = {'stopped': stopped}
                elif action == 'finish-abort':
                    if not state.get('restoration') or state['restoration'].get('stopped'):
                        raise Rejected('no healthy restoration awaiting the CP gate')
                    clear_pending(root, state)
                    result = {'restoration_finished': True}
                else:
                    if state.get('restoration'):
                        raise Rejected('failed candidate cannot be committed')
                    if state.get('pending'):
                        if state['pending'] != state['checked']:
                            state['previous'] = state['checked']
                        state['checked'] = state['pending']
                        clear_pending(root, state)
                    result = {'committed': True}
            else:
                raise Rejected('unknown lifecycle operation')
    print(json.dumps(result))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        # Intentionally omit exceptions originating in TLS/config/credentials.
        print(json.dumps({'failed': True, 'reason': str(error) if isinstance(error, Rejected) else 'node operation failed'}))
        sys.exit(1)
