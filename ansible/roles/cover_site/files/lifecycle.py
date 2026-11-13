#!/usr/bin/env python3
# Managed by cover_site. Checked nginx and Certbot lifecycle.
"""Owned nginx/Certbot stage-check-activate lifecycle. Never prints key material."""
from __future__ import annotations

import argparse
import fcntl
import fnmatch
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import socket
import ssl
import subprocess
import tempfile
import time

from validate_content import validate
from ownership import inspect, sync_directory

BASE = Path('/var/lib/cover-site')
SETTINGS = Path('/etc/cover-site/settings.json')
ENABLED = Path('/etc/nginx/sites-enabled/cover-site.conf')
ACTIVE = BASE / 'active'
PREVIOUS = BASE / 'previous'
PENDING = BASE / 'pending.json'
SCRIPT = '/usr/local/libexec/cover-site/lifecycle.py'
MARKER = '# Managed by cover_site'


def run(argv, *, env=None, data=None):
    result = subprocess.run(argv, input=data, env=env, capture_output=True, timeout=180)
    if result.returncode:
        # Commands may handle private keys or ACME contacts. Do not echo argv/output.
        raise RuntimeError(f'{Path(argv[0]).name} validation/operation failed (exit {result.returncode})')
    return result.stdout


def settings(path=SETTINGS):
    value = json.loads(Path(path).read_text())
    if value['test']:
        if not (os.environ.get('VPN_COVER_SITE_DISPOSABLE_GUEST') == 'yes'
                and os.environ.get('GITHUB_ACTIONS') == 'true'
                and os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted'
                and value['directory'] == 'https://localhost:14000/dir'):
            raise ValueError('Local CA/ACME requires an explicitly guarded disposable GitHub guest')
    elif (value['acme_ca'] or value['trust'] != '/etc/ssl/certs/ca-certificates.crt'
          or value['directory'] not in ('https://acme-v02.api.letsencrypt.org/directory',
                                       'https://acme-staging-v02.api.letsencrypt.org/directory')):
        raise ValueError('Custom CA/ACME is forbidden outside disposable tests')
    return value


def atomic_json(path, value):
    temporary = path.with_suffix('.tmp')
    with temporary.open('w') as handle:
        handle.write(json.dumps(value, sort_keys=True) + '\n')
        handle.flush()
        os.fchmod(handle.fileno(), 0o600)
        os.fsync(handle.fileno())
    os.replace(temporary, path)
    directory = os.open(path.parent, os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def link(path, target):
    temporary = path.with_name(path.name + '.next')
    temporary.unlink(missing_ok=True)
    temporary.symlink_to(target)
    os.replace(temporary, path)
    directory = os.open(path.parent, os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def unlink(path):
    path.unlink(missing_ok=True)
    sync_directory(path.parent)


def release(path=None):
    path = ACTIVE if path is None else path
    return path.resolve() if path.is_symlink() else None


def restore(old, previous):
    if old:
        link(ENABLED, Path(old) / 'site.conf')
        link(ACTIVE, old)
        atomic_json(SETTINGS, json.loads((Path(old) / 'metadata.json').read_text())['settings'])
    else:
        unlink(ENABLED)
        unlink(ACTIVE)
        unlink(SETTINGS)
    if previous:
        link(PREVIOUS, previous)
    else:
        unlink(PREVIOUS)


def recover():
    if not PENDING.exists():
        return False
    pending = json.loads(PENDING.read_text())
    restore(pending['old'], pending['previous'])
    run(['nginx', '-t'])
    unlink(PENDING)
    return True


# Tokenize nginx -T files as cp_proxy preflight does, retaining block boundaries.
def servers(text):
    lexer = shlex.shlex(text, posix=True, punctuation_chars='{};')
    lexer.whitespace_split = True
    lexer.commenters = '#'
    tokens = list(lexer)
    # shlex groups consecutive punctuation; nginx grammar needs single delimiters.
    tokens = [part for token in tokens for part in
              (list(token) if token and all(c in '{};' for c in token) else [token])]
    stack, current, result = [], [], []
    for token in tokens:
        if token == '{':
            stack.append((current[0] if current else '', []))
            current = []
        elif token == ';':
            if stack and stack[-1][0] == 'server' and current:
                stack[-1][1].append(current)
            current = []
        elif token == '}':
            if stack:
                name, directives = stack.pop()
                if name == 'server':
                    result.append((any(n == 'stream' for n, _ in stack), directives))
            current = []
        else:
            current.append(token)
    return result


def preflight(value, *, before_install=False):
    inspect()
    if not shutil.which('nginx'):
        if not before_install:
            raise ValueError('nginx must be installed before activation')
        if os.path.lexists(ENABLED):
            raise ValueError('Existing cover configuration requires nginx validation')
        listener_preflight(value, set())
        return
    output = subprocess.run(['nginx', '-v'], capture_output=True, text=True, timeout=10)
    version = re.search(r'nginx/(\d+\.\d+\.\d+)', output.stderr)
    if not version or version.group(1) != value['nginx_version']:
        raise ValueError('Unsupported nginx upstream version; expected 1.24.0 distribution security build')
    features = subprocess.run(['nginx', '-V'], capture_output=True, text=True, timeout=10).stderr
    if '--with-http_v2_module' not in features or '--with-http_ssl_module' not in features:
        raise ValueError('nginx must provide TLS and HTTP/2 modules')
    dump = run(['nginx', '-T']).decode()
    paths = []
    for section in re.split(r'^# configuration file (.+):\n', dump, flags=re.MULTILINE)[1:]:
        paths.append(section)
    nginx_ports = set()
    for path, text in zip(paths[::2], paths[1::2]):
        if Path(path).resolve() == ENABLED.resolve() and ENABLED.is_symlink():
            nginx_ports.update((80, value['port']))
            continue
        for stream, directives in servers(text):
            names = [arg for row in directives if row[0] == 'server_name' for arg in row[1:]]
            listens = [row[1:] for row in directives if row[0] == 'listen'] or [['80']]
            for listen in listens:
                address = listen[0]
                if address.startswith('unix:'):
                    continue
                port = int(address) if address.isdigit() else int(address.rsplit(':', 1)[1]) if ':' in address and address.rsplit(':', 1)[1].isdigit() else 80
                nginx_ports.add(port)
                if port == value['port']:
                    raise ValueError('Another nginx server uses the private TLS port')
                if port == 80:
                    if stream or 'ssl' in listen or 'proxy_protocol' in listen:
                        raise ValueError('TCP/80 conflicts with the HTTP-01 vhost')
                    for name in names:
                        if name.startswith('~') or fnmatch.fnmatch(value['hostname'], name) or (name.startswith('.') and (value['hostname'] == name[1:] or value['hostname'].endswith(name))):
                            raise ValueError('Another nginx vhost owns the cover hostname on TCP/80')
    listener_preflight(value, nginx_ports)
    # -T must actually include the directory we own; do not silently activate a dead file.
    if not re.search(r'include\s+/etc/nginx/sites-enabled/\*\s*;', dump):
        raise ValueError('Expected distribution sites-enabled include is absent')


def listener_preflight(value, nginx_ports):
    listeners = run(['ss', '-H', '-ltnp']).decode()
    for row in listeners.splitlines():
        columns = row.split()
        if len(columns) < 5:
            continue
        address = columns[3]
        port = int(address.rsplit(':', 1)[1])
        if port in (80, value['port']) and ('"nginx"' not in row or port not in nginx_ports):
            raise ValueError('A non-owned listener conflicts with TCP/80 or the private TLS port')


def certificate(path, value):
    key = path / 'privkey.pem'
    mode = key.stat()
    if mode.st_uid != 0 or mode.st_mode & 0o077:
        raise ValueError('Certificate private key must belong to root with mode 0600')
    run(['openssl', 'x509', '-in', str(path / 'cert.pem'), '-noout', '-checkend', str(value['min_lifetime'])])
    san = run(['openssl', 'x509', '-in', str(path / 'cert.pem'), '-noout', '-ext', 'subjectAltName']).decode()
    entries = [item.strip() for item in ''.join(san.splitlines()[1:]).split(',')]
    if entries != ['DNS:' + value['hostname']]:
        raise ValueError('Certificate SAN must contain exactly the owned hostname')
    run(['openssl', 'verify', '-purpose', 'sslserver', '-verify_hostname', value['hostname'],
         '-CAfile', value['trust'], '-untrusted', str(path / 'chain.pem'), str(path / 'cert.pem')])
    pub_cert = run(['openssl', 'x509', '-in', str(path / 'cert.pem'), '-noout', '-pubkey'])
    pub_key = run(['openssl', 'pkey', '-in', str(key), '-pubout'])
    if pub_cert != pub_key:
        raise ValueError('Certificate and private key do not match')
    fullchain = (path / 'fullchain.pem').read_bytes()
    if fullchain != (path / 'cert.pem').read_bytes() + (path / 'chain.pem').read_bytes():
        raise ValueError('Fullchain differs from the checked leaf and chain')


def config(path, value, tls):
    text = f'''{MARKER}. Immutable checked release.
server {{
    listen 80;
    listen [::]:80;
    server_name {value['hostname']};
    server_tokens off;
    location ^~ /.well-known/acme-challenge/ {{
        root /var/www/cover-site-acme;
        default_type text/plain;
        try_files $uri =404;
    }}
    location / {{ return 301 https://{value['hostname']}$request_uri; }}
}}
'''
    if tls:
        text += f'''
server {{
    listen 127.0.0.1:{value['port']} ssl http2;
    server_name {value['hostname']};
    server_tokens off;
    ssl_certificate {path}/certificate/fullchain.pem;
    ssl_certificate_key {path}/certificate/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_tickets off;
    root {path}/content;
    index index.html;
    autoindex off;
    location / {{ try_files $uri $uri/ =404; }}
}}
'''
    return text


def health(path):
    value = json.loads((path / 'metadata.json').read_text())['settings']
    if not (path / 'certificate').is_dir():
        return {'tls': False}
    master = Path('/run/nginx.pid').read_text().strip()
    if os.readlink(f'/proc/{master}/ns/net') != os.readlink('/proc/1/ns/net'):
        raise RuntimeError('nginx must use the host init network namespace')
    certificate(path / 'certificate', value)
    context = ssl.create_default_context(cafile=value['trust'])
    context.set_alpn_protocols(['http/1.1'])
    expected = (path / 'content/index.html').read_bytes()
    for _ in range(30):
        try:
            addresses = {row.split()[3] for row in run(['ss', '-H', '-ltn']).decode().splitlines()
                         if len(row.split()) >= 5 and row.split()[3].rsplit(':', 1)[1] == str(value['port'])}
            if addresses != {f"127.0.0.1:{value['port']}"}:
                raise RuntimeError('Private origin listener must bind only host-loopback IPv4')
            with socket.create_connection(('127.0.0.1', value['port']), timeout=2) as raw:
                with context.wrap_socket(raw, server_hostname=value['hostname']) as tls:
                    if tls.getpeercert(binary_form=True) != ssl.PEM_cert_to_DER_cert((path / 'certificate/cert.pem').read_text()):
                        raise RuntimeError('Active nginx is still serving a different certificate')
                    tls.sendall(f"GET / HTTP/1.1\r\nHost: {value['hostname']}\r\nConnection: close\r\n\r\n".encode())
                    response = http.client.HTTPResponse(tls)
                    response.begin()
                    if response.status != 200 or response.read() != expected:
                        raise RuntimeError('Active nginx is not serving the checked content')
            h2 = run(['curl', '--silent', '--show-error', '--fail', '--noproxy', '*', '--http2',
                      '--cacert', value['trust'], '--resolve', f"{value['hostname']}:{value['port']}:127.0.0.1",
                      '--max-time', '3', '--output', '/dev/null', '--write-out', '%{http_version}',
                      f"https://{value['hostname']}:{value['port']}/"])
            if h2 != b'2':
                raise RuntimeError('HTTP/2 ALPN health check failed')
            expiry = run(['openssl', 'x509', '-in', str(path / 'certificate/cert.pem'), '-noout', '-enddate']).decode().strip()
            return {'tls': True, 'http2': True, 'hostname': value['hostname'], 'port': value['port'], 'expiry': expiry}
        except (OSError, ssl.SSLError, RuntimeError, http.client.HTTPException):
            time.sleep(0.1)
    raise RuntimeError('TLS/content/HTTP2 health check failed; previous release must remain active')


def validate_candidate(path):
    # Validate the full shared configuration without touching the enabled site.
    with tempfile.TemporaryDirectory(prefix='cover-nginx-', dir='/run') as temporary:
        mirror = Path(temporary) / 'nginx'
        shutil.copytree('/etc/nginx', mirror, symlinks=False)
        for conf in mirror.rglob('*.conf'):
            if conf.is_file():
                conf.write_text(conf.read_text().replace('/etc/nginx/', str(mirror) + '/'))
        target = mirror / 'sites-enabled/cover-site.conf'
        target.unlink(missing_ok=True)
        target.write_text((path / 'site.conf').read_text())
        run(['nginx', '-t', '-c', str(mirror / 'nginx.conf'), '-p', '/etc/nginx/'])


def activate(path):
    old = release()
    previous = release(PREVIOUS)
    validate_candidate(path)
    atomic_json(PENDING, {'old': str(old) if old else None,
                          'previous': str(previous) if previous else None, 'candidate': str(path)})
    try:
        link(ENABLED, path / 'site.conf')
        run(['nginx', '-t'])
        running = subprocess.run(['systemctl', 'is-active', '--quiet', 'nginx'], timeout=10).returncode == 0
        run(['systemctl', 'reload' if running else 'start', 'nginx'])
        result = health(path)
        if old and (old / 'certificate').is_dir():
            link(PREVIOUS, old)
        else:
            unlink(PREVIOUS)
        link(ACTIVE, path)
        atomic_json(SETTINGS, json.loads((path / 'metadata.json').read_text())['settings'])
        unlink(PENDING)
        return result
    except Exception as error:
        restore(str(old) if old else None, str(previous) if previous else None)
        run(['nginx', '-t'])
        if old:
            try:
                run(['systemctl', 'reload', 'nginx'])
            except RuntimeError:
                # A refused reload can leave the old workers healthy. Prove that
                # actual service before considering restoration complete.
                health(old)
            else:
                health(old)
        elif subprocess.run(['systemctl', 'is-active', '--quiet', 'nginx'], timeout=10).returncode == 0:
            # First-install absence is also a real service state: retire candidate
            # workers by reloading the restored shared config, not only its link.
            run(['systemctl', 'reload', 'nginx'])
        unlink(PENDING)
        raise RuntimeError('Activation failed; restored the previous owned configuration/content/certificate') from error

def rollback():
    previous = release(PREVIOUS)
    if previous is None or not (previous / 'certificate').is_dir():
        raise ValueError('No previous checked TLS release; HTTP bootstrap is not a rollback target')
    value = json.loads((previous / 'metadata.json').read_text())['settings']
    certificate(previous / 'certificate', value)
    return activate(previous)



def stage(value, *, tls, source=None):
    live = Path('/etc/cover-site/acme/live') / value['hostname']
    if tls:
        certificate(live, value)
    manifest = json.loads((BASE / 'manifest.json').read_text()) if source is None else validate(source)
    content = source or BASE / 'input'
    digest = hashlib.sha256(json.dumps(value, sort_keys=True).encode())
    for name in manifest:
        digest.update(name.encode())
        digest.update((content / name).read_bytes())
    if tls:
        for name in ('cert.pem', 'chain.pem', 'fullchain.pem', 'privkey.pem'):
            digest.update((live / name).read_bytes())
    identity = digest.hexdigest() + ('-tls' if tls else '-http')
    old = release()
    if old and old.name == identity:
        health(old)
        return False
    path = BASE / 'releases' / identity
    if path.exists():
        # A checked retained release may be selected again; never mutate it.
        health_metadata = json.loads((path / 'metadata.json').read_text())
        if health_metadata['fingerprint'] != identity:
            raise ValueError('Owned release identity mismatch')
    else:
        with tempfile.TemporaryDirectory(prefix='.stage-', dir=path.parent) as temporary:
            staged = Path(temporary) / 'release'
            staged.mkdir(mode=0o755)
            (staged / 'content').mkdir(mode=0o755)
            for name in manifest:
                target = staged / 'content' / name
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
                shutil.copyfile(content / name, target)
                target.chmod(0o644)
            validate(staged / 'content')
            if tls:
                (staged / 'certificate').mkdir(mode=0o700)
                for name in ('cert.pem', 'chain.pem', 'fullchain.pem', 'privkey.pem'):
                    shutil.copyfile(live / name, staged / 'certificate' / name)
                    (staged / 'certificate' / name).chmod(0o600 if name == 'privkey.pem' else 0o644)
            (staged / 'site.conf').write_text(config(path, value, tls))
            (staged / 'site.conf').chmod(0o644)
            atomic_json(staged / 'metadata.json', {'fingerprint': identity, 'settings': value})
            for directory, _, files in os.walk(staged, topdown=False):
                for name in files:
                    with (Path(directory) / name).open('rb') as handle:
                        os.fsync(handle.fileno())
                sync_directory(Path(directory))
            os.rename(staged, path)
            sync_directory(path.parent)
    activate(path)
    return True


def certbot(value, operation, extra=()):
    env = os.environ.copy()
    if value['acme_ca']:
        env['REQUESTS_CA_BUNDLE'] = value['acme_ca']
    argv = ['certbot', operation, '--non-interactive', '--config-dir', '/etc/cover-site/acme',
            '--work-dir', '/var/lib/cover-site/acme-work', '--logs-dir', '/var/log/cover-site',
            '--server', value['directory']]
    if operation == 'certonly':
        argv += ['--webroot', '-w', '/var/www/cover-site-acme', '--cert-name', value['hostname'],
                 '-d', value['hostname'], '--email', value['email'], '--agree-tos', '--keep-until-expiring']
    else:
        # The owned timer already applies the machine-specific randomized delay.
        argv += ['--no-random-sleep-on-renew', '--cert-name', value['hostname'], '--deploy-hook', SCRIPT + ' deploy']
    run(argv + list(extra), env=env)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('operation', choices=('preflight', 'bootstrap', 'issue', 'apply', 'health', 'rollback', 'recover', 'renew', 'deploy'))
    parser.add_argument('--force-renewal', action='store_true')
    parser.add_argument('--settings-file', type=Path, default=SETTINGS)
    parser.add_argument('--before-install', action='store_true')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.exit(2, 'Root is required for the owned lifecycle\n')
    if args.settings_file != SETTINGS and args.operation not in ('preflight', 'bootstrap', 'issue', 'apply'):
        parser.error('Candidate settings are only valid for preflight/bootstrap/issue/apply')
    if args.before_install and args.operation != 'preflight':
        parser.error('before-install is only valid for preflight')
    if args.operation == 'preflight':
        try:
            preflight(settings(args.settings_file), before_install=args.before_install)
        except Exception as error:
            parser.exit(1, f'cover_site: {error}\n')
        print(json.dumps({'changed': False}))
        return
    inspect()
    # Renewal owns Certbot; its synchronous hook acquires the lifecycle lock only.
    lockpath = BASE / ('renew.lock' if args.operation == 'renew' else 'lifecycle.lock')
    with lockpath.open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            value = settings(args.settings_file) if args.operation != 'recover' else None
            changed, result = False, {}
            if args.operation == 'recover':
                changed = recover()
            elif args.operation == 'bootstrap':
                recover()
                if release() is None:
                    changed = stage(value, tls=False)
            elif args.operation == 'issue':
                live = Path('/etc/cover-site/acme/live') / value['hostname']
                before = (live / 'cert.pem').read_bytes() if (live / 'cert.pem').exists() else None
                certbot(value, 'certonly')
                certificate(live, value)
                changed = (live / 'cert.pem').read_bytes() != before
            elif args.operation in ('apply', 'deploy'):
                if args.operation == 'deploy':
                    expected = Path('/etc/cover-site/acme/live') / value['hostname']
                    if Path(os.environ.get('RENEWED_LINEAGE', '')).resolve() != expected.resolve():
                        raise ValueError('Deploy hook lineage is not owned by cover_site')
                    old = release()
                    if old is None:
                        raise ValueError('Renewal requires a checked active site')
                    changed = stage(value, tls=True, source=old / 'content')
                else:
                    recover()
                    preflight(value)
                    changed = stage(value, tls=True)
            elif args.operation == 'health':
                old = release()
                if old is None:
                    raise ValueError('No active checked release')
                result = health(old)
            elif args.operation == 'rollback':
                result = rollback()
                changed = True
            elif args.operation == 'renew':
                if args.force_renewal and not value['test']:
                    raise ValueError('Forced renewal is only allowed in disposable tests')
                old = release()
                if old is None:
                    raise ValueError('Renewal requires an active site')
                certbot(value, 'renew', ['--force-renewal'] if args.force_renewal else [])
                # Certbot may exit 0 when a deploy hook fails: explicitly verify deployment.
                active = release()
                live = Path('/etc/cover-site/acme/live') / value['hostname']
                if (active / 'certificate/cert.pem').read_bytes() != (live / 'cert.pem').read_bytes():
                    raise RuntimeError('Certbot issued a certificate but deployment failed; checked previous certificate remains active')
                result = health(active)
                changed = old != active
            print(json.dumps({'changed': changed, **result}))
        except Exception as error:
            parser.exit(1, f'cover_site: {error}\n')


if __name__ == '__main__':
    main()
