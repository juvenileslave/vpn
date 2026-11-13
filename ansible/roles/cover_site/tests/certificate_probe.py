#!/usr/bin/env python3
"""Real OpenSSL negative certificates; checked nginx snapshots remain untouched."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, '/usr/local/libexec/cover-site')
import lifecycle

assert os.environ.get('VPN_COVER_SITE_DISPOSABLE_GUEST') == 'yes'
value = lifecycle.settings()
assert value['test']
active = lifecycle.release()
source = active / 'certificate'


def reject(path, label):
    try:
        lifecycle.certificate(path, value)
    except (ValueError, RuntimeError):
        print('Rejected real certificate case:', label)
    else:
        raise AssertionError('Accepted invalid certificate: ' + label)
    assert lifecycle.release() == active
    lifecycle.health(active)


with tempfile.TemporaryDirectory(prefix='cover-negative-cert-') as directory:
    root = Path(directory)
    snapshot = root / 'certificate'
    shutil.copytree(source, snapshot)
    key = snapshot / 'privkey.pem'
    key.chmod(0o644)
    reject(snapshot, 'world-readable private key')
    key.chmod(0o600)
    wrong_key = root / 'wrong-key.pem'
    lifecycle.run(['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', str(wrong_key)])
    shutil.copyfile(wrong_key, key)
    reject(snapshot, 'certificate/key mismatch')
    shutil.copyfile(source / 'privkey.pem', key)
    shutil.copyfile(source / 'cert.pem', snapshot / 'chain.pem')
    (snapshot / 'fullchain.pem').write_bytes((snapshot / 'cert.pem').read_bytes() + (snapshot / 'chain.pem').read_bytes())
    reject(snapshot, 'untrusted/incomplete issuer chain')
    lifecycle.run(['openssl', 'req', '-x509', '-key', str(wrong_key), '-out', str(root / 'ca.pem'),
                   '-days', '2', '-subj', '/CN=Disposable-Negative-CA',
                   '-addext', 'basicConstraints=critical,CA:TRUE'])
    (root / 'index').write_text('')
    (root / 'serial').write_text('02\n')
    (root / 'ca.cnf').write_text(f'''[ca]
default_ca=local
[local]
database={root}/index
serial={root}/serial
new_certs_dir={root}
certificate={root}/ca.pem
private_key={wrong_key}
default_md=sha256
default_days=2
policy=subject
[subject]
commonName=supplied
''')
    # Generate actual certificates with incorrect SAN and expired validity.
    for label, hostname in [('wrong DNS SAN', 'different.example.test'),
                            ('expired leaf', value['hostname'])]:
        shutil.rmtree(snapshot)
        shutil.copytree(source, snapshot)
        lifecycle.run(['openssl', 'req', '-new', '-key', str(wrong_key), '-out', str(root / 'leaf.csr'),
                       '-subj', '/CN=' + hostname])
        (root / 'leaf.ext').write_text('subjectAltName=DNS:' + hostname + '\nextendedKeyUsage=serverAuth\n')
        if label == 'expired leaf':
            lifecycle.run(['openssl', 'ca', '-batch', '-config', str(root / 'ca.cnf'),
                           '-startdate', '20200101000000Z', '-enddate', '20200102000000Z',
                           '-in', str(root / 'leaf.csr'), '-out', str(snapshot / 'cert.pem'),
                           '-extfile', str(root / 'leaf.ext')])
        else:
            lifecycle.run(['openssl', 'x509', '-req', '-in', str(root / 'leaf.csr'),
                           '-CA', str(root / 'ca.pem'), '-CAkey', str(wrong_key), '-set_serial', '1',
                           '-out', str(snapshot / 'cert.pem'), '-days', '2', '-extfile', str(root / 'leaf.ext')])
        shutil.copyfile(wrong_key, snapshot / 'privkey.pem')
        (snapshot / 'fullchain.pem').write_bytes((snapshot / 'cert.pem').read_bytes() + (snapshot / 'chain.pem').read_bytes())
        reject(snapshot, label)
print(json.dumps({'negative_certificate_cases': 5, 'active_release_preserved': True}))
