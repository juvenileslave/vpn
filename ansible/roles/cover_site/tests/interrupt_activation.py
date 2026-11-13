#!/usr/bin/env python3
"""Interrupt the real lifecycle at a durable pointer write, never mock nginx/health."""
import fcntl
import json
import os
from pathlib import Path
import sys

if not (os.geteuid() == 0 and os.environ.get('VPN_COVER_SITE_DISPOSABLE_GUEST') == 'yes'
        and os.environ.get('GITHUB_ACTIONS') == 'true'
        and os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted'):
    raise SystemExit('Only a guarded disposable GitHub-hosted root guest is allowed')
sys.path.insert(0, '/usr/local/libexec/cover-site')
import lifecycle

point, candidate = sys.argv[1:]
assert point in ('enabled', 'previous', 'active')
candidate = Path(candidate).resolve(strict=True)
assert candidate.parent == lifecycle.BASE / 'releases'
value = json.loads((candidate / 'metadata.json').read_text())['settings']
assert value['test'] and value['hostname'].endswith('.example.test')
assert value['directory'] == 'https://localhost:14000/dir'
lifecycle.inspect()
real_link = lifecycle.link
wanted = {'enabled': lifecycle.ENABLED, 'previous': lifecycle.PREVIOUS, 'active': lifecycle.ACTIVE}[point]


def interrupted_link(path, target):
    real_link(path, target)
    if path == wanted:
        assert lifecycle.PENDING.is_file(), 'Interruption must leave the real durable journal'
        os._exit(86)


lifecycle.link = interrupted_link
with (lifecycle.BASE / 'lifecycle.lock').open('a') as lock:
    fcntl.flock(lock, fcntl.LOCK_EX)
    lifecycle.activate(candidate)
raise SystemExit('Requested real activation interruption seam was never reached')
