#!/usr/bin/env python3
# Managed by cover_site. Persistent namespace ownership and type checks.
"""Inspect without mutation; claim absent roots by durable atomic directory rename."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import re
import tempfile

MARKER = '# Managed by cover_site'
OWNER_UID = 0
ROOTS = {
    Path('/etc/cover-site'): (0o700, {'settings.json': 'file', 'settings.tmp': 'file',
        'candidate-settings.json': 'file', 'acme': 'dir'}),
    Path('/usr/local/libexec/cover-site'): (0o755, {'lifecycle.py': 'helper',
        'validate_content.py': 'helper', 'ownership.py': 'helper', '__pycache__': 'dir'}),
    Path('/var/lib/cover-site'): (0o755, {'releases': 'dir', 'acme-work': 'dir',
        'input': 'dir', 'manifest.json': 'file', 'active': 'release', 'previous': 'release',
        'active.next': 'release', 'previous.next': 'release', 'pending.json': 'file',
        'pending.tmp': 'file', 'lifecycle.lock': 'file', 'renew.lock': 'file'}),
    Path('/var/log/cover-site'): (0o700, None),
    Path('/var/www/cover-site-acme'): (0o755, {'.well-known': 'dir'}),
}
UNIT_DIR = Path('/etc/systemd/system')
UNITS = ('cover-site-recover.service', 'cover-site-renew.service', 'cover-site-renew.timer')
ENABLE_LINKS = {
    'multi-user.target.wants/cover-site-recover.service': 'cover-site-recover.service',
    'nginx.service.requires/cover-site-recover.service': 'cover-site-recover.service',
    'timers.target.wants/cover-site-renew.timer': 'cover-site-renew.timer',
}
ENABLED = Path('/etc/nginx/sites-enabled/cover-site.conf')
BASE = Path('/var/lib/cover-site')


def exists(path):
    return os.path.lexists(path)


def sync_directory(path):
    handle = os.open(path, os.O_DIRECTORY)
    try:
        os.fsync(handle)
    finally:
        os.close(handle)


def marker(root):
    return json.dumps({'owner': 'cover_site', 'schema': 1, 'root': str(root)}, sort_keys=True) + '\n'


def ancestors(path):
    for parent in reversed(path.parents):
        if exists(parent) and not stat.S_ISDIR(parent.lstat().st_mode):
            raise ValueError(f'Owned path has an unrelated or symlink ancestor: {parent}')


def regular(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != OWNER_UID:
        raise ValueError(f'Owned file must be a root-owned regular file: {path}')


def marked(path):
    regular(path)
    if MARKER not in path.read_text().splitlines()[:2]:
        # Helpers have a longer explanatory marker line; units use the exact line.
        if not any(line.startswith(MARKER + '.') for line in path.read_text().splitlines()[:2]):
            raise ValueError(f'Unrelated helper or unit: {path}')


def pointer(path, *, site=False):
    if not path.is_symlink():
        raise ValueError(f'Owned pointer must be a symlink: {path}')
    target = path.resolve(strict=True)
    releases = BASE / 'releases'
    release = target.parent if site else target
    if release.parent != releases or not release.is_dir() or (site and target.name != 'site.conf'):
        raise ValueError(f'Owned pointer escapes immutable releases: {path}')
    marked(release / 'site.conf')
    regular(release / 'metadata.json')


def tree(root):
    for directory, dirs, files in os.walk(root, followlinks=False):
        for name in dirs + files:
            path = Path(directory) / name
            info = path.lstat()
            if info.st_uid != OWNER_UID:
                raise ValueError(f'Owned tree contains a non-root resource: {path}')
            if stat.S_ISLNK(info.st_mode):
                if path.parent == BASE and name in ('active', 'previous', 'active.next', 'previous.next'):
                    pointer(path)
                elif root == Path('/etc/cover-site') and path.is_relative_to(root / 'acme/live'):
                    if not path.resolve(strict=True).is_relative_to(root / 'acme/archive'):
                        raise ValueError(f'Certbot symlink escapes owned archive: {path}')
                else:
                    raise ValueError(f'Unexpected symlink in owned tree: {path}')
            elif not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
                raise ValueError(f'Unexpected resource type in owned tree: {path}')


def inspect():
    for root, (_, children) in ROOTS.items():
        ancestors(root)
        if not exists(root):
            continue
        info = root.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != OWNER_UID:
            raise ValueError(f'Unrelated owned root: {root}')
        claim = root / '.cover-site-owner.json'
        if not exists(claim):
            raise ValueError(f'Unmarked owned root: {root}')
        regular(claim)
        if claim.read_text() != marker(root):
            raise ValueError(f'Unrelated ownership marker: {root}')
        if children is not None:
            for path in root.iterdir():
                if path == claim:
                    continue
                kind = children.get(path.name)
                if kind is None:
                    raise ValueError(f'Unexpected owned-root resource: {path}')
                if kind == 'helper':
                    marked(path)
                elif kind == 'file':
                    regular(path)
                elif kind == 'release':
                    pointer(path)
                elif not stat.S_ISDIR(path.lstat().st_mode):
                    raise ValueError(f'Owned child must be a directory: {path}')
        tree(root)
    for path in (Path('/var/www/cover-site-acme/.well-known/acme-challenge'),
                 Path('/etc/cover-site/acme/live'), Path('/etc/cover-site/acme/archive'),
                 Path('/etc/cover-site/acme/renewal')):
        if exists(path) and not stat.S_ISDIR(path.lstat().st_mode):
            raise ValueError(f'Owned persistent subtree must be a directory: {path}')
    releases = BASE / 'releases'
    if exists(releases):
        for path in releases.iterdir():
            if not stat.S_ISDIR(path.lstat().st_mode):
                raise ValueError(f'Owned release must be a directory: {path}')
            if path.name.startswith('.stage-'):
                continue  # An interrupted unpublished staging tree is never activated.
            if not re.fullmatch(r'[0-9a-f]{64}-(?:http|tls)', path.name):
                raise ValueError(f'Unrelated resource in immutable releases: {path}')
            marked(path / 'site.conf')
            regular(path / 'metadata.json')
            if json.loads((path / 'metadata.json').read_text())['fingerprint'] != path.name:
                raise ValueError(f'Owned release fingerprint mismatch: {path}')
            if not stat.S_ISDIR((path / 'content').lstat().st_mode):
                raise ValueError(f'Owned release content must be a directory: {path}')
            if path.name.endswith('-tls'):
                if not stat.S_ISDIR((path / 'certificate').lstat().st_mode):
                    raise ValueError(f'Owned certificate snapshot must be a directory: {path}')
                for name in ('cert.pem', 'chain.pem', 'fullchain.pem', 'privkey.pem'):
                    regular(path / 'certificate' / name)
            allowed = {'site.conf', 'metadata.json', 'content'} | ({'certificate'} if path.name.endswith('-tls') else set())
            if any(child.name not in allowed for child in path.iterdir()):
                raise ValueError(f'Unexpected immutable release sidecar: {path}')
    for name in UNITS:
        unit = UNIT_DIR / name
        ancestors(unit)
        if exists(unit):
            marked(unit)
        for directory in (UNIT_DIR, Path('/run/systemd/system'), Path('/usr/lib/systemd/system'),
                          Path('/lib/systemd/system')):
            for sidecar in (name + '.d', name + '.tmp', name + '.next', name + '~'):
                if exists(directory / sidecar):
                    raise ValueError(f'Unrelated lifecycle unit sidecar: {directory / sidecar}')
            if directory != UNIT_DIR and exists(directory / name):
                raise ValueError(f'Lifecycle unit is already supplied outside owned unit path: {directory / name}')
    for relative, name in ENABLE_LINKS.items():
        path = UNIT_DIR / relative
        ancestors(path)
        if exists(path):
            if not path.is_symlink() or path.resolve() != UNIT_DIR / name:
                raise ValueError(f'Unrelated lifecycle enable link: {path}')
            marked(UNIT_DIR / name)
    for path in (ENABLED, ENABLED.with_name(ENABLED.name + '.next')):
        ancestors(path)
        if exists(path):
            if not exists(BASE / '.cover-site-owner.json'):
                raise ValueError('Enabled site has no owned release namespace')
            pointer(path, site=True)


def initialize():
    changed = False
    inspect()
    for root, (mode, _) in ROOTS.items():
        if exists(root):
            continue
        root.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='.cover-site-claim-', dir=root.parent) as temporary:
            staged = Path(temporary) / root.name
            staged.mkdir(mode=mode)
            claim = staged / '.cover-site-owner.json'
            with claim.open('x') as handle:
                handle.write(marker(root))
                handle.flush()
                os.fchmod(handle.fileno(), 0o600)
                os.fsync(handle.fileno())
            sync_directory(staged)
            # An independently created root is never adopted or overwritten.
            if exists(root):
                raise ValueError(f'Owned root appeared during initialization: {root}')
            os.rename(staged, root)
            sync_directory(root.parent)
            changed = True
    return changed


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('operation', choices=('inspect', 'initialize'))
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.exit(2, 'Root is required for ownership inspection\n')
    try:
        changed = initialize() if args.operation == 'initialize' else (inspect() or False)
        print(json.dumps({'changed': changed}))
    except (OSError, ValueError) as error:
        parser.exit(1, f'cover_site: {error}\n')
