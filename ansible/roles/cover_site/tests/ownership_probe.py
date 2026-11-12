#!/usr/bin/env python3
"""Real playbook negatives: foreign persistent paths must remain byte/mode identical."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'files'))
import ownership

if not (os.geteuid() == 0 and os.environ.get('VPN_COVER_SITE_DISPOSABLE_GUEST') == 'yes'
        and os.environ.get('GITHUB_ACTIONS') == 'true'
        and os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted'):
    raise SystemExit('Only a guarded disposable GitHub-hosted root guest is allowed')
phase, *command = sys.argv[1:]
assert phase in ('fresh', 'managed') and command


def snapshot():
    paths = list(ownership.ROOTS) + [Path('/etc/nginx'), ownership.UNIT_DIR,
        Path('/var/lib/dpkg/status'), Path('/var/lib/apt/lists'), Path('/var/cache/apt')]
    result = {}
    for root in paths:
        candidates = [root]
        if root.is_dir() and not root.is_symlink():
            for directory, dirs, files in os.walk(root, followlinks=False):
                candidates.extend(Path(directory) / name for name in dirs + files)
        for path in candidates:
            if not os.path.lexists(path):
                result[str(path)] = None
                continue
            info = path.lstat()
            data = os.readlink(path) if path.is_symlink() else hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None
            result[str(path)] = (info.st_mode, info.st_uid, info.st_gid, info.st_ino,
                                 info.st_size, info.st_mtime_ns, data)
    return result


def reject(label):
    before = snapshot()
    with tempfile.TemporaryFile() as log:
        result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=180)
    assert result.returncode != 0, f'Foreign {label} was accepted'
    after = snapshot()
    assert after == before, f'Foreign {label} changed persistent resources, modes or content'
    print(json.dumps({'foreign_resource': label, 'rejected': result.returncode != 0,
                      'persistent_state_unchanged': after == before}))


def fresh_file(path, *, directory=False, symlink=False):
    assert not os.path.lexists(path), f'Non-fresh fixture target: {path}'
    parent_existed = path.parent.exists()
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        if directory:
            path.mkdir(mode=0o751)
            (path / 'foreign.txt').write_text('Unrelated disposable fixture\n')
        elif symlink:
            path.symlink_to('/dev/null')
        else:
            path.write_text('Unrelated disposable fixture\n')
            path.chmod(0o751)
        reject(str(path))
    finally:
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(path)
        else:
            path.unlink()
        if not parent_existed:
            path.parent.rmdir()


if phase == 'fresh':
    for root in ownership.ROOTS:
        fresh_file(root, directory=True)
    fresh_file(Path('/usr/local/libexec/cover-site'), symlink=True)
    for name in ownership.UNITS:
        fresh_file(ownership.UNIT_DIR / name)
        fresh_file(ownership.UNIT_DIR / (name + '.d'), directory=True)
        fresh_file(ownership.UNIT_DIR / (name + '.next'))
    for relative in ownership.ENABLE_LINKS:
        fresh_file(ownership.UNIT_DIR / relative, symlink=True)
    fresh_file(ownership.ENABLED)
    fresh_file(ownership.ENABLED.with_name(ownership.ENABLED.name + '.next'), symlink=True)
else:
    ownership.inspect()
    for name in ('lifecycle.py', 'validate_content.py', 'ownership.py'):
        path = Path('/usr/local/libexec/cover-site') / name
        original, info = path.read_bytes(), path.stat()
        try:
            path.write_text('Unrelated replacement helper fixture\n')
            path.chmod(0o751)
            reject(str(path))
        finally:
            path.write_bytes(original)
            path.chmod(info.st_mode & 0o7777)
            os.utime(path, ns=(info.st_atime_ns, info.st_mtime_ns))
    for name in ownership.UNITS:
        fresh_file(ownership.UNIT_DIR / (name + '.d'), directory=True)
    fresh_file(Path('/etc/cover-site/foreign-sidecar.json'))
    ownership.inspect()
