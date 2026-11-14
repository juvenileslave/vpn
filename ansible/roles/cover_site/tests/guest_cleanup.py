"""Fail-closed teardown of the disposable cover-site boot guest, never production."""
import argparse
import json
import os
from pathlib import Path
import re
import select
import shutil
import stat
import subprocess
import sys

MARKER = ".cover-guest-owner.json"


def prepare(work):
    work = Path(work)
    info = work.lstat()
    if not work.is_absolute() or work.resolve() != work or not stat.S_ISDIR(info.st_mode):
        raise ValueError("invalid owned guest directory")
    if info.st_uid != os.geteuid():
        raise ValueError("guest directory owner mismatch")
    with (work / MARKER).open("x") as stream:
        json.dump({"owner": "cover-guest-test", "path": str(work), "device": info.st_dev, "inode": info.st_ino}, stream)
    (work / MARKER).chmod(0o600)


def validate_owner(work):
    work = Path(work)
    if not work.is_absolute() or ".." in work.parts or work.resolve() != work:
        raise ValueError("invalid owned guest directory")
    info = work.lstat()
    marker = work / MARKER
    marked = marker.lstat()
    if not stat.S_ISDIR(info.st_mode) or not stat.S_ISREG(marked.st_mode):
        raise ValueError("invalid guest ownership marker")
    if info.st_uid != os.geteuid() or marked.st_uid != os.geteuid():
        raise ValueError("guest directory owner mismatch")
    value = json.loads(marker.read_text())
    expected = {"owner": "cover-guest-test", "path": str(work), "device": info.st_dev, "inode": info.st_ino}
    if value != expected:
        raise ValueError("guest ownership marker mismatch")
    return work


def owned_mountpoints(mountinfo, root):
    """Use the existing runtime-driver rule: canonical owned targets, deepest first."""
    root = Path(root)
    if not root.is_absolute() or ".." in root.parts:
        raise ValueError("invalid owned mount root")
    points = set()
    for line in mountinfo.splitlines():
        if not line:
            continue
        fields = line.split()
        if len(fields) < 10 or "-" not in fields:
            raise ValueError("malformed mountinfo")
        target = re.sub(r"\\([0-7]{3})", lambda match: chr(int(match.group(1), 8)), fields[4])
        point = Path(target)
        if not point.is_absolute() or ".." in point.parts:
            raise ValueError("noncanonical mount target")
        if point == root or root in point.parents:
            points.add(point)
    return sorted(points, key=lambda point: (len(point.parts), str(point)), reverse=True)


def run(args):
    result = subprocess.run(args, capture_output=True, timeout=15, check=False)
    if result.returncode != 0:
        raise RuntimeError("guest teardown command failed")
    return result.stdout.decode()


def machine_present(machine):
    rows = run(["machinectl", "list", "--no-legend", "--no-pager"])
    return any(line.split()[0] == machine for line in rows.splitlines() if line.split())


def wait_supervisor(pid, timeout=60):
    """A pidfd becomes readable at exit, including an unreaped direct-child zombie."""
    if pid == 0:
        return
    if pid < 0:
        raise ValueError("invalid supervisor pid")
    try:
        descriptor = os.pidfd_open(pid)
    except ProcessLookupError:
        return
    try:
        ready, _, _ = select.select([descriptor], [], [], timeout)
        if not ready:
            raise TimeoutError("guest supervisor did not exit")
    finally:
        os.close(descriptor)


def mark_stopping(work):
    path = work / "stopping"
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
            raise ValueError("invalid guest stop marker")
        return
    os.close(descriptor)


def cleanup(work, machine, supervisor):
    work = validate_owner(work)
    mark_stopping(work)
    if machine_present(machine):
        root = run(["machinectl", "show", machine, "--property=RootDirectory", "--value"]).strip()
        if root != str(work / "rootfs"):
            raise ValueError("machine root is not owned by this guest")
        run(["machinectl", "terminate", machine])
    # Do not kill the waiting shell: its foreground nspawn must finish teardown.
    wait_supervisor(supervisor)
    if machine_present(machine):
        raise RuntimeError("owned guest machine remains registered")
    mountinfo = Path("/proc/self/mountinfo")
    for point in owned_mountpoints(mountinfo.read_text(), work):
        run(["umount", "--", str(point)])
    if owned_mountpoints(mountinfo.read_text(), work):
        raise RuntimeError("owned guest mounts remain")
    validate_owner(work)
    shutil.rmtree(work)
    try:
        work.lstat()
    except FileNotFoundError:
        return
    raise RuntimeError("owned guest directory remains")


def main():
    guard = {"VPN_COVER_SITE_DISPOSABLE_GUEST": "yes", "GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted"}
    if sys.platform != "linux" or os.geteuid() != 0 or any(os.environ.get(key) != value for key, value in guard.items()):
        print("refusing non-disposable guest cleanup", file=sys.stderr)
        return 2
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("prepare", "cleanup"))
    parser.add_argument("work")
    parser.add_argument("--machine", default="")
    parser.add_argument("--supervisor", type=int, default=0)
    args = parser.parse_args()
    if not re.fullmatch(r"/var/tmp/vpn-cover-boot\.[A-Za-z0-9]{6}", args.work):
        print("invalid disposable guest path", file=sys.stderr)
        return 2
    try:
        if args.action == "prepare":
            prepare(args.work)
        else:
            expected_machine = "cover-reboot-" + args.work.rsplit(".", 1)[1]
            if args.machine != expected_machine:
                raise ValueError("unexpected guest machine identity")
            cleanup(args.work, args.machine, args.supervisor)
            print(json.dumps({"cleanup": "PASS", "machine_absent": True, "supervisor_exited": True, "mounts_absent": True, "work_absent": True}))
    except Exception as error:
        print(json.dumps({"cleanup": "FAIL", "error_type": type(error).__name__, "errno": getattr(error, "errno", None)}), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
