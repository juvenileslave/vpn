"""Regression checks for owned guest teardown; no real machine or mount mutation."""
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("guest_cleanup", HERE / "guest_cleanup.py")
cleanup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cleanup)


class GuestCleanupTests(unittest.TestCase):
    def test_selects_only_owned_mounts_deepest_first(self):
        mountinfo = "\n".join([
            "1 0 0:1 / / rw - rootfs rootfs rw",
            "2 1 0:2 / /var/tmp/guest/rootfs/run rw - tmpfs tmpfs rw",
            "3 2 0:3 / /var/tmp/guest/rootfs/run/systemd rw - tmpfs tmpfs rw",
            "4 1 0:4 / /var/tmp/guest-other/rootfs rw - tmpfs tmpfs rw",
            "5 1 0:5 / /var/tmp/guest/rootfs/with\\040space rw - tmpfs tmpfs rw",
        ])
        self.assertEqual(cleanup.owned_mountpoints(mountinfo, "/var/tmp/guest"), [
            Path("/var/tmp/guest/rootfs/run/systemd"), Path("/var/tmp/guest/rootfs/with space"), Path("/var/tmp/guest/rootfs/run"),
        ])

    def test_unmarked_or_symlink_directory_is_not_deleted(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            work = root / "work"
            work.mkdir()
            sentinel = work / "preserve"
            sentinel.write_text("unrelated data")
            with self.assertRaises(FileNotFoundError):
                cleanup.cleanup(work, "machine", 0)
            self.assertEqual(sentinel.read_text(), "unrelated data")
            alias = root / "alias"
            alias.symlink_to(work, target_is_directory=True)
            with self.assertRaises(ValueError):
                cleanup.prepare(alias)
            self.assertEqual(sentinel.read_text(), "unrelated data")

    def test_waits_for_supervisor_before_unmounting_and_removing(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary).resolve() / "guest"
            work.mkdir()
            cleanup.prepare(work)
            (work / "rootfs").mkdir()
            (work / "rootfs" / "data").write_text("owned")
            events = []
            mounts = "2 1 0:2 / " + str(work / "rootfs") + " rw - tmpfs tmpfs rw"
            def command(args):
                events.append(args[0])
                return ""
            def waited(pid):
                self.assertTrue((work / "stopping").exists())
                self.assertTrue((work / "rootfs" / "data").exists())
                events.append("supervisor exited")
            with patch.object(cleanup, "machine_present", return_value=False), \
                 patch.object(cleanup, "wait_supervisor", side_effect=waited), \
                 patch.object(cleanup, "run", side_effect=command), \
                 patch.object(Path, "read_text", autospec=True) as read:
                marker_text = (work / cleanup.MARKER).read_bytes().decode()
                count = 0
                def content(path, *args, **kwargs):
                    nonlocal count
                    if path.name == cleanup.MARKER:
                        return marker_text
                    count += 1
                    return mounts if count == 1 else "1 0 0:1 / / rw - rootfs rootfs rw"
                read.side_effect = content
                cleanup.cleanup(work, "owned", 123)
            self.assertEqual(events, ["supervisor exited", "umount"])
            self.assertFalse(work.exists())

    def test_timeout_retains_owned_root_and_does_not_unmount(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary).resolve()
            cleanup.prepare(work)
            sentinel = work / "preserve"
            sentinel.write_text("owned state")
            with patch.object(cleanup, "machine_present", return_value=False), \
                 patch.object(cleanup, "wait_supervisor", side_effect=TimeoutError), \
                 patch.object(cleanup, "run") as command:
                with self.assertRaises(TimeoutError):
                    cleanup.cleanup(work, "owned", 123)
            command.assert_not_called()
            self.assertEqual(sentinel.read_text(), "owned state")

    @unittest.skipUnless(hasattr(os, "pidfd_open"), "Linux pidfd exit notification required")
    def test_pidfd_waits_for_real_child_exit_instead_of_killing_waiting_parent(self):
        child = subprocess.Popen([sys.executable, "-c", "import sys; sys.stdin.buffer.read(1)"], stdin=subprocess.PIPE)
        try:
            with self.assertRaises(TimeoutError):
                cleanup.wait_supervisor(child.pid, timeout=0)
            self.assertIsNone(child.poll())
            child.stdin.write(b"x")
            child.stdin.flush()
            cleanup.wait_supervisor(child.pid, timeout=5)
            self.assertEqual(child.wait(timeout=5), 0)
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()
            child.stdin.close()


if __name__ == "__main__":
    unittest.main()
