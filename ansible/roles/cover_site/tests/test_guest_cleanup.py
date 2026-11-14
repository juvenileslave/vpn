"""Regression checks for owned guest teardown; no real machine or mount mutation."""
import contextlib
import io
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
            def waited(pid, **kwargs):
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


class CleanupVerdictTests(unittest.TestCase):
    def test_cli_failures_are_nonzero_and_never_report_pass(self):
        remove_directory = cleanup.shutil.rmtree
        for scenario in ("timeout", "machine remains", "mount remains", "remove fails"):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as temporary:
                work = Path(temporary).resolve()
                cleanup.prepare(work)
                mount = "2 1 0:2 / " + str(work / "rootfs") + " rw - tmpfs tmpfs rw"
                output, errors = io.StringIO(), io.StringIO()
                environment = {"VPN_COVER_SITE_DISPOSABLE_GUEST": "yes", "GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted"}
                with patch.dict(os.environ, environment), patch.object(sys, "platform", "linux"), \
                     patch.object(os, "geteuid", return_value=0), \
                     patch.object(sys, "argv", ["guest_cleanup", "cleanup", "/var/tmp/vpn-cover-boot.ABC123", "--machine", "cover-reboot-ABC123"]), \
                     patch.object(cleanup, "validate_owner", return_value=work), \
                     patch.object(cleanup, "machine_present", side_effect=[False, scenario == "machine remains"]), \
                     patch.object(cleanup, "wait_supervisor", side_effect=TimeoutError if scenario == "timeout" else None), \
                     patch.object(Path, "read_text", return_value=mount if scenario == "mount remains" else "1 0 0:1 / / rw - rootfs rootfs rw"), \
                     patch.object(cleanup, "run", return_value=""), \
                     patch.object(cleanup.shutil, "rmtree", side_effect=OSError if scenario == "remove fails" else remove_directory), \
                     contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                    code = cleanup.main()
                self.assertEqual(code, 1)
                self.assertIn('"cleanup": "FAIL"', errors.getvalue())
                self.assertNotIn("PASS", output.getvalue() + errors.getvalue())
                self.assertTrue(work.exists())

    @unittest.skipUnless(hasattr(os, "pidfd_open"), "Linux retained-child pidfd required")
    def test_stop_during_unregistered_child_run_awaits_real_child_exit(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary).resolve()
            stopped = work / "child-stopped"
            child_code = (
                "import os,signal,sys; from pathlib import Path; "
                "signal.signal(signal.SIGTERM, lambda *_: (Path(sys.argv[1]).write_text('stopped'), sys.exit(0))); "
                "print(os.getpid(), flush=True); sys.stdin.buffer.read(1)"
            )
            driver = (
                "import sys; from pathlib import Path; sys.path.insert(0,sys.argv[1]); "
                "import guest_cleanup; raise SystemExit(guest_cleanup.supervise_command("
                "[sys.executable,'-c',sys.argv[2],sys.argv[3]],Path(sys.argv[4])))"
            )
            supervisor = subprocess.Popen([
                sys.executable, "-c", driver, str(HERE), child_code, str(stopped), str(work / "stopping"),
            ], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
            try:
                child_pid = int(supervisor.stdout.readline())
                supervisor.terminate()
                self.assertEqual(supervisor.wait(timeout=5), 0)
                self.assertEqual(stopped.read_text(), "stopped")
                with self.assertRaises(ProcessLookupError):
                    os.kill(child_pid, 0)
            finally:
                supervisor.stdin.close()
                if supervisor.poll() is None:
                    supervisor.kill()
                    supervisor.wait()
                supervisor.stdout.close()


    @unittest.skipUnless(hasattr(os, "pidfd_open"), "Linux retained-child pidfd required")
    def test_pending_stop_survives_popen_before_child_assignment(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary).resolve()
            stopped = work / "child-stopped"
            child_pid_file = work / "child-pid"
            child_code = (
                "import os,signal,sys; from pathlib import Path; "
                "signal.signal(signal.SIGTERM, lambda *_: (Path(sys.argv[1]).write_text('stopped'), sys.exit(0))); "
                "Path(sys.argv[2]).write_text(str(os.getpid())); print('ready',flush=True); sys.stdin.buffer.read(1)"
            )
            driver = """
import os, signal, subprocess, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import guest_cleanup
original = subprocess.Popen
def in_flight(command):
    child = original(command, stdout=subprocess.PIPE, text=True)
    child.stdout.readline()
    child.stdout.close()
    os.kill(os.getpid(), signal.SIGTERM)
    return child
guest_cleanup.subprocess.Popen = in_flight
raise SystemExit(guest_cleanup.supervise_command(
    [sys.executable, '-c', sys.argv[2], sys.argv[3], sys.argv[4]], Path(sys.argv[5])))
"""
            supervisor = subprocess.Popen([
                sys.executable, "-c", driver, str(HERE), child_code,
                str(stopped), str(child_pid_file), str(work / "stopping"),
            ], stdin=subprocess.PIPE)
            try:
                self.assertEqual(supervisor.wait(timeout=5), 0)
                self.assertEqual(stopped.read_text(), "stopped")
                with self.assertRaises(ProcessLookupError):
                    os.kill(int(child_pid_file.read_text()), 0)
            finally:
                supervisor.stdin.close()
                if supervisor.poll() is None:
                    supervisor.kill()
                    supervisor.wait()


class ConcurrentExitTests(unittest.TestCase):
    def test_confirmed_exit_races_remove_root_but_live_mismatch_is_refused(self):
        for race in ("empty cmdline after exit", "exit during signal", "live identity mismatch"):
            with self.subTest(race=race), tempfile.TemporaryDirectory() as temporary:
                work = Path(temporary).resolve() / "work"
                work.mkdir()
                cleanup.prepare(work)
                pid, descriptor = 99999999, 9876543
                base = Path("/proc") / str(pid)
                read_text, read_bytes, close = Path.read_text, Path.read_bytes, os.close
                def text(path, *args, **kwargs):
                    if path == base / "stat":
                        return f"{pid} (python) S {os.getppid()}"
                    if path == Path("/proc/self/mountinfo"):
                        return "1 0 0:1 / / rw - rootfs rootfs rw"
                    return read_text(path, *args, **kwargs)
                def binary(path, *args, **kwargs):
                    if path == base / "cmdline":
                        if race == "empty cmdline after exit":
                            return b""
                        action = "wrong-process" if race == "live identity mismatch" else "supervise"
                        return b"\0".join(value.encode() for value in [sys.executable, str(Path(cleanup.__file__).resolve()), action, str(work)])
                    return read_bytes(path, *args, **kwargs)
                closed = []
                def close_fd(value):
                    if value == descriptor:
                        closed.append(value)
                    else:
                        close(value)
                ready = ([], [], [])
                exited = ([descriptor], [], [])
                sequence = [ready, ready] if race == "live identity mismatch" else [ready, exited, exited]
                with patch.object(cleanup.os, "pidfd_open", return_value=descriptor, create=True), \
                     patch.object(cleanup.signal, "pidfd_send_signal", side_effect=ProcessLookupError, create=True) as send, \
                     patch.object(cleanup.select, "select", side_effect=sequence), \
                     patch.object(Path, "read_text", new=text), patch.object(Path, "read_bytes", new=binary), \
                     patch.object(cleanup.os, "close", side_effect=close_fd), \
                     patch.object(cleanup, "machine_present", return_value=False):
                    if race == "live identity mismatch":
                        with self.assertRaises(ValueError):
                            cleanup.cleanup(work, "owned", pid)
                        self.assertTrue(work.exists())
                        send.assert_not_called()
                    else:
                        cleanup.cleanup(work, "owned", pid)
                        self.assertFalse(work.exists())
                        if race == "empty cmdline after exit":
                            send.assert_not_called()
                        else:
                            send.assert_called_once()
                self.assertEqual(closed, [descriptor])


if __name__ == "__main__":
    unittest.main()
