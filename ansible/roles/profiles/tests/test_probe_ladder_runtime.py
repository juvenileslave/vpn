"""Consumer payload/guard regressions only; real authorization belongs to CI."""
import hashlib
import os
from pathlib import Path
import queue
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest

from probe_ladder_runtime import AUTH_BYTES, SMALL_BYTES, LARGE_BYTES, PATTERN, payload_digest, read_probe_rows, child_pids


class PayloadExpectationTest(unittest.TestCase):
    def test_streaming_expectation_matches_the_transferred_pattern(self):
        for size in (AUTH_BYTES, SMALL_BYTES, LARGE_BYTES, 17 << 10):
            with self.subTest(size=size):
                reference = hashlib.sha256()
                full, remainder = divmod(size, len(PATTERN))
                for _ in range(full):
                    reference.update(PATTERN)
                reference.update(PATTERN[:remainder])
                self.assertEqual(payload_digest(size), reference.hexdigest())
        self.assertNotEqual(payload_digest(17 << 10), payload_digest(LARGE_BYTES))

    def test_unguarded_ladder_entry_refuses_before_runtime_setup(self):
        environment = {key: value for key, value in os.environ.items()
                       if key not in ("VPN_PROFILES_DISPOSABLE_GUEST", "GITHUB_ACTIONS", "RUNNER_ENVIRONMENT")}
        entry = Path(__file__).with_name("runtime_vm.py")
        result = subprocess.run([sys.executable, str(entry), "probe-ladder"], env=environment,
                                capture_output=True, timeout=5, check=False)
        self.assertEqual(result.returncode, 2)
        self.assertNotIn(b"PASS", result.stdout)


class StoreReaderTest(unittest.TestCase):
    def test_missing_database_is_not_created_as_empty_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "missing.db"
            with self.assertRaises(sqlite3.OperationalError):
                read_probe_rows(path, "fixture")
            self.assertFalse(path.exists())

    def test_closed_reader_keeps_successive_writer_observations(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "state.db"
            with sqlite3.connect(path) as database:
                database.execute("CREATE TABLE probes (id INTEGER PRIMARY KEY, run_id TEXT, stage TEXT, family TEXT, outcome TEXT, error_code TEXT, bytes INTEGER, duration_ns INTEGER, vantage TEXT, network TEXT, scope TEXT, expected_bytes INTEGER, body_duration_ns INTEGER) STRICT")
            database.close()
            expected = ("throughput", "ipv6", "success", "", LARGE_BYTES, 100, "inside", "synthetic", "node_path", LARGE_BYTES, 50)
            for index in range(3):
                with sqlite3.connect(path) as database:
                    database.execute("INSERT INTO probes VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (index + 1, "fixture", *expected))
                database.close()
                before = path.read_bytes()
                self.assertEqual(read_probe_rows(path, "fixture"), [expected] * (index + 1))
                self.assertEqual(path.read_bytes(), before)


class ChildProcessTest(unittest.TestCase):
    def test_child_created_by_nonmain_thread_is_observed(self):
        processes = queue.Queue()
        release = threading.Event()

        def create_child():
            process = subprocess.Popen([sys.executable, "-c", "import sys; sys.stdin.buffer.read()"], stdin=subprocess.PIPE)
            processes.put(process)
            release.wait(5)
            process.stdin.close()
            process.wait(timeout=5)

        thread = threading.Thread(target=create_child)
        thread.start()
        try:
            process = processes.get(timeout=5)
            self.assertIn(str(process.pid), child_pids(os.getpid()))
        finally:
            release.set()
            thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
