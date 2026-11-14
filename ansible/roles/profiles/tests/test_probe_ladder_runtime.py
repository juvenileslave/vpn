"""Consumer payload/guard regressions only; real authorization belongs to CI."""
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import unittest

from probe_ladder_runtime import AUTH_BYTES, SMALL_BYTES, LARGE_BYTES, PATTERN, payload_digest


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


if __name__ == "__main__":
    unittest.main()
