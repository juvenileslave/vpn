"""Unit checks for the panel_proxy TLS bootstrap; no host or network access."""

import datetime
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "files" / "panel_proxy_tls.py"
spec = importlib.util.spec_from_file_location("panel_proxy_tls", SCRIPT)
tls = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tls)

UTC = datetime.timezone.utc


class RenewalDecisionTests(unittest.TestCase):
    def test_renewal_window_boundaries(self):
        now = datetime.datetime(2026, 11, 16, tzinfo=UTC)
        self.assertTrue(tls.needs_renewal(now, now, 30))
        self.assertTrue(tls.needs_renewal(now + datetime.timedelta(days=29), now, 30))
        self.assertTrue(tls.needs_renewal(now + datetime.timedelta(days=30), now, 30))
        self.assertFalse(tls.needs_renewal(now + datetime.timedelta(days=31), now, 30))

    def test_enddate_is_parsed(self):
        parsed = tls.parse_enddate("notAfter=Nov 16 12:00:00 2027 GMT")
        self.assertEqual(parsed, datetime.datetime(2027, 11, 16, 12, 0, 0, tzinfo=UTC))

    def test_enddate_without_field_is_rejected(self):
        with self.assertRaises(ValueError):
            tls.parse_enddate("no expiry here")

    def test_san_must_cover_the_requested_identity(self):
        text = "X509v3 Subject Alternative Name:\n    IP Address:127.0.0.1, DNS:localhost\n"
        self.assertTrue(tls.san_matches(text, ["127.0.0.1"], ["localhost"]))
        self.assertFalse(tls.san_matches(text, ["192.0.2.10"], ["localhost"]))
        self.assertFalse(tls.san_matches(text, ["127.0.0.1"], ["panel.invalid"]))


class BootstrapTests(unittest.TestCase):
    def run_script(self, directory, *extra):
        return subprocess.run(
            [sys.executable, str(SCRIPT), "--directory", str(directory), *extra],
            capture_output=True, text=True, check=True,
        )

    def test_first_run_issues_and_second_run_is_idempotent(self):
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            first = json.loads(self.run_script(directory, "--address", "127.0.0.1").stdout)
            self.assertTrue(first["changed"])
            self.assertTrue(first["ca_created"])
            self.assertTrue(first["certificate_issued"])

            second = json.loads(self.run_script(directory, "--address", "127.0.0.1").stdout)
            self.assertFalse(second["changed"])
            self.assertFalse(second["ca_created"])
            self.assertFalse(second["certificate_issued"])

    def test_certificate_is_loopback_only_and_key_is_private(self):
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            self.run_script(directory, "--address", "127.0.0.1", "--name", "localhost")
            certificate = directory / "server.pem"
            self.assertEqual(os.stat(directory / "server.key").st_mode & 0o777, 0o600)
            self.assertEqual(os.stat(directory / "ca.key").st_mode & 0o777, 0o600)
            self.assertIn("IP Address:127.0.0.1", tls.subject_alt_names(certificate))
            verify = subprocess.run(
                [tls.OPENSSL, "verify", "-purpose", "sslserver", "-verify_ip", "127.0.0.1",
                 "-CAfile", str(directory / "ca.pem"), str(certificate)],
                capture_output=True, text=True,
            )
            self.assertEqual(verify.returncode, 0, verify.stderr)

    def test_expired_certificate_is_reissued(self):
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            self.run_script(directory, "--address", "127.0.0.1")
            before = (directory / "server.pem").read_bytes()
            expiry = tls.not_after(directory / "server.pem")
            later = expiry + datetime.timedelta(days=1)
            renewed = json.loads(self.run_script(
                directory, "--address", "127.0.0.1", "--now", later.isoformat()).stdout)
            self.assertTrue(renewed["certificate_issued"])
            self.assertFalse(renewed["ca_created"])
            self.assertNotEqual((directory / "server.pem").read_bytes(), before)

    def test_identity_change_forces_reissue(self):
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            self.run_script(directory, "--address", "127.0.0.1")
            changed = json.loads(self.run_script(
                directory, "--address", "127.0.0.1", "--name", "panel.internal").stdout)
            self.assertTrue(changed["certificate_issued"])
            self.assertIn("DNS:panel.internal", tls.subject_alt_names(directory / "server.pem"))


if __name__ == "__main__":
    unittest.main()
