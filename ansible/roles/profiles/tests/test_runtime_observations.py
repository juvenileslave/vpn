"""Parser and CLI safety regressions, not live route/runtime acceptance."""
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest

from runtime_vm import captured_streams, established_pair, http_observation


class RuntimeObservationParserTest(unittest.TestCase):
    def test_failed_syn_and_ack_cannot_count_application_payload(self):
        decoded = b"1.0 IP6 2001:db8:47::20.31000 > 2001:db8:47::10.18444: Flags [S], seq 100, win 100, length 0\n2.0 IP6 2001:db8:47::10.18444 > 2001:db8:47::20.31000: Flags [.], ack 100, length 0\n"
        self.assertEqual(captured_streams(decoded), {})

    def test_retransmitted_and_any_interface_duplicates_count_once(self):
        line = b"1.0 IP 192.0.2.20.31000 > 192.0.2.10.18444: Flags [P.], seq 100:200, ack 5, length 100\n"
        overlap = b"2.0 IP 192.0.2.20.31000 > 192.0.2.10.18444: Flags [P.], seq 150:250, ack 5, length 100\n"
        self.assertEqual(captured_streams(line + line + overlap), {("192.0.2.20.31000", "192.0.2.10.18444"): 150})

    def test_tiny_probe_does_not_qualify_as_megabyte_application(self):
        decoded = b"1.0 IP6 2001:db8:47::20.31000 > 2001:db8:47::10.18444: Flags [P.], seq 100:164, ack 5, length 64\n"
        counts = captured_streams(decoded)
        self.assertLess(sum(counts.values()), 65536)
        self.assertLess(sum(counts.values()), 1048576)

    def test_established_socket_requires_exact_bidirectional_peers(self):
        samples = [b"0 0 [2001:db8:47::20]:31000 [2001:db8:47::10]:18444\n"]
        self.assertTrue(established_pair(samples, "2001:db8:47::20.31000", "2001:db8:47::10.18444"))
        self.assertFalse(established_pair(samples, "2001:db8:47::20.31001", "2001:db8:47::10.18444"))
        self.assertFalse(established_pair(samples, "2001:db8:47::20.31000", "2001:db8:47::10.1844"))


class RuntimeVisitorRepresentationTest(unittest.TestCase):
    def test_head_keeps_get_representation_headers_without_body(self):
        headers = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 5\r\nETag: \"fixture\"\r\nDate: ignored\r\n\r\n"
        get = http_observation(headers + b"hello", "GET", "TLSv1.3")
        head = http_observation(headers, "HEAD", "TLSv1.3")
        self.assertEqual(head["status"], get["status"])
        self.assertEqual(head["headers"], get["headers"])
        self.assertEqual(head["headers"]["content-length"], ["5"])
        self.assertEqual(head["body_bytes"], 0)
        self.assertNotEqual(head["body_sha256"], get["body_sha256"])
        with self.assertRaises(AssertionError):
            http_observation(headers + b"hello", "HEAD", "TLSv1.3")

    def test_real_error_status_and_http2_representation_are_retained(self):
        response = b"HTTP/2 404\r\ncontent-type: text/html\r\ncontent-length: 7\r\n\r\nmissing"
        observed = http_observation(response, "GET", "TLSv1.2")
        self.assertEqual(observed["status"], 404)
        self.assertEqual(observed["HTTP"], "2")
        self.assertEqual(observed["TLS"], "TLSv1.2")
        self.assertEqual(observed["body_bytes"], 7)


class RuntimeChildRefusalTest(unittest.TestCase):
    def test_unauthorized_cli_cannot_read_private_input_or_touch_network(self):
        required = {"VPN_PROFILES_DISPOSABLE_GUEST": "yes", "GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted"}
        with tempfile.TemporaryDirectory(prefix="profile-refusal-") as temporary, socket.socket() as listener:
            private_input = Path(temporary) / "unread.private.fifo"
            # An attempted private read blocks forever without a writer. The
            # real CLI must instead refuse immediately, before importing Node
            # lifecycle contracts, opening the FIFO or making a connection.
            os.mkfifo(private_input, 0o600)
            listener.bind(("127.0.0.1", 0))
            listener.listen(16)
            listener.settimeout(.05)
            port = str(listener.getsockname()[1])
            operations = [
                [],
                ["node-start", str(private_input)],
                ["node-health", str(private_input)],
                ["tcp-listen", "127.0.0.1", port],
                ["connect-proxy", "127.0.0.1", port],
                ["ssh-banner", "127.0.0.1"],
                ["tcp", "127.0.0.1", port],
                ["visitor", "127.0.0.1", port, str(private_input)],
                ["malformed", "127.0.0.1", port, str(private_input), "1"],
            ]
            script = Path(__file__).with_name("runtime_vm.py")
            for missing in required:
                environment = {**os.environ, **required}
                environment.pop(missing, None)
                for operation in operations:
                    with self.subTest(missing=missing, operation=operation[:1]):
                        result = subprocess.run([sys.executable, str(script), *operation], env=environment, capture_output=True, timeout=10, check=False)
                        # Exit 2 is the CLI identity refusal, not an unrelated
                        # missing-contract/invalid-input/runtime failure (1).
                        self.assertEqual(result.returncode, 2)
                        self.assertEqual(result.stdout, b"")
                        with self.assertRaises(TimeoutError):
                            connection, _peer = listener.accept()
                            connection.close()



if __name__ == "__main__":
    unittest.main()
