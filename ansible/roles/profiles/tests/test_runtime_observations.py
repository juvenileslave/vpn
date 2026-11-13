"""Parser and CLI safety regressions, not live route/runtime acceptance."""
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest

from runtime_vm import captured_streams, core_observation, established_pair, http_observation


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

    def test_mapped_ipv4_socket_is_the_same_wire_peer_not_another_port_or_family(self):
        samples = [b"0 0 [::ffff:192.0.2.20]:33252 [::ffff:192.0.2.10]:18444\n"]
        self.assertTrue(established_pair(samples, "192.0.2.20.33252", "192.0.2.10.18444"))
        self.assertFalse(established_pair(samples, "192.0.2.20.33253", "192.0.2.10.18444"))
        self.assertFalse(established_pair(samples, "192.0.2.20.33252", "192.0.2.11.18444"))
        self.assertFalse(established_pair(samples, "2001:db8:47::20.33252", "2001:db8:47::10.18444"))

    def test_core_route_retains_actual_transit_tag_without_inferring_wire_family(self):
        logs = b"2026/11/13 19:00:00.000001 from tcp:192.0.2.20:31000 accepted tcp:192.0.2.100:18080 [transit-v4 -> egress-0] email: egress-0\n"
        observed = core_observation(logs, ("transit-v4", "transit-v6"), "egress-0")
        self.assertTrue(observed["valid"])
        self.assertEqual(observed["accepted_application_routes"], [{"inbound": "transit-v4", "outbound": "egress-0"}])

    def test_core_route_rejects_unrelated_or_rejected_application_observations(self):
        for status, target, detour in (
            ("rejected", "192.0.2.100:18080", "transit-v4 -> egress-0"),
            ("accepted", "192.0.2.100:18081", "transit-v4 -> egress-0"),
            ("accepted", "192.0.2.100:180800", "transit-v4 -> egress-0"),
            ("accepted", "192.0.2.101:18080", "transit-v4 -> egress-0"),
            ("accepted", "192.0.2.100:18080", "direct-v4 -> egress-0"),
            ("accepted", "192.0.2.100:18080", "transit-v4 -> egress-1"),
        ):
            with self.subTest(status=status, target=target, detour=detour):
                logs = ("from tcp:192.0.2.20:31000 " + status + " tcp:" + target + " [" + detour + "]\n").encode()
                self.assertFalse(core_observation(logs, ("transit-v4", "transit-v6"), "egress-0")["valid"])
        logs = b"from tcp:192.0.2.30:31000 accepted tcp:192.0.2.100:18080 [slot-1-v4 -> slot-1-v6]\n"
        self.assertFalse(core_observation(logs, ("slot-0-v4",), "slot-0-v6")["valid"])

    def test_correct_route_cannot_hide_an_additional_direct_leak(self):
        logs = b"from tcp:192.0.2.20:31000 accepted tcp:192.0.2.100:18080 [transit-v4 -> egress-0]\nfrom tcp:192.0.2.30:31001 accepted tcp:192.0.2.100:18080 [direct-v4 -> egress-0]\n"
        observed = core_observation(logs, ("transit-v4", "transit-v6"), "egress-0")
        self.assertFalse(observed["valid"])
        self.assertEqual(observed["application_flow_observations"], 2)

    def test_unknown_route_is_counted_but_not_published(self):
        logs = b"from tcp:192.0.2.20:31000 accepted tcp:192.0.2.100:18080 [private-route-canary -> egress-0] reason: [transit-v4 -> egress-0]\n"
        observed = core_observation(logs, ("transit-v4", "transit-v6"), "egress-0")
        self.assertFalse(observed["valid"])
        self.assertEqual(observed["application_flow_observations"], 1)
        self.assertEqual(observed["accepted_application_routes"], [{"inbound": None, "outbound": None}])


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
                ["replay-hello", "127.0.0.1", port, str(private_input)],
                ["cleanup-smoke"],
            ]
            scripts = (
                (Path(__file__).with_name("runtime_vm.py"), operations),
                (Path(__file__).with_name("traffic.py"), [["serve"], ["load", port], ["transfer", port, "1"]]),
            )
            for missing in required:
                environment = {**os.environ, **required}
                environment.pop(missing, None)
                for script, script_operations in scripts:
                    for operation in script_operations:
                        with self.subTest(missing=missing, script=script.name, operation=operation[:1]):
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
