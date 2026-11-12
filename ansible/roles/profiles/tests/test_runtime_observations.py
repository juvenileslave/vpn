"""Observation-parser regression tests, not real route/runtime acceptance."""
import unittest

from runtime_vm import captured_streams, established_pair


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


if __name__ == "__main__":
    unittest.main()
