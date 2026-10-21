import unittest

from host_check import (
    Finding,
    parse_netstat_listeners,
    parse_ss_listeners,
    parse_sshd_settings,
    parse_windows_firewall_states,
    parse_windows_listen_addresses,
    render_text,
)


class HostCheckTests(unittest.TestCase):
    def test_listener_parser_counts_wildcards(self):
        sample = "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\ntcp LISTEN 0 128 127.0.0.1:9000 0.0.0.0:*"
        self.assertEqual(parse_ss_listeners(sample), (2, 1))

    def test_windows_listen_addresses_count_wildcards(self):
        sample = "::\n0.0.0.0\n127.0.0.1\n::1\n192.168.1.10\n"
        self.assertEqual(parse_windows_listen_addresses(sample), (5, 2))

    def test_netstat_parser_counts_wildcards(self):
        sample = (
            "  Proto  Local Address          Foreign Address        State           PID\n"
            "  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1332\n"
            "  TCP    127.0.0.1:9000         0.0.0.0:0              LISTENING       4\n"
            "  TCP    [::]:445               [::]:0                 LISTENING       4\n"
            "  TCP    192.168.1.10:50000     10.0.0.1:443           ESTABLISHED     900\n"
        )
        self.assertEqual(parse_netstat_listeners(sample), (3, 2))

    def test_sshd_parser_ignores_comments_and_match_blocks(self):
        parsed = parse_sshd_settings("# comment\nPermitRootLogin no\nMatch User deploy\nPasswordAuthentication yes")
        self.assertEqual(parsed, {"permitrootlogin": "no"})

    def test_localized_windows_firewall_states(self):
        sample = "State ON\nEstado Ligado\nEstado Desligado\n"
        self.assertEqual(parse_windows_firewall_states(sample), [True, True, False])

    def test_text_report_contains_summary(self):
        report = {
            "platform": {"system": "Test", "release": "1", "architecture": "x"},
            "findings": [Finding("firewall", "pass", "active", "").__dict__],
            "summary": {"pass": 1, "warn": 0, "fail": 0, "unknown": 0},
        }
        self.assertIn("1 passed", render_text(report))


if __name__ == "__main__":
    unittest.main()
