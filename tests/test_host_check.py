import unittest

from host_check import Finding, parse_ss_listeners, parse_sshd_settings, parse_windows_firewall_states, render_text


class HostCheckTests(unittest.TestCase):
    def test_listener_parser_counts_wildcards(self):
        sample = "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\ntcp LISTEN 0 128 127.0.0.1:9000 0.0.0.0:*"
        self.assertEqual(parse_ss_listeners(sample), (2, 1))

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
