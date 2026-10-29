import tempfile
import unittest
from pathlib import Path

from host_check import Finding, parse_ss_listeners, parse_sshd_settings, parse_windows_firewall_states, read_sshd_includes, render_text


class HostCheckTests(unittest.TestCase):
    def test_listener_parser_counts_wildcards(self):
        sample = "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\ntcp LISTEN 0 128 127.0.0.1:9000 0.0.0.0:*"
        self.assertEqual(parse_ss_listeners(sample), (2, 1))

    def test_sshd_parser_ignores_comments_and_match_blocks(self):
        parsed = parse_sshd_settings("# comment\nPermitRootLogin no\nMatch User deploy\nPasswordAuthentication yes")
        self.assertEqual(parsed, {"permitrootlogin": "no"})

    def test_sshd_parser_accepts_equals_and_tabs(self):
        parsed = parse_sshd_settings("PermitRootLogin=yes\nPasswordAuthentication\tno")
        self.assertEqual(parsed, {"permitrootlogin": "yes", "passwordauthentication": "no"})

    def test_sshd_parser_applies_includes_first_value_wins(self):
        included = {"/etc/ssh/sshd_config.d/*.conf": ["PasswordAuthentication yes\nMatch User deploy\nPermitRootLogin yes"]}
        parsed = parse_sshd_settings(
            "Include /etc/ssh/sshd_config.d/*.conf\nPasswordAuthentication no\nPermitRootLogin no",
            lambda patterns: included.get(patterns, []),
        )
        self.assertEqual(parsed, {"passwordauthentication": "yes"})

    def test_sshd_includes_resolve_relative_globs_in_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "sshd_config.d").mkdir()
            (base / "sshd_config.d" / "50-cloud-init.conf").write_text("PasswordAuthentication yes\n", encoding="utf-8")
            (base / "sshd_config.d" / "10-hardening.conf").write_text("PasswordAuthentication no\n", encoding="utf-8")
            (base / "sshd_config.d" / "notes.txt").write_text("PermitRootLogin yes\n", encoding="utf-8")
            texts = read_sshd_includes("sshd_config.d/*.conf", base)
        self.assertEqual(texts, ["PasswordAuthentication no\n", "PasswordAuthentication yes\n"])


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
