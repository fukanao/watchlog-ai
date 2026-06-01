from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from watchlog_ai.ai import format_analysis_for_debug, parse_analysis
from watchlog_ai.heuristics import analyze_failed_access_bursts
from watchlog_ai.log_reader import read_new_logs
from watchlog_ai.notifier import render_ollama_unreachable_message
from watchlog_ai.severity import Severity
from watchlog_ai.state import State


class AnalysisParsingTest(unittest.TestCase):
    def test_parse_japanese_severity(self) -> None:
        result = parse_analysis(
            """
            {
              "severity": "中",
              "summary": "攻撃らしいアクセスを検知",
              "incidents": [{"severity": "中", "title": "/.git/config", "summary": "探索", "evidence": [], "recommended_actions": []}]
            }
            """
        )

        self.assertEqual(result.severity, Severity.MEDIUM)
        self.assertEqual(result.incidents[0].severity, Severity.MEDIUM)

    def test_medium_and_high_severity_are_notifiable(self) -> None:
        self.assertTrue(Severity.HIGH.should_notify)
        self.assertTrue(Severity.MEDIUM.should_notify)
        self.assertFalse(Severity.LOW.should_notify)
        self.assertFalse(Severity.NONE.should_notify)

    def test_debug_format_contains_readable_ai_result(self) -> None:
        result = parse_analysis(
            """
            {
              "severity": "low",
              "summary": "スキャン程度",
              "incidents": [{"severity": "low", "title": "/wp-admin", "summary": "探索", "evidence": ["404"], "recommended_actions": []}]
            }
            """
        )

        debug_text = format_analysis_for_debug("access.log", result)

        self.assertIn('"source":"access.log"', debug_text)
        self.assertIn('"severity":"low"', debug_text)
        self.assertIn("スキャン程度", debug_text)


class StatePersistenceTest(unittest.TestCase):
    def test_preserves_ollama_unreachable_notification_time(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            state_path = Path(temp) / "state.json"
            state = State(ollama_unreachable_notified_at=123.5)

            state.save(state_path)
            loaded = State.load(state_path)

            self.assertEqual(loaded.ollama_unreachable_notified_at, 123.5)


class NotifierMessageTest(unittest.TestCase):
    def test_ollama_unreachable_message_contains_slack_heading(self) -> None:
        message = render_ollama_unreachable_message("http://ollama:11434", "timed out")

        self.assertIn("https://ft-chat.znw.co.jp watchlog-ai: Ollamaサーバー不達", message)
        self.assertIn("接続先: http://ollama:11434", message)
        self.assertIn("エラー: timed out", message)


class LogReaderTest(unittest.TestCase):
    def test_reads_only_new_bytes_after_first_scan(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            log_dir = Path(temp)
            path = log_dir / "access.log"
            path.write_text("line1\n", encoding="utf-8")
            state = State()

            first = read_new_logs(log_dir, ["access.log"], state, start_at_end=False)
            self.assertEqual(first["access.log"], "line1\n")

            path.write_text("line1\nline2\n", encoding="utf-8")
            second = read_new_logs(log_dir, ["access.log"], state, start_at_end=False)
            self.assertEqual(second["access.log"], "line2\n")

    def test_start_at_end_skips_existing_content(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            log_dir = Path(temp)
            path = log_dir / "error.log"
            path.write_text("old\n", encoding="utf-8")
            state = State()

            first = read_new_logs(log_dir, ["error.log"], state, start_at_end=True)
            self.assertEqual(first, {})

            with path.open("a", encoding="utf-8") as handle:
                handle.write("new\n")
            second = read_new_logs(log_dir, ["error.log"], state, start_at_end=True)
            self.assertEqual(second["error.log"], "new\n")


class HeuristicsTest(unittest.TestCase):
    def test_ten_consecutive_failed_suspicious_accesses_are_medium(self) -> None:
        lines = [
            '198.51.100.10 - - [28/May/2026:15:00:%02d +0900] "GET /.git/config%d HTTP/1.1" 404 207 "-" "curl/8.0"'
            % (index, index)
            for index in range(10)
        ]

        result = analyze_failed_access_bursts({"access.log": "\n".join(lines)})

        self.assertEqual(result.severity, Severity.MEDIUM)
        self.assertEqual(len(result.incidents), 1)

    def test_nine_consecutive_failed_suspicious_accesses_are_not_escalated(self) -> None:
        lines = [
            '198.51.100.10 - - [28/May/2026:15:00:%02d +0900] "GET /.git/config%d HTTP/1.1" 404 207 "-" "curl/8.0"'
            % (index, index)
            for index in range(9)
        ]

        result = analyze_failed_access_bursts({"access.log": "\n".join(lines)})

        self.assertEqual(result.severity, Severity.NONE)


if __name__ == "__main__":
    unittest.main()
