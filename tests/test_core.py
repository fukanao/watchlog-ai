from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from watchlog_ai.ai import AnalysisResult, Incident, format_analysis_for_debug, parse_analysis
from watchlog_ai.heuristics import analyze_failed_access_bursts
from watchlog_ai.log_reader import read_new_logs
from watchlog_ai.notifier import render_message, render_ollama_unreachable_message
from watchlog_ai.runner import merge_results
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

    def test_render_message_keeps_incident_details_readable(self) -> None:
        result = AnalysisResult(
            Severity.LOW,
            "GeoServer 管理画面へのスキャンが検出された",
            [
                Incident(
                    Severity.LOW,
                    "GeoServer 管理画面探索",
                    "/geoserver/web/ へのアクセスが404で返されました。",
                    ["line1", "line2"],
                    ["対応1", "対応2"],
                )
            ],
        )

        message = render_message(result, ["access.log", "error.log"])

        self.assertIn("- [低] GeoServer 管理画面探索: /geoserver/web/ へのアクセスが404で返されました。", message)
        self.assertEqual(message.count("根拠:"), 2)
        self.assertEqual(message.count("対応:"), 2)


class ResultMergeTest(unittest.TestCase):
    def test_merge_results_deduplicates_same_request_from_access_and_error_logs(self) -> None:
        access_incident = Incident(
            Severity.LOW,
            "GeoServer 管理画面探索",
            "/geoserver/web/ へのアクセスが 404 で返されました。",
            [
                '65.49.1.10 - - [04/Jun/2026:09:43:16 +0900] "GET /geoserver/web/ HTTP/1.1" 404 207 "-" "Mozilla/5.0"'
            ],
            ["該当 IP アドレスをファイアウォールでブロックまたはレートリミットを設定する"],
        )
        error_incident = Incident(
            Severity.LOW,
            "未知パスへのスキャン試行",
            "/geoserver/web/ へのアクセスが 404 で返され、単発であるためスキャンとみなす。",
            ["[2026-06-04 09:43:16,607] INFO in views: 65.49.1.10 - GET /geoserver/web/? 404"],
            ["該当IPからの同様アクセスが増加した場合はブロックを検討"],
        )

        merged = merge_results(
            [
                AnalysisResult(Severity.LOW, "GeoServer 管理画面へのスキャンが検出された", [access_incident]),
                AnalysisResult(Severity.LOW, "不審なパスへの単発アクセスを検出", [error_incident]),
                AnalysisResult(Severity.NONE, "連続した不正アクセス失敗は検出されませんでした。", []),
            ]
        )

        self.assertEqual(len(merged.incidents), 1)
        self.assertEqual(len(merged.incidents[0].evidence), 2)
        self.assertEqual(len(merged.incidents[0].recommended_actions), 2)
        self.assertIn("同一内容の検知を2件にまとめています。", merged.incidents[0].summary)
        self.assertEqual(merged.summary, "GeoServer 管理画面へのスキャンが検出された")


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
