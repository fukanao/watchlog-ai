import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from watchlog_ai.ai import AnalysisResult, Incident
from watchlog_ai.config import Config
from watchlog_ai.notifier import NotificationResult, Notifier, render_message
from watchlog_ai.runner import run_once
from watchlog_ai.severity import Severity


class RejectedAccessTest(unittest.TestCase):
    def run_case(self, rejected_severity, other_severity=None, text="probe\n", chunk_size=160):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            names = ["znw-support-ai-rejected-access.log"]
            if other_severity is not None:
                names.append("access.log")
            for name in names:
                (root / name).write_text(text)
            config = replace(Config.from_env(root / "missing.env"), log_dir=root,
                             log_files=names, state_file=root / "state.json",
                             start_at_end=False, chunk_max_lines=chunk_size,
                             slack_webhook_url="https://example.invalid/slack", raspi_webhook_url=None,
                             email_enabled=False, dry_run=False)

            def analyze(source, chunk):
                severity = other_severity if source == "access.log" else rejected_severity
                return AnalysisResult(severity, "検知", [Incident(severity, "探索", "同じ探索")])

            with patch("watchlog_ai.runner.OllamaClient.analyze", side_effect=analyze), patch(
                "watchlog_ai.notifier._post_json", return_value=NotificationResult("slack", True)
            ), patch("watchlog_ai.runner.Notifier.notify", wraps=Notifier(config).notify) as notify:
                outcome = run_once(config)
                result = notify.call_args.args[0] if notify.called else None
                return outcome, result

    def test_high_rejected_detection_is_small_without_immediate_slack(self):
        outcome, result = self.run_case(Severity.HIGH)
        self.assertFalse(outcome.notified)
        self.assertEqual(result.severity, Severity.LOW)
        self.assertEqual(result.incidents[0].severity, Severity.LOW)
        message = render_message(result, result.source_names)
        self.assertIn("危険度 小", message)
        self.assertIn("- [小]", message)
        self.assertIn("遮断済み", message)

    def test_other_high_is_preserved_and_not_merged_with_blocked_incident(self):
        _, result = self.run_case(Severity.HIGH, Severity.HIGH)
        self.assertEqual(result.severity, Severity.HIGH)
        self.assertEqual([item.severity for item in result.incidents], [Severity.LOW, Severity.HIGH])

    def test_normal_rejected_log_does_not_trigger_notification(self):
        outcome, _ = self.run_case(Severity.NONE, Severity.LOW)
        self.assertFalse(outcome.notified)

    def test_heuristic_escalation_is_capped_even_with_multiple_chunks(self):
        lines = '\n'.join(
            f'198.51.100.10 - - [05/Sep/2026:10:00:00 +0900] "GET /.git/config HTTP/1.1" 444 0'
            for _ in range(10)
        )
        outcome, result = self.run_case(Severity.NONE, text=lines, chunk_size=2)
        self.assertFalse(outcome.notified)
        self.assertEqual(result.severity, Severity.LOW)
        self.assertTrue(all(item.severity in (Severity.NONE, Severity.LOW) for item in result.incidents))

    def test_later_chunk_is_also_capped(self):
        _, result = self.run_case(Severity.MEDIUM, text="probe\nprobe\n", chunk_size=1)
        self.assertEqual(result.severity, Severity.LOW)
        self.assertTrue(all(item.severity == Severity.LOW for item in result.incidents))
