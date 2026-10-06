import json
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from watchlog_ai.ai import AnalysisResult, Incident, OllamaError
from watchlog_ai.config import Config
from watchlog_ai.daily_report import DailyReport, JST, MAX_SAMPLES, MAX_SOURCE_IPS, extract_source_ips, next_report_at, render_daily_report
from watchlog_ai.notifier import NotificationResult
from watchlog_ai.runner import run_forever, run_once
from watchlog_ai.severity import Severity
from watchlog_ai.state import State


def at(value):
    return datetime.fromisoformat(value).replace(tzinfo=JST).timestamp()


class DailyReportTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = replace(
            Config.from_env(self.root / "missing.env"), log_dir=self.root,
            log_files=["rejected-access.log", "access.log"], state_file=self.root / "state.json",
            start_at_end=False, slack_webhook_url="https://example.invalid/slack",
            raspi_webhook_url=None, email_enabled=False, dry_run=False,
        )
        self.now = self.enterContext(patch("watchlog_ai.runner.time.time", return_value=at("2026-09-11T08:00")))
        self.post = self.enterContext(patch("watchlog_ai.notifier._post_json", return_value=NotificationResult("slack", True)))
        self.analyze = self.enterContext(patch("watchlog_ai.runner.OllamaClient.analyze", side_effect=self.analysis))

    @staticmethod
    def analysis(source, chunk):
        return AnalysisResult(Severity.HIGH, source + " summary", [Incident(Severity.HIGH, source, source + " detail")])

    def append(self, name="rejected-access.log"):
        with (self.root / name).open("a") as handle:
            handle.write("probe\n")

    def pending(self):
        return State.load(self.config.state_file).daily_report

    def test_small_is_persisted_without_slack_and_offsets_advance(self):
        self.append()
        outcome = run_once(self.config)
        self.assertFalse(outcome.notified)
        self.post.assert_not_called()
        self.assertEqual(self.pending().count, 1)
        run_once(self.config)
        self.assertEqual(self.pending().count, 1)
        self.assertEqual(self.analyze.call_count, 1)

    def test_nine_am_sends_once_even_without_new_logs_after_restart(self):
        self.append()
        run_once(self.config)
        self.now.return_value = at("2026-09-11T08:59:59")
        run_once(self.config)
        self.post.assert_not_called()
        self.now.return_value = at("2026-09-11T09:00")
        outcome = run_once(self.config)
        self.assertTrue(outcome.notified)
        self.assertEqual(self.post.call_count, 1)
        self.assertIn("日次報告", self.post.call_args.args[2]["text"])
        self.assertIsNone(self.pending())
        self.append()
        run_once(self.config)
        self.assertEqual(self.pending().due_at, at("2026-09-12T09:00"))
        run_once(self.config)
        self.assertEqual(self.post.call_count, 1)
        self.now.return_value = at("2026-09-12T09:00")
        run_once(self.config)
        self.assertEqual(self.post.call_count, 2)

    def test_source_ips_survive_restart_and_appear_in_nine_am_report(self):
        self.config = replace(self.config, chunk_max_lines=1)
        (self.root / "rejected-access.log").write_text(
            '198.51.100.10 - - [11/Sep/2026:08:00:00 +0900] "GET /.env HTTP/1.1" 444 0\n'
            '2001:db8::1 - - [11/Sep/2026:08:00:01 +0900] "GET /.git HTTP/1.1" 444 0\n'
        )
        run_once(self.config)
        samples = self.pending().samples
        self.assertEqual(samples[0]["source_ips"], ["198.51.100.10"])
        self.assertEqual(samples[1]["source_ips"], ["2001:db8::1"])
        self.assertEqual(samples[1]["sources"], ["rejected-access.log part 2"])
        self.now.return_value = at("2026-09-11T09:00")
        run_once(self.config)
        message = self.post.call_args.args[2]["text"]
        self.assertIn("アクセス元IP（解析対象ログ内）: 198.51.100.10", message)
        self.assertIn("アクセス元IP（解析対象ログ内）: 2001:db8::1", message)
        self.assertIsNone(self.pending())

    def test_mixed_severities_keep_log_client_ips_in_daily_report(self):
        self.analyze.side_effect = None
        self.analyze.return_value = AnalysisResult(Severity.MEDIUM, "攻撃", [
            Incident(Severity.MEDIUM, "攻撃", "要確認"), Incident(Severity.LOW, "探索", "低い危険度")])
        (self.root / "access.log").write_text(
            '[2026-09-11 08:00:00] INFO in views: 198.51.100.10 - GET /.env 404\n'
        )
        run_once(self.config)
        self.assertEqual(self.pending().samples[0]["source_ips"], ["198.51.100.10"])

    def test_blocked_burst_client_ips_are_saved_when_ai_reports_none(self):
        self.analyze.side_effect = None
        self.analyze.return_value = AnalysisResult(Severity.NONE, "正常")
        (self.root / "rejected-access.log").write_text(
            '198.51.100.10 - - [11/Sep/2026:08:00:00 +0900] "GET /.env HTTP/1.1" 444 0\n' * 10
        )
        run_once(self.config)
        self.assertEqual(self.pending().count, 1)
        self.assertEqual(self.pending().samples[0]["source_ips"], ["198.51.100.10"])

    def test_first_detection_after_nine_waits_until_next_day(self):
        self.now.return_value = at("2026-09-11T10:00")
        self.append()
        run_once(self.config)
        run_once(self.config)
        self.post.assert_not_called()
        self.assertEqual(self.pending().due_at, at("2026-09-12T09:00"))

    def test_empty_day_has_no_report(self):
        self.now.return_value = at("2026-09-11T09:00")
        run_once(self.config)
        self.post.assert_not_called()

    def test_mixed_high_and_small_only_posts_high_immediately(self):
        self.append()
        self.append("access.log")
        outcome = run_once(self.config)
        self.assertTrue(outcome.notified)
        message = self.post.call_args.args[2]["text"]
        self.assertIn("危険度 高", message)
        self.assertIn("access.log detail", message)
        self.assertNotIn("rejected-access.log detail", message)
        self.assertNotIn("[小]", message)
        self.assertEqual(self.pending().count, 1)

    def test_medium_is_immediate(self):
        self.analyze.side_effect = None
        self.analyze.return_value = AnalysisResult(Severity.MEDIUM, "攻撃")
        self.append("access.log")
        self.assertTrue(run_once(self.config).notified)
        self.assertIn("危険度 中", self.post.call_args.args[2]["text"])
        self.assertIn("攻撃元IP（検知根拠）: 不明（根拠にIP情報なし）", self.post.call_args.args[2]["text"])
        self.assertIsNone(self.pending())

    def test_medium_notification_keeps_client_ips_across_chunks_without_evidence(self):
        self.config = replace(self.config, chunk_max_lines=1)
        self.analyze.side_effect = lambda source, chunk: AnalysisResult(
            Severity.NONE if '"GET / HTTP' in chunk else Severity.MEDIUM, "判定")
        (self.root / "access.log").write_text(
            '198.51.100.10 - - [11/Sep/2026:08:00:00 +0900] "GET /.env HTTP/1.1" 404 0\n'
            '2001:db8::1 - - [11/Sep/2026:08:00:01 +0900] "GET /.git HTTP/1.1" 404 0\n'
            '198.51.100.10 - - [11/Sep/2026:08:00:02 +0900] "GET /.env HTTP/1.1" 404 0\n'
            '203.0.113.20 - - [11/Sep/2026:08:00:03 +0900] "GET / HTTP/1.1" 200 0\n'
        )
        self.assertTrue(run_once(self.config).notified)
        message = self.post.call_args.args[2]["text"]
        self.assertIn("アクセス元IP（解析対象ログ内）: 198.51.100.10, 2001:db8::1", message)
        self.assertEqual(message.count("198.51.100.10"), 1)
        self.assertNotIn("203.0.113.20", message)
        self.assertIn("攻撃元とは限りません", message)

    def test_immediate_notification_uses_attack_evidence_not_normal_or_low_clients(self):
        attack = '2001:db8::1 - - [11/Sep/2026:08:00:00 +0900] "GET /.env HTTP/1.1" 403 0'
        low = '198.51.100.20 - - [11/Sep/2026:08:00:01 +0900] "GET /wp-admin HTTP/1.1" 404 0'
        normal = '203.0.113.20 - - [11/Sep/2026:08:00:02 +0900] "GET / HTTP/1.1" 200 0'
        self.analyze.side_effect = None
        (self.root / "access.log").write_text("\n".join([attack, low, normal]) + "\n")
        for severity in (Severity.MEDIUM, Severity.HIGH):
            with self.subTest(severity=severity):
                self.analyze.return_value = AnalysisResult(severity, "攻撃", [
                    Incident(severity, "攻撃", "要確認", evidence=[attack]),
                    Incident(Severity.LOW, "探索", "低い危険度", evidence=[low]),
                ])
                with (self.root / "access.log").open("a") as handle:
                    handle.write(attack + "\n")
                self.assertTrue(run_once(self.config).notified)
                message = self.post.call_args.args[2]["text"]
                self.assertIn("攻撃元IP（検知根拠）: 2001:db8::1", message)
                self.assertNotIn("198.51.100.20", message)
                self.assertNotIn("203.0.113.20", message)

    def test_medium_burst_notification_includes_attacker_ip_when_ai_reports_none(self):
        self.analyze.side_effect = None
        self.analyze.return_value = AnalysisResult(Severity.NONE, "正常")
        (self.root / "access.log").write_text(
            '203.0.113.20 - - [11/Sep/2026:08:00:00 +0900] "GET / HTTP/1.1" 200 0\n'
            + '198.51.100.10 - - [11/Sep/2026:08:00:01 +0900] "GET /.env HTTP/1.1" 404 0\n' * 10
        )
        self.assertTrue(run_once(self.config).notified)
        message = self.post.call_args.args[2]["text"]
        self.assertIn("危険度 中", message)
        self.assertIn("攻撃元IP（検知根拠）: 198.51.100.10", message)
        self.assertNotIn("203.0.113.20", message)

    def test_normal_is_not_queued_and_low_is_daily(self):
        self.analyze.side_effect = None
        self.analyze.return_value = AnalysisResult(Severity.NONE, "正常")
        self.append("access.log")
        run_once(self.config)
        self.assertIsNone(self.pending())
        self.analyze.return_value = AnalysisResult(Severity.LOW, "探索")
        self.append("access.log")
        run_once(self.config)
        self.assertEqual(self.pending().count, 1)
        self.post.assert_not_called()

    def test_low_incident_with_medium_is_kept_for_daily_report(self):
        self.analyze.side_effect = None
        self.analyze.return_value = AnalysisResult(Severity.MEDIUM, "攻撃", [
            Incident(Severity.MEDIUM, "攻撃", "要確認"), Incident(Severity.LOW, "探索", "低い危険度")])
        self.append("access.log")
        run_once(self.config)
        self.assertNotIn("低い危険度", self.post.call_args.args[2]["text"])
        self.assertEqual(self.pending().samples[0]["summary"], "低い危険度")

    def test_daily_failure_keeps_report_and_new_entries_until_retry(self):
        self.append()
        run_once(self.config)
        self.now.return_value = at("2026-09-11T09:00")
        self.post.return_value = NotificationResult("slack", False, "HTTP 500")
        self.append()
        self.assertFalse(run_once(self.config).notified)
        self.assertEqual(self.pending().count, 2)
        self.assertIsNone(State.load(self.config.state_file).daily_report_sent_on)
        self.post.return_value = NotificationResult("slack", True)
        self.assertTrue(run_once(self.config).notified)
        self.assertIsNone(self.pending())
        self.assertIn("判定件数: 2件", self.post.call_args.args[2]["text"])

    def test_daily_success_does_not_commit_failed_immediate_offsets(self):
        self.append()
        run_once(self.config)
        self.now.return_value = at("2026-09-11T09:00")
        self.append("access.log")
        self.post.side_effect = [NotificationResult("slack", True), NotificationResult("slack", False)]
        run_once(self.config)
        self.assertIsNone(self.pending())
        self.assertNotIn(str(self.root / "access.log"), State.load(self.config.state_file).files)
        self.post.side_effect = None
        run_once(self.config)
        self.assertEqual(self.post.call_count, 3)
        self.assertEqual(State.load(self.config.state_file).files[str(self.root / "access.log")].offset, 6)

    def test_failed_mixed_notification_does_not_duplicate_pending_small(self):
        self.append()
        self.append("access.log")
        self.post.return_value = NotificationResult("slack", False)
        run_once(self.config)
        self.assertIsNone(self.pending())
        self.post.return_value = NotificationResult("slack", True)
        run_once(self.config)
        self.assertEqual(self.pending().count, 1)

    def test_ollama_outage_does_not_prevent_daily_delivery_or_restore_queue(self):
        self.append()
        run_once(self.config)
        self.now.return_value = at("2026-09-11T09:00")
        self.append()
        self.analyze.side_effect = OllamaError("unreachable")
        run_once(self.config)
        self.assertEqual(self.post.call_count, 2)
        self.assertIn("日次報告", self.post.call_args_list[0].args[2]["text"])
        self.assertIsNone(self.pending())
        self.assertEqual(State.load(self.config.state_file).files[str(self.root / "rejected-access.log")].offset, 6)

    def test_overdue_report_is_sent_on_restart(self):
        self.append()
        run_once(self.config)
        self.now.return_value = at("2026-09-13T10:00")
        run_once(self.config)
        run_once(self.config)
        self.assertEqual(self.post.call_count, 1)

    def test_other_channels_keep_small_immediate_notification(self):
        self.config = replace(self.config, raspi_webhook_url="https://example.invalid/raspi")
        self.append()
        run_once(self.config)
        self.assertEqual(self.post.call_count, 1)
        self.assertEqual(self.post.call_args.args[0], "raspi")
        self.assertEqual(self.pending().count, 1)

    def test_scheduler_wakes_at_nine_despite_twenty_minute_interval(self):
        self.config = replace(self.config, check_interval_seconds=1200)
        self.now.return_value = at("2026-09-11T08:55")
        with patch("watchlog_ai.runner.time.sleep", side_effect=InterruptedError) as sleep:
            with self.assertRaises(InterruptedError):
                run_forever(self.config)
        sleep.assert_called_once_with(300)

    def test_scheduler_does_not_retry_failed_daily_twice_in_one_cycle(self):
        self.append()
        run_once(self.config)
        self.now.return_value = at("2026-09-11T09:00")
        self.post.return_value = NotificationResult("slack", False)
        with patch("watchlog_ai.runner.time.sleep", side_effect=InterruptedError):
            with self.assertRaises(InterruptedError):
                run_forever(self.config)
        self.assertEqual(self.post.call_count, 1)
        self.assertEqual(self.pending().count, 1)

    def test_analysis_finishing_after_nine_flushes_daily_before_sleep(self):
        self.append()
        run_once(self.config)
        self.now.return_value = at("2026-09-11T08:59")
        self.append()

        def slow_analysis(source, chunk):
            self.now.return_value = at("2026-09-11T09:05")
            return self.analysis(source, chunk)

        self.analyze.side_effect = slow_analysis
        with patch("watchlog_ai.runner.time.sleep", side_effect=InterruptedError):
            with self.assertRaises(InterruptedError):
                run_forever(self.config)
        self.assertEqual(self.post.call_count, 1)
        self.assertIsNone(self.pending())


class DailyReportStorageTest(unittest.TestCase):
    def test_schedule_uses_japan_time(self):
        utc = datetime(2026, 9, 10, 23, 59, tzinfo=timezone.utc).timestamp()
        self.assertEqual(next_report_at(utc), at("2026-09-11T09:00"))
        self.assertEqual(next_report_at(at("2026-09-11T09:00")), at("2026-09-12T09:00"))

    def test_bounded_samples_still_count_all_detections(self):
        report = DailyReport(0, 0, 0)
        for i in range(MAX_SAMPLES + 5):
            report.add(AnalysisResult(Severity.LOW, f"探索{i}"), i)
        report.add(AnalysisResult(Severity.LOW, "探索0"), 30)
        self.assertEqual(report.count, MAX_SAMPLES + 6)
        self.assertEqual(len(report.samples), MAX_SAMPLES)
        self.assertEqual(report.samples[0]["count"], 2)
        self.assertIn("その他: 5件", render_daily_report(report))

    def test_source_ips_merge_without_duplicates_and_are_bounded(self):
        report = DailyReport(0, 0, 0)
        report.add(AnalysisResult(Severity.LOW, "探索", source_ips=["198.51.100.1"]), 1)
        report.add(AnalysisResult(Severity.LOW, "探索", source_ips=["198.51.100.1", "2001:db8::1"]), 2)
        self.assertEqual(report.samples[0]["source_ips"], ["198.51.100.1", "2001:db8::1"])
        self.assertFalse(report.samples[0]["source_ips_truncated"])
        report.add(AnalysisResult(Severity.LOW, "探索", source_ips=[
            f"198.51.100.{i}" for i in range(2, MAX_SOURCE_IPS + 2)]), 3)
        report.add(AnalysisResult(Severity.LOW, "探索", source_ips=["198.51.100.1"]), 4)
        self.assertEqual(report.samples[0]["count"], 4)
        self.assertEqual(len(report.samples[0]["source_ips"]), MAX_SOURCE_IPS)
        self.assertTrue(report.samples[0]["source_ips_truncated"])
        self.assertIn("ほか（最大20件まで表示）", render_daily_report(report))

    def test_old_pending_samples_without_ips_load_render_and_merge(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "state.json"
            path.write_text(json.dumps({"daily_report": {
                "due_at": 10, "first_at": 1, "last_at": 1, "count": 1,
                "samples": [{"summary": "探索", "sources": [], "count": 1}],
            }}))
            state = State.load(path)
            self.assertIn("不明（IP情報なし）", render_daily_report(state.daily_report))
            clone = state.clone()
            clone.daily_report.add(AnalysisResult(Severity.LOW, "探索", source_ips=["2001:db8::1"]), 2)
            self.assertNotIn("source_ips", state.daily_report.samples[0])
            clone.save(path)
            loaded = State.load(path).daily_report
            self.assertEqual(loaded.samples[0]["count"], 2)
            self.assertIn("アクセス元IP（解析対象ログ内）: 2001:db8::1", render_daily_report(loaded))

    def test_old_state_loads_and_clone_does_not_mutate_pending_report(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "state.json"
            path.write_text('{"files": {"access.log": {"inode": 42, "offset": 50}}}')
            state = State.load(path)
            self.assertIsNone(state.daily_report)
            state.daily_report = DailyReport(10, 1, 1)
            state.daily_report.add(AnalysisResult(Severity.LOW, "探索"), 1)
            state.daily_report_sent_on = "2026-09-10"
            state.save(path)
            clone = State.load(path).clone()
            clone.daily_report.add(AnalysisResult(Severity.LOW, "探索"), 2)
            self.assertEqual(state.daily_report.count, 1)
            self.assertEqual(state.daily_report.samples[0]["count"], 1)
            self.assertEqual(clone.daily_report.count, 2)
            self.assertEqual(clone.daily_report_sent_on, state.daily_report_sent_on)
            self.assertEqual(clone.files["access.log"].offset, 50)


class SourceIPExtractionTest(unittest.TestCase):
    def test_access_app_and_error_client_fields_with_ipv4_and_ipv6(self):
        logs = '\n'.join([
            '198.51.100.10 - - [11/Sep/2026:08:00:00 +0900] "GET / HTTP/1.1" 200 0',
            '2001:0db8:0:0:0:0:0:1 - - [11/Sep/2026:08:00:00 +0900] "GET / HTTP/2.0" 200 0',
            '[2026-09-11 08:00:00] INFO in views: 198.51.100.20 - GET /login 404',
            '[2026-09-11 08:00:00] INFO in views: ::1 - POST /login 403',
            '2026/09/11 08:00:00 [error] 123#123: *1 failed, client: 2001:db8::2, server: example.test',
            '2026/09/11 08:00:00 [error] 123#123: *1 failed, client: 198.51.100.30, server: example.test',
            '2001:db8::1 - - [11/Sep/2026:08:00:00 +0900] "GET / HTTP/1.1" 200 0',
        ])
        self.assertEqual(extract_source_ips(logs), [
            "198.51.100.10", "2001:db8::1", "198.51.100.20", "::1", "2001:db8::2", "198.51.100.30"])

    def test_invalid_ips_and_non_client_fields_are_ignored(self):
        logs = '\n'.join([
            '999.51.100.10 - - [11/Sep/2026:08:00:00 +0900] "GET / HTTP/1.1" 444 0',
            '198.51.100.10 - - [11/Sep/2026:08:00:00 +0900] "GET /203.0.113.1 HTTP/1.1" 444 0 "-" "203.0.113.2"',
            '2026/09/11 08:00:00 [error] failed, client: 2001:db8::2, upstream: "http://127.0.0.1:8000/"',
            'Connection failed to upstream 203.0.113.3',
            'probe',
        ])
        self.assertEqual(extract_source_ips(logs), ["198.51.100.10", "2001:db8::2"])


if __name__ == "__main__":
    unittest.main()
