from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import List

from .ai import AnalysisResult, OllamaClient
from .config import Config
from .heuristics import analyze_failed_access_bursts
from .log_reader import format_log_batch, read_new_logs
from .notifier import NotificationResult, Notifier
from .severity import Severity, max_severity
from .state import State


LOGGER = logging.getLogger(__name__)


@dataclass
class RunResult:
    checked_files: List[str]
    severity: Severity
    notified: bool
    notification_results: List[NotificationResult]


def run_once(config: Config) -> RunResult:
    state = State.load(config.state_file)
    logs = read_new_logs(config.log_dir, config.log_files, state, start_at_end=config.start_at_end)

    if not logs:
        state.save(config.state_file)
        LOGGER.info("No new log entries.")
        return RunResult([], Severity.NONE, False, [])

    client = OllamaClient(config.ollama_url, config.ollama_model, config.ollama_timeout_seconds)
    analyses: List[AnalysisResult] = []
    for source_name, chunk in format_log_batch(logs, config.chunk_max_lines):
        LOGGER.info("Analyzing %s (%d chars)", source_name, len(chunk))
        analyses.append(client.analyze(source_name, chunk))
    analyses.append(analyze_failed_access_bursts(logs))

    merged = merge_results(analyses)
    LOGGER.info("AI severity: %s", merged.severity.value)
    if not merged.severity.should_notify:
        state.save(config.state_file)
        return RunResult(sorted(logs.keys()), merged.severity, False, [])

    notification_results = Notifier(config).notify(merged, sorted(logs.keys()))
    for item in notification_results:
        if item.ok:
            LOGGER.info("Notification sent via %s %s", item.channel, item.detail)
        else:
            LOGGER.error("Notification failed via %s: %s", item.channel, item.detail)

    if not notification_results or any(item.ok for item in notification_results):
        state.save(config.state_file)
    else:
        LOGGER.error("All notification channels failed; keeping log offsets for retry.")

    return RunResult(
        sorted(logs.keys()),
        merged.severity,
        any(item.ok for item in notification_results),
        notification_results,
    )


def run_forever(config: Config) -> None:
    LOGGER.info("Starting watchlog-ai. interval=%ss log_dir=%s", config.check_interval_seconds, config.log_dir)
    while True:
        try:
            run_once(config)
        except Exception:
            LOGGER.exception("watchlog-ai cycle failed")
        time.sleep(config.check_interval_seconds)


def merge_results(results: List[AnalysisResult]) -> AnalysisResult:
    severity = max_severity(*(result.severity for result in results))
    incidents = [incident for result in results for incident in result.incidents]
    summaries = [result.summary for result in results if result.summary]
    return AnalysisResult(
        severity=severity,
        summary=" / ".join(summaries[:5]) or "新規ログを確認しました。",
        incidents=incidents,
    )
