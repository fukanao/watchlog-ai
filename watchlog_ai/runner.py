from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Tuple

from .ai import AnalysisResult, Incident, OllamaClient, OllamaError
from .config import Config
from .heuristics import analyze_failed_access_bursts
from .log_reader import format_log_batch, read_new_logs
from .notifier import NotificationResult, Notifier
from .severity import Severity, max_severity
from .state import State


LOGGER = logging.getLogger(__name__)
OLLAMA_UNREACHABLE_NOTIFY_INTERVAL_SECONDS = 3600
_COMBINED_REQUEST_RE = re.compile(
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3}).*"
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+HTTP/[^"]+"\s+(?P<status>\d{3})'
)
_APP_REQUEST_RE = re.compile(
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+-\s+"
    r"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+(?P<status>\d{3})"
)


@dataclass
class RunResult:
    checked_files: List[str]
    severity: Severity
    notified: bool
    notification_results: List[NotificationResult]


def run_once(config: Config) -> RunResult:
    saved_state = State.load(config.state_file)
    state = saved_state.clone()
    logs = read_new_logs(config.log_dir, config.log_files, state, start_at_end=config.start_at_end)

    if not logs:
        state.save(config.state_file)
        LOGGER.info("No new log entries.")
        return RunResult([], Severity.NONE, False, [])

    client = OllamaClient(config.ollama_url, config.ollama_model, config.ollama_timeout_seconds)
    analyses: List[AnalysisResult] = []
    try:
        for source_name, chunk in format_log_batch(logs, config.chunk_max_lines):
            LOGGER.info("Analyzing %s (%d chars)", source_name, len(chunk))
            analyses.append(client.analyze(source_name, chunk))
    except OllamaError as exc:
        notification_results = _notify_ollama_unreachable(config, saved_state, exc)
        return RunResult(
            sorted(logs.keys()),
            Severity.NONE,
            any(item.ok for item in notification_results),
            notification_results,
        )
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
    incidents = _merge_incidents(incident for result in results for incident in result.incidents)
    summary = next(
        (
            result.summary
            for result in results
            if result.severity == severity and result.severity != Severity.NONE and result.summary
        ),
        "",
    )
    return AnalysisResult(
        severity=severity,
        summary=summary or "新規ログを確認しました。",
        incidents=incidents,
    )


def _merge_incidents(incidents: Iterable[Incident]) -> List[Incident]:
    merged: Dict[Tuple[str, ...], Incident] = {}
    counts: Dict[Tuple[str, ...], int] = {}
    for incident in incidents:
        signature = _incident_signature(incident)
        if signature not in merged:
            merged[signature] = Incident(
                severity=incident.severity,
                title=incident.title,
                summary=incident.summary,
                evidence=list(incident.evidence),
                recommended_actions=list(incident.recommended_actions),
            )
            counts[signature] = 1
            continue
        existing = merged[signature]
        counts[signature] += 1
        if incident.severity.score > existing.severity.score:
            existing.severity = incident.severity
        existing.evidence = _unique_limited([*existing.evidence, *incident.evidence], 5)
        existing.recommended_actions = _unique_limited(
            [*existing.recommended_actions, *incident.recommended_actions], 5
        )

    for signature, incident in merged.items():
        count = counts[signature]
        if count > 1:
            incident.summary = f"{incident.summary} 同一内容の検知を{count}件にまとめています。"
    return list(merged.values())


def _incident_signature(incident: Incident) -> Tuple[str, ...]:
    request_signature = _first_request_signature(incident.evidence)
    if request_signature:
        return ("request", *request_signature)
    return (
        "text",
        _normalize_text(incident.title),
        _normalize_text(incident.summary),
    )


def _first_request_signature(evidence: Iterable[str]) -> Optional[Tuple[str, ...]]:
    for item in evidence:
        match = _COMBINED_REQUEST_RE.search(item) or _APP_REQUEST_RE.search(item)
        if not match:
            continue
        path = match.group("path").split("?", 1)[0]
        return (match.group("ip"), match.group("method"), path, match.group("status"))
    return None


def _normalize_text(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip().lower())


def _unique_limited(values: Iterable[str], limit: int) -> List[str]:
    results: List[str] = []
    seen = set()
    for value in values:
        normalized = _normalize_text(value)
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        results.append(value)
        if len(results) >= limit:
            break
    return results


def _notify_ollama_unreachable(config: Config, state: State, exc: OllamaError) -> List[NotificationResult]:
    now = time.time()
    last_notified_at = state.ollama_unreachable_notified_at
    if last_notified_at is not None and now - last_notified_at < OLLAMA_UNREACHABLE_NOTIFY_INTERVAL_SECONDS:
        LOGGER.error("Ollama is unreachable; Slack notification suppressed by 1-hour throttle: %s", exc)
        return []

    LOGGER.error("Ollama is unreachable; sending Slack notification: %s", exc)
    notification_results = Notifier(config).notify_ollama_unreachable(str(exc))
    for item in notification_results:
        if item.ok:
            LOGGER.info("Ollama unreachable notification sent via %s %s", item.channel, item.detail)
        else:
            LOGGER.error("Ollama unreachable notification failed via %s: %s", item.channel, item.detail)

    if any(item.ok for item in notification_results):
        state.ollama_unreachable_notified_at = now
        state.save(config.state_file)
    elif not notification_results:
        LOGGER.error("Ollama is unreachable, but Slack webhook is not configured.")
    return notification_results
