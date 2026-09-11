from __future__ import annotations

import json
import smtplib
import urllib.request
from dataclasses import dataclass
from datetime import datetime
from email.message import EmailMessage
from pathlib import Path
from typing import Dict, List, Optional

from .ai import AnalysisResult, Incident
from .config import Config
from .daily_report import DailyReport, render_daily_report
from .rejected_access import report_label, is_rejected_access


@dataclass
class NotificationResult:
    channel: str
    ok: bool
    detail: str = ""


class Notifier:
    def __init__(self, config: Config) -> None:
        self.config = config

    def notify(
        self, result: AnalysisResult, checked_files: List[str],
        *, slack_result: Optional[AnalysisResult] = None,
    ) -> List[NotificationResult]:
        title = f"[watchlog-ai] 危険度 {report_label(result.severity, result.source_names)}: chatログ警告"
        text = render_message(result, checked_files)
        payload = {
            "title": title,
            "severity": result.severity.value,
            "severity_label": report_label(result.severity, result.source_names),
            "checked_files": checked_files,
            "summary": result.summary,
            "incidents": [_incident_payload(incident) for incident in result.incidents],
        }

        slack_result = slack_result or result
        slack_text = render_message(slack_result, checked_files) if slack_result.severity.should_notify else None
        if self.config.dry_run:
            if not slack_text and not (self.config.raspi_webhook_url or self.config.email_enabled):
                return []
            print(slack_text or text)
            return [NotificationResult(channel="dry-run", ok=True)]

        results: List[NotificationResult] = []
        if self.config.slack_webhook_url and slack_text:
            results.append(_post_json("slack", self.config.slack_webhook_url, {"text": slack_text}))
        if self.config.raspi_webhook_url:
            results.append(_post_json("raspi", self.config.raspi_webhook_url, payload))
        if self.config.email_enabled:
            results.append(self._send_email(title, text))
        return results

    def notify_daily_report(self, report: DailyReport) -> List[NotificationResult]:
        text = render_daily_report(report)
        if self.config.dry_run:
            print(text)
            return [NotificationResult(channel="dry-run", ok=True)]
        if not self.config.slack_webhook_url:
            return []
        return [_post_json("slack", self.config.slack_webhook_url, {"text": text})]

    def notify_ollama_unreachable(self, error_detail: str) -> List[NotificationResult]:
        text = render_ollama_unreachable_message(self.config.ollama_url, error_detail)
        if self.config.dry_run:
            print(text)
            return [NotificationResult(channel="dry-run", ok=True)]
        if not self.config.slack_webhook_url:
            return []
        return [_post_json("slack", self.config.slack_webhook_url, {"text": text})]

    def _send_email(self, subject: str, body: str) -> NotificationResult:
        if not self.config.smtp_host or not self.config.smtp_from or not self.config.smtp_to:
            return NotificationResult("email", False, "SMTP_HOST, SMTP_FROM, SMTP_TO are required")

        message = EmailMessage()
        message["Subject"] = subject
        message["From"] = self.config.smtp_from
        message["To"] = ", ".join(self.config.smtp_to)
        message.set_content(body)

        try:
            with smtplib.SMTP(self.config.smtp_host, self.config.smtp_port, timeout=30) as smtp:
                if self.config.smtp_use_tls:
                    smtp.starttls()
                if self.config.smtp_username and self.config.smtp_password:
                    smtp.login(self.config.smtp_username, self.config.smtp_password)
                smtp.send_message(message)
        except OSError as exc:
            return NotificationResult("email", False, str(exc))
        return NotificationResult("email", True)


def render_ollama_unreachable_message(ollama_url: str, error_detail: str) -> str:
    lines = [
        f"日時: {_current_timestamp()}",
        "https://ft-chat.znw.co.jp watchlog-ai: Ollamaサーバー不達",
        "AI判定に失敗しました。Ollamaサーバーへ接続できません。",
        f"接続先: {ollama_url}",
        f"エラー: {error_detail}",
        "対応: Ollamaサービス、ネットワーク疎通、待受ポートを確認してください。",
    ]
    return "\n".join(lines)


def _current_timestamp() -> str:
    return datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z (%z)")

def render_message(result: AnalysisResult, checked_files: List[str]) -> str:
    timestamp = _current_timestamp()
    detected_logs = _display_log_names(result.source_names)
    lines = [
        f"日時: {timestamp}",
        f"https://ft-chat.znw.co.jp watchlog-ai: 危険度 {report_label(result.severity, result.source_names)}",
        f"対象ログ: {', '.join(checked_files)}",
        f"検知ログ: {', '.join(detected_logs) if detected_logs else '特定できませんでした'}",
        f"要約: {result.summary}",
    ]
    if _contains_rejected_access_log(result.source_names):
        lines.append(
            "補足: znw-support-ai-rejected-access.log に記録されたアクセスは、"
            "nginxのリバースプロキシで遮断済みです。アプリケーションには到達していないため、原則問題ありません。"
        )
    for incident in result.incidents[:5]:
        lines.append("")
        lines.append(f"- [{report_label(incident.severity, incident.source_names)}] {incident.title or '検知'}: {incident.summary}")
        incident_logs = _display_log_names(incident.source_names)
        if incident_logs:
            lines.append(f"  検知ログ: {', '.join(incident_logs)}")
        for evidence in incident.evidence[:3]:
            lines.append(f"  根拠: `{evidence}`")
        for action in incident.recommended_actions[:3]:
            lines.append(f"  対応: {action}")
    return "\n".join(lines)


def _incident_payload(incident: Incident) -> Dict[str, object]:
    return {
        "severity": incident.severity.value,
        "severity_label": report_label(incident.severity, incident.source_names),
        "title": incident.title,
        "summary": incident.summary,
        "evidence": incident.evidence,
        "recommended_actions": incident.recommended_actions,
        "source_names": incident.source_names,
    }


def _display_log_names(source_names: List[str]) -> List[str]:
    return list(dict.fromkeys(_base_log_name(source_name) for source_name in source_names))


def _contains_rejected_access_log(source_names: List[str]) -> bool:
    return any(is_rejected_access(source_name) for source_name in source_names)


def _base_log_name(source_name: str) -> str:
    base, separator, part = source_name.rpartition(" part ")
    if separator and part.isdigit():
        source_name = base
    return Path(source_name).name


def _post_json(channel: str, url: str, payload: Dict[str, object]) -> NotificationResult:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            status = response.getcode()
    except OSError as exc:
        return NotificationResult(channel, False, str(exc))
    return NotificationResult(channel, 200 <= status < 300, f"HTTP {status}")
