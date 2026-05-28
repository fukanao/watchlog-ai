from __future__ import annotations

import json
import smtplib
import urllib.request
from dataclasses import dataclass
from email.message import EmailMessage
from typing import Dict, List, Optional

from .ai import AnalysisResult, Incident
from .config import Config


@dataclass
class NotificationResult:
    channel: str
    ok: bool
    detail: str = ""


class Notifier:
    def __init__(self, config: Config) -> None:
        self.config = config

    def notify(self, result: AnalysisResult, checked_files: List[str]) -> List[NotificationResult]:
        title = f"[watchlog-ai] 危険度 {result.severity.label_ja}: chatログ警告"
        text = render_message(result, checked_files)
        payload = {
            "title": title,
            "severity": result.severity.value,
            "severity_label": result.severity.label_ja,
            "checked_files": checked_files,
            "summary": result.summary,
            "incidents": [_incident_payload(incident) for incident in result.incidents],
        }

        if self.config.dry_run:
            print(text)
            return [NotificationResult(channel="dry-run", ok=True)]

        results: List[NotificationResult] = []
        if self.config.slack_webhook_url:
            results.append(_post_json("slack", self.config.slack_webhook_url, {"text": text}))
        if self.config.raspi_webhook_url:
            results.append(_post_json("raspi", self.config.raspi_webhook_url, payload))
        if self.config.email_enabled:
            results.append(self._send_email(title, text))
        return results

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


def render_message(result: AnalysisResult, checked_files: List[str]) -> str:
    lines = [
        f"*watchlog-ai: 危険度 {result.severity.label_ja}*",
        f"対象ログ: {', '.join(checked_files)}",
        f"要約: {result.summary}",
    ]
    for incident in result.incidents[:5]:
        lines.append("")
        lines.append(f"- [{incident.severity.label_ja}] {incident.title or '検知'}: {incident.summary}")
        for evidence in incident.evidence[:3]:
            lines.append(f"  根拠: `{evidence}`")
        for action in incident.recommended_actions[:3]:
            lines.append(f"  対応: {action}")
    return "\n".join(lines)


def _incident_payload(incident: Incident) -> Dict[str, object]:
    return {
        "severity": incident.severity.value,
        "severity_label": incident.severity.label_ja,
        "title": incident.title,
        "summary": incident.summary,
        "evidence": incident.evidence,
        "recommended_actions": incident.recommended_actions,
    }


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

