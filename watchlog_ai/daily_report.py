from __future__ import annotations

import re
from ipaddress import ip_address
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import List

from .ai import AnalysisResult


JST = timezone(timedelta(hours=9), "JST")
MAX_SAMPLES = 20
MAX_SOURCE_IPS = 20

# Match client fields, rather than IPs in URLs, user agents or upstream addresses.
_CLIENT_PATTERNS = (
    re.compile(r'^\s*(?P<ip>\S+)\s+\S+\s+\S+\s+\[[^\]]+\]\s+"'),
    re.compile(r'(?:^|\s)(?P<ip>[\da-fA-F:.]+)\s+-\s+[A-Z]+\s+\S+\s+\d{3}(?:\s|$)'),
    re.compile(r'(?:^|,\s*)client:\s*(?P<ip>[^,\s]+)'),
)


def extract_source_ips(log_text: str) -> List[str]:
    ips = {}
    for line in log_text.splitlines():
        for pattern in _CLIENT_PATTERNS:
            match = pattern.search(line)
            if not match:
                continue
            try:
                address = str(ip_address(match.group("ip")))
            except ValueError:
                continue
            ips[address] = None
            break
    return list(ips)


def next_report_at(now: float) -> float:
    local = datetime.fromtimestamp(now, JST)
    deadline = local.replace(hour=9, minute=0, second=0, microsecond=0)
    if deadline <= local:
        deadline += timedelta(days=1)
    return deadline.timestamp()


@dataclass
class DailyReport:
    due_at: float
    first_at: float
    last_at: float
    count: int = 0
    samples: List[dict] = field(default_factory=list)

    def add(self, result: AnalysisResult, now: float) -> None:
        self.count += 1
        self.last_at = now
        sample = {"summary": result.summary[:500], "sources": result.source_names[:20]}
        for existing in self.samples:
            if existing["summary"] == sample["summary"] and existing["sources"] == sample["sources"]:
                existing["count"] += 1
                self._add_source_ips(existing, result.source_ips)
                return
        if len(self.samples) < MAX_SAMPLES:
            self._add_source_ips(sample, result.source_ips)
            self.samples.append({**sample, "count": 1})

    @staticmethod
    def _add_source_ips(sample: dict, source_ips: List[str]) -> None:
        ips = list(dict.fromkeys([*sample.get("source_ips", []), *source_ips]))
        sample["source_ips"] = ips[:MAX_SOURCE_IPS]
        sample["source_ips_truncated"] = sample.get("source_ips_truncated", False) or len(ips) > MAX_SOURCE_IPS


def render_daily_report(report: DailyReport) -> str:
    def timestamp(value: float) -> str:
        return datetime.fromtimestamp(value, JST).strftime("%Y-%m-%d %H:%M JST")

    lines = [
        "https://ft-chat.znw.co.jp watchlog-ai: 危険度 小・低 日次報告（毎朝9:00 JST）",
        f"検知期間: {timestamp(report.first_at)} ～ {timestamp(report.last_at)}",
        f"低優先度の判定件数: {report.count}件（ログ行数ではありません）",
        "遮断ログに記録されたアクセスはnginxで遮断済みです。",
    ]
    for sample in report.samples:
        lines.append(f"- {sample['summary']}（{sample['count']}件）")
        lines.append(f"  検知ログ: {', '.join(sample['sources'])}")
        ips = ", ".join(sample.get("source_ips", [])) or "不明（IP情報なし）"
        if sample.get("source_ips_truncated", False):
            ips += f" ほか（最大{MAX_SOURCE_IPS}件まで表示）"
        lines.append(f"  アクセス元IP（解析対象ログ内）: {ips}")
    omitted = report.count - sum(sample["count"] for sample in report.samples)
    if omitted:
        lines.append(f"その他: {omitted}件（要約は最大{MAX_SAMPLES}種類まで表示）")
    return "\n".join(lines)
