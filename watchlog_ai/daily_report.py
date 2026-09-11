from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import List

from .ai import AnalysisResult


JST = timezone(timedelta(hours=9), "JST")
MAX_SAMPLES = 20


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
                return
        if len(self.samples) < MAX_SAMPLES:
            self.samples.append({**sample, "count": 1})


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
    omitted = report.count - sum(sample["count"] for sample in report.samples)
    if omitted:
        lines.append(f"その他: {omitted}件（要約は最大{MAX_SAMPLES}種類まで表示）")
    return "\n".join(lines)
