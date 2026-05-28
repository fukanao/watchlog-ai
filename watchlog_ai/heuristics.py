from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional

from .ai import AnalysisResult, Incident
from .severity import Severity


FAILED_ACCESS_THRESHOLD = 10

_COMBINED_RE = re.compile(
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3}).*"
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+HTTP/[^"]+"\s+(?P<status>\d{3})'
)
_APP_RE = re.compile(
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+-\s+"
    r"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+(?P<status>\d{3})"
)
_SUSPICIOUS_PATH_RE = re.compile(
    r"("
    r"\.git|\.env|wp-admin|wp-login|phpmyadmin|xmlrpc\.php|"
    r"etc/passwd|shadow|config|backup|admin|console|cgi-bin|"
    r"\.\./|%2e%2e|select%20|union%20|<script|%3cscript|"
    r"cmd=|exec=|/vendor/|composer\.json|id_rsa"
    r")",
    re.IGNORECASE,
)
_BENIGN_PREFIXES = (
    "/static/",
    "/favicon.ico",
    "/robots.txt",
)


@dataclass(frozen=True)
class LogRequest:
    line: str
    ip: str
    method: str
    path: str
    status: int


def analyze_failed_access_bursts(logs: Dict[str, str], threshold: int = FAILED_ACCESS_THRESHOLD) -> AnalysisResult:
    incidents: List[Incident] = []

    for source_name, text in logs.items():
        incidents.extend(_find_failed_access_bursts(source_name, _parse_requests(text.splitlines()), threshold))

    if not incidents:
        return AnalysisResult(Severity.NONE, "連続した不正アクセス失敗は検出されませんでした。", [])

    return AnalysisResult(
        Severity.MEDIUM,
        "失敗していても、同一IPから10回以上連続した不正アクセスを検出したため危険度を中に引き上げました。",
        incidents,
    )


def _find_failed_access_bursts(source_name: str, requests: Iterable[LogRequest], threshold: int) -> List[Incident]:
    incidents: List[Incident] = []
    current_ip: Optional[str] = None
    current: List[LogRequest] = []

    def flush() -> None:
        if current_ip and len(current) >= threshold:
            evidence = [request.line for request in current[:5]]
            incidents.append(
                Incident(
                    Severity.MEDIUM,
                    f"{current_ip} から失敗した不正アクセスが{len(current)}回連続",
                    (
                        f"{source_name} で、同一IPから失敗ステータスの不正アクセスが"
                        f"{len(current)}回連続しています。情報漏洩は確認できなくても攻撃検知として扱います。"
                    ),
                    evidence,
                    [
                        "該当IPのアクセス頻度と直近のリクエスト内容を確認してください。",
                        "継続する場合はWAF、リバースプロキシ、ファイアウォールで制限してください。",
                    ],
                )
            )

    for request in requests:
        if _is_suspicious_failed_access(request):
            if request.ip != current_ip:
                flush()
                current_ip = request.ip
                current = []
            current.append(request)
        else:
            flush()
            current_ip = None
            current = []

    flush()
    return incidents


def _parse_requests(lines: Iterable[str]) -> Iterable[LogRequest]:
    for line in lines:
        match = _COMBINED_RE.search(line) or _APP_RE.search(line)
        if not match:
            continue
        yield LogRequest(
            line=line.strip()[:300],
            ip=match.group("ip"),
            method=match.group("method"),
            path=match.group("path"),
            status=int(match.group("status")),
        )


def _is_suspicious_failed_access(request: LogRequest) -> bool:
    path = request.path.split("?", 1)[0]
    if request.status < 400:
        return False
    if path.startswith(_BENIGN_PREFIXES):
        return False
    if request.method not in {"GET", "POST", "HEAD", "OPTIONS"}:
        return True
    if _SUSPICIOUS_PATH_RE.search(path):
        return True
    return request.status in {401, 403, 404, 405, 429}
