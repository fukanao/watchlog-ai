from __future__ import annotations

import json
import logging
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, List

from .severity import Severity


LOGGER = logging.getLogger(__name__)


@dataclass
class Incident:
    severity: Severity
    title: str
    summary: str
    evidence: List[str] = field(default_factory=list)
    recommended_actions: List[str] = field(default_factory=list)
    source_names: List[str] = field(default_factory=list)


@dataclass
class AnalysisResult:
    severity: Severity
    summary: str
    incidents: List[Incident] = field(default_factory=list)
    source_names: List[str] = field(default_factory=list)


class OllamaError(RuntimeError):
    pass


class OllamaClient:
    def __init__(self, base_url: str, model: str, timeout_seconds: int) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout_seconds = timeout_seconds

    def analyze(self, source_name: str, log_text: str) -> AnalysisResult:
        prompt = self._build_prompt(source_name, log_text)
        payload = {
            "model": self.model,
            "stream": False,
            "format": "json",
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are a security log analyst for a Flask chat service. "
                        "Return only compact JSON. Be conservative: do not mark normal access as dangerous."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            "options": {"temperature": 0.1},
        }
        request = urllib.request.Request(
            f"{self.base_url}/api/chat",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                raw = json.loads(response.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise OllamaError(f"Ollama request failed: {exc}") from exc

        message = raw.get("message", {})
        content = message.get("content", "")
        result = parse_analysis(content)
        result.source_names = [source_name]
        for incident in result.incidents:
            incident.source_names = [source_name]
        LOGGER.info("Ollama AI analysis result: %s", format_analysis_for_debug(source_name, result))
        return result

    @staticmethod
    def _build_prompt(source_name: str, log_text: str) -> str:
        return f"""
次の chat サービスのログを確認し、危険度を判定してください。

危険度の定義:
- 高: いますぐ対応が必要。脆弱性を突かれた、または情報が漏洩した。
- 中: 攻撃検知。
- 低: スキャン程度。
- 無: 正常アクセス。

判定では、HTTPメソッド、パス、ステータス、回数、同一IPからの連続性、エラートレースを重視してください。
管理者の通常操作、/login, /chat, /ask, /stream の正常な 200/302 は原則「無」です。
ただし、/.git/config, /wp-admin, /phpmyadmin, SQLi/XSS/RCE らしいパス、認証突破、機密ファイル探索、異常な大量アクセスは危険として扱ってください。

パスワードリセットURLのメールセキュリティ検査:
- /reset_password/<token> へのHEADは、メールサービスがリンクの安全性を確認するために発生することがあります。
- 104.47.0.0/17（104.47.0.0〜104.47.127.255）はMicrosoft 365のメールセキュリティ基盤として扱ってください。
- 次をすべて満たす場合は、トークン横取りや漏洩ではなく正常なリンク検査として、危険度を「無」、incidentsを空にしてください。
  1. 104.47.0.0/17からのアクセスがHEADだけで、同IPからPOSTされていない。
  2. 利用者IPから直前に/reset_password_requestへのGET/POSTがある。
  3. Microsoft側のHEAD直後に、利用者IPが同じリセットURLをGET/POSTしている。
  4. その後、同じ利用者IPで/login、/two_factor、/consent、/chatなどの通常操作が続いている。
- HEADのIPと利用者IPが異なるという理由だけで、トークン横取りや漏洩と判定しないでください。
- Microsoft側IPからPOSTされた場合、Microsoft範囲外の第三者IPが同じトークンを利用した場合、利用者の操作と対応しない場合、または不審な認証・アカウント操作が続く場合は危険として再評価してください。

JSON形式だけで返してください:
{{
  "severity": "high|medium|low|none",
  "summary": "短い日本語の要約",
  "incidents": [
    {{
      "severity": "high|medium|low|none",
      "title": "短い題名",
      "summary": "理由",
      "evidence": ["ログから短い根拠を最大5件"],
      "recommended_actions": ["推奨対応を最大5件"]
    }}
  ]
}}

対象: {source_name}
ログ:
```log
{log_text}
```
""".strip()


def parse_analysis(content: str) -> AnalysisResult:
    data = _load_json_object(content)
    incidents: List[Incident] = []
    for raw_incident in data.get("incidents", []) or []:
        incidents.append(
            Incident(
                severity=Severity.parse(raw_incident.get("severity")),
                title=str(raw_incident.get("title", "")).strip()[:160],
                summary=str(raw_incident.get("summary", "")).strip()[:1000],
                evidence=[str(item).strip()[:300] for item in raw_incident.get("evidence", [])[:5]],
                recommended_actions=[
                    str(item).strip()[:300] for item in raw_incident.get("recommended_actions", [])[:5]
                ],
            )
        )

    severity = Severity.parse(data.get("severity"))
    for incident in incidents:
        if incident.severity.score > severity.score:
            severity = incident.severity

    return AnalysisResult(
        severity=severity,
        summary=str(data.get("summary", "")).strip()[:1000] or "AI判定の要約が空でした。",
        incidents=incidents,
    )


def format_analysis_for_debug(source_name: str, result: AnalysisResult) -> str:
    return json.dumps(
        {
            "source": source_name,
            "severity": result.severity.value,
            "severity_label": result.severity.label_ja,
            "summary": result.summary,
            "source_names": result.source_names,
            "incidents": [
                {
                    "severity": incident.severity.value,
                    "severity_label": incident.severity.label_ja,
                    "title": incident.title,
                    "summary": incident.summary,
                    "evidence": incident.evidence,
                    "recommended_actions": incident.recommended_actions,
                    "source_names": incident.source_names,
                }
                for incident in result.incidents
            ],
        },
        ensure_ascii=False,
        separators=(",", ":"),
    )


def _load_json_object(content: str) -> Dict[str, Any]:
    content = content.strip()
    try:
        parsed = json.loads(content)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        pass

    match = re.search(r"\{.*\}", content, flags=re.DOTALL)
    if not match:
        raise OllamaError("Ollama response did not contain a JSON object")
    parsed = json.loads(match.group(0))
    if not isinstance(parsed, dict):
        raise OllamaError("Ollama response JSON was not an object")
    return parsed
