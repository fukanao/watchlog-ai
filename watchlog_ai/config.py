from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional


def load_dotenv(path: Path) -> Dict[str, str]:
    values: Dict[str, str] = {}
    if not path.exists():
        return values

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key:
            values[key] = value
    return values


def _env(name: str, default: Optional[str], dotenv: Dict[str, str]) -> Optional[str]:
    return os.environ.get(name, dotenv.get(name, default))


def _bool(value: Optional[str], default: bool) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _csv(value: Optional[str], default: List[str]) -> List[str]:
    if not value:
        return default
    return [item.strip() for item in value.split(",") if item.strip()]


@dataclass(frozen=True)
class Config:
    log_dir: Path
    log_files: List[str]
    state_file: Path
    check_interval_seconds: int
    start_at_end: bool
    chunk_max_lines: int
    ollama_url: str
    ollama_model: str
    ollama_timeout_seconds: int
    slack_webhook_url: Optional[str]
    raspi_webhook_url: Optional[str]
    email_enabled: bool
    smtp_host: Optional[str]
    smtp_port: int
    smtp_username: Optional[str]
    smtp_password: Optional[str]
    smtp_from: Optional[str]
    smtp_to: List[str]
    smtp_use_tls: bool
    dry_run: bool

    @classmethod
    def from_env(cls, env_file: Path = Path(".env")) -> "Config":
        dotenv = load_dotenv(env_file)
        log_dir = Path(_env("LOG_DIR", "logs", dotenv) or "logs")
        state_file = Path(_env("STATE_FILE", ".watchlog-ai-state.json", dotenv) or ".watchlog-ai-state.json")

        return cls(
            log_dir=log_dir,
            log_files=_csv(_env("LOG_FILES", "access.log,error.log", dotenv), ["access.log", "error.log"]),
            state_file=state_file,
            check_interval_seconds=int(_env("CHECK_INTERVAL_SECONDS", "300", dotenv) or "300"),
            start_at_end=_bool(_env("START_AT_END", "false", dotenv), False),
            chunk_max_lines=int(_env("CHUNK_MAX_LINES", "160", dotenv) or "160"),
            ollama_url=(_env("OLLAMA_URL", "http://10.0.4.101:11534", dotenv) or "").rstrip("/"),
            ollama_model=_env("OLLAMA_MODEL", "gpt-oss:120b", dotenv) or "gpt-oss:120b",
            ollama_timeout_seconds=int(_env("OLLAMA_TIMEOUT_SECONDS", "120", dotenv) or "120"),
            slack_webhook_url=_env("SLACK_WEBHOOK_URL", None, dotenv),
            raspi_webhook_url=_env("RASPI_WEBHOOK_URL", None, dotenv),
            email_enabled=_bool(_env("EMAIL_ENABLED", "false", dotenv), False),
            smtp_host=_env("SMTP_HOST", None, dotenv),
            smtp_port=int(_env("SMTP_PORT", "587", dotenv) or "587"),
            smtp_username=_env("SMTP_USERNAME", None, dotenv),
            smtp_password=_env("SMTP_PASSWORD", None, dotenv),
            smtp_from=_env("SMTP_FROM", None, dotenv),
            smtp_to=_csv(_env("SMTP_TO", "", dotenv), []),
            smtp_use_tls=_bool(_env("SMTP_USE_TLS", "true", dotenv), True),
            dry_run=_bool(_env("DRY_RUN", "false", dotenv), False),
        )

