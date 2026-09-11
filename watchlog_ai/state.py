from __future__ import annotations

import copy
import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, Optional

from .daily_report import DailyReport


@dataclass
class FileState:
    inode: Optional[int] = None
    offset: int = 0


@dataclass
class State:
    files: Dict[str, FileState] = field(default_factory=dict)
    ollama_unreachable_notified_at: Optional[float] = None
    daily_report: Optional[DailyReport] = None
    daily_report_sent_on: Optional[str] = None

    @classmethod
    def load(cls, path: Path) -> "State":
        if not path.exists():
            return cls()
        raw = json.loads(path.read_text(encoding="utf-8"))
        files = {
            name: FileState(inode=value.get("inode"), offset=int(value.get("offset", 0)))
            for name, value in raw.get("files", {}).items()
        }
        notified_at = raw.get("ollama_unreachable_notified_at")
        return cls(
            files=files,
            daily_report=DailyReport(**raw["daily_report"]) if raw.get("daily_report") else None,
            daily_report_sent_on=raw.get("daily_report_sent_on"),
            ollama_unreachable_notified_at=float(notified_at) if notified_at is not None else None,
        )

    def clone(self) -> "State":
        return State(
            files={
                name: FileState(inode=file_state.inode, offset=file_state.offset)
                for name, file_state in self.files.items()
            },
            ollama_unreachable_notified_at=self.ollama_unreachable_notified_at,
            daily_report=copy.deepcopy(self.daily_report),
            daily_report_sent_on=self.daily_report_sent_on,
        )

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "files": {
                name: {"inode": file_state.inode, "offset": file_state.offset}
                for name, file_state in self.files.items()
            }
        }
        if self.ollama_unreachable_notified_at is not None:
            payload["ollama_unreachable_notified_at"] = self.ollama_unreachable_notified_at
        if self.daily_report is not None:
            payload["daily_report"] = asdict(self.daily_report)
        if self.daily_report_sent_on is not None:
            payload["daily_report_sent_on"] = self.daily_report_sent_on
        temp_path = path.with_suffix(path.suffix + ".tmp")
        temp_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        os.replace(temp_path, path)

