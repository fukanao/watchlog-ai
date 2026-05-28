from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Optional


@dataclass
class FileState:
    inode: Optional[int] = None
    offset: int = 0


@dataclass
class State:
    files: Dict[str, FileState] = field(default_factory=dict)

    @classmethod
    def load(cls, path: Path) -> "State":
        if not path.exists():
            return cls()
        raw = json.loads(path.read_text(encoding="utf-8"))
        files = {
            name: FileState(inode=value.get("inode"), offset=int(value.get("offset", 0)))
            for name, value in raw.get("files", {}).items()
        }
        return cls(files=files)

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "files": {
                name: {"inode": file_state.inode, "offset": file_state.offset}
                for name, file_state in self.files.items()
            }
        }
        temp_path = path.with_suffix(path.suffix + ".tmp")
        temp_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        os.replace(temp_path, path)

