from __future__ import annotations

from pathlib import Path
from typing import Dict, Iterable, List, Tuple

from .state import FileState, State


def read_new_logs(
    log_dir: Path,
    log_files: Iterable[str],
    state: State,
    *,
    start_at_end: bool,
) -> Dict[str, str]:
    updates: Dict[str, str] = {}

    for log_file in log_files:
        path = log_dir / log_file
        if not path.exists():
            continue

        stat = path.stat()
        key = str(path)
        file_state = state.files.get(key)

        if file_state is None:
            if start_at_end:
                state.files[key] = FileState(inode=stat.st_ino, offset=stat.st_size)
                continue
            file_state = FileState(inode=stat.st_ino, offset=0)

        if file_state.inode != stat.st_ino or stat.st_size < file_state.offset:
            file_state = FileState(inode=stat.st_ino, offset=0)

        with path.open("rb") as handle:
            handle.seek(file_state.offset)
            data = handle.read()
            file_state.offset = handle.tell()
            file_state.inode = stat.st_ino

        state.files[key] = file_state
        if data:
            updates[log_file] = data.decode("utf-8", errors="replace")

    return updates


def chunk_lines(text: str, max_lines: int) -> List[str]:
    lines = text.splitlines()
    if not lines:
        return []
    return ["\n".join(lines[index : index + max_lines]) for index in range(0, len(lines), max_lines)]


def format_log_batch(logs: Dict[str, str], max_lines: int) -> List[Tuple[str, str]]:
    batches: List[Tuple[str, str]] = []
    for name, text in logs.items():
        for index, chunk in enumerate(chunk_lines(text, max_lines), start=1):
            label = name if index == 1 else f"{name} part {index}"
            batches.append((label, chunk))
    return batches

