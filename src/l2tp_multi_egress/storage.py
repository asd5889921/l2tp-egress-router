from __future__ import annotations

import json
import os
import shutil
import tempfile
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from .models import AppState
from .settings import Settings

if os.name == "nt":
    import msvcrt
else:
    import fcntl


def atomic_write(path: Path, content: str, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
        if os.name != "nt":
            directory_fd = os.open(path.parent, os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


@contextmanager
def exclusive_lock(path: Path) -> Iterator[None]:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+b") as handle:
        if os.name == "nt":
            # Windows development runs are single-process in this project;
            # production Debian uses the advisory fcntl lock below.
            yield
            return
        else:
            fcntl.flock(handle, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


class StateStore:
    def __init__(self, settings: Settings):
        self.settings = settings
        settings.ensure_dirs()

    def load(self) -> AppState:
        if not self.settings.state_file.exists():
            state = AppState()
            self.save(state)
            return state
        return AppState.model_validate_json(self.settings.state_file.read_text(encoding="utf-8"))

    def save(self, state: AppState) -> None:
        atomic_write(self.settings.state_file, state.model_dump_json(indent=2) + "\n")

    def snapshot(self, state: AppState, label: str = "change") -> Path:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
        path = self.settings.history_dir / f"{stamp}-{state.revision}-{label}.json"
        atomic_write(path, state.model_dump_json(indent=2) + "\n")
        snapshots = sorted(self.settings.history_dir.glob("*.json"), reverse=True)
        for stale in snapshots[5:]:
            stale.unlink(missing_ok=True)
        return path

    def histories(self) -> list[dict[str, str | int]]:
        result = []
        for path in sorted(self.settings.history_dir.glob("*.json"), reverse=True):
            state = AppState.model_validate_json(path.read_text(encoding="utf-8"))
            result.append({"name": path.name, "revision": state.revision, "updated_at": state.updated_at})
        return result

    def load_snapshot(self, name: str) -> AppState:
        if Path(name).name != name:
            raise ValueError("快照名称无效")
        path = self.settings.history_dir / name
        if not path.is_file():
            raise FileNotFoundError(name)
        return AppState.model_validate_json(path.read_text(encoding="utf-8"))
