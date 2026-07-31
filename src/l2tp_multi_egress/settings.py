from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    config_dir: Path
    run_dir: Path
    xray_binary: Path
    xray_api: str
    dry_run: bool
    listen_host: str
    listen_port: int
    rollback_seconds: int

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            config_dir=Path(os.getenv("L2ER_CONFIG_DIR", "/etc/l2tp-egress-router")),
            run_dir=Path(os.getenv("L2ER_RUN_DIR", "/run/l2tp-egress-router")),
            xray_binary=Path(os.getenv("L2ER_XRAY_BINARY", "/usr/local/bin/xray")),
            xray_api=os.getenv("L2ER_XRAY_API", "127.0.0.1:10085"),
            dry_run=os.getenv("L2ER_DRY_RUN", "0") == "1",
            listen_host=os.getenv("L2ER_LISTEN_HOST", "127.0.0.1"),
            listen_port=int(os.getenv("L2ER_LISTEN_PORT", "17890")),
            rollback_seconds=int(os.getenv("L2ER_ROLLBACK_SECONDS", "60")),
        )

    @property
    def state_file(self) -> Path:
        return self.config_dir / "state.json"

    @property
    def history_dir(self) -> Path:
        return self.config_dir / "history"

    @property
    def xray_dir(self) -> Path:
        return self.config_dir / "xray_config"

    @property
    def pending_file(self) -> Path:
        return self.run_dir / "pending-transaction.json"

    @property
    def lock_file(self) -> Path:
        return self.run_dir / "apply.lock"

    def ensure_dirs(self) -> None:
        for path in (self.config_dir, self.run_dir, self.history_dir, self.xray_dir):
            path.mkdir(parents=True, exist_ok=True)
