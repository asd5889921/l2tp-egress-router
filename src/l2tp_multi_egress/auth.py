from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from pathlib import Path

import bcrypt

from .settings import Settings
from .storage import atomic_write


class AuthManager:
    def __init__(self, settings: Settings):
        self.path = settings.config_dir / "auth.json"
        self.secret_path = settings.config_dir / "session.key"
        if not self.secret_path.exists():
            atomic_write(self.secret_path, secrets.token_hex(32) + "\n")
        self.secret = self.secret_path.read_text(encoding="utf-8").strip().encode()

    def initialized(self) -> bool:
        return self.path.exists()

    def initialize(self, username: str, password: str) -> None:
        if self.path.exists():
            raise RuntimeError("管理员账号已初始化")
        if len(password) < 12:
            raise ValueError("管理员密码至少需要 12 个字符")
        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()
        atomic_write(self.path, json.dumps({"username": username, "password_hash": hashed}) + "\n")

    def verify(self, username: str, password: str) -> bool:
        if not self.path.exists():
            return False
        config = json.loads(self.path.read_text(encoding="utf-8"))
        valid_name = hmac.compare_digest(username, config["username"])
        valid_password = bcrypt.checkpw(password.encode(), config["password_hash"].encode())
        return valid_name and valid_password

    def create_session(self, username: str) -> tuple[str, str]:
        csrf = secrets.token_urlsafe(24)
        payload = json.dumps({"sub": username, "exp": int(time.time()) + 43200, "csrf": csrf}, separators=(",", ":")).encode()
        encoded = base64.urlsafe_b64encode(payload).rstrip(b"=").decode()
        signature = hmac.new(self.secret, encoded.encode(), hashlib.sha256).hexdigest()
        return f"{encoded}.{signature}", csrf

    def parse_session(self, token: str) -> dict | None:
        try:
            encoded, signature = token.rsplit(".", 1)
            expected = hmac.new(self.secret, encoded.encode(), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(signature, expected):
                return None
            padded = encoded + "=" * (-len(encoded) % 4)
            payload = json.loads(base64.urlsafe_b64decode(padded))
            return payload if payload["exp"] >= time.time() else None
        except (ValueError, KeyError, json.JSONDecodeError):
            return None

