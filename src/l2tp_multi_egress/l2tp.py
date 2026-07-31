from __future__ import annotations

import os
import re
import signal
import subprocess
import time

from .models import AppState, Egress, ProxyType
from .settings import Settings
from .storage import atomic_write


class L2TPManager:
    """Manage an isolated xl2tpd client without touching host L2TP server files."""

    def __init__(self, settings: Settings):
        self.settings = settings
        self.root = settings.config_dir / "l2tp"
        self.pid_file = settings.run_dir / "l2tp-xl2tpd.pid"
        self.config_file = self.root / "xl2tpd.conf"

    @staticmethod
    def _safe(value: str) -> str:
        return re.sub(r"[^A-Za-z0-9_.-]", "_", value)

    def render_ppp_options(self, egress: Egress) -> str:
        options = [
            "noauth",
            "noipdefault",
            "defaultroute",
            f"mtu {egress.mtu}",
            f"mru {egress.mtu}",
            f"user {egress.username}",
            f"password {egress.password}",
            "persist",
            "ip-up-script /etc/l2tp-egress-router/l2tp/ip-up",
        ]
        if egress.dns_proxy:
            options.append("usepeerdns")
        return "\n".join(options) + "\n"

    def render(self, egresses: list[Egress]) -> str:
        lines = ["[global]", "access control = no", "port = 1701", ""]
        for egress in egresses:
            name = self._safe(egress.id)
            options = self.root / name / "ppp.options"
            lines.extend([
                f"[lac {name}]",
                f"lns = {egress.address}",
                f"pppoptfile = {options}",
                "autodial = yes",
                "redial = yes",
                f"redial timeout = {egress.reconnect_delay}",
                "require authentication = no",
                "length bit = yes",
                "",
            ])
        return "\n".join(lines)

    def write_configs(self, state: AppState):
        self.root.mkdir(parents=True, exist_ok=True)
        atomic_write(self.root / "ip-up", "#!/bin/sh\nexec /opt/l2tp-egress-router/.venv/bin/l2er-ppp-event up \"$1\" \"$4\" \"$5\"\n", mode=0o700)
        l2tps = [e for e in state.egresses if e.type == ProxyType.L2TP]
        for egress in l2tps:
            directory = self.root / self._safe(egress.id)
            directory.mkdir(parents=True, exist_ok=True)
            atomic_write(directory / "ppp.options", self.render_ppp_options(egress), mode=0o600)
        atomic_write(self.config_file, self.render(l2tps), mode=0o600)
        return self.config_file

    def _stop(self) -> None:
        if not self.pid_file.exists():
            return
        try:
            os.kill(int(self.pid_file.read_text().strip()), signal.SIGTERM)
        except (ValueError, ProcessLookupError, PermissionError):
            pass
        self.pid_file.unlink(missing_ok=True)

    def apply(self, state: AppState) -> None:
        config = self.write_configs(state)
        self._stop()
        if self.settings.dry_run:
            return
        if not any(e.type == ProxyType.L2TP for e in state.egresses):
            return
        binary = os.getenv("L2ER_XL2TPD_BINARY", "/usr/sbin/xl2tpd")
        proc = subprocess.Popen([binary, "-D", "-c", str(config)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        atomic_write(self.pid_file, f"{proc.pid}\n", mode=0o600)
        # PPP negotiation is asynchronous; refresh policy routes once the
        # kernel creates the interface so the first request uses the tunnel.
        from .network import NetworkManager
        network = NetworkManager(self.settings)
        for _ in range(10):
            links = network._run(["ip", "-o", "link", "show"])
            if re.search(r"\d+: ppp\d+:", links.stdout):
                network.ensure_policy_route(state)
                network.ensure_source_routes(state)
                break
            time.sleep(1)
