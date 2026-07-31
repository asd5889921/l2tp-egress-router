from __future__ import annotations

import hashlib
import json
import os
import re
import signal
import subprocess
from pathlib import Path

from .models import AppState, Egress, ProxyType
from .settings import Settings
from .storage import atomic_write


class L2TPManager:
    """Run every outbound L2TP client in its own network namespace.

    The host's existing xl2tpd LNS is never inspected, rewritten, or restarted.
    Each client owns a namespace, a veth pair, an xl2tpd process, and a PPP
    device. Host policy routing uses the namespace-side veth as its gateway.
    """

    def __init__(self, settings: Settings):
        self.settings = settings
        self.root = settings.config_dir / "l2tp"
        self.runtime_root = settings.run_dir / "l2tp"
        self.config_file = self.root / "xl2tpd.conf"
        self.managed_file = self.root / "managed.json"

    @staticmethod
    def _safe(value: str) -> str:
        return re.sub(r"[^A-Za-z0-9_.-]", "_", value)

    @classmethod
    def runtime_name(cls, prefix: str, egress_id: str) -> str:
        digest = hashlib.sha256(egress_id.encode()).hexdigest()[:5]
        readable = cls._safe(egress_id)[:8]
        return f"{prefix}{readable}-{digest}"[:15]

    @classmethod
    def namespace_name(cls, egress_id: str) -> str:
        return cls.runtime_name("l2e-", egress_id)

    @classmethod
    def host_interface(cls, egress_id: str) -> str:
        return cls.runtime_name("lh-", egress_id)

    @classmethod
    def namespace_interface(cls, egress_id: str) -> str:
        return cls.runtime_name("ln-", egress_id)

    @classmethod
    def link_addresses(cls, egress_id: str) -> tuple[str, str, str]:
        # Deterministic link-local /30: host address, namespace gateway, CIDR.
        number = int.from_bytes(hashlib.sha256(egress_id.encode()).digest()[:2], "big") % 16000
        third, slot = divmod(number, 64)
        fourth = slot * 4
        network = f"169.254.{third + 1}.{fourth}"
        return f"169.254.{third + 1}.{fourth + 1}", f"169.254.{third + 1}.{fourth + 2}", f"{network}/30"

    def _run(self, args: list[str], namespace: str | None = None) -> subprocess.CompletedProcess[str]:
        command = ["ip", "netns", "exec", namespace, *args] if namespace else args
        if self.settings.dry_run:
            return subprocess.CompletedProcess(command, 0, "dry-run", "")
        return subprocess.run(command, text=True, capture_output=True, timeout=20, check=False)

    def _checked(self, args: list[str], namespace: str | None = None) -> None:
        result = self._run(args, namespace)
        if result.returncode:
            raise RuntimeError(f"command failed {' '.join(args)}: {(result.stderr or result.stdout).strip()}")

    def render_ppp_options(self, egress: Egress) -> str:
        directory = self.root / self._safe(egress.id)
        options = [
            "noauth",
            "noipdefault",
            "defaultroute",
            f"mtu {egress.mtu}",
            f"mru {egress.mtu}",
            f"user {egress.username}",
            f"password {egress.password}",
            f"ipparam l2er:{self._safe(egress.id)}",
            "persist",
            f"ip-up-script {directory / 'ip-up'}",
            f"ip-down-script {directory / 'ip-down'}",
        ]
        if egress.dns_proxy:
            options.append("usepeerdns")
        return "\n".join(options) + "\n"

    def render_lac(self, egress: Egress) -> list[str]:
        name = self._safe(egress.id)
        options = self.root / name / "ppp.options"
        return [
            f"[lac {name}]",
            f"lns = {egress.address}",
            f"pppoptfile = {options}",
            "autodial = yes",
            "redial = yes",
            f"redial timeout = {egress.reconnect_delay}",
            "require authentication = no",
            "length bit = yes",
            "",
        ]

    def render(self, egresses: list[Egress]) -> str:
        lines = ["[global]", "access control = no", "port = 1701", ""]
        for egress in egresses:
            lines.extend(self.render_lac(egress))
        return "\n".join(lines)

    def _hook(self, egress: Egress, action: str) -> str:
        binary = os.getenv("L2ER_PPP_EVENT_BINARY", "/opt/l2tp-egress-router/.venv/bin/l2er-ppp-event")
        host_interface = self.host_interface(egress.id)
        namespace = self.namespace_name(egress.id)
        _, gateway, _ = self.link_addresses(egress.id)
        return (
            "#!/bin/sh\n"
            f"export L2ER_HOST_INTERFACE={host_interface}\n"
            f"export L2ER_NAMESPACE={namespace}\n"
            f"export L2ER_GATEWAY_IP={gateway}\n"
            f"exec {binary} {action} \"$1\" \"$4\" \"$5\" \"$6\" l2er:{self._safe(egress.id)}\n"
        )

    def write_configs(self, state: AppState) -> Path:
        self.root.mkdir(parents=True, exist_ok=True)
        self.runtime_root.mkdir(parents=True, exist_ok=True)
        l2tps = [e for e in state.egresses if e.type == ProxyType.L2TP]
        for egress in l2tps:
            directory = self.root / self._safe(egress.id)
            directory.mkdir(parents=True, exist_ok=True)
            atomic_write(directory / "ppp.options", self.render_ppp_options(egress), mode=0o600)
            atomic_write(directory / "xl2tpd.conf", "\n".join(["[global]", "access control = no", "port = 1701", ""] + self.render_lac(egress)), mode=0o600)
            atomic_write(directory / "ip-up", self._hook(egress, "up"), mode=0o700)
            atomic_write(directory / "ip-down", self._hook(egress, "down"), mode=0o700)
        atomic_write(self.config_file, self.render(l2tps), mode=0o600)
        atomic_write(self.managed_file, json.dumps(sorted(self._safe(e.id) for e in l2tps)), mode=0o600)
        return self.config_file

    def _namespace_exists(self, namespace: str) -> bool:
        return namespace in self._run(["ip", "netns", "list"]).stdout.split()

    def _host_link_exists(self, interface: str) -> bool:
        return bool(re.search(rf"\b{re.escape(interface)}(?:@[^:]+)?:", self._run(["ip", "-o", "link", "show"]).stdout))

    def _configure_namespace(self, egress: Egress) -> None:
        namespace = self.namespace_name(egress.id)
        host_interface = self.host_interface(egress.id)
        namespace_interface = self.namespace_interface(egress.id)
        host_ip, namespace_ip, network = self.link_addresses(egress.id)
        if not self._namespace_exists(namespace):
            self._checked(["ip", "netns", "add", namespace])
        if not self._host_link_exists(host_interface):
            self._checked(["ip", "link", "add", host_interface, "type", "veth", "peer", "name", namespace_interface])
            self._checked(["ip", "link", "set", namespace_interface, "netns", namespace])
        self._checked(["ip", "addr", "replace", f"{host_ip}/30", "dev", host_interface])
        self._checked(["ip", "link", "set", host_interface, "up"])
        self._checked(["ip", "addr", "replace", f"{namespace_ip}/30", "dev", namespace_interface], namespace)
        self._checked(["ip", "link", "set", namespace_interface, "up"], namespace)
        self._checked(["ip", "link", "set", "lo", "up"], namespace)
        self._checked(["sysctl", "-q", "-w", "net.ipv4.ip_forward=1"], namespace)
        self._checked(["ip", "route", "replace", "default", "via", host_ip, "dev", namespace_interface], namespace)
        self._checked(["ip", "route", "replace", f"{egress.address}/32", "via", host_ip, "dev", namespace_interface], namespace)
        for command in (
            ["iptables", "-C", "FORWARD", "-i", namespace_interface, "-o", "ppp+", "-j", "ACCEPT"],
            ["iptables", "-C", "FORWARD", "-i", "ppp+", "-o", namespace_interface, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
            ["iptables", "-t", "nat", "-C", "POSTROUTING", "-o", "ppp+", "-j", "MASQUERADE"],
        ):
            if self._run(command, namespace).returncode:
                add = command.copy()
                add[1 if command[1] != "-t" else 3] = "-A"
                self._checked(add, namespace)

    def _pid_path(self, egress_id: str) -> Path:
        return self.runtime_root / f"{self._safe(egress_id)}.pid"

    def _running(self, path: Path) -> bool:
        try:
            os.kill(int(path.read_text().strip()), 0)
            return True
        except (OSError, ValueError):
            return False

    def _stop(self, egress_id: str, remove_namespace: bool = True) -> None:
        pid_path = self._pid_path(egress_id)
        try:
            os.kill(int(pid_path.read_text().strip()), signal.SIGTERM)
        except (OSError, ValueError):
            pass
        pid_path.unlink(missing_ok=True)
        if self.settings.dry_run or not remove_namespace:
            return
        namespace = self.namespace_name(egress_id)
        host_interface = self.host_interface(egress_id)
        self._run(["ip", "netns", "delete", namespace])
        self._run(["ip", "link", "delete", host_interface])
        (self.settings.run_dir / "ppp" / f"{self._safe(egress_id)}.json").unlink(missing_ok=True)

    def _start(self, egress: Egress) -> None:
        if self.settings.dry_run:
            return
        namespace = self.namespace_name(egress.id)
        pid_path = self._pid_path(egress.id)
        config = self.root / self._safe(egress.id) / "xl2tpd.conf"
        binary = os.getenv("L2ER_XL2TPD_BINARY", "/usr/sbin/xl2tpd")
        process = subprocess.Popen(["ip", "netns", "exec", namespace, binary, "-D", "-c", str(config), "-p", str(pid_path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        atomic_write(pid_path, f"{process.pid}\n", mode=0o600)

    def apply(self, state: AppState) -> None:
        desired = {e.id: e for e in state.egresses if e.type == ProxyType.L2TP}
        previous_ids: set[str] = set()
        try:
            previous_ids = set(json.loads(self.managed_file.read_text(encoding="utf-8")))
        except (OSError, ValueError, TypeError):
            pass
        self.write_configs(state)
        for old_id in previous_ids - set(desired):
            self._stop(old_id)
        for egress in desired.values():
            self._configure_namespace(egress)
            pid_path = self._pid_path(egress.id)
            if not self._running(pid_path):
                self._start(egress)
