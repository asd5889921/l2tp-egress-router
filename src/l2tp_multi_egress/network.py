from __future__ import annotations

import json
import re
import subprocess

from .models import AppState, ProxyType
from .settings import Settings

CHAIN = "L2ER_TPROXY"
ROUTE_TABLE = 100
MANAGED_MARK = 0x8000


def l2tp_table(egress_id: str, state: AppState) -> int:
    ids = sorted(e.id for e in state.egresses if e.type == ProxyType.L2TP)
    return ROUTE_TABLE + 1 + ids.index(egress_id)


def iptables_restore_script(state: AppState) -> str:
    lines = [
        "*mangle", f":{CHAIN} - [0:0]", f"-F {CHAIN}",
        f"-A {CHAIN} -p udp --dport 1701 -j RETURN",
        f"-A {CHAIN} -d 0.0.0.0/8 -j RETURN", f"-A {CHAIN} -d 10.0.0.0/8 -j RETURN",
        f"-A {CHAIN} -d 100.64.0.0/10 -j RETURN", f"-A {CHAIN} -d 127.0.0.0/8 -j RETURN",
        f"-A {CHAIN} -d 169.254.0.0/16 -j RETURN", f"-A {CHAIN} -d 172.16.0.0/12 -j RETURN",
        f"-A {CHAIN} -d 192.168.0.0/16 -j RETURN", f"-A {CHAIN} -d 224.0.0.0/4 -j RETURN",
        f"-A {CHAIN} -d 240.0.0.0/4 -j RETURN",
    ]
    egresses = {e.id: e for e in state.egresses}
    for binding in state.bindings:
        if not binding.enabled:
            continue
        egress = egresses.get(binding.egress_id)
        if egress and egress.type == ProxyType.L2TP:
            lines.append(f"-A {CHAIN} -i ppp+ -s {binding.source_cidr} -j RETURN")
            continue
        for protocol in ("tcp", "udp"):
            lines.append(
                f"-A {CHAIN} -i ppp+ -s {binding.source_cidr} -p {protocol} "
                f"-j TPROXY --on-ip 127.0.0.1 --on-port {binding.tproxy_port} --tproxy-mark {binding.mark}/0xffffffff"
            )
    lines.extend(["COMMIT", ""])
    return "\n".join(lines)


class NetworkManager:
    def __init__(self, settings: Settings):
        self.settings = settings

    def _run(self, args: list[str], stdin: str | None = None) -> subprocess.CompletedProcess[str]:
        if self.settings.dry_run:
            return subprocess.CompletedProcess(args, 0, "dry-run", "")
        return subprocess.run(args, input=stdin, text=True, capture_output=True, timeout=20, check=False)

    def _checked(self, args: list[str], stdin: str | None = None) -> None:
        result = self._run(args, stdin)
        if result.returncode:
            raise RuntimeError(f"command failed {' '.join(args)}: {(result.stderr or result.stdout).strip()}")

    def ensure_policy_route(self, state: AppState) -> None:
        self._checked(["ip", "route", "replace", "local", "0.0.0.0/0", "dev", "lo", "table", str(ROUTE_TABLE)])
        links = self._run(["ip", "-o", "link", "show"])
        interfaces = sorted(re.findall(r"\d+: (ppp\d+):", links.stdout))
        runtime = self.settings.run_dir / "ppp"
        for egress in (e for e in state.egresses if e.type == ProxyType.L2TP):
            interface = None
            mapping = runtime / f"{egress.id}.json"
            if mapping.exists():
                try:
                    interface = json.loads(mapping.read_text()).get("interface")
                except (OSError, ValueError):
                    pass
            if interface not in interfaces and len(interfaces) == len([e for e in state.egresses if e.type == ProxyType.L2TP]):
                interface = interfaces[sorted(e.id for e in state.egresses if e.type == ProxyType.L2TP).index(egress.id)]
            if interface in interfaces:
                self._checked(["ip", "route", "replace", "default", "via", self._peer_for(interface), "dev", interface, "table", str(l2tp_table(egress.id, state))])
                for binding in state.bindings:
                    if binding.enabled and binding.egress_id == egress.id:
                        self._ensure_source_rule(binding.source_cidr, l2tp_table(egress.id, state))
        result = self._run(["ip", "rule", "show"])
        if f"fwmark 0x8000/0x8000 lookup {ROUTE_TABLE}" not in result.stdout:
            self._checked(["ip", "rule", "add", "fwmark", f"{MANAGED_MARK}/{MANAGED_MARK}", "table", str(ROUTE_TABLE), "priority", "30000"])

    def _peer_for(self, interface: str) -> str:
        result = self._run(["ip", "-4", "addr", "show", "dev", interface])
        match = re.search(r"peer (\d+\.\d+\.\d+\.\d+)/", result.stdout)
        return match.group(1) if match else "0.0.0.0"

    def _ensure_source_rule(self, cidr: str, table: int) -> None:
        result = self._run(["ip", "rule", "show"])
        if f"from {cidr} lookup {table}" not in result.stdout:
            self._checked(["ip", "rule", "add", "from", cidr, "table", str(table), "priority", "28000"])

    def ensure_source_routes(self, state: AppState) -> None:
        result = self._run(["ip", "-o", "link", "show"])
        interfaces = re.findall(r"\d+: (ppp\d+):", result.stdout)
        if self.settings.dry_run or not interfaces:
            return
        l2tp_ids = {e.id for e in state.egresses if e.type == ProxyType.L2TP}
        runtime = self.settings.run_dir / "ppp"
        ingress: list[str] = []
        for path in runtime.glob("*.json") if runtime.exists() else []:
            if path.stem in l2tp_ids:
                continue
            try:
                item = json.loads(path.read_text(encoding="utf-8"))
                if item.get("interface") in interfaces:
                    ingress.append(item["interface"])
            except (OSError, ValueError):
                continue
        for binding in state.bindings:
            if not binding.enabled:
                continue
            interface = binding.ppp_interface or (ingress[0] if ingress else (interfaces[0] if len(interfaces) == 1 else None))
            if not interface or interface not in interfaces:
                raise RuntimeError(f"no inbound PPP interface for binding {binding.id}")
            self._checked(["ip", "route", "replace", binding.source_cidr, "dev", interface])

    def apply(self, state: AppState) -> None:
        self.ensure_source_routes(state)
        self.ensure_policy_route(state)
        script = iptables_restore_script(state)
        self._checked(["iptables-restore", "--noflush", "--test"], script)
        self._checked(["iptables-restore", "--noflush"], script)
        check = self._run(["iptables", "-t", "mangle", "-C", "PREROUTING", "-i", "ppp+", "-j", CHAIN])
        if check.returncode:
            self._checked(["iptables", "-t", "mangle", "-I", "PREROUTING", "1", "-i", "ppp+", "-j", CHAIN])
        self.ensure_l2tp_nat(state)

    def ensure_l2tp_nat(self, state: AppState) -> None:
        """Masquerade each direct-L2TP source network on its PPP egress."""
        runtime = self.settings.run_dir / "ppp"
        interfaces = set(re.findall(r"\d+: (ppp\d+):", self._run(["ip", "-o", "link", "show"]).stdout))
        for egress in (e for e in state.egresses if e.type == ProxyType.L2TP):
            try:
                interface = json.loads((runtime / f"{egress.id}.json").read_text()).get("interface")
            except (OSError, ValueError):
                interface = None
            if interface not in interfaces:
                continue
            for binding in state.bindings:
                if not binding.enabled or binding.egress_id != egress.id:
                    continue
                nat = ["iptables", "-t", "nat", "-C", "POSTROUTING", "-s", binding.source_cidr, "-o", interface, "-j", "MASQUERADE"]
                if self._run(nat).returncode:
                    self._checked(["iptables", "-t", "nat", "-I", "POSTROUTING", "1", "-s", binding.source_cidr, "-o", interface, "-j", "MASQUERADE"])
                forward = ["iptables", "-C", "FORWARD", "-s", binding.source_cidr, "-o", interface, "-j", "ACCEPT"]
                if self._run(forward).returncode:
                    self._checked(["iptables", "-I", "FORWARD", "1", *forward[2:]])
                reverse = ["iptables", "-C", "FORWARD", "-i", interface, "-d", binding.source_cidr, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"]
                if self._run(reverse).returncode:
                    self._checked(["iptables", "-I", "FORWARD", "1", *reverse[2:]])
