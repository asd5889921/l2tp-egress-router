from __future__ import annotations

import argparse
import json
import os
import time

from .settings import Settings
from .storage import StateStore, atomic_write


def run() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["up", "down"])
    parser.add_argument("interface")
    parser.add_argument("local_ip", nargs="?", default="")
    parser.add_argument("peer_ip", nargs="?", default="")
    parser.add_argument("egress_id", nargs="?", default="")
    args = parser.parse_args()
    settings = Settings.from_env()
    directory = settings.run_dir / "ppp"
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{args.interface}.json"
    if args.action == "down":
        path.unlink(missing_ok=True)
        if args.egress_id.startswith("l2er:"):
            (directory / f"{args.egress_id[5:]}.json").unlink(missing_ok=True)
        return
    payload = {
        "up": True,
        "interface": args.interface,
        "username": os.getenv("PEERNAME", os.getenv("PPP_PEERNAME", "unknown")),
        "local_ip": args.local_ip,
        "peer_ip": args.peer_ip,
        "started_epoch": time.time(),
    }
    if args.egress_id.startswith("l2er:"):
        atomic_write(directory / f"{args.egress_id[5:]}.json", json.dumps(payload, ensure_ascii=False) + "\n")
        path.unlink(missing_ok=True)
    else:
        atomic_write(path, json.dumps(payload, ensure_ascii=False) + "\n")
    # ip-up.d runs after the PPP device is ready. Re-apply source routes here
    # so a reconnect never leaves the Xray path without a return route.
    try:
        from .network import NetworkManager
        manager = NetworkManager(settings)
        state = StateStore(settings).load()
        manager.ensure_source_routes(state)
        manager.ensure_policy_route(state)
        manager.ensure_l2tp_nat(state)
    except Exception as exc:
        # Do not fail PPP negotiation because the optional routing layer failed;
        # leave an actionable message in the journal for the watchdog/operator.
        print(f"l2er: failed to restore source routes on {args.interface}: {exc}", flush=True)


if __name__ == "__main__":
    run()
