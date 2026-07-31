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
    args = parser.parse_args()
    settings = Settings.from_env()
    directory = settings.run_dir / "ppp"
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{args.interface}.json"
    if args.action == "down":
        path.unlink(missing_ok=True)
        return
    payload = {
        "up": True,
        "interface": args.interface,
        "username": os.getenv("PEERNAME", os.getenv("PPP_PEERNAME", "unknown")),
        "local_ip": args.local_ip,
        "peer_ip": args.peer_ip,
        "started_epoch": time.time(),
    }
    atomic_write(path, json.dumps(payload, ensure_ascii=False) + "\n")
    # ip-up.d runs after the PPP device is ready. Re-apply source routes here
    # so a reconnect never leaves the Xray path without a return route.
    try:
        from .network import NetworkManager
        NetworkManager(settings).ensure_source_routes(StateStore(settings).load())
    except Exception as exc:
        # Do not fail PPP negotiation because the optional routing layer failed;
        # leave an actionable message in the journal for the watchdog/operator.
        print(f"l2er: failed to restore source routes on {args.interface}: {exc}", flush=True)


if __name__ == "__main__":
    run()
