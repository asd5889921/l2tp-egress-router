from __future__ import annotations

import logging
import time

from .settings import Settings
from .transaction import TransactionManager


def run() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    settings = Settings.from_env()
    manager = TransactionManager(settings)
    while True:
        try:
            pending = manager.pending()
            if pending and time.time() >= pending.deadline_epoch:
                logging.warning("transaction %s expired; rolling back", pending.id)
                manager.rollback(pending.id)
        except Exception:
            logging.exception("rollback watchdog iteration failed")
        time.sleep(1)


if __name__ == "__main__":
    run()

