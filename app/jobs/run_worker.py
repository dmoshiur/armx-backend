# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""
Worker entrypoint (``python -m app.jobs.run_worker``).

The worker container runs this instead of the API. It registers job handlers, starts one loop
per configured concurrency slot, and shuts down gracefully on SIGTERM so an in-flight deploy is
either completed or left for another worker to retry - never half-reported.
"""

from __future__ import annotations

import asyncio
import contextlib
import signal

from app.config import Settings, get_settings
from app.core.logging import configure_logging, get_logger
from app.core.metrics import set_gauge
from app.db.session import dispose_engines
from app.db.urls import redacted_database_url
from app.jobs.queue import load_job_handlers
from app.jobs.worker import build_worker_id, worker_loop

logger = get_logger("jobs.run_worker")


async def run(settings: Settings) -> None:
    configure_logging(level=settings.log_level, fmt=settings.log_format)
    logger.info("worker starting: database=%s", redacted_database_url(settings.database_url))
    handlers = load_job_handlers()
    if not handlers:
        logger.warning("no job handlers are registered; the worker has nothing to do")

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for signal_name in ("SIGTERM", "SIGINT"):
        with contextlib.suppress(NotImplementedError):
            loop.add_signal_handler(getattr(signal, signal_name), stop.set)

    set_gauge("worker_up", 1)
    tasks = [
        asyncio.create_task(
            worker_loop(settings, stop, worker_name=f"{build_worker_id()}-{index}"),
            name=f"worker-{index}",
        )
        for index in range(max(1, settings.worker_concurrency))
    ]
    try:
        await asyncio.gather(*tasks)
    finally:
        set_gauge("worker_up", 0)
        await dispose_engines()
        logger.info("worker stopped")


def main() -> None:
    settings = get_settings()
    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(run(settings))


if __name__ == "__main__":
    main()
