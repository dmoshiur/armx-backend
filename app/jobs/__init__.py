# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""
Durable background jobs.

Redis is intentionally absent from this deployment (Supabase is the backing store), so the
queue lives in the primary database: workers claim rows with ``SELECT ... FOR UPDATE SKIP
LOCKED`` on PostgreSQL, claims expire so a crashed worker cannot strand a job, and every
attempt is recorded with its idempotency key so a retry after an uncertain outcome is
visible rather than silent.
"""

from app.jobs.queue import (
    JobHandler,
    enqueue_job,
    job_handler,
    job_handlers,
    load_job_handlers,
)

__all__ = [
    "JobHandler",
    "enqueue_job",
    "job_handler",
    "job_handlers",
    "load_job_handlers",
]
