# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.
#
# Multi-stage build: dependencies are compiled into a virtualenv in the builder stage, and the
# runtime image carries only that virtualenv plus the application - no compilers, no pip cache,
# no source-mounted development tooling. The image runs as a non-root user and its health check
# hits /health.

# ---------------------------------------------------------------------------- builder
FROM python:3.12-slim AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_ROOT_USER_ACTION=ignore

WORKDIR /build

# Build tooling is needed only for sdists without wheels (e.g. a pinned source-only release).
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential libpq5 \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY app ./app

RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --upgrade pip setuptools wheel \
    && /opt/venv/bin/pip install --no-cache-dir .

# ---------------------------------------------------------------------------- runtime
FROM python:3.12-slim AS runtime

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONFAULTHANDLER=1 \
    API_HOST=0.0.0.0 \
    API_PORT=8000

# curl: container health check and the entrypoint's readiness wait.
# postgresql-client: pg_dump / pg_restore for scripts/backup.sh and scripts/restore.sh.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates postgresql-client \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 --shell /usr/sbin/nologin armx

WORKDIR /app

COPY --from=builder /opt/venv /opt/venv
COPY app ./app
COPY migrations ./migrations
COPY alembic.ini ./alembic.ini
COPY scripts ./scripts

# Writable runtime directories (sandboxed sites, edited images, backups) owned by the app user.
RUN mkdir -p /app/var/sites /app/var/images /app/var/backups /app/data \
    && chmod +x /app/scripts/*.sh \
    && chown -R armx:armx /app

USER armx

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=25s --retries=3 \
    CMD curl -fsS "http://127.0.0.1:${API_PORT}/health" || exit 1

ENTRYPOINT ["/app/scripts/entrypoint.sh"]
CMD ["api"]
