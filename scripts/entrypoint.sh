#!/bin/sh
# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.
#
# Container entrypoint. Migrations run before the API accepts traffic so a rolling deploy can
# never serve requests against an old schema; the readiness endpoint enforces the same rule from
# the load-balancer side.
set -eu

TARGET="${1:-api}"
shift 2>/dev/null || true

run_migrations() {
    if [ "${DB_AUTO_MIGRATE:-true}" = "true" ]; then
        echo "[entrypoint] applying database migrations"
        alembic upgrade head
    else
        echo "[entrypoint] DB_AUTO_MIGRATE=false; assuming the schema is managed elsewhere"
    fi
}

case "${TARGET}" in
    api)
        run_migrations
        exec uvicorn app.main:app \
            --host "${API_HOST:-0.0.0.0}" \
            --port "${API_PORT:-8000}" \
            --workers "${WEB_CONCURRENCY:-2}" \
            --proxy-headers \
            --forwarded-allow-ips "${FORWARDED_ALLOW_IPS:-*}" \
            --timeout-keep-alive 30 \
            --limit-concurrency 512 \
            --no-server-header
        ;;
    worker)
        # The worker does not migrate: exactly one component owns schema changes per deploy.
        echo "[entrypoint] starting worker"
        exec python -m app.jobs.run_worker
        ;;
    migrate)
        run_migrations
        ;;
    shell)
        exec /bin/sh
        ;;
    *)
        echo "[entrypoint] unknown target '${TARGET}' (expected api|worker|migrate|shell)" >&2
        exit 64
        ;;
esac
