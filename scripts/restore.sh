#!/usr/bin/env bash
# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.
#
# Restore a backup produced by scripts/backup.sh.
#
#   DATABASE_URL=postgresql://target/... BACKUP_ENCRYPTION_PASSWORD=... \
#     ./scripts/restore.sh ./var/backups/armx-20261013T000000Z.dump.enc
#
# Run this against a *fresh* database, then verify before pointing production at it:
#   1. ./scripts/restore.sh <file>
#   2. alembic upgrade head                 (a restore is a point-in-time schema, not the latest)
#   3. curl -fsS https://<host>/ready       (must report migration_revision, not 503)
#   4. spot-check: SELECT count(*) FROM users; SELECT max(occurred_at) FROM audit_events;
#   5. sign in with a non-admin account and confirm one LOW tool call is audited.
# Record the drill (date, operator, backup file, restore duration) in docs/operations.md.
set -euo pipefail

: "${DATABASE_URL:?DATABASE_URL is required}"
: "${BACKUP_ENCRYPTION_PASSWORD:?BACKUP_ENCRYPTION_PASSWORD is required}"

BACKUP_FILE="${1:?usage: restore.sh <backup-file.dump.enc>}"
[ -f "${BACKUP_FILE}" ] || { echo "[restore] no such backup: ${BACKUP_FILE}" >&2; exit 66; }

# 1. Verify the checksum before doing anything with the contents.
if [ -f "${BACKUP_FILE}.sha256" ]; then
    EXPECTED="$(cat "${BACKUP_FILE}.sha256")"
    ACTUAL="$(sha256sum "${BACKUP_FILE}" | awk '{print $1}')"
    if [ "${EXPECTED}" != "${ACTUAL}" ]; then
        echo "[restore] checksum mismatch: the backup file is corrupted or has been altered" >&2
        exit 65
    fi
    echo "[restore] checksum verified"
fi

# 2. Decrypt to a private temporary file.
PLAIN="$(mktemp -t armx-restore-XXXXXX.dump)"
chmod 600 "${PLAIN}"
trap 'shred --remove "${PLAIN}" 2>/dev/null || rm -f "${PLAIN}"' EXIT

openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -pass env:BACKUP_ENCRYPTION_PASSWORD \
    -in "${BACKUP_FILE}" -out "${PLAIN}"

head -c 5 "${PLAIN}" | grep -q "PGDMP" || { echo "[restore] not a PostgreSQL custom-format dump" >&2; exit 65; }

# 3. Confirm the target is empty: restoring over a live database would mix two histories.
EXISTING="$(psql "${DATABASE_URL}" -tAc "SELECT count(*) FROM information_schema.tables WHERE table_schema='public'" || echo "0")"
if [ "${EXISTING}" != "0" ] && [ "${FORCE_RESTORE:-false}" != "true" ]; then
    echo "[restore] target database already has ${EXISTING} tables; set FORCE_RESTORE=true to overwrite" >&2
    exit 65
fi

echo "[restore] restoring"
pg_restore --no-owner --no-privileges --clean --if-exists --dbname="${DATABASE_URL}" "${PLAIN}"

echo "[restore] restore complete. Next: alembic upgrade head, then check /ready."
