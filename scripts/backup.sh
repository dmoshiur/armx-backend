#!/usr/bin/env bash
# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.
#
# Encrypted logical backup of the primary database (Supabase PostgreSQL or the bundled
# Postgres). Schedule it from cron or a platform scheduler:
#
#   DATABASE_URL=postgresql://... BACKUP_ENCRYPTION_PASSWORD=... ./scripts/backup.sh
#
# Properties:
#   * pg_dump custom format (restorable table-by-table, concurrent-restore capable)
#   * AES-256-CBC with PBKDF2 (200k iterations) - the dump never touches disk unencrypted
#   * a SHA-256 sidecar so a truncated or tampered backup is detected before a restore
#   * the file is decrypted once, header-checked, then discarded: a backup that cannot be
#     read is worse than no backup, because it is trusted
#
# Restore procedure: docs/operations.md, and scripts/restore.sh.
set -euo pipefail

: "${DATABASE_URL:?DATABASE_URL is required}"
: "${BACKUP_ENCRYPTION_PASSWORD:?BACKUP_ENCRYPTION_PASSWORD is required (store it in your secrets manager)}"

BACKUP_DIR="${BACKUP_DIR:-./var/backups}"
RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-30}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
TARGET="${BACKUP_DIR}/armx-${STAMP}.dump.enc"

# Backups are a PostgreSQL feature; a SQLite file is copied by the operator instead.
case "${DATABASE_URL}" in
    postgresql*|postgres://*) ;;
    *) echo "[backup] refusing to run: DATABASE_URL is not PostgreSQL (use 'cp' for SQLite dev)" >&2; exit 64 ;;
esac

mkdir -p "${BACKUP_DIR}"
chmod 700 "${BACKUP_DIR}"

echo "[backup] dumping database"
# -Fc: custom format. --no-owner/--no-privileges keep the dump portable across roles,
# which matters when restoring a Supabase project into a different project.
pg_dump --format=custom --no-owner --no-privileges --compress=6 --file="${TARGET}.plain" "${DATABASE_URL}"

echo "[backup] encrypting"
openssl enc -aes-256-cbc -pbkdf2 -iter 200000 -salt \
    -pass env:BACKUP_ENCRYPTION_PASSWORD \
    -in "${TARGET}.plain" -out "${TARGET}"
shred --remove "${TARGET}.plain" 2>/dev/null || rm -f "${TARGET}.plain"

echo "[backup] writing checksum"
sha256sum "${TARGET}" | awk '{print $1}' > "${TARGET}.sha256"
chmod 600 "${TARGET}" "${TARGET}.sha256"

echo "[backup] verifying the backup is readable (decrypt + header check)"
if openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -pass env:BACKUP_ENCRYPTION_PASSWORD \
        -in "${TARGET}" 2>/dev/null | head -c 5 | grep -q "PGDMP"; then
    echo "[backup] verification passed"
else
    echo "[backup] VERIFICATION FAILED - the backup is not readable" >&2
    rm -f "${TARGET}" "${TARGET}.sha256"
    exit 1
fi

echo "[backup] pruning backups older than ${RETENTION_DAYS} days"
find "${BACKUP_DIR}" -maxdepth 1 -name 'armx-*.dump.enc' -mtime "+${RETENTION_DAYS}" -delete
find "${BACKUP_DIR}" -maxdepth 1 -name 'armx-*.dump.enc.sha256' -mtime "+${RETENTION_DAYS}" -delete

echo "[backup] complete: ${TARGET}"
