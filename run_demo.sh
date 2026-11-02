#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# M-SHIELD live-demo launcher.
# Rebuilds the database from scratch (schema -> data -> views -> triggers),
# then runs the narrated demo. Guarantees a clean, identical demo every time.
#
# Usage:   ./run_demo.sh
# Requires: a MySQL user with rights on the 'mshield' schema.
# -----------------------------------------------------------------------------
set -euo pipefail
cd "$(dirname "$0")"

DB_USER="${DB_USER:-mshield_demo}"
export MYSQL_PWD="${DB_PASS:-MShield2026}"   # avoids the password-on-CLI warning

echo ">> Rebuilding database (01 -> 04) ..."
for f in sql/01_schema.sql sql/02_sample_data.sql sql/03_views.sql sql/04_triggers.sql; do
    mysql -u "$DB_USER" < "$f"
    echo "   loaded $f"
done

echo ">> Running demo ..."
echo
mysql -u "$DB_USER" --table mshield < sql/demo.sql
