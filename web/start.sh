#!/usr/bin/env bash
# Launch the M-SHIELD web console against the live MySQL database.
# Usage:  ./start.sh            (then open http://localhost:3000)
#         PORT=3001 ./start.sh  (use a different port)
set -euo pipefail
cd "$(dirname "$0")"
export DB_USER="${DB_USER:-mshield_demo}"
export DB_PASS="${DB_PASS:-MShield2026}"
export DB_NAME="${DB_NAME:-mshield}"
export PORT="${PORT:-3000}"

# Free the port if a previous run (or anything else) is still holding it,
# so you never hit EADDRINUSE.
if command -v fuser >/dev/null 2>&1 && fuser "${PORT}/tcp" >/dev/null 2>&1; then
    echo "Port ${PORT} is busy — freeing it..."
    fuser -k "${PORT}/tcp" >/dev/null 2>&1 || true
    sleep 1
fi

echo "Starting M-SHIELD console on http://localhost:${PORT}  (Ctrl+C to stop)"
exec node server.js
