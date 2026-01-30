#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

if [ -f .env ]; then
    set -a; source .env; set +a
fi

if [ -z "${WG_KEY_SECRET:-}" ]; then
    WG_KEY_SECRET="$(openssl rand -hex 32)"
    echo "WG_KEY_SECRET=\"$WG_KEY_SECRET\"" >> .env
    export WG_KEY_SECRET
    echo "Generated WG_KEY_SECRET and saved to .env"
fi

usage() {
    cat <<EOF
Usage: ./dev.sh <command>

Commands:
  api       Run the API server (cargo run)
  frontend  Run the frontend dev server (vite)
  all       Start API and frontend together
  psql      Open a psql shell (uses DATABASE_URL from .env)

Configure DATABASE_URL, JWT_SECRET, etc. in .env
EOF
}

check_env() {
    local missing=()
    [ -z "${DATABASE_URL:-}" ] && missing+=(DATABASE_URL)
    [ -z "${JWT_SECRET:-}" ] && missing+=(JWT_SECRET)
    if [ ${#missing[@]} -gt 0 ]; then
        echo "Error: missing required env vars: ${missing[*]}" >&2
        echo "Set them in .env" >&2
        exit 1
    fi
}

cmd_api() {
    check_env
    echo "Starting API server..."
    cargo run -p wirewarden-api -- "$@"
}

cmd_frontend() {
    echo "Starting frontend dev server..."
    cd frontend
    npm install --silent
    npx vite --host "$@"
}

cmd_psql() {
    check_env
    psql "$DATABASE_URL" "$@"
}

cmd_all() {
    check_env

    trap 'kill $(jobs -p) 2>/dev/null' EXIT INT TERM

    cargo run -p wirewarden-api &

    cd frontend
    npm install --silent
    npx vite &

    cd "$ROOT"
    echo ""
    echo "=== wirewarden dev ==="
    echo "  API:      http://localhost:${BIND_ADDR##*:}"
    echo "  Frontend: http://localhost:5173"
    echo "  Press Ctrl+C to stop all"
    echo ""

    wait
}

CMD="${1:-}"
shift || true

case "$CMD" in
    api)      cmd_api "$@" ;;
    frontend) cmd_frontend "$@" ;;
    all)      cmd_all "$@" ;;
    psql)     cmd_psql "$@" ;;
    *)        usage ;;
esac
