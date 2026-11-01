#!/usr/bin/env bash
set -euo pipefail

project_root="$(cd "$(dirname "$0")/.." && pwd)"
api_pid=""
ui_pid=""
cleanup() {
  if [[ -n "$api_pid" ]]; then kill "$api_pid" 2>/dev/null || true; fi
  if [[ -n "$ui_pid" ]]; then kill "$ui_pid" 2>/dev/null || true; fi
}
trap cleanup EXIT INT TERM

(cd "$project_root/backend" && uv run uvicorn app.main:app --host 127.0.0.1 --port 8001) &
api_pid=$!
(cd "$project_root/frontend" && npm run dev -- --port 4174) &
ui_pid=$!

printf 'OQVIAN CHAINTRACE API: http://127.0.0.1:8001\n'
printf 'OQVIAN CHAINTRACE UI:  http://127.0.0.1:4174\n'
printf 'Press Ctrl+C to stop both local services.\n'
wait "$api_pid" "$ui_pid"
