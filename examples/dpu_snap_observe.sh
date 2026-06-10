#!/usr/bin/env bash
set -euo pipefail

PID="${PID:-${1:-}}"
BINARY="${BINARY:-${2:-/path/to/snap_binary}}"
SEARCH_DIR="${SEARCH_DIR:-${3:-/path/to/snap/libs}}"

if [[ -z "${PID}" ]]; then
  echo "usage: PID=<snap_pid> BINARY=/path/to/snap SEARCH_DIR=/path/to/libs $0" >&2
  echo "   or: $0 <snap_pid> <binary> <search_dir>" >&2
  exit 2
fi

sudo "$(dirname "$0")/../snap_io_observe_dpu.py" \
  --pid "$PID" \
  --binary "$BINARY" \
  --search-dir "$SEARCH_DIR" \
  --mode both \
  --interval "${INTERVAL:-1}" \
  --hist
