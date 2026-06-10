#!/usr/bin/env bash
set -euo pipefail

PID="${PID:-$(pidof nvmf_tgt || pidof spdk_tgt)}"
BINARY="${BINARY:-/path/to/nvmf_tgt}"
SPDK_BUILD_DIR="${SPDK_BUILD_DIR:-/path/to/spdk/build}"

sudo "$(dirname "$0")/../spdk_io_observe_uprobe.py" \
  --pid "$PID" \
  --binary "$BINARY" \
  --spdk-build-dir "$SPDK_BUILD_DIR" \
  --interval "${INTERVAL:-1}" \
  --hist \
  --symbols-auto-detect
