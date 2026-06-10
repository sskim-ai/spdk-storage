#!/usr/bin/env bash
set -euo pipefail

sudo "$(dirname "$0")/../nvme_io_observe_host.py" \
  --devices "${1:-/dev/nvme1n1,/dev/nvme3n1}" \
  --interval "${INTERVAL:-1}" \
  --hist \
  --latency
