#!/usr/bin/env bash
set -euo pipefail

# Example runner for BlueField DPU/SNAP observation.
# Run this inside the DPU OS or inside the SNAP container where the target
# process and SNAP/SPDK libraries are visible.

SNAP_PID="${SNAP_PID:-$(pidof snap 2>/dev/null || pidof nvmf_tgt 2>/dev/null || pidof spdk_tgt 2>/dev/null || true)}"
SNAP_BIN="${SNAP_BIN:-/path/to/snap_or_spdk_binary}"
SNAP_LIB_DIR="${SNAP_LIB_DIR:-/path/to/snap_or_spdk_libs}"
LBA_SIZE="${LBA_SIZE:-512}"
INTERVAL="${INTERVAL:-1}"

if [[ -z "${SNAP_PID}" ]]; then
  echo "SNAP_PID is empty. Set SNAP_PID=<pid> explicitly." >&2
  exit 2
fi

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

cat >&2 <<EOF
Using:
  SNAP_PID=${SNAP_PID}
  SNAP_BIN=${SNAP_BIN}
  SNAP_LIB_DIR=${SNAP_LIB_DIR}
  LBA_SIZE=${LBA_SIZE}
  INTERVAL=${INTERVAL}

Step 1: list symbols
EOF

sudo "${REPO_DIR}/snap_io_observe_dpu.py" \
  --pid "${SNAP_PID}" \
  --binary "${SNAP_BIN}" \
  --search-dir "${SNAP_LIB_DIR}" \
  --list-symbols

cat >&2 <<EOF

Step 2: dry-run egress attach plan
EOF

sudo "${REPO_DIR}/snap_io_observe_dpu.py" \
  --pid "${SNAP_PID}" \
  --binary "${SNAP_BIN}" \
  --search-dir "${SNAP_LIB_DIR}" \
  --mode egress \
  --dry-run

cat >&2 <<EOF

Step 3: observe egress size histogram
EOF

sudo "${REPO_DIR}/snap_io_observe_dpu.py" \
  --pid "${SNAP_PID}" \
  --binary "${SNAP_BIN}" \
  --search-dir "${SNAP_LIB_DIR}" \
  --mode egress \
  --interval "${INTERVAL}" \
  --hist \
  --lba-size "${LBA_SIZE}"
