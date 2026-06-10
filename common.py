#!/usr/bin/env python3
"""Shared helpers for SPDK/NVMe BCC observers."""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Tuple


OP_READ = 0
OP_WRITE = 1
OP_FLUSH = 2
OP_UNMAP = 3
OP_OTHER = 4

OP_NAMES = {
    OP_READ: "read",
    OP_WRITE: "write",
    OP_FLUSH: "flush",
    OP_UNMAP: "unmap",
    OP_OTHER: "other",
}


def linux_block_trace_dev_key(major: int, minor: int) -> int:
    """Return the dev value observed by this host's block tracepoints.

    On the user's Ubuntu/BCC host, block:block_rq_issue reports dev as
    `(major << 20) | minor`, e.g. major 259 minor 1 appears as 0x10300001.
    Keep this encoding for BPF map filtering against `args->dev`.
    """
    return ((major << 20) | minor) & 0xFFFFFFFF


def _parse_major_minor(text: str) -> Tuple[int, int]:
    major_s, minor_s = text.strip().split(":", 1)
    return int(major_s, 0), int(minor_s, 0)


def _sysfs_block_dev_file(identifier: str) -> Optional[str]:
    """Resolve an iostat-style block name/path to a sysfs dev file.

    iostat/sysstat enumerates block devices from sysfs.  NVMe multipath path
    devices such as nvme2c2n1 can exist under /sys/class/block even when udev
    does not create /dev/nvme2c2n1.  This resolver lets tracepoint filters use
    the same naming source as iostat while still measuring bytes via BPF.
    """
    raw = identifier.strip()
    if not raw:
        return None
    if raw.startswith("/sys/class/block/"):
        name = os.path.basename(raw.rstrip("/"))
    elif raw.startswith("/sys/block/"):
        name = os.path.basename(raw.rstrip("/"))
    elif raw.startswith("/dev/"):
        name = os.path.basename(raw)
    else:
        name = raw

    candidates = [
        f"/sys/class/block/{name}/dev",
        f"/sys/block/{name}/dev",
    ]
    for path in candidates:
        if os.path.exists(path):
            return path
    return None


def linux_dev_key(identifier: str) -> Tuple[int, int, int]:
    """Return major, minor, tracepoint dev key for a block device identifier.

    Accepted identifiers:
    - real block device node: /dev/nvme2n1
    - sysfs/iostat-style name: nvme2c2n1
    - sysfs path: /sys/class/block/nvme2c2n1

    The function prefers real device-node stat when available, then falls back
    to /sys/class/block/<name>/dev like iostat.  The returned key is encoded for
    the observed block tracepoint args->dev format on this host.
    """
    if os.path.exists(identifier):
        st = os.stat(identifier)
        if stat.S_ISBLK(st.st_mode):
            major = os.major(st.st_rdev)
            minor = os.minor(st.st_rdev)
            return major, minor, linux_block_trace_dev_key(major, minor)

    dev_file = _sysfs_block_dev_file(identifier)
    if dev_file:
        major, minor = _parse_major_minor(open(dev_file, "r", encoding="utf-8").read())
        return major, minor, linux_block_trace_dev_key(major, minor)

    if os.path.exists(identifier):
        raise ValueError(f"{identifier} exists but is not a block device and has no sysfs block dev file")
    raise FileNotFoundError(f"block device {identifier!r} not found in /dev or /sys/class/block")


def log2_bucket_label(slot: int) -> str:
    if slot <= 0:
        return "0"
    low = 1 << slot
    high = (1 << (slot + 1)) - 1
    return f"{low}-{high}"


def print_log2_hist(title: str, rows: Dict[int, int], unit: str) -> None:
    if not rows:
        return
    print(title)
    max_count = max(rows.values()) or 1
    for slot in sorted(rows):
        count = rows[slot]
        bar = "*" * max(1, int(count * 40 / max_count))
        print(f"  {log2_bucket_label(slot):>15} {unit:<5} | {count:>10} | {bar}")


def json_dumps(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def tracefs_paths() -> List[str]:
    return ["/sys/kernel/debug/tracing", "/sys/kernel/tracing"]


def first_existing_tracefs() -> Optional[str]:
    for path in tracefs_paths():
        if os.path.exists(path):
            return path
    return None


def require_root() -> None:
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print("warning: BCC tracing normally requires root/CAP_BPF/CAP_SYS_ADMIN", file=sys.stderr)


def diagnostics() -> List[str]:
    out = []
    if first_existing_tracefs() is None:
        out.append("tracefs not found at /sys/kernel/debug/tracing or /sys/kernel/tracing; try: mount -t debugfs debugfs /sys/kernel/debug && mount -t tracefs tracefs /sys/kernel/debug/tracing")
    if shutil.which("bpftool") is None:
        out.append("bpftool not found; optional but useful for verifier diagnostics")
    return out


def run_tool(args: Sequence[str], timeout: int = 10) -> str:
    try:
        return subprocess.check_output(args, stderr=subprocess.DEVNULL, text=True, timeout=timeout)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return ""


@dataclass(frozen=True)
class SymbolHit:
    obj: str
    symbol: str
    source: str


def iter_elf_objects(binary: Optional[str], build_dir: Optional[str]) -> List[str]:
    seen = set()
    objects: List[str] = []
    for path in [binary]:
        if path and os.path.exists(path) and path not in seen:
            seen.add(path)
            objects.append(path)
    if build_dir and os.path.isdir(build_dir):
        for root, _, files in os.walk(build_dir):
            for name in files:
                if name.endswith(".so") or ".so." in name or name in {"nvmf_tgt", "spdk_tgt"}:
                    path = os.path.join(root, name)
                    if path not in seen:
                        seen.add(path)
                        objects.append(path)
    return objects


def symbols_from_object(path: str) -> Dict[str, str]:
    symbols: Dict[str, str] = {}
    commands = [
        ("nm-D", ["nm", "-D", path]),
        ("nm", ["nm", "-an", path]),
        ("readelf", ["readelf", "-Ws", path]),
        ("objdump", ["objdump", "-t", path]),
    ]
    for source, cmd in commands:
        if shutil.which(cmd[0]) is None:
            continue
        text = run_tool(cmd)
        for line in text.splitlines():
            for token in line.replace("\t", " ").split():
                if token.startswith(("spdk_", "bdev_", "nvme_")):
                    symbols.setdefault(token.split("@@")[0].split("@")[0], source)
    return symbols


def broad_symbols_from_object(path: str, keywords: Sequence[str]) -> Dict[str, str]:
    """Return symbols containing any keyword.

    This is intentionally broader than symbols_from_object() for SNAP/DPU
    environments where proprietary symbols may not use SPDK-style prefixes.
    """
    lowered = [k.lower() for k in keywords]
    symbols: Dict[str, str] = {}
    commands = [
        ("nm-D", ["nm", "-D", path]),
        ("nm", ["nm", "-an", path]),
        ("readelf", ["readelf", "-Ws", path]),
        ("objdump", ["objdump", "-t", path]),
    ]
    for source, cmd in commands:
        if shutil.which(cmd[0]) is None:
            continue
        text = run_tool(cmd)
        for line in text.splitlines():
            for token in line.replace("\t", " ").split():
                sym = token.split("@@")[0].split("@")[0]
                low = sym.lower()
                if any(k in low for k in lowered):
                    symbols.setdefault(sym, source)
    return symbols


def discover_symbols_fuzzy(objects: Iterable[str], keywords: Sequence[str]) -> List[SymbolHit]:
    hits: List[SymbolHit] = []
    for obj in objects:
        for sym, source in broad_symbols_from_object(obj, keywords).items():
            hits.append(SymbolHit(obj=obj, symbol=sym, source=source))
    return hits


def discover_symbols(objects: Iterable[str], candidates: Sequence[str]) -> List[SymbolHit]:
    hits: List[SymbolHit] = []
    for obj in objects:
        syms = symbols_from_object(obj)
        for cand in candidates:
            if cand in syms:
                hits.append(SymbolHit(obj=obj, symbol=cand, source=syms[cand]))
    return hits


def choose_first(hits: Sequence[SymbolHit], candidates: Sequence[str]) -> Optional[SymbolHit]:
    rank = {sym: idx for idx, sym in enumerate(candidates)}
    if not hits:
        return None
    return sorted(hits, key=lambda h: (rank.get(h.symbol, 10_000), h.obj))[0]


def bcc_import_error(exc: Exception) -> str:
    return (
        f"failed to import/load BCC: {exc}. Install python3-bcc/bpfcc-tools and matching kernel headers; "
        "Ubuntu 24.04 often needs linux-headers-$(uname -r)."
    )
