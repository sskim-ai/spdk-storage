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


def linux_dev_key(path: str) -> Tuple[int, int, int]:
    st = os.stat(path)
    if not stat.S_ISBLK(st.st_mode):
        raise ValueError(f"{path} is not a block device")
    major = os.major(st.st_rdev)
    minor = os.minor(st.st_rdev)
    return major, minor, linux_block_trace_dev_key(major, minor)


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
