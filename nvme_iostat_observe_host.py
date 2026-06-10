#!/usr/bin/env python3
"""Observe host NVMe devices from /sys/block/*/stat, iostat-style.

This is a fallback/complement to nvme_io_observe_host.py:
- It does not require BCC/eBPF.
- It follows the same accounting source as iostat/sysstat.
- It works with sysfs-only names such as nvme2c2n1 even when /dev/nvme2c2n1
  is not created by udev.

Limitations:
- This is interval aggregate data, not per-IO trace data.
- It cannot produce true per-IO size histograms.
- avg_size is bytes / completed IOs in the interval.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional

SECTOR_SIZE = 512


@dataclass
class DiskStat:
    reads_completed: int
    reads_merged: int
    sectors_read: int
    read_ms: int
    writes_completed: int
    writes_merged: int
    sectors_written: int
    write_ms: int
    ios_in_progress: int
    io_ms: int
    weighted_io_ms: int
    discards_completed: int = 0
    discards_merged: int = 0
    sectors_discarded: int = 0
    discard_ms: int = 0
    flushes_completed: int = 0
    flush_ms: int = 0


@dataclass
class Target:
    name: str
    stat_path: str
    label: str
    major_minor: Optional[str] = None


def read_text(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read().strip()


def parse_stat(text: str) -> DiskStat:
    vals = [int(x) for x in text.split()]
    vals += [0] * max(0, 17 - len(vals))
    return DiskStat(
        reads_completed=vals[0],
        reads_merged=vals[1],
        sectors_read=vals[2],
        read_ms=vals[3],
        writes_completed=vals[4],
        writes_merged=vals[5],
        sectors_written=vals[6],
        write_ms=vals[7],
        ios_in_progress=vals[8],
        io_ms=vals[9],
        weighted_io_ms=vals[10],
        discards_completed=vals[11],
        discards_merged=vals[12],
        sectors_discarded=vals[13],
        discard_ms=vals[14],
        flushes_completed=vals[15],
        flush_ms=vals[16],
    )


def read_stat(target: Target) -> DiskStat:
    return parse_stat(read_text(target.stat_path))


def normalize_name(raw: str) -> str:
    raw = raw.strip()
    if raw.startswith("/dev/"):
        return os.path.basename(raw)
    if raw.startswith("/sys/block/"):
        return os.path.basename(raw.rstrip("/"))
    return raw


def target_from_name(raw: str) -> Target:
    name = normalize_name(raw)
    sys_block = f"/sys/block/{name}"
    stat_path = f"{sys_block}/stat"
    if not os.path.exists(stat_path):
        raise FileNotFoundError(f"{stat_path} not found for {raw!r}")
    major_minor = None
    dev_path = f"{sys_block}/dev"
    if os.path.exists(dev_path):
        major_minor = read_text(dev_path)
    return Target(name=name, stat_path=stat_path, label=name, major_minor=major_minor)


def discover_nvme_targets() -> List[Target]:
    out = []
    for name in sorted(os.listdir("/sys/block")):
        if name.startswith("nvme"):
            try:
                out.append(target_from_name(name))
            except FileNotFoundError:
                pass
    return out


def diff(cur: DiskStat, prev: DiskStat) -> Dict[str, int]:
    return {
        "read_ios": max(0, cur.reads_completed - prev.reads_completed),
        "read_sectors": max(0, cur.sectors_read - prev.sectors_read),
        "read_ms": max(0, cur.read_ms - prev.read_ms),
        "write_ios": max(0, cur.writes_completed - prev.writes_completed),
        "write_sectors": max(0, cur.sectors_written - prev.sectors_written),
        "write_ms": max(0, cur.write_ms - prev.write_ms),
        "discard_ios": max(0, cur.discards_completed - prev.discards_completed),
        "discard_sectors": max(0, cur.sectors_discarded - prev.sectors_discarded),
        "discard_ms": max(0, cur.discard_ms - prev.discard_ms),
        "flush_ios": max(0, cur.flushes_completed - prev.flushes_completed),
        "flush_ms": max(0, cur.flush_ms - prev.flush_ms),
        "io_ms": max(0, cur.io_ms - prev.io_ms),
        "weighted_io_ms": max(0, cur.weighted_io_ms - prev.weighted_io_ms),
        "in_flight": cur.ios_in_progress,
    }


def rows_from_delta(target: Target, d: Dict[str, int], interval: float) -> List[Dict[str, object]]:
    rows: List[Dict[str, object]] = []
    specs = [
        ("read", d["read_ios"], d["read_sectors"], d["read_ms"]),
        ("write", d["write_ios"], d["write_sectors"], d["write_ms"]),
        ("discard", d["discard_ios"], d["discard_sectors"], d["discard_ms"]),
        ("flush", d["flush_ios"], 0, d["flush_ms"]),
    ]
    for op, ios, sectors, op_ms in specs:
        if ios == 0 and sectors == 0:
            continue
        bytes_ = sectors * SECTOR_SIZE
        rows.append({
            "device": target.label,
            "major_minor": target.major_minor,
            "op": op,
            "ios": ios,
            "iops": ios / interval if interval > 0 else 0.0,
            "bytes": bytes_,
            "throughput_Bps": bytes_ / interval if interval > 0 else 0.0,
            "avg_size": bytes_ / ios if ios else None,
            "avg_latency_ms": op_ms / ios if ios else None,
            "in_flight": d["in_flight"],
        })
    return rows


def human_bps(v: float) -> str:
    units = ["B/s", "KiB/s", "MiB/s", "GiB/s"]
    x = float(v)
    for unit in units:
        if abs(x) < 1024 or unit == units[-1]:
            return f"{x:.1f}{unit}"
        x /= 1024
    return f"{x:.1f}B/s"


def print_rows(rows: Iterable[Dict[str, object]]) -> None:
    for r in rows:
        avg_size = r["avg_size"]
        avg_lat = r["avg_latency_ms"]
        avg_size_s = "-" if avg_size is None else f"{avg_size:.1f}"
        avg_lat_s = "-" if avg_lat is None else f"{avg_lat:.3f}"
        print(
            f"{str(r['device']):<16} {str(r['major_minor'] or ''):<8} {str(r['op']):<8} "
            f"ios={int(r['ios']):<10} iops={float(r['iops']):<10.1f} "
            f"bytes={int(r['bytes']):<14} bw={human_bps(float(r['throughput_Bps'])):<12} "
            f"avg_size={avg_size_s:<10} avg_lat_ms={avg_lat_s:<10} in_flight={int(r['in_flight'])}"
        )


def main() -> int:
    parser = argparse.ArgumentParser(description="iostat-style host NVMe observer using /sys/block/<dev>/stat")
    parser.add_argument("--devices", help="comma-separated sysfs block names or /dev paths, e.g. nvme2c2n1,/dev/nvme2n1")
    parser.add_argument("--all-nvme", action="store_true", help="observe all /sys/block/nvme* devices")
    parser.add_argument("--interval", type=float, default=1.0, help="print interval in seconds")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON lines")
    parser.add_argument("--once", action="store_true", help="print one interval and exit")
    args = parser.parse_args()

    targets: List[Target] = []
    if args.all_nvme:
        targets.extend(discover_nvme_targets())
    if args.devices:
        for raw in args.devices.split(","):
            raw = raw.strip()
            if raw:
                try:
                    targets.append(target_from_name(raw))
                except FileNotFoundError as exc:
                    print(f"error: {exc}", file=sys.stderr)
                    return 2
    # Deduplicate by stat_path while preserving order.
    seen = set()
    unique_targets = []
    for t in targets:
        if t.stat_path not in seen:
            seen.add(t.stat_path)
            unique_targets.append(t)
    targets = unique_targets

    if not targets:
        print("error: provide --devices or --all-nvme", file=sys.stderr)
        return 2

    print("observing iostat/sysfs counters: " + ", ".join(f"{t.label}({t.major_minor or '?'})" for t in targets), file=sys.stderr)
    prev = {t.name: read_stat(t) for t in targets}

    while True:
        time.sleep(args.interval)
        ts = time.time()
        all_rows: List[Dict[str, object]] = []
        for t in targets:
            cur = read_stat(t)
            d = diff(cur, prev[t.name])
            prev[t.name] = cur
            all_rows.extend(rows_from_delta(t, d, args.interval))

        if args.json:
            print(json.dumps({"ts": ts, "interval": args.interval, "stats": all_rows}, sort_keys=True, separators=(",", ":")))
        else:
            print(time.strftime("%H:%M:%S"))
            print_rows(all_rows)
        if args.once:
            break
    return 0


if __name__ == "__main__":
    sys.exit(main())
