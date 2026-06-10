#!/usr/bin/env python3
"""Observe selected Linux NVMe block devices with BCC tracepoints."""

from __future__ import annotations

import argparse
import ctypes as ct
import os
import signal
import sys
import time
from typing import Dict, Tuple

from common import OP_NAMES, diagnostics, json_dumps, linux_dev_key, print_log2_hist, require_root


def tracepoint_format(tp: str) -> str:
    path = f"/sys/kernel/debug/tracing/events/{tp}/format"
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except OSError:
        return ""


def build_bpf_text(has_bytes_issue: bool, has_bytes_complete: bool, want_latency: bool) -> str:
    issue_bytes = "args->bytes" if has_bytes_issue else "(args->nr_sector << 9)"
    complete_bytes = "args->bytes" if has_bytes_complete else "(args->nr_sector << 9)"
    latency_issue = (
        """
    struct start_key sk = {};
    sk.dev = dev;
    sk.sector = args->sector;
    sk.bytes = bytes;
    sk.op = op;
    struct start_val sv = {};
    sv.ts = bpf_ktime_get_ns();
    start.update(&sk, &sv);
"""
        if want_latency
        else ""
    )
    latency_complete = (
        f"""
    struct start_key sk = {{}};
    sk.dev = dev;
    sk.sector = args->sector;
    sk.bytes = {complete_bytes};
    sk.op = op_from_rwbs(args->rwbs);
    struct start_val *sv = start.lookup(&sk);
    if (sv) {{
        u64 delta_us = (bpf_ktime_get_ns() - sv->ts) / 1000;
        struct hist_key hk = {{}};
        hk.dev = dev;
        hk.op = sk.op;
        hk.slot = bpf_log2l(delta_us ? delta_us : 1);
        increment_lat_hist(&hk);
        start.delete(&sk);
    }}
"""
        if want_latency
        else ""
    )
    return f"""
#include <uapi/linux/ptrace.h>

struct stat_key {{
    u32 dev;
    u32 op;
}};

struct stat_val {{
    u64 ios;
    u64 bytes;
}};

struct hist_key {{
    u32 dev;
    u32 op;
    u64 slot;
}};

struct start_key {{
    u32 dev;
    u64 sector;
    u32 bytes;
    u32 op;
}};

struct start_val {{
    u64 ts;
}};

BPF_HASH(filter_devs, u32, u8);
BPF_HASH(stats, struct stat_key, struct stat_val);
BPF_HASH(size_hist, struct hist_key, u64);
BPF_HASH(lat_hist, struct hist_key, u64);
BPF_HASH(start, struct start_key, struct start_val);

static __always_inline int op_from_rwbs(const char *rwbs)
{{
    char c = 0;
    bpf_probe_read_kernel(&c, sizeof(c), rwbs);
    if (c == 'R') return 0;
    if (c == 'W') return 1;
    if (c == 'F') return 2;
    if (c == 'D') return 3;
    return 4;
}}

static __always_inline void increment_size_hist(struct hist_key *key)
{{
    u64 zero = 0, *val;
    val = size_hist.lookup(key);
    if (val) {{
        __sync_fetch_and_add(val, 1);
    }} else {{
        size_hist.update(key, &zero);
        val = size_hist.lookup(key);
        if (val) __sync_fetch_and_add(val, 1);
    }}
}}

static __always_inline void increment_lat_hist(struct hist_key *key)
{{
    u64 zero = 0, *val;
    val = lat_hist.lookup(key);
    if (val) {{
        __sync_fetch_and_add(val, 1);
    }} else {{
        lat_hist.update(key, &zero);
        val = lat_hist.lookup(key);
        if (val) __sync_fetch_and_add(val, 1);
    }}
}}

TRACEPOINT_PROBE(block, block_rq_issue)
{{
    u32 dev = args->dev;
    u8 *enabled = filter_devs.lookup(&dev);
    if (!enabled) return 0;

    u32 bytes = {issue_bytes};
    u32 op = op_from_rwbs(args->rwbs);

    struct stat_key key = {{}};
    key.dev = dev;
    key.op = op;
    struct stat_val zero = {{}}, *val;
    val = stats.lookup_or_try_init(&key, &zero);
    if (val) {{
        __sync_fetch_and_add(&val->ios, 1);
        __sync_fetch_and_add(&val->bytes, bytes);
    }}

    struct hist_key hk = {{}};
    hk.dev = dev;
    hk.op = op;
    hk.slot = bpf_log2l(bytes ? bytes : 1);
    increment_size_hist(&hk);
{latency_issue}
    return 0;
}}

TRACEPOINT_PROBE(block, block_rq_complete)
{{
    u32 dev = args->dev;
    u8 *enabled = filter_devs.lookup(&dev);
    if (!enabled) return 0;
{latency_complete}
    return 0;
}}
"""


class StatKey(ct.Structure):
    _fields_ = [("dev", ct.c_uint32), ("op", ct.c_uint32)]


class StatVal(ct.Structure):
    _fields_ = [("ios", ct.c_uint64), ("bytes", ct.c_uint64)]


class HistKey(ct.Structure):
    _fields_ = [("dev", ct.c_uint32), ("op", ct.c_uint32), ("slot", ct.c_uint64)]


def snapshot_hash(table) -> Dict[Tuple[int, int], Tuple[int, int]]:
    return {(k.dev, k.op): (v.ios, v.bytes) for k, v in table.items()}


def delta_stats(now, prev):
    out = {}
    for key, (ios, bytes_) in now.items():
        p_ios, p_bytes = prev.get(key, (0, 0))
        out[key] = (max(0, ios - p_ios), max(0, bytes_ - p_bytes))
    return out


def snapshot_hist(table) -> Dict[Tuple[int, int, int], int]:
    return {(k.dev, k.op, int(k.slot)): int(v.value) for k, v in table.items()}


def delta_hist(now, prev):
    out = {}
    for key, val in now.items():
        d = val - prev.get(key, 0)
        if d > 0:
            out[key] = d
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description="BCC block tracepoint observer for selected NVMe block devices")
    parser.add_argument("--mode", choices=["host"], default="host", help="observer mode; this script implements host mode")
    parser.add_argument("--devices", required=True, help="comma-separated block devices, e.g. /dev/nvme1n1,/dev/nvme3n1")
    parser.add_argument("--interval", type=float, default=1.0, help="print interval in seconds")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON lines")
    parser.add_argument("--hist", action="store_true", help="print log2 IO size histogram")
    parser.add_argument("--latency", action="store_true", help="track issue-to-complete latency histogram")
    parser.add_argument("--dry-run", action="store_true", help="validate devices and generated tracepoint assumptions without attaching")
    args = parser.parse_args()

    require_root()
    for msg in diagnostics():
        print(f"diagnostic: {msg}", file=sys.stderr)

    devs = {}
    for raw in args.devices.split(","):
        path = raw.strip()
        if not path:
            continue
        try:
            major, minor, key = linux_dev_key(path)
        except (OSError, ValueError) as exc:
            parser.error(str(exc))
        devs[key] = {"path": path, "major": major, "minor": minor, "dev": key}
    if not devs:
        parser.error("--devices did not contain any paths")

    issue_fmt = tracepoint_format("block/block_rq_issue")
    complete_fmt = tracepoint_format("block/block_rq_complete")
    has_issue = bool(issue_fmt)
    has_complete = bool(complete_fmt)
    has_bytes_issue = "field:" in issue_fmt and "bytes" in issue_fmt
    has_bytes_complete = "field:" in complete_fmt and "bytes" in complete_fmt
    if not has_issue or not has_complete:
        print("warning: block tracepoint format not readable; BCC compile may still work on the target host", file=sys.stderr)

    if args.dry_run:
        print(json_dumps({"devices": list(devs.values()), "has_bytes_issue": has_bytes_issue, "has_bytes_complete": has_bytes_complete}))
        return 0

    try:
        from bcc import BPF
    except Exception as exc:
        print(f"failed to import BCC: {exc}", file=sys.stderr)
        return 2

    b = BPF(text=build_bpf_text(has_bytes_issue, has_bytes_complete, args.latency))
    one = ct.c_ubyte(1)
    for dev in devs:
        b["filter_devs"][ct.c_uint32(dev)] = one

    dev_names = {dev: f"{meta['path']}({meta['major']}:{meta['minor']})" for dev, meta in devs.items()}
    print(f"observing: {', '.join(dev_names.values())}", file=sys.stderr)

    stop = False

    def _stop(_signo, _frame):
        nonlocal stop
        stop = True

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)
    prev_stats, prev_size, prev_lat = {}, {}, {}
    summary: Dict[Tuple[int, int], Tuple[int, int]] = {}
    while not stop:
        time.sleep(args.interval)
        now_stats = snapshot_hash(b["stats"])
        now_size = snapshot_hist(b["size_hist"])
        now_lat = snapshot_hist(b["lat_hist"])
        d_stats = delta_stats(now_stats, prev_stats)
        d_size = delta_hist(now_size, prev_size)
        d_lat = delta_hist(now_lat, prev_lat)
        prev_stats, prev_size, prev_lat = now_stats, now_size, now_lat
        ts = time.time()
        for key, val in d_stats.items():
            old = summary.get(key, (0, 0))
            summary[key] = (old[0] + val[0], old[1] + val[1])
        if args.json:
            rows = []
            for (dev, op), (ios, bytes_) in sorted(d_stats.items()):
                rows.append({"device": dev_names.get(dev, str(dev)), "op": OP_NAMES.get(op, "other"), "ios": ios, "bytes": bytes_, "avg_size": (bytes_ / ios if ios else 0)})
            print(json_dumps({"ts": ts, "interval": args.interval, "stats": rows}))
            continue
        print(time.strftime("%H:%M:%S"))
        for (dev, op), (ios, bytes_) in sorted(d_stats.items()):
            avg = bytes_ / ios if ios else 0
            print(f"{dev_names.get(dev, str(dev)):>24} {OP_NAMES.get(op, 'other'):<6} ios={ios:<10} bytes={bytes_:<12} avg_size={avg:.1f}")
        if args.hist:
            for dev in sorted(devs):
                for op in range(5):
                    rows = {slot: cnt for (d, o, slot), cnt in d_size.items() if d == dev and o == op}
                    print_log2_hist(f"size {dev_names[dev]} {OP_NAMES.get(op, 'other')}", rows, "bytes")
        if args.latency:
            for dev in sorted(devs):
                for op in range(5):
                    rows = {slot: cnt for (d, o, slot), cnt in d_lat.items() if d == dev and o == op}
                    print_log2_hist(f"latency {dev_names[dev]} {OP_NAMES.get(op, 'other')}", rows, "usec")

    print("summary", file=sys.stderr)
    for (dev, op), (ios, bytes_) in sorted(summary.items()):
        print(f"{dev_names.get(dev, str(dev))} {OP_NAMES.get(op, 'other')} ios={ios} bytes={bytes_}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
