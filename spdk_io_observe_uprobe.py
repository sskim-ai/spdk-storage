#!/usr/bin/env python3
"""Observe SPDK/vfio userspace IO with BCC uprobes."""

from __future__ import annotations

import argparse
import ctypes as ct
import os
import signal
import sys
import time
from typing import Dict, Tuple

from common import (
    OP_NAMES,
    SymbolHit,
    choose_first,
    diagnostics,
    discover_symbols,
    iter_elf_objects,
    json_dumps,
    print_log2_hist,
    require_root,
)


NVME_SUBMIT_CANDIDATES = [
    "spdk_nvme_ns_cmd_read",
    "spdk_nvme_ns_cmd_write",
    "spdk_nvme_ns_cmd_readv",
    "spdk_nvme_ns_cmd_writev",
]

BDEV_SUBMIT_CANDIDATES = [
    "spdk_bdev_io_submit",
    "bdev_io_submit",
    "spdk_bdev_read",
    "spdk_bdev_write",
    "spdk_bdev_read_blocks",
    "spdk_bdev_write_blocks",
    "spdk_bdev_readv",
    "spdk_bdev_writev",
]

COMPLETE_CANDIDATES = [
    "spdk_bdev_io_complete",
    "bdev_io_complete",
    "nvme_complete_request",
    "spdk_nvme_qpair_process_completions",
    "nvme_pcie_qpair_process_completions",
]


def build_bpf_text(want_latency: bool, lba_size: int) -> str:
    latency_submit = (
        """
    if (req != 0) {
        struct start_val sv = {};
        sv.ts = bpf_ktime_get_ns();
        sv.op = op;
        starts.update(&req, &sv);
    }
"""
        if want_latency
        else ""
    )
    latency_complete = (
        """
    u64 req = PT_REGS_PARM1(ctx);
    struct start_val *sv = starts.lookup(&req);
    if (sv) {
        u64 delta_us = (bpf_ktime_get_ns() - sv->ts) / 1000;
        struct hist_key hk = {};
        hk.op = sv->op;
        hk.tid = (u32)bpf_get_current_pid_tgid();
        hk.slot = bpf_log2l(delta_us ? delta_us : 1);
        increment_lat_hist(&hk);
        starts.delete(&req);
    }
"""
        if want_latency
        else ""
    )
    return f"""
#include <uapi/linux/ptrace.h>

struct stat_key {{
    u32 op;
    u32 tid;
}};

struct stat_val {{
    u64 ios;
    u64 bytes;
}};

struct hist_key {{
    u32 op;
    u32 tid;
    u64 slot;
}};

struct start_val {{
    u64 ts;
    u32 op;
}};

BPF_HASH(stats, struct stat_key, struct stat_val);
BPF_HASH(size_hist, struct hist_key, u64);
BPF_HASH(lat_hist, struct hist_key, u64);
BPF_HASH(starts, u64, struct start_val);
struct comm_val {{
    char comm[16];
}};

BPF_HASH(thread_names, u32, struct comm_val);

static __always_inline void save_comm(u32 tid)
{{
    struct comm_val val = {{}};
    bpf_get_current_comm(&val.comm, sizeof(val.comm));
    thread_names.update(&tid, &val);
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

static __always_inline int submit_common(struct pt_regs *ctx, u32 op, u64 bytes, u64 req)
{{
    u32 tid = (u32)bpf_get_current_pid_tgid();
    save_comm(tid);
    struct stat_key key = {{}};
    key.op = op;
    key.tid = tid;
    struct stat_val zero = {{}}, *val;
    val = stats.lookup_or_try_init(&key, &zero);
    if (val) {{
        __sync_fetch_and_add(&val->ios, 1);
        __sync_fetch_and_add(&val->bytes, bytes);
    }}
    struct hist_key hk = {{}};
    hk.op = op;
    hk.tid = tid;
    hk.slot = bpf_log2l(bytes ? bytes : 1);
    increment_size_hist(&hk);
{latency_submit}
    return 0;
}}

int trace_nvme_read(struct pt_regs *ctx)
{{
    u64 lba_count = PT_REGS_PARM5(ctx);
    return submit_common(ctx, 0, lba_count * {lba_size}ULL, 0);
}}

int trace_nvme_write(struct pt_regs *ctx)
{{
    u64 lba_count = PT_REGS_PARM5(ctx);
    return submit_common(ctx, 1, lba_count * {lba_size}ULL, 0);
}}

int trace_bdev_submit(struct pt_regs *ctx)
{{
    return submit_common(ctx, 4, 0, PT_REGS_PARM1(ctx));
}}

int trace_complete(struct pt_regs *ctx)
{{
{latency_complete}
    return 0;
}}
"""


class StatKey(ct.Structure):
    _fields_ = [("op", ct.c_uint32), ("tid", ct.c_uint32)]


class StatVal(ct.Structure):
    _fields_ = [("ios", ct.c_uint64), ("bytes", ct.c_uint64)]


class HistKey(ct.Structure):
    _fields_ = [("op", ct.c_uint32), ("tid", ct.c_uint32), ("slot", ct.c_uint64)]


def attach_uprobe_compat(b, obj: str, sym: str, fn: str, pid: int) -> None:
    try:
        b.attach_uprobe(name=obj, sym=sym, fn_name=fn, pid=pid)
    except TypeError:
        b.attach_uprobe(name=obj, sym=sym, fn_name=fn)


def describe_hits(title: str, hits):
    print(title, file=sys.stderr)
    if not hits:
        print("  none", file=sys.stderr)
        return
    for h in hits:
        print(f"  {h.symbol} in {h.obj} via {h.source}", file=sys.stderr)


def snapshot_hash(table) -> Dict[Tuple[int, int], Tuple[int, int]]:
    return {(k.op, k.tid): (v.ios, v.bytes) for k, v in table.items()}


def delta_stats(now, prev):
    return {k: (max(0, v[0] - prev.get(k, (0, 0))[0]), max(0, v[1] - prev.get(k, (0, 0))[1])) for k, v in now.items()}


def snapshot_hist(table) -> Dict[Tuple[int, int, int], int]:
    return {(k.op, k.tid, int(k.slot)): int(v.value) for k, v in table.items()}


def delta_hist(now, prev):
    return {k: v - prev.get(k, 0) for k, v in now.items() if v - prev.get(k, 0) > 0}


def thread_names(table) -> Dict[int, str]:
    out = {}
    for k, v in table.items():
        raw = bytes(v.comm).split(b"\0", 1)[0]
        out[int(k.value)] = raw.decode("utf-8", "replace")
    return out


def manual_hit(symbol: str, objects) -> SymbolHit:
    return SymbolHit(obj=objects[0], symbol=symbol, source="manual")


def select_submit_hits(args, objects, submit_hits):
    if args.submit_symbol:
        return [manual_hit(args.submit_symbol, objects)]
    nvme_hits = [h for h in submit_hits if h.symbol in NVME_SUBMIT_CANDIDATES]
    if nvme_hits:
        seen = set()
        selected = []
        for sym in NVME_SUBMIT_CANDIDATES:
            for hit in nvme_hits:
                key = (hit.obj, hit.symbol)
                if hit.symbol == sym and key not in seen:
                    seen.add(key)
                    selected.append(hit)
                    break
        return selected
    first = choose_first(submit_hits, BDEV_SUBMIT_CANDIDATES)
    return [first] if first else []


def main() -> int:
    parser = argparse.ArgumentParser(description="BCC uprobe observer for SPDK userspace NVMe/vfio IO paths")
    parser.add_argument("--mode", choices=["spdk"], default="spdk", help="observer mode; this script implements spdk mode")
    parser.add_argument("--pid", type=int, help="SPDK process pid; limits uprobes when supported by BCC")
    parser.add_argument("--binary", required=True, help="path to nvmf_tgt, spdk_tgt, or target process executable")
    parser.add_argument("--spdk-build-dir", help="SPDK build directory to scan for libspdk_*.so")
    parser.add_argument("--interval", type=float, default=1.0, help="print interval in seconds")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON lines")
    parser.add_argument("--hist", action="store_true", help="print log2 size histogram")
    parser.add_argument("--latency", action="store_true", help="attempt pointer-based submit/complete latency")
    parser.add_argument("--symbols-auto-detect", action="store_true", help="scan binary/build-dir for candidate symbols")
    parser.add_argument("--submit-symbol", help="manual submit symbol; attaches to --binary unless symbol is discovered elsewhere")
    parser.add_argument("--complete-symbol", help="manual completion symbol for latency")
    parser.add_argument("--lba-size", type=int, default=512, help="NVMe logical block size for spdk_nvme_ns_cmd_* byte calculation")
    parser.add_argument("--list-symbols", action="store_true", help="list discovered candidate symbols and exit")
    parser.add_argument("--dry-run", action="store_true", help="show selected attach points without attaching")
    args = parser.parse_args()

    require_root()
    for msg in diagnostics():
        print(f"diagnostic: {msg}", file=sys.stderr)

    objects = iter_elf_objects(args.binary, args.spdk_build_dir)
    if not objects:
        parser.error("no binary/shared library objects found")
    submit_candidates = NVME_SUBMIT_CANDIDATES + BDEV_SUBMIT_CANDIDATES
    submit_hits = discover_symbols(objects, submit_candidates)
    complete_hits = discover_symbols(objects, COMPLETE_CANDIDATES)
    if args.list_symbols:
        describe_hits("submit candidates:", submit_hits)
        describe_hits("completion candidates:", complete_hits)
        return 0

    selected_submit_hits = select_submit_hits(args, objects, submit_hits)
    submit_hit = selected_submit_hits[0] if selected_submit_hits else None
    complete_hit = manual_hit(args.complete_symbol, objects) if args.complete_symbol else choose_first(complete_hits, COMPLETE_CANDIDATES)
    if not submit_hit:
        print("error: no attachable SPDK submit symbol found", file=sys.stderr)
        print("try: rebuild SPDK with debug symbols, disable LTO, do not strip binaries, or add a noinline wrapper/USDT tracepoint", file=sys.stderr)
        return 2
    nvme_api_submit = submit_hit.symbol in NVME_SUBMIT_CANDIDATES
    latency_supported = args.latency and bool(complete_hit) and not nvme_api_submit
    if args.latency and not latency_supported:
        reason = "NVMe API submit symbols do not expose a stable per-IO request pointer" if nvme_api_submit else "completion symbol not found"
        print(f"warning: latency unsupported because {reason}; submit counts and size histograms remain available", file=sys.stderr)

    selected = {
        "submit": [h.__dict__ for h in selected_submit_hits],
        "complete": complete_hit.__dict__ if complete_hit else None,
        "pid": args.pid,
        "lba_size": args.lba_size,
        "latency_supported": latency_supported,
    }
    if args.dry_run:
        print(json_dumps(selected))
        return 0

    try:
        from bcc import BPF
    except Exception as exc:
        print(f"failed to import BCC: {exc}", file=sys.stderr)
        return 2

    b = BPF(text=build_bpf_text(latency_supported, args.lba_size))
    pid = args.pid if args.pid is not None else -1
    attached = []
    nvme_submit_map = {
        "spdk_nvme_ns_cmd_read": "trace_nvme_read",
        "spdk_nvme_ns_cmd_readv": "trace_nvme_read",
        "spdk_nvme_ns_cmd_write": "trace_nvme_write",
        "spdk_nvme_ns_cmd_writev": "trace_nvme_write",
    }
    try:
        for hit in selected_submit_hits:
            fn = nvme_submit_map.get(hit.symbol, "trace_bdev_submit")
            attach_uprobe_compat(b, hit.obj, hit.symbol, fn, pid)
            attached.append(f"{hit.symbol}@{hit.obj}->{fn}")
        if latency_supported and complete_hit:
            attach_uprobe_compat(b, complete_hit.obj, complete_hit.symbol, "trace_complete", pid)
            attached.append(f"{complete_hit.symbol}@{complete_hit.obj}->trace_complete")
    except Exception as exc:
        print(f"attach failed: {exc}", file=sys.stderr)
        print("alternatives: include debug symbols, disable LTO, avoid strip, use SPDK tracepoints/USDT, or add __attribute__((noinline)) wrapper symbols", file=sys.stderr)
        return 2

    print("attached: " + ", ".join(attached), file=sys.stderr)
    stop = False

    def _stop(_signo, _frame):
        nonlocal stop
        stop = True

    signal.signal(signal.SIGINT, _stop)
    prev_stats, prev_size, prev_lat = {}, {}, {}
    summary: Dict[Tuple[int, int], Tuple[int, int]] = {}
    while not stop:
        time.sleep(args.interval)
        names = thread_names(b["thread_names"])
        now_stats = snapshot_hash(b["stats"])
        now_size = snapshot_hist(b["size_hist"])
        now_lat = snapshot_hist(b["lat_hist"])
        d_stats = delta_stats(now_stats, prev_stats)
        d_size = delta_hist(now_size, prev_size)
        d_lat = delta_hist(now_lat, prev_lat)
        prev_stats, prev_size, prev_lat = now_stats, now_size, now_lat
        for key, val in d_stats.items():
            old = summary.get(key, (0, 0))
            summary[key] = (old[0] + val[0], old[1] + val[1])
        if args.json:
            rows = []
            for (op, tid), (ios, bytes_) in sorted(d_stats.items()):
                rows.append({"op": OP_NAMES.get(op, "other"), "tid": tid, "thread": names.get(tid, ""), "ios": ios, "bytes": bytes_, "avg_size": (bytes_ / ios if ios else 0)})
            print(json_dumps({"ts": time.time(), "interval": args.interval, "stats": rows, "latency_supported": latency_supported}))
            continue
        print(time.strftime("%H:%M:%S"))
        for (op, tid), (ios, bytes_) in sorted(d_stats.items()):
            avg = bytes_ / ios if ios else 0
            print(f"tid={tid:<8} comm={names.get(tid, ''):<16} {OP_NAMES.get(op, 'other'):<6} ios={ios:<10} bytes={bytes_:<12} avg_size={avg:.1f}")
        if args.hist:
            for (op, tid) in sorted({(op, tid) for op, tid, _ in d_size}):
                rows = {slot: cnt for (o, t, slot), cnt in d_size.items() if o == op and t == tid}
                print_log2_hist(f"size tid={tid} {names.get(tid, '')} {OP_NAMES.get(op, 'other')}", rows, "bytes")
        if latency_supported:
            for (op, tid) in sorted({(op, tid) for op, tid, _ in d_lat}):
                rows = {slot: cnt for (o, t, slot), cnt in d_lat.items() if o == op and t == tid}
                print_log2_hist(f"latency tid={tid} {names.get(tid, '')} {OP_NAMES.get(op, 'other')}", rows, "usec")

    print("summary", file=sys.stderr)
    for (op, tid), (ios, bytes_) in sorted(summary.items()):
        print(f"tid={tid} {OP_NAMES.get(op, 'other')} ios={ios} bytes={bytes_}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
