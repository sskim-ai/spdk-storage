#!/usr/bin/env python3
"""Observe BlueField DPU/SNAP RDMA-ZC IO sizes with BCC uprobes.

Validated SNAP path
-------------------
The current validated DPU/SNAP path uses the RDMA-ZC completion callbacks:

  snap_bdev_spdk_rdma_zc_read_done
  snap_bdev_spdk_rdma_zc_write_done

The verified argument/layout from the active snap_service binary is:

  zc_ctx     = C arg3 == bpftrace arg2 == PT_REGS_PARM3(ctx)
  req        = *(uint64_t *)(zc_ctx + 0x40)
  size_bytes = *(uint64_t *)(req + 0xd0)

Classification rule
-------------------
The observer always attaches to both RDMA-ZC done symbols and collects all sizes.
Per reporting interval, it classifies rows into three categories:

  read                         zc_read_done when no zc_write_done happened
  write                        zc_write_done
  internal_read_during_write   zc_read_done in an interval that also has writes

For intentionally mixed read+write workloads, zc_read_done cannot be separated
into host reads versus write-induced internal reads with this symbol set alone.
Such intervals are conservatively labeled internal_read_during_write.
"""

from __future__ import annotations

import argparse
import ctypes as ct
import signal
import sys
import time
from typing import Dict, Tuple

from common import diagnostics, json_dumps, print_log2_hist, require_root


READ_SYMBOL = "snap_bdev_spdk_rdma_zc_read_done"
WRITE_SYMBOL = "snap_bdev_spdk_rdma_zc_write_done"

DIR_EGRESS = 1
DIR_NAMES = {DIR_EGRESS: "egress"}

OP_READ = 0
OP_WRITE = 1
OP_INTERNAL_READ_DURING_WRITE = 5
OP_NAMES = {
    OP_READ: "read",
    OP_WRITE: "write",
    OP_INTERNAL_READ_DURING_WRITE: "internal_read_during_write",
}

MODE_DPU_RDMA_ZC_DONE = 6
MODE_NAMES = {MODE_DPU_RDMA_ZC_DONE: "dpu-rdma-zc-done"}


def parse_int_auto(value: str) -> int:
    return int(value, 0)


def arg_expr(n: int) -> str:
    return {
        1: "PT_REGS_PARM1(ctx)",
        2: "PT_REGS_PARM2(ctx)",
        3: "PT_REGS_PARM3(ctx)",
        4: "PT_REGS_PARM4(ctx)",
        5: "PT_REGS_PARM5(ctx)",
        6: "PT_REGS_PARM6(ctx)",
    }.get(n, "PT_REGS_PARM3(ctx)")


def build_bpf_text(args) -> str:
    zc_ctx_expr = arg_expr(args.zc_ctx_arg)
    return f"""
#include <uapi/linux/ptrace.h>

struct stat_key {{
    u32 direction;
    u32 op;
    u32 tid;
    u32 mode;
}};

struct stat_val {{
    u64 ios;
    u64 bytes;
    u64 sized_ios;
}};

struct hist_key {{
    u32 direction;
    u32 op;
    u32 tid;
    u64 slot;
}};

struct size_count_key {{
    u32 direction;
    u32 op;
    u32 tid;
    u32 bytes;
}};

struct comm_val {{
    char comm[16];
}};

BPF_HASH(stats, struct stat_key, struct stat_val);
BPF_HASH(size_hist, struct hist_key, u64);
BPF_HASH(size_counts, struct size_count_key, u64);
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

static __always_inline void increment_size_count(struct size_count_key *key)
{{
    u64 zero = 0, *val;
    val = size_counts.lookup(key);
    if (val) {{
        __sync_fetch_and_add(val, 1);
    }} else {{
        size_counts.update(key, &zero);
        val = size_counts.lookup(key);
        if (val) __sync_fetch_and_add(val, 1);
    }}
}}

static __always_inline int record_io(struct pt_regs *ctx, u32 op)
{{
    u64 zc_ctx = {zc_ctx_expr};
    u64 req = 0;
    u64 bytes = 0;

    bpf_probe_read_user(&req, sizeof(req), (void *)(zc_ctx + {args.zc_ctx_req_offset}ULL));
    if (req == 0) {{
        return 0;
    }}

    bpf_probe_read_user(&bytes, sizeof(bytes), (void *)(req + {args.req_size_offset}ULL));
    if (bytes == 0 || bytes > {args.max_size}ULL) {{
        return 0;
    }}

    u32 tid = (u32)bpf_get_current_pid_tgid();
    save_comm(tid);

    struct stat_key skey = {{}};
    skey.direction = {DIR_EGRESS};
    skey.op = op;
    skey.tid = tid;
    skey.mode = {MODE_DPU_RDMA_ZC_DONE};

    struct stat_val zero = {{}}, *val;
    val = stats.lookup(&skey);
    if (!val) {{
        stats.update(&skey, &zero);
        val = stats.lookup(&skey);
    }}
    if (val) {{
        __sync_fetch_and_add(&val->ios, 1);
        __sync_fetch_and_add(&val->bytes, bytes);
        __sync_fetch_and_add(&val->sized_ios, 1);
    }}

    struct hist_key hkey = {{}};
    hkey.direction = {DIR_EGRESS};
    hkey.op = op;
    hkey.tid = tid;
    hkey.slot = bpf_log2l(bytes ? bytes : 1);
    increment_size_hist(&hkey);

    struct size_count_key ckey = {{}};
    ckey.direction = {DIR_EGRESS};
    ckey.op = op;
    ckey.tid = tid;
    ckey.bytes = (u32)bytes;
    increment_size_count(&ckey);
    return 0;
}}

int trace_zc_read_done(struct pt_regs *ctx)
{{
    return record_io(ctx, {OP_READ});
}}

int trace_zc_write_done(struct pt_regs *ctx)
{{
    return record_io(ctx, {OP_WRITE});
}}
"""


class StatKey(ct.Structure):
    _fields_ = [
        ("direction", ct.c_uint32),
        ("op", ct.c_uint32),
        ("tid", ct.c_uint32),
        ("mode", ct.c_uint32),
    ]


class StatVal(ct.Structure):
    _fields_ = [("ios", ct.c_uint64), ("bytes", ct.c_uint64), ("sized_ios", ct.c_uint64)]


class HistKey(ct.Structure):
    _fields_ = [
        ("direction", ct.c_uint32),
        ("op", ct.c_uint32),
        ("tid", ct.c_uint32),
        ("slot", ct.c_uint64),
    ]


class SizeCountKey(ct.Structure):
    _fields_ = [
        ("direction", ct.c_uint32),
        ("op", ct.c_uint32),
        ("tid", ct.c_uint32),
        ("bytes", ct.c_uint32),
    ]


def attach_uprobe_compat(b, obj: str, sym: str, fn: str, pid: int) -> None:
    try:
        b.attach_uprobe(name=obj, sym=sym, fn_name=fn, pid=pid)
    except TypeError:
        b.attach_uprobe(name=obj, sym=sym, fn_name=fn)


def snapshot_stats(table) -> Dict[Tuple[int, int, int, int], Tuple[int, int, int]]:
    return {(int(k.direction), int(k.op), int(k.tid), int(k.mode)): (int(v.ios), int(v.bytes), int(v.sized_ios)) for k, v in table.items()}


def snapshot_hist(table) -> Dict[Tuple[int, int, int, int], int]:
    return {(int(k.direction), int(k.op), int(k.tid), int(k.slot)): int(v.value) for k, v in table.items()}


def snapshot_size_counts(table) -> Dict[Tuple[int, int, int, int], int]:
    return {(int(k.direction), int(k.op), int(k.tid), int(k.bytes)): int(v.value) for k, v in table.items()}


def delta_stats(now, prev):
    out = {}
    for key, val in now.items():
        old = prev.get(key, (0, 0, 0))
        delta = tuple(max(0, val[i] - old[i]) for i in range(3))
        if any(delta):
            out[key] = delta
    return out


def delta_counts(now, prev):
    return {k: v - prev.get(k, 0) for k, v in now.items() if v - prev.get(k, 0) > 0}


def thread_names(table) -> Dict[int, str]:
    out = {}
    for k, v in table.items():
        raw = bytes(v.comm).split(b"\0", 1)[0]
        out[int(k.value)] = raw.decode("utf-8", "replace")
    return out


def print_size_counts(title: str, rows: Dict[int, int]) -> None:
    if not rows:
        return
    print(title)
    for size in sorted(rows):
        print(f"  size_bytes={size:<12} count={rows[size]}")


def interval_has_write(d_stats: Dict[Tuple[int, int, int, int], Tuple[int, int, int]]) -> bool:
    return any(op == OP_WRITE and vals[0] > 0 for (_direction, op, _tid, _mode), vals in d_stats.items())


def relabel_read_op(op: int, has_write: bool) -> int:
    if op == OP_READ and has_write:
        return OP_INTERNAL_READ_DURING_WRITE
    return op


def relabel_stats(d_stats: Dict[Tuple[int, int, int, int], Tuple[int, int, int]], has_write: bool):
    out: Dict[Tuple[int, int, int, int], Tuple[int, int, int]] = {}
    for (direction, op, tid, mode), vals in d_stats.items():
        new_key = (direction, relabel_read_op(op, has_write), tid, mode)
        old = out.get(new_key, (0, 0, 0))
        out[new_key] = tuple(old[i] + vals[i] for i in range(3))
    return out


def relabel_counts(d_counts: Dict[Tuple[int, int, int, int], int], has_write: bool):
    out: Dict[Tuple[int, int, int, int], int] = {}
    for (direction, op, tid, last), value in d_counts.items():
        new_key = (direction, relabel_read_op(op, has_write), tid, last)
        out[new_key] = out.get(new_key, 0) + value
    return out


def parse_args():
    parser = argparse.ArgumentParser(description="BCC uprobe observer for validated BlueField DPU/SNAP RDMA-ZC IO sizes")
    parser.add_argument("--pid", type=int, help="snap_service host pid; limits uprobes when supported by BCC")
    parser.add_argument("--binary", required=True, help="path to snap_service, e.g. /proc/$pid/root/opt/nvidia/nvda_snap/bin/snap_service")
    parser.add_argument("--interval", type=float, default=1.0, help="print interval in seconds")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON lines")
    parser.add_argument("--hist", action="store_true", help="print log2 size histogram")
    parser.add_argument("--size-counts", action="store_true", help="print exact IO size byte counts")
    parser.add_argument("--zc-ctx-arg", type=int, default=3, choices=[1, 2, 3, 4, 5, 6], help="C argument index containing RDMA-ZC context; verified default 3 equals bpftrace arg2")
    parser.add_argument("--zc-ctx-req-offset", type=parse_int_auto, default=0x40, help="offset from RDMA-ZC context to original request pointer; default 0x40")
    parser.add_argument("--req-size-offset", type=parse_int_auto, default=0xD0, help="offset from original request to byte size; default 0xd0")
    parser.add_argument("--max-size", type=parse_int_auto, default=16 * 1024 * 1024, help="drop sizes above this byte value; default 16MiB")
    parser.add_argument("--dry-run", action="store_true", help="show selected attach plan without attaching")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    require_root()
    for msg in diagnostics():
        print(f"diagnostic: {msg}", file=sys.stderr)

    selected = {
        "mode": "dpu-snap-rdma-zc-done",
        "pid": args.pid,
        "binary": args.binary,
        "symbols": {
            READ_SYMBOL: "trace_zc_read_done",
            WRITE_SYMBOL: "trace_zc_write_done",
        },
        "categories": [OP_NAMES[OP_READ], OP_NAMES[OP_WRITE], OP_NAMES[OP_INTERNAL_READ_DURING_WRITE]],
        "classification": "zc_read_done is reported as read in intervals without writes, and internal_read_during_write in intervals with zc_write_done activity.",
        "layout": {
            "zc_ctx_arg": args.zc_ctx_arg,
            "zc_ctx_req_offset": args.zc_ctx_req_offset,
            "req_size_offset": args.req_size_offset,
        },
    }
    if args.dry_run:
        print(json_dumps(selected))
        return 0

    try:
        from bcc import BPF
    except Exception as exc:
        print(f"failed to import BCC: {exc}", file=sys.stderr)
        return 2

    b = BPF(text=build_bpf_text(args))
    pid = args.pid if args.pid is not None else -1
    attached = []
    try:
        attach_uprobe_compat(b, args.binary, READ_SYMBOL, "trace_zc_read_done", pid)
        attached.append(f"{READ_SYMBOL}@{args.binary}->trace_zc_read_done")
        attach_uprobe_compat(b, args.binary, WRITE_SYMBOL, "trace_zc_write_done", pid)
        attached.append(f"{WRITE_SYMBOL}@{args.binary}->trace_zc_write_done")
    except Exception as exc:
        print(f"attach failed: {exc}", file=sys.stderr)
        print("verify --binary path is visible from this mount namespace and contains the SNAP RDMA-ZC symbols", file=sys.stderr)
        return 2

    print("attached: " + ", ".join(attached), file=sys.stderr)
    print("mode=dpu-snap-rdma-zc-done bytes_supported=True", file=sys.stderr)
    print("classification: read intervals -> read; intervals with writes -> zc_read_done is internal_read_during_write", file=sys.stderr)

    stop = False

    def _stop(_signo, _frame):
        nonlocal stop
        stop = True

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    prev_stats, prev_hist, prev_size_counts = {}, {}, {}
    summary_stats: Dict[Tuple[int, int, int, int], Tuple[int, int, int]] = {}
    summary_size_counts: Dict[Tuple[int, int, int, int], int] = {}

    while not stop:
        time.sleep(args.interval)
        names = thread_names(b["thread_names"])
        now_stats = snapshot_stats(b["stats"])
        now_hist = snapshot_hist(b["size_hist"])
        now_size_counts = snapshot_size_counts(b["size_counts"])

        raw_d_stats = delta_stats(now_stats, prev_stats)
        raw_d_hist = delta_counts(now_hist, prev_hist)
        raw_d_size_counts = delta_counts(now_size_counts, prev_size_counts)
        prev_stats, prev_hist, prev_size_counts = now_stats, now_hist, now_size_counts

        has_write = interval_has_write(raw_d_stats)
        d_stats = relabel_stats(raw_d_stats, has_write)
        d_hist = relabel_counts(raw_d_hist, has_write)
        d_size_counts = relabel_counts(raw_d_size_counts, has_write)

        for key, val in d_stats.items():
            old = summary_stats.get(key, (0, 0, 0))
            summary_stats[key] = tuple(old[i] + val[i] for i in range(3))
        for key, val in d_size_counts.items():
            summary_size_counts[key] = summary_size_counts.get(key, 0) + val

        if args.json:
            rows = []
            for (direction, op, tid, mode), (ios, bytes_, sized_ios) in sorted(d_stats.items()):
                rows.append({
                    "direction": DIR_NAMES.get(direction, str(direction)),
                    "op": OP_NAMES.get(op, f"op{op}"),
                    "tid": tid,
                    "thread": names.get(tid, ""),
                    "attach_mode": MODE_NAMES.get(mode, str(mode)),
                    "ios": ios,
                    "bytes": bytes_,
                    "avg_size": (bytes_ / sized_ios if sized_ios else None),
                    "size_supported": bool(sized_ios),
                })
            size_rows = []
            for (direction, op, tid, size), count in sorted(d_size_counts.items()):
                size_rows.append({
                    "direction": DIR_NAMES.get(direction, str(direction)),
                    "op": OP_NAMES.get(op, f"op{op}"),
                    "tid": tid,
                    "thread": names.get(tid, ""),
                    "size_bytes": size,
                    "count": count,
                })
            print(json_dumps({"ts": time.time(), "interval": args.interval, "stats": rows, "size_counts": size_rows, "mode": "dpu-snap-rdma-zc-done"}))
            continue

        print(time.strftime("%H:%M:%S"))
        for (direction, op, tid, mode), (ios, bytes_, sized_ios) in sorted(d_stats.items()):
            avg = bytes_ / sized_ios if sized_ios else 0
            print(
                f"{DIR_NAMES.get(direction, str(direction)):<8} "
                f"{MODE_NAMES.get(mode, str(mode)):<20} "
                f"tid={tid:<8} comm={names.get(tid, ''):<16} "
                f"{OP_NAMES.get(op, f'op{op}'):<28} ios={ios:<10} bytes={bytes_:<14} avg_size={avg:.1f}"
            )

        if args.hist:
            for direction, op, tid in sorted({(d, o, t) for d, o, t, _ in d_hist}):
                rows = {slot: cnt for (d, o, t, slot), cnt in d_hist.items() if d == direction and o == op and t == tid}
                print_log2_hist(f"size {DIR_NAMES.get(direction, direction)} tid={tid} {names.get(tid, '')} {OP_NAMES.get(op, f'op{op}')}", rows, "bytes")

        if args.size_counts:
            for direction, op, tid in sorted({(d, o, t) for d, o, t, _ in d_size_counts}):
                rows = {size: cnt for (d, o, t, size), cnt in d_size_counts.items() if d == direction and o == op and t == tid}
                print_size_counts(f"size_counts {DIR_NAMES.get(direction, direction)} tid={tid} {names.get(tid, '')} {OP_NAMES.get(op, f'op{op}')}", rows)

    print("summary", file=sys.stderr)
    for (direction, op, tid, mode), (ios, bytes_, sized_ios) in sorted(summary_stats.items()):
        avg = bytes_ / sized_ios if sized_ios else 0
        print(f"{DIR_NAMES.get(direction, direction)} {MODE_NAMES.get(mode, mode)} tid={tid} {OP_NAMES.get(op, f'op{op}')} ios={ios} bytes={bytes_} avg_size={avg:.1f}", file=sys.stderr)
    if args.size_counts:
        print("summary_size_counts", file=sys.stderr)
        for (direction, op, tid, size), count in sorted(summary_size_counts.items()):
            print(f"{DIR_NAMES.get(direction, direction)} tid={tid} {OP_NAMES.get(op, f'op{op}')} size_bytes={size} count={count}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
