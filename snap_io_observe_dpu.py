#!/usr/bin/env python3
"""Observe validated BlueField DPU/SNAP RDMA-ZC IO sizes with BCC uprobes."""

from __future__ import annotations

import argparse
import ctypes as ct
import os
import signal
import subprocess
import sys
import time
from typing import Dict, Iterable, Optional, Tuple

from common import diagnostics, json_dumps, print_log2_hist, require_root

READ_SYMBOL = "snap_bdev_spdk_rdma_zc_read_done"
WRITE_SYMBOL = "snap_bdev_spdk_rdma_zc_write_done"
DIR_EGRESS = 1
DIR_NAMES = {DIR_EGRESS: "egress"}
OP_READ = 0
OP_WRITE = 1
OP_NAMES = {OP_READ: "read", OP_WRITE: "write"}
MODE_DPU_RDMA_ZC_DONE = 6
MODE_NAMES = {MODE_DPU_RDMA_ZC_DONE: "dpu-rdma-zc-done"}


def parse_int_auto(value: str) -> int:
    return int(value, 0)


def parse_device_map(value: str) -> Dict[int, str]:
    out: Dict[int, str] = {}
    if not value:
        return out
    for item in value.split(","):
        item = item.strip()
        if not item:
            continue
        if "=" not in item:
            raise argparse.ArgumentTypeError("device map entries must be key=name")
        key_s, name = item.split("=", 1)
        out[int(key_s, 0)] = name
    return out


def run_text(cmd: Iterable[str], timeout: float = 2.0) -> str:
    try:
        result = subprocess.run(list(cmd), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return result.stdout.strip()


def auto_pid() -> Optional[int]:
    out = run_text(["pgrep", "-n", "-f", "snap_service"])
    if not out:
        return None
    try:
        return int(out.splitlines()[-1].strip())
    except ValueError:
        return None


def auto_binary(pid: int) -> Optional[str]:
    if pid > 0:
        path = f"/proc/{pid}/root/opt/nvidia/nvda_snap/bin/snap_service"
        if os.path.exists(path):
            return path
        try:
            exe = os.readlink(f"/proc/{pid}/exe")
            if exe:
                return exe
        except OSError:
            pass
    path = "/opt/nvidia/nvda_snap/bin/snap_service"
    return path if os.path.exists(path) else None


def device_label(device_key: int, device_map: Dict[int, str]) -> str:
    return device_map.get(device_key, f"0x{device_key:x}")


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
struct stat_key {{ u64 device_key; u32 direction; u32 op; u32 tid; u32 mode; }};
struct stat_val {{ u64 ios; u64 bytes; u64 sized_ios; }};
struct hist_key {{ u64 device_key; u32 direction; u32 op; u32 tid; u64 slot; }};
struct size_count_key {{ u64 device_key; u32 direction; u32 op; u32 tid; u32 bytes; }};
struct comm_val {{ char comm[16]; }};
BPF_HASH(stats, struct stat_key, struct stat_val);
BPF_HASH(size_hist, struct hist_key, u64);
BPF_HASH(size_counts, struct size_count_key, u64);
BPF_HASH(thread_names, u32, struct comm_val);
static __always_inline void save_comm(u32 tid) {{
    struct comm_val val = {{}};
    bpf_get_current_comm(&val.comm, sizeof(val.comm));
    thread_names.update(&tid, &val);
}}
static __always_inline void inc_hist(struct hist_key *key) {{
    u64 zero = 0, *val = size_hist.lookup(key);
    if (!val) {{ size_hist.update(key, &zero); val = size_hist.lookup(key); }}
    if (val) __sync_fetch_and_add(val, 1);
}}
static __always_inline void inc_count(struct size_count_key *key) {{
    u64 zero = 0, *val = size_counts.lookup(key);
    if (!val) {{ size_counts.update(key, &zero); val = size_counts.lookup(key); }}
    if (val) __sync_fetch_and_add(val, 1);
}}
static __always_inline int record_io(struct pt_regs *ctx, u32 op) {{
    u64 zc_ctx = {zc_ctx_expr};
    u64 qctx = 0, device_key = 0, req = 0, bytes = 0;
    bpf_probe_read_user(&qctx, sizeof(qctx), (void *)(zc_ctx + {args.zc_ctx_qctx_offset}ULL));
    if (qctx == 0) return 0;
    bpf_probe_read_user(&device_key, sizeof(device_key), (void *)(qctx + {args.qctx_ctrl_offset}ULL));
    if (device_key == 0) return 0;
    bpf_probe_read_user(&req, sizeof(req), (void *)(zc_ctx + {args.zc_ctx_req_offset}ULL));
    if (req == 0) return 0;
    bpf_probe_read_user(&bytes, sizeof(bytes), (void *)(req + {args.req_size_offset}ULL));
    if (bytes == 0 || bytes > {args.max_size}ULL) return 0;
    u32 tid = (u32)bpf_get_current_pid_tgid();
    save_comm(tid);
    struct stat_key skey = {{}};
    skey.device_key = device_key; skey.direction = {DIR_EGRESS}; skey.op = op; skey.tid = tid; skey.mode = {MODE_DPU_RDMA_ZC_DONE};
    struct stat_val zero = {{}}, *val = stats.lookup(&skey);
    if (!val) {{ stats.update(&skey, &zero); val = stats.lookup(&skey); }}
    if (val) {{ __sync_fetch_and_add(&val->ios, 1); __sync_fetch_and_add(&val->bytes, bytes); __sync_fetch_and_add(&val->sized_ios, 1); }}
    struct hist_key hkey = {{}};
    hkey.device_key = device_key; hkey.direction = {DIR_EGRESS}; hkey.op = op; hkey.tid = tid; hkey.slot = bpf_log2l(bytes ? bytes : 1);
    inc_hist(&hkey);
    struct size_count_key ckey = {{}};
    ckey.device_key = device_key; ckey.direction = {DIR_EGRESS}; ckey.op = op; ckey.tid = tid; ckey.bytes = (u32)bytes;
    inc_count(&ckey);
    return 0;
}}
int trace_zc_read_done(struct pt_regs *ctx) {{ return record_io(ctx, {OP_READ}); }}
int trace_zc_write_done(struct pt_regs *ctx) {{ return record_io(ctx, {OP_WRITE}); }}
"""


class StatKey(ct.Structure):
    _fields_ = [("device_key", ct.c_uint64), ("direction", ct.c_uint32), ("op", ct.c_uint32), ("tid", ct.c_uint32), ("mode", ct.c_uint32)]


class StatVal(ct.Structure):
    _fields_ = [("ios", ct.c_uint64), ("bytes", ct.c_uint64), ("sized_ios", ct.c_uint64)]


class HistKey(ct.Structure):
    _fields_ = [("device_key", ct.c_uint64), ("direction", ct.c_uint32), ("op", ct.c_uint32), ("tid", ct.c_uint32), ("slot", ct.c_uint64)]


class SizeCountKey(ct.Structure):
    _fields_ = [("device_key", ct.c_uint64), ("direction", ct.c_uint32), ("op", ct.c_uint32), ("tid", ct.c_uint32), ("bytes", ct.c_uint32)]


def attach_uprobe_compat(b, obj: str, sym: str, fn: str, pid: int) -> None:
    try:
        b.attach_uprobe(name=obj, sym=sym, fn_name=fn, pid=pid)
    except TypeError:
        b.attach_uprobe(name=obj, sym=sym, fn_name=fn)


def snapshot_stats(table) -> Dict[Tuple[int, int, int, int, int], Tuple[int, int, int]]:
    return {(int(k.device_key), int(k.direction), int(k.op), int(k.tid), int(k.mode)): (int(v.ios), int(v.bytes), int(v.sized_ios)) for k, v in table.items()}


def snapshot_hist(table) -> Dict[Tuple[int, int, int, int, int], int]:
    return {(int(k.device_key), int(k.direction), int(k.op), int(k.tid), int(k.slot)): int(v.value) for k, v in table.items()}


def snapshot_size_counts(table) -> Dict[Tuple[int, int, int, int, int], int]:
    return {(int(k.device_key), int(k.direction), int(k.op), int(k.tid), int(k.bytes)): int(v.value) for k, v in table.items()}


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


def parse_args():
    parser = argparse.ArgumentParser(description="BCC uprobe observer for validated BlueField DPU/SNAP RDMA-ZC IO sizes")
    parser.add_argument("--pid", type=int, help="snap_service host pid; auto-detected when omitted")
    parser.add_argument("--binary", help="path to snap_service; auto-detected when omitted")
    parser.add_argument("--device-map", type=parse_device_map, default={}, help="optional comma-separated key=name map")
    parser.add_argument("--interval", type=float, default=1.0, help="print interval in seconds")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON lines")
    parser.add_argument("--hist", action="store_true", help="print log2 size histogram")
    parser.add_argument("--no-size-counts", action="store_true", help="disable exact IO size byte counts; enabled by default")
    parser.add_argument("--zc-ctx-arg", type=int, default=3, choices=[1, 2, 3, 4, 5, 6])
    parser.add_argument("--zc-ctx-qctx-offset", type=parse_int_auto, default=0x8)
    parser.add_argument("--qctx-ctrl-offset", type=parse_int_auto, default=0x0)
    parser.add_argument("--zc-ctx-req-offset", type=parse_int_auto, default=0x40)
    parser.add_argument("--req-size-offset", type=parse_int_auto, default=0xD0)
    parser.add_argument("--max-size", type=parse_int_auto, default=16 * 1024 * 1024)
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    require_root()
    for msg in diagnostics():
        print(f"diagnostic: {msg}", file=sys.stderr)

    pid = args.pid or auto_pid()
    if not pid:
        print("could not auto-detect snap_service pid; pass --pid", file=sys.stderr)
        return 2
    binary = args.binary or auto_binary(pid)
    if not binary:
        print("could not auto-detect snap_service binary; pass --binary", file=sys.stderr)
        return 2
    size_counts_enabled = not args.no_size_counts

    selected = {"mode": "dpu-snap-rdma-zc-done", "pid": pid, "binary": binary, "size_counts_enabled": size_counts_enabled}
    if args.dry_run:
        print(json_dumps(selected))
        return 0

    try:
        from bcc import BPF
    except Exception as exc:
        print(f"failed to import BCC: {exc}", file=sys.stderr)
        return 2

    b = BPF(text=build_bpf_text(args))
    try:
        attach_uprobe_compat(b, binary, READ_SYMBOL, "trace_zc_read_done", pid)
        attach_uprobe_compat(b, binary, WRITE_SYMBOL, "trace_zc_write_done", pid)
    except Exception as exc:
        print(f"attach failed: {exc}", file=sys.stderr)
        return 2

    print(f"attached: {READ_SYMBOL},{WRITE_SYMBOL}@{binary}", file=sys.stderr)
    print(f"mode=dpu-snap-rdma-zc-done pid={pid} binary={binary} device_key=ctrl size_counts={size_counts_enabled}", file=sys.stderr)

    stop = False

    def _stop(_signo, _frame):
        nonlocal stop
        stop = True

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    prev_stats, prev_hist, prev_size_counts = {}, {}, {}
    summary_stats: Dict[Tuple[int, int, int, int, int], Tuple[int, int, int]] = {}
    summary_size_counts: Dict[Tuple[int, int, int, int, int], int] = {}

    while not stop:
        time.sleep(args.interval)
        names = thread_names(b["thread_names"])
        now_stats = snapshot_stats(b["stats"])
        now_hist = snapshot_hist(b["size_hist"])
        now_size_counts = snapshot_size_counts(b["size_counts"])
        d_stats = delta_stats(now_stats, prev_stats)
        d_hist = delta_counts(now_hist, prev_hist)
        d_size_counts = delta_counts(now_size_counts, prev_size_counts)
        prev_stats, prev_hist, prev_size_counts = now_stats, now_hist, now_size_counts

        for key, val in d_stats.items():
            old = summary_stats.get(key, (0, 0, 0))
            summary_stats[key] = tuple(old[i] + val[i] for i in range(3))
        for key, val in d_size_counts.items():
            summary_size_counts[key] = summary_size_counts.get(key, 0) + val

        if args.json:
            rows = []
            for (device_key, direction, op, tid, mode), (ios, bytes_, sized_ios) in sorted(d_stats.items()):
                rows.append({"device_key": f"0x{device_key:x}", "device": device_label(device_key, args.device_map), "direction": DIR_NAMES.get(direction, str(direction)), "op": OP_NAMES.get(op, f"op{op}"), "tid": tid, "thread": names.get(tid, ""), "attach_mode": MODE_NAMES.get(mode, str(mode)), "ios": ios, "bytes": bytes_, "avg_size": bytes_ / sized_ios if sized_ios else None})
            size_rows = []
            if size_counts_enabled:
                for (device_key, direction, op, tid, size), count in sorted(d_size_counts.items()):
                    size_rows.append({"device_key": f"0x{device_key:x}", "device": device_label(device_key, args.device_map), "direction": DIR_NAMES.get(direction, str(direction)), "op": OP_NAMES.get(op, f"op{op}"), "tid": tid, "thread": names.get(tid, ""), "size_bytes": size, "count": count})
            print(json_dumps({"ts": time.time(), "interval": args.interval, "stats": rows, "size_counts": size_rows, "mode": "dpu-snap-rdma-zc-done"}))
            continue

        print(time.strftime("%H:%M:%S"))
        for (device_key, direction, op, tid, mode), (ios, bytes_, sized_ios) in sorted(d_stats.items()):
            avg = bytes_ / sized_ios if sized_ios else 0
            print(f"device={device_label(device_key, args.device_map):<18} device_key=0x{device_key:x} {DIR_NAMES.get(direction, str(direction)):<8} {MODE_NAMES.get(mode, str(mode)):<20} tid={tid:<8} comm={names.get(tid, ''):<16} {OP_NAMES.get(op, f'op{op}'):<8} ios={ios:<10} bytes={bytes_:<14} avg_size={avg:.1f}")

        if args.hist:
            for device_key, direction, op, tid in sorted({(dev, d, o, t) for dev, d, o, t, _ in d_hist}):
                rows = {slot: cnt for (dev, d, o, t, slot), cnt in d_hist.items() if dev == device_key and d == direction and o == op and t == tid}
                print_log2_hist(f"size device={device_label(device_key, args.device_map)} device_key=0x{device_key:x} {DIR_NAMES.get(direction, direction)} tid={tid} {names.get(tid, '')} {OP_NAMES.get(op, f'op{op}')}", rows, "bytes")

        if size_counts_enabled:
            for device_key, direction, op, tid in sorted({(dev, d, o, t) for dev, d, o, t, _ in d_size_counts}):
                rows = {size: cnt for (dev, d, o, t, size), cnt in d_size_counts.items() if dev == device_key and d == direction and o == op and t == tid}
                print_size_counts(f"size_counts device={device_label(device_key, args.device_map)} device_key=0x{device_key:x} {DIR_NAMES.get(direction, direction)} tid={tid} {names.get(tid, '')} {OP_NAMES.get(op, f'op{op}')}", rows)

    print("summary", file=sys.stderr)
    for (device_key, direction, op, tid, mode), (ios, bytes_, sized_ios) in sorted(summary_stats.items()):
        avg = bytes_ / sized_ios if sized_ios else 0
        print(f"device={device_label(device_key, args.device_map)} device_key=0x{device_key:x} {DIR_NAMES.get(direction, direction)} {MODE_NAMES.get(mode, mode)} tid={tid} {OP_NAMES.get(op, f'op{op}')} ios={ios} bytes={bytes_} avg_size={avg:.1f}", file=sys.stderr)
    if size_counts_enabled:
        print("summary_size_counts", file=sys.stderr)
        for (device_key, direction, op, tid, size), count in sorted(summary_size_counts.items()):
            print(f"device={device_label(device_key, args.device_map)} device_key=0x{device_key:x} {DIR_NAMES.get(direction, direction)} tid={tid} {OP_NAMES.get(op, f'op{op}')} size_bytes={size} count={count}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
