#!/usr/bin/env python3
"""Observe the validated SPDK backend NVMe bdev submit path with BCC uprobes.

Default behavior is intentionally optimized for the user's verified Storage path:

  symbol      = bdev_nvme_submit_request
  arg2        = struct spdk_bdev_io *bdev_io
  device_key  = *(uint64_t *)(bdev_io + 0x0)      # struct spdk_bdev *
  io_type     = *(uint8_t  *)(bdev_io + 0x8)
  num_blocks  = *(uint64_t *)(bdev_io + 0x250)

The observer groups IO by device_key and resolves device_key -> SPDK bdev name
through gdb by default. Use --no-auto-device-names to disable this.
"""

from __future__ import annotations

import argparse
import ctypes as ct
import os
import re
import signal
import subprocess
import sys
import time
from typing import Dict, Iterable, Optional, Tuple

from common import diagnostics, json_dumps, print_log2_hist, require_root


SUBMIT_SYMBOL = "bdev_nvme_submit_request"

OP_READ = 0
OP_WRITE = 1
OP_OTHER = 4
OP_NAMES = {
    OP_READ: "read",
    OP_WRITE: "write",
    OP_OTHER: "other",
}


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
    for cmd in (["pidof", "nvmf_tgt"], ["pidof", "spdk_tgt"]):
        out = run_text(cmd)
        if out:
            try:
                return int(out.split()[0])
            except ValueError:
                pass
    out = run_text(["pgrep", "-n", "-f", "nvmf_tgt|spdk_tgt"])
    if out:
        try:
            return int(out.splitlines()[-1].strip())
        except ValueError:
            return None
    return None


def auto_binary(pid: int) -> Optional[str]:
    if pid > 0:
        exe = f"/proc/{pid}/exe"
        try:
            path = os.readlink(exe)
            if path:
                return path
        except OSError:
            pass
    for path in (
        "/root/bin/nvmf_tgt",
        "/root/spdk/build/bin/nvmf_tgt",
        "/usr/local/bin/nvmf_tgt",
        "/root/bin/spdk_tgt",
        "/root/spdk/build/bin/spdk_tgt",
        "/usr/local/bin/spdk_tgt",
    ):
        if os.path.exists(path):
            return path
    return None


def resolve_bdev_name_with_gdb(pid: int, device_key: int, gdb_path: str, timeout: float) -> Optional[str]:
    if pid <= 0 or device_key == 0:
        return None
    expr = f"((struct spdk_bdev *)0x{device_key:x})->name"
    cmd = [
        gdb_path,
        "-q",
        "-batch",
        "-p",
        str(pid),
        "-ex",
        "set pagination off",
        "-ex",
        f"x/s {expr}",
        "-ex",
        "detach",
    ]
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    matches = re.findall(r'"([^"\\]*(?:\\.[^"\\]*)*)"', result.stdout or "")
    if not matches:
        return None
    name = bytes(matches[-1], "utf-8").decode("unicode_escape", "replace")
    return name or None


def build_bpf_text(args) -> str:
    return f"""
#include <uapi/linux/ptrace.h>

struct stat_key {{
    u64 device_key;
    u32 op;
    u32 tid;
}};

struct stat_val {{
    u64 ios;
    u64 bytes;
}};

struct hist_key {{
    u64 device_key;
    u32 op;
    u32 tid;
    u64 slot;
}};

struct size_count_key {{
    u64 device_key;
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

static __always_inline void inc_stat(struct stat_key *key, u64 bytes)
{{
    struct stat_val zero = {{}}, *val;
    val = stats.lookup(key);
    if (!val) {{
        stats.update(key, &zero);
        val = stats.lookup(key);
    }}
    if (val) {{
        __sync_fetch_and_add(&val->ios, 1);
        __sync_fetch_and_add(&val->bytes, bytes);
    }}
}}

static __always_inline void inc_hist(struct hist_key *key)
{{
    u64 zero = 0, *val;
    val = size_hist.lookup(key);
    if (!val) {{
        size_hist.update(key, &zero);
        val = size_hist.lookup(key);
    }}
    if (val) __sync_fetch_and_add(val, 1);
}}

static __always_inline void inc_size_count(struct size_count_key *key)
{{
    u64 zero = 0, *val;
    val = size_counts.lookup(key);
    if (!val) {{
        size_counts.update(key, &zero);
        val = size_counts.lookup(key);
    }}
    if (val) __sync_fetch_and_add(val, 1);
}}

int trace_bdev_nvme_submit_request(struct pt_regs *ctx)
{{
    u64 bdev_io = PT_REGS_PARM2(ctx);
    u64 device_key = 0;
    u8 io_type = 0;
    u64 num_blocks = 0;

    bpf_probe_read_user(&device_key, sizeof(device_key), (void *)(bdev_io + {args.bdev_io_bdev_offset}ULL));
    bpf_probe_read_user(&io_type, sizeof(io_type), (void *)(bdev_io + {args.bdev_io_type_offset}ULL));
    bpf_probe_read_user(&num_blocks, sizeof(num_blocks), (void *)(bdev_io + {args.bdev_io_num_blocks_offset}ULL));

    u32 op = {OP_OTHER};
    if (io_type == {args.bdev_io_read_type}) {{
        op = {OP_READ};
    }} else if (io_type == {args.bdev_io_write_type}) {{
        op = {OP_WRITE};
    }}

    u64 bytes = num_blocks * {args.lba_size}ULL;
    u32 tid = (u32)bpf_get_current_pid_tgid();
    save_comm(tid);

    struct stat_key sk = {{}};
    sk.device_key = device_key;
    sk.op = op;
    sk.tid = tid;
    inc_stat(&sk, bytes);

    if (bytes > 0) {{
        struct hist_key hk = {{}};
        hk.device_key = device_key;
        hk.op = op;
        hk.tid = tid;
        hk.slot = bpf_log2l(bytes);
        inc_hist(&hk);

        struct size_count_key ck = {{}};
        ck.device_key = device_key;
        ck.op = op;
        ck.tid = tid;
        ck.bytes = (u32)bytes;
        inc_size_count(&ck);
    }}
    return 0;
}}
"""


class StatKey(ct.Structure):
    _fields_ = [("device_key", ct.c_uint64), ("op", ct.c_uint32), ("tid", ct.c_uint32)]


class StatVal(ct.Structure):
    _fields_ = [("ios", ct.c_uint64), ("bytes", ct.c_uint64)]


class HistKey(ct.Structure):
    _fields_ = [("device_key", ct.c_uint64), ("op", ct.c_uint32), ("tid", ct.c_uint32), ("slot", ct.c_uint64)]


class SizeCountKey(ct.Structure):
    _fields_ = [("device_key", ct.c_uint64), ("op", ct.c_uint32), ("tid", ct.c_uint32), ("bytes", ct.c_uint32)]


def snapshot_stats(table) -> Dict[Tuple[int, int, int], Tuple[int, int]]:
    return {(int(k.device_key), int(k.op), int(k.tid)): (int(v.ios), int(v.bytes)) for k, v in table.items()}


def snapshot_hist(table) -> Dict[Tuple[int, int, int, int], int]:
    return {(int(k.device_key), int(k.op), int(k.tid), int(k.slot)): int(v.value) for k, v in table.items()}


def snapshot_size_counts(table) -> Dict[Tuple[int, int, int, int], int]:
    return {(int(k.device_key), int(k.op), int(k.tid), int(k.bytes)): int(v.value) for k, v in table.items()}


def delta_stats(now, prev):
    return {k: (max(0, v[0] - prev.get(k, (0, 0))[0]), max(0, v[1] - prev.get(k, (0, 0))[1])) for k, v in now.items() if v != prev.get(k, (0, 0))}


def delta_counts(now, prev):
    return {k: v - prev.get(k, 0) for k, v in now.items() if v - prev.get(k, 0) > 0}


def thread_names(table) -> Dict[int, str]:
    out: Dict[int, str] = {}
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


def attach_uprobe_compat(b, obj: str, sym: str, fn: str, pid: int) -> None:
    try:
        b.attach_uprobe(name=obj, sym=sym, fn_name=fn, pid=pid)
    except TypeError:
        b.attach_uprobe(name=obj, sym=sym, fn_name=fn)


def main() -> int:
    parser = argparse.ArgumentParser(description="BCC uprobe observer for validated SPDK bdev_nvme_submit_request IO path")
    parser.add_argument("--pid", type=int, help="SPDK target pid; auto-detected from nvmf_tgt/spdk_tgt when omitted")
    parser.add_argument("--binary", help="path to nvmf_tgt/spdk_tgt executable; auto-detected from /proc/<pid>/exe when omitted")
    parser.add_argument("--submit-symbol", default=SUBMIT_SYMBOL, help="submit symbol to attach; default bdev_nvme_submit_request")
    parser.add_argument("--device-map", type=parse_device_map, default={}, help="optional comma-separated key=name map, e.g. 0xb3c...=Nvme0n1")
    parser.add_argument("--no-auto-device-names", action="store_true", help="disable automatic SPDK bdev name resolution through gdb")
    parser.add_argument("--gdb-path", default="gdb", help="gdb executable for automatic device-name resolution")
    parser.add_argument("--device-name-timeout", type=float, default=3.0, help="seconds to wait for each gdb device-name lookup")
    parser.add_argument("--interval", type=float, default=1.0, help="print interval in seconds")
    parser.add_argument("--json", action="store_true", help="emit JSON lines")
    parser.add_argument("--hist", action="store_true", help="print log2 size histogram")
    parser.add_argument("--no-size-counts", action="store_true", help="disable exact IO size byte counts; enabled by default")
    parser.add_argument("--lba-size", type=int, default=512, help="logical block size used for block-to-byte conversion")
    parser.add_argument("--bdev-io-bdev-offset", type=parse_int_auto, default=0x0, help="offset of struct spdk_bdev_io.bdev/device pointer")
    parser.add_argument("--bdev-io-type-offset", type=parse_int_auto, default=0x8, help="offset of struct spdk_bdev_io.type")
    parser.add_argument("--bdev-io-num-blocks-offset", type=parse_int_auto, default=0x250, help="offset of struct spdk_bdev_io.u.bdev.num_blocks")
    parser.add_argument("--bdev-io-read-type", type=parse_int_auto, default=1, help="SPDK_BDEV_IO_TYPE_READ numeric value")
    parser.add_argument("--bdev-io-write-type", type=parse_int_auto, default=2, help="SPDK_BDEV_IO_TYPE_WRITE numeric value")
    parser.add_argument("--dry-run", action="store_true", help="show selected attach plan without attaching")
    args = parser.parse_args()

    require_root()
    for msg in diagnostics():
        print(f"diagnostic: {msg}", file=sys.stderr)

    pid = args.pid or auto_pid()
    if not pid:
        parser.error("could not auto-detect SPDK target pid; pass --pid")
    binary = args.binary or auto_binary(pid)
    if not binary:
        parser.error("could not auto-detect SPDK target binary; pass --binary")
    size_counts_enabled = not args.no_size_counts
    auto_device_names = not args.no_auto_device_names

    selected = {
        "pid": pid,
        "binary": binary,
        "submit_symbol": args.submit_symbol,
        "size_counts_enabled": size_counts_enabled,
        "auto_device_names": auto_device_names,
        "device_key": "*(struct spdk_bdev_io + bdev_io_bdev_offset)",
        "offsets": {
            "bdev_io_bdev_offset": args.bdev_io_bdev_offset,
            "bdev_io_type_offset": args.bdev_io_type_offset,
            "bdev_io_num_blocks_offset": args.bdev_io_num_blocks_offset,
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
    try:
        attach_uprobe_compat(b, binary, args.submit_symbol, "trace_bdev_nvme_submit_request", pid)
    except Exception as exc:
        print(f"attach failed: {exc}", file=sys.stderr)
        print("check --binary, --submit-symbol, debug symbols, strip/LTO, or pass the exact executable path", file=sys.stderr)
        return 2

    print(f"attached: {args.submit_symbol}@{binary}->trace_bdev_nvme_submit_request", file=sys.stderr)
    print(f"mode=spdk-bdev-nvme-submit-request pid={pid} binary={binary} size_counts={size_counts_enabled} auto_device_names={auto_device_names}", file=sys.stderr)

    device_map = dict(args.device_map)
    unresolved_device_keys = set()

    def label_for(device_key: int) -> str:
        if device_key in device_map:
            return device_map[device_key]
        if auto_device_names and device_key != 0 and device_key not in unresolved_device_keys:
            name = resolve_bdev_name_with_gdb(pid, device_key, args.gdb_path, args.device_name_timeout)
            if name:
                device_map[device_key] = name
                print(f"resolved_device device_key=0x{device_key:x} name={name}", file=sys.stderr)
                return name
            unresolved_device_keys.add(device_key)
            print(f"warning: failed to resolve device_key=0x{device_key:x} via gdb", file=sys.stderr)
        return f"0x{device_key:x}"

    stop = False

    def _stop(_signo, _frame):
        nonlocal stop
        stop = True

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    prev_stats, prev_hist, prev_size_counts = {}, {}, {}
    summary: Dict[Tuple[int, int, int], Tuple[int, int]] = {}
    summary_size_counts: Dict[Tuple[int, int, int, int], int] = {}

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
            old = summary.get(key, (0, 0))
            summary[key] = (old[0] + val[0], old[1] + val[1])
        for key, val in d_size_counts.items():
            summary_size_counts[key] = summary_size_counts.get(key, 0) + val

        if args.json:
            rows = []
            for (device_key, op, tid), (ios, bytes_) in sorted(d_stats.items()):
                rows.append({
                    "device_key": f"0x{device_key:x}",
                    "device": label_for(device_key),
                    "op": OP_NAMES.get(op, "other"),
                    "tid": tid,
                    "thread": names.get(tid, ""),
                    "ios": ios,
                    "bytes": bytes_,
                    "avg_size": bytes_ / ios if ios else 0,
                })
            size_rows = []
            if size_counts_enabled:
                for (device_key, op, tid, size), count in sorted(d_size_counts.items()):
                    size_rows.append({
                        "device_key": f"0x{device_key:x}",
                        "device": label_for(device_key),
                        "op": OP_NAMES.get(op, "other"),
                        "tid": tid,
                        "thread": names.get(tid, ""),
                        "size_bytes": size,
                        "count": count,
                    })
            print(json_dumps({"ts": time.time(), "interval": args.interval, "stats": rows, "size_counts": size_rows, "mode": "spdk-bdev-nvme-submit-request"}))
            continue

        print(time.strftime("%H:%M:%S"))
        for (device_key, op, tid), (ios, bytes_) in sorted(d_stats.items()):
            avg = bytes_ / ios if ios else 0
            print(f"device={label_for(device_key):<18} device_key=0x{device_key:x} tid={tid:<8} comm={names.get(tid, ''):<16} {OP_NAMES.get(op, 'other'):<6} ios={ios:<10} bytes={bytes_:<12} avg_size={avg:.1f}")

        if args.hist:
            for device_key, op, tid in sorted({(dev, op, tid) for dev, op, tid, _ in d_hist}):
                rows = {slot: cnt for (dev, o, t, slot), cnt in d_hist.items() if dev == device_key and o == op and t == tid}
                print_log2_hist(f"size_hist device={label_for(device_key)} device_key=0x{device_key:x} tid={tid} {names.get(tid, '')} {OP_NAMES.get(op, 'other')}", rows, "bytes")

        if size_counts_enabled:
            for device_key, op, tid in sorted({(dev, op, tid) for dev, op, tid, _ in d_size_counts}):
                rows = {size: cnt for (dev, o, t, size), cnt in d_size_counts.items() if dev == device_key and o == op and t == tid}
                print_size_counts(f"size_counts device={label_for(device_key)} device_key=0x{device_key:x} tid={tid} {names.get(tid, '')} {OP_NAMES.get(op, 'other')}", rows)

    print("summary", file=sys.stderr)
    for (device_key, op, tid), (ios, bytes_) in sorted(summary.items()):
        print(f"device={label_for(device_key)} device_key=0x{device_key:x} tid={tid} {OP_NAMES.get(op, 'other')} ios={ios} bytes={bytes_}", file=sys.stderr)
    if size_counts_enabled:
        print("summary_size_counts", file=sys.stderr)
        for (device_key, op, tid, size), count in sorted(summary_size_counts.items()):
            print(f"device={label_for(device_key)} device_key=0x{device_key:x} tid={tid} {OP_NAMES.get(op, 'other')} size_bytes={size} count={count}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
