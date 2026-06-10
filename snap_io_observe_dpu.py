#!/usr/bin/env python3
"""Observe BlueField DPU/SNAP ingress and egress IO sizes with BCC uprobes.

This observer is intentionally conservative:
- egress defaults to fixed-buffer SPDK NVMe read/write APIs when available.
- ingress is not auto-attached from fuzzy symbols unless --auto-ingress-fuzzy is set.
- latency is only attempted on egress request-pointer submit/completion paths.
"""

from __future__ import annotations

import argparse
import ctypes as ct
import os
import signal
import stat
import sys
import time
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from common import (
    OP_NAMES,
    SymbolHit,
    broad_symbols_from_object,
    choose_first,
    diagnostics,
    discover_symbols,
    json_dumps,
    print_log2_hist,
    require_root,
)


DIR_INGRESS = 0
DIR_EGRESS = 1

DIR_NAMES = {
    DIR_INGRESS: "ingress",
    DIR_EGRESS: "egress",
}

MODE_INGRESS_POINTER_ONLY = 0
MODE_INGRESS_NVME_CMD = 1
MODE_EGRESS_NVME_RW_SIZE = 2
MODE_EGRESS_REQUEST_POINTER = 3
MODE_MANUAL_SIZE = 4
MODE_UNSUPPORTED_SIZE = 5

MODE_NAMES = {
    MODE_INGRESS_POINTER_ONLY: "ingress-pointer-only",
    MODE_INGRESS_NVME_CMD: "ingress-nvme-cmd",
    MODE_EGRESS_NVME_RW_SIZE: "egress-nvme-rw-size",
    MODE_EGRESS_REQUEST_POINTER: "egress-request-pointer",
    MODE_MANUAL_SIZE: "manual-size",
    MODE_UNSUPPORTED_SIZE: "unsupported-size",
}

OP_READ = 0
OP_WRITE = 1
OP_FLUSH = 2
OP_UNMAP = 3
OP_OTHER = 4

MANUAL_OPS = {
    "read": OP_READ,
    "write": OP_WRITE,
    "flush": OP_FLUSH,
    "unmap": OP_UNMAP,
    "other": OP_OTHER,
}

DISCOVERY_KEYWORDS = [
    "snap",
    "nvme",
    "nvmf",
    "bdev",
    "rdma",
    "mlx5",
    "vfio",
    "pci",
    "submit",
    "request",
    "cmd",
    "complete",
    "process",
    "qpair",
]

INGRESS_KEYWORDS = [
    "snap",
    "nvme",
    "cmd",
    "request",
    "submit",
    "process",
    "emulation",
    "emul",
    "ctrlr",
    "qpair",
]

EGRESS_READ_CANDIDATES = [
    "spdk_nvme_ns_cmd_read",
]

EGRESS_WRITE_CANDIDATES = [
    "spdk_nvme_ns_cmd_write",
]

EGRESS_MANUAL_CANDIDATES = [
    "spdk_nvme_ns_cmd_readv",
    "spdk_nvme_ns_cmd_writev",
]

EGRESS_REQUEST_CANDIDATES = [
    "nvme_qpair_submit_request",
    "nvme_transport_qpair_submit_request",
]

COMPLETE_CANDIDATES = [
    "nvme_complete_request",
    "spdk_nvme_qpair_process_completions",
    "nvme_pcie_qpair_process_completions",
]


def arg_expr(n: int) -> str:
    return {
        1: "PT_REGS_PARM1(ctx)",
        2: "PT_REGS_PARM2(ctx)",
        3: "PT_REGS_PARM3(ctx)",
        4: "PT_REGS_PARM4(ctx)",
        5: "PT_REGS_PARM5(ctx)",
        6: "PT_REGS_PARM6(ctx)",
    }.get(n, "PT_REGS_PARM1(ctx)")


def candidate_objects(binary: Optional[str], search_dir: Optional[str]) -> List[str]:
    seen = set()
    objects: List[str] = []
    if binary and os.path.exists(binary):
        path = os.path.realpath(binary)
        seen.add(path)
        objects.append(path)
    if not search_dir or not os.path.isdir(search_dir):
        return objects
    name_keywords = tuple(k.lower() for k in ("snap", "spdk", "nvmf", "nvme", "rdma", "mlx5", "bdev"))
    for root, _, files in os.walk(search_dir):
        for name in files:
            low = name.lower()
            path = os.path.join(root, name)
            try:
                st = os.stat(path)
            except OSError:
                continue
            is_shared = name.endswith(".so") or ".so." in name
            is_exec = bool(st.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
            if not (is_shared or (is_exec and any(k in low for k in name_keywords))):
                continue
            real = os.path.realpath(path)
            if real not in seen:
                seen.add(real)
                objects.append(real)
    return objects


def score_ingress_symbol(symbol: str) -> int:
    low = symbol.lower()
    score = 0
    for word in ("snap", "nvme", "cmd", "request", "submit", "process", "emul", "ctrlr", "qpair"):
        if word in low:
            score += 2
    for bad in ("complete", "destroy", "free", "delete", "cleanup", "admin"):
        if bad in low:
            score -= 2
    return score


def score_egress_symbol(symbol: str) -> int:
    low = symbol.lower()
    score = 0
    for word in ("nvme", "nvmf", "rdma", "submit", "request", "qpair", "send", "transport", "mlx5"):
        if word in low:
            score += 2
    for bad in ("complete", "poll", "process_completions", "destroy", "free", "delete", "cleanup"):
        if bad in low:
            score -= 1
    return score


def discover_ingress(objects: Sequence[str]) -> List[SymbolHit]:
    hits: List[SymbolHit] = []
    for obj in objects:
        for sym, source in broad_symbols_from_object(obj, INGRESS_KEYWORDS).items():
            if score_ingress_symbol(sym) > 2:
                hits.append(SymbolHit(obj=obj, symbol=sym, source=source))
    return sorted(hits, key=lambda h: (-score_ingress_symbol(h.symbol), h.obj, h.symbol))


def discover_egress_fuzzy(objects: Sequence[str]) -> List[SymbolHit]:
    hits: List[SymbolHit] = []
    for obj in objects:
        for sym, source in broad_symbols_from_object(obj, DISCOVERY_KEYWORDS).items():
            if score_egress_symbol(sym) > 2:
                hits.append(SymbolHit(obj=obj, symbol=sym, source=source))
    return sorted(hits, key=lambda h: (-score_egress_symbol(h.symbol), h.obj, h.symbol))


def discover_all_candidates(objects: Sequence[str]) -> Dict[str, List[SymbolHit]]:
    egress_read = discover_symbols(objects, EGRESS_READ_CANDIDATES)
    egress_write = discover_symbols(objects, EGRESS_WRITE_CANDIDATES)
    egress_manual = discover_symbols(objects, EGRESS_MANUAL_CANDIDATES)
    egress_req = discover_symbols(objects, EGRESS_REQUEST_CANDIDATES)
    complete = discover_symbols(objects, COMPLETE_CANDIDATES)
    return {
        "ingress": discover_ingress(objects),
        "egress_read": egress_read,
        "egress_write": egress_write,
        "egress_manual": egress_manual,
        "egress_request": egress_req,
        "egress_fuzzy": discover_egress_fuzzy(objects),
        "completion": complete,
    }


def build_bpf_text(args, enable_latency: bool) -> str:
    manual_arg = arg_expr(args.manual_size_arg or 1)
    req_submit_arg = arg_expr(args.req_submit_arg)
    req_complete_arg = arg_expr(args.req_complete_arg)
    manual_op = MANUAL_OPS[args.manual_op]
    manual_bytes_expr = f"((u64){manual_arg})"
    if args.manual_size_mode == "lba_count":
        manual_bytes_expr = f"((u64){manual_arg}) * {args.lba_size}ULL"

    latency_start = """
    if (req != 0) {
        struct start_val sv = {};
        sv.ts = bpf_ktime_get_ns();
        sv.direction = 1;
        sv.op = 4;
        starts.update(&req, &sv);
    }
"""
    latency_complete = """
    u64 req = REQ_COMPLETE_EXPR;
    struct start_val *sv = starts.lookup(&req);
    if (sv) {
        u64 delta_us = (bpf_ktime_get_ns() - sv->ts) / 1000;
        struct hist_key hk = {};
        hk.direction = sv->direction;
        hk.op = sv->op;
        hk.tid = (u32)bpf_get_current_pid_tgid();
        hk.slot = bpf_log2l(delta_us ? delta_us : 1);
        increment_lat_hist(&hk);
        starts.delete(&req);
    }
""".replace("REQ_COMPLETE_EXPR", req_complete_arg)
    if not enable_latency:
        latency_start = ""
        latency_complete = ""

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

struct start_val {{
    u64 ts;
    u32 direction;
    u32 op;
}};

struct comm_val {{
    char comm[16];
}};

BPF_HASH(stats, struct stat_key, struct stat_val);
BPF_HASH(size_hist, struct hist_key, u64);
BPF_HASH(lat_hist, struct hist_key, u64);
BPF_HASH(starts, u64, struct start_val);
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

static __always_inline int record_io(struct pt_regs *ctx, u32 direction, u32 op, u32 mode, u64 bytes, u32 has_size)
{{
    u32 tid = (u32)bpf_get_current_pid_tgid();
    save_comm(tid);

    struct stat_key key = {{}};
    key.direction = direction;
    key.op = op;
    key.tid = tid;
    key.mode = mode;

    struct stat_val zero = {{}}, *val;
    val = stats.lookup(&key);
    if (!val) {{
        stats.update(&key, &zero);
        val = stats.lookup(&key);
    }}
    if (val) {{
        __sync_fetch_and_add(&val->ios, 1);
        if (has_size) {{
            __sync_fetch_and_add(&val->bytes, bytes);
            __sync_fetch_and_add(&val->sized_ios, 1);
        }}
    }}

    if (has_size) {{
        struct hist_key hk = {{}};
        hk.direction = direction;
        hk.op = op;
        hk.tid = tid;
        hk.slot = bpf_log2l(bytes ? bytes : 1);
        increment_size_hist(&hk);
    }}
    return 0;
}}

int trace_ingress_pointer(struct pt_regs *ctx)
{{
    return record_io(ctx, 0, 4, 0, 0, 0);
}}

int trace_manual_ingress(struct pt_regs *ctx)
{{
    return record_io(ctx, 0, {manual_op}, 4, {manual_bytes_expr}, 1);
}}

int trace_egress_read(struct pt_regs *ctx)
{{
    u64 lba_count = PT_REGS_PARM5(ctx);
    return record_io(ctx, 1, 0, 2, lba_count * {args.lba_size}ULL, 1);
}}

int trace_egress_write(struct pt_regs *ctx)
{{
    u64 lba_count = PT_REGS_PARM5(ctx);
    return record_io(ctx, 1, 1, 2, lba_count * {args.lba_size}ULL, 1);
}}

int trace_egress_request(struct pt_regs *ctx)
{{
    u64 req = {req_submit_arg};
    record_io(ctx, 1, 4, 3, 0, 0);
{latency_start}
    return 0;
}}

int trace_manual_egress(struct pt_regs *ctx)
{{
    return record_io(ctx, 1, {manual_op}, 4, {manual_bytes_expr}, 1);
}}

int trace_complete(struct pt_regs *ctx)
{{
{latency_complete}
    return 0;
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


def attach_uprobe_compat(b, obj: str, sym: str, fn: str, pid: int) -> None:
    try:
        b.attach_uprobe(name=obj, sym=sym, fn_name=fn, pid=pid)
    except TypeError:
        b.attach_uprobe(name=obj, sym=sym, fn_name=fn)


def hit_to_dict(hit: Optional[SymbolHit], confidence: Optional[str] = None, size_supported: Optional[bool] = None):
    if not hit:
        return None
    out = {"obj": hit.obj, "symbol": hit.symbol, "source": hit.source}
    if confidence is not None:
        out["confidence"] = confidence
    if size_supported is not None:
        out["size_supported"] = size_supported
    return out


def manual_hit(symbol: Optional[str], obj: Optional[str], objects: Sequence[str]) -> Optional[SymbolHit]:
    if not symbol:
        return None
    if not obj:
        if not objects:
            raise ValueError("manual symbol requires --binary, --search-dir, or an explicit object path")
        obj = objects[0]
    return SymbolHit(obj=obj, symbol=symbol, source="manual")


def choose_symbol_plan(args, objects: Sequence[str], hits: Dict[str, List[SymbolHit]]):
    plan = {
        "ingress": None,
        "ingress_confidence": None,
        "egress_read": None,
        "egress_write": None,
        "egress_request": None,
        "completion": None,
        "manual_egress": None,
    }

    if args.mode in ("ingress", "both"):
        manual_ingress = manual_hit(args.ingress_symbol, args.ingress_object, objects)
        if manual_ingress:
            plan["ingress"] = manual_ingress
            plan["ingress_confidence"] = "manual"
        elif args.auto_ingress_fuzzy and hits["ingress"]:
            plan["ingress"] = hits["ingress"][0]
            plan["ingress_confidence"] = "fuzzy-low"
        else:
            plan["ingress_confidence"] = "disabled"

    if args.mode in ("egress", "both"):
        plan["manual_egress"] = manual_hit(args.egress_symbol, args.egress_object, objects)
        if not plan["manual_egress"]:
            plan["egress_read"] = choose_first(hits["egress_read"], EGRESS_READ_CANDIDATES)
            plan["egress_write"] = choose_first(hits["egress_write"], EGRESS_WRITE_CANDIDATES)
            if args.latency or (not plan["egress_read"] and not plan["egress_write"]):
                plan["egress_request"] = choose_first(hits["egress_request"], EGRESS_REQUEST_CANDIDATES)
        if args.latency:
            plan["completion"] = choose_first(hits["completion"], COMPLETE_CANDIDATES)

    return plan


def print_symbol_group(title: str, hits: Iterable[SymbolHit], limit: int = 80) -> None:
    print(title)
    shown = 0
    for hit in hits:
        print(f"  {hit.symbol} in {hit.obj} via {hit.source}")
        shown += 1
        if shown >= limit:
            print(f"  ... truncated after {limit} candidates")
            break
    if shown == 0:
        print("  none")


def snapshot_stats(table) -> Dict[Tuple[int, int, int, int], Tuple[int, int, int]]:
    return {(k.direction, k.op, k.tid, k.mode): (v.ios, v.bytes, v.sized_ios) for k, v in table.items()}


def delta_stats(now, prev):
    out = {}
    for key, val in now.items():
        old = prev.get(key, (0, 0, 0))
        out[key] = tuple(max(0, val[i] - old[i]) for i in range(3))
    return out


def snapshot_hist(table) -> Dict[Tuple[int, int, int, int], int]:
    return {(k.direction, k.op, k.tid, int(k.slot)): int(v.value) for k, v in table.items()}


def delta_hist(now, prev):
    return {k: v - prev.get(k, 0) for k, v in now.items() if v - prev.get(k, 0) > 0}


def thread_names(table) -> Dict[int, str]:
    out = {}
    for k, v in table.items():
        raw = bytes(v.comm).split(b"\0", 1)[0]
        out[int(k.value)] = raw.decode("utf-8", "replace")
    return out


def parse_args():
    parser = argparse.ArgumentParser(description="BCC uprobe observer for BlueField DPU/SNAP ingress and egress IO")
    parser.add_argument("--pid", type=int, help="SNAP/SPDK process pid; limits uprobes when supported by BCC")
    parser.add_argument("--binary", help="path to SNAP/SPDK target executable")
    parser.add_argument("--search-dir", help="directory containing SNAP/SPDK shared libraries or binaries")
    parser.add_argument("--container", help="container name for operator notes only; this script does not run docker exec")
    parser.add_argument("--mode", choices=["ingress", "egress", "both"], default="egress", help="which DPU path to observe; default is egress because ingress requires verified SNAP symbols")
    parser.add_argument("--interval", type=float, default=1.0, help="print interval in seconds")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON lines")
    parser.add_argument("--hist", action="store_true", help="print log2 size and latency histograms")
    parser.add_argument("--latency", action="store_true", help="attempt egress request-pointer submit/complete latency")
    parser.add_argument("--lba-size", type=int, default=512, help="logical block size for fixed-buffer spdk_nvme_ns_cmd_read/write")
    parser.add_argument("--list-symbols", action="store_true", help="list ingress/egress candidate symbols and exit")
    parser.add_argument("--dry-run", action="store_true", help="show selected attach plan without attaching")
    parser.add_argument("--auto-ingress-fuzzy", action="store_true", help="allow fuzzy ingress auto-attach; unsafe until manually validated")
    parser.add_argument("--ingress-symbol", help="manual ingress symbol")
    parser.add_argument("--ingress-object", help="object path for --ingress-symbol")
    parser.add_argument("--egress-symbol", help="manual egress symbol")
    parser.add_argument("--egress-object", help="object path for --egress-symbol")
    parser.add_argument("--req-submit-arg", type=int, default=1, choices=[1, 2, 3, 4, 5, 6], help="argument index containing request/object pointer")
    parser.add_argument("--req-complete-arg", type=int, default=1, choices=[1, 2, 3, 4, 5, 6], help="completion argument index containing the same request/object pointer")
    parser.add_argument("--manual-size-arg", type=int, choices=[1, 2, 3, 4, 5, 6], help="manual symbol argument containing bytes or lba_count")
    parser.add_argument("--manual-size-mode", choices=["bytes", "lba_count"], default="bytes", help="interpret --manual-size-arg as bytes or lba_count")
    parser.add_argument("--manual-op", choices=sorted(MANUAL_OPS), default="other", help="operation for manual-size symbols")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    require_root()
    for msg in diagnostics():
        print(f"diagnostic: {msg}", file=sys.stderr)
    if args.container:
        print(f"container note: inspect paths inside {args.container}; pass container-visible binary/lib paths to this script when running inside it", file=sys.stderr)

    objects = candidate_objects(args.binary, args.search_dir)
    if not objects:
        print("error: no binary or ELF objects found; pass --binary and/or --search-dir", file=sys.stderr)
        return 2

    hits = discover_all_candidates(objects)
    if args.list_symbols:
        print_symbol_group("ingress fuzzy candidates (listing only; not auto-attached unless --auto-ingress-fuzzy is used):", hits["ingress"])
        print_symbol_group("egress fixed-buffer read candidates:", hits["egress_read"])
        print_symbol_group("egress fixed-buffer write candidates:", hits["egress_write"])
        print_symbol_group("egress manual/experimental readv/writev candidates:", hits["egress_manual"])
        print_symbol_group("egress request-pointer candidates:", hits["egress_request"])
        print_symbol_group("egress fuzzy SNAP/SPDK/RDMA candidates:", hits["egress_fuzzy"])
        print_symbol_group("completion candidates:", hits["completion"])
        return 0

    try:
        plan = choose_symbol_plan(args, objects, hits)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.mode in ("ingress", "both") and not plan.get("ingress"):
        print("note: ingress is not attached because no --ingress-symbol was provided and --auto-ingress-fuzzy is not set", file=sys.stderr)
        print("      run --list-symbols first, then pass a verified --ingress-symbol/--manual-size-arg for meaningful ingress data", file=sys.stderr)
    if plan.get("ingress_confidence") == "fuzzy-low":
        print("warning: fuzzy ingress attach selected; treat ingress counts as unverified until the symbol is confirmed to be the SNAP host-command path", file=sys.stderr)

    latency_supported = bool(args.latency and plan.get("egress_request") and plan.get("completion"))
    if args.latency and not latency_supported:
        print("warning: latency unsupported because a matching egress request submit and completion symbol were not selected", file=sys.stderr)
    if args.latency and latency_supported and (plan.get("egress_read") or plan.get("egress_write")):
        print("note: latency rows use egress-request-pointer mode; size rows use egress-nvme-rw-size mode. Do not sum these modes as one IO count.", file=sys.stderr)

    selected = {
        "mode": args.mode,
        "pid": args.pid,
        "lba_size": args.lba_size,
        "latency_supported": latency_supported,
        "manual_size_arg": args.manual_size_arg,
        "manual_size_mode": args.manual_size_mode,
        "manual_op": args.manual_op,
        "auto_ingress_fuzzy": args.auto_ingress_fuzzy,
        "ingress": hit_to_dict(plan.get("ingress"), plan.get("ingress_confidence"), bool(args.manual_size_arg and args.ingress_symbol)),
        "egress_read": hit_to_dict(plan.get("egress_read"), "exact", True),
        "egress_write": hit_to_dict(plan.get("egress_write"), "exact", True),
        "egress_request": hit_to_dict(plan.get("egress_request"), "request-pointer", False),
        "manual_egress": hit_to_dict(plan.get("manual_egress"), "manual", bool(args.manual_size_arg)),
        "completion": hit_to_dict(plan.get("completion"), "completion", False),
    }
    if args.dry_run:
        print(json_dumps(selected))
        return 0

    try:
        from bcc import BPF
    except Exception as exc:
        print(f"failed to import BCC: {exc}", file=sys.stderr)
        return 2

    b = BPF(text=build_bpf_text(args, latency_supported))
    pid = args.pid if args.pid is not None else -1
    attached: List[str] = []
    try:
        if plan.get("ingress"):
            fn = "trace_manual_ingress" if args.manual_size_arg and args.ingress_symbol else "trace_ingress_pointer"
            attach_uprobe_compat(b, plan["ingress"].obj, plan["ingress"].symbol, fn, pid)
            attached.append(f"{plan['ingress'].symbol}@{plan['ingress'].obj}->{fn}")
        if plan.get("manual_egress"):
            fn = "trace_manual_egress" if args.manual_size_arg else "trace_egress_request"
            attach_uprobe_compat(b, plan["manual_egress"].obj, plan["manual_egress"].symbol, fn, pid)
            attached.append(f"{plan['manual_egress'].symbol}@{plan['manual_egress'].obj}->{fn}")
        if plan.get("egress_read"):
            attach_uprobe_compat(b, plan["egress_read"].obj, plan["egress_read"].symbol, "trace_egress_read", pid)
            attached.append(f"{plan['egress_read'].symbol}@{plan['egress_read'].obj}->trace_egress_read")
        if plan.get("egress_write"):
            attach_uprobe_compat(b, plan["egress_write"].obj, plan["egress_write"].symbol, "trace_egress_write", pid)
            attached.append(f"{plan['egress_write'].symbol}@{plan['egress_write'].obj}->trace_egress_write")
        if plan.get("egress_request"):
            attach_uprobe_compat(b, plan["egress_request"].obj, plan["egress_request"].symbol, "trace_egress_request", pid)
            attached.append(f"{plan['egress_request'].symbol}@{plan['egress_request'].obj}->trace_egress_request")
        if latency_supported:
            attach_uprobe_compat(b, plan["completion"].obj, plan["completion"].symbol, "trace_complete", pid)
            attached.append(f"{plan['completion'].symbol}@{plan['completion'].obj}->trace_complete")
    except Exception as exc:
        print(f"attach failed: {exc}", file=sys.stderr)
        print("fallbacks: run --list-symbols/--dry-run, rebuild with symbols, avoid strip/LTO, or add noinline SNAP/SPDK wrapper symbols", file=sys.stderr)
        return 2
    if not attached:
        print("error: no attachable symbols selected", file=sys.stderr)
        print("fallbacks: for egress, verify spdk_nvme_ns_cmd_read/write are visible; for ingress, specify --ingress-symbol manually or add noinline SNAP wrapper symbols", file=sys.stderr)
        return 2
    print("attached: " + ", ".join(attached), file=sys.stderr)

    stop = False

    def _stop(_signo, _frame):
        nonlocal stop
        stop = True

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)
    prev_stats, prev_size, prev_lat = {}, {}, {}
    summary: Dict[Tuple[int, int, int, int], Tuple[int, int, int]] = {}
    while not stop:
        time.sleep(args.interval)
        names = thread_names(b["thread_names"])
        now_stats = snapshot_stats(b["stats"])
        now_size = snapshot_hist(b["size_hist"])
        now_lat = snapshot_hist(b["lat_hist"])
        d_stats = delta_stats(now_stats, prev_stats)
        d_size = delta_hist(now_size, prev_size)
        d_lat = delta_hist(now_lat, prev_lat)
        prev_stats, prev_size, prev_lat = now_stats, now_size, now_lat
        for key, val in d_stats.items():
            old = summary.get(key, (0, 0, 0))
            summary[key] = tuple(old[i] + val[i] for i in range(3))
        if args.json:
            rows = []
            for (direction, op, tid, mode), (ios, bytes_, sized_ios) in sorted(d_stats.items()):
                rows.append({
                    "direction": DIR_NAMES.get(direction, str(direction)),
                    "op": OP_NAMES.get(op, "other"),
                    "tid": tid,
                    "thread": names.get(tid, ""),
                    "attach_mode": MODE_NAMES.get(mode, str(mode)),
                    "ios": ios,
                    "bytes": bytes_ if sized_ios else None,
                    "avg_size": (bytes_ / sized_ios if sized_ios else None),
                    "size_supported": bool(sized_ios),
                })
            print(json_dumps({"ts": time.time(), "interval": args.interval, "stats": rows, "latency_supported": latency_supported}))
            continue
        print(time.strftime("%H:%M:%S"))
        for (direction, op, tid, mode), (ios, bytes_, sized_ios) in sorted(d_stats.items()):
            if sized_ios:
                avg = f"{bytes_ / sized_ios:.1f}"
                bytes_s = str(bytes_)
            else:
                avg = "unsupported"
                bytes_s = "unsupported"
            print(
                f"{DIR_NAMES.get(direction, str(direction)):<8} "
                f"{MODE_NAMES.get(mode, str(mode)):<23} "
                f"tid={tid:<8} comm={names.get(tid, ''):<16} "
                f"{OP_NAMES.get(op, 'other'):<6} ios={ios:<10} bytes={bytes_s:<14} avg_size={avg}"
            )
        if args.hist:
            for direction, op, tid in sorted({(d, o, t) for d, o, t, _ in d_size}):
                rows = {slot: cnt for (d, o, t, slot), cnt in d_size.items() if d == direction and o == op and t == tid}
                print_log2_hist(f"size {DIR_NAMES.get(direction, direction)} tid={tid} {names.get(tid, '')} {OP_NAMES.get(op, 'other')}", rows, "bytes")
            if latency_supported:
                for direction, op, tid in sorted({(d, o, t) for d, o, t, _ in d_lat}):
                    rows = {slot: cnt for (d, o, t, slot), cnt in d_lat.items() if d == direction and o == op and t == tid}
                    print_log2_hist(f"latency {DIR_NAMES.get(direction, direction)} tid={tid} {names.get(tid, '')} {OP_NAMES.get(op, 'other')}", rows, "usec")

    print("summary", file=sys.stderr)
    for (direction, op, tid, mode), (ios, bytes_, sized_ios) in sorted(summary.items()):
        bytes_s = str(bytes_) if sized_ios else "unsupported"
        print(f"{DIR_NAMES.get(direction, direction)} {MODE_NAMES.get(mode, mode)} tid={tid} {OP_NAMES.get(op, 'other')} ios={ios} bytes={bytes_s}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
