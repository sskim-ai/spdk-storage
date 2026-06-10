# spdk-storage

BCC/eBPF observers for a BlueField/SNAP NVMe-oF deployment where the GPU host sees emulated NVMe block devices, the DPU/SNAP path forwards NVMe-oF traffic, and the storage server drives physical NVMe SSDs from SPDK through `vfio-pci`.

## Why separate observers exist

`bcc/tools/bitesize.py` watches Linux block-layer tracepoints. That is useful on the GPU host because `/dev/nvme1n1` and `/dev/nvme3n1` are Linux block devices exposed by BF3/SNAP. It is not sufficient on the storage server because SPDK owns the physical NVMe controller through `vfio-pci`; real SSD IO bypasses the kernel block layer, so `block:block_rq_issue` and `iostat` can legitimately show nothing.

```text
GPU host
  fio/app
    -> Linux nvme/block layer
    -> BF3/SNAP emulated NVMe device (/dev/nvme1n1, /dev/nvme3n1)
       observe: block tracepoints

DPU / fabric
  SNAP / NVMe-oF path
       observe: SNAP/SPDK userspace uprobes for ingress and egress

Storage server
  SPDK nvmf_tgt/spdk_tgt
    -> SPDK bdev/nvme userspace driver
    -> vfio-pci
    -> physical NVMe SSD
       observe: userspace uprobes on SPDK symbols
```

## Files

- `nvme_io_observe_host.py`: GPU host observer for selected Linux block devices.
- `snap_io_observe_dpu.py`: BlueField DPU/SNAP observer for host-command ingress and NVMe-oF egress.
- `spdk_io_observe_uprobe.py`: storage server observer for SPDK userspace submit/completion symbols.
- `common.py`: shared histogram, device, diagnostics, and symbol discovery helpers.
- `examples/`: shell examples for common runs.

## Requirements

- Ubuntu 24.04 target hosts.
- Python 3.
- BCC Python bindings (`python3-bcc` or distro equivalent).
- Root privileges or equivalent BPF/perf capabilities.
- Mounted tracefs/debugfs, usually `/sys/kernel/debug/tracing`.
- Kernel headers matching the running kernel.

## GPU Host Usage

```bash
sudo ./nvme_io_observe_host.py \
  --devices /dev/nvme1n1,/dev/nvme3n1 \
  --interval 1 \
  --hist \
  --latency
```

JSON output:

```bash
sudo ./nvme_io_observe_host.py --devices /dev/nvme1n1,/dev/nvme3n1 --interval 1 --json
```

Dry-run device and tracepoint assumptions:

```bash
./nvme_io_observe_host.py --devices /dev/nvme1n1,/dev/nvme3n1 --dry-run
```

The host tool filters by exact Linux `dev_t`: Python reads each device's major/minor with `stat(2)` and inserts `(major << 20) | minor` into a BPF map. The BPF program drops all other block IO.

Host output includes per-device read/write/flush/unmap/other IO counts, bytes, average IO size, log2 size histograms, and optional issue-to-complete latency histograms. Latency matching uses a composite key of `dev, sector, bytes, op` because the portable block tracepoint payload does not always expose a request pointer. This is usually good enough for per-device histogramming, but very high queue-depth repeated same-sector workloads can collide. Treat host latency histograms as approximate unless your tracepoint format exposes a stable request pointer and the code is extended to use it.

## Storage Server SPDK Usage

List discovered symbols:

```bash
sudo ./spdk_io_observe_uprobe.py \
  --pid $(pidof nvmf_tgt) \
  --binary /path/to/nvmf_tgt \
  --spdk-build-dir /path/to/spdk/build \
  --list-symbols
```

Run auto-detected submit observation. Symbol auto-detection is now the default; `--symbols-auto-detect` is accepted only as a deprecated no-op for compatibility.

```bash
sudo ./spdk_io_observe_uprobe.py \
  --pid $(pidof nvmf_tgt) \
  --binary /path/to/nvmf_tgt \
  --spdk-build-dir /path/to/spdk/build \
  --interval 1 \
  --hist
```

Force a known fixed-buffer NVMe submit symbol:

```bash
sudo ./spdk_io_observe_uprobe.py \
  --pid <pid> \
  --binary <binary> \
  --submit-symbol spdk_nvme_ns_cmd_read \
  --interval 1 \
  --hist \
  --lba-size 512
```

For `spdk_nvme_ns_cmd_read` and `spdk_nvme_ns_cmd_write`, the tool uses `lba_count * --lba-size` for size histograms. The default `--lba-size` is 512; set `--lba-size 4096` or the real namespace logical block size when needed.

Important: `spdk_nvme_ns_cmd_readv` and `spdk_nvme_ns_cmd_writev` are listed by `--list-symbols` but are **not auto-attached** for size accounting. Their prototype/argument order can differ by SPDK version/build, so attaching them as if arg5 is `lba_count` can produce bogus byte histograms. Use them manually only after verifying the SPDK 26.05 header/prototype for your exact build.

Latency can be requested:

```bash
sudo ./spdk_io_observe_uprobe.py \
  --pid $(pidof nvmf_tgt) \
  --binary /path/to/nvmf_tgt \
  --spdk-build-dir /path/to/spdk/build \
  --interval 1 \
  --hist \
  --latency
```

Latency is only reported when a compatible completion symbol is found and the submit path exposes a usable per-IO object pointer. Fixed-buffer NVMe API submit symbols do not expose a stable request pointer in this observer, so latency falls back to submit-side counts/histograms. Pointer-only request/bdev fallback modes may show IO counts while marking `bytes`, `avg_size`, and size histograms as unsupported.

Manual request-level latency can be attempted when you know the submit and completion functions expose the same request pointer:

```bash
sudo ./spdk_io_observe_uprobe.py \
  --pid $(pidof nvmf_tgt) \
  --binary /path/to/nvmf_tgt \
  --spdk-build-dir /path/to/spdk/build \
  --submit-symbol nvme_qpair_submit_request \
  --complete-symbol nvme_complete_request \
  --req-submit-arg 2 \
  --req-complete-arg 1 \
  --latency \
  --hist
```

Use `--submit-object` or `--complete-object` when a manual symbol lives in a shared library instead of `--binary`. The request pointer argument positions are SPDK-build and symbol dependent, so verify the prototype before relying on latency data.

## DPU/SNAP Observer

`snap_io_observe_dpu.py` runs inside the BlueField DPU environment or inside the SNAP container where the target process and libraries are visible. It separates the two DPU-side layers:

```text
GPU Host
  app/fio
    -> Linux block layer
    -> host NVMe driver
    -> BF3/SNAP emulated NVMe
DPU/SNAP
  ingress: host NVMe command received by SNAP
    -> SNAP/NVMe-oF initiator path
  egress: NVMe-oF/RDMA request sent toward storage
Storage server
  SPDK NVMe-oF target
    -> SPDK NVMe driver
    -> physical NVMe SSD
```

Basic run:

```bash
sudo ./snap_io_observe_dpu.py \
  --pid $(pidof <snap_process>) \
  --binary /path/to/snap_binary \
  --search-dir /path/to/snap/libs \
  --mode both \
  --interval 1 \
  --hist
```

Symbol discovery:

```bash
sudo ./snap_io_observe_dpu.py \
  --pid $(pidof <snap_process>) \
  --binary /path/to/snap_binary \
  --search-dir /path/to/snap/libs \
  --list-symbols
```

Dry-run the selected attach plan:

```bash
sudo ./snap_io_observe_dpu.py \
  --pid $(pidof <snap_process>) \
  --binary /path/to/snap_binary \
  --search-dir /path/to/snap/libs \
  --mode both \
  --dry-run
```

Start with egress first. This is the most reliable size path because fixed-buffer SPDK NVMe initiator APIs expose `lba_count`:

```bash
sudo ./snap_io_observe_dpu.py \
  --pid $(pidof <snap_process>) \
  --binary /path/to/snap_binary \
  --search-dir /path/to/snap/libs \
  --mode egress \
  --lba-size 512 \
  --hist
```

Ingress size usually needs a known SNAP command-processing symbol and argument. Without that, ingress is pointer-only and reports bytes as `unsupported` or JSON `null`:

```bash
sudo ./snap_io_observe_dpu.py \
  --pid $(pidof <snap_process>) \
  --binary /path/to/snap_binary \
  --search-dir /path/to/snap/libs \
  --mode ingress \
  --ingress-symbol <symbol> \
  --manual-size-arg 5 \
  --manual-size-mode lba_count \
  --manual-op read \
  --hist
```

Manual egress symbol example:

```bash
sudo ./snap_io_observe_dpu.py \
  --pid $(pidof <snap_process>) \
  --binary /path/to/snap_binary \
  --search-dir /path/to/snap/libs \
  --mode egress \
  --egress-symbol <symbol> \
  --egress-object /path/to/lib_or_binary \
  --manual-size-arg 5 \
  --manual-size-mode lba_count \
  --manual-op write
```

DPU container path discovery examples:

```bash
docker ps
docker exec -it <snap_container> bash
ps aux
find / -type f -perm -111 2>/dev/null | grep -Ei 'snap|spdk|nvmf|nvme'
find / -type f -name '*.so*' 2>/dev/null | grep -Ei 'snap|spdk|nvme|nvmf'
```

The DPU observer requires Python 3, BCC Python bindings, root or equivalent BPF/perf privileges, tracefs/debugfs, and kernel headers in the DPU/container environment where it runs. `--container` is only an operator note; the script does not force `docker exec` because path namespaces differ by deployment.

Interpretation:

- If GPU Host block size and DPU ingress size differ, reshaping may be happening in the host NVMe driver, PCIe emulation, or SNAP receive path.
- If DPU ingress and DPU egress differ, SNAP/NVMe-oF initiator split/merge/re-chunking may be happening.
- If DPU egress and Storage SPDK physical submit differ, the storage target, bdev, or NVMe layer may be splitting or merging requests.
- These layers measure different events and should not be treated as identical latency or media-size points.

## Symbol Discovery

The SPDK observer scans the target executable and `.so` files below `--spdk-build-dir` using available tools:

```bash
nm -an <binary> | grep spdk_nvme
nm -D <libspdk_nvme.so> | grep spdk_nvme_ns_cmd
readelf -Ws <binary> | grep bdev
objdump -t <binary> | grep nvme
```

Priority submit candidates include:

- `spdk_nvme_ns_cmd_read`, `spdk_nvme_ns_cmd_write` for automatic size accounting.
- `spdk_nvme_ns_cmd_readv`, `spdk_nvme_ns_cmd_writev` for manual/experimental attachment only after prototype verification.
- `nvme_qpair_submit_request`, `nvme_transport_qpair_submit_request` for pointer-based latency experiments.
- `spdk_bdev_io_submit`, `bdev_io_submit`, and bdev read/write variants as pointer-only fallbacks.

Priority completion candidates include:

- `spdk_bdev_io_complete`, `bdev_io_complete`
- `nvme_complete_request`
- `spdk_nvme_qpair_process_completions`, `nvme_pcie_qpair_process_completions`

SPDK may be static or dynamic. Dynamic builds usually attach to `libspdk_bdev.so`, `libspdk_nvme.so`, or `libspdk_nvmf.so`; static builds attach directly to `nvmf_tgt` or `spdk_tgt`.

## Build Recommendations

- Include debug symbols.
- Do not strip the target binary or SPDK shared libraries.
- Disable LTO where possible.
- Avoid inlining the specific function you want to probe.
- If needed, add a lightweight wrapper with `__attribute__((noinline))` around the submit/completion point, or use SPDK tracepoints/USDT.

This implementation deliberately avoids hardcoded SPDK struct offsets. It provides stable minimum observation by pointer and function arguments. Enhanced bdev name, namespace, controller, qpair, and exact opcode decoding should be added through DWARF/BTF/pahole-derived offset profiles or explicit SPDK wrapper/tracepoint support for your exact SPDK 26.05 build.

## Validation

1. On the GPU host, run `fio` against `/dev/nvme1n1` or `/dev/nvme3n1`.
2. Confirm `nvme_io_observe_host.py` shows the selected device only and that size histograms change.
3. Add `--latency` only after basic count/size validation.
4. On the storage server, run `spdk_io_observe_uprobe.py --list-symbols`.
5. Start the SPDK observer with fixed-buffer `spdk_nvme_ns_cmd_read/write` when possible and confirm submit counts increase during the same workload.
6. Compare counts with SPDK RPC/stat output where possible.
7. Expect `iostat` and Linux block tracepoints on the storage server to miss vfio-owned physical SSD IO.

## Troubleshooting

- `attach failed`: symbol may be missing, static/inlined, stripped, or BCC may not support pid filtering on that version.
- `symbol not found`: run `--list-symbols`, check `nm/readelf`, rebuild with symbols, disable LTO, and avoid strip.
- `Operation not permitted`: run as root or configure BPF/perf capabilities and kernel lockdown policy.
- `debugfs not mounted`: `mount -t debugfs debugfs /sys/kernel/debug`.
- `BCC version mismatch`: install matching BCC Python bindings and kernel headers; this code targets BCC 0.29 and 0.36 style APIs where practical.
- `BPF verifier rejected program`: check kernel headers, tracepoint fields, and simplify options such as disabling `--latency`.
- `no IO observed`: verify the device filter on the GPU host; on storage, verify the SPDK pid, binary path, symbol choice, and that the workload reaches that SPDK process.
- `bytes=unsupported`: the observer attached to a pointer-only request/bdev fallback path. Use fixed-buffer `spdk_nvme_ns_cmd_read/write` for size histograms, or add a SPDK wrapper/USDT tracepoint that exposes size/opcode explicitly.

## Limitations

- SPDK internal functions can be inline/static or stripped, making uprobes impossible.
- SNAP binaries may be stripped, statically linked, inlined, or proprietary with no public hot-path symbols.
- Function-boundary uprobes add overhead on very hot poll-mode IO paths.
- Per-IO latency is reliable only when submit and completion expose the same object pointer.
- Request pointer argument positions are build/symbol dependent; use `--req-submit-arg` and `--req-complete-arg` only after checking the selected SPDK function prototypes.
- readv/writev byte accounting is intentionally not automatic because incorrect argument assumptions can silently produce invalid histograms.
- DPU ingress size is often pointer-only unless a known SNAP symbol and size/lba_count argument are supplied manually.
- DPU egress size is most reliable when attaching to fixed-buffer `spdk_nvme_ns_cmd_read/write`; `readv/writev` are listed as manual/experimental and are not used for automatic size accounting.
- Host block latency, DPU/SNAP emulation latency, NVMe-oF network latency, SPDK queueing, and physical SSD media latency are different layers and must be interpreted separately.
- The host latency key can collide for repeated same-sector IO at high queue depth because portable block tracepoints do not expose a request pointer on all kernels.

## End-to-End Validation Order

1. On the DPU, identify the SNAP container/process.
2. Run `snap_io_observe_dpu.py --list-symbols`.
3. Run `snap_io_observe_dpu.py --dry-run` and inspect selected attach points.
4. Start with `--mode egress` and verify `spdk_nvme_ns_cmd_read/write` count and size histograms.
5. Add ingress only after choosing a reasonable SNAP symbol; expect pointer-only counts unless manual size arguments are known.
6. Run the GPU Host observer, DPU observer, and Storage SPDK observer during the same fio workload.
7. Compare histograms in this order: GPU Host block issue size, DPU/SNAP ingress size, DPU/SNAP egress size, Storage SPDK physical NVMe submit size.
