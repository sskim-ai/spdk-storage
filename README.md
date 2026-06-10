# spdk-storage

BCC/eBPF observers for a BlueField/SNAP NVMe-oF deployment where the GPU host sees emulated NVMe block devices, but the storage server drives physical NVMe SSDs from SPDK through `vfio-pci`.

## Why two observers exist

`bcc/tools/bitesize.py` watches Linux block-layer tracepoints. That is useful on the GPU host because `/dev/nvme1n1` and `/dev/nvme3n1` are Linux block devices exposed by BF3/SNAP. It is not sufficient on the storage server because SPDK owns the physical NVMe controller through `vfio-pci`; real SSD IO bypasses the kernel block layer, so `block:block_rq_issue` and `iostat` can legitimately show nothing.

```text
GPU host
  fio/app
    -> Linux nvme/block layer
    -> BF3/SNAP emulated NVMe device (/dev/nvme1n1, /dev/nvme3n1)
       observe: block tracepoints

DPU / fabric
  SNAP / NVMe-oF path
       interpret separately from host block latency

Storage server
  SPDK nvmf_tgt/spdk_tgt
    -> SPDK bdev/nvme userspace driver
    -> vfio-pci
    -> physical NVMe SSD
       observe: userspace uprobes on SPDK symbols
```

## Files

- `nvme_io_observe_host.py`: GPU host observer for selected Linux block devices.
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

Host output includes per-device read/write/flush/unmap/other IO counts, bytes, average IO size, log2 size histograms, and optional issue-to-complete latency histograms. Latency matching uses a composite key of `dev, sector, bytes, op` because the portable block tracepoint payload does not always expose a request pointer. This is usually good enough for per-device histogramming, but very high queue-depth repeated same-sector workloads can collide.

## Storage Server SPDK Usage

List discovered symbols:

```bash
sudo ./spdk_io_observe_uprobe.py \
  --pid $(pidof nvmf_tgt) \
  --binary /path/to/nvmf_tgt \
  --spdk-build-dir /path/to/spdk/build \
  --list-symbols
```

Run auto-detected submit observation:

```bash
sudo ./spdk_io_observe_uprobe.py \
  --pid $(pidof nvmf_tgt) \
  --binary /path/to/nvmf_tgt \
  --spdk-build-dir /path/to/spdk/build \
  --interval 1 \
  --hist \
  --symbols-auto-detect
```

Force a known NVMe submit symbol:

```bash
sudo ./spdk_io_observe_uprobe.py \
  --pid <pid> \
  --binary <binary> \
  --submit-symbol spdk_nvme_ns_cmd_read \
  --interval 1 \
  --hist
```

If read/write NVMe API symbols are attachable, the tool uses `lba_count * --lba-size` for size histograms. The default `--lba-size` is 512; set `--lba-size 4096` or the real namespace logical block size when needed.

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

Latency is only reported when a compatible completion symbol is found. The submit key is the SPDK object pointer available at the selected layer, such as a bdev IO pointer or NVMe qpair/request-related pointer. If submit and completion are from different SPDK layers, matching can be wrong; the tool warns and falls back to submit-side counts/histograms when no completion symbol is usable.

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

## Symbol Discovery

The SPDK observer scans the target executable and `.so` files below `--spdk-build-dir` using available tools:

```bash
nm -an <binary> | grep spdk_nvme
nm -D <libspdk_nvme.so> | grep spdk_nvme_ns_cmd
readelf -Ws <binary> | grep bdev
objdump -t <binary> | grep nvme
```

Priority submit candidates include:

- `spdk_bdev_io_submit`, `bdev_io_submit`
- `spdk_bdev_read`, `spdk_bdev_write`, block/readv/writev variants
- `spdk_nvme_ns_cmd_read`, `spdk_nvme_ns_cmd_write`, readv/writev variants
- `nvme_qpair_submit_request`, `nvme_transport_qpair_submit_request`

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

This first implementation deliberately avoids hardcoded SPDK struct offsets. It provides stable minimum observation by pointer and function arguments. Enhanced bdev name, namespace, controller, qpair, and exact opcode decoding should be added through DWARF/BTF/pahole-derived offset profiles or explicit SPDK wrapper/tracepoint support for your exact SPDK 26.05 build.

## Validation

1. On the GPU host, run `fio` against `/dev/nvme1n1` or `/dev/nvme3n1`.
2. Confirm `nvme_io_observe_host.py` shows the selected device only and that size/latency histograms change.
3. On the storage server, run `spdk_io_observe_uprobe.py --list-symbols`.
4. Start the SPDK observer and confirm submit counts increase during the same workload.
5. Compare counts with SPDK RPC/stat output where possible.
6. Expect `iostat` and Linux block tracepoints on the storage server to miss vfio-owned physical SSD IO.

## Troubleshooting

- `attach failed`: symbol may be missing, static/inlined, stripped, or BCC may not support pid filtering on that version.
- `symbol not found`: run `--list-symbols`, check `nm/readelf`, rebuild with symbols, disable LTO, and avoid strip.
- `Operation not permitted`: run as root or configure BPF/perf capabilities and kernel lockdown policy.
- `debugfs not mounted`: `mount -t debugfs debugfs /sys/kernel/debug`.
- `BCC version mismatch`: install matching BCC Python bindings and kernel headers; this code targets BCC 0.29 and 0.36 style APIs where practical.
- `BPF verifier rejected program`: check kernel headers, tracepoint fields, and simplify options such as disabling `--latency`.
- `no IO observed`: verify the device filter on the GPU host; on storage, verify the SPDK pid, binary path, symbol choice, and that the workload reaches that SPDK process.

## Limitations

- SPDK internal functions can be inline/static or stripped, making uprobes impossible.
- Function-boundary uprobes add overhead on very hot poll-mode IO paths.
- Per-IO latency is reliable only when submit and completion expose the same object pointer.
- Request pointer argument positions are build/symbol dependent; use `--req-submit-arg` and `--req-complete-arg` only after checking the selected SPDK function prototypes.
- Host block latency, DPU/SNAP emulation latency, NVMe-oF network latency, SPDK queueing, and physical SSD media latency are different layers and must be interpreted separately.
- The host latency key can collide for repeated same-sector IO at high queue depth because portable block tracepoints do not expose a request pointer on all kernels.
