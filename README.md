# spdk-storage

BCC/eBPF observers for a BlueField/SNAP NVMe-oF deployment where the GPU host sees emulated NVMe block devices, the DPU/SNAP path forwards NVMe-oF traffic, and the storage server drives physical NVMe SSDs from SPDK through `vfio-pci`.

## What each observer measures

```text
GPU Host
  app/fio
    -> Linux block layer
    -> host NVMe driver
    -> BF3/SNAP emulated NVMe device (/dev/nvme1n1, /dev/nvme3n1)
       observer: nvme_io_observe_host.py
       meaning: host-side block issue size toward the emulated NVMe device

DPU / SNAP
  ingress: host NVMe command received by SNAP
  egress : NVMe-oF/SPDK initiator request sent toward storage
       observer: snap_io_observe_dpu.py
       meaning: DPU-side request shape before/after SNAP/NVMe-oF processing

Storage server
  SPDK NVMe-oF target
    -> SPDK bdev/nvme userspace driver
    -> vfio-pci
    -> physical NVMe SSD
       observer: spdk_io_observe_uprobe.py
       meaning: storage-side SPDK submit size toward the physical NVMe device
```

`bcc/tools/bitesize.py` is useful only where IO passes through the Linux block layer. It can observe the GPU host block device path, but it cannot see physical SSD IO on the storage server when SPDK owns the NVMe controller through `vfio-pci`.

## Files

- `nvme_io_observe_host.py`: GPU host observer for selected Linux block devices.
- `snap_io_observe_dpu.py`: BlueField DPU/SNAP observer for DPU egress first and manually verified ingress.
- `spdk_io_observe_uprobe.py`: storage server observer for SPDK userspace submit/completion symbols.
- `common.py`: shared histogram, device, diagnostics, and symbol discovery helpers.
- `examples/`: shell examples for common runs.

## Requirements

- Ubuntu 24.04 target hosts, or the equivalent BlueField DPU OS/container environment.
- Python 3.
- BCC Python bindings (`python3-bcc` or distro equivalent).
- Root privileges or equivalent BPF/perf capabilities.
- Mounted tracefs/debugfs, usually `/sys/kernel/debug/tracing`.
- Kernel headers matching the running kernel.

## Recommended validation order

1. GPU Host: verify host block issue size on `/dev/nvme1n1`, `/dev/nvme3n1`.
2. DPU: discover SNAP/SPDK symbols before attaching.
3. DPU: validate `--mode egress` first. This is the safest DPU path because fixed-buffer `spdk_nvme_ns_cmd_read/write` expose `lba_count`.
4. Storage: discover SPDK target symbols before attaching.
5. Storage: validate fixed-buffer `spdk_nvme_ns_cmd_read/write` submit size.
6. DPU ingress: only attach after selecting a verified SNAP host-command symbol. Ingress fuzzy candidates are listed but not attached by default.
7. Run all three observers during the same fio workload and compare histograms.

Compare in this order:

```text
GPU Host block issue size
DPU/SNAP ingress size, if verified
DPU/SNAP egress size
Storage SPDK physical NVMe submit size
```

## GPU Host: commands

### Check block tracepoints and device keys

```bash
sudo ./nvme_io_observe_host.py \
  --devices /dev/nvme1n1,/dev/nvme3n1 \
  --dry-run
```

Optional raw tracepoint check:

```bash
sudo cat /sys/kernel/debug/tracing/events/block/block_rq_issue/format
sudo cat /sys/kernel/debug/tracing/events/block/block_rq_complete/format
```

### Observe host IO size

Start without latency first:

```bash
sudo ./nvme_io_observe_host.py \
  --devices /dev/nvme1n1,/dev/nvme3n1 \
  --interval 1 \
  --hist
```

Then add approximate block-layer latency:

```bash
sudo ./nvme_io_observe_host.py \
  --devices /dev/nvme1n1,/dev/nvme3n1 \
  --interval 1 \
  --hist \
  --latency
```

Host latency uses `dev + sector + bytes + op` matching because portable block tracepoints do not always expose request pointers. Treat it as approximate for high-QD repeated same-sector workloads.

## DPU/SNAP: symbol discovery and tests

Run `snap_io_observe_dpu.py` inside the DPU environment or inside the SNAP container where the target process and libraries are visible. The `--container` flag is informational only; it does not run `docker exec`.

### Find SNAP process and binaries

```bash
docker ps

docker exec -it <snap_container> bash
ps aux
find / -type f -perm -111 2>/dev/null | grep -Ei 'snap|spdk|nvmf|nvme'
find / -type f -name '*.so*' 2>/dev/null | grep -Ei 'snap|spdk|nvme|nvmf|rdma|mlx5'
```

If running directly on the DPU OS rather than inside the container:

```bash
ps aux | grep -Ei 'snap|spdk|nvmf|nvme'
find / -type f -perm -111 2>/dev/null | grep -Ei 'snap|spdk|nvmf|nvme'
find / -type f -name '*.so*' 2>/dev/null | grep -Ei 'snap|spdk|nvme|nvmf|rdma|mlx5'
```

### Low-level symbol checks

Run these before attaching if paths are known:

```bash
nm -an /path/to/snap_or_spdk_binary | grep -Ei 'snap|nvme|nvmf|bdev|rdma|submit|request|qpair|cmd' | head -200
nm -D /path/to/libspdk_nvme.so 2>/dev/null | grep -Ei 'spdk_nvme_ns_cmd|qpair|submit|complete'
readelf -Ws /path/to/snap_or_spdk_binary | grep -Ei 'snap|nvme|nvmf|bdev|rdma|submit|request|qpair|cmd' | head -200
objdump -t /path/to/snap_or_spdk_binary | grep -Ei 'snap|nvme|nvmf|bdev|rdma|submit|request|qpair|cmd' | head -200
```

### Tool-based discovery

```bash
sudo ./snap_io_observe_dpu.py \
  --pid $(pidof <snap_process>) \
  --binary /path/to/snap_or_spdk_binary \
  --search-dir /path/to/snap_or_spdk_libs \
  --list-symbols
```

This lists ingress fuzzy candidates, egress fixed-buffer candidates, request-pointer candidates, and completion candidates. Ingress fuzzy candidates are listing-only by default.

### Dry-run selected DPU attach plan

Egress first:

```bash
sudo ./snap_io_observe_dpu.py \
  --pid $(pidof <snap_process>) \
  --binary /path/to/snap_or_spdk_binary \
  --search-dir /path/to/snap_or_spdk_libs \
  --mode egress \
  --dry-run
```

### Observe DPU egress size

```bash
sudo ./snap_io_observe_dpu.py \
  --pid $(pidof <snap_process>) \
  --binary /path/to/snap_or_spdk_binary \
  --search-dir /path/to/snap_or_spdk_libs \
  --mode egress \
  --interval 1 \
  --hist \
  --lba-size 512
```

Use `--lba-size 4096` if the namespace logical block size is 4 KiB.

### Observe DPU ingress after manual symbol verification

Ingress is not auto-attached unless `--auto-ingress-fuzzy` is set. For meaningful ingress size, first verify the SNAP host-command processing symbol and argument layout, then run:

```bash
sudo ./snap_io_observe_dpu.py \
  --pid $(pidof <snap_process>) \
  --binary /path/to/snap_or_spdk_binary \
  --search-dir /path/to/snap_or_spdk_libs \
  --mode ingress \
  --ingress-symbol <verified_snap_command_symbol> \
  --ingress-object /path/to/object_if_not_binary \
  --manual-size-arg <n> \
  --manual-size-mode lba_count \
  --manual-op read \
  --interval 1 \
  --hist
```

Pointer-only ingress count, without size, can be attempted with a verified symbol but no `--manual-size-arg`:

```bash
sudo ./snap_io_observe_dpu.py \
  --pid $(pidof <snap_process>) \
  --binary /path/to/snap_or_spdk_binary \
  --search-dir /path/to/snap_or_spdk_libs \
  --mode ingress \
  --ingress-symbol <verified_snap_command_symbol> \
  --interval 1
```

Unsafe fuzzy ingress attach is available only for exploration:

```bash
sudo ./snap_io_observe_dpu.py \
  --pid $(pidof <snap_process>) \
  --binary /path/to/snap_or_spdk_binary \
  --search-dir /path/to/snap_or_spdk_libs \
  --mode ingress \
  --auto-ingress-fuzzy \
  --dry-run
```

Do not treat fuzzy ingress counts as host-command ingress until the selected symbol is manually confirmed.

### DPU latency experiment

Latency is only attempted on egress request-pointer submit/completion paths. This can double count with fixed-buffer size rows, so do not sum different attach modes as one IO count.

```bash
sudo ./snap_io_observe_dpu.py \
  --pid $(pidof <snap_process>) \
  --binary /path/to/snap_or_spdk_binary \
  --search-dir /path/to/snap_or_spdk_libs \
  --mode egress \
  --latency \
  --req-submit-arg 2 \
  --req-complete-arg 1 \
  --hist
```

## Storage server SPDK: symbol discovery and tests

### Find target process and symbols

```bash
pidof nvmf_tgt || pidof spdk_tgt

nm -an /path/to/nvmf_tgt | grep -Ei 'spdk_nvme_ns_cmd|nvme_qpair|nvme_complete|bdev_io'
nm -D /path/to/spdk/build/lib/libspdk_nvme.so 2>/dev/null | grep -Ei 'spdk_nvme_ns_cmd|qpair|complete'
readelf -Ws /path/to/nvmf_tgt | grep -Ei 'spdk_nvme_ns_cmd|nvme_qpair|nvme_complete|bdev_io'
```

### Tool-based discovery

```bash
sudo ./spdk_io_observe_uprobe.py \
  --pid $(pidof nvmf_tgt) \
  --binary /path/to/nvmf_tgt \
  --spdk-build-dir /path/to/spdk/build \
  --list-symbols
```

### Dry-run selected storage attach plan

```bash
sudo ./spdk_io_observe_uprobe.py \
  --pid $(pidof nvmf_tgt) \
  --binary /path/to/nvmf_tgt \
  --spdk-build-dir /path/to/spdk/build \
  --dry-run
```

### Observe storage-side physical NVMe submit size

```bash
sudo ./spdk_io_observe_uprobe.py \
  --pid $(pidof nvmf_tgt) \
  --binary /path/to/nvmf_tgt \
  --spdk-build-dir /path/to/spdk/build \
  --interval 1 \
  --hist \
  --lba-size 512
```

Manual fixed-buffer read/write examples:

```bash
sudo ./spdk_io_observe_uprobe.py \
  --pid $(pidof nvmf_tgt) \
  --binary /path/to/nvmf_tgt \
  --submit-symbol spdk_nvme_ns_cmd_read \
  --interval 1 \
  --hist \
  --lba-size 512

sudo ./spdk_io_observe_uprobe.py \
  --pid $(pidof nvmf_tgt) \
  --binary /path/to/nvmf_tgt \
  --submit-symbol spdk_nvme_ns_cmd_write \
  --interval 1 \
  --hist \
  --lba-size 512
```

`spdk_nvme_ns_cmd_readv/writev` are listed but not auto-attached for size accounting because their argument layout can differ by SPDK build. Use them manually only after checking the exact SPDK 26.05 prototype.

## End-to-end fio example

Run observers first, then generate IO from the GPU host:

```bash
sudo fio --name=bf3_snap_test \
  --filename=/dev/nvme1n1 \
  --direct=1 \
  --rw=randread \
  --bs=4k \
  --iodepth=64 \
  --ioengine=libaio \
  --runtime=60 \
  --time_based \
  --numjobs=1 \
  --group_reporting
```

Try multiple block sizes to confirm histogram shape:

```bash
for bs in 4k 16k 64k 256k 1m; do
  sudo fio --name=bf3_snap_${bs} --filename=/dev/nvme1n1 --direct=1 \
    --rw=randread --bs=$bs --iodepth=32 --ioengine=libaio \
    --runtime=30 --time_based --numjobs=1 --group_reporting
done
```

## Interpretation

- If GPU Host block size and DPU ingress size differ, reshaping may be happening in the host NVMe driver, PCIe emulation, or SNAP receive path.
- If DPU ingress and DPU egress differ, SNAP/NVMe-oF initiator split/merge/re-chunking may be happening.
- If DPU egress and Storage SPDK physical submit differ, the storage target, bdev, or NVMe layer may be splitting or merging requests.
- These layers measure different events and should not be treated as identical latency or media-size points.

## Build recommendations

- Include debug symbols.
- Do not strip the target binary or SPDK/SNAP shared libraries.
- Disable LTO where possible.
- Avoid inlining the specific function you want to probe.
- If needed, add a lightweight wrapper with `__attribute__((noinline))` around the submit/completion point, or use SPDK/SNAP tracepoints/USDT.

## Troubleshooting

- `attach failed`: symbol may be missing, static/inlined, stripped, or BCC may not support pid filtering on that version.
- `symbol not found`: run `--list-symbols`, check `nm/readelf/objdump`, rebuild with symbols, disable LTO, and avoid strip.
- `Operation not permitted`: run as root or configure BPF/perf capabilities and kernel lockdown policy.
- `debugfs not mounted`: `mount -t debugfs debugfs /sys/kernel/debug`.
- `BCC version mismatch`: install matching BCC Python bindings and kernel headers.
- `BPF verifier rejected program`: check kernel headers, tracepoint fields, and simplify options such as disabling `--latency`.
- `no IO observed`: verify pid, binary/object path, symbol choice, and that the workload reaches that process.
- `bytes=unsupported`: the observer attached to a pointer-only path. Use fixed-buffer `spdk_nvme_ns_cmd_read/write`, provide manual size arguments, or add a wrapper/USDT tracepoint that exposes size/opcode explicitly.

## Limitations

- SNAP binaries may be stripped, statically linked, inlined, or proprietary with no public hot-path symbols.
- DPU ingress size is often pointer-only unless a known SNAP symbol and size/lba_count argument are supplied manually.
- DPU egress size is most reliable when attaching to fixed-buffer `spdk_nvme_ns_cmd_read/write`.
- Storage size is most reliable when attaching to fixed-buffer `spdk_nvme_ns_cmd_read/write` close to the physical NVMe submit path.
- readv/writev byte accounting is intentionally not automatic because incorrect argument assumptions can silently produce invalid histograms.
- Function-boundary uprobes add overhead on hot IO paths.
- Per-IO latency is reliable only when submit and completion expose the same object pointer.
- Host block latency, DPU/SNAP emulation latency, NVMe-oF network latency, SPDK queueing, and physical SSD media latency are different layers and must be interpreted separately.
- The host latency key can collide for repeated same-sector IO at high queue depth because portable block tracepoints do not expose a request pointer on all kernels.
