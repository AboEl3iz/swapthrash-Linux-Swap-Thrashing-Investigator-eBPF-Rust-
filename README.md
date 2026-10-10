# swapthrash: Linux Swap Thrashing Investigator (eBPF & Rust)

`swapthrash` is an advanced Linux eBPF diagnostic tool written in **Rust** and **C BPF (CO-RE)**. It investigates **swap thrashing** by measuring the exact duration anonymous memory pages spend on the swap storage device (the time from **swap-out** to **swap-in**) and visualizing the distribution as a logarithmic power-of-2 histogram.

This tool solves the challenge originally highlighted in *BPF Performance Tools* (Brendan Gregg, Chapter 7):
> *"Develop a tool to investigate swap thrashing. Show the time spent by pages on the swap device as a histogram. This is likely to involve measuring the time from swap-out to swap-in."*

---

## 1. Why Measure Swap Residency Time?

Traditional Linux monitoring utilities (`free -m`, `vmstat`, `sar -S`, `/proc/meminfo`) report swap usage as a static capacity metric:
- **Swap Used**: 2.5 GB / 4.0 GB

However, **swap utilization by itself does not imply performance degradation**:
- **Healthy Swap Usage**: The kernel reclaims inactive, cold anonymous pages (e.g., initialization data of daemons) and writes them to swap. These pages sit on the swap device for **hours or days**, freeing up physical RAM for active page cache.
- **Toxic Swap Thrashing**: Physical RAM is exhausted. Active working set pages are evicted to swap by `kswapd` or direct reclaim (`__swap_writepage`), only to be immediately needed by running threads and faulted right back in (`swap_read_folio`) milliseconds later. Disk queues saturate, processes stall in `D` state (uninterruptible disk sleep), and system latency skyrockets.

`swapthrash` directly reveals the difference:
- **Residency > 60s**: Benign, cold page swapping.
- **Residency < 1s or < 100ms**: Severe, active **swap thrashing**.

---

## 2. Kernel Mechanics & eBPF Architecture

```
Physical Memory (RAM)                      Swap Device (/swap.img, NVMe, ZRAM)
   [ Active Folio ]                                       |
          |                                               |
  (Memory Pressure)                                       |
  kswapd / Direct Reclaim                                 |
          |                                               |
  folio_alloc_swap()                                      |
          |                                               |
  __swap_writepage(folio)  ===[ Hook 1: Swap-Out ]======> | [ Written to Disk ]
                                Record: map[swp_val] = t0 |         |
                                                          |         |
                                                          |   Page Residency
                                                          |   Duration (Δt)
                                                          |         |
  Page Fault: do_swap_page()                              |         v
          |                                               |
  swap_read_folio(folio)   <==[ Hook 2: Swap-In ]======== | [ Read from Disk ]
                                Lookup: t1 - map[swp_val] |
                                Record Δt in Hist Map     |
```

### 2.1 The Tracking Key: `swp_entry_t.val`
Every page written to swap is uniquely addressed by a `swp_entry_t`:
- `swp_type`: The swap partition / device index.
- `swp_offset`: The page slot index on that device.
- `swp_entry_t.val`: A 64-bit integer combining type and offset.

Inside both `__swap_writepage(struct folio *folio)` and `swap_read_folio(struct folio *folio)`, `folio->swap.val` contains this exact identifier.

### 2.2 eBPF Hook Points
1. **Swap-Out Hook (`kprobe/__swap_writepage`)**:
   - Fires when the memory subsystem dispatches a dirty folio to the swap device.
   - Extracts `swp_val = folio->swap.val` via BTF CO-RE (`BPF_CORE_READ`).
   - Stores the start timestamp $t_0$ (`bpf_ktime_get_ns()`) in a `BPF_MAP_TYPE_LRU_HASH`.
   - Atomically increments global swap-out counters.

2. **Swap-In Hook (`kprobe/swap_read_folio`)**:
   - Fires when a page fault or swap readahead initiates reading the folio back from storage.
   - Looks up `swp_val` in the hash map.
   - If found:
     $$\Delta t = t_1 - t_0$$
     - Deletes the entry to avoid duplicate accounting.
     - Calculates the power-of-2 logarithmic bucket: $\lfloor \log_2(\Delta t_{\mu s}) \rfloor$.
     - Locklessly increments the per-CPU histogram bucket in `BPF_MAP_TYPE_PERCPU_ARRAY`.
     - Updates min, max, average, and thrashing thresholds (<100ms, <1s, <10s).
     - Tracks per-process swap-in count and thrash count in `proc_stats_map`.
     - Optionally streams the individual event to `events_ringbuf` if `--realtime` is enabled.

3. **Page Free Hook (`kprobe/folio_free_swap`)**:
   - Fires when a swap slot is freed without being read (e.g. process terminated or memory unmapped).
   - Deletes `swp_val` from the map, ensuring no memory leaks and recording `freed_count`.

---

## 3. Project Structure

```
/media/karim/New Volume16/devops/memory/
├── Cargo.toml               # Cargo package manifest (libbpf-rs 0.27, clap, ctrlc)
├── build.rs                 # Build script invoking libbpf-cargo SkeletonBuilder
├── Makefile                 # Make targets (build, release, run, test)
├── README.md                # This comprehensive documentation
├── src/
│   ├── main.rs              # Rust userspace CLI, signal handling, statistics engine
│   ├── hist.rs              # Logarithmic histogram rendering, percentiles, ASCII bars
│   └── bpf/
│       ├── swapthrash.bpf.c # eBPF C program (kprobes, LRU hash, Per-CPU histogram)
│       ├── swapthrash.h     # Shared data structures between BPF and Rust
│       └── vmlinux.h        # Kernel BTF type definitions
└── scripts/
    ├── thrash_generator.py  # Synthetic anonymous memory stress workload
    └── test_thrash.sh       # Automated test runner script
```

---

## 4. Building the Tool

### Prerequisites
- Linux kernel 5.8+ with BTF enabled (`/sys/kernel/btf/vmlinux`).
- `clang` and `llvm` (version 16+).
- `libbpf-dev` and `libelf-dev`.
- Rust toolchain (`cargo`, `rustc` 1.82+).

### Build Commands
```bash
# Build optimized release binary
cargo build --release

# The binary is placed at target/release/swapthrash
```

---

## 5. Usage & Command-Line Options

```
Usage: swapthrash [OPTIONS]

Options:
  -i, --interval <INTERVAL>      Output interval in seconds (0 = summary on Ctrl-C) [default: 0]
  -c, --count <COUNT>            Number of interval reports before exiting [default: 0]
  -u, --microseconds             Display residency histogram in microseconds
  -s, --seconds                  Display residency histogram in seconds
  -p, --per-process              Show per-process breakdown of swap-ins
  -r, --realtime                 Stream individual page residency events via BPF ring buffer
  -t, --threshold-ms <THRESHOLD> Highlight/filter thrashing events below this threshold in ms
      --cumulative               Print cumulative totals instead of interval deltas
  -h, --help                     Print help
  -V, --version                  Print version
```

---

## 6. Inducing Swap Thrashing with `stress-ng`

`stress-ng` provides an explicit `--vm-method swap` stressor designed to force anonymous pages to repeatedly swap out and fault back in (`--vm-keep`).

### Recommended: Isolated Sandbox Test (Zero Risk to Host/Desktop)
Using `systemd-run --user` to restrict `stress-ng` to a 512 MB memory slice while it allocates 1 GB:

```bash
# Terminal 1: Run swapthrash
sudo ./target/release/swapthrash -i 2 -p

# Terminal 2: Run the stress-ng script (15 seconds)
./scripts/run_stress_test.sh 15
```

Or run `stress-ng` directly:
```bash
systemd-run --user --scope -p MemoryMax=512M \
    stress-ng --vm 1 --vm-bytes 1G --vm-keep --vm-method swap --timeout 15s
```

### Full-System Thrashing Test
To stress the host system's entire memory footprint:
```bash
./scripts/run_stress_test.sh 20 system
```

---

## 6. Example Output & Interpretation

### 6.1 Interval Histogram Mode (`sudo ./target/release/swapthrash -i 2 -p`)

```text
============================================================
  swapthrash - Linux Swap Thrashing Investigator (eBPF/Rust)
============================================================
Tracing swap operations:
  Swap-out hook: __swap_writepage (page sent to swap device)
  Swap-in hook : swap_read_folio   (page faulted back from swap)
  Residency    : Time page spent on swap device
  Display Unit : ms
  Sampling     : Every 2s (count: unlimited)
Press Ctrl-C to stop.

--- Swap Residency Distribution @ 15:42:10 ---
  Residency (ms) : Count    Distribution                           Pct
---------------- : -------- -------------------------------------- ------
      1.0 -> 2.0 : 42       |@@@@                                  |   2.1% [CRITICAL THRASH]
      2.0 -> 4.0 : 128      |@@@@@@@@@@@@                          |   6.5% [CRITICAL THRASH]
      4.0 -> 8.0 : 380      |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@    |  19.2% [CRITICAL THRASH]
     8.0 -> 16.0 : 512      |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|  25.9% [CRITICAL THRASH]
    16.0 -> 32.0 : 410      |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@   |  20.7% [CRITICAL THRASH]
    32.0 -> 64.0 : 260      |@@@@@@@@@@@@@@@@@@@@@@@               |  13.1% [CRITICAL THRASH]
   64.0 -> 128.0 : 180      |@@@@@@@@@@@@@@@@                      |   9.1%
  128.0 -> 256.0 : 54       |@@@@@                                 |   2.7%
  256.0 -> 512.0 : 12       |@                                     |   0.6%

  Percentiles (ms): p50 = 12.00, p90 = 48.00, p99 = 192.00

=== [Interval 1] Swap Thrashing Diagnostics ===
  Total Pages Swapped Out  :       2450
  Total Pages Swapped In   :       1978
  Matched Residency Events :       1978
  Freed While in Swap      :         12
  Cold / Pre-existing In   :          0

--- Swap Residency Latency ---
  Min Residency Duration   : 1.15 ms
  Avg Residency Duration   : 22.40 ms
  Max Residency Duration   : 410.20 ms

--- Thrashing Severity Assessment ---
  Critical Thrashing (< 100ms) :     1912 ( 96.7%)
  Severe Thrashing   (< 1s)    :     1978 (100.0%)
  Moderate Thrashing (< 10s)   :     1978 (100.0%)

  [!] CRITICAL ALERT: SYSTEM IS ACTIVELY THRASHING!
      Over 50% of pages swapped in were evicted less than 1 second ago.
      Active working set exceeds available physical memory.

--- Top Processes Triggering Swap-Ins ---
     PID COMM               SWAP-INS  THRASH(<1s)  AVG RESIDENCY
-------- ---------------- ---------- ------------ --------------
   28419 python3                1978         1978       22.40 ms
```

### 6.2 Real-time Event Streaming Mode (`sudo ./target/release/swapthrash -r`)

```text
TIME              PID COMM                 SWAP_ENTRY        RESIDENCY
------------ -------- ---------------- ------------------ ----------------
15:43:02.104    28419 python3          0x00000000001a4f00         8.42 ms
15:43:02.106    28419 python3          0x00000000001a4f01         8.95 ms
15:43:02.108    28419 python3          0x00000000001a4f02         9.12 ms
```

---

## 7. Thrashing Diagnostic Criteria

| Residency Window | Classification | Health State | Operational Meaning |
| :--- | :--- | :--- | :--- |
| **< 100 ms** | **Critical Thrash** | Extreme Thrashing | Page barely reached disk before being demanded back. Disk saturated. |
| **100 ms – 1 s** | **Severe Thrash** | Active Thrashing | Working set exceeds RAM. CPU cycles wasted in page reclaim & page faults. |
| **1 s – 10 s** | **Moderate Thrash** | Transient Pressure | Bursty workload exceeding RAM momentarily. |
| **> 60 s** | **Cold Swap** | Healthy VM Behavior | Normal, efficient memory management. Inactive pages safely swapped out. |

---

## 8. Root Cause Analysis & Mitigation

When `swapthrash` flags active thrashing:
1. **Identify the Culprit**:
   Check the `Top Processes Triggering Swap-Ins` table to see which PID/comm is suffering major page faults.
2. **Inspect PSI (Pressure Stall Information)**:
   ```bash
   cat /proc/pressure/memory
   # High 'some' and 'full' values confirm CPU/threads are blocked waiting on swap I/O.
   ```
3. **Cgroups v2 Limits**:
   Constrain runaway containers to prevent system-wide thrashing:
   ```bash
   echo 2G > /sys/fs/cgroup/workload/memory.max
   echo 512M > /sys/fs/cgroup/workload/memory.swap.max
   ```
4. **Tune Swappiness**:
   If direct reclaim is evicting anonymous memory prematurely relative to file cache:
   ```bash
   sudo sysctl vm.swappiness=30
   ```
5. **Consider ZRAM / ZSWAP**:
   Compressed RAM swap drastically reduces thrashing latency compared to spinning disks or high-latency SSDs.
