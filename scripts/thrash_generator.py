#!/usr/bin/env python3
"""
Synthetic Swap Thrashing Workload Generator.
Allocates a memory block exceeding available physical RAM or specified size,
then repeatedly loops through pages, touching 1 byte per 4KB page.
This forces the kernel to continually evict pages to swap and fault them back in.
"""

import sys
import os
import time
import mmap

def main():
    if len(sys.argv) > 1:
        size_mb = int(sys.argv[1])
    else:
        # Default: 1024 MB (1 GB) or read /proc/meminfo to tune
        size_mb = 512

    size_bytes = size_mb * 1024 * 1024
    page_size = 4096
    num_pages = size_bytes // page_size

    print(f"[*] Swap Thrash Generator PID: {os.getpid()}")
    print(f"[*] Allocating {size_mb} MB ({num_pages:,} pages)...")

    # Allocate anonymous memory via mmap
    buf = mmap.mmap(-1, size_bytes, flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS, prot=mmap.PROT_READ | mmap.PROT_WRITE)

    # Initial dirtying pass
    print("[*] Performing initial write to dirty all pages...")
    for i in range(num_pages):
        buf[i * page_size] = (i & 0xFF)

    print(f"[*] Starting cyclic page touch loop (thrashing test) for 30 seconds...")
    start_time = time.time()
    loops = 0

    try:
        while time.time() - start_time < 30:
            # Stride through pages to force swap-ins
            for i in range(num_pages):
                # Read-modify-write each page
                val = buf[i * page_size]
                buf[i * page_size] = (val + 1) & 0xFF
            loops += 1
            print(f"  Completed cycle {loops}...", end="\r", flush=True)
    except KeyboardInterrupt:
        print("\n[*] Interrupted by user.")

    print(f"\n[*] Finished {loops} cycles in {time.time() - start_time:.2f}s.")
    buf.close()

if __name__ == "__main__":
    main()
