#!/usr/bin/env bash
# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
# Swap Thrashing Stress Test using stress-ng

set -euo pipefail

DURATION=${1:-15}
MODE=${2:-"cgroup"}

echo "============================================================"
echo "  stress-ng Swap Thrashing Load Generator"
echo "============================================================"
echo "Duration : ${DURATION} seconds"
echo "Mode     : ${MODE}"
echo ""

if ! command -v stress-ng &>/dev/null; then
    echo "[!] Error: stress-ng is not installed."
    echo "    Install via: sudo apt-get install -y stress-ng"
    exit 1
fi

SWAP_IN_BEFORE=$(awk '/pswpin/ {print $2}' /proc/vmstat)
SWAP_OUT_BEFORE=$(awk '/pswpout/ {print $2}' /proc/vmstat)

if [ "${MODE}" = "cgroup" ]; then
    echo "[*] Running in Isolated Cgroup Mode (MemoryMax=512M, Buffer=1G)..."
    echo "    This forces 512MB of active memory to continuously thrash into swap"
    echo "    without consuming host RAM or freezing your desktop."
    echo ""
    systemd-run --user --scope -p MemoryMax=512M \
        stress-ng --vm 1 --vm-bytes 1G --vm-keep --vm-method swap --timeout "${DURATION}s"
else
    # Full system mode: dynamically measure available RAM
    AVAIL_MB=$(awk '/MemAvailable/ {print int($2 / 1024)}' /proc/meminfo)
    TARGET_MB=$(( AVAIL_MB + 1500 ))
    WORKER_MB=$(( TARGET_MB / 2 ))
    echo "[*] Running in Full-System Mode (Available: ${AVAIL_MB} MB, Target: ${TARGET_MB} MB)..."
    echo "    Spawning 2 workers allocating ${WORKER_MB} MB each..."
    echo ""
    stress-ng --vm 2 --vm-bytes "${WORKER_MB}M" --vm-keep --vm-method swap --timeout "${DURATION}s"
fi

SWAP_IN_AFTER=$(awk '/pswpin/ {print $2}' /proc/vmstat)
SWAP_OUT_AFTER=$(awk '/pswpout/ {print $2}' /proc/vmstat)

DELTA_IN=$(( SWAP_IN_AFTER - SWAP_IN_BEFORE ))
DELTA_OUT=$(( SWAP_OUT_AFTER - SWAP_OUT_BEFORE ))

echo ""
echo "============================================================"
echo "  Stress Run Complete!"
echo "============================================================"
echo "  Kernel Swap Pages Out (pswpout) : +${DELTA_OUT} pages (~$(( DELTA_OUT * 4 / 1024 )) MB)"
echo "  Kernel Swap Pages In  (pswpin)  : +${DELTA_IN} pages (~$(( DELTA_IN * 4 / 1024 )) MB)"
echo "============================================================"
