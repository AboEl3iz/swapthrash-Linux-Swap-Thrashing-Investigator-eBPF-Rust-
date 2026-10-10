#!/usr/bin/env bash
# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
# Test runner for swapthrash eBPF tool

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
BIN="${PROJECT_DIR}/target/release/swapthrash"

if [ ! -f "${BIN}" ]; then
    echo "[!] Binary not found at ${BIN}. Building..."
    cargo build --release --manifest-path "${PROJECT_DIR}/Cargo.toml"
fi

echo "============================================================"
echo "  Swap Thrashing eBPF Test Suite"
echo "============================================================"
echo "This script demonstrates swapthrash by running the eBPF tool"
echo "alongside a synthetic anonymous memory thrashing workload."
echo ""
echo "Command to run swapthrash:"
echo "  sudo ${BIN} -i 2 -p"
echo ""
echo "In another terminal, run the memory thrash generator:"
echo "  python3 ${SCRIPT_DIR}/thrash_generator.py 2048"
echo "============================================================"
