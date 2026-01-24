#!/bin/bash
# Build the minimal ARM64 stub for QEMU initialization

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
NDK=/mnt/ExtraSSD/AndroidSdk/ndk/25.0.8775105/toolchains/llvm/prebuilt/linux-x86_64

# Use NDK's clang for ARM64
CC="${NDK}/bin/aarch64-linux-android24-clang"

# Build as a static binary with minimal runtime
"${CC}" -static -nostdlib -o "${SCRIPT_DIR}/qemu_stub" "${SCRIPT_DIR}/qemu_stub.S" \
    -Wl,-e,_start \
    -Wl,--build-id=none

# Check size
if [ -f "${SCRIPT_DIR}/qemu_stub" ]; then
    echo "Built qemu_stub: $(stat -c%s "${SCRIPT_DIR}/qemu_stub") bytes"
    file "${SCRIPT_DIR}/qemu_stub"
else
    echo "Build failed"
    exit 1
fi
