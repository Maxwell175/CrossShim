#!/bin/bash
#
# Build script for cooperative threading test
# Uses the Android NDK toolchain to compile ARM64 binary
#

set -e

# NDK toolchain path
NDK_BIN="/mnt/ExtraSSD/AndroidSdk/ndk/25.0.8775105/toolchains/llvm/prebuilt/linux-x86_64/bin"

# Compiler and flags
CC="${NDK_BIN}/aarch64-linux-android30-clang"
# Use -fPIE -pie to create position-independent executable (DYN type)
# Note: Cannot use -static with -pie, so we create a shared executable
CFLAGS="-Wall -Wextra -O2 -g -fPIE"
LDFLAGS="-pthread -lm -pie"

# Output directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${SCRIPT_DIR}/ndk_build"

# Source file
SOURCE="${SCRIPT_DIR}/test_cooperative_threading.c"

# Output binary
OUTPUT="${OUT_DIR}/test_cooperative_threading_arm64"

echo "========================================"
echo "  Cooperative Threading Test Build"
echo "========================================"
echo ""
echo "NDK Compiler: ${CC}"
echo "Source: ${SOURCE}"
echo "Output: ${OUTPUT}"
echo ""

# Check if compiler exists
if [ ! -x "${CC}" ]; then
    echo "ERROR: NDK compiler not found at ${CC}"
    exit 1
fi

# Check if source exists
if [ ! -f "${SOURCE}" ]; then
    echo "ERROR: Source file not found at ${SOURCE}"
    exit 1
fi

# Create output directory
mkdir -p "${OUT_DIR}"

# Compile
echo "Compiling..."
"${CC}" ${CFLAGS} ${LDFLAGS} -o "${OUTPUT}" "${SOURCE}"

# Check result
if [ -f "${OUTPUT}" ]; then
    echo ""
    echo "Build successful!"
    echo ""
    file "${OUTPUT}"
    echo ""
    echo "Binary size: $(ls -lh "${OUTPUT}" | awk '{print $5}')"
    echo ""
    echo "To run in emulator:"
    echo "  ./build/emu_test_runner ${OUTPUT}"
else
    echo "ERROR: Build failed!"
    exit 1
fi

