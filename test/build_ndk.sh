#!/bin/bash
#
# Build script for Android NDK ARM64 test binaries
# Uses the Android NDK toolchain to compile test cases
#

set -e

# NDK toolchain path
NDK_BIN="/mnt/ExtraSSD/AndroidSdk/ndk/25.0.8775105/toolchains/llvm/prebuilt/linux-x86_64/bin"

# Compiler and flags
CC="${NDK_BIN}/aarch64-linux-android30-clang"
# Use -fPIE -pie to create position-independent executable (DYN type)
# This allows the emulator's HLE functions to be used instead of bionic's
CFLAGS="-Wall -Wextra -O2 -g -fPIE"
LDFLAGS="-pthread -lm -pie"

# Output directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${SCRIPT_DIR}/ndk_build"

# Source files
SOURCES=(
    "${SCRIPT_DIR}/test_emulator_main.c"
    "${SCRIPT_DIR}/test_string.c"
    "${SCRIPT_DIR}/test_memory.c"
    "${SCRIPT_DIR}/test_stdio.c"
    "${SCRIPT_DIR}/test_stdlib.c"
    "${SCRIPT_DIR}/test_ctype.c"
    "${SCRIPT_DIR}/test_time.c"
    "${SCRIPT_DIR}/test_math.c"
    "${SCRIPT_DIR}/test_networking.c"
    "${SCRIPT_DIR}/test_threading.c"
    "${SCRIPT_DIR}/test_dir.c"
    "${SCRIPT_DIR}/test_wchar.c"
    "${SCRIPT_DIR}/test_pipe.c"
    "${SCRIPT_DIR}/test_signal.c"
    "${SCRIPT_DIR}/test_cooperative_threading.c"
    "${SCRIPT_DIR}/test_atomics.c"
)

# Output binary
OUTPUT="${OUT_DIR}/test_emulator_arm64"

echo "========================================"
echo "  Android NDK ARM64 Test Build"
echo "========================================"
echo ""
echo "NDK Compiler: ${CC}"
echo "Output: ${OUTPUT}"
echo ""

# Check if compiler exists
if [ ! -x "${CC}" ]; then
    echo "ERROR: NDK compiler not found at ${CC}"
    exit 1
fi

# Create output directory
mkdir -p "${OUT_DIR}"

# Compile
echo "Compiling..."
"${CC}" ${CFLAGS} ${LDFLAGS} -o "${OUTPUT}" "${SOURCES[@]}"

# Check result
if [ -f "${OUTPUT}" ]; then
    echo ""
    echo "Build successful!"
    echo ""
    file "${OUTPUT}"
    echo ""
    echo "Binary size: $(ls -lh "${OUTPUT}" | awk '{print $5}')"
    echo ""
    echo "To run in emulator, load this binary and execute it."
else
    echo "ERROR: Build failed!"
    exit 1
fi

