#!/bin/bash
#
# Unified build and run script for emulator validation tests
# 
# This script:
# 1. Builds the emulator and test runner (x86_64)
# 2. Builds the ARM64 test binary using Android NDK
# 3. Runs the ARM64 tests through the emulator
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="${PROJECT_DIR}/build"
NDK_BUILD_DIR="${SCRIPT_DIR}/ndk_build"

# NDK toolchain path - can be overridden with environment variable
NDK_BIN="${ANDROID_NDK_TOOLCHAIN:-/mnt/ExtraSSD/AndroidSdk/ndk/25.0.8775105/toolchains/llvm/prebuilt/linux-x86_64/bin}"
NDK_CC="${NDK_BIN}/aarch64-linux-android30-clang"

echo "========================================"
echo "  Emulator Validation Test Suite"
echo "========================================"
echo ""
echo "Project directory: ${PROJECT_DIR}"
echo "Build directory:   ${BUILD_DIR}"
echo "NDK build dir:     ${NDK_BUILD_DIR}"
echo ""

# Step 1: Build the emulator and test runner
echo "========================================"
echo "  Step 1: Building emulator (x86_64)"
echo "========================================"
echo ""

mkdir -p "${BUILD_DIR}"
cd "${BUILD_DIR}"

cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc) emu_test_runner

if [ ! -f "${BUILD_DIR}/emu_test_runner" ]; then
    echo "ERROR: Failed to build emu_test_runner"
    exit 1
fi

echo ""
echo "Emulator test runner built successfully."
echo ""

# Step 2: Build the ARM64 test binary
echo "========================================"
echo "  Step 2: Building ARM64 test binary"
echo "========================================"
echo ""

if [ ! -x "${NDK_CC}" ]; then
    echo "ERROR: NDK compiler not found at ${NDK_CC}"
    exit 1
fi

mkdir -p "${NDK_BUILD_DIR}"

# Compile ARM64 test binary
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

ARM64_BINARY="${NDK_BUILD_DIR}/test_emulator_arm64"

echo "Compiling ARM64 test binary..."
# Use -pie -fPIE for position-independent executable (works with HLE)
# Use -fno-stack-protector to avoid stack guard issues
"${NDK_CC}" -Wall -Wextra -O2 -g -pie -fPIE -fno-stack-protector -lm -pthread \
    -o "${ARM64_BINARY}" \
    "${SOURCES[@]}"

if [ ! -f "${ARM64_BINARY}" ]; then
    echo "ERROR: Failed to build ARM64 test binary"
    exit 1
fi

echo ""
file "${ARM64_BINARY}"
echo ""
echo "ARM64 test binary built successfully."
echo ""

# Step 3: Run the tests through the emulator
echo "========================================"
echo "  Step 3: Running tests through emulator"
echo "========================================"
echo ""

cd "${PROJECT_DIR}"
"${BUILD_DIR}/emu_test_runner" "${ARM64_BINARY}"
EXIT_CODE=$?

echo ""
echo "========================================"
if [ $EXIT_CODE -eq 0 ]; then
    echo "  ALL TESTS PASSED"
else
    echo "  SOME TESTS FAILED (exit code: $EXIT_CODE)"
fi
echo "========================================"

exit $EXIT_CODE

