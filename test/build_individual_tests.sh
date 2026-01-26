#!/bin/bash
#
# Build individual test executables for the CrossShim emulator
#
# Each test is compiled as a standalone ARM64 executable that can be
# run through the cross_shim emulator independently.
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NDK_BUILD_DIR="${SCRIPT_DIR}/ndk_build"

# NDK toolchain
NDK_BIN="${ANDROID_NDK_TOOLCHAIN:-/mnt/ExtraSSD/AndroidSdk/ndk/25.0.8775105/toolchains/llvm/prebuilt/linux-x86_64/bin}"
NDK_CC="${NDK_BIN}/aarch64-linux-android30-clang"

# Common compiler flags
CFLAGS="-Wall -Wextra -O2 -g -pie -fPIE -fno-stack-protector"

mkdir -p "${NDK_BUILD_DIR}"

echo "Building individual test executables..."
echo "NDK: ${NDK_BIN}"
echo "Output: ${NDK_BUILD_DIR}"
echo ""

# Helper function to compile a standalone test
build_standalone() {
    local name=$1
    local src="${SCRIPT_DIR}/${name}.c"
    local out="${NDK_BUILD_DIR}/${name}"
    local extra_flags="${2:-}"

    if [ ! -f "$src" ]; then
        echo "  [SKIP] $name - source not found"
        return
    fi

    echo -n "  Building $name... "
    if "${NDK_CC}" ${CFLAGS} ${extra_flags} -o "$out" "$src" 2>/dev/null; then
        echo "OK"
    else
        echo "FAILED"
    fi
}

# Helper function to compile a test that needs a main wrapper
build_with_wrapper() {
    local name=$1
    local func=$2
    local src="${SCRIPT_DIR}/${name}.c"
    local out="${NDK_BUILD_DIR}/${name}"
    local extra_flags="${3:-}"
    local wrapper="${NDK_BUILD_DIR}/${name}_main.c"

    if [ ! -f "$src" ]; then
        echo "  [SKIP] $name - source not found"
        return
    fi

    # Create wrapper main
    cat > "$wrapper" << EOF
/* Auto-generated wrapper for ${name} */
extern int ${func}(void);
int main(void) { return ${func}(); }
EOF

    echo -n "  Building $name... "
    if "${NDK_CC}" ${CFLAGS} ${extra_flags} -o "$out" "$src" "$wrapper" 2>/dev/null; then
        echo "OK"
        rm -f "$wrapper"
    else
        echo "FAILED"
        rm -f "$wrapper"
    fi
}

# Helper for tests with passed/failed pointer interface
build_with_wrapper_pf() {
    local name=$1
    local func=$2
    local src="${SCRIPT_DIR}/${name}.c"
    local out="${NDK_BUILD_DIR}/${name}"
    local extra_flags="${3:-}"
    local wrapper="${NDK_BUILD_DIR}/${name}_main.c"

    if [ ! -f "$src" ]; then
        echo "  [SKIP] $name - source not found"
        return
    fi

    # Create wrapper main with passed/failed interface
    cat > "$wrapper" << EOF
/* Auto-generated wrapper for ${name} */
#include <stdio.h>
extern void ${func}(int *passed, int *failed);
int main(void) {
    int passed = 0, failed = 0;
    ${func}(&passed, &failed);
    printf("Results: %d passed, %d failed\\n", passed, failed);
    return failed > 0 ? 1 : 0;
}
EOF

    echo -n "  Building $name... "
    if "${NDK_CC}" ${CFLAGS} ${extra_flags} -o "$out" "$src" "$wrapper" 2>/dev/null; then
        echo "OK"
        rm -f "$wrapper"
    else
        echo "FAILED"
        rm -f "$wrapper"
    fi
}

echo "=== Standalone tests (already have main) ==="
build_standalone "test_fp_simple"
build_standalone "test_printf_only"
build_standalone "test_printf_fp"
build_standalone "test_strtod_only"
build_standalone "test_tls"
build_standalone "test_hle_fp"
build_standalone "test_indirect_call"
build_standalone "test_exec_helper"

echo ""
echo "=== Tests with run_*_tests() interface ==="
build_with_wrapper "test_string" "run_string_tests"
build_with_wrapper "test_memory" "run_memory_tests"
build_with_wrapper "test_stdio" "run_stdio_tests"
build_with_wrapper "test_stdlib" "run_stdlib_tests"
build_with_wrapper "test_ctype" "run_ctype_tests"
build_with_wrapper "test_time" "run_time_tests"
build_with_wrapper "test_math" "run_math_tests" "-lm"
build_with_wrapper "test_networking" "run_networking_tests"
build_with_wrapper "test_threading" "run_threading_tests" "-pthread"
build_with_wrapper "test_cooperative_threading" "run_cooperative_tests" "-pthread"
build_with_wrapper "test_atomics" "run_atomics_tests" "-pthread"

echo ""
echo "=== Tests with passed/failed pointer interface ==="
build_with_wrapper_pf "test_dir" "run_dir_tests"
build_with_wrapper_pf "test_wchar" "run_wchar_tests"
build_with_wrapper_pf "test_pipe" "run_pipe_tests"
build_with_wrapper_pf "test_signal" "run_signal_tests"
build_with_wrapper_pf "test_exec" "run_exec_tests"

echo ""
echo "Build complete. Executables in: ${NDK_BUILD_DIR}"
echo ""
echo "Run individual tests with:"
echo "  ./build/cross_shim test/ndk_build/<test_name>"
