#!/bin/bash
#
# Build bionic tests for ARM64 using Android NDK
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# NDK toolchain (NDK r29, API 35)
NDK_BIN="${ANDROID_NDK_TOOLCHAIN:-/mnt/ExtraSSD/AndroidSdk/ndk/29.0.14206865/toolchains/llvm/prebuilt/linux-x86_64/bin}"
NDK_CXX="${NDK_BIN}/aarch64-linux-android35-clang++"
DISABLED_TESTS_FILE="${SCRIPT_DIR}/ndk_disabled_tests.conf"

# Verify setup
if [ ! -d "googletest" ] || [ ! -d "tests" ]; then
    echo "ERROR: Run ./setup.sh first to download sources"
    exit 1
fi

# Apply source modifications to guard APIs not available in NDK
apply_source_fixes() {
    echo "=== Applying source fixes for NDK compatibility ==="
    if [ -f "$DISABLED_TESTS_FILE" ]; then
        local disabled_count
        disabled_count=$(grep -Evc '^[[:space:]]*($|#)' "$DISABLED_TESTS_FILE" || true)
        echo "  Documented compile-time omissions: ${disabled_count} cases (${DISABLED_TESTS_FILE})"
    fi

    # stdlib_test.cpp: qsort_r not available in API 35
    if [ -f "tests/stdlib_test.cpp" ] && ! grep -q "NDK_COMPAT_PATCHED" "tests/stdlib_test.cpp"; then
        echo "  Fixing stdlib_test.cpp (qsort_r)..."
        python3 - tests/stdlib_test.cpp <<'PYEOF'
import sys
with open(sys.argv[1], 'r') as f:
    content = f.read()
content = '// NDK_COMPAT_PATCHED\n' + content
# Wrap TEST(stdlib, qsort_r) in #if 0
import re
content = re.sub(
    r'(TEST\(stdlib, qsort_r\) \{.*?\n\})',
    r'#if 0  // NDK: qsort_r not available\n\1\n#endif',
    content, flags=re.DOTALL)
with open(sys.argv[1], 'w') as f:
    f.write(content)
PYEOF
    fi

    # unistd_test.cpp: bionic/pthread_internal.h not available via NDK
    if [ -f "tests/unistd_test.cpp" ] && ! grep -q "NDK_COMPAT_PATCHED" "tests/unistd_test.cpp"; then
        echo "  Fixing unistd_test.cpp (pthread_internal.h, _Fork, vfork)..."
        python3 - tests/unistd_test.cpp <<'PYEOF'
import sys, re
with open(sys.argv[1], 'r') as f:
    content = f.read()
content = '// NDK_COMPAT_PATCHED\n' + content
# Comment out the include
content = content.replace('#include "bionic/pthread_internal.h"', '// NDK: #include "bionic/pthread_internal.h"')
# Wrap TEST(UNISTD_TEST, _Fork) in #if 0
content = re.sub(
    r'(TEST\(UNISTD_TEST, _Fork\) \{.*?\n\})',
    r'#if 0  // NDK: requires bionic internals\n\1\n#endif',
    content, flags=re.DOTALL)
# Wrap TEST(UNISTD_TEST, vfork) in #if 0
content = re.sub(
    r'(TEST\(UNISTD_TEST, vfork\) \{.*?\n\})',
    r'#if 0  // NDK: requires pthread_internal_t\n\1\n#endif',
    content, flags=re.DOTALL)
with open(sys.argv[1], 'w') as f:
    f.write(content)
PYEOF
    fi

    # pthread_test.cpp: pthread_*affinity_np, android_run_on_all_threads, FrameCounter not available in NDK
    if [ -f "tests/pthread_test.cpp" ] && ! grep -q "NDK_COMPAT_PATCHED" "tests/pthread_test.cpp"; then
        echo "  Fixing pthread_test.cpp (pthread_*affinity_np, android_run_on_all_threads, FrameCounter)..."
        python3 - tests/pthread_test.cpp <<'PYEOF'
import sys, re
with open(sys.argv[1], 'r') as f:
    content = f.read()
content = '// NDK_COMPAT_PATCHED\n' + content
# Wrap all four affinity tests
for test in ['pthread_getaffinity_np_failure', 'pthread_getaffinity', 'pthread_setaffinity_np_failure', 'pthread_setaffinity']:
    content = re.sub(
        rf'(TEST\(pthread, {test}\) \{{.*?\n\}})',
        rf'#if 0  // NDK: pthread_*affinity_np not available\n\1\n#endif',
        content, flags=re.DOTALL)
# Wrap run_on_all_threads test
content = re.sub(
    r'(TEST\(pthread, run_on_all_threads\) \{.*?\n\})',
    r'#if 0  // NDK: android_run_on_all_threads not available\n\1\n#endif',
    content, flags=re.DOTALL)
# Wrap FrameCounter and related functions in #if 0
# This includes the extern declaration, signal_handler_backtrace, and big_enough_signal_stack test
content = re.sub(
    r'(extern _Unwind_Reason_Code FrameCounter.*?)(TEST\(pthread, pthread_barrierattr_smoke\))',
    r'#if 0  // NDK: FrameCounter not available\n\1#endif\n\n\2',
    content, flags=re.DOTALL)
# Wrap pthread_attr_setstack_bigger_stack test (also uses FrameCounter)
content = re.sub(
    r'(TEST\(pthread, pthread_attr_setstack_bigger_stack\) \{.*?\n\})',
    r'#if 0  // NDK: FrameCounter not available\n\1\n#endif',
    content, flags=re.DOTALL)
with open(sys.argv[1], 'w') as f:
    f.write(content)
PYEOF
    fi

    # sched_test.cpp: sched_getattr/sched_setattr require API 37+
    if [ -f "tests/sched_test.cpp" ] && ! grep -q "NDK_COMPAT_PATCHED" "tests/sched_test.cpp"; then
        echo "  Fixing sched_test.cpp (sched_*attr)..."
        python3 - tests/sched_test.cpp <<'PYEOF'
import sys, re
with open(sys.argv[1], 'r') as f:
    content = f.read()
content = '// NDK_COMPAT_PATCHED\n' + content
for test in ['sched_getattr', 'sched_setattr_failure']:
    content = re.sub(
        rf'(TEST\(sched, {test}\) \{{.*?\n\}})',
        rf'#if 0  // NDK: sched_*attr requires API 37+\n\1\n#endif',
        content, flags=re.DOTALL)
with open(sys.argv[1], 'w') as f:
    f.write(content)
PYEOF
    fi

    # semaphore_test.cpp: android_set_application_target_sdk_version not available via NDK
    if [ -f "tests/semaphore_test.cpp" ] && ! grep -q "NDK_COMPAT_PATCHED" "tests/semaphore_test.cpp"; then
        echo "  Fixing semaphore_test.cpp (android_set_application_target_sdk_version)..."
        python3 - tests/semaphore_test.cpp <<'PYEOF'
import sys, re
with open(sys.argv[1], 'r') as f:
    content = f.read()
content = '// NDK_COMPAT_PATCHED\n' + content
content = content.replace('extern "C" void android_set_application_target_sdk_version', '// NDK: extern "C" void android_set_application_target_sdk_version')
for test in ['sem_wait_no_EINTR_in_sdk_less_equal_than_23', 'sem_wait_EINTR_in_sdk_greater_than_23']:
    content = re.sub(
        rf'(TEST\(semaphore, {test}\) \{{.*?\n\}})',
        rf'#if 0  // NDK: android_set_application_target_sdk_version not available\n\1\n#endif',
        content, flags=re.DOTALL)
with open(sys.argv[1], 'w') as f:
    f.write(content)
PYEOF
    fi

    # signal_test.cpp: sig2str/str2sig not available in NDK
    if [ -f "tests/signal_test.cpp" ] && ! grep -q "NDK_COMPAT_PATCHED" "tests/signal_test.cpp"; then
        echo "  Fixing signal_test.cpp (sig2str/str2sig)..."
        python3 - tests/signal_test.cpp <<'PYEOF'
import sys, re
with open(sys.argv[1], 'r') as f:
    content = f.read()
content = '// NDK_COMPAT_PATCHED\n' + content
for test in ['sig2str', 'str2sig']:
    content = re.sub(
        rf'(TEST\(signal, {test}\) \{{.*?\n\}})',
        rf'#if 0  // NDK: {test} not available\n\1\n#endif',
        content, flags=re.DOTALL)
with open(sys.argv[1], 'w') as f:
    f.write(content)
PYEOF
    fi

    # sys_stat_test.cpp: lchmod not available in bionic
    if [ -f "tests/sys_stat_test.cpp" ] && ! grep -q "NDK_COMPAT_PATCHED" "tests/sys_stat_test.cpp"; then
        echo "  Fixing sys_stat_test.cpp (lchmod)..."
        python3 - tests/sys_stat_test.cpp <<'PYEOF'
import sys, re
with open(sys.argv[1], 'r') as f:
    content = f.read()
content = '// NDK_COMPAT_PATCHED\n' + content
content = re.sub(
    r'(TEST\(sys_stat, lchmod\) \{.*?\n\})',
    r'#if 0  // NDK: lchmod not available\n\1\n#endif',
    content, flags=re.DOTALL)
with open(sys.argv[1], 'w') as f:
    f.write(content)
PYEOF
    fi

    echo ""
}

if [ ! -x "$NDK_CXX" ]; then
    echo "ERROR: NDK compiler not found at $NDK_CXX"
    echo "Set ANDROID_NDK_TOOLCHAIN to your NDK bin directory"
    exit 1
fi

# Apply source modifications for NDK compatibility
apply_source_fixes

# Build googletest first
echo "=== Building googletest ==="
mkdir -p build/gtest

GTEST_SOURCES="
    googletest/googletest/src/gtest-all.cc
    googletest/googletest/src/gtest_main.cc
"

GTEST_INCLUDES="
    -I googletest/googletest/include
    -I googletest/googletest
"

# Build dynamically linked with static libc++
CXXFLAGS="-std=c++20 -O2 -g -fPIE -pie -fno-stack-protector -static-libstdc++ -DGTEST_HAS_DEATH_TEST=0"

# Compile gtest objects
for src in $GTEST_SOURCES; do
    obj="build/gtest/$(basename $src .cc).o"
    if [ ! -f "$obj" ] || [ "$src" -nt "$obj" ]; then
        echo "  Compiling $(basename $src)..."
        "$NDK_CXX" $CXXFLAGS $GTEST_INCLUDES -c "$src" -o "$obj"
    fi
done

# Create gtest archive
echo "  Creating libgtest.a..."
"${NDK_BIN}/llvm-ar" rcs build/gtest/libgtest.a build/gtest/*.o

echo ""
echo "=== Building bionic tests ==="
mkdir -p build/tests

# Include paths - shim provides TEST UTILITIES ONLY (utils.h, android-base/*)
# All bionic headers come from NDK
INCLUDES="
    $GTEST_INCLUDES
    -I shim
    -I tests
    -isystem tests
"

# Common flags for bionic tests
TEST_FLAGS="$CXXFLAGS $INCLUDES -D__BIONIC__ -DANDROID -Wno-unused-parameter"

# Function to build a single test
build_test() {
    local name=$1
    local src="tests/${name}.cpp"
    local out="build/tests/${name}"
    local extra_flags="${2:-}"
    local extra_sources="${3:-}"

    if [ ! -f "$src" ]; then
        echo "  [SKIP] $name - source not found"
        return
    fi

    printf "  Building %-30s " "$name..."

    # Try to compile
    if "$NDK_CXX" $TEST_FLAGS $extra_flags \
        -o "$out" "$src" $extra_sources \
        build/gtest/libgtest.a \
        -lm -pthread 2>/tmp/bionic_build_err.txt; then
        echo "OK"
    else
        echo "FAILED"
        # Show first few lines of error
        tail -50 /tmp/bionic_build_err.txt | sed 's/^/    /'
    fi
}

# Tests with minimal dependencies (most likely to build)
echo ""
echo "--- Simple tests (no utils.h) ---"
build_test "ctype_test"
build_test "stdint_test"
build_test "float_test"

echo ""
echo "--- Tests using utils.h ---"
build_test "inttypes_test"
build_test "fenv_test" "-lm"
build_test "math_test" "-lm -DANDROID_HOST_MUSL"
build_test "stdlib_test" "-lm"
build_test "stdio_test"
build_test "string_test" "" "tests/buffer_tests.cpp"
build_test "strings_test"
build_test "time_test"
build_test "unistd_test"
build_test "wchar_test"
build_test "wctype_test"
build_test "dirent_test"
build_test "fcntl_test"
build_test "pthread_test" "-pthread"
build_test "sched_test"
build_test "semaphore_test" "-pthread"
build_test "signal_test"
build_test "sys_stat_test"
build_test "sys_time_test"
build_test "netdb_test"
build_test "arpa_inet_test"
build_test "ifaddrs_test"

echo ""
echo "--- Header/macro tests ---"
build_test "errno_test"
build_test "endian_test"
build_test "byteswap_test"
build_test "limits_test"
build_test "sys_param_test"
build_test "sys_types_test"
build_test "stdalign_test"
build_test "stdarg_test"
build_test "stdnoreturn_test"
build_test "assert_test"

echo ""
echo "--- File/directory tests ---"
build_test "getcwd_test"
build_test "libgen_test"

echo ""
echo "--- Search/data structure tests ---"
build_test "search_test"

echo ""
echo "--- System tests ---"
build_test "getauxval_test"
build_test "sys_auxv_test"
build_test "atexit_test"
build_test "poll_test"
build_test "sys_select_test"

echo ""
echo "--- Memory tests ---"
build_test "setjmp_test"
build_test "alloca_test"

echo ""
echo "--- Miscellaneous tests ---"
build_test "fnmatch_test"
build_test "uchar_test"
build_test "termios_test"
build_test "langinfo_test"
build_test "glob_test"
build_test "fts_test"
build_test "ftw_test"
build_test "iconv_test"
build_test "eventfd_test"

echo ""
echo "=== Build Summary ==="
built=$(ls -1 build/tests/ 2>/dev/null | wc -l)
echo "Successfully built: $built tests"
echo ""
echo "Run tests with: ./run.sh"
