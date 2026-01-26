#!/bin/bash
#
# Run individual ARM64 tests through the CrossShim emulator
#
# Usage:
#   ./run_individual_tests.sh [options] [test_name...]
#
# Options:
#   --build, -b     Build tests before running
#   --all, -a       Run all tests (default if no tests specified)
#   --quick, -q     Run only quick tests (skip threading/networking)
#   --verbose, -v   Show test output
#   --help, -h      Show help
#
# Examples:
#   ./run_individual_tests.sh                    # Run all tests
#   ./run_individual_tests.sh --build            # Build and run all
#   ./run_individual_tests.sh test_string        # Run specific test
#   ./run_individual_tests.sh --quick            # Run quick tests only
#

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="${PROJECT_DIR}/build"
NDK_BUILD_DIR="${SCRIPT_DIR}/ndk_build"
CROSS_SHIM="${BUILD_DIR}/cross_shim"

# All available tests (in recommended order)
ALL_TESTS=(
    # Simple/quick tests
    "test_fp_simple"
    "test_printf_only"
    "test_printf_fp"
    "test_strtod_only"
    "test_tls"
    "test_hle_fp"
    "test_indirect_call"

    # Core functionality
    "test_string"
    "test_memory"
    "test_stdio"
    "test_stdlib"
    "test_ctype"
    "test_time"
    "test_math"

    # I/O and filesystem
    "test_dir"
    "test_wchar"
    "test_pipe"
    "test_signal"
    "test_exec"

    # Threading and networking (slower)
    "test_networking"
    "test_threading"
    "test_cooperative_threading"
    "test_atomics"
)

# Quick tests (no threading/networking)
QUICK_TESTS=(
    "test_fp_simple"
    "test_printf_only"
    "test_printf_fp"
    "test_strtod_only"
    "test_tls"
    "test_hle_fp"
    "test_string"
    "test_memory"
    "test_stdio"
    "test_stdlib"
    "test_ctype"
    "test_time"
    "test_math"
    "test_dir"
    "test_wchar"
)

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Parse arguments
BUILD=false
VERBOSE=false
QUICK=false
TESTS_TO_RUN=()

while [[ $# -gt 0 ]]; do
    case $1 in
        --build|-b)
            BUILD=true
            shift
            ;;
        --verbose|-v)
            VERBOSE=true
            shift
            ;;
        --quick|-q)
            QUICK=true
            shift
            ;;
        --all|-a)
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [options] [test_name...]"
            echo ""
            echo "Options:"
            echo "  --build, -b     Build tests before running"
            echo "  --quick, -q     Run only quick tests (skip threading/networking)"
            echo "  --verbose, -v   Show full test output"
            echo "  --help, -h      Show this help"
            echo ""
            echo "Available tests:"
            for t in "${ALL_TESTS[@]}"; do
                echo "  - $t"
            done
            exit 0
            ;;
        *)
            TESTS_TO_RUN+=("$1")
            shift
            ;;
    esac
done

# Determine which tests to run
if [ ${#TESTS_TO_RUN[@]} -eq 0 ]; then
    if [ "$QUICK" = true ]; then
        TESTS_TO_RUN=("${QUICK_TESTS[@]}")
    else
        TESTS_TO_RUN=("${ALL_TESTS[@]}")
    fi
fi

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  CrossShim Individual Test Runner${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Build if requested
if [ "$BUILD" = true ]; then
    echo "Building cross_shim and tests..."
    cd "${BUILD_DIR}"
    cmake .. -DCMAKE_BUILD_TYPE=Release > /dev/null 2>&1
    make -j$(nproc) cross_shim_runner > /dev/null 2>&1
    echo "  cross_shim built."

    "${SCRIPT_DIR}/build_individual_tests.sh"
    echo ""
fi

# Check cross_shim exists
if [ ! -x "${CROSS_SHIM}" ]; then
    echo -e "${RED}ERROR: cross_shim not found at ${CROSS_SHIM}${NC}"
    echo "Run with --build to build first."
    exit 1
fi

# Run tests
echo "Running ${#TESTS_TO_RUN[@]} tests..."
echo ""

PASSED=0
FAILED=0
SKIPPED=0
FAILED_TESTS=()

for test_name in "${TESTS_TO_RUN[@]}"; do
    binary="${NDK_BUILD_DIR}/${test_name}"

    if [ ! -x "$binary" ]; then
        echo -e "  ${YELLOW}[SKIP]${NC} $test_name - binary not found"
        SKIPPED=$((SKIPPED + 1))
        continue
    fi

    printf "  %-35s " "$test_name"

    # Run test with timeout and capture output
    output=$(timeout 60s "${CROSS_SHIM}" "$binary" 2>&1) || true
    exit_code=$?

    if [ $exit_code -eq 0 ]; then
        # Filter out debug lines (starting with [) and check for explicit [FAIL] markers
        filtered_output=$(echo "$output" | grep -v "^\[" || true)
        if echo "$filtered_output" | grep -q "\[FAIL\]"; then
            fail_count=$(echo "$filtered_output" | grep -c "\[FAIL\]" || echo 0)
            echo -e "${RED}[FAIL]${NC} ($fail_count failures)"
            FAILED_TESTS+=("$test_name")
            FAILED=$((FAILED + 1))
        else
            echo -e "${GREEN}[PASS]${NC}"
            PASSED=$((PASSED + 1))
        fi
    elif [ $exit_code -eq 124 ]; then
        echo -e "${RED}[TIMEOUT]${NC}"
        FAILED_TESTS+=("$test_name (timeout)")
        FAILED=$((FAILED + 1))
    else
        echo -e "${RED}[FAIL]${NC} (exit $exit_code)"
        FAILED_TESTS+=("$test_name")
        FAILED=$((FAILED + 1))
    fi

    # Show verbose output if requested
    if [ "$VERBOSE" = true ]; then
        echo "$output" | grep -v "^\[" | sed 's/^/      /'
        echo ""
    fi
done

# Summary
echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  Summary${NC}"
echo -e "${BLUE}========================================${NC}"
echo -e "  ${GREEN}Passed:${NC}  $PASSED"
echo -e "  ${RED}Failed:${NC}  $FAILED"
echo -e "  ${YELLOW}Skipped:${NC} $SKIPPED"

if [ ${#FAILED_TESTS[@]} -gt 0 ]; then
    echo ""
    echo -e "  ${RED}Failed tests:${NC}"
    for t in "${FAILED_TESTS[@]}"; do
        echo "    - $t"
    done
fi

echo -e "${BLUE}========================================${NC}"

if [ $FAILED -gt 0 ]; then
    exit 1
fi
exit 0
