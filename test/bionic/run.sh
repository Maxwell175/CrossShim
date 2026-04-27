#!/bin/bash
#
# Run bionic tests through CrossShim emulator
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
BUILD_DIR="${PROJECT_DIR}/build"
CROSS_SHIM="${BUILD_DIR}/cross_shim"
TEST_DIR="${SCRIPT_DIR}/build/tests"
EXCLUDED_TESTS_FILE="${SCRIPT_DIR}/excluded_tests.conf"
CASE_TIMEOUT_SECS="${BIONIC_CASE_TIMEOUT_SECS:-30}"
RUN_TEST_CASE_STATUS=""
RUN_TEST_CASE_EXIT_CODE=0

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Load excluded tests from configuration file.
# Emits one gtest pattern per line for the given test binary.
get_exclusion_patterns() {
    local test_name="$1"

    if [ -f "$EXCLUDED_TESTS_FILE" ]; then
        while IFS= read -r line || [ -n "$line" ]; do
            [[ "$line" =~ ^[[:space:]]*# ]] && continue
            [[ -z "${line// }" ]] && continue

            local binary="${line%%:*}"
            local pattern="${line#*:}"

            if [ "$binary" = "$test_name" ] || [ "${binary}_test" = "$test_name" ]; then
                printf '%s\n' "$pattern"
            fi
        done < "$EXCLUDED_TESTS_FILE"
    fi
}

is_excluded_case() {
    local full_name="$1"
    shift

    local pattern
    for pattern in "$@"; do
        [ -z "$pattern" ] && continue
        if [[ "$full_name" == $pattern ]]; then
            return 0
        fi
    done

    return 1
}

list_test_cases() {
    local binary="$1"

    "$CROSS_SHIM" "$binary" --gtest_list_tests --gtest_color=no 2>/dev/null | awk '
        /^Running main\(\) from / { next }
        /^[^[:space:]].*\.$/ {
            suite = $1
            next
        }
        /^  / {
            test = $1
            if (suite != "") {
                print suite test
            }
        }
    '
}

run_test_case() {
    local binary="$1"
    local full_name="$2"
    local timeout_secs="${3:-30}"
    local output_file
    output_file=$(mktemp)
    RUN_TEST_CASE_STATUS="failed"
    RUN_TEST_CASE_EXIT_CODE=0

    if timeout "${timeout_secs}s" "$CROSS_SHIM" "$binary" --gtest_color=no --gtest_filter="$full_name" >"$output_file" 2>&1; then
        if grep -Eq '^\[  SKIPPED \] ' "$output_file"; then
            RUN_TEST_CASE_STATUS="runtime-skipped"
        else
            RUN_TEST_CASE_STATUS="passed"
        fi
        rm -f "$output_file"
        return 0
    else
        RUN_TEST_CASE_EXIT_CODE=$?
        tail -n 80 "$output_file" >&2
        rm -f "$output_file"
        return 0
    fi
}

PASSED=0
FAILED=0
PASSED_CASES=0
FAILED_CASES=0
EXCLUDED_CASES=0
RUNTIME_SKIPPED_CASES=0
FAILED_TESTS=()
FAILED_CASE_LIST=()

run_binary_cases() {
    local binary="$1"
    local requested_case_pattern="${2:-}"
    local timeout_secs="${3:-30}"
    local test_name
    test_name=$(basename "$binary")

    local -a exclusions=()
    mapfile -t exclusions < <(get_exclusion_patterns "$test_name")

    local -a cases=()
    mapfile -t cases < <(list_test_cases "$binary")

    if [ "${#cases[@]}" -eq 0 ]; then
        local zero_case_output
        zero_case_output=$(mktemp)
        if timeout "${timeout_secs}s" "$CROSS_SHIM" "$binary" --gtest_color=no >"$zero_case_output" 2>&1; then
            if grep -q '0 tests\.' "$zero_case_output"; then
                rm -f "$zero_case_output"
                printf "  %-35s " "$test_name"
                echo -e "${GREEN}[PASS]${NC} (0 passed, 0 runtime-skipped, 0 excluded)"
                PASSED=$((PASSED + 1))
                return 0
            fi
        fi
        tail -n 80 "$zero_case_output" >&2
        rm -f "$zero_case_output"
        echo -e "${RED}ERROR:${NC} unable to enumerate gtest cases for ${test_name}" >&2
        FAILED=$((FAILED + 1))
        FAILED_TESTS+=("$test_name (list_tests failed)")
        return 1
    fi

    local case_name
    local ran_cases=0
    local binary_passed_cases=0
    local binary_failed_cases=0
    local binary_excluded_cases=0
    local binary_runtime_skipped_cases=0

    for case_name in "${cases[@]}"; do
        if [ -n "$requested_case_pattern" ] && [[ "$case_name" != $requested_case_pattern ]]; then
            continue
        fi

        ran_cases=$((ran_cases + 1))

        if is_excluded_case "$case_name" "${exclusions[@]}"; then
            binary_excluded_cases=$((binary_excluded_cases + 1))
            continue
        fi

        run_test_case "$binary" "$case_name" "$timeout_secs"
        case "$RUN_TEST_CASE_STATUS" in
            passed)
                binary_passed_cases=$((binary_passed_cases + 1))
                ;;
            runtime-skipped)
                binary_runtime_skipped_cases=$((binary_runtime_skipped_cases + 1))
                ;;
            *)
                binary_failed_cases=$((binary_failed_cases + 1))
                if [ "$RUN_TEST_CASE_EXIT_CODE" -eq 124 ]; then
                    FAILED_CASE_LIST+=("${test_name}:${case_name} (timeout)")
                else
                    FAILED_CASE_LIST+=("${test_name}:${case_name}")
                fi
                ;;
        esac
    done

    if [ "$ran_cases" -eq 0 ]; then
        echo -e "${RED}ERROR:${NC} no gtest cases matched in ${test_name}" >&2
        FAILED=$((FAILED + 1))
        FAILED_TESTS+=("$test_name (no matching cases)")
        return 1
    fi

    PASSED_CASES=$((PASSED_CASES + binary_passed_cases))
    FAILED_CASES=$((FAILED_CASES + binary_failed_cases))
    EXCLUDED_CASES=$((EXCLUDED_CASES + binary_excluded_cases))
    RUNTIME_SKIPPED_CASES=$((RUNTIME_SKIPPED_CASES + binary_runtime_skipped_cases))

    printf "  %-35s " "$test_name"
    if [ "$binary_failed_cases" -eq 0 ]; then
        echo -e "${GREEN}[PASS]${NC} (${binary_passed_cases} passed, ${binary_runtime_skipped_cases} runtime-skipped, ${binary_excluded_cases} excluded)"
        PASSED=$((PASSED + 1))
        return 0
    fi

    echo -e "${RED}[FAIL]${NC} (${binary_failed_cases} failed, ${binary_passed_cases} passed, ${binary_runtime_skipped_cases} runtime-skipped, ${binary_excluded_cases} excluded)"
    FAILED=$((FAILED + 1))
    FAILED_TESTS+=("$test_name")
    return 1
}

if [ ! -x "$CROSS_SHIM" ]; then
    echo -e "${RED}ERROR: cross_shim not found at ${CROSS_SHIM}${NC}"
    echo "Build CrossShim first."
    exit 1
fi

if [ ! -d "$TEST_DIR" ]; then
    echo -e "${RED}ERROR: No tests built. Run ./build.sh first${NC}"
    exit 1
fi

echo -e "${BLUE}=======================================${NC}"
echo -e "${BLUE}  Bionic Test Suite via CrossShim${NC}"
echo -e "${BLUE}=======================================${NC}"
echo ""

if [ -n "${1:-}" ]; then
    test_name="$1"
    requested_case_pattern="${2:-}"
    binary="${TEST_DIR}/${test_name}"

    if [ ! -x "$binary" ]; then
        binary="${TEST_DIR}/${test_name}_test"
    fi

    if [ ! -x "$binary" ]; then
        echo -e "${RED}ERROR: Test not found: $test_name${NC}"
        exit 1
    fi

    run_binary_cases "$binary" "$requested_case_pattern" "$CASE_TIMEOUT_SECS" || true
else
    for binary in "$TEST_DIR"/*; do
        if [ ! -x "$binary" ]; then
            continue
        fi

        run_binary_cases "$binary" "" "$CASE_TIMEOUT_SECS" || true
    done
fi

echo ""
echo -e "${BLUE}=======================================${NC}"
echo -e "${BLUE}  Summary${NC}"
echo -e "${BLUE}=======================================${NC}"
echo -e "  ${GREEN}Passed:${NC}        $PASSED"
echo -e "  ${RED}Failed:${NC}        $FAILED"
echo -e "  ${GREEN}Passed cases:${NC}  $PASSED_CASES"
echo -e "  ${RED}Failed cases:${NC}  $FAILED_CASES"
echo -e "  ${YELLOW}Skipped cases:${NC} $((RUNTIME_SKIPPED_CASES + EXCLUDED_CASES))"
echo -e "  ${YELLOW}  Runtime:${NC}     $RUNTIME_SKIPPED_CASES"
echo -e "  ${YELLOW}  Excluded:${NC}    $EXCLUDED_CASES"

if [ ${#FAILED_TESTS[@]} -gt 0 ]; then
    echo ""
    echo -e "  ${RED}Failed tests:${NC}"
    for t in "${FAILED_TESTS[@]}"; do
        echo "    - $t"
    done
fi

if [ ${#FAILED_CASE_LIST[@]} -gt 0 ]; then
    echo ""
    echo -e "  ${RED}Failed cases:${NC}"
    for t in "${FAILED_CASE_LIST[@]}"; do
        echo "    - $t"
    done
fi

echo -e "${BLUE}=======================================${NC}"

if [ "$FAILED" -gt 0 ]; then
    exit 1
fi

exit 0
