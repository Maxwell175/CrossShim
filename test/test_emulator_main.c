/**
 * Main Test Runner for Android Emulator Validation
 * Pure C using only libc/libm - Runs all test suites.
 * Designed to be compiled with Android NDK for ARM64 target.
 */

#include <stdio.h>
#include <stdlib.h>

/* External test suite entry points */
extern int run_networking_tests(void);
extern int run_threading_tests(void);
extern int run_string_tests(void);
extern int run_memory_tests(void);
extern int run_stdio_tests(void);
extern int run_stdlib_tests(void);
extern int run_ctype_tests(void);
extern int run_time_tests(void);
extern int run_math_tests(void);

/* Additional test suites */
extern void run_dir_tests(int *passed, int *failed);
extern void run_wchar_tests(int *passed, int *failed);
extern void run_pipe_tests(int *passed, int *failed);
extern void run_signal_tests(int *passed, int *failed);
extern int run_cooperative_tests(void);
extern int run_atomics_tests(void);

int main(int argc, char *argv[]) {
    int net_failures, thread_failures, total_failures;
    int string_failures, memory_failures, stdio_failures;
    int stdlib_failures, ctype_failures, time_failures, math_failures;
    int cooperative_failures, atomics_failures;
    int dir_passed, dir_failed;
    int wchar_passed, wchar_failed;
    int pipe_passed, pipe_failed;
    int signal_passed, signal_failed;

    (void)argc;
    (void)argv;

    printf("==============================================\n");
    printf("  ANDROID EMULATOR VALIDATION TEST SUITE\n");
    printf("==============================================\n");
    printf("\nThis test suite validates emulator functionality\n");
    printf("for libc, libm, networking and threading.\n");

    /* Run all test suites */
    string_failures = run_string_tests();
    memory_failures = run_memory_tests();
    stdio_failures = run_stdio_tests();
    stdlib_failures = run_stdlib_tests();
    ctype_failures = run_ctype_tests();
    time_failures = run_time_tests();
    math_failures = run_math_tests();
    net_failures = run_networking_tests();
    thread_failures = run_threading_tests();

    /* Run additional test suites */
    run_dir_tests(&dir_passed, &dir_failed);
    run_wchar_tests(&wchar_passed, &wchar_failed);
    run_pipe_tests(&pipe_passed, &pipe_failed);
    run_signal_tests(&signal_passed, &signal_failed);
    cooperative_failures = run_cooperative_tests();
    atomics_failures = run_atomics_tests();

    /* Summary */
    total_failures = string_failures + memory_failures + stdio_failures +
                     stdlib_failures + ctype_failures + time_failures +
                     math_failures + net_failures + thread_failures +
                     dir_failed + wchar_failed + pipe_failed +
                     signal_failed + cooperative_failures + atomics_failures;

    printf("\n");
    printf("==============================================\n");
    printf("  FINAL SUMMARY\n");
    printf("==============================================\n");
    printf("  String failures:      %d\n", string_failures);
    printf("  Memory failures:      %d\n", memory_failures);
    printf("  Stdio failures:       %d\n", stdio_failures);
    printf("  Stdlib failures:      %d\n", stdlib_failures);
    printf("  Ctype failures:       %d\n", ctype_failures);
    printf("  Time failures:        %d\n", time_failures);
    printf("  Math failures:        %d\n", math_failures);
    printf("  Networking failures:  %d\n", net_failures);
    printf("  Threading failures:   %d\n", thread_failures);
    printf("  Dir failures:         %d\n", dir_failed);
    printf("  Wchar failures:       %d\n", wchar_failed);
    printf("  Pipe failures:        %d\n", pipe_failed);
    printf("  Signal failures:      %d\n", signal_failed);
    printf("  Cooperative failures: %d\n", cooperative_failures);
    printf("  Atomics failures:     %d\n", atomics_failures);
    printf("  --------------------------\n");
    printf("  Total failures:       %d\n", total_failures);
    printf("==============================================\n");

    if (total_failures == 0) {
        printf("\n  *** ALL TESTS PASSED ***\n\n");
    } else {
        printf("\n  *** SOME TESTS FAILED ***\n\n");
    }

    return total_failures > 0 ? 1 : 0;
}

