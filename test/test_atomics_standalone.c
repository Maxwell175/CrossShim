/**
 * Standalone atomics test - just runs atomics tests directly
 */
#include <stdio.h>

extern int run_atomics_tests(void);

int main(int argc, char *argv[]) {
    (void)argc;
    (void)argv;

    printf("Running standalone atomics tests...\n");
    int failures = run_atomics_tests();

    if (failures == 0) {
        printf("\n*** ALL ATOMICS TESTS PASSED ***\n");
    } else {
        printf("\n*** %d ATOMICS TESTS FAILED ***\n", failures);
    }

    return failures > 0 ? 1 : 0;
}
