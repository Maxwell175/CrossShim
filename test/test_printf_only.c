/**
 * Test printf only - no HLE FP functions
 */

#include <stdio.h>

int main(void) {
    int i;

    printf("Testing printf...\n");

    for (i = 0; i < 10; i++) {
        printf("Loop %d\n", i);
    }

    printf("printf test PASSED!\n");
    return 0;
}
