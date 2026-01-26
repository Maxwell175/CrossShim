/**
 * Test printf with floating point - no HLE FP functions, just printf %f
 */

#include <stdio.h>

int main(void) {
    double d = 3.14159;
    float f = 2.71828f;

    printf("Testing printf with floats...\n");
    printf("d = %f\n", d);
    printf("f = %f\n", f);
    printf("printf FP test PASSED!\n");
    return 0;
}
