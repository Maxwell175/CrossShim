/**
 * Simple FP test - minimal test for floating point operations
 */

#include <stdio.h>

double test_double(void) {
    return 3.14159;
}

float test_float(void) {
    return 2.71828f;
}

int main(void) {
    double d;
    float f;

    printf("Testing floating point...\n");

    d = test_double();
    printf("test_double() = %f\n", d);

    f = test_float();
    printf("test_float() = %f\n", f);

    if (d > 3.14 && d < 3.15 && f > 2.71 && f < 2.72) {
        printf("PASS: Floating point works!\n");
        return 0;
    } else {
        printf("FAIL: Unexpected values d=%f f=%f\n", d, f);
        return 1;
    }
}
