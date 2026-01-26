/**
 * Test HLE functions that return floating point values
 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>

int main(void) {
    double d;
    time_t t1, t2;

    printf("Testing HLE floating point functions...\n");

    /* Test strtod - HLE function */
    printf("Testing strtod...\n");
    d = strtod("3.14159", NULL);
    printf("strtod(\"3.14159\") = %f\n", d);
    if (d < 3.14 || d > 3.15) {
        printf("FAIL: strtod returned wrong value\n");
        return 1;
    }
    printf("strtod PASS\n");

    /* Test difftime - HLE function */
    printf("Testing difftime...\n");
    t1 = 1700000000;
    t2 = 1700003600;
    d = difftime(t2, t1);
    printf("difftime(1700003600, 1700000000) = %f\n", d);
    if (d != 3600.0) {
        printf("FAIL: difftime returned %f instead of 3600.0\n", d);
        return 1;
    }
    printf("difftime PASS\n");

    /* Test sin - HLE math function */
    printf("Testing sin...\n");
    d = sin(0.0);
    printf("sin(0.0) = %f\n", d);
    if (d != 0.0) {
        printf("FAIL: sin(0) returned %f instead of 0.0\n", d);
        return 1;
    }
    printf("sin PASS\n");

    printf("\nAll HLE FP tests PASSED!\n");
    return 0;
}
