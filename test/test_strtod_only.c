/**
 * Test strtod in isolation
 */

#include <stdio.h>
#include <stdlib.h>

int main(void) {
    double d;
    char *endptr;

    printf("Calling strtod...\n");
    d = strtod("3.14159", &endptr);

    /* Print result using integer comparison to avoid printf %f */
    if (d > 3.14 && d < 3.15) {
        printf("strtod returned value in expected range (3.14-3.15)\n");
        printf("strtod test PASSED!\n");
        return 0;
    } else {
        printf("strtod returned unexpected value\n");
        return 1;
    }
}
