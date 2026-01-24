/**
 * Math Function Tests for Android Emulator Validation
 * Tests libm math functions.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <errno.h>
#include <float.h>

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST_ASSERT(cond, name) do { \
    if (cond) { \
        printf("  [PASS] %s\n", name); \
        tests_passed++; \
    } else { \
        printf("  [FAIL] %s (errno=%d: %s)\n", name, errno, strerror(errno)); \
        tests_failed++; \
    } \
} while(0)

/* Helper for floating point comparison */
#define EPSILON 1e-9
#define APPROX_EQ(a, b) (fabs((a) - (b)) < EPSILON)
#define APPROX_EQ_REL(a, b, rel) (fabs((a) - (b)) < (rel) * fabs(b) + EPSILON)

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

#ifndef M_E
#define M_E 2.71828182845904523536
#endif

/* ========================================================================== */
/* Trigonometric functions                                                    */
/* ========================================================================== */
static void test_trig(void) {
    printf("\n=== Trigonometric Function Tests ===\n");
    
    /* sin */
    TEST_ASSERT(APPROX_EQ(sin(0.0), 0.0), "sin(0)");
    TEST_ASSERT(APPROX_EQ(sin(M_PI/2), 1.0), "sin(pi/2)");
    TEST_ASSERT(APPROX_EQ(sin(M_PI), 0.0), "sin(pi)");
    TEST_ASSERT(APPROX_EQ(sin(-M_PI/2), -1.0), "sin(-pi/2)");
    
    /* cos */
    TEST_ASSERT(APPROX_EQ(cos(0.0), 1.0), "cos(0)");
    TEST_ASSERT(APPROX_EQ(cos(M_PI/2), 0.0), "cos(pi/2)");
    TEST_ASSERT(APPROX_EQ(cos(M_PI), -1.0), "cos(pi)");
    
    /* tan */
    TEST_ASSERT(APPROX_EQ(tan(0.0), 0.0), "tan(0)");
    TEST_ASSERT(APPROX_EQ(tan(M_PI/4), 1.0), "tan(pi/4)");
    TEST_ASSERT(APPROX_EQ(tan(-M_PI/4), -1.0), "tan(-pi/4)");
}

/* ========================================================================== */
/* Inverse trigonometric functions                                            */
/* ========================================================================== */
static void test_inverse_trig(void) {
    printf("\n=== Inverse Trigonometric Function Tests ===\n");
    
    /* asin */
    TEST_ASSERT(APPROX_EQ(asin(0.0), 0.0), "asin(0)");
    TEST_ASSERT(APPROX_EQ(asin(1.0), M_PI/2), "asin(1)");
    TEST_ASSERT(APPROX_EQ(asin(-1.0), -M_PI/2), "asin(-1)");
    
    /* acos */
    TEST_ASSERT(APPROX_EQ(acos(1.0), 0.0), "acos(1)");
    TEST_ASSERT(APPROX_EQ(acos(0.0), M_PI/2), "acos(0)");
    TEST_ASSERT(APPROX_EQ(acos(-1.0), M_PI), "acos(-1)");
    
    /* atan */
    TEST_ASSERT(APPROX_EQ(atan(0.0), 0.0), "atan(0)");
    TEST_ASSERT(APPROX_EQ(atan(1.0), M_PI/4), "atan(1)");
    TEST_ASSERT(APPROX_EQ(atan(-1.0), -M_PI/4), "atan(-1)");
    
    /* atan2 */
    TEST_ASSERT(APPROX_EQ(atan2(0.0, 1.0), 0.0), "atan2(0,1)");
    TEST_ASSERT(APPROX_EQ(atan2(1.0, 0.0), M_PI/2), "atan2(1,0)");
    TEST_ASSERT(APPROX_EQ(atan2(1.0, 1.0), M_PI/4), "atan2(1,1)");
    TEST_ASSERT(APPROX_EQ(atan2(-1.0, -1.0), -3*M_PI/4), "atan2(-1,-1)");
}

/* ========================================================================== */
/* Hyperbolic functions                                                       */
/* ========================================================================== */
static void test_hyperbolic(void) {
    printf("\n=== Hyperbolic Function Tests ===\n");
    
    /* sinh */
    TEST_ASSERT(APPROX_EQ(sinh(0.0), 0.0), "sinh(0)");
    TEST_ASSERT(APPROX_EQ_REL(sinh(1.0), 1.1752011936, 1e-6), "sinh(1)");
    
    /* cosh */
    TEST_ASSERT(APPROX_EQ(cosh(0.0), 1.0), "cosh(0)");
    TEST_ASSERT(APPROX_EQ_REL(cosh(1.0), 1.5430806348, 1e-6), "cosh(1)");
    
    /* tanh */
    TEST_ASSERT(APPROX_EQ(tanh(0.0), 0.0), "tanh(0)");
    TEST_ASSERT(APPROX_EQ_REL(tanh(1.0), 0.7615941559, 1e-6), "tanh(1)");
    TEST_ASSERT(tanh(100.0) > 0.999, "tanh(100) approaches 1");
}

/* ========================================================================== */
/* Exponential and logarithmic functions                                      */
/* ========================================================================== */
static void test_exp_log(void) {
    printf("\n=== Exponential/Logarithmic Function Tests ===\n");
    
    /* exp */
    TEST_ASSERT(APPROX_EQ(exp(0.0), 1.0), "exp(0)");
    TEST_ASSERT(APPROX_EQ_REL(exp(1.0), M_E, 1e-9), "exp(1)");
    TEST_ASSERT(APPROX_EQ_REL(exp(2.0), M_E*M_E, 1e-9), "exp(2)");
    
    /* log (natural) */
    TEST_ASSERT(APPROX_EQ(log(1.0), 0.0), "log(1)");
    TEST_ASSERT(APPROX_EQ(log(M_E), 1.0), "log(e)");
    TEST_ASSERT(APPROX_EQ_REL(log(10.0), 2.302585093, 1e-6), "log(10)");
    
    /* log10 */
    TEST_ASSERT(APPROX_EQ(log10(1.0), 0.0), "log10(1)");
    TEST_ASSERT(APPROX_EQ(log10(10.0), 1.0), "log10(10)");
    TEST_ASSERT(APPROX_EQ(log10(100.0), 2.0), "log10(100)");
    
    /* log2 */
    TEST_ASSERT(APPROX_EQ(log2(1.0), 0.0), "log2(1)");
    TEST_ASSERT(APPROX_EQ(log2(2.0), 1.0), "log2(2)");
    TEST_ASSERT(APPROX_EQ(log2(8.0), 3.0), "log2(8)");
    
    /* exp2 */
    TEST_ASSERT(APPROX_EQ(exp2(0.0), 1.0), "exp2(0)");
    TEST_ASSERT(APPROX_EQ(exp2(3.0), 8.0), "exp2(3)");
    TEST_ASSERT(APPROX_EQ(exp2(10.0), 1024.0), "exp2(10)");
}

/* ========================================================================== */
/* Power functions                                                            */
/* ========================================================================== */
static void test_power(void) {
    printf("\n=== Power Function Tests ===\n");
    
    /* pow */
    TEST_ASSERT(APPROX_EQ(pow(2.0, 0.0), 1.0), "pow(2,0)");
    TEST_ASSERT(APPROX_EQ(pow(2.0, 3.0), 8.0), "pow(2,3)");
    TEST_ASSERT(APPROX_EQ(pow(2.0, -1.0), 0.5), "pow(2,-1)");
    TEST_ASSERT(APPROX_EQ(pow(4.0, 0.5), 2.0), "pow(4,0.5)");
    TEST_ASSERT(APPROX_EQ(pow(27.0, 1.0/3.0), 3.0), "pow(27,1/3)");
    
    /* sqrt */
    TEST_ASSERT(APPROX_EQ(sqrt(0.0), 0.0), "sqrt(0)");
    TEST_ASSERT(APPROX_EQ(sqrt(1.0), 1.0), "sqrt(1)");
    TEST_ASSERT(APPROX_EQ(sqrt(4.0), 2.0), "sqrt(4)");
    TEST_ASSERT(APPROX_EQ(sqrt(2.0), 1.41421356237), "sqrt(2)");
    
    /* cbrt */
    TEST_ASSERT(APPROX_EQ(cbrt(0.0), 0.0), "cbrt(0)");
    TEST_ASSERT(APPROX_EQ(cbrt(8.0), 2.0), "cbrt(8)");
    TEST_ASSERT(APPROX_EQ(cbrt(-8.0), -2.0), "cbrt(-8)");
    
    /* hypot */
    TEST_ASSERT(APPROX_EQ(hypot(3.0, 4.0), 5.0), "hypot(3,4)");
    TEST_ASSERT(APPROX_EQ(hypot(5.0, 12.0), 13.0), "hypot(5,12)");
}

/* ========================================================================== */
/* Rounding functions                                                         */
/* ========================================================================== */
static void test_rounding(void) {
    printf("\n=== Rounding Function Tests ===\n");

    /* ceil */
    TEST_ASSERT(APPROX_EQ(ceil(2.3), 3.0), "ceil(2.3)");
    TEST_ASSERT(APPROX_EQ(ceil(2.0), 2.0), "ceil(2.0)");
    TEST_ASSERT(APPROX_EQ(ceil(-2.3), -2.0), "ceil(-2.3)");

    /* floor */
    TEST_ASSERT(APPROX_EQ(floor(2.7), 2.0), "floor(2.7)");
    TEST_ASSERT(APPROX_EQ(floor(2.0), 2.0), "floor(2.0)");
    TEST_ASSERT(APPROX_EQ(floor(-2.3), -3.0), "floor(-2.3)");

    /* round */
    TEST_ASSERT(APPROX_EQ(round(2.3), 2.0), "round(2.3)");
    TEST_ASSERT(APPROX_EQ(round(2.5), 3.0), "round(2.5)");
    TEST_ASSERT(APPROX_EQ(round(2.7), 3.0), "round(2.7)");
    TEST_ASSERT(APPROX_EQ(round(-2.5), -3.0), "round(-2.5)");

    /* trunc */
    TEST_ASSERT(APPROX_EQ(trunc(2.7), 2.0), "trunc(2.7)");
    TEST_ASSERT(APPROX_EQ(trunc(-2.7), -2.0), "trunc(-2.7)");

    /* rint */
    TEST_ASSERT(APPROX_EQ(rint(2.3), 2.0), "rint(2.3)");
    TEST_ASSERT(APPROX_EQ(rint(2.7), 3.0), "rint(2.7)");

    /* nearbyint */
    TEST_ASSERT(APPROX_EQ(nearbyint(2.3), 2.0), "nearbyint(2.3)");
    TEST_ASSERT(APPROX_EQ(nearbyint(2.7), 3.0), "nearbyint(2.7)");
}

/* ========================================================================== */
/* Absolute value and remainder functions                                     */
/* ========================================================================== */
static void test_abs_remainder(void) {
    printf("\n=== Absolute Value/Remainder Function Tests ===\n");

    /* fabs */
    TEST_ASSERT(APPROX_EQ(fabs(3.14), 3.14), "fabs(3.14)");
    TEST_ASSERT(APPROX_EQ(fabs(-3.14), 3.14), "fabs(-3.14)");
    TEST_ASSERT(APPROX_EQ(fabs(0.0), 0.0), "fabs(0)");

    /* fmod */
    TEST_ASSERT(APPROX_EQ(fmod(5.0, 2.0), 1.0), "fmod(5,2)");
    TEST_ASSERT(APPROX_EQ(fmod(5.5, 2.0), 1.5), "fmod(5.5,2)");
    TEST_ASSERT(APPROX_EQ(fmod(-5.0, 2.0), -1.0), "fmod(-5,2)");

    /* remainder */
    TEST_ASSERT(APPROX_EQ(remainder(5.0, 2.0), 1.0), "remainder(5,2)");
    TEST_ASSERT(APPROX_EQ(remainder(5.0, 3.0), -1.0), "remainder(5,3)");

    /* copysign */
    TEST_ASSERT(APPROX_EQ(copysign(3.0, -1.0), -3.0), "copysign(3,-1)");
    TEST_ASSERT(APPROX_EQ(copysign(-3.0, 1.0), 3.0), "copysign(-3,1)");
}

/* ========================================================================== */
/* Min/max and difference functions                                           */
/* ========================================================================== */
static void test_minmax(void) {
    printf("\n=== Min/Max Function Tests ===\n");

    /* fmin */
    TEST_ASSERT(APPROX_EQ(fmin(2.0, 3.0), 2.0), "fmin(2,3)");
    TEST_ASSERT(APPROX_EQ(fmin(-2.0, -3.0), -3.0), "fmin(-2,-3)");

    /* fmax */
    TEST_ASSERT(APPROX_EQ(fmax(2.0, 3.0), 3.0), "fmax(2,3)");
    TEST_ASSERT(APPROX_EQ(fmax(-2.0, -3.0), -2.0), "fmax(-2,-3)");

    /* fdim */
    TEST_ASSERT(APPROX_EQ(fdim(5.0, 3.0), 2.0), "fdim(5,3)");
    TEST_ASSERT(APPROX_EQ(fdim(3.0, 5.0), 0.0), "fdim(3,5)");
}

/* ========================================================================== */
/* Classification functions                                                   */
/* ========================================================================== */
static void test_classification(void) {
    printf("\n=== Classification Function Tests ===\n");

    TEST_ASSERT(isfinite(1.0) != 0, "isfinite(1.0)");
    TEST_ASSERT(isfinite(INFINITY) == 0, "isfinite(INFINITY) false");
    TEST_ASSERT(isfinite(NAN) == 0, "isfinite(NAN) false");

    TEST_ASSERT(isinf(INFINITY) != 0, "isinf(INFINITY)");
    TEST_ASSERT(isinf(-INFINITY) != 0, "isinf(-INFINITY)");
    TEST_ASSERT(isinf(1.0) == 0, "isinf(1.0) false");

    TEST_ASSERT(isnan(NAN) != 0, "isnan(NAN)");
    TEST_ASSERT(isnan(1.0) == 0, "isnan(1.0) false");
    TEST_ASSERT(isnan(INFINITY) == 0, "isnan(INFINITY) false");

    TEST_ASSERT(isnormal(1.0) != 0, "isnormal(1.0)");
    TEST_ASSERT(isnormal(0.0) == 0, "isnormal(0.0) false");
}

/* ========================================================================== */
/* Float versions (sinf, cosf, etc.)                                          */
/* ========================================================================== */
static void test_float_versions(void) {
    printf("\n=== Float Version Function Tests ===\n");

    TEST_ASSERT(fabsf(sinf(0.0f)) < 1e-6f, "sinf(0)");
    TEST_ASSERT(fabsf(cosf(0.0f) - 1.0f) < 1e-6f, "cosf(0)");
    TEST_ASSERT(fabsf(sqrtf(4.0f) - 2.0f) < 1e-6f, "sqrtf(4)");
    TEST_ASSERT(fabsf(expf(0.0f) - 1.0f) < 1e-6f, "expf(0)");
    TEST_ASSERT(fabsf(logf(1.0f)) < 1e-6f, "logf(1)");
    TEST_ASSERT(fabsf(powf(2.0f, 3.0f) - 8.0f) < 1e-6f, "powf(2,3)");
    TEST_ASSERT(fabsf(ceilf(2.3f) - 3.0f) < 1e-6f, "ceilf(2.3)");
    TEST_ASSERT(fabsf(floorf(2.7f) - 2.0f) < 1e-6f, "floorf(2.7)");
}

/* ========================================================================== */
/* Error function tests (from math_extra)                                     */
/* ========================================================================== */
static void test_erf(void) {
    printf("\n=== erf/erfc Tests ===\n");

    TEST_ASSERT(APPROX_EQ(erf(0.0), 0.0), "erf(0) = 0");
    TEST_ASSERT(APPROX_EQ_REL(erf(1.0), 0.8427007929, 1e-6), "erf(1)");
    TEST_ASSERT(erf(3.0) > 0.999, "erf(3) approaches 1");
    TEST_ASSERT(APPROX_EQ(erf(-1.0), -erf(1.0)), "erf(-x) = -erf(x)");

    TEST_ASSERT(APPROX_EQ(erfc(0.0), 1.0), "erfc(0) = 1");
    TEST_ASSERT(APPROX_EQ(erf(1.0) + erfc(1.0), 1.0), "erf(x) + erfc(x) = 1");
}

/* ========================================================================== */
/* Gamma function tests (from math_extra)                                     */
/* ========================================================================== */
static void test_gamma(void) {
    printf("\n=== lgamma/tgamma Tests ===\n");

    TEST_ASSERT(APPROX_EQ(tgamma(1.0), 1.0), "tgamma(1) = 1");
    TEST_ASSERT(APPROX_EQ(tgamma(2.0), 1.0), "tgamma(2) = 1");
    TEST_ASSERT(APPROX_EQ(tgamma(3.0), 2.0), "tgamma(3) = 2");
    TEST_ASSERT(APPROX_EQ(tgamma(4.0), 6.0), "tgamma(4) = 6");
    TEST_ASSERT(APPROX_EQ(tgamma(5.0), 24.0), "tgamma(5) = 24");

    TEST_ASSERT(APPROX_EQ(lgamma(1.0), 0.0), "lgamma(1) = 0");
    TEST_ASSERT(APPROX_EQ(lgamma(2.0), 0.0), "lgamma(2) = 0");
    TEST_ASSERT(APPROX_EQ_REL(exp(lgamma(5.0)), 24.0, 1e-9), "exp(lgamma(5)) = 24");
}

/* ========================================================================== */
/* nextafter tests (from math_extra)                                          */
/* ========================================================================== */
static void test_nextafter(void) {
    double next;

    printf("\n=== nextafter Tests ===\n");

    next = nextafter(1.0, 2.0);
    TEST_ASSERT(next > 1.0, "nextafter(1,2) > 1");
    TEST_ASSERT(next < 1.0 + 1e-10, "nextafter(1,2) close to 1");

    next = nextafter(1.0, 0.0);
    TEST_ASSERT(next < 1.0, "nextafter(1,0) < 1");

    TEST_ASSERT(nextafter(1.0, 1.0) == 1.0, "nextafter(1,1) = 1");
}

/* ========================================================================== */
/* scalbn/scalbln tests (from math_extra)                                     */
/* ========================================================================== */
static void test_scalbn(void) {
    printf("\n=== scalbn/scalbln Tests ===\n");

    TEST_ASSERT(APPROX_EQ(scalbn(1.0, 3), 8.0), "scalbn(1,3) = 8");
    TEST_ASSERT(APPROX_EQ(scalbn(2.0, 2), 8.0), "scalbn(2,2) = 8");
    TEST_ASSERT(APPROX_EQ(scalbn(1.0, -1), 0.5), "scalbn(1,-1) = 0.5");

    TEST_ASSERT(APPROX_EQ(scalbln(1.0, 3), 8.0), "scalbln(1,3) = 8");
    TEST_ASSERT(APPROX_EQ(scalbln(2.0, 2), 8.0), "scalbln(2,2) = 8");
}

/* ========================================================================== */
/* ilogb/logb tests (from math_extra)                                         */
/* ========================================================================== */
static void test_ilogb_logb(void) {
    printf("\n=== ilogb/logb Tests ===\n");

    TEST_ASSERT(ilogb(8.0) == 3, "ilogb(8) = 3");
    TEST_ASSERT(ilogb(1.0) == 0, "ilogb(1) = 0");
    TEST_ASSERT(ilogb(0.5) == -1, "ilogb(0.5) = -1");

    TEST_ASSERT(APPROX_EQ(logb(8.0), 3.0), "logb(8) = 3");
    TEST_ASSERT(APPROX_EQ(logb(1.0), 0.0), "logb(1) = 0");
    TEST_ASSERT(APPROX_EQ(logb(0.5), -1.0), "logb(0.5) = -1");
}

/* ========================================================================== */
/* Main entry point                                                           */
/* ========================================================================== */
int run_math_tests(void) {
    printf("\n");
    printf("========================================\n");
    printf("   MATH FUNCTION TEST SUITE\n");
    printf("========================================\n");

    test_trig();
    test_inverse_trig();
    test_hyperbolic();
    test_exp_log();
    test_power();
    test_rounding();
    test_abs_remainder();
    test_minmax();
    test_classification();
    test_float_versions();
    test_erf();
    test_gamma();
    test_nextafter();
    test_scalbn();
    test_ilogb_logb();

    printf("\n========================================\n");
    printf("   MATH RESULTS: %d passed, %d failed\n", tests_passed, tests_failed);
    printf("========================================\n");

    return tests_failed;
}

