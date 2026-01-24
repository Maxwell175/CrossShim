/**
 * Stdlib Function Tests for Android Emulator Validation
 * Tests libc stdlib functions.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <pwd.h>
#include <grp.h>
#include <syslog.h>

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

/* ========================================================================== */
/* atoi/atol/atoll tests                                                      */
/* ========================================================================== */
static void test_atoi(void) {
    printf("\n=== atoi/atol/atoll Tests ===\n");
    
    TEST_ASSERT(atoi("42") == 42, "atoi positive");
    TEST_ASSERT(atoi("-42") == -42, "atoi negative");
    TEST_ASSERT(atoi("0") == 0, "atoi zero");
    TEST_ASSERT(atoi("  123") == 123, "atoi leading spaces");
    TEST_ASSERT(atoi("123abc") == 123, "atoi trailing chars");
    TEST_ASSERT(atoi("abc") == 0, "atoi non-numeric");
    
    TEST_ASSERT(atol("1234567890") == 1234567890L, "atol large");
    TEST_ASSERT(atol("-1234567890") == -1234567890L, "atol negative large");
    
    TEST_ASSERT(atoll("9223372036854775807") == 9223372036854775807LL, "atoll max");
}

/* ========================================================================== */
/* strtol/strtoul tests                                                       */
/* ========================================================================== */
static void test_strtol(void) {
    char *endptr;
    long val;
    unsigned long uval;
    
    printf("\n=== strtol/strtoul Tests ===\n");
    
    val = strtol("42", &endptr, 10);
    TEST_ASSERT(val == 42 && *endptr == '\0', "strtol decimal");
    
    val = strtol("-42", &endptr, 10);
    TEST_ASSERT(val == -42, "strtol negative");
    
    val = strtol("0xff", &endptr, 16);
    TEST_ASSERT(val == 255, "strtol hex");
    
    val = strtol("0xFF", &endptr, 0);
    TEST_ASSERT(val == 255, "strtol auto hex");
    
    val = strtol("0777", &endptr, 0);
    TEST_ASSERT(val == 511, "strtol auto octal");
    
    val = strtol("1010", &endptr, 2);
    TEST_ASSERT(val == 10, "strtol binary");
    
    val = strtol("123abc", &endptr, 10);
    TEST_ASSERT(val == 123 && strcmp(endptr, "abc") == 0, "strtol with endptr");
    
    uval = strtoul("4294967295", &endptr, 10);
    TEST_ASSERT(uval == 4294967295UL, "strtoul max 32-bit");
    
    uval = strtoul("-1", &endptr, 10);
    TEST_ASSERT(uval == ULONG_MAX, "strtoul negative wraps");
}

/* ========================================================================== */
/* strtod/strtof tests                                                        */
/* ========================================================================== */
static void test_strtod(void) {
    char *endptr;
    double d;
    float f;
    
    printf("\n=== strtod/strtof Tests ===\n");
    
    d = strtod("3.14159", &endptr);
    TEST_ASSERT(d > 3.14 && d < 3.15, "strtod basic");
    
    d = strtod("-2.5e10", &endptr);
    TEST_ASSERT(d < -2.4e10 && d > -2.6e10, "strtod scientific");
    
    d = strtod("1.5E-5", &endptr);
    TEST_ASSERT(d > 1.4e-5 && d < 1.6e-5, "strtod small exponent");
    
    d = strtod("  42.0abc", &endptr);
    TEST_ASSERT(d == 42.0 && strcmp(endptr, "abc") == 0, "strtod with endptr");
    
    f = strtof("3.14", &endptr);
    TEST_ASSERT(f > 3.13f && f < 3.15f, "strtof basic");
}

/* ========================================================================== */
/* abs/labs/llabs tests                                                       */
/* ========================================================================== */
static void test_abs(void) {
    printf("\n=== abs/labs/llabs Tests ===\n");
    
    TEST_ASSERT(abs(42) == 42, "abs positive");
    TEST_ASSERT(abs(-42) == 42, "abs negative");
    TEST_ASSERT(abs(0) == 0, "abs zero");
    
    TEST_ASSERT(labs(1234567890L) == 1234567890L, "labs positive");
    TEST_ASSERT(labs(-1234567890L) == 1234567890L, "labs negative");
    
    TEST_ASSERT(llabs(9223372036854775807LL) == 9223372036854775807LL, "llabs max");
    TEST_ASSERT(llabs(-9223372036854775807LL) == 9223372036854775807LL, "llabs negative");
}

/* ========================================================================== */
/* div/ldiv/lldiv tests                                                       */
/* ========================================================================== */
static void test_div(void) {
    div_t d;
    ldiv_t ld;
    lldiv_t lld;
    
    printf("\n=== div/ldiv/lldiv Tests ===\n");
    
    d = div(17, 5);
    TEST_ASSERT(d.quot == 3 && d.rem == 2, "div positive");
    
    d = div(-17, 5);
    TEST_ASSERT(d.quot == -3 && d.rem == -2, "div negative");
    
    ld = ldiv(1000000007L, 1000L);
    TEST_ASSERT(ld.quot == 1000000L && ld.rem == 7L, "ldiv");
    
    lld = lldiv(9223372036854775807LL, 1000000000LL);
    TEST_ASSERT(lld.quot == 9223372036LL && lld.rem == 854775807LL, "lldiv");
}

/* ========================================================================== */
/* rand/srand tests                                                           */
/* ========================================================================== */
static void test_rand(void) {
    int r1, r2, r3;
    int i, all_same;
    
    printf("\n=== rand/srand Tests ===\n");
    
    srand(12345);
    r1 = rand();
    r2 = rand();
    r3 = rand();
    TEST_ASSERT(r1 >= 0 && r1 <= RAND_MAX, "rand in range");
    TEST_ASSERT(r1 != r2 || r2 != r3, "rand produces different values");
    
    /* Same seed should produce same sequence */
    srand(12345);
    TEST_ASSERT(rand() == r1, "srand reproducible 1");
    TEST_ASSERT(rand() == r2, "srand reproducible 2");
    
    /* Different seed should produce different sequence */
    srand(54321);
    all_same = 1;
    for (i = 0; i < 10; i++) {
        if (rand() != r1) {
            all_same = 0;
            break;
        }
    }
    TEST_ASSERT(!all_same, "different seed different sequence");
}

/* ========================================================================== */
/* qsort tests                                                                */
/* ========================================================================== */
static int int_compare(const void *a, const void *b) {
    return (*(const int*)a - *(const int*)b);
}

static int str_compare(const void *a, const void *b) {
    return strcmp(*(const char**)a, *(const char**)b);
}

static void test_qsort(void) {
    int arr[] = {5, 2, 8, 1, 9, 3, 7, 4, 6, 0};
    const char *strs[] = {"zebra", "apple", "mango", "banana"};
    int sorted;
    size_t i;

    printf("\n=== qsort Tests ===\n");

    qsort(arr, 10, sizeof(int), int_compare);
    sorted = 1;
    for (i = 0; i < 9; i++) {
        if (arr[i] > arr[i+1]) {
            sorted = 0;
            break;
        }
    }
    TEST_ASSERT(sorted && arr[0] == 0 && arr[9] == 9, "qsort integers");

    qsort(strs, 4, sizeof(char*), str_compare);
    TEST_ASSERT(strcmp(strs[0], "apple") == 0, "qsort strings first");
    TEST_ASSERT(strcmp(strs[3], "zebra") == 0, "qsort strings last");
}

/* ========================================================================== */
/* bsearch tests                                                              */
/* ========================================================================== */
static void test_bsearch(void) {
    int arr[] = {1, 3, 5, 7, 9, 11, 13, 15};
    int key;
    int *result;

    printf("\n=== bsearch Tests ===\n");

    key = 7;
    result = bsearch(&key, arr, 8, sizeof(int), int_compare);
    TEST_ASSERT(result != NULL && *result == 7, "bsearch found");

    key = 1;
    result = bsearch(&key, arr, 8, sizeof(int), int_compare);
    TEST_ASSERT(result != NULL && *result == 1, "bsearch first");

    key = 15;
    result = bsearch(&key, arr, 8, sizeof(int), int_compare);
    TEST_ASSERT(result != NULL && *result == 15, "bsearch last");

    key = 6;
    result = bsearch(&key, arr, 8, sizeof(int), int_compare);
    TEST_ASSERT(result == NULL, "bsearch not found");
}

/* ========================================================================== */
/* getenv/setenv tests                                                        */
/* ========================================================================== */
static void test_getenv(void) {
    char *val;

    printf("\n=== getenv/setenv Tests ===\n");

    /* PATH should exist */
    val = getenv("PATH");
    TEST_ASSERT(val != NULL, "getenv PATH exists");

    /* Set a new variable */
    int ret = setenv("EMU_TEST_VAR", "test_value", 1);
    TEST_ASSERT(ret == 0, "setenv new var");

    val = getenv("EMU_TEST_VAR");
    TEST_ASSERT(val != NULL && strcmp(val, "test_value") == 0, "getenv new var");

    /* Overwrite */
    ret = setenv("EMU_TEST_VAR", "new_value", 1);
    val = getenv("EMU_TEST_VAR");
    TEST_ASSERT(val != NULL && strcmp(val, "new_value") == 0, "setenv overwrite");

    /* Don't overwrite */
    ret = setenv("EMU_TEST_VAR", "ignored", 0);
    val = getenv("EMU_TEST_VAR");
    TEST_ASSERT(val != NULL && strcmp(val, "new_value") == 0, "setenv no overwrite");

    /* Unset */
    ret = unsetenv("EMU_TEST_VAR");
    TEST_ASSERT(ret == 0, "unsetenv");
    val = getenv("EMU_TEST_VAR");
    TEST_ASSERT(val == NULL, "getenv after unset");
}

/* ========================================================================== */
/* exit/atexit tests (limited - can't actually test exit)                     */
/* ========================================================================== */
static int atexit_called = 0;
static void atexit_handler(void) {
    atexit_called = 1;
}

static void test_atexit(void) {
    printf("\n=== atexit Tests ===\n");

    /* Just verify atexit registration works */
    int ret = atexit(atexit_handler);
    TEST_ASSERT(ret == 0, "atexit registration");
}

/* ========================================================================== */
/* User/Group function tests (from stubs)                                     */
/* ========================================================================== */
static void test_user_group(void) {
    struct passwd *pw;
    struct group *gr;

    printf("\n=== User/Group Function Tests ===\n");

    /* getpwuid should return a valid structure */
    pw = getpwuid(0);
    TEST_ASSERT(pw != NULL, "getpwuid(0) returns non-NULL");
    if (pw) {
        TEST_ASSERT(pw->pw_name != NULL, "pw_name is not NULL");
        TEST_ASSERT(pw->pw_uid == 0, "pw_uid is 0");
    }

    pw = getpwuid(1000);
    TEST_ASSERT(pw != NULL, "getpwuid(1000) returns non-NULL");
    if (pw) {
        TEST_ASSERT(pw->pw_uid == 1000, "pw_uid is 1000");
    }

    /* getpwnam should return a valid structure */
    pw = getpwnam("root");
    TEST_ASSERT(pw != NULL, "getpwnam(root) returns non-NULL");

    /* getgrgid should return a valid structure */
    gr = getgrgid(0);
    TEST_ASSERT(gr != NULL, "getgrgid(0) returns non-NULL");
    if (gr) {
        TEST_ASSERT(gr->gr_name != NULL, "gr_name is not NULL");
        TEST_ASSERT(gr->gr_gid == 0, "gr_gid is 0");
    }

    /* getgrnam should return a valid structure */
    gr = getgrnam("root");
    TEST_ASSERT(gr != NULL, "getgrnam(root) returns non-NULL");
}

/* ========================================================================== */
/* setlogmask tests (from stubs)                                              */
/* ========================================================================== */
static void test_setlogmask(void) {
    int old_mask, new_mask;

    printf("\n=== setlogmask Tests ===\n");

    /* Get current mask (pass 0 to query without changing) */
    old_mask = setlogmask(0);
    TEST_ASSERT(old_mask != 0, "setlogmask(0) returns non-zero mask");

    /* Set a new mask */
    new_mask = setlogmask(LOG_UPTO(LOG_WARNING));
    TEST_ASSERT(new_mask == old_mask, "setlogmask returns previous mask");

    /* Verify the mask was set */
    old_mask = setlogmask(0);
    TEST_ASSERT(old_mask == LOG_UPTO(LOG_WARNING), "mask was set correctly");

    /* Restore original mask */
    setlogmask(0xFF);
}

/* ========================================================================== */
/* Main entry point                                                           */
/* ========================================================================== */
int run_stdlib_tests(void) {
    printf("\n");
    printf("========================================\n");
    printf("   STDLIB FUNCTION TEST SUITE\n");
    printf("========================================\n");

    test_atoi();
    test_strtol();
    test_strtod();
    test_abs();
    test_div();
    test_rand();
    test_qsort();
    test_bsearch();
    test_getenv();
    test_atexit();
    test_user_group();
    test_setlogmask();

    printf("\n========================================\n");
    printf("   STDLIB RESULTS: %d passed, %d failed\n", tests_passed, tests_failed);
    printf("========================================\n");

    return tests_failed;
}

