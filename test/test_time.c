/**
 * Time Function Tests for Android Emulator Validation
 * Tests libc time functions.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <errno.h>
#include <stddef.h>

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

#define TEST_ASSERT_MSG(cond, name, ...) do { \
    if (cond) { \
        printf("  [PASS] %s\n", name); \
        tests_passed++; \
    } else { \
        printf("  [FAIL] %s: ", name); \
        printf(__VA_ARGS__); \
        printf("\n"); \
        tests_failed++; \
    } \
} while(0)

/* ========================================================================== */
/* time() tests                                                               */
/* ========================================================================== */
static void test_time(void) {
    time_t t1, t2;
    
    printf("\n=== time() Tests ===\n");
    
    t1 = time(NULL);
    TEST_ASSERT(t1 > 0, "time() returns positive");
    TEST_ASSERT(t1 > 1700000000, "time() after 2023");  /* Sanity check */
    
    t2 = time(&t1);
    TEST_ASSERT(t1 == t2, "time() with pointer");
    TEST_ASSERT(t1 > 0, "time() pointer value");
}

/* ========================================================================== */
/* gettimeofday() tests                                                       */
/* ========================================================================== */
static void test_gettimeofday(void) {
    struct timeval tv1, tv2;
    int ret;
    
    printf("\n=== gettimeofday() Tests ===\n");
    
    ret = gettimeofday(&tv1, NULL);
    TEST_ASSERT(ret == 0, "gettimeofday() returns 0");
    TEST_ASSERT(tv1.tv_sec > 0, "gettimeofday() sec positive");
    TEST_ASSERT(tv1.tv_usec >= 0 && tv1.tv_usec < 1000000, "gettimeofday() usec valid");
    
    /* Second call should be >= first */
    ret = gettimeofday(&tv2, NULL);
    TEST_ASSERT(ret == 0, "gettimeofday() second call");
    TEST_ASSERT(tv2.tv_sec > tv1.tv_sec || 
                (tv2.tv_sec == tv1.tv_sec && tv2.tv_usec >= tv1.tv_usec),
                "gettimeofday() monotonic");
}

/* ========================================================================== */
/* clock_gettime() tests                                                      */
/* ========================================================================== */
static void test_clock_gettime(void) {
    struct timespec ts1, ts2;
    int ret;
    
    printf("\n=== clock_gettime() Tests ===\n");
    
    ret = clock_gettime(CLOCK_REALTIME, &ts1);
    TEST_ASSERT(ret == 0, "clock_gettime CLOCK_REALTIME");
    TEST_ASSERT(ts1.tv_sec > 0, "CLOCK_REALTIME sec positive");
    TEST_ASSERT(ts1.tv_nsec >= 0 && ts1.tv_nsec < 1000000000, "CLOCK_REALTIME nsec valid");
    
    ret = clock_gettime(CLOCK_MONOTONIC, &ts2);
    TEST_ASSERT(ret == 0, "clock_gettime CLOCK_MONOTONIC");
    TEST_ASSERT(ts2.tv_nsec >= 0 && ts2.tv_nsec < 1000000000, "CLOCK_MONOTONIC nsec valid");
}

/* ========================================================================== */
/* localtime/gmtime tests                                                     */
/* ========================================================================== */
static void test_localtime_gmtime(void) {
    time_t t = 1700000000;  /* 2023-11-14 22:13:20 UTC */
    struct tm *tm_local, *tm_gmt;
    struct tm tm_buf;
    
    printf("\n=== localtime/gmtime Tests ===\n");
    
    tm_gmt = gmtime(&t);
    TEST_ASSERT(tm_gmt != NULL, "gmtime() not NULL");
    TEST_ASSERT(tm_gmt->tm_year == 123, "gmtime year 2023");  /* years since 1900 */
    TEST_ASSERT(tm_gmt->tm_mon == 10, "gmtime month Nov");    /* 0-based */
    TEST_ASSERT(tm_gmt->tm_mday == 14, "gmtime day 14");
    TEST_ASSERT(tm_gmt->tm_hour == 22, "gmtime hour 22");
    
    tm_local = localtime(&t);
    TEST_ASSERT(tm_local != NULL, "localtime() not NULL");
    TEST_ASSERT(tm_local->tm_year == 123, "localtime year 2023");
    
    /* Thread-safe versions */
    tm_gmt = gmtime_r(&t, &tm_buf);
    TEST_ASSERT(tm_gmt == &tm_buf, "gmtime_r returns buffer");
    TEST_ASSERT(tm_buf.tm_year == 123, "gmtime_r year");
    
    tm_local = localtime_r(&t, &tm_buf);
    TEST_ASSERT(tm_local == &tm_buf, "localtime_r returns buffer");
}

/* ========================================================================== */
/* mktime tests                                                               */
/* ========================================================================== */
static void test_mktime(void) {
    struct tm tm_in;
    time_t t;
    
    printf("\n=== mktime Tests ===\n");
    
    memset(&tm_in, 0, sizeof(tm_in));
    tm_in.tm_year = 123;  /* 2023 */
    tm_in.tm_mon = 10;    /* November */
    tm_in.tm_mday = 14;
    tm_in.tm_hour = 22;
    tm_in.tm_min = 13;
    tm_in.tm_sec = 20;
    tm_in.tm_isdst = 0;
    
    t = mktime(&tm_in);
    TEST_ASSERT(t != (time_t)-1, "mktime() success");
    /* Note: exact value depends on timezone */
    
    /* Normalization test */
    memset(&tm_in, 0, sizeof(tm_in));
    tm_in.tm_year = 123;
    tm_in.tm_mon = 0;
    tm_in.tm_mday = 32;  /* Should normalize to Feb 1 */
    tm_in.tm_isdst = -1;
    
    t = mktime(&tm_in);
    TEST_ASSERT(t != (time_t)-1, "mktime() normalizes");
    TEST_ASSERT(tm_in.tm_mon == 1 && tm_in.tm_mday == 1, "mktime() normalized to Feb 1");
}

/* ========================================================================== */
/* strftime tests                                                             */
/* ========================================================================== */
static void test_strftime(void) {
    time_t t = 1700000000;
    struct tm *tm;
    char buf[128];
    size_t n;
    
    printf("\n=== strftime Tests ===\n");
    
    tm = gmtime(&t);
    
    n = strftime(buf, sizeof(buf), "%Y-%m-%d", tm);
    TEST_ASSERT(n > 0 && strcmp(buf, "2023-11-14") == 0, "strftime Y-m-d");
    
    n = strftime(buf, sizeof(buf), "%H:%M:%S", tm);
    TEST_ASSERT(n > 0 && strcmp(buf, "22:13:20") == 0, "strftime H:M:S");
    
    n = strftime(buf, sizeof(buf), "%A", tm);
    TEST_ASSERT(n > 0, "strftime weekday name");
    
    n = strftime(buf, sizeof(buf), "%B", tm);
    TEST_ASSERT(n > 0, "strftime month name");
    
    /* Buffer too small */
    n = strftime(buf, 5, "%Y-%m-%d", tm);
    TEST_ASSERT(n == 0, "strftime buffer too small");
}

/* ========================================================================== */
/* difftime tests                                                             */
/* ========================================================================== */
static void test_difftime(void) {
    time_t t1 = 1700000000;
    time_t t2 = 1700003600;  /* 1 hour later */
    double diff;

    printf("\n=== difftime Tests ===\n");

    diff = difftime(t2, t1);
    TEST_ASSERT(diff == 3600.0, "difftime 1 hour");

    diff = difftime(t1, t2);
    TEST_ASSERT(diff == -3600.0, "difftime negative");

    diff = difftime(t1, t1);
    TEST_ASSERT(diff == 0.0, "difftime same time");
}

/* ========================================================================== */
/* clock() tests                                                              */
/* ========================================================================== */
static void test_clock(void) {
    clock_t c1, c2;
    volatile int i;

    printf("\n=== clock() Tests ===\n");

    c1 = clock();
    TEST_ASSERT(c1 != (clock_t)-1, "clock() returns valid");

    /* Do some work */
    for (i = 0; i < 100000; i++) {
        /* busy loop */
    }

    c2 = clock();
    TEST_ASSERT(c2 >= c1, "clock() increases");
}

/* ========================================================================== */
/* nanosleep tests                                                            */
/* ========================================================================== */
static void test_nanosleep(void) {
    struct timespec req, rem;
    int ret;

    printf("\n=== nanosleep Tests ===\n");

    req.tv_sec = 0;
    req.tv_nsec = 10000000;  /* 10ms */
    memset(&rem, 0, sizeof(rem));

    ret = nanosleep(&req, &rem);
    TEST_ASSERT(ret == 0, "nanosleep returns 0");

    /* Note: In emulator, nanosleep may not actually sleep, so we just test
     * that it returns success. The rem structure should be zeroed on success. */
    TEST_ASSERT(rem.tv_sec == 0 && rem.tv_nsec == 0, "nanosleep rem is zero on success");
}

/* ========================================================================== */
/* Structure Layout Validation Tests                                          */
/* These tests verify that the ARM64 bionic libc structures have the expected */
/* sizes and field offsets. If these fail, the emulator's structure           */
/* conversion code may be incorrect.                                          */
/* ========================================================================== */
static void test_structure_layouts(void) {
    printf("\n=== Structure Layout Validation ===\n");

    /* struct timespec - ARM64 bionic: 16 bytes */
    TEST_ASSERT_MSG(sizeof(struct timespec) == 16,
        "sizeof(struct timespec) == 16",
        "got %zu", sizeof(struct timespec));
    TEST_ASSERT_MSG(offsetof(struct timespec, tv_sec) == 0,
        "offsetof(timespec, tv_sec) == 0",
        "got %zu", offsetof(struct timespec, tv_sec));
    TEST_ASSERT_MSG(offsetof(struct timespec, tv_nsec) == 8,
        "offsetof(timespec, tv_nsec) == 8",
        "got %zu", offsetof(struct timespec, tv_nsec));

    /* struct timeval - ARM64 bionic: 16 bytes */
    TEST_ASSERT_MSG(sizeof(struct timeval) == 16,
        "sizeof(struct timeval) == 16",
        "got %zu", sizeof(struct timeval));
    TEST_ASSERT_MSG(offsetof(struct timeval, tv_sec) == 0,
        "offsetof(timeval, tv_sec) == 0",
        "got %zu", offsetof(struct timeval, tv_sec));
    TEST_ASSERT_MSG(offsetof(struct timeval, tv_usec) == 8,
        "offsetof(timeval, tv_usec) == 8",
        "got %zu", offsetof(struct timeval, tv_usec));

    /* struct tm - ARM64 bionic: 56 bytes */
    TEST_ASSERT_MSG(sizeof(struct tm) == 56,
        "sizeof(struct tm) == 56",
        "got %zu", sizeof(struct tm));
    TEST_ASSERT_MSG(offsetof(struct tm, tm_sec) == 0,
        "offsetof(tm, tm_sec) == 0",
        "got %zu", offsetof(struct tm, tm_sec));
    TEST_ASSERT_MSG(offsetof(struct tm, tm_min) == 4,
        "offsetof(tm, tm_min) == 4",
        "got %zu", offsetof(struct tm, tm_min));
    TEST_ASSERT_MSG(offsetof(struct tm, tm_hour) == 8,
        "offsetof(tm, tm_hour) == 8",
        "got %zu", offsetof(struct tm, tm_hour));
    TEST_ASSERT_MSG(offsetof(struct tm, tm_mday) == 12,
        "offsetof(tm, tm_mday) == 12",
        "got %zu", offsetof(struct tm, tm_mday));
    TEST_ASSERT_MSG(offsetof(struct tm, tm_mon) == 16,
        "offsetof(tm, tm_mon) == 16",
        "got %zu", offsetof(struct tm, tm_mon));
    TEST_ASSERT_MSG(offsetof(struct tm, tm_year) == 20,
        "offsetof(tm, tm_year) == 20",
        "got %zu", offsetof(struct tm, tm_year));
    TEST_ASSERT_MSG(offsetof(struct tm, tm_wday) == 24,
        "offsetof(tm, tm_wday) == 24",
        "got %zu", offsetof(struct tm, tm_wday));
    TEST_ASSERT_MSG(offsetof(struct tm, tm_yday) == 28,
        "offsetof(tm, tm_yday) == 28",
        "got %zu", offsetof(struct tm, tm_yday));
    TEST_ASSERT_MSG(offsetof(struct tm, tm_isdst) == 32,
        "offsetof(tm, tm_isdst) == 32",
        "got %zu", offsetof(struct tm, tm_isdst));
    TEST_ASSERT_MSG(offsetof(struct tm, tm_gmtoff) == 40,
        "offsetof(tm, tm_gmtoff) == 40",
        "got %zu", offsetof(struct tm, tm_gmtoff));
    TEST_ASSERT_MSG(offsetof(struct tm, tm_zone) == 48,
        "offsetof(tm, tm_zone) == 48",
        "got %zu", offsetof(struct tm, tm_zone));
}

/* ========================================================================== */
/* Structure Field Value Tests                                                */
/* These tests verify that structure fields are correctly read/written by     */
/* the emulator's HLE functions.                                              */
/* ========================================================================== */
static void test_structure_field_values(void) {
    struct timespec ts;
    struct timeval tv;
    struct tm tm_val;
    time_t t = 1700000000;  /* 2023-11-14 22:13:20 UTC */

    printf("\n=== Structure Field Value Tests ===\n");

    /* Test clock_gettime writes correct fields */
    memset(&ts, 0xAA, sizeof(ts));  /* Fill with pattern */
    clock_gettime(CLOCK_REALTIME, &ts);
    TEST_ASSERT(ts.tv_sec > 1700000000, "clock_gettime tv_sec field valid");
    TEST_ASSERT(ts.tv_nsec >= 0 && ts.tv_nsec < 1000000000, "clock_gettime tv_nsec field valid");

    /* Test gettimeofday writes correct fields */
    memset(&tv, 0xAA, sizeof(tv));  /* Fill with pattern */
    gettimeofday(&tv, NULL);
    TEST_ASSERT(tv.tv_sec > 1700000000, "gettimeofday tv_sec field valid");
    TEST_ASSERT(tv.tv_usec >= 0 && tv.tv_usec < 1000000, "gettimeofday tv_usec field valid");

    /* Test gmtime_r writes all tm fields correctly */
    memset(&tm_val, 0xAA, sizeof(tm_val));  /* Fill with pattern */
    gmtime_r(&t, &tm_val);
    TEST_ASSERT(tm_val.tm_sec == 20, "gmtime_r tm_sec field");
    TEST_ASSERT(tm_val.tm_min == 13, "gmtime_r tm_min field");
    TEST_ASSERT(tm_val.tm_hour == 22, "gmtime_r tm_hour field");
    TEST_ASSERT(tm_val.tm_mday == 14, "gmtime_r tm_mday field");
    TEST_ASSERT(tm_val.tm_mon == 10, "gmtime_r tm_mon field");
    TEST_ASSERT(tm_val.tm_year == 123, "gmtime_r tm_year field");
    TEST_ASSERT(tm_val.tm_wday == 2, "gmtime_r tm_wday field");  /* Tuesday */
    TEST_ASSERT(tm_val.tm_yday == 317, "gmtime_r tm_yday field");
    TEST_ASSERT(tm_val.tm_isdst == 0, "gmtime_r tm_isdst field");
    TEST_ASSERT(tm_val.tm_gmtoff == 0, "gmtime_r tm_gmtoff field");
}

/* ========================================================================== */
/* Main entry point                                                           */
/* ========================================================================== */
int run_time_tests(void) {
    printf("\n");
    printf("========================================\n");
    printf("   TIME FUNCTION TEST SUITE\n");
    printf("========================================\n");

    test_structure_layouts();
    test_structure_field_values();
    test_time();
    test_gettimeofday();
    test_clock_gettime();
    test_localtime_gmtime();
    test_mktime();
    test_strftime();
    test_difftime();
    test_clock();
    test_nanosleep();

    printf("\n========================================\n");
    printf("   TIME RESULTS: %d passed, %d failed\n", tests_passed, tests_failed);
    printf("========================================\n");

    return tests_failed;
}

