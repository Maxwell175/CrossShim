/**
 * Wide Character Function Tests for Android Emulator Validation
 * Tests libc wide character and multibyte functions.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <wchar.h>

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
/* wcslen tests                                                               */
/* ========================================================================== */
static void test_wcslen(void) {
    printf("\n=== wcslen Tests ===\n");
    
    TEST_ASSERT(wcslen(L"") == 0, "wcslen empty");
    TEST_ASSERT(wcslen(L"hello") == 5, "wcslen 'hello'");
    TEST_ASSERT(wcslen(L"a") == 1, "wcslen single char");
    TEST_ASSERT(wcslen(L"hello world") == 11, "wcslen 'hello world'");
}

/* ========================================================================== */
/* wcscpy tests                                                               */
/* ========================================================================== */
static void test_wcscpy(void) {
    wchar_t buf[64];
    
    printf("\n=== wcscpy Tests ===\n");
    
    wcscpy(buf, L"hello");
    TEST_ASSERT(wcscmp(buf, L"hello") == 0, "wcscpy basic");
    
    wcscpy(buf, L"");
    TEST_ASSERT(wcscmp(buf, L"") == 0, "wcscpy empty");
    
    wcscpy(buf, L"test string");
    TEST_ASSERT(wcslen(buf) == 11, "wcscpy length");
}

/* ========================================================================== */
/* wcsncpy tests                                                              */
/* ========================================================================== */
static void test_wcsncpy(void) {
    wchar_t buf[64];
    
    printf("\n=== wcsncpy Tests ===\n");
    
    memset(buf, 0xFF, sizeof(buf));
    wcsncpy(buf, L"hello world", 5);
    TEST_ASSERT(wcsncmp(buf, L"hello", 5) == 0, "wcsncpy partial");
    
    memset(buf, 0, sizeof(buf));
    wcsncpy(buf, L"hi", 10);
    TEST_ASSERT(wcscmp(buf, L"hi") == 0, "wcsncpy with padding");
}

/* ========================================================================== */
/* wcscmp tests                                                               */
/* ========================================================================== */
static void test_wcscmp(void) {
    printf("\n=== wcscmp Tests ===\n");
    
    TEST_ASSERT(wcscmp(L"abc", L"abc") == 0, "wcscmp equal");
    TEST_ASSERT(wcscmp(L"abc", L"abd") < 0, "wcscmp less");
    TEST_ASSERT(wcscmp(L"abd", L"abc") > 0, "wcscmp greater");
    TEST_ASSERT(wcscmp(L"", L"") == 0, "wcscmp empty");
    TEST_ASSERT(wcscmp(L"a", L"") > 0, "wcscmp vs empty");
}

/* ========================================================================== */
/* wcsncmp tests                                                              */
/* ========================================================================== */
static void test_wcsncmp(void) {
    printf("\n=== wcsncmp Tests ===\n");
    
    TEST_ASSERT(wcsncmp(L"abcdef", L"abcxyz", 3) == 0, "wcsncmp equal prefix");
    TEST_ASSERT(wcsncmp(L"abcdef", L"abcxyz", 4) < 0, "wcsncmp differ at 4");
    TEST_ASSERT(wcsncmp(L"abc", L"abc", 10) == 0, "wcsncmp n > len");
}

/* ========================================================================== */
/* mbstowcs/wcstombs tests                                                    */
/* ========================================================================== */
static void test_mbstowcs_wcstombs(void) {
    wchar_t wbuf[64];
    char mbuf[64];
    size_t result;
    
    printf("\n=== mbstowcs/wcstombs Tests ===\n");
    
    result = mbstowcs(wbuf, "hello", 64);
    TEST_ASSERT(result == 5, "mbstowcs returns length");
    TEST_ASSERT(wcscmp(wbuf, L"hello") == 0, "mbstowcs converts correctly");
    
    result = wcstombs(mbuf, L"world", 64);
    TEST_ASSERT(result == 5, "wcstombs returns length");
    TEST_ASSERT(strcmp(mbuf, "world") == 0, "wcstombs converts correctly");
    
    result = mbstowcs(wbuf, "", 64);
    TEST_ASSERT(result == 0, "mbstowcs empty string");
    
    result = wcstombs(mbuf, L"", 64);
    TEST_ASSERT(result == 0, "wcstombs empty string");
}

/* ========================================================================== */
/* Entry point                                                                */
/* ========================================================================== */
void run_wchar_tests(int *passed, int *failed) {
    printf("\n========================================\n");
    printf("   WIDE CHARACTER FUNCTION TESTS\n");
    printf("========================================\n");
    
    tests_passed = 0;
    tests_failed = 0;
    
    test_wcslen();
    test_wcscpy();
    test_wcsncpy();
    test_wcscmp();
    test_wcsncmp();
    test_mbstowcs_wcstombs();
    
    printf("\n========================================\n");
    printf("   WCHAR RESULTS: %d passed, %d failed\n", tests_passed, tests_failed);
    printf("========================================\n");
    
    *passed = tests_passed;
    *failed = tests_failed;
}

