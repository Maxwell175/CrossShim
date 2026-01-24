/**
 * Ctype Function Tests for Android Emulator Validation
 * Tests libc ctype functions.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

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
/* isalpha tests                                                              */
/* ========================================================================== */
static void test_isalpha(void) {
    printf("\n=== isalpha Tests ===\n");
    
    TEST_ASSERT(isalpha('a') != 0, "isalpha 'a'");
    TEST_ASSERT(isalpha('z') != 0, "isalpha 'z'");
    TEST_ASSERT(isalpha('A') != 0, "isalpha 'A'");
    TEST_ASSERT(isalpha('Z') != 0, "isalpha 'Z'");
    TEST_ASSERT(isalpha('0') == 0, "isalpha '0' false");
    TEST_ASSERT(isalpha(' ') == 0, "isalpha ' ' false");
    TEST_ASSERT(isalpha('@') == 0, "isalpha '@' false");
}

/* ========================================================================== */
/* isdigit tests                                                              */
/* ========================================================================== */
static void test_isdigit(void) {
    printf("\n=== isdigit Tests ===\n");
    
    TEST_ASSERT(isdigit('0') != 0, "isdigit '0'");
    TEST_ASSERT(isdigit('5') != 0, "isdigit '5'");
    TEST_ASSERT(isdigit('9') != 0, "isdigit '9'");
    TEST_ASSERT(isdigit('a') == 0, "isdigit 'a' false");
    TEST_ASSERT(isdigit('A') == 0, "isdigit 'A' false");
    TEST_ASSERT(isdigit(' ') == 0, "isdigit ' ' false");
}

/* ========================================================================== */
/* isalnum tests                                                              */
/* ========================================================================== */
static void test_isalnum(void) {
    printf("\n=== isalnum Tests ===\n");
    
    TEST_ASSERT(isalnum('a') != 0, "isalnum 'a'");
    TEST_ASSERT(isalnum('Z') != 0, "isalnum 'Z'");
    TEST_ASSERT(isalnum('5') != 0, "isalnum '5'");
    TEST_ASSERT(isalnum(' ') == 0, "isalnum ' ' false");
    TEST_ASSERT(isalnum('!') == 0, "isalnum '!' false");
    TEST_ASSERT(isalnum('\n') == 0, "isalnum '\\n' false");
}

/* ========================================================================== */
/* isspace tests                                                              */
/* ========================================================================== */
static void test_isspace(void) {
    printf("\n=== isspace Tests ===\n");
    
    TEST_ASSERT(isspace(' ') != 0, "isspace ' '");
    TEST_ASSERT(isspace('\t') != 0, "isspace '\\t'");
    TEST_ASSERT(isspace('\n') != 0, "isspace '\\n'");
    TEST_ASSERT(isspace('\r') != 0, "isspace '\\r'");
    TEST_ASSERT(isspace('\f') != 0, "isspace '\\f'");
    TEST_ASSERT(isspace('\v') != 0, "isspace '\\v'");
    TEST_ASSERT(isspace('a') == 0, "isspace 'a' false");
    TEST_ASSERT(isspace('0') == 0, "isspace '0' false");
}

/* ========================================================================== */
/* isupper/islower tests                                                      */
/* ========================================================================== */
static void test_isupper_islower(void) {
    printf("\n=== isupper/islower Tests ===\n");
    
    TEST_ASSERT(isupper('A') != 0, "isupper 'A'");
    TEST_ASSERT(isupper('Z') != 0, "isupper 'Z'");
    TEST_ASSERT(isupper('a') == 0, "isupper 'a' false");
    TEST_ASSERT(isupper('0') == 0, "isupper '0' false");
    
    TEST_ASSERT(islower('a') != 0, "islower 'a'");
    TEST_ASSERT(islower('z') != 0, "islower 'z'");
    TEST_ASSERT(islower('A') == 0, "islower 'A' false");
    TEST_ASSERT(islower('0') == 0, "islower '0' false");
}

/* ========================================================================== */
/* toupper/tolower tests                                                      */
/* ========================================================================== */
static void test_toupper_tolower(void) {
    printf("\n=== toupper/tolower Tests ===\n");
    
    TEST_ASSERT(toupper('a') == 'A', "toupper 'a'");
    TEST_ASSERT(toupper('z') == 'Z', "toupper 'z'");
    TEST_ASSERT(toupper('A') == 'A', "toupper 'A' unchanged");
    TEST_ASSERT(toupper('0') == '0', "toupper '0' unchanged");
    
    TEST_ASSERT(tolower('A') == 'a', "tolower 'A'");
    TEST_ASSERT(tolower('Z') == 'z', "tolower 'Z'");
    TEST_ASSERT(tolower('a') == 'a', "tolower 'a' unchanged");
    TEST_ASSERT(tolower('0') == '0', "tolower '0' unchanged");
}

/* ========================================================================== */
/* isxdigit tests                                                             */
/* ========================================================================== */
static void test_isxdigit(void) {
    printf("\n=== isxdigit Tests ===\n");
    
    TEST_ASSERT(isxdigit('0') != 0, "isxdigit '0'");
    TEST_ASSERT(isxdigit('9') != 0, "isxdigit '9'");
    TEST_ASSERT(isxdigit('a') != 0, "isxdigit 'a'");
    TEST_ASSERT(isxdigit('f') != 0, "isxdigit 'f'");
    TEST_ASSERT(isxdigit('A') != 0, "isxdigit 'A'");
    TEST_ASSERT(isxdigit('F') != 0, "isxdigit 'F'");
    TEST_ASSERT(isxdigit('g') == 0, "isxdigit 'g' false");
    TEST_ASSERT(isxdigit('G') == 0, "isxdigit 'G' false");
}

/* ========================================================================== */
/* isprint/isgraph/iscntrl tests                                              */
/* ========================================================================== */
static void test_isprint_isgraph_iscntrl(void) {
    printf("\n=== isprint/isgraph/iscntrl Tests ===\n");
    
    TEST_ASSERT(isprint('a') != 0, "isprint 'a'");
    TEST_ASSERT(isprint(' ') != 0, "isprint ' '");
    TEST_ASSERT(isprint('\n') == 0, "isprint '\\n' false");
    TEST_ASSERT(isprint('\0') == 0, "isprint '\\0' false");
    
    TEST_ASSERT(isgraph('a') != 0, "isgraph 'a'");
    TEST_ASSERT(isgraph('!') != 0, "isgraph '!'");
    TEST_ASSERT(isgraph(' ') == 0, "isgraph ' ' false");
    TEST_ASSERT(isgraph('\n') == 0, "isgraph '\\n' false");
    
    TEST_ASSERT(iscntrl('\0') != 0, "iscntrl '\\0'");
    TEST_ASSERT(iscntrl('\n') != 0, "iscntrl '\\n'");
    TEST_ASSERT(iscntrl('\x1F') != 0, "iscntrl 0x1F");
    TEST_ASSERT(iscntrl('a') == 0, "iscntrl 'a' false");
}

/* ========================================================================== */
/* ispunct tests                                                              */
/* ========================================================================== */
static void test_ispunct(void) {
    printf("\n=== ispunct Tests ===\n");
    
    TEST_ASSERT(ispunct('!') != 0, "ispunct '!'");
    TEST_ASSERT(ispunct('.') != 0, "ispunct '.'");
    TEST_ASSERT(ispunct(',') != 0, "ispunct ','");
    TEST_ASSERT(ispunct('@') != 0, "ispunct '@'");
    TEST_ASSERT(ispunct('a') == 0, "ispunct 'a' false");
    TEST_ASSERT(ispunct('0') == 0, "ispunct '0' false");
    TEST_ASSERT(ispunct(' ') == 0, "ispunct ' ' false");
}

/* ========================================================================== */
/* Main entry point                                                           */
/* ========================================================================== */
int run_ctype_tests(void) {
    printf("\n");
    printf("========================================\n");
    printf("   CTYPE FUNCTION TEST SUITE\n");
    printf("========================================\n");
    
    test_isalpha();
    test_isdigit();
    test_isalnum();
    test_isspace();
    test_isupper_islower();
    test_toupper_tolower();
    test_isxdigit();
    test_isprint_isgraph_iscntrl();
    test_ispunct();
    
    printf("\n========================================\n");
    printf("   CTYPE RESULTS: %d passed, %d failed\n", tests_passed, tests_failed);
    printf("========================================\n");
    
    return tests_failed;
}

