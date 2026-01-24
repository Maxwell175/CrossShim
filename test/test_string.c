/**
 * String Function Tests for Android Emulator Validation
 * Tests libc string and memory functions.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
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
/* strlen tests                                                               */
/* ========================================================================== */
static void test_strlen(void) {
    printf("\n=== strlen Tests ===\n");
    
    TEST_ASSERT(strlen("") == 0, "strlen empty string");
    TEST_ASSERT(strlen("hello") == 5, "strlen 'hello'");
    TEST_ASSERT(strlen("hello world") == 11, "strlen 'hello world'");
    TEST_ASSERT(strlen("a") == 1, "strlen single char");
}

/* ========================================================================== */
/* strcpy/strncpy tests                                                       */
/* ========================================================================== */
static void test_strcpy(void) {
    char buf[64];
    
    printf("\n=== strcpy/strncpy Tests ===\n");
    
    strcpy(buf, "hello");
    TEST_ASSERT(strcmp(buf, "hello") == 0, "strcpy basic");
    
    strcpy(buf, "");
    TEST_ASSERT(strcmp(buf, "") == 0, "strcpy empty");
    
    strncpy(buf, "hello world", 5);
    buf[5] = '\0';
    TEST_ASSERT(strcmp(buf, "hello") == 0, "strncpy truncate");
    
    memset(buf, 'X', sizeof(buf));
    strncpy(buf, "hi", 10);
    TEST_ASSERT(strcmp(buf, "hi") == 0, "strncpy with padding");
    TEST_ASSERT(buf[2] == '\0' && buf[9] == '\0', "strncpy null padding");
}

/* ========================================================================== */
/* strcat/strncat tests                                                       */
/* ========================================================================== */
static void test_strcat(void) {
    char buf[64];
    
    printf("\n=== strcat/strncat Tests ===\n");
    
    strcpy(buf, "hello");
    strcat(buf, " world");
    TEST_ASSERT(strcmp(buf, "hello world") == 0, "strcat basic");
    
    strcpy(buf, "");
    strcat(buf, "test");
    TEST_ASSERT(strcmp(buf, "test") == 0, "strcat to empty");
    
    strcpy(buf, "hello");
    strncat(buf, " world!!!", 6);
    TEST_ASSERT(strcmp(buf, "hello world") == 0, "strncat truncate");
}

/* ========================================================================== */
/* strcmp/strncmp tests                                                       */
/* ========================================================================== */
static void test_strcmp(void) {
    printf("\n=== strcmp/strncmp Tests ===\n");
    
    TEST_ASSERT(strcmp("hello", "hello") == 0, "strcmp equal");
    TEST_ASSERT(strcmp("abc", "abd") < 0, "strcmp less than");
    TEST_ASSERT(strcmp("abd", "abc") > 0, "strcmp greater than");
    TEST_ASSERT(strcmp("", "") == 0, "strcmp empty");
    TEST_ASSERT(strcmp("a", "") > 0, "strcmp vs empty");
    
    TEST_ASSERT(strncmp("hello", "hello world", 5) == 0, "strncmp prefix match");
    TEST_ASSERT(strncmp("hello", "help", 3) == 0, "strncmp partial match");
    TEST_ASSERT(strncmp("abc", "abd", 2) == 0, "strncmp before diff");
    TEST_ASSERT(strncmp("abc", "abd", 3) < 0, "strncmp at diff");
}

/* ========================================================================== */
/* strchr/strrchr tests                                                       */
/* ========================================================================== */
static void test_strchr(void) {
    const char *s = "hello world";
    
    printf("\n=== strchr/strrchr Tests ===\n");
    
    TEST_ASSERT(strchr(s, 'h') == s, "strchr first char");
    TEST_ASSERT(strchr(s, 'o') == s + 4, "strchr middle char");
    TEST_ASSERT(strchr(s, 'z') == NULL, "strchr not found");
    TEST_ASSERT(strchr(s, '\0') == s + 11, "strchr null terminator");
    
    TEST_ASSERT(strrchr(s, 'o') == s + 7, "strrchr last occurrence");
    TEST_ASSERT(strrchr(s, 'h') == s, "strrchr first char");
    TEST_ASSERT(strrchr(s, 'z') == NULL, "strrchr not found");
}

/* ========================================================================== */
/* strstr tests                                                               */
/* ========================================================================== */
static void test_strstr(void) {
    const char *s = "hello world";
    
    printf("\n=== strstr Tests ===\n");
    
    TEST_ASSERT(strstr(s, "hello") == s, "strstr at start");
    TEST_ASSERT(strstr(s, "world") == s + 6, "strstr at end");
    TEST_ASSERT(strstr(s, "lo wo") == s + 3, "strstr middle");
    TEST_ASSERT(strstr(s, "") == s, "strstr empty needle");
    TEST_ASSERT(strstr(s, "xyz") == NULL, "strstr not found");
    TEST_ASSERT(strstr(s, "hello world!") == NULL, "strstr too long");
}

/* ========================================================================== */
/* memcpy/memmove tests                                                       */
/* ========================================================================== */
static void test_memcpy(void) {
    char src[] = "hello world";
    char dst[32];
    char overlap[32] = "0123456789";
    
    printf("\n=== memcpy/memmove Tests ===\n");
    
    memset(dst, 0, sizeof(dst));
    memcpy(dst, src, 5);
    TEST_ASSERT(memcmp(dst, "hello", 5) == 0, "memcpy basic");
    
    memset(dst, 0, sizeof(dst));
    memcpy(dst, src, 0);
    TEST_ASSERT(dst[0] == 0, "memcpy zero length");
    
    /* memmove with overlap - forward */
    memmove(overlap + 2, overlap, 5);
    TEST_ASSERT(memcmp(overlap, "0101234789", 10) == 0, "memmove forward overlap");
    
    /* memmove with overlap - backward */
    strcpy(overlap, "0123456789");
    memmove(overlap, overlap + 2, 5);
    TEST_ASSERT(memcmp(overlap, "2345656789", 10) == 0, "memmove backward overlap");
}

/* ========================================================================== */
/* memset/memcmp/memchr tests                                                 */
/* ========================================================================== */
static void test_memset(void) {
    char buf[32];
    unsigned char ubuf[16];

    printf("\n=== memset/memcmp/memchr Tests ===\n");

    memset(buf, 'A', 10);
    buf[10] = '\0';
    TEST_ASSERT(strcmp(buf, "AAAAAAAAAA") == 0, "memset basic");

    memset(buf, 0, 10);
    TEST_ASSERT(buf[0] == 0 && buf[9] == 0, "memset zero");

    /* memcmp */
    TEST_ASSERT(memcmp("abc", "abc", 3) == 0, "memcmp equal");
    TEST_ASSERT(memcmp("abc", "abd", 3) < 0, "memcmp less");
    TEST_ASSERT(memcmp("abd", "abc", 3) > 0, "memcmp greater");
    TEST_ASSERT(memcmp("abc", "abx", 2) == 0, "memcmp partial");

    /* memchr */
    memset(ubuf, 0, sizeof(ubuf));
    ubuf[5] = 0x42;
    TEST_ASSERT(memchr(ubuf, 0x42, 16) == ubuf + 5, "memchr found");
    TEST_ASSERT(memchr(ubuf, 0x99, 16) == NULL, "memchr not found");
    TEST_ASSERT(memchr(ubuf, 0x42, 5) == NULL, "memchr before range");
}

/* ========================================================================== */
/* strtok tests                                                               */
/* ========================================================================== */
static void test_strtok(void) {
    char str[64];
    char *tok;

    printf("\n=== strtok Tests ===\n");

    strcpy(str, "hello,world,test");
    tok = strtok(str, ",");
    TEST_ASSERT(tok != NULL && strcmp(tok, "hello") == 0, "strtok first token");

    tok = strtok(NULL, ",");
    TEST_ASSERT(tok != NULL && strcmp(tok, "world") == 0, "strtok second token");

    tok = strtok(NULL, ",");
    TEST_ASSERT(tok != NULL && strcmp(tok, "test") == 0, "strtok third token");

    tok = strtok(NULL, ",");
    TEST_ASSERT(tok == NULL, "strtok end");
}

/* ========================================================================== */
/* strdup/strndup tests                                                       */
/* ========================================================================== */
static void test_strdup(void) {
    char *dup;

    printf("\n=== strdup/strndup Tests ===\n");

    dup = strdup("hello");
    TEST_ASSERT(dup != NULL && strcmp(dup, "hello") == 0, "strdup basic");
    free(dup);

    dup = strdup("");
    TEST_ASSERT(dup != NULL && strcmp(dup, "") == 0, "strdup empty");
    free(dup);

    dup = strndup("hello world", 5);
    TEST_ASSERT(dup != NULL && strcmp(dup, "hello") == 0, "strndup truncate");
    free(dup);

    dup = strndup("hi", 10);
    TEST_ASSERT(dup != NULL && strcmp(dup, "hi") == 0, "strndup short string");
    free(dup);
}

/* ========================================================================== */
/* sprintf/snprintf tests                                                     */
/* ========================================================================== */
static void test_sprintf(void) {
    char buf[128];
    int n;

    printf("\n=== sprintf/snprintf Tests ===\n");

    sprintf(buf, "hello %s", "world");
    TEST_ASSERT(strcmp(buf, "hello world") == 0, "sprintf string");

    sprintf(buf, "%d + %d = %d", 2, 3, 5);
    TEST_ASSERT(strcmp(buf, "2 + 3 = 5") == 0, "sprintf integers");

    sprintf(buf, "%x %X", 255, 255);
    TEST_ASSERT(strcmp(buf, "ff FF") == 0, "sprintf hex");

    sprintf(buf, "%c", 'A');
    TEST_ASSERT(strcmp(buf, "A") == 0, "sprintf char");

    sprintf(buf, "%%");
    TEST_ASSERT(strcmp(buf, "%") == 0, "sprintf percent");

    n = snprintf(buf, 10, "hello world");
    TEST_ASSERT(n == 11 && strcmp(buf, "hello wor") == 0, "snprintf truncate");

    n = snprintf(buf, 128, "test");
    TEST_ASSERT(n == 4 && strcmp(buf, "test") == 0, "snprintf no truncate");
}

/* ========================================================================== */
/* strspn/strcspn tests (from string_extra)                                   */
/* ========================================================================== */
static void test_strspn_strcspn(void) {
    printf("\n=== strspn/strcspn Tests ===\n");

    TEST_ASSERT(strspn("hello", "hel") == 4, "strspn 'hello' 'hel'");
    TEST_ASSERT(strspn("hello", "abc") == 0, "strspn no match");
    TEST_ASSERT(strspn("aabbcc", "abc") == 6, "strspn all match");
    TEST_ASSERT(strspn("", "abc") == 0, "strspn empty string");

    TEST_ASSERT(strcspn("hello", "o") == 4, "strcspn 'hello' 'o'");
    TEST_ASSERT(strcspn("hello", "xyz") == 5, "strcspn no match");
    TEST_ASSERT(strcspn("hello", "h") == 0, "strcspn first char");
    TEST_ASSERT(strcspn("", "abc") == 0, "strcspn empty string");
}

/* ========================================================================== */
/* strpbrk tests (from string_extra)                                          */
/* ========================================================================== */
static void test_strpbrk(void) {
    char *result;

    printf("\n=== strpbrk Tests ===\n");

    result = strpbrk("hello world", "aeiou");
    TEST_ASSERT(result != NULL && *result == 'e', "strpbrk finds 'e'");

    result = strpbrk("hello", "xyz");
    TEST_ASSERT(result == NULL, "strpbrk no match");

    result = strpbrk("hello", "h");
    TEST_ASSERT(result != NULL && result[0] == 'h', "strpbrk first char");
}

/* ========================================================================== */
/* strsep tests (from string_extra)                                           */
/* ========================================================================== */
static void test_strsep(void) {
    char str[] = "one,two,three";
    char *ptr = str;
    char *token;

    printf("\n=== strsep Tests ===\n");

    token = strsep(&ptr, ",");
    TEST_ASSERT(token != NULL && strcmp(token, "one") == 0, "strsep first token");

    token = strsep(&ptr, ",");
    TEST_ASSERT(token != NULL && strcmp(token, "two") == 0, "strsep second token");

    token = strsep(&ptr, ",");
    TEST_ASSERT(token != NULL && strcmp(token, "three") == 0, "strsep third token");

    token = strsep(&ptr, ",");
    TEST_ASSERT(token == NULL, "strsep end");
}

/* ========================================================================== */
/* strcasecmp/strncasecmp tests (from string_extra)                           */
/* ========================================================================== */
static void test_strcasecmp(void) {
    printf("\n=== strcasecmp/strncasecmp Tests ===\n");

    TEST_ASSERT(strcasecmp("hello", "HELLO") == 0, "strcasecmp equal");
    TEST_ASSERT(strcasecmp("Hello", "hElLo") == 0, "strcasecmp mixed case");
    TEST_ASSERT(strcasecmp("abc", "abd") < 0, "strcasecmp less");
    TEST_ASSERT(strcasecmp("abd", "abc") > 0, "strcasecmp greater");

    TEST_ASSERT(strncasecmp("HELLO", "hello world", 5) == 0, "strncasecmp prefix");
    TEST_ASSERT(strncasecmp("ABC", "ABD", 2) == 0, "strncasecmp partial");
}

/* ========================================================================== */
/* strcasestr tests (from string_extra)                                       */
/* ========================================================================== */
static void test_strcasestr(void) {
    char *result;

    printf("\n=== strcasestr Tests ===\n");

    result = strcasestr("Hello World", "WORLD");
    TEST_ASSERT(result != NULL, "strcasestr finds WORLD");

    result = strcasestr("Hello World", "xyz");
    TEST_ASSERT(result == NULL, "strcasestr no match");

    result = strcasestr("HELLO", "hello");
    TEST_ASSERT(result != NULL, "strcasestr case insensitive");
}

/* ========================================================================== */
/* stpcpy/stpncpy tests (from string_extra)                                   */
/* ========================================================================== */
static void test_stpcpy(void) {
    char buf[64];
    char *end;

    printf("\n=== stpcpy/stpncpy Tests ===\n");

    end = stpcpy(buf, "hello");
    TEST_ASSERT(strcmp(buf, "hello") == 0, "stpcpy copies");
    TEST_ASSERT(*end == '\0', "stpcpy returns end");
    TEST_ASSERT(end == buf + 5, "stpcpy end position");

    end = stpncpy(buf, "world", 3);
    TEST_ASSERT(strncmp(buf, "wor", 3) == 0, "stpncpy copies n chars");
}

/* ========================================================================== */
/* bcopy/bzero tests (from string_extra)                                      */
/* ========================================================================== */
static void test_bcopy_bzero(void) {
    char src[] = "hello";
    char dst[10];
    char buf[10];

    printf("\n=== bcopy/bzero Tests ===\n");

    bcopy(src, dst, 6);
    TEST_ASSERT(strcmp(dst, "hello") == 0, "bcopy copies");

    memset(buf, 'x', 10);
    bzero(buf, 5);
    TEST_ASSERT(buf[0] == 0 && buf[4] == 0, "bzero clears");
    TEST_ASSERT(buf[5] == 'x', "bzero only clears n bytes");
}

/* ========================================================================== */
/* memrchr tests (from string_extra)                                          */
/* ========================================================================== */
static void test_memrchr(void) {
    char *result;
    const char *str = "hello world";

    printf("\n=== memrchr Tests ===\n");

    result = memrchr(str, 'o', strlen(str));
    TEST_ASSERT(result != NULL && result == str + 7, "memrchr finds last 'o'");

    result = memrchr(str, 'h', strlen(str));
    TEST_ASSERT(result != NULL && result == str, "memrchr finds 'h'");

    result = memrchr(str, 'z', strlen(str));
    TEST_ASSERT(result == NULL, "memrchr no match");
}

/* ========================================================================== */
/* Main entry point                                                           */
/* ========================================================================== */
int run_string_tests(void) {
    printf("\n");
    printf("========================================\n");
    printf("   STRING FUNCTION TEST SUITE\n");
    printf("========================================\n");

    test_strlen();
    test_strcpy();
    test_strcat();
    test_strcmp();
    test_strchr();
    test_strstr();
    test_memcpy();
    test_memset();
    test_strtok();
    test_strdup();
    test_sprintf();
    test_strspn_strcspn();
    test_strpbrk();
    test_strsep();
    test_strcasecmp();
    test_strcasestr();
    test_stpcpy();
    test_bcopy_bzero();
    test_memrchr();

    printf("\n========================================\n");
    printf("   STRING RESULTS: %d passed, %d failed\n", tests_passed, tests_failed);
    printf("========================================\n");

    return tests_failed;
}

