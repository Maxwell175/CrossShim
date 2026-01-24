/**
 * Stdio Function Tests for Android Emulator Validation
 * Tests libc stdio functions.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

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

static const char *test_file = "/tmp/emu_test_stdio.txt";

/* ========================================================================== */
/* sscanf tests                                                               */
/* ========================================================================== */
static void test_sscanf(void) {
    int i1, i2;
    float f;
    char str[64];
    int n;
    
    printf("\n=== sscanf Tests ===\n");
    
    n = sscanf("42", "%d", &i1);
    TEST_ASSERT(n == 1 && i1 == 42, "sscanf integer");
    
    n = sscanf("10 20", "%d %d", &i1, &i2);
    TEST_ASSERT(n == 2 && i1 == 10 && i2 == 20, "sscanf two integers");
    
    n = sscanf("3.14", "%f", &f);
    TEST_ASSERT(n == 1 && f > 3.13 && f < 3.15, "sscanf float");
    
    n = sscanf("hello world", "%s", str);
    TEST_ASSERT(n == 1 && strcmp(str, "hello") == 0, "sscanf string");
    
    n = sscanf("0xff", "%x", &i1);
    TEST_ASSERT(n == 1 && i1 == 255, "sscanf hex");
    
    n = sscanf("abc 123", "%[a-z] %d", str, &i1);
    TEST_ASSERT(n == 2 && strcmp(str, "abc") == 0 && i1 == 123, "sscanf scanset");
}

/* ========================================================================== */
/* fopen/fclose tests                                                         */
/* ========================================================================== */
static void test_fopen(void) {
    FILE *fp;
    
    printf("\n=== fopen/fclose Tests ===\n");
    
    /* Create and close */
    fp = fopen(test_file, "w");
    TEST_ASSERT(fp != NULL, "fopen write mode");
    if (fp) {
        int ret = fclose(fp);
        TEST_ASSERT(ret == 0, "fclose");
    }
    
    /* Open for read */
    fp = fopen(test_file, "r");
    TEST_ASSERT(fp != NULL, "fopen read mode");
    if (fp) fclose(fp);
    
    /* Open for append */
    fp = fopen(test_file, "a");
    TEST_ASSERT(fp != NULL, "fopen append mode");
    if (fp) fclose(fp);
    
    /* Open non-existent file for read */
    fp = fopen("/tmp/nonexistent_file_12345.txt", "r");
    TEST_ASSERT(fp == NULL, "fopen non-existent file");
}

/* ========================================================================== */
/* fread/fwrite tests                                                         */
/* ========================================================================== */
static void test_fread_fwrite(void) {
    FILE *fp;
    char write_buf[] = "Hello, World!";
    char read_buf[64];
    size_t n;
    
    printf("\n=== fread/fwrite Tests ===\n");
    
    /* Write data */
    fp = fopen(test_file, "wb");
    TEST_ASSERT(fp != NULL, "fopen for write");
    if (fp) {
        n = fwrite(write_buf, 1, strlen(write_buf), fp);
        TEST_ASSERT(n == strlen(write_buf), "fwrite");
        fclose(fp);
    }
    
    /* Read data back */
    fp = fopen(test_file, "rb");
    TEST_ASSERT(fp != NULL, "fopen for read");
    if (fp) {
        memset(read_buf, 0, sizeof(read_buf));
        n = fread(read_buf, 1, sizeof(read_buf), fp);
        TEST_ASSERT(n == strlen(write_buf), "fread size");
        TEST_ASSERT(strcmp(read_buf, write_buf) == 0, "fread content");
        fclose(fp);
    }
}

/* ========================================================================== */
/* fseek/ftell/rewind tests                                                   */
/* ========================================================================== */
static void test_fseek_ftell(void) {
    FILE *fp;
    long pos;
    char c;
    
    printf("\n=== fseek/ftell/rewind Tests ===\n");
    
    /* Write test data */
    fp = fopen(test_file, "wb");
    if (fp) {
        fwrite("0123456789", 1, 10, fp);
        fclose(fp);
    }
    
    fp = fopen(test_file, "rb");
    TEST_ASSERT(fp != NULL, "fopen for seek test");
    if (fp) {
        pos = ftell(fp);
        TEST_ASSERT(pos == 0, "ftell at start");
        
        fseek(fp, 5, SEEK_SET);
        pos = ftell(fp);
        TEST_ASSERT(pos == 5, "fseek SEEK_SET");
        
        c = fgetc(fp);
        TEST_ASSERT(c == '5', "fgetc after seek");
        
        fseek(fp, -2, SEEK_CUR);
        pos = ftell(fp);
        TEST_ASSERT(pos == 4, "fseek SEEK_CUR negative");
        
        fseek(fp, -1, SEEK_END);
        pos = ftell(fp);
        TEST_ASSERT(pos == 9, "fseek SEEK_END");
        
        rewind(fp);
        pos = ftell(fp);
        TEST_ASSERT(pos == 0, "rewind");

        fclose(fp);
    }
}

/* ========================================================================== */
/* fgets/fputs tests                                                          */
/* ========================================================================== */
static void test_fgets_fputs(void) {
    FILE *fp;
    char buf[64];

    printf("\n=== fgets/fputs Tests ===\n");

    /* Write lines */
    fp = fopen(test_file, "w");
    TEST_ASSERT(fp != NULL, "fopen for fputs");
    if (fp) {
        int ret = fputs("line one\n", fp);
        TEST_ASSERT(ret >= 0, "fputs line 1");
        ret = fputs("line two\n", fp);
        TEST_ASSERT(ret >= 0, "fputs line 2");
        fclose(fp);
    }

    /* Read lines */
    fp = fopen(test_file, "r");
    TEST_ASSERT(fp != NULL, "fopen for fgets");
    if (fp) {
        char *ret = fgets(buf, sizeof(buf), fp);
        TEST_ASSERT(ret != NULL && strcmp(buf, "line one\n") == 0, "fgets line 1");

        ret = fgets(buf, sizeof(buf), fp);
        TEST_ASSERT(ret != NULL && strcmp(buf, "line two\n") == 0, "fgets line 2");

        ret = fgets(buf, sizeof(buf), fp);
        TEST_ASSERT(ret == NULL, "fgets EOF");

        fclose(fp);
    }
}

/* ========================================================================== */
/* fprintf/fscanf tests                                                       */
/* ========================================================================== */
static void test_fprintf_fscanf(void) {
    FILE *fp;
    int i;
    float f;
    char str[64];

    printf("\n=== fprintf/fscanf Tests ===\n");

    /* Write formatted data */
    fp = fopen(test_file, "w");
    TEST_ASSERT(fp != NULL, "fopen for fprintf");
    if (fp) {
        int n = fprintf(fp, "%d %f %s\n", 42, 3.14f, "hello");
        TEST_ASSERT(n > 0, "fprintf");
        fclose(fp);
    }

    /* Read formatted data */
    fp = fopen(test_file, "r");
    TEST_ASSERT(fp != NULL, "fopen for fscanf");
    if (fp) {
        int n = fscanf(fp, "%d %f %s", &i, &f, str);
        TEST_ASSERT(n == 3, "fscanf count");
        TEST_ASSERT(i == 42, "fscanf int");
        TEST_ASSERT(f > 3.13 && f < 3.15, "fscanf float");
        TEST_ASSERT(strcmp(str, "hello") == 0, "fscanf string");
        fclose(fp);
    }
}

/* ========================================================================== */
/* feof/ferror/clearerr tests                                                 */
/* ========================================================================== */
static void test_feof_ferror(void) {
    FILE *fp;
    char buf[64];

    printf("\n=== feof/ferror/clearerr Tests ===\n");

    /* Write small file */
    fp = fopen(test_file, "w");
    if (fp) {
        fputs("test", fp);
        fclose(fp);
    }

    fp = fopen(test_file, "r");
    TEST_ASSERT(fp != NULL, "fopen for feof test");
    if (fp) {
        TEST_ASSERT(feof(fp) == 0, "feof before read");

        fread(buf, 1, 100, fp);  /* Read past end */
        TEST_ASSERT(feof(fp) != 0, "feof after read past end");

        clearerr(fp);
        TEST_ASSERT(feof(fp) == 0, "clearerr clears EOF");

        fclose(fp);
    }
}

/* ========================================================================== */
/* fflush tests                                                               */
/* ========================================================================== */
static void test_fflush(void) {
    FILE *fp;

    printf("\n=== fflush Tests ===\n");

    fp = fopen(test_file, "w");
    TEST_ASSERT(fp != NULL, "fopen for fflush");
    if (fp) {
        fputs("buffered data", fp);
        int ret = fflush(fp);
        TEST_ASSERT(ret == 0, "fflush");
        fclose(fp);
    }

    /* fflush(NULL) flushes all streams */
    TEST_ASSERT(fflush(NULL) == 0, "fflush(NULL)");
}

/* ========================================================================== */
/* remove/rename tests                                                        */
/* ========================================================================== */
static void test_remove_rename(void) {
    FILE *fp;
    const char *new_name = "/tmp/emu_test_stdio_renamed.txt";

    printf("\n=== remove/rename Tests ===\n");

    /* Create file */
    fp = fopen(test_file, "w");
    if (fp) {
        fputs("test", fp);
        fclose(fp);
    }

    /* Rename */
    int ret = rename(test_file, new_name);
    TEST_ASSERT(ret == 0, "rename");

    /* Verify renamed file exists */
    fp = fopen(new_name, "r");
    TEST_ASSERT(fp != NULL, "renamed file exists");
    if (fp) fclose(fp);

    /* Remove */
    ret = remove(new_name);
    TEST_ASSERT(ret == 0, "remove");

    /* Verify removed */
    fp = fopen(new_name, "r");
    TEST_ASSERT(fp == NULL, "removed file gone");
}

/* ========================================================================== */
/* fstat tests (from stubs)                                                   */
/* ========================================================================== */
static void test_fstat(void) {
    FILE *fp;
    struct stat st;
    int ret;
    const char *fstat_test_file = "/tmp/test_fstat.txt";

    printf("\n=== fstat Tests ===\n");

    /* Create a test file */
    fp = fopen(fstat_test_file, "w");
    TEST_ASSERT(fp != NULL, "fopen for fstat test");
    if (fp) {
        fprintf(fp, "Hello, World!");
        fclose(fp);
    }

    /* Open and fstat */
    int fd = open(fstat_test_file, O_RDONLY);
    TEST_ASSERT(fd >= 0, "open for fstat");
    if (fd >= 0) {
        ret = fstat(fd, &st);
        TEST_ASSERT(ret == 0, "fstat returns 0");
        TEST_ASSERT(st.st_size == 13, "fstat size is correct");
        TEST_ASSERT(S_ISREG(st.st_mode), "fstat mode is regular file");
        close(fd);
    }

    /* Cleanup */
    remove(fstat_test_file);
}

/* ========================================================================== */
/* Main entry point                                                           */
/* ========================================================================== */
int run_stdio_tests(void) {
    printf("\n");
    printf("========================================\n");
    printf("   STDIO FUNCTION TEST SUITE\n");
    printf("========================================\n");

    test_sscanf();
    test_fopen();
    test_fread_fwrite();
    test_fseek_ftell();
    test_fgets_fputs();
    test_fprintf_fscanf();
    test_feof_ferror();
    test_fflush();
    test_remove_rename();
    test_fstat();

    /* Cleanup */
    remove(test_file);

    printf("\n========================================\n");
    printf("   STDIO RESULTS: %d passed, %d failed\n", tests_passed, tests_failed);
    printf("========================================\n");

    return tests_failed;
}

