/**
 * Memory Function Tests for Android Emulator Validation
 * Tests libc memory allocation functions.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>

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
/* malloc tests                                                               */
/* ========================================================================== */
static void test_malloc(void) {
    void *p1, *p2, *p3;
    
    printf("\n=== malloc Tests ===\n");
    
    p1 = malloc(100);
    TEST_ASSERT(p1 != NULL, "malloc 100 bytes");
    
    /* Write to allocated memory */
    memset(p1, 0xAA, 100);
    TEST_ASSERT(((unsigned char*)p1)[0] == 0xAA, "malloc write/read");
    
    p2 = malloc(1);
    TEST_ASSERT(p2 != NULL, "malloc 1 byte");
    
    p3 = malloc(1024 * 1024);  /* 1MB */
    TEST_ASSERT(p3 != NULL, "malloc 1MB");
    
    free(p1);
    free(p2);
    free(p3);
    
    /* malloc(0) - implementation defined, but should not crash */
    p1 = malloc(0);
    free(p1);  /* Should be safe even if NULL */
    TEST_ASSERT(1, "malloc(0) and free");
}

/* ========================================================================== */
/* calloc tests                                                               */
/* ========================================================================== */
static void test_calloc(void) {
    int *arr;
    size_t i;
    int all_zero;
    
    printf("\n=== calloc Tests ===\n");
    
    arr = calloc(100, sizeof(int));
    TEST_ASSERT(arr != NULL, "calloc 100 ints");
    
    /* Verify zero initialization */
    all_zero = 1;
    for (i = 0; i < 100; i++) {
        if (arr[i] != 0) {
            all_zero = 0;
            break;
        }
    }
    TEST_ASSERT(all_zero, "calloc zero initialization");
    
    free(arr);
    
    arr = calloc(1, 1);
    TEST_ASSERT(arr != NULL, "calloc 1 byte");
    free(arr);
    
    /* Large allocation */
    arr = calloc(1024, 1024);  /* 1MB */
    TEST_ASSERT(arr != NULL, "calloc 1MB");
    free(arr);
}

/* ========================================================================== */
/* realloc tests                                                              */
/* ========================================================================== */
static void test_realloc(void) {
    char *p;
    size_t i;
    int data_preserved;
    
    printf("\n=== realloc Tests ===\n");
    
    /* realloc(NULL, size) == malloc(size) */
    p = realloc(NULL, 100);
    TEST_ASSERT(p != NULL, "realloc(NULL, 100)");
    
    /* Write data */
    for (i = 0; i < 100; i++) {
        p[i] = (char)(i & 0xFF);
    }
    
    /* Grow allocation */
    p = realloc(p, 200);
    TEST_ASSERT(p != NULL, "realloc grow to 200");
    
    /* Verify data preserved */
    data_preserved = 1;
    for (i = 0; i < 100; i++) {
        if (p[i] != (char)(i & 0xFF)) {
            data_preserved = 0;
            break;
        }
    }
    TEST_ASSERT(data_preserved, "realloc data preserved after grow");
    
    /* Shrink allocation */
    p = realloc(p, 50);
    TEST_ASSERT(p != NULL, "realloc shrink to 50");
    
    /* Verify data preserved */
    data_preserved = 1;
    for (i = 0; i < 50; i++) {
        if (p[i] != (char)(i & 0xFF)) {
            data_preserved = 0;
            break;
        }
    }
    TEST_ASSERT(data_preserved, "realloc data preserved after shrink");
    
    /* realloc(p, 0) - implementation defined, may return NULL or valid ptr */
    p = realloc(p, 0);
    free(p);  /* Safe even if NULL */
    TEST_ASSERT(1, "realloc(p, 0) and free");
}

/* ========================================================================== */
/* aligned_alloc tests                                                        */
/* ========================================================================== */
static void test_aligned_alloc(void) {
    void *p;
    
    printf("\n=== aligned_alloc Tests ===\n");
    
    /* 16-byte alignment */
    p = aligned_alloc(16, 64);
    TEST_ASSERT(p != NULL, "aligned_alloc(16, 64)");
    TEST_ASSERT(((uintptr_t)p % 16) == 0, "16-byte alignment");
    free(p);
    
    /* 64-byte alignment */
    p = aligned_alloc(64, 128);
    TEST_ASSERT(p != NULL, "aligned_alloc(64, 128)");
    TEST_ASSERT(((uintptr_t)p % 64) == 0, "64-byte alignment");
    free(p);
    
    /* 4096-byte (page) alignment */
    p = aligned_alloc(4096, 8192);
    TEST_ASSERT(p != NULL, "aligned_alloc(4096, 8192)");
    TEST_ASSERT(((uintptr_t)p % 4096) == 0, "4096-byte alignment");
    free(p);
}

/* ========================================================================== */
/* posix_memalign tests                                                       */
/* ========================================================================== */
static void test_posix_memalign(void) {
    void *p = NULL;
    int ret;

    printf("\n=== posix_memalign Tests ===\n");

    ret = posix_memalign(&p, 32, 128);
    TEST_ASSERT(ret == 0 && p != NULL, "posix_memalign(32, 128)");
    TEST_ASSERT(((uintptr_t)p % 32) == 0, "32-byte alignment");
    free(p);

    ret = posix_memalign(&p, 256, 512);
    TEST_ASSERT(ret == 0 && p != NULL, "posix_memalign(256, 512)");
    TEST_ASSERT(((uintptr_t)p % 256) == 0, "256-byte alignment");
    free(p);
}

/* ========================================================================== */
/* Multiple allocations stress test                                           */
/* ========================================================================== */
static void test_alloc_stress(void) {
    void *ptrs[100];
    size_t i;
    int all_valid;

    printf("\n=== Allocation Stress Tests ===\n");

    /* Allocate many small blocks */
    all_valid = 1;
    for (i = 0; i < 100; i++) {
        ptrs[i] = malloc(64);
        if (ptrs[i] == NULL) {
            all_valid = 0;
            break;
        }
        memset(ptrs[i], (int)i, 64);
    }
    TEST_ASSERT(all_valid, "Allocate 100 x 64 bytes");

    /* Verify and free */
    all_valid = 1;
    for (i = 0; i < 100; i++) {
        if (ptrs[i]) {
            unsigned char *p = ptrs[i];
            if (p[0] != (unsigned char)i || p[63] != (unsigned char)i) {
                all_valid = 0;
            }
            free(ptrs[i]);
        }
    }
    TEST_ASSERT(all_valid, "Verify and free 100 blocks");

    /* Interleaved alloc/free */
    for (i = 0; i < 50; i++) {
        ptrs[i] = malloc(128);
    }
    for (i = 0; i < 50; i += 2) {
        free(ptrs[i]);
        ptrs[i] = NULL;
    }
    for (i = 0; i < 50; i += 2) {
        ptrs[i] = malloc(64);
    }
    for (i = 0; i < 50; i++) {
        free(ptrs[i]);
    }
    TEST_ASSERT(1, "Interleaved alloc/free pattern");
}

/* ========================================================================== */
/* Main entry point                                                           */
/* ========================================================================== */
int run_memory_tests(void) {
    printf("\n");
    printf("========================================\n");
    printf("   MEMORY FUNCTION TEST SUITE\n");
    printf("========================================\n");

    test_malloc();
    test_calloc();
    test_realloc();
    test_aligned_alloc();
    test_posix_memalign();
    test_alloc_stress();

    printf("\n========================================\n");
    printf("   MEMORY RESULTS: %d passed, %d failed\n", tests_passed, tests_failed);
    printf("========================================\n");

    return tests_failed;
}

