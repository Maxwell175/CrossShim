/**
 * Pipe and File Descriptor Tests for Android Emulator Validation
 * Tests libc pipe, dup, and related functions.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
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

/* ========================================================================== */
/* pipe tests                                                                 */
/* ========================================================================== */
static void test_pipe(void) {
    int pipefd[2];
    int ret;
    char buf[64];
    const char *msg = "hello pipe";
    ssize_t n;
    
    printf("\n=== pipe Tests ===\n");
    
    ret = pipe(pipefd);
    TEST_ASSERT(ret == 0, "pipe creates pipe");
    TEST_ASSERT(pipefd[0] >= 0, "pipe read fd valid");
    TEST_ASSERT(pipefd[1] >= 0, "pipe write fd valid");
    TEST_ASSERT(pipefd[0] != pipefd[1], "pipe fds different");
    
    if (ret == 0) {
        n = write(pipefd[1], msg, strlen(msg));
        TEST_ASSERT(n == (ssize_t)strlen(msg), "write to pipe");
        
        n = read(pipefd[0], buf, sizeof(buf));
        TEST_ASSERT(n == (ssize_t)strlen(msg), "read from pipe");
        buf[n] = '\0';
        TEST_ASSERT(strcmp(buf, msg) == 0, "pipe data correct");
        
        close(pipefd[0]);
        close(pipefd[1]);
    }
}

/* ========================================================================== */
/* dup tests                                                                  */
/* ========================================================================== */
static void test_dup(void) {
    int fd, fd2;
    int ret;
    
    printf("\n=== dup Tests ===\n");
    
    fd = open("/tmp/emu_dup_test.txt", O_CREAT | O_RDWR, 0644);
    TEST_ASSERT(fd >= 0, "open for dup test");
    
    if (fd >= 0) {
        fd2 = dup(fd);
        TEST_ASSERT(fd2 >= 0, "dup returns valid fd");
        TEST_ASSERT(fd2 != fd, "dup returns different fd");
        
        if (fd2 >= 0) {
            /* Write through one, read through other */
            write(fd, "test", 4);
            lseek(fd2, 0, SEEK_SET);
            
            char buf[10];
            ssize_t n = read(fd2, buf, 10);
            TEST_ASSERT(n == 4, "read through dup'd fd");
            
            close(fd2);
        }
        
        close(fd);
        unlink("/tmp/emu_dup_test.txt");
    }
}

/* ========================================================================== */
/* dup2 tests                                                                 */
/* ========================================================================== */
static void test_dup2(void) {
    int fd, fd2, ret;
    
    printf("\n=== dup2 Tests ===\n");
    
    fd = open("/tmp/emu_dup2_test.txt", O_CREAT | O_RDWR, 0644);
    TEST_ASSERT(fd >= 0, "open for dup2 test");
    
    if (fd >= 0) {
        /* dup2 to specific fd */
        fd2 = 50;  /* Pick an unlikely fd */
        ret = dup2(fd, fd2);
        TEST_ASSERT(ret == fd2, "dup2 returns target fd");
        
        if (ret == fd2) {
            write(fd, "hello", 5);
            lseek(fd2, 0, SEEK_SET);
            
            char buf[10];
            ssize_t n = read(fd2, buf, 10);
            TEST_ASSERT(n == 5, "read through dup2'd fd");
            
            close(fd2);
        }
        
        /* dup2 to same fd */
        ret = dup2(fd, fd);
        TEST_ASSERT(ret == fd, "dup2 same fd");
        
        close(fd);
        unlink("/tmp/emu_dup2_test.txt");
    }
}

/* ========================================================================== */
/* fcntl tests                                                                */
/* ========================================================================== */
static void test_fcntl(void) {
    int fd, flags, ret;
    
    printf("\n=== fcntl Tests ===\n");
    
    fd = open("/tmp/emu_fcntl_test.txt", O_CREAT | O_RDWR, 0644);
    TEST_ASSERT(fd >= 0, "open for fcntl test");
    
    if (fd >= 0) {
        flags = fcntl(fd, F_GETFL);
        TEST_ASSERT(flags >= 0, "fcntl F_GETFL");
        
        ret = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
        TEST_ASSERT(ret == 0, "fcntl F_SETFL O_NONBLOCK");
        
        flags = fcntl(fd, F_GETFL);
        TEST_ASSERT((flags & O_NONBLOCK) != 0, "O_NONBLOCK is set");
        
        close(fd);
        unlink("/tmp/emu_fcntl_test.txt");
    }
}

/* ========================================================================== */
/* Entry point                                                                */
/* ========================================================================== */
void run_pipe_tests(int *passed, int *failed) {
    printf("\n========================================\n");
    printf("   PIPE/DUP FUNCTION TESTS\n");
    printf("========================================\n");
    
    tests_passed = 0;
    tests_failed = 0;
    
    test_pipe();
    test_dup();
    test_dup2();
    test_fcntl();
    
    printf("\n========================================\n");
    printf("   PIPE RESULTS: %d passed, %d failed\n", tests_passed, tests_failed);
    printf("========================================\n");
    
    *passed = tests_passed;
    *failed = tests_failed;
}

