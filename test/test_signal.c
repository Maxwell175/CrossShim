/**
 * Signal Function Tests for Android Emulator Validation
 * Tests libc signal handling functions.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>

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

static volatile sig_atomic_t signal_received = 0;

static void test_handler(int sig) {
    (void)sig;
    signal_received = 1;
}

/* ========================================================================== */
/* sigemptyset/sigfillset tests                                               */
/* ========================================================================== */
static void test_sigset(void) {
    sigset_t set;
    int ret;
    
    printf("\n=== sigset Tests ===\n");
    
    ret = sigemptyset(&set);
    TEST_ASSERT(ret == 0, "sigemptyset");
    TEST_ASSERT(sigismember(&set, SIGINT) == 0, "SIGINT not in empty set");
    TEST_ASSERT(sigismember(&set, SIGTERM) == 0, "SIGTERM not in empty set");
    
    ret = sigfillset(&set);
    TEST_ASSERT(ret == 0, "sigfillset");
    TEST_ASSERT(sigismember(&set, SIGINT) == 1, "SIGINT in full set");
    TEST_ASSERT(sigismember(&set, SIGTERM) == 1, "SIGTERM in full set");
}

/* ========================================================================== */
/* sigaddset/sigdelset tests                                                  */
/* ========================================================================== */
static void test_sigaddset_sigdelset(void) {
    sigset_t set;
    int ret;
    
    printf("\n=== sigaddset/sigdelset Tests ===\n");
    
    sigemptyset(&set);
    
    ret = sigaddset(&set, SIGINT);
    TEST_ASSERT(ret == 0, "sigaddset SIGINT");
    TEST_ASSERT(sigismember(&set, SIGINT) == 1, "SIGINT added");
    TEST_ASSERT(sigismember(&set, SIGTERM) == 0, "SIGTERM not added");
    
    ret = sigaddset(&set, SIGTERM);
    TEST_ASSERT(ret == 0, "sigaddset SIGTERM");
    TEST_ASSERT(sigismember(&set, SIGTERM) == 1, "SIGTERM added");
    
    ret = sigdelset(&set, SIGINT);
    TEST_ASSERT(ret == 0, "sigdelset SIGINT");
    TEST_ASSERT(sigismember(&set, SIGINT) == 0, "SIGINT removed");
    TEST_ASSERT(sigismember(&set, SIGTERM) == 1, "SIGTERM still present");
}

/* ========================================================================== */
/* signal tests                                                               */
/* ========================================================================== */
static void test_signal(void) {
    void (*old_handler)(int);
    
    printf("\n=== signal Tests ===\n");
    
    old_handler = signal(SIGUSR1, test_handler);
    TEST_ASSERT(old_handler != SIG_ERR, "signal set handler");
    
    old_handler = signal(SIGUSR1, SIG_DFL);
    TEST_ASSERT(old_handler == test_handler || old_handler != SIG_ERR, "signal restore default");
    
    old_handler = signal(SIGUSR1, SIG_IGN);
    TEST_ASSERT(old_handler != SIG_ERR, "signal set ignore");
}

/* ========================================================================== */
/* sigaction tests                                                            */
/* ========================================================================== */
static void test_sigaction(void) {
    struct sigaction sa, old_sa;
    int ret;
    
    printf("\n=== sigaction Tests ===\n");
    
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = test_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    
    ret = sigaction(SIGUSR2, &sa, &old_sa);
    TEST_ASSERT(ret == 0, "sigaction set handler");
    
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_DFL;
    ret = sigaction(SIGUSR2, &sa, NULL);
    TEST_ASSERT(ret == 0, "sigaction restore default");
}

/* ========================================================================== */
/* sigprocmask tests                                                          */
/* ========================================================================== */
static void test_sigprocmask(void) {
    sigset_t set, old_set;
    int ret;
    
    printf("\n=== sigprocmask Tests ===\n");
    
    sigemptyset(&set);
    sigaddset(&set, SIGUSR1);
    
    ret = sigprocmask(SIG_BLOCK, &set, &old_set);
    TEST_ASSERT(ret == 0, "sigprocmask SIG_BLOCK");
    
    ret = sigprocmask(SIG_UNBLOCK, &set, NULL);
    TEST_ASSERT(ret == 0, "sigprocmask SIG_UNBLOCK");
    
    ret = sigprocmask(SIG_SETMASK, &old_set, NULL);
    TEST_ASSERT(ret == 0, "sigprocmask SIG_SETMASK");
}

/* ========================================================================== */
/* Entry point                                                                */
/* ========================================================================== */
void run_signal_tests(int *passed, int *failed) {
    printf("\n========================================\n");
    printf("   SIGNAL FUNCTION TESTS\n");
    printf("========================================\n");
    
    tests_passed = 0;
    tests_failed = 0;
    
    test_sigset();
    test_sigaddset_sigdelset();
    test_signal();
    test_sigaction();
    test_sigprocmask();
    
    printf("\n========================================\n");
    printf("   SIGNAL RESULTS: %d passed, %d failed\n", tests_passed, tests_failed);
    printf("========================================\n");
    
    *passed = tests_passed;
    *failed = tests_failed;
}

