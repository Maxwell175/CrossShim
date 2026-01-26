/**
 * Exec Tests for Android Emulator Validation
 * Tests execve syscall functionality including:
 * - Basic exec of ARM64 binary
 * - Argument passing
 * - Environment variable passing
 * - Exit code propagation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/wait.h>

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

/* Get the path to the exec helper binary from environment */
static const char* get_helper_path(void) {
    const char *path = getenv("EXEC_HELPER_PATH");
    if (path == NULL) {
        /* Try common locations */
        if (access("./test_exec_helper_arm64", X_OK) == 0) {
            return "./test_exec_helper_arm64";
        }
        if (access("/tmp/test_exec_helper_arm64", X_OK) == 0) {
            return "/tmp/test_exec_helper_arm64";
        }
        return NULL;
    }
    return path;
}

/* ========================================================================== */
/* Helper: fork and exec, capture output                                      */
/* ========================================================================== */
static int fork_exec_capture(char *const argv[], char *const envp[],
                             char *output, size_t output_size, int *exit_code) {
    int pipefd[2];
    pid_t pid;

    if (pipe(pipefd) < 0) {
        return -1;
    }

    pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }

    if (pid == 0) {
        /* Child: redirect stdout to pipe, exec */
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[1]);

        if (envp) {
            execve(argv[0], argv, envp);
        } else {
            execv(argv[0], argv);
        }
        _exit(127);  /* exec failed */
    }

    /* Parent: read output and wait */
    close(pipefd[1]);

    ssize_t n = read(pipefd[0], output, output_size - 1);
    if (n >= 0) output[n] = '\0';
    else output[0] = '\0';

    close(pipefd[0]);

    int status;
    waitpid(pid, &status, 0);

    if (WIFEXITED(status)) {
        *exit_code = WEXITSTATUS(status);
        return 0;
    }

    return -1;
}

/* ========================================================================== */
/* Test: Basic exec                                                           */
/* ========================================================================== */
static void test_exec_basic(const char *helper_path) {
    char output[1024];
    int exit_code;

    printf("\n=== Basic Exec Test ===\n");

    char *argv[] = { (char*)helper_path, NULL };
    int ret = fork_exec_capture(argv, NULL, output, sizeof(output), &exit_code);

    TEST_ASSERT(ret == 0, "fork_exec_capture succeeds");
    TEST_ASSERT(exit_code == 0, "helper exits with code 0");
    TEST_ASSERT(strstr(output, "EXEC_HELPER_OK") != NULL, "helper output correct");
}

/* ========================================================================== */
/* Test: Argument passing                                                     */
/* ========================================================================== */
static void test_exec_args(const char *helper_path) {
    char output[1024];
    int exit_code;

    printf("\n=== Exec Argument Passing Test ===\n");

    char *argv[] = { (char*)helper_path, "echo_args", "arg1", "arg2", "arg3", NULL };
    int ret = fork_exec_capture(argv, NULL, output, sizeof(output), &exit_code);

    TEST_ASSERT(ret == 0, "fork_exec_capture succeeds");
    TEST_ASSERT(exit_code == 0, "helper exits with code 0");
    TEST_ASSERT(strstr(output, "ARGC=5") != NULL, "argc correct");
    TEST_ASSERT(strstr(output, "ARGV[1]=echo_args") != NULL, "argv[1] correct");
    TEST_ASSERT(strstr(output, "ARGV[2]=arg1") != NULL, "argv[2] correct");
    TEST_ASSERT(strstr(output, "ARGV[3]=arg2") != NULL, "argv[3] correct");
    TEST_ASSERT(strstr(output, "ARGV[4]=arg3") != NULL, "argv[4] correct");
}

/* ========================================================================== */
/* Test: Environment variable passing                                         */
/* ========================================================================== */
static void test_exec_env(const char *helper_path) {
    char output[1024];
    int exit_code;

    printf("\n=== Exec Environment Passing Test ===\n");

    char *argv[] = { (char*)helper_path, "echo_env", NULL };
    char *envp[] = {
        "TEST_VAR1=hello",
        "TEST_VAR2=world",
        "PATH=/usr/bin",  /* Should not be printed (doesn't start with TEST_) */
        NULL
    };

    int ret = fork_exec_capture(argv, envp, output, sizeof(output), &exit_code);

    TEST_ASSERT(ret == 0, "fork_exec_capture succeeds");
    TEST_ASSERT(exit_code == 0, "helper exits with code 0");
    TEST_ASSERT(strstr(output, "ENV: TEST_VAR1=hello") != NULL, "TEST_VAR1 passed");
    TEST_ASSERT(strstr(output, "ENV: TEST_VAR2=world") != NULL, "TEST_VAR2 passed");
    TEST_ASSERT(strstr(output, "PATH=") == NULL, "PATH not printed (filtered)");
}

/* ========================================================================== */
/* Test: Exit code propagation                                                */
/* ========================================================================== */
static void test_exec_exit_code(const char *helper_path) {
    char output[1024];
    int exit_code;

    printf("\n=== Exec Exit Code Test ===\n");

    /* Test exit code 0 */
    char *argv0[] = { (char*)helper_path, "exit_code", "0", NULL };
    int ret = fork_exec_capture(argv0, NULL, output, sizeof(output), &exit_code);
    TEST_ASSERT(ret == 0 && exit_code == 0, "exit code 0");

    /* Test exit code 1 */
    char *argv1[] = { (char*)helper_path, "exit_code", "1", NULL };
    ret = fork_exec_capture(argv1, NULL, output, sizeof(output), &exit_code);
    TEST_ASSERT(ret == 0 && exit_code == 1, "exit code 1");

    /* Test exit code 42 */
    char *argv42[] = { (char*)helper_path, "exit_code", "42", NULL };
    ret = fork_exec_capture(argv42, NULL, output, sizeof(output), &exit_code);
    TEST_ASSERT(ret == 0 && exit_code == 42, "exit code 42");

    /* Test exit code 255 */
    char *argv255[] = { (char*)helper_path, "exit_code", "255", NULL };
    ret = fork_exec_capture(argv255, NULL, output, sizeof(output), &exit_code);
    TEST_ASSERT(ret == 0 && exit_code == 255, "exit code 255");
}

/* ========================================================================== */
/* Test: Exec non-existent file                                               */
/* ========================================================================== */
static void test_exec_nonexistent(void) {
    char output[1024];
    int exit_code;

    printf("\n=== Exec Non-existent File Test ===\n");

    char *argv[] = { "/nonexistent/binary/path", NULL };
    int ret = fork_exec_capture(argv, NULL, output, sizeof(output), &exit_code);

    /* Fork should succeed but exec should fail with code 127 */
    TEST_ASSERT(ret == 0, "fork_exec_capture returns");
    TEST_ASSERT(exit_code == 127, "exit code 127 for exec failure");
}

/* ========================================================================== */
/* Entry point                                                                */
/* ========================================================================== */
void run_exec_tests(int *passed, int *failed) {
    const char *helper_path;

    printf("\n========================================\n");
    printf("   EXEC FUNCTION TESTS\n");
    printf("========================================\n");

    tests_passed = 0;
    tests_failed = 0;

    helper_path = get_helper_path();
    if (helper_path == NULL) {
        printf("  [SKIP] EXEC_HELPER_PATH not set and helper not found\n");
        printf("         Set EXEC_HELPER_PATH to the ARM64 exec helper binary\n");
        *passed = 0;
        *failed = 0;
        return;
    }

    printf("  Using helper: %s\n", helper_path);

    test_exec_basic(helper_path);
    test_exec_args(helper_path);
    test_exec_env(helper_path);
    test_exec_exit_code(helper_path);
    test_exec_nonexistent();

    printf("\n========================================\n");
    printf("   EXEC RESULTS: %d passed, %d failed\n", tests_passed, tests_failed);
    printf("========================================\n");

    *passed = tests_passed;
    *failed = tests_failed;
}
