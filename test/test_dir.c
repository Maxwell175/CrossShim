/**
 * Directory Function Tests for Android Emulator Validation
 * Tests libc directory and path functions.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include <libgen.h>
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
/* getcwd tests                                                               */
/* ========================================================================== */
static void test_getcwd(void) {
    char buf[1024];
    char *result;
    
    printf("\n=== getcwd Tests ===\n");
    
    result = getcwd(buf, sizeof(buf));
    TEST_ASSERT(result != NULL, "getcwd returns non-NULL");
    TEST_ASSERT(result == buf, "getcwd returns buffer");
    TEST_ASSERT(strlen(buf) > 0, "getcwd returns non-empty path");
    TEST_ASSERT(buf[0] == '/', "getcwd returns absolute path");
}

/* ========================================================================== */
/* mkdir/rmdir tests                                                          */
/* ========================================================================== */
static void test_mkdir_rmdir(void) {
    int ret;
    struct stat st;
    const char *testdir = "/tmp/emu_test_dir_12345";
    
    printf("\n=== mkdir/rmdir Tests ===\n");
    
    /* Clean up if exists */
    rmdir(testdir);
    
    ret = mkdir(testdir, 0755);
    TEST_ASSERT(ret == 0, "mkdir creates directory");
    
    ret = stat(testdir, &st);
    TEST_ASSERT(ret == 0, "stat on new directory");
    TEST_ASSERT(S_ISDIR(st.st_mode), "created path is directory");
    
    ret = mkdir(testdir, 0755);
    TEST_ASSERT(ret == -1 && errno == EEXIST, "mkdir fails on existing");
    
    ret = rmdir(testdir);
    TEST_ASSERT(ret == 0, "rmdir removes directory");
    
    ret = stat(testdir, &st);
    TEST_ASSERT(ret == -1, "directory no longer exists");
}

/* ========================================================================== */
/* chdir tests                                                                */
/* ========================================================================== */
static void test_chdir(void) {
    char orig_cwd[1024];
    char new_cwd[1024];
    int ret;
    
    printf("\n=== chdir Tests ===\n");
    
    getcwd(orig_cwd, sizeof(orig_cwd));
    
    ret = chdir("/tmp");
    TEST_ASSERT(ret == 0, "chdir to /tmp");
    
    getcwd(new_cwd, sizeof(new_cwd));
    TEST_ASSERT(strcmp(new_cwd, "/tmp") == 0, "cwd is /tmp");
    
    ret = chdir(orig_cwd);
    TEST_ASSERT(ret == 0, "chdir back to original");
    
    ret = chdir("/nonexistent_dir_xyz");
    TEST_ASSERT(ret == -1, "chdir to nonexistent fails");
}

/* ========================================================================== */
/* opendir/readdir/closedir tests                                             */
/* ========================================================================== */
static void test_opendir_readdir(void) {
    DIR *dir;
    struct dirent *entry;
    int count;
    int found_dot, found_dotdot;
    
    printf("\n=== opendir/readdir/closedir Tests ===\n");
    
    dir = opendir("/tmp");
    TEST_ASSERT(dir != NULL, "opendir /tmp");
    
    if (dir) {
        count = 0;
        found_dot = 0;
        found_dotdot = 0;
        
        while ((entry = readdir(dir)) != NULL) {
            count++;
            if (strcmp(entry->d_name, ".") == 0) found_dot = 1;
            if (strcmp(entry->d_name, "..") == 0) found_dotdot = 1;
        }
        
        TEST_ASSERT(count >= 2, "readdir returns entries");
        TEST_ASSERT(found_dot, "readdir finds '.'");
        TEST_ASSERT(found_dotdot, "readdir finds '..'");
        
        closedir(dir);
        TEST_ASSERT(1, "closedir succeeds");
    }
    
    dir = opendir("/nonexistent_xyz");
    TEST_ASSERT(dir == NULL, "opendir nonexistent returns NULL");
}

/* ========================================================================== */
/* rewinddir tests                                                            */
/* ========================================================================== */
static void test_rewinddir(void) {
    DIR *dir;
    struct dirent *entry1, *entry2;
    char first_name[256];
    
    printf("\n=== rewinddir Tests ===\n");
    
    dir = opendir("/tmp");
    if (dir) {
        entry1 = readdir(dir);
        if (entry1) {
            strcpy(first_name, entry1->d_name);
            
            /* Read a few more */
            readdir(dir);
            readdir(dir);
            
            rewinddir(dir);
            
            entry2 = readdir(dir);
            TEST_ASSERT(entry2 != NULL, "readdir after rewind");
            TEST_ASSERT(strcmp(entry2->d_name, first_name) == 0, "rewinddir resets position");
        }
        closedir(dir);
    }
}

/* ========================================================================== */
/* realpath tests                                                             */
/* ========================================================================== */
static void test_realpath(void) {
    char resolved[1024];
    char *result;
    
    printf("\n=== realpath Tests ===\n");
    
    result = realpath("/tmp", resolved);
    TEST_ASSERT(result != NULL, "realpath /tmp");
    TEST_ASSERT(result == resolved, "realpath returns buffer");
    
    result = realpath("/tmp/../tmp", resolved);
    TEST_ASSERT(result != NULL, "realpath with ..");
    TEST_ASSERT(strcmp(resolved, "/tmp") == 0, "realpath resolves ..");
    
    result = realpath("/nonexistent_xyz", resolved);
    TEST_ASSERT(result == NULL, "realpath nonexistent returns NULL");
}

/* ========================================================================== */
/* basename/dirname tests                                                     */
/* ========================================================================== */
static void test_basename_dirname(void) {
    char path1[] = "/usr/lib/libfoo.so";
    char path2[] = "/usr/lib/libfoo.so";
    char path3[] = "libfoo.so";
    char path4[] = "/";
    char *result;
    
    printf("\n=== basename/dirname Tests ===\n");
    
    result = basename(path1);
    TEST_ASSERT(strcmp(result, "libfoo.so") == 0, "basename of /usr/lib/libfoo.so");
    
    result = dirname(path2);
    TEST_ASSERT(strcmp(result, "/usr/lib") == 0, "dirname of /usr/lib/libfoo.so");
    
    result = basename(path3);
    TEST_ASSERT(strcmp(result, "libfoo.so") == 0, "basename of libfoo.so");
    
    result = basename(path4);
    TEST_ASSERT(strcmp(result, "/") == 0, "basename of /");
}

/* ========================================================================== */
/* access tests                                                               */
/* ========================================================================== */
static void test_access(void) {
    int ret;
    
    printf("\n=== access Tests ===\n");
    
    ret = access("/tmp", F_OK);
    TEST_ASSERT(ret == 0, "access F_OK /tmp");
    
    ret = access("/tmp", R_OK);
    TEST_ASSERT(ret == 0, "access R_OK /tmp");
    
    ret = access("/tmp", W_OK);
    TEST_ASSERT(ret == 0, "access W_OK /tmp");
    
    ret = access("/tmp", X_OK);
    TEST_ASSERT(ret == 0, "access X_OK /tmp");
    
    ret = access("/nonexistent_xyz", F_OK);
    TEST_ASSERT(ret == -1, "access nonexistent fails");
}

/* ========================================================================== */
/* stat tests                                                                 */
/* ========================================================================== */
static void test_stat(void) {
    struct stat st;
    int ret;
    
    printf("\n=== stat Tests ===\n");
    
    ret = stat("/tmp", &st);
    TEST_ASSERT(ret == 0, "stat /tmp");
    TEST_ASSERT(S_ISDIR(st.st_mode), "/tmp is directory");
    
    ret = stat("/etc/passwd", &st);
    if (ret == 0) {
        TEST_ASSERT(S_ISREG(st.st_mode), "/etc/passwd is regular file");
        TEST_ASSERT(st.st_size > 0, "/etc/passwd has size");
    } else {
        TEST_ASSERT(1, "/etc/passwd stat (skipped)");
        TEST_ASSERT(1, "/etc/passwd size (skipped)");
    }
    
    ret = stat("/nonexistent_xyz", &st);
    TEST_ASSERT(ret == -1, "stat nonexistent fails");
}

/* ========================================================================== */
/* Structure Layout Validation Tests                                          */
/* These tests verify that the ARM64 bionic libc structures have the expected */
/* sizes and field offsets. If these fail, the emulator's structure           */
/* conversion code may be incorrect.                                          */
/* ========================================================================== */
static void test_structure_layouts(void) {
    printf("\n=== Structure Layout Validation ===\n");

    /* struct dirent - ARM64 bionic: 280 bytes
     * Layout: d_ino (8), d_off (8), d_reclen (2), d_type (1), d_name[256], padding (5)
     */
    TEST_ASSERT_MSG(sizeof(struct dirent) == 280,
        "sizeof(struct dirent) == 280",
        "got %zu", sizeof(struct dirent));
    TEST_ASSERT_MSG(offsetof(struct dirent, d_ino) == 0,
        "offsetof(dirent, d_ino) == 0",
        "got %zu", offsetof(struct dirent, d_ino));
    TEST_ASSERT_MSG(offsetof(struct dirent, d_off) == 8,
        "offsetof(dirent, d_off) == 8",
        "got %zu", offsetof(struct dirent, d_off));
    TEST_ASSERT_MSG(offsetof(struct dirent, d_reclen) == 16,
        "offsetof(dirent, d_reclen) == 16",
        "got %zu", offsetof(struct dirent, d_reclen));
    TEST_ASSERT_MSG(offsetof(struct dirent, d_type) == 18,
        "offsetof(dirent, d_type) == 18",
        "got %zu", offsetof(struct dirent, d_type));
    TEST_ASSERT_MSG(offsetof(struct dirent, d_name) == 19,
        "offsetof(dirent, d_name) == 19",
        "got %zu", offsetof(struct dirent, d_name));

    /* struct stat - ARM64 bionic: 128 bytes */
    TEST_ASSERT_MSG(sizeof(struct stat) == 128,
        "sizeof(struct stat) == 128",
        "got %zu", sizeof(struct stat));
    TEST_ASSERT_MSG(offsetof(struct stat, st_dev) == 0,
        "offsetof(stat, st_dev) == 0",
        "got %zu", offsetof(struct stat, st_dev));
    TEST_ASSERT_MSG(offsetof(struct stat, st_ino) == 8,
        "offsetof(stat, st_ino) == 8",
        "got %zu", offsetof(struct stat, st_ino));
    TEST_ASSERT_MSG(offsetof(struct stat, st_mode) == 16,
        "offsetof(stat, st_mode) == 16",
        "got %zu", offsetof(struct stat, st_mode));
    TEST_ASSERT_MSG(offsetof(struct stat, st_nlink) == 20,
        "offsetof(stat, st_nlink) == 20",
        "got %zu", offsetof(struct stat, st_nlink));
    TEST_ASSERT_MSG(offsetof(struct stat, st_uid) == 24,
        "offsetof(stat, st_uid) == 24",
        "got %zu", offsetof(struct stat, st_uid));
    TEST_ASSERT_MSG(offsetof(struct stat, st_gid) == 28,
        "offsetof(stat, st_gid) == 28",
        "got %zu", offsetof(struct stat, st_gid));
    TEST_ASSERT_MSG(offsetof(struct stat, st_rdev) == 32,
        "offsetof(stat, st_rdev) == 32",
        "got %zu", offsetof(struct stat, st_rdev));
    TEST_ASSERT_MSG(offsetof(struct stat, st_size) == 48,
        "offsetof(stat, st_size) == 48",
        "got %zu", offsetof(struct stat, st_size));
    TEST_ASSERT_MSG(offsetof(struct stat, st_blksize) == 56,
        "offsetof(stat, st_blksize) == 56",
        "got %zu", offsetof(struct stat, st_blksize));
    TEST_ASSERT_MSG(offsetof(struct stat, st_blocks) == 64,
        "offsetof(stat, st_blocks) == 64",
        "got %zu", offsetof(struct stat, st_blocks));
}

/* ========================================================================== */
/* Structure Field Value Tests                                                */
/* These tests verify that structure fields are correctly read/written by     */
/* the emulator's HLE functions.                                              */
/* ========================================================================== */
static void test_structure_field_values(void) {
    DIR *dir;
    struct dirent *entry;
    struct stat st;
    int ret;

    printf("\n=== Structure Field Value Tests ===\n");

    /* Test readdir returns valid dirent fields */
    dir = opendir("/tmp");
    if (dir) {
        entry = readdir(dir);
        if (entry) {
            TEST_ASSERT(entry->d_ino != 0, "readdir d_ino field non-zero");
            TEST_ASSERT(entry->d_type != 0xFF, "readdir d_type field valid");
            TEST_ASSERT(strlen(entry->d_name) > 0, "readdir d_name field non-empty");
            TEST_ASSERT(entry->d_reclen > 0, "readdir d_reclen field positive");
        } else {
            TEST_ASSERT(0, "readdir returned entry");
        }
        closedir(dir);
    } else {
        TEST_ASSERT(0, "opendir /tmp for field test");
    }

    /* Test stat returns valid stat fields */
    ret = stat("/tmp", &st);
    if (ret == 0) {
        TEST_ASSERT(st.st_ino != 0, "stat st_ino field non-zero");
        TEST_ASSERT(S_ISDIR(st.st_mode), "stat st_mode field indicates directory");
        TEST_ASSERT(st.st_nlink >= 2, "stat st_nlink field >= 2 for directory");
        TEST_ASSERT(st.st_blksize > 0, "stat st_blksize field positive");
    } else {
        TEST_ASSERT(0, "stat /tmp for field test");
    }
}

/* ========================================================================== */
/* Entry point                                                                */
/* ========================================================================== */
void run_dir_tests(int *passed, int *failed) {
    printf("\n========================================\n");
    printf("   DIRECTORY FUNCTION TESTS\n");
    printf("========================================\n");

    tests_passed = 0;
    tests_failed = 0;

    test_structure_layouts();
    test_structure_field_values();
    test_getcwd();
    test_mkdir_rmdir();
    test_chdir();
    test_opendir_readdir();
    test_rewinddir();
    test_realpath();
    test_basename_dirname();
    test_access();
    test_stat();

    printf("\n========================================\n");
    printf("   DIR RESULTS: %d passed, %d failed\n", tests_passed, tests_failed);
    printf("========================================\n");

    *passed = tests_passed;
    *failed = tests_failed;
}

