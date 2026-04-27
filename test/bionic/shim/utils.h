/*
 * Complete shim replacement for bionic tests/utils.h
 * Provides all functionality without Android-specific dependencies
 */

#pragma once

#include <dirent.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <gtest/gtest.h>
#include <inttypes.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>

// No prctl on some systems
#ifdef __linux__
#include <sys/prctl.h>
#include <sys/sysmacros.h>
#endif

#include <atomic>
#include <iomanip>
#include <string>
#include <regex>
#include <vector>
#include <memory>
#include <functional>

// Include our android-base shims
#include <android-base/file.h>
#include <android-base/macros.h>
#include <android-base/scopeguard.h>
#include <android-base/stringprintf.h>

// bionic/macros.h
#define untag_address(p) p

#if defined(__LP64__)
#define PATH_TO_SYSTEM_LIB "/system/lib64/"
#else
#define PATH_TO_SYSTEM_LIB "/system/lib/"
#endif

#define BIN_DIR "/bin/"

#define KNOWN_FAILURE_ON_BIONIC(x) x

// HWASAN skip macro - never skips (we're not running with HWASAN)
// The if(false) makes it a no-op while still accepting << operator syntax
#define SKIP_WITH_HWASAN if (false) GTEST_SKIP()

// Stub - always return false (not running with native bridge)
static inline bool running_with_native_bridge() {
    return false;
}

// Check if dynamic linking is available
static inline bool have_dl() {
    // In CrossShim these tests use have_dl() as a proxy for Unicode-capable
    // wide-character behavior. That support is provided directly by the HLE
    // rather than guest-side libdl/ICU discovery.
    return true;
}

#define SKIP_WITH_NATIVE_BRIDGE if (running_with_native_bridge()) GTEST_SKIP()

#if defined(__linux__)

struct map_record {
    uintptr_t addr_start;
    uintptr_t addr_end;
    int perms;
    size_t offset;
    dev_t device;
    ino_t inode;
    std::string pathname;
};

class Maps {
 public:
    static bool parse_maps(std::vector<map_record>* maps) {
        maps->clear();
        std::unique_ptr<FILE, decltype(&fclose)> fp(fopen("/proc/self/maps", "re"), fclose);
        if (!fp) return false;

        char line[BUFSIZ];
        while (fgets(line, sizeof(line), fp.get()) != nullptr) {
            map_record record;
            uint32_t dev_major, dev_minor;
            int path_offset;
            char prot[5];
            if (sscanf(line, "%" SCNxPTR "-%" SCNxPTR " %4s %" SCNxPTR " %x:%x %lu %n",
                    &record.addr_start, &record.addr_end, prot, &record.offset,
                    &dev_major, &dev_minor, &record.inode, &path_offset) == 7) {
                record.perms = 0;
                if (prot[0] == 'r') record.perms |= PROT_READ;
                if (prot[1] == 'w') record.perms |= PROT_WRITE;
                if (prot[2] == 'x') record.perms |= PROT_EXEC;
                record.device = makedev(dev_major, dev_minor);
                record.pathname = line + path_offset;
                if (!record.pathname.empty() && record.pathname.back() == '\n') {
                    record.pathname.pop_back();
                }
                maps->push_back(record);
            }
        }
        return true;
    }
};

extern "C" pid_t gettid();

#endif

static inline void WaitUntilThreadSleep(std::atomic<pid_t>& tid) {
    while (tid == 0) {
        usleep(1000);
    }
    std::string filename = android::base::StringPrintf("/proc/%d/stat", tid.load());
    std::regex regex {R"(\s+S\s+)"};

    while (true) {
        std::string content;
        ASSERT_TRUE(android::base::ReadFileToString(filename, &content));
        if (std::regex_search(content, regex)) {
            break;
        }
        usleep(1000);
    }
}

static inline void AssertChildExited(int pid, int expected_exit_status,
                                     const std::string* error_msg = nullptr) {
    int status;
    std::string error;
    if (error_msg == nullptr) {
        error_msg = &error;
    }
    ASSERT_EQ(pid, TEMP_FAILURE_RETRY(waitpid(pid, &status, 0))) << *error_msg;
    if (expected_exit_status >= 0) {
        ASSERT_TRUE(WIFEXITED(status)) << *error_msg;
        ASSERT_EQ(expected_exit_status, WEXITSTATUS(status)) << *error_msg;
    } else {
        ASSERT_TRUE(WIFSIGNALED(status)) << *error_msg;
        ASSERT_EQ(-expected_exit_status, WTERMSIG(status)) << *error_msg;
    }
}

static inline bool CloseOnExec(int fd) {
    int flags = fcntl(fd, F_GETFD);
    if (flags == -1) abort();
    return flags & FD_CLOEXEC;
}

// Stubs for executable path and args
inline const std::string& get_executable_path() {
    static std::string path;
    if (path.empty()) {
        char buf[PATH_MAX];
        ssize_t len = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
        if (len > 0) {
            buf[len] = '\0';
            path = buf;
        }
    }
    return path;
}

// These need to be defined in main or linked from gtest
inline int get_argc() { return 0; }
inline char** get_argv() { return nullptr; }
inline char** get_envp() { return environ; }

#ifndef __APPLE__
class ExecTestHelper {
 public:
    char** GetArgs() { return const_cast<char**>(args_.data()); }
    const char* GetArg0() { return args_[0]; }
    char** GetEnv() { return const_cast<char**>(env_.data()); }
    const std::string& GetOutput() { return output_; }

    void SetArgs(const std::vector<const char*>& args) { args_ = args; }
    void SetEnv(const std::vector<const char*>& env) { env_ = env; }

    void Run(const std::function<void()>& child_fn, int expected_exit_status,
             const char* expected_output_regex) {
        int fds[2];
        ASSERT_NE(pipe(fds), -1);

        pid_t pid = fork();
        ASSERT_NE(pid, -1);

        if (pid == 0) {
            close(fds[0]);
            dup2(fds[1], STDOUT_FILENO);
            dup2(fds[1], STDERR_FILENO);
            if (fds[1] != STDOUT_FILENO && fds[1] != STDERR_FILENO) close(fds[1]);
            child_fn();
            _exit(1);
        }

        close(fds[1]);
        output_.clear();
        char buf[BUFSIZ];
        ssize_t bytes_read;
        while ((bytes_read = TEMP_FAILURE_RETRY(read(fds[0], buf, sizeof(buf)))) > 0) {
            output_.append(buf, bytes_read);
        }
        close(fds[0]);

        std::string error_msg("Test output:\n" + output_);
        AssertChildExited(pid, expected_exit_status, &error_msg);
        if (expected_output_regex != nullptr) {
            if (!std::regex_search(output_, std::regex(expected_output_regex))) {
                FAIL() << "regex didn't match output";
            }
        }
    }

 private:
    std::vector<const char*> args_;
    std::vector<const char*> env_;
    std::string output_;
};

inline void RunGwpAsanTest(const char*) { GTEST_SKIP() << "GWP-ASan not supported"; }
inline void RunSubtestNoEnv(const char*) { GTEST_SKIP() << "Subtest not supported"; }
#endif

class FdLeakChecker {
 public:
    FdLeakChecker() : start_count_(CountOpenFds()) {}

    ~FdLeakChecker() {
        size_t end_count = CountOpenFds();
        EXPECT_EQ(start_count_, end_count);
    }

 private:
    static size_t CountOpenFds() {
        auto fd_dir = std::unique_ptr<DIR, decltype(&closedir)>{ opendir("/proc/self/fd"), closedir };
        size_t count = 0;
        dirent* de = nullptr;
        while ((de = readdir(fd_dir.get())) != nullptr) {
            if (de->d_type == DT_LNK) {
                ++count;
            }
        }
        return count;
    }

    size_t start_count_;
};

inline bool IsLowRamDevice() { return false; }

inline int64_t NanoTime() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<int64_t>(ts.tv_sec) * 1000000000LL + ts.tv_nsec;
}

class Errno {
 public:
    Errno(int e) : errno_(e) {}
    int errno_;
};

inline void PrintTo(const Errno& e, std::ostream* os) {
    *os << strerror(e.errno_) << " (" << e.errno_ << ")";
}

inline bool operator==(const Errno& lhs, const Errno& rhs) {
    return lhs.errno_ == rhs.errno_;
}

#define ASSERT_ERRNO(expected_errno) ASSERT_EQ(Errno(expected_errno), Errno(errno))
#define EXPECT_ERRNO(expected_errno) EXPECT_EQ(Errno(expected_errno), Errno(errno))

// Regex matching macros for tests
#define ASSERT_MATCH(str, regex_pattern) \
    ASSERT_TRUE(std::regex_search(str, std::regex(regex_pattern))) << "String '" << str << "' doesn't match pattern '" << regex_pattern << "'"
#define EXPECT_MATCH(str, regex_pattern) \
    EXPECT_TRUE(std::regex_search(str, std::regex(regex_pattern))) << "String '" << str << "' doesn't match pattern '" << regex_pattern << "'"
