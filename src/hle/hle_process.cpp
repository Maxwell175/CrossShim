/**
 * HLE Process Control Functions
 * fork, exec, waitpid, kill, pipe, dup2, signal, sigaction
 * socketpair, syscall
 */

#include "debug_log.h"
#include "hle_brk_state.h"
#include "hle_env_state.h"
#include "hle_manager.h"
#include "hle_path_translation.h"
#include "hle_signal_state.h"
#include "hle_virtual_threads.h"
#include "bionic_types.h"
#include "cross_shim.h"
#include "memory_manager.h"
#include "emu_compat.h"
#include <chrono>
#include <cstring>
#include <fstream>
#include <iostream>
#include <limits>
#include <pwd.h>
#include <vector>
#include <unistd.h>
#include <signal.h>
#include <cerrno>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/prctl.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <atomic>
#include <mutex>
#include <unordered_map>

namespace cross_shim {

using namespace cross_shim::bionic;

// get_reg and set_reg are provided by emu_compat.h

std::atomic<bool> g_hle_fork_child{false};
std::mutex g_virtual_clone_mutex;
std::unordered_map<uint64_t, int> g_virtual_clone_status;
std::mutex g_guest_alarm_mutex;
bool g_guest_alarm_armed = false;
std::chrono::steady_clock::time_point g_guest_alarm_deadline;

static constexpr uint64_t GUEST_GETLOGIN_BUF = 0xB0000400;

static unsigned int remaining_guest_alarm_seconds_locked(std::chrono::steady_clock::time_point now) {
    if (!g_guest_alarm_armed || now >= g_guest_alarm_deadline) {
        return 0;
    }

    auto remaining = g_guest_alarm_deadline - now;
    auto secs = std::chrono::duration_cast<std::chrono::seconds>(remaining);
    if (secs < remaining) {
        ++secs;
    }
    return static_cast<unsigned int>(secs.count());
}

static std::string read_string(Emulator& emu, uint64_t addr, size_t max_len = 4096) {
    std::string result;
    char c;
    for (size_t i = 0; i < max_len; i++) {
        if (!emu.mem_read(addr + i, &c, 1) || c == '\0') break;
        result += c;
    }
    return result;
}

static std::vector<std::string> read_guest_string_array(Emulator& emu, uint64_t array_ptr) {
    std::vector<std::string> values;
    if (array_ptr == 0) {
        return values;
    }

    while (true) {
        uint64_t value_ptr = 0;
        emu.mem_read(array_ptr, &value_ptr, sizeof(value_ptr));
        if (value_ptr == 0) {
            break;
        }
        values.push_back(read_string(emu, value_ptr));
        array_ptr += sizeof(uint64_t);
    }
    return values;
}

static std::vector<char*> make_exec_vector(std::vector<std::string>& storage) {
    std::vector<char*> result;
    result.reserve(storage.size() + 1);
    for (std::string& value : storage) {
        result.push_back(value.empty() ? const_cast<char*>("") : value.data());
    }
    result.push_back(nullptr);
    return result;
}

static std::string resolve_guest_login_name() {
    if (const char* name = ::getenv("LOGNAME"); name != nullptr && name[0] != '\0') {
        return name;
    }
    if (const char* name = ::getenv("USER"); name != nullptr && name[0] != '\0') {
        return name;
    }

    struct passwd pwd {};
    struct passwd* result = nullptr;
    std::array<char, 4096> buf {};
    if (::getpwuid_r(::getuid(), &pwd, buf.data(), buf.size(), &result) == 0 &&
        result != nullptr && result->pw_name != nullptr && result->pw_name[0] != '\0') {
        return result->pw_name;
    }

    return "user";
}

static uint64_t read_guest_call_argument(Emulator& emu, size_t arg_index) {
    static constexpr int kArgRegs[] = {
        UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
        UC_ARM64_REG_X4, UC_ARM64_REG_X5, UC_ARM64_REG_X6, UC_ARM64_REG_X7,
    };

    if (arg_index < std::size(kArgRegs)) {
        return get_reg(emu, kArgRegs[arg_index]);
    }

    uint64_t value = 0;
    uint64_t sp = get_reg(emu, UC_ARM64_REG_SP);
    emu.mem_read(sp + (arg_index - std::size(kArgRegs)) * sizeof(uint64_t), &value, sizeof(value));
    return value;
}

static std::vector<std::string> read_guest_variadic_argv(Emulator& emu, size_t first_arg_index,
                                                         size_t* next_arg_index_out) {
    std::vector<std::string> args;
    size_t arg_index = first_arg_index;
    for (size_t count = 0; count < 128; ++count, ++arg_index) {
        uint64_t ptr = read_guest_call_argument(emu, arg_index);
        if (ptr == 0) {
            if (next_arg_index_out != nullptr) {
                *next_arg_index_out = arg_index + 1;
            }
            return args;
        }
        args.push_back(read_string(emu, ptr));
    }

    if (next_arg_index_out != nullptr) {
        *next_arg_index_out = arg_index;
    }
    return args;
}

static bool parse_shebang_interpreter(const std::string& host_path, std::string& interpreter,
                                      std::vector<std::string>& interpreter_args) {
    std::ifstream file(host_path);
    if (!file.is_open()) {
        return false;
    }

    std::string line;
    if (!std::getline(file, line) || line.rfind("#!", 0) != 0) {
        return false;
    }

    size_t pos = 2;
    while (pos < line.size() && (line[pos] == ' ' || line[pos] == '\t')) {
        ++pos;
    }
    if (pos >= line.size()) {
        return false;
    }

    interpreter_args.clear();
    std::string token;
    while (pos < line.size()) {
        while (pos < line.size() && (line[pos] == ' ' || line[pos] == '\t')) {
            ++pos;
        }
        if (pos >= line.size()) {
            break;
        }
        size_t end = pos;
        while (end < line.size() && line[end] != ' ' && line[end] != '\t') {
            ++end;
        }
        token = line.substr(pos, end - pos);
        if (interpreter.empty()) {
            interpreter = translate_guest_host_path(token);
        } else {
            interpreter_args.push_back(token);
        }
        pos = end;
    }

    return !interpreter.empty();
}

static int try_execve_guest_path(const std::string& guest_path, const std::vector<std::string>& argv_strings,
                                 char* const envp[], bool allow_shell_fallback) {
    std::string host_path = translate_guest_host_path(guest_path);

    if (guest_path == "/system/bin/run-as" && host_path == guest_path) {
        static constexpr char kRunAsUsage[] = "run-as: usage: run-as\n";
        ::write(STDERR_FILENO, kRunAsUsage, sizeof(kRunAsUsage) - 1);
        ::_exit(1);
    }

    std::vector<std::string> exec_argv_storage = argv_strings;
    auto exec_argv = make_exec_vector(exec_argv_storage);
    ::execve(host_path.c_str(), exec_argv.data(), envp);
    int err = errno;

    std::string interpreter;
    std::vector<std::string> interpreter_args;
    if (err == ENOENT && parse_shebang_interpreter(host_path, interpreter, interpreter_args)) {
        std::vector<std::string> shebang_argv_storage;
        shebang_argv_storage.push_back(interpreter);
        shebang_argv_storage.insert(shebang_argv_storage.end(), interpreter_args.begin(),
                                    interpreter_args.end());
        shebang_argv_storage.push_back(host_path);
        for (size_t i = 1; i < argv_strings.size(); ++i) {
            shebang_argv_storage.push_back(argv_strings[i]);
        }
        auto shebang_argv = make_exec_vector(shebang_argv_storage);
        ::execve(interpreter.c_str(), shebang_argv.data(), envp);
        err = errno;
    }

    if (allow_shell_fallback && err == ENOEXEC) {
        std::vector<std::string> shell_argv_storage;
        std::string shell = translate_guest_host_path("/system/bin/sh");
        shell_argv_storage.push_back(shell);
        shell_argv_storage.push_back(host_path);
        for (size_t i = 1; i < argv_strings.size(); ++i) {
            shell_argv_storage.push_back(argv_strings[i]);
        }
        auto shell_argv = make_exec_vector(shell_argv_storage);
        ::execve(shell.c_str(), shell_argv.data(), envp);
        err = errno;
    }

    errno = err;
    return -1;
}

static int exec_search_path(const std::string& file, const std::vector<std::string>& argv_strings,
                            char* const envp[], bool allow_shell_fallback) {
    if (file.find('/') != std::string::npos) {
        return try_execve_guest_path(file, argv_strings, envp, allow_shell_fallback);
    }

    const char* path_env = ::getenv("PATH");
    std::string search_path = (path_env != nullptr && path_env[0] != '\0') ? path_env : "/bin:/usr/bin";
    bool saw_eacces = false;
    bool saw_etxtbsy = false;

    size_t start = 0;
    while (start <= search_path.size()) {
        size_t end = search_path.find(':', start);
        std::string dir = (end == std::string::npos) ? search_path.substr(start)
                                                     : search_path.substr(start, end - start);
        std::string candidate = dir.empty() ? file : (dir + "/" + file);
        if (try_execve_guest_path(candidate, argv_strings, envp, allow_shell_fallback) == -1) {
            if (errno == ETXTBSY) {
                saw_etxtbsy = true;
            } else if (errno == EACCES) {
                saw_eacces = true;
            } else if (errno != ENOENT && errno != ENOTDIR) {
                return -1;
            }
        }

        if (end == std::string::npos) {
            break;
        }
        start = end + 1;
    }

    if (saw_etxtbsy) {
        errno = ETXTBSY;
    } else if (saw_eacces) {
        errno = EACCES;
    } else {
        errno = ENOENT;
    }
    return -1;
}

void register_hle_process(HleManager& hle) {
    // ========================================================================
    // Process creation
    // ========================================================================

    hle.register_function("fork", [](Emulator& emu) {
        errno = 0;
        pid_t pid = ::fork();
        if (pid < 0) {
            int err = errno;
            EMU_LOG << "[HLE] fork() failed errno=" << err << std::endl;
            hle_set_errno(emu, err);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        if (pid == 0) {
            g_hle_fork_child.store(true, std::memory_order_relaxed);
        }

        EMU_LOG << "[HLE] fork() -> " << pid << std::endl;
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(pid));
    });

    hle.register_function("vfork", [](Emulator& emu) {
        EMU_LOG << "[HLE] vfork() - not supported, returning -1" << std::endl;
        hle_set_errno(emu, ENOSYS);
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
    });

    hle.register_function("execl", [](Emulator& emu) {
        uint64_t path_ptr = get_reg(emu, UC_ARM64_REG_X0);
        std::string path = read_string(emu, path_ptr);
        size_t next_arg_index = 0;
        std::vector<std::string> argv_strings = read_guest_variadic_argv(emu, 1, &next_arg_index);
        (void)next_arg_index;

        int result = try_execve_guest_path(path, argv_strings, environ, false);
        hle_set_errno(emu, errno);
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
        (void)result;
    });

    hle.register_function("execle", [](Emulator& emu) {
        uint64_t path_ptr = get_reg(emu, UC_ARM64_REG_X0);
        std::string path = read_string(emu, path_ptr);
        size_t next_arg_index = 0;
        std::vector<std::string> argv_strings = read_guest_variadic_argv(emu, 1, &next_arg_index);
        uint64_t envp_ptr = read_guest_call_argument(emu, next_arg_index);
        std::vector<std::string> env_strings = read_guest_string_array(emu, envp_ptr);
        auto envp = make_exec_vector(env_strings);

        try_execve_guest_path(path, argv_strings, envp.data(), false);
        hle_set_errno(emu, errno);
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
    });

    hle.register_function("execlp", [](Emulator& emu) {
        uint64_t file_ptr = get_reg(emu, UC_ARM64_REG_X0);
        std::string file = read_string(emu, file_ptr);
        size_t next_arg_index = 0;
        std::vector<std::string> argv_strings = read_guest_variadic_argv(emu, 1, &next_arg_index);
        (void)next_arg_index;

        exec_search_path(file, argv_strings, environ, true);
        hle_set_errno(emu, errno);
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
    });

    hle.register_function("execv", [](Emulator& emu) {
        uint64_t path_ptr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t argv_ptr = get_reg(emu, UC_ARM64_REG_X1);
        std::string path = read_string(emu, path_ptr);
        std::vector<std::string> argv_strings = read_guest_string_array(emu, argv_ptr);

        try_execve_guest_path(path, argv_strings, environ, false);
        hle_set_errno(emu, errno);
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
    });

    hle.register_function("execve", [](Emulator& emu) {
        uint64_t pathname_ptr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t argv_ptr = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t envp_ptr = get_reg(emu, UC_ARM64_REG_X2);

        std::string pathname = read_string(emu, pathname_ptr);
        std::vector<std::string> argv_strings = read_guest_string_array(emu, argv_ptr);
        std::vector<std::string> env_strings = read_guest_string_array(emu, envp_ptr);
        auto envp = make_exec_vector(env_strings);

        EMU_LOG << "[HLE] execve(\"" << pathname << "\", argc=" << argv_strings.size() << ")" << std::endl;
        try_execve_guest_path(pathname, argv_strings, envp.data(), false);
        hle_set_errno(emu, errno);
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
    });

    hle.register_function("execvp", [](Emulator& emu) {
        uint64_t file_ptr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t argv_ptr = get_reg(emu, UC_ARM64_REG_X1);
        std::string file = read_string(emu, file_ptr);
        std::vector<std::string> argv_strings = read_guest_string_array(emu, argv_ptr);

        exec_search_path(file, argv_strings, environ, true);
        hle_set_errno(emu, errno);
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
    });

    hle.register_function("execvpe", [](Emulator& emu) {
        uint64_t file_ptr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t argv_ptr = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t envp_ptr = get_reg(emu, UC_ARM64_REG_X2);
        std::string file = read_string(emu, file_ptr);
        std::vector<std::string> argv_strings = read_guest_string_array(emu, argv_ptr);
        std::vector<std::string> env_strings = read_guest_string_array(emu, envp_ptr);
        auto envp = make_exec_vector(env_strings);

        exec_search_path(file, argv_strings, envp.data(), true);
        hle_set_errno(emu, errno);
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
    });

    hle.register_function("fexecve", [](Emulator& emu) {
        int fd = static_cast<int>(get_reg(emu, UC_ARM64_REG_X0));
        uint64_t argv_ptr = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t envp_ptr = get_reg(emu, UC_ARM64_REG_X2);
        std::vector<std::string> argv_strings = read_guest_string_array(emu, argv_ptr);
        std::vector<std::string> env_strings = read_guest_string_array(emu, envp_ptr);
        auto envp = make_exec_vector(env_strings);

        if (fd < 0 || ::fcntl(fd, F_GETFD) == -1) {
            hle_set_errno(emu, EBADF);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        std::string proc_path = "/proc/self/fd/" + std::to_string(fd);
        try_execve_guest_path(proc_path, argv_strings, envp.data(), false);
        hle_set_errno(emu, errno);
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
    });

    // ========================================================================
    // Process waiting - actually wait for child processes
    // ========================================================================

    hle.register_function("waitpid", [](Emulator& emu) {
        pid_t pid = static_cast<pid_t>(get_reg(emu, UC_ARM64_REG_X0));
        uint64_t status_ptr = get_reg(emu, UC_ARM64_REG_X1);
        int options = static_cast<int>(get_reg(emu, UC_ARM64_REG_X2));

        if (pid > 0 && hle_virtual_thread_is_virtual(static_cast<uint64_t>(pid))) {
            std::lock_guard<std::mutex> lock(g_virtual_clone_mutex);
            auto it = g_virtual_clone_status.find(static_cast<uint64_t>(pid));
            if (it == g_virtual_clone_status.end()) {
                hle_set_errno(emu, ECHILD);
                set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
                return;
            }

            if (status_ptr) {
                emu.mem_write(status_ptr, &it->second, sizeof(it->second));
            }
            g_virtual_clone_status.erase(it);
            (void)options;
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(pid));
            return;
        }

        int status;
        pid_t result = ::waitpid(pid, &status, options);

        if (result < 0) {
            hle_set_errno(emu, errno);
        } else if (status_ptr) {
            // Write status to guest memory
            emu.mem_write(status_ptr, &status, sizeof(status));
        }

        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(result));
    });

    hle.register_function("wait", [](Emulator& emu) {
        uint64_t status_ptr = get_reg(emu, UC_ARM64_REG_X0);

        int status;
        pid_t result = ::wait(&status);

        if (result < 0) {
            hle_set_errno(emu, errno);
        } else if (status_ptr) {
            emu.mem_write(status_ptr, &status, sizeof(status));
        }

        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(result));
    });

    hle.register_function("wait3", [](Emulator& emu) {
        uint64_t status_ptr = get_reg(emu, UC_ARM64_REG_X0);
        int options = static_cast<int>(get_reg(emu, UC_ARM64_REG_X1));
        uint64_t rusage_ptr = get_reg(emu, UC_ARM64_REG_X2);

        int status;
        struct rusage rusage;
        pid_t result = ::wait3(&status, options, rusage_ptr ? &rusage : nullptr);

        if (result < 0) {
            hle_set_errno(emu, errno);
        } else {
            if (status_ptr) {
                emu.mem_write(status_ptr, &status, sizeof(status));
            }
            if (rusage_ptr) {
                emu.mem_write(rusage_ptr, &rusage, sizeof(rusage));
            }
        }

        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(result));
    });

    hle.register_function("wait4", [](Emulator& emu) {
        pid_t pid = static_cast<pid_t>(get_reg(emu, UC_ARM64_REG_X0));
        uint64_t status_ptr = get_reg(emu, UC_ARM64_REG_X1);
        int options = static_cast<int>(get_reg(emu, UC_ARM64_REG_X2));
        uint64_t rusage_ptr = get_reg(emu, UC_ARM64_REG_X3);

        int status;
        struct rusage rusage;
        pid_t result = ::wait4(pid, &status, options, rusage_ptr ? &rusage : nullptr);

        if (result < 0) {
            hle_set_errno(emu, errno);
        } else {
            if (status_ptr) {
                emu.mem_write(status_ptr, &status, sizeof(status));
            }
            if (rusage_ptr) {
                emu.mem_write(rusage_ptr, &rusage, sizeof(rusage));
            }
        }

        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(result));
    });

    // ========================================================================
    // Signals
    // ========================================================================

    hle.register_function("kill", [](Emulator& emu) {
        pid_t pid = static_cast<pid_t>(get_reg(emu, UC_ARM64_REG_X0));
        int sig = static_cast<int>(get_reg(emu, UC_ARM64_REG_X1));

        if (hle_virtual_thread_is_virtual(static_cast<uint64_t>(pid))) {
            if (sig == 0 && hle_virtual_thread_is_alive(static_cast<uint64_t>(pid))) {
                set_reg(emu, UC_ARM64_REG_X0, 0);
                return;
            }
            hle_set_errno(emu, ESRCH);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        int result = ::kill(pid, sig);
        if (result == -1) {
            hle_set_errno(emu, errno);
        }

        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(result));
    });

    hle.register_function("raise", [](Emulator& emu) {
        int sig = get_reg(emu, UC_ARM64_REG_X0);
        // Validate signal number
        if (sig < 1 || sig > 64) {
            hle_set_errno(emu, 22);  // EINVAL
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }
        // For valid signals, pretend success (we don't actually deliver signals)
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("signal", [](Emulator& emu) {
        // Return SIG_DFL (0)
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("sigaction", [](Emulator& emu) {
        // Pretend success
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("sigprocmask", [](Emulator& emu) {
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    // sigset_t on ARM64 Android is 8 bytes (64 bits for 64 signals)
    // It's defined as: typedef struct { unsigned long sig[1]; } sigset_t;
    // Each signal is represented by a bit: bit (signum-1)
    constexpr size_t SIGSET_SIZE = 8;  // sizeof(unsigned long) on ARM64
    constexpr int MAX_SIGNAL = 64;     // _KERNEL__NSIG

    hle.register_function("sigemptyset", [](Emulator& emu) {
        uint64_t set_addr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t zeros = 0;
        emu.mem_write(set_addr, &zeros, sizeof(zeros));
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("sigfillset", [](Emulator& emu) {
        uint64_t set_addr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t ones = ~0ULL;
        emu.mem_write(set_addr, &ones, sizeof(ones));
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("sigaddset", [](Emulator& emu) {
        uint64_t set_addr = get_reg(emu, UC_ARM64_REG_X0);
        int signum = get_reg(emu, UC_ARM64_REG_X1);
        if (signum < 1 || signum > MAX_SIGNAL) {
            set_reg(emu, UC_ARM64_REG_X0, -1);
            return;
        }
        uint64_t set_val;
        emu.mem_read(set_addr, &set_val, sizeof(set_val));
        set_val |= (1ULL << (signum - 1));
        emu.mem_write(set_addr, &set_val, sizeof(set_val));
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("sigdelset", [](Emulator& emu) {
        uint64_t set_addr = get_reg(emu, UC_ARM64_REG_X0);
        int signum = get_reg(emu, UC_ARM64_REG_X1);
        if (signum < 1 || signum > MAX_SIGNAL) {
            set_reg(emu, UC_ARM64_REG_X0, -1);
            return;
        }
        uint64_t set_val;
        emu.mem_read(set_addr, &set_val, sizeof(set_val));
        set_val &= ~(1ULL << (signum - 1));
        emu.mem_write(set_addr, &set_val, sizeof(set_val));
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("sigismember", [](Emulator& emu) {
        uint64_t set_addr = get_reg(emu, UC_ARM64_REG_X0);
        int signum = get_reg(emu, UC_ARM64_REG_X1);
        if (signum < 1 || signum > MAX_SIGNAL) {
            set_reg(emu, UC_ARM64_REG_X0, -1);
            return;
        }
        uint64_t set_val;
        emu.mem_read(set_addr, &set_val, sizeof(set_val));
        int result = (set_val >> (signum - 1)) & 1;
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // ========================================================================
    // Pipes and file descriptor operations
    // ========================================================================

    hle.register_function("pipe", [](Emulator& emu) {
        uint64_t pipefd_addr = get_reg(emu, UC_ARM64_REG_X0);
        int pipefd[2];
        int result = pipe(pipefd);
        if (result == 0 && pipefd_addr) {
            emu.mem_write(pipefd_addr, pipefd, sizeof(pipefd));
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("pipe2", [](Emulator& emu) {
        uint64_t pipefd_addr = get_reg(emu, UC_ARM64_REG_X0);
        int flags = get_reg(emu, UC_ARM64_REG_X1);
        int pipefd[2];
        int result = pipe2(pipefd, flags);
        if (result == 0 && pipefd_addr) {
            emu.mem_write(pipefd_addr, pipefd, sizeof(pipefd));
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("dup", [](Emulator& emu) {
        int oldfd = get_reg(emu, UC_ARM64_REG_X0);
        errno = 0;
        int result = dup(oldfd);
        if (result == -1) {
            hle_set_errno(emu, errno);
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("dup2", [](Emulator& emu) {
        int oldfd = get_reg(emu, UC_ARM64_REG_X0);
        int newfd = get_reg(emu, UC_ARM64_REG_X1);
        errno = 0;
        int result = dup2(oldfd, newfd);
        if (result == -1) {
            hle_set_errno(emu, errno);
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("dup3", [](Emulator& emu) {
        int oldfd = get_reg(emu, UC_ARM64_REG_X0);
        int newfd = get_reg(emu, UC_ARM64_REG_X1);
        int flags = get_reg(emu, UC_ARM64_REG_X2);
        errno = 0;
        int result = dup3(oldfd, newfd, flags);
        if (result == -1) {
            hle_set_errno(emu, errno);
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // ========================================================================
    // Socket pairs
    // ========================================================================

    hle.register_function("socketpair", [](Emulator& emu) {
        int domain = get_reg(emu, UC_ARM64_REG_X0);
        int type = get_reg(emu, UC_ARM64_REG_X1);
        int protocol = get_reg(emu, UC_ARM64_REG_X2);
        uint64_t sv_addr = get_reg(emu, UC_ARM64_REG_X3);

        int sv[2];
        int result = socketpair(domain, type, protocol, sv);
        if (result == 0 && sv_addr) {
            emu.mem_write(sv_addr, sv, sizeof(sv));
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("prctl", [](Emulator& emu) {
        int option = static_cast<int>(get_reg(emu, UC_ARM64_REG_X0));
        unsigned long arg2 = static_cast<unsigned long>(get_reg(emu, UC_ARM64_REG_X1));
        unsigned long arg3 = static_cast<unsigned long>(get_reg(emu, UC_ARM64_REG_X2));
        unsigned long arg4 = static_cast<unsigned long>(get_reg(emu, UC_ARM64_REG_X3));
        unsigned long arg5 = static_cast<unsigned long>(get_reg(emu, UC_ARM64_REG_X4));

        errno = 0;
        int result = -1;

        switch (option) {
#ifdef PR_SET_NAME
            case PR_SET_NAME:
                {
                    std::string name = read_string(emu, arg2, 16);
                    result = ::prctl(option, name.c_str(), arg3, arg4, arg5);
                }
                break;
#endif
#ifdef PR_GET_NAME
            case PR_GET_NAME:
                {
                    void* host_name_ptr = emu.memory().get_host_ptr(arg2);
                    result = ::prctl(option, host_name_ptr, arg3, arg4, arg5);
                }
                break;
#endif
#ifdef PR_SET_VMA
            case PR_SET_VMA:
                {
                    void* host_addr = emu.memory().get_host_ptr(arg3);
                    std::string name;
                    const char* host_name = nullptr;
#ifdef PR_SET_VMA_ANON_NAME
                    if (arg2 == PR_SET_VMA_ANON_NAME && arg5 != 0) {
                        name = read_string(emu, arg5);
                        host_name = name.c_str();
                    }
#endif
                    result = ::prctl(option, arg2, host_addr, arg4, host_name);
                }
                break;
#endif
            default:
                result = ::prctl(option, arg2, arg3, arg4, arg5);
                break;
        }

        if (result == -1) {
            hle_set_errno(emu, errno);
        }
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(result));
    });

    // ========================================================================
    // System call interface
    // ========================================================================

    hle.register_function("syscall", [](Emulator& emu) {
        // syscall(long number, ...) - x0 is the syscall number
        long syscall_num = get_reg(emu, UC_ARM64_REG_X0);
        // Arguments are in x1, x2, x3, x4, x5, x6

        EMU_LOG << "[HLE] syscall(" << syscall_num << ") called" << std::endl;

        // Handle some common syscalls
        switch (syscall_num) {
            case 96:  // SYS_gettimeofday
            case 169: // SYS_gettimeofday on some systems
                {
                    struct timeval tv;
                    gettimeofday(&tv, nullptr);
                    uint64_t tv_addr = get_reg(emu, UC_ARM64_REG_X1);
                    if (tv_addr) {
                        emu.mem_write(tv_addr, &tv, sizeof(tv));
                    }
                    set_reg(emu, UC_ARM64_REG_X0, 0);
                }
                return;

            case 113: // SYS_clock_gettime
                {
                    int clock_id = static_cast<int>(get_reg(emu, UC_ARM64_REG_X1));
                    uint64_t tp_addr = get_reg(emu, UC_ARM64_REG_X2);
                    struct timespec ts{};
                    int result = ::clock_gettime(clock_id, &ts);
                    if (result == 0 && tp_addr != 0) {
                        timespec_arm64 guest_ts{};
                        host_to_arm64_timespec(ts, guest_ts);
                        emu.mem_write(tp_addr, &guest_ts, sizeof(guest_ts));
                    } else if (result != 0) {
                        hle_set_errno(emu, errno);
                    }
                    set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(result));
                }
                return;

            case 64:  // SYS_write
                {
                    int fd = get_reg(emu, UC_ARM64_REG_X1);
                    uint64_t buf = get_reg(emu, UC_ARM64_REG_X2);
                    size_t count = get_reg(emu, UC_ARM64_REG_X3);
                    if (fd == 1 || fd == 2) {  // stdout/stderr
                        std::vector<char> data(count);
                        emu.mem_read(buf, data.data(), count);
                        ssize_t written = ::write(fd, data.data(), count);
                        set_reg(emu, UC_ARM64_REG_X0, written);
                    } else {
                        set_reg(emu, UC_ARM64_REG_X0, count);  // Pretend success
                    }
                }
                return;

            case 63:  // SYS_read
                {
                    int fd = get_reg(emu, UC_ARM64_REG_X1);
                    uint64_t buf = get_reg(emu, UC_ARM64_REG_X2);
                    size_t count = get_reg(emu, UC_ARM64_REG_X3);
                    std::vector<char> data(count);
                    ssize_t n = ::read(fd, data.data(), count);
                    if (n > 0) {
                        emu.mem_write(buf, data.data(), n);
                    }
                    set_reg(emu, UC_ARM64_REG_X0, n);
                }
                return;

            case 178: // SYS_gettid
                {
                    uint64_t virtual_tid = hle_virtual_thread_current_override();
                    if (virtual_tid != 0) {
                        set_reg(emu, UC_ARM64_REG_X0, virtual_tid);
                        return;
                    }
                    pid_t tid = hle_get_current_visible_tid(emu);
                    set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(tid));
                }
                return;

            case 214: // SYS_brk
                {
                    uint64_t addr = get_reg(emu, UC_ARM64_REG_X1);
                    guest_brk_initialize(emu.memory().heap().get_base());
                    GuestBrkState& state = guest_brk_state();
                    if (addr != 0 && addr <= static_cast<uint64_t>(std::numeric_limits<intptr_t>::max())) {
                        state.current_brk = addr;
                    }
                    set_reg(emu, UC_ARM64_REG_X0, state.current_brk);
                }
                return;

            case 172: // SYS_getpid
                set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(::getpid()));
                return;

            case 174: // SYS_getuid
                set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(::getuid()));
                return;

            case 175: // SYS_geteuid
                set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(::geteuid()));
                return;

            case 176: // SYS_getgid
                set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(::getgid()));
                return;

            case 177: // SYS_getegid
                set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(::getegid()));
                return;

            case 130: // SYS_tkill
                {
#ifdef SYS_tkill
                    errno = 0;
                    long result = ::syscall(
                        SYS_tkill,
                        static_cast<pid_t>(get_reg(emu, UC_ARM64_REG_X1)),
                        static_cast<int>(get_reg(emu, UC_ARM64_REG_X2)));
                    if (result < 0) {
                        hle_set_errno(emu, errno);
                    }
                    set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(result));
#else
                    hle_set_errno(emu, ENOSYS);
                    set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
#endif
                }
                return;

            case 131: // SYS_tgkill
                {
#ifdef SYS_tgkill
                    errno = 0;
                    long result = ::syscall(
                        SYS_tgkill,
                        static_cast<pid_t>(get_reg(emu, UC_ARM64_REG_X1)),
                        static_cast<pid_t>(get_reg(emu, UC_ARM64_REG_X2)),
                        static_cast<int>(get_reg(emu, UC_ARM64_REG_X3)));
                    if (result < 0) {
                        hle_set_errno(emu, errno);
                    }
                    set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(result));
#else
                    hle_set_errno(emu, ENOSYS);
                    set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
#endif
                }
                return;

            case 135: // SYS_rt_sigprocmask
                {
                    int result = hle_signal_rt_sigprocmask(
                        emu,
                        static_cast<int>(get_reg(emu, UC_ARM64_REG_X1)),
                        get_reg(emu, UC_ARM64_REG_X2),
                        get_reg(emu, UC_ARM64_REG_X3),
                        static_cast<size_t>(get_reg(emu, UC_ARM64_REG_X4)));
                    set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(result));
                }
                return;

            case 240: // SYS_rt_tgsigqueueinfo
                {
                    int result = hle_signal_rt_tgsigqueueinfo(
                        emu,
                        static_cast<int>(get_reg(emu, UC_ARM64_REG_X1)),
                        static_cast<int>(get_reg(emu, UC_ARM64_REG_X2)),
                        static_cast<int>(get_reg(emu, UC_ARM64_REG_X3)),
                        get_reg(emu, UC_ARM64_REG_X4));
                    set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(result));
                }
                return;

            case 93:  // SYS_exit
            case 94:  // SYS_exit_group
                {
                    int status = get_reg(emu, UC_ARM64_REG_X1);
                    EMU_LOG << "[HLE] syscall exit(" << status << ")" << std::endl;
                    emu.stop();
                    set_reg(emu, UC_ARM64_REG_X0, 0);
                }
                return;

            default:
                EMU_LOG << "[HLE] syscall(" << syscall_num << ") - not implemented" << std::endl;
                hle_set_errno(emu, ENOSYS);
                set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
                return;
        }
    });

    hle.register_function("__system_property_get", [](Emulator& emu) {
        uint64_t name_addr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t value_addr = get_reg(emu, UC_ARM64_REG_X1);
        std::string name = read_string(emu, name_addr);

        if (emu.is_debug()) {
            EMU_LOG << "[HLE] __system_property_get: name=" << name << std::endl;
        }

        // Provide values for common Android properties
        std::string value;
        if (name == "ro.arch") {
            value = "aarch64";
        } else if (name == "ro.product.cpu.abi") {
            value = "arm64-v8a";
        } else if (name == "ro.build.version.sdk") {
            value = "30";
        } else if (name == "net.dns1") {
            value = "8.8.8.8";
        } else if (name == "net.dns2") {
            value = "8.8.4.4";
        }

        if (!value.empty() && value_addr != 0) {
            emu.mem_write(value_addr, value.c_str(), value.length() + 1);
            set_reg(emu, UC_ARM64_REG_X0, value.length());
        } else {
            // Return 0 (property not found)
            set_reg(emu, UC_ARM64_REG_X0, 0);
        }
    });

    hle.register_function("__system_property_find", [](Emulator& emu) {
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("__system_property_read", [](Emulator& emu) {
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    // ========================================================================
    // Extended signal functions (64-bit versions)
    // ========================================================================

    // sigaction64 - same as sigaction but with 64-bit signal mask
    hle.register_function("sigaction64", [](Emulator& emu) {
        // Pretend success
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    // sigqueue - queue a signal with value
    hle.register_function("sigqueue", [](Emulator& emu) {
        pid_t pid = get_reg(emu, UC_ARM64_REG_X0);
        int sig = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t value = get_reg(emu, UC_ARM64_REG_X2);

        union sigval sv;
        sv.sival_ptr = reinterpret_cast<void*>(value);
        int result = ::sigqueue(pid, sig, sv);
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // pthread_sigqueue - queue a signal to a thread
    hle.register_function("pthread_sigqueue", [](Emulator& emu) {
        // Not directly supported - return error
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
    });

    // sigwait - wait for a signal
    hle.register_function("sigwait", [](Emulator& emu) {
        uint64_t set_ptr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t sig_ptr = get_reg(emu, UC_ARM64_REG_X1);

        if (!set_ptr || !sig_ptr) {
            set_reg(emu, UC_ARM64_REG_X0, EINVAL);
            return;
        }

        sigset_t set;
        uint64_t arm_set;
        emu.mem_read(set_ptr, &arm_set, 8);
        sigemptyset(&set);
        for (int i = 1; i <= 64; i++) {
            if (arm_set & (1ULL << (i - 1))) {
                sigaddset(&set, i);
            }
        }

        int sig;
        int result = ::sigwait(&set, &sig);
        if (result == 0 && sig_ptr) {
            int32_t sig32 = sig;
            emu.mem_write(sig_ptr, &sig32, 4);
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // sigwait64 - same as sigwait but with 64-bit signal set
    hle.register_function("sigwait64", [](Emulator& emu) {
        uint64_t set_ptr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t sig_ptr = get_reg(emu, UC_ARM64_REG_X1);

        if (!set_ptr || !sig_ptr) {
            set_reg(emu, UC_ARM64_REG_X0, EINVAL);
            return;
        }

        sigset_t set;
        uint64_t arm_set;
        emu.mem_read(set_ptr, &arm_set, 8);
        sigemptyset(&set);
        for (int i = 1; i <= 64; i++) {
            if (arm_set & (1ULL << (i - 1))) {
                sigaddset(&set, i);
            }
        }

        int sig;
        int result = ::sigwait(&set, &sig);
        if (result == 0 && sig_ptr) {
            int32_t sig32 = sig;
            emu.mem_write(sig_ptr, &sig32, 4);
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // sigtimedwait - wait for signal with timeout
    hle.register_function("sigtimedwait", [](Emulator& emu) {
        uint64_t set_ptr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t info_ptr = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t timeout_ptr = get_reg(emu, UC_ARM64_REG_X2);

        if (!set_ptr) {
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        sigset_t set;
        uint64_t arm_set;
        emu.mem_read(set_ptr, &arm_set, 8);
        sigemptyset(&set);
        for (int i = 1; i <= 64; i++) {
            if (arm_set & (1ULL << (i - 1))) {
                sigaddset(&set, i);
            }
        }

        struct timespec* timeout = nullptr;
        struct timespec ts;
        if (timeout_ptr) {
            int64_t sec, nsec;
            emu.mem_read(timeout_ptr, &sec, 8);
            emu.mem_read(timeout_ptr + 8, &nsec, 8);
            ts.tv_sec = sec;
            ts.tv_nsec = nsec;
            timeout = &ts;
        }

        siginfo_t info;
        int result = ::sigtimedwait(&set, info_ptr ? &info : nullptr, timeout);

        // Note: siginfo_t conversion would be complex; simplified here
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // sigtimedwait64 - same as sigtimedwait but with 64-bit time
    hle.register_function("sigtimedwait64", [](Emulator& emu) {
        uint64_t set_ptr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t info_ptr = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t timeout_ptr = get_reg(emu, UC_ARM64_REG_X2);

        if (!set_ptr) {
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        sigset_t set;
        uint64_t arm_set;
        emu.mem_read(set_ptr, &arm_set, 8);
        sigemptyset(&set);
        for (int i = 1; i <= 64; i++) {
            if (arm_set & (1ULL << (i - 1))) {
                sigaddset(&set, i);
            }
        }

        struct timespec* timeout = nullptr;
        struct timespec ts;
        if (timeout_ptr) {
            int64_t sec, nsec;
            emu.mem_read(timeout_ptr, &sec, 8);
            emu.mem_read(timeout_ptr + 8, &nsec, 8);
            ts.tv_sec = sec;
            ts.tv_nsec = nsec;
            timeout = &ts;
        }

        siginfo_t info;
        int result = ::sigtimedwait(&set, info_ptr ? &info : nullptr, timeout);

        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // sigpending - get pending signals
    hle.register_function("sigpending", [](Emulator& emu) {
        uint64_t set_ptr = get_reg(emu, UC_ARM64_REG_X0);
        if (!set_ptr) {
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        sigset_t set;
        int result = ::sigpending(&set);

        if (result == 0) {
            uint64_t arm_set = 0;
            for (int i = 1; i <= 64; i++) {
                if (sigismember(&set, i)) {
                    arm_set |= (1ULL << (i - 1));
                }
            }
            emu.mem_write(set_ptr, &arm_set, 8);
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // sigpending64 - same as sigpending but with 64-bit set
    hle.register_function("sigpending64", [](Emulator& emu) {
        uint64_t set_ptr = get_reg(emu, UC_ARM64_REG_X0);
        if (!set_ptr) {
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        sigset_t set;
        int result = ::sigpending(&set);

        if (result == 0) {
            uint64_t arm_set = 0;
            for (int i = 1; i <= 64; i++) {
                if (sigismember(&set, i)) {
                    arm_set |= (1ULL << (i - 1));
                }
            }
            emu.mem_write(set_ptr, &arm_set, 8);
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // sigprocmask64 - same as sigprocmask but with 64-bit mask
    hle.register_function("sigprocmask64", [](Emulator& emu) {
        int how = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t set_ptr = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t oldset_ptr = get_reg(emu, UC_ARM64_REG_X2);

        sigset_t set, oldset;
        if (set_ptr) {
            uint64_t arm_set;
            emu.mem_read(set_ptr, &arm_set, 8);
            sigemptyset(&set);
            for (int i = 1; i <= 64; i++) {
                if (arm_set & (1ULL << (i - 1))) {
                    sigaddset(&set, i);
                }
            }
        }

        int result = ::sigprocmask(how, set_ptr ? &set : nullptr, oldset_ptr ? &oldset : nullptr);

        if (result == 0 && oldset_ptr) {
            uint64_t arm_oldset = 0;
            for (int i = 1; i <= 64; i++) {
                if (sigismember(&oldset, i)) {
                    arm_oldset |= (1ULL << (i - 1));
                }
            }
            emu.mem_write(oldset_ptr, &arm_oldset, 8);
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // sigwaitinfo - wait for signal with info
    hle.register_function("sigwaitinfo", [](Emulator& emu) {
        uint64_t set_ptr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t info_ptr = get_reg(emu, UC_ARM64_REG_X1);

        if (!set_ptr) {
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        sigset_t set;
        uint64_t arm_set;
        emu.mem_read(set_ptr, &arm_set, 8);
        sigemptyset(&set);
        for (int i = 1; i <= 64; i++) {
            if (arm_set & (1ULL << (i - 1))) {
                sigaddset(&set, i);
            }
        }

        siginfo_t info;
        int result = ::sigwaitinfo(&set, info_ptr ? &info : nullptr);

        // Note: siginfo_t conversion is complex; simplified here
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // sigwaitinfo64 - same as sigwaitinfo
    hle.register_function("sigwaitinfo64", [](Emulator& emu) {
        uint64_t set_ptr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t info_ptr = get_reg(emu, UC_ARM64_REG_X1);

        if (!set_ptr) {
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        sigset_t set;
        uint64_t arm_set;
        emu.mem_read(set_ptr, &arm_set, 8);
        sigemptyset(&set);
        for (int i = 1; i <= 64; i++) {
            if (arm_set & (1ULL << (i - 1))) {
                sigaddset(&set, i);
            }
        }

        siginfo_t info;
        int result = ::sigwaitinfo(&set, info_ptr ? &info : nullptr);
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // sigignore - set signal handler to SIG_IGN
    hle.register_function("sigignore", [](Emulator& emu) {
        int sig = get_reg(emu, UC_ARM64_REG_X0);
        struct sigaction sa = {};
        sa.sa_handler = SIG_IGN;
        int result = ::sigaction(sig, &sa, nullptr);
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // sighold - add signal to process signal mask
    hle.register_function("sighold", [](Emulator& emu) {
        int sig = get_reg(emu, UC_ARM64_REG_X0);
        sigset_t set;
        sigemptyset(&set);
        sigaddset(&set, sig);
        int result = ::sigprocmask(SIG_BLOCK, &set, nullptr);
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // sigpause - atomically release signal and suspend
    hle.register_function("sigpause", [](Emulator& emu) {
        int sig = get_reg(emu, UC_ARM64_REG_X0);
        sigset_t set;
        sigemptyset(&set);
        sigaddset(&set, sig);
        // sigpause() removes sig from mask and waits for any signal
        int result = ::sigsuspend(&set);
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // sigrelse - remove signal from process signal mask
    hle.register_function("sigrelse", [](Emulator& emu) {
        int sig = get_reg(emu, UC_ARM64_REG_X0);
        sigset_t set;
        sigemptyset(&set);
        sigaddset(&set, sig);
        int result = ::sigprocmask(SIG_UNBLOCK, &set, nullptr);
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // sigset - set signal handler
    hle.register_function("sigset", [](Emulator& emu) {
        int sig = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t handler = get_reg(emu, UC_ARM64_REG_X1);
        // Return SIG_ERR for now (not fully implemented)
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
    });

    // ========================================================================
    // Process timing functions
    // ========================================================================

    // alarm - set alarm clock
    hle.register_function("alarm", [](Emulator& emu) {
        unsigned int seconds = get_reg(emu, UC_ARM64_REG_X0);
        const auto now = std::chrono::steady_clock::now();

        unsigned int result = 0;
        {
            std::lock_guard<std::mutex> lock(g_guest_alarm_mutex);
            result = remaining_guest_alarm_seconds_locked(now);
            if (seconds == 0) {
                g_guest_alarm_armed = false;
            } else {
                g_guest_alarm_armed = true;
                g_guest_alarm_deadline = now + std::chrono::seconds(seconds);
            }
        }

        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(result));
    });

    // pause - wait for signal
    hle.register_function("pause", [](Emulator& emu) {
        while (true) {
            bool trigger_alarm = false;
            auto sleep_for = std::chrono::milliseconds(50);

            {
                std::lock_guard<std::mutex> lock(g_guest_alarm_mutex);
                const auto now = std::chrono::steady_clock::now();
                if (g_guest_alarm_armed && now >= g_guest_alarm_deadline) {
                    g_guest_alarm_armed = false;
                    trigger_alarm = true;
                } else if (g_guest_alarm_armed) {
                    auto remaining = g_guest_alarm_deadline - now;
                    sleep_for = std::chrono::duration_cast<std::chrono::milliseconds>(remaining);
                    if (sleep_for <= std::chrono::milliseconds::zero()) {
                        sleep_for = std::chrono::milliseconds(1);
                    } else if (sleep_for > std::chrono::milliseconds(50)) {
                        sleep_for = std::chrono::milliseconds(50);
                    }
                }
            }

            if (trigger_alarm) {
                hle_signal_queue(emu, SIGALRM, SI_TIMER, 0, false);
                hle_set_errno(emu, EINTR);
                set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
                return;
            }

            std::this_thread::sleep_for(sleep_for);
        }
    });

    // ========================================================================
    // Environment functions
    // ========================================================================

    // putenv - change or add environment variable
    hle.register_function("putenv", [](Emulator& emu) {
        uint64_t string_ptr = get_reg(emu, UC_ARM64_REG_X0);
        if (!string_ptr) {
            hle_set_errno(emu, EINVAL);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }
        std::string str = read_string(emu, string_ptr);
        size_t eq = str.find('=');
        if (eq != std::string::npos && eq > 0) {
            std::string name = str.substr(0, eq);
            g_putenv_guest_strings[name] = string_ptr;
            g_env.erase(name);
        }
        // Note: putenv takes ownership, so we need to allocate persistent storage
        static std::vector<std::string> env_strings;
        env_strings.push_back(str);
        int result = ::putenv(const_cast<char*>(env_strings.back().c_str()));
        if (result != 0) {
            hle_set_errno(emu, errno);
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // clearenv - clear environment
    hle.register_function("clearenv", [](Emulator& emu) {
        int result = ::clearenv();
        if (result == 0) {
            g_env.clear();
            g_putenv_guest_strings.clear();
        } else {
            hle_set_errno(emu, errno);
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // ========================================================================
    // Filesystem sync functions
    // ========================================================================

    // syncfs - sync filesystem containing fd
    hle.register_function("syncfs", [](Emulator& emu) {
        int fd = get_reg(emu, UC_ARM64_REG_X0);
        errno = 0;
        int result = ::syncfs(fd);
        if (result == -1) {
            hle_set_errno(emu, errno);
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("getlogin", [](Emulator& emu) {
        const std::string login = resolve_guest_login_name();
        emu.mem_write(GUEST_GETLOGIN_BUF, login.c_str(), login.size() + 1);
        set_reg(emu, UC_ARM64_REG_X0, GUEST_GETLOGIN_BUF);
    });

    hle.register_function("getlogin_r", [](Emulator& emu) {
        uint64_t buf_ptr = get_reg(emu, UC_ARM64_REG_X0);
        size_t buf_len = static_cast<size_t>(get_reg(emu, UC_ARM64_REG_X1));
        const std::string login = resolve_guest_login_name();

        if (buf_ptr == 0 || buf_len == 0 || login.size() + 1 > buf_len) {
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(ERANGE));
            return;
        }

        emu.mem_write(buf_ptr, login.c_str(), login.size() + 1);
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("swab", [](Emulator& emu) {
        uint64_t src_ptr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t dst_ptr = get_reg(emu, UC_ARM64_REG_X1);
        int64_t nbytes = static_cast<int64_t>(get_reg(emu, UC_ARM64_REG_X2));

        if (nbytes <= 1 || src_ptr == 0 || dst_ptr == 0) {
            return;
        }

        size_t count = static_cast<size_t>(nbytes) & ~static_cast<size_t>(1);
        if (count == 0) {
            return;
        }

        std::vector<uint8_t> temp(count);
        emu.mem_read(src_ptr, temp.data(), count);
        for (size_t i = 0; i < count; i += 2) {
            std::swap(temp[i], temp[i + 1]);
        }
        emu.mem_write(dst_ptr, temp.data(), count);
    });

    hle.register_function("close_range", [](Emulator& emu) {
        unsigned int first = static_cast<unsigned int>(get_reg(emu, UC_ARM64_REG_X0));
        unsigned int last = static_cast<unsigned int>(get_reg(emu, UC_ARM64_REG_X1));
        unsigned int flags = static_cast<unsigned int>(get_reg(emu, UC_ARM64_REG_X2));

        errno = 0;
#ifdef SYS_close_range
        int result = static_cast<int>(::syscall(SYS_close_range, first, last, flags));
#else
        int result = -1;
        errno = ENOSYS;
#endif
        if (result == -1) {
            hle_set_errno(emu, errno);
        }
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(result));
    });

    hle.register_function("copy_file_range", [](Emulator& emu) {
        int fd_in = static_cast<int>(get_reg(emu, UC_ARM64_REG_X0));
        uint64_t off_in_ptr = get_reg(emu, UC_ARM64_REG_X1);
        int fd_out = static_cast<int>(get_reg(emu, UC_ARM64_REG_X2));
        uint64_t off_out_ptr = get_reg(emu, UC_ARM64_REG_X3);
        size_t len = static_cast<size_t>(get_reg(emu, UC_ARM64_REG_X4));
        unsigned int flags = static_cast<unsigned int>(get_reg(emu, UC_ARM64_REG_X5));

        off64_t off_in = 0;
        off64_t off_out = 0;
        off64_t* off_in_host = nullptr;
        off64_t* off_out_host = nullptr;
        if (off_in_ptr != 0) {
            emu.mem_read(off_in_ptr, &off_in, sizeof(off_in));
            off_in_host = &off_in;
        }
        if (off_out_ptr != 0) {
            emu.mem_read(off_out_ptr, &off_out, sizeof(off_out));
            off_out_host = &off_out;
        }

        errno = 0;
#ifdef SYS_copy_file_range
        ssize_t result = static_cast<ssize_t>(
            ::syscall(SYS_copy_file_range, fd_in, off_in_host, fd_out, off_out_host, len, flags));
#else
        ssize_t result = -1;
        errno = ENOSYS;
#endif
        if (result == -1) {
            hle_set_errno(emu, errno);
        } else {
            if (off_in_ptr != 0) {
                emu.mem_write(off_in_ptr, &off_in, sizeof(off_in));
            }
            if (off_out_ptr != 0) {
                emu.mem_write(off_out_ptr, &off_out, sizeof(off_out));
            }
        }
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(result));
    });
}

} // namespace cross_shim
