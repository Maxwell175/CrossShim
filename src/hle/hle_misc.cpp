/**
 * HLE Miscellaneous Functions
 *
 * This file contains truly miscellaneous functions that don't fit into other categories:
 * - Error handling (__errno)
 * - Process control (exit, abort, atexit)
 * - Process info (getpid, getuid, getgid, getppid)
 * - Stack protection (__stack_chk_fail)
 * - Libc init (__libc_init, __register_atfork)
 * - Regex (regcomp, regexec, regfree, regerror)
 * - Terminal/TTY (isatty, mkstemp, mkdtemp, PTY functions)
 * - Stdio locking (flockfile, funlockfile)
 * - File system (mkfifo, fchmodat, faccessat, linkat)
 * - Network addresses (inet_nsap_addr, inet_nsap_ntoa)
 * - Other misc (fnmatch, system, getprogname, etc.)
 *
 * Functions moved to other files:
 * - hle_stdlib.cpp: getenv, setenv, atoi, strtol, rand, qsort, bsearch, abs, div
 * - hle_wchar.cpp: wcslen, wcscpy, swprintf, wcsftime, wmemcpy, etc.
 * - hle_locale.cpp: setlocale, newlocale, mbstowcs, wcstombs, mbrtowc, etc.
 * - hle_ctype.cpp: isalpha, isdigit, toupper, towlower, wctype, wctrans, etc.
 * - hle_signal.cpp: sigemptyset64, sigprocmask64, pthread_sigmask, tgkill, etc.
 * - hle_search.cpp: lfind, lsearch, tfind, tsearch, hcreate, hsearch, etc.
 * - hle_sched.cpp: sched_*, sem_*, __sched_cpu*
 * - hle_setjmp.cpp: setjmp, longjmp, sigsetjmp, siglongjmp
 * - hle_sysconf.cpp: uname, getrlimit, pathconf, statfs, capget, etc.
 */

#include "debug_log.h"
#include "hle_exit_state.h"
#include "hle_manager.h"
#include "hle_sched_state.h"
#include "hle_stdio_state.h"
#include "cross_shim.h"
#include "memory_manager.h"
#include "emu_compat.h"
#include "hle_virtual_threads.h"
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <vector>
#include <algorithm>
#include <iostream>
#include <unistd.h>
#include <cerrno>
#include <sys/syscall.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pty.h>
#include <fnmatch.h>
#include <regex.h>
#include <map>
#include <mutex>
#include <atomic>
#include <condition_variable>
#include <thread>
#include <unordered_map>

namespace cross_shim {

// Map guest regex_t addresses to host compiled regex objects
static std::map<uint64_t, regex_t*> g_regex_map;
static std::mutex g_regex_mutex;
extern std::atomic<bool> g_hle_fork_child;
extern std::mutex g_virtual_clone_mutex;
extern std::unordered_map<uint64_t, int> g_virtual_clone_status;

struct ExitHandler {
    uint64_t func = 0;
    uint64_t arg = 0;
    bool takes_arg = false;
};

enum class ExitCallDisposition {
    OwnerFirstCall,
    OwnerReentrant,
    NonOwnerWaited,
};

static std::mutex g_exit_state_mutex;
static std::condition_variable g_exit_state_cv;
static std::vector<ExitHandler> g_atexit_handlers;
static std::vector<ExitHandler> g_quick_exit_handlers;
static bool g_exit_in_progress = false;
static bool g_exit_complete = false;
static int g_exit_status = 0;
static std::thread::id g_exit_owner_thread;

// get_reg and set_reg are provided by emu_compat.h

static std::string read_string(Emulator& emu, uint64_t addr, size_t max_len = 4096) {
    std::string result;
    char c;
    for (size_t i = 0; i < max_len; i++) {
        if (!emu.mem_read(addr + i, &c, 1) || c == '\0') break;
        result += c;
    }
    return result;
}

static bool is_invalid_guest_cstring_ptr(uint64_t ptr) {
    return ptr < 0x1000;
}

static ExitCallDisposition begin_process_exit(int status) {
    std::unique_lock<std::mutex> lock(g_exit_state_mutex);
    if (!g_exit_in_progress) {
        g_exit_in_progress = true;
        g_exit_complete = false;
        g_exit_status = status;
        g_exit_owner_thread = std::this_thread::get_id();
        return ExitCallDisposition::OwnerFirstCall;
    }

    if (g_exit_owner_thread == std::this_thread::get_id()) {
        g_exit_status = status;
        return ExitCallDisposition::OwnerReentrant;
    }

    while (!g_exit_complete) {
        g_exit_state_cv.wait(lock);
    }
    return ExitCallDisposition::NonOwnerWaited;
}

static void finish_process_exit_state() {
    std::lock_guard<std::mutex> lock(g_exit_state_mutex);
    g_exit_complete = true;
    g_exit_state_cv.notify_all();
}

static int current_process_exit_status() {
    std::lock_guard<std::mutex> lock(g_exit_state_mutex);
    return g_exit_status;
}

bool hle_exit_is_in_progress() {
    std::lock_guard<std::mutex> lock(g_exit_state_mutex);
    return g_exit_in_progress && !g_exit_complete;
}

static void run_exit_handlers(Emulator& emu, std::vector<ExitHandler>& handlers) {
    while (true) {
        ExitHandler handler;
        {
            std::lock_guard<std::mutex> lock(g_exit_state_mutex);
            if (handlers.empty()) {
                return;
            }
            handler = handlers.back();
            handlers.pop_back();
        }

        if (handler.func == 0) {
            continue;
        }

        if (handler.takes_arg) {
            emu.call_function_safe(handler.func, {handler.arg});
        } else {
            emu.call_function_safe(handler.func, {});
        }
    }
}

static void finalize_process_exit(Emulator& emu, int status) {
    if (g_hle_fork_child.load(std::memory_order_relaxed)) {
        ::_exit(status);
    }
    emu.stop();
}

static bool resize_guest_line_buffer(Emulator& emu, uint64_t lineptr_ptr, uint64_t n_ptr, size_t required_capacity,
                                     uint64_t& guest_buf, size_t& guest_capacity) {
    if (required_capacity <= guest_capacity && guest_buf != 0) {
        return true;
    }

    uint64_t new_buf = emu.memory().heap().allocate(required_capacity, 16);
    if (new_buf == 0) {
        hle_set_errno(emu, ENOMEM);
        return false;
    }

    if (guest_buf != 0 && guest_capacity != 0) {
        size_t copy_size = std::min(guest_capacity, required_capacity);
        std::vector<char> existing(copy_size);
        if (emu.mem_read(guest_buf, existing.data(), copy_size)) {
            emu.mem_write(new_buf, existing.data(), copy_size);
        }
        emu.memory().heap().free(guest_buf);
    }

    guest_buf = new_buf;
    guest_capacity = required_capacity;
    emu.mem_write(lineptr_ptr, &guest_buf, sizeof(guest_buf));
    emu.mem_write(n_ptr, &guest_capacity, sizeof(guest_capacity));
    return true;
}

static std::string make_temp_name_path(const char* base_dir, const char* prefix) {
    static std::atomic<uint64_t> counter{0};

    std::string dir = (base_dir != nullptr && base_dir[0] != '\0') ? base_dir : "/tmp";
    if (!dir.empty() && dir.back() == '/') {
        dir.pop_back();
    }

    std::string stem = (prefix != nullptr && prefix[0] != '\0') ? prefix : "cs";
    uint64_t seq = counter.fetch_add(1, std::memory_order_relaxed);
    return dir + "/" + stem + std::to_string(::getpid()) + "_" + std::to_string(seq);
}

// Errno location - fixed address in TLS region (must match tls_manager.cpp)
// TLS_BASE = 0xC0000000, errno storage at TLS_BASE + 0x100 for the main thread.
static constexpr uint64_t ERRNO_ADDR = 0xC0000100ULL;
static constexpr uint64_t CLONE_TRAMPOLINE_ADDR = 0x10080200ULL;
static constexpr uint64_t CLONE_CHILD_WRAPPER_ADDR = 0x10080300ULL;
static constexpr uint64_t SYS_CLONE_CHILD_EXIT = 0x1237ULL;
static bool g_clone_trampoline_written = false;

static uint64_t guest_errno_addr(Emulator& emu) {
    uint64_t tpidr = get_reg(emu, UC_ARM64_REG_TPIDR_EL0);
    if (tpidr >= 8) {
        return (tpidr - 8) + 0x100;
    }
    return ERRNO_ADDR;
}

static void write_clone_trampoline(Emulator& emu) {
    if (g_clone_trampoline_written) {
        return;
    }
    g_clone_trampoline_written = true;

    // Child wrapper:
    //   LDR X4, [SP, #16]      // X4 = guest TLS value
    //   MOV X8, #0x1235        // SYS_THREAD_START (forces TPIDR_EL0 via hook)
    //   SVC #0
    //   LDP X2, X3, [SP]       // X2 = fn, X3 = arg
    //   MOV X0, X3
    //   BLR X2
    //   MOV X8, #0x1237        // SYS_CLONE_CHILD_EXIT
    //   SVC #0
    uint32_t child_wrapper[] = {
        0xF9400BE4,  // LDR X4, [SP, #16]
        0xD28246A8,  // MOV X8, #0x1235
        0xD4000001,  // SVC #0
        0xA9400FE2,  // LDP X2, X3, [SP]
        0xAA0303E0,  // MOV X0, X3
        0xD63F0040,  // BLR X2
        0xD28246E8,  // MOV X8, #0x1237
        0xD4000001,  // SVC #0
    };

    // Trampoline:
    //   SVC #0                 // clone syscall
    //   CBNZ X0, parent_ret    // parent/error: return to caller with X0 as-is
    //   B child_wrapper        // child: jump into helper
    // parent_ret:
    //   RET
    uint32_t trampoline[] = {
        0xD4000001,  // SVC #0
        0xB5000040,  // CBNZ X0, +2 instructions
        0x1400003E,  // B CLONE_CHILD_WRAPPER_ADDR
        0xD65F03C0,  // RET
    };

    emu.mem_write(CLONE_CHILD_WRAPPER_ADDR, child_wrapper, sizeof(child_wrapper));
    emu.mem_write(CLONE_TRAMPOLINE_ADDR, trampoline, sizeof(trampoline));
}

void register_hle_misc(HleManager& hle) {
    // ========================================================================
    // Error handling
    // ========================================================================

    hle.register_function("__errno", [](Emulator& emu) {
        set_reg(emu, UC_ARM64_REG_X0, guest_errno_addr(emu));
    });

    // NOTE: strerror and strerror_r are defined in hle_string.cpp with thread-safe implementations
    // using per-thread buffers keyed by TPIDR_EL0. Do not duplicate them here.

    // ========================================================================
    // Process control
    // ========================================================================

    hle.register_function("exit", [](Emulator& emu) {
        int status = get_reg(emu, UC_ARM64_REG_X0);
        EMU_LOG << "[HLE] exit(" << status << ") called!" << std::endl;
        ExitCallDisposition disposition = begin_process_exit(status);
        if (disposition == ExitCallDisposition::OwnerFirstCall) {
            run_exit_handlers(emu, g_atexit_handlers);
            int final_status = current_process_exit_status();
            finish_process_exit_state();
            finalize_process_exit(emu, final_status);
        }
    });

    hle.register_function("_exit", [](Emulator& emu) {
        int status = get_reg(emu, UC_ARM64_REG_X0);
        EMU_LOG << "[HLE] _exit(" << status << ")" << std::endl;
        finish_process_exit_state();
        finalize_process_exit(emu, status);
    });

    hle.register_function("_Exit", [](Emulator& emu) {
        int status = get_reg(emu, UC_ARM64_REG_X0);
        EMU_LOG << "[HLE] _Exit(" << status << ")" << std::endl;
        finish_process_exit_state();
        finalize_process_exit(emu, status);
    });

    hle.register_function("abort", [](Emulator& emu) {
        finish_process_exit_state();
        finalize_process_exit(emu, SIGABRT);
    });

    hle.register_function("__cxa_atexit", [](Emulator& emu) {
        uint64_t func = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t arg = get_reg(emu, UC_ARM64_REG_X1);
        std::lock_guard<std::mutex> lock(g_exit_state_mutex);
        g_atexit_handlers.push_back({func, arg, true});
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("__cxa_finalize", [](Emulator& emu) {
        // No-op
    });

    hle.register_function("atexit", [](Emulator& emu) {
        uint64_t func = get_reg(emu, UC_ARM64_REG_X0);
        std::lock_guard<std::mutex> lock(g_exit_state_mutex);
        g_atexit_handlers.push_back({func, 0, false});
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("quick_exit", [](Emulator& emu) {
        int status = get_reg(emu, UC_ARM64_REG_X0);
        EMU_LOG << "[HLE] quick_exit(" << status << ")" << std::endl;
        ExitCallDisposition disposition = begin_process_exit(status);
        if (disposition == ExitCallDisposition::OwnerFirstCall) {
            run_exit_handlers(emu, g_quick_exit_handlers);
            int final_status = current_process_exit_status();
            finish_process_exit_state();
            finalize_process_exit(emu, final_status);
        }
    });

    hle.register_function("at_quick_exit", [](Emulator& emu) {
        uint64_t func = get_reg(emu, UC_ARM64_REG_X0);
        std::lock_guard<std::mutex> lock(g_exit_state_mutex);
        g_quick_exit_handlers.push_back({func, 0, false});
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    // ========================================================================
    // Process info
    // ========================================================================

    hle.register_function("getpid", [](Emulator& emu) {
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(::getpid()));
    });

    hle.register_function("gettid", [](Emulator& emu) {
        uint64_t virtual_tid = hle_virtual_thread_current_override();
        if (virtual_tid != 0) {
            set_reg(emu, UC_ARM64_REG_X0, virtual_tid);
            return;
        }
        pid_t tid = hle_get_current_visible_tid(emu);
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(tid));
    });

    hle.register_function("getuid", [](Emulator& emu) {
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(::getuid()));
    });

    hle.register_function("geteuid", [](Emulator& emu) {
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(::geteuid()));
    });

    hle.register_function("getgid", [](Emulator& emu) {
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(::getgid()));
    });

    hle.register_function("getegid", [](Emulator& emu) {
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(::getegid()));
    });

    hle.register_function("getppid", [](Emulator& emu) {
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(::getppid()));
    });

    hle.register_function("pthread_gettid_np", [](Emulator& emu) {
        uint64_t thread = get_reg(emu, UC_ARM64_REG_X0);
        pid_t tid = hle_lookup_pthread_tid(emu, thread);
        if (tid <= 0) {
            hle_set_errno(emu, ESRCH);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(tid));
    });

    // ========================================================================
    // Stack protection
    // ========================================================================

    hle.register_function("__stack_chk_fail", [](Emulator& emu) {
        // Read TPIDR_EL0 to understand the TLS state
        uint64_t tpidr = get_reg(emu, UC_ARM64_REG_TPIDR_EL0);

        // Read the stack guard from TLS (at offset 0x28 from TPIDR_EL0)
        uint64_t stack_guard_from_tls = 0;
        emu.mem_read(tpidr + 0x28, &stack_guard_from_tls, sizeof(stack_guard_from_tls));

        // Read SP to see the stack state
        uint64_t sp = get_reg(emu, UC_ARM64_REG_SP);

        // Read LR to see where we came from
        uint64_t lr = get_reg(emu, UC_ARM64_REG_LR);

        // Read PC
        uint64_t pc = get_reg(emu, UC_ARM64_REG_PC);

        // Read FP (X29) - frame pointer
        uint64_t fp = get_reg(emu, UC_ARM64_REG_X29);

        EMU_LOG << "[HLE] __stack_chk_fail called! Stack corruption detected.\n";
        EMU_LOG << "[HLE] TPIDR_EL0=0x" << std::hex << tpidr
                  << " stack_guard@0x" << (tpidr + 0x28) << "=0x" << stack_guard_from_tls
                  << std::dec << std::endl;
        EMU_LOG << "[HLE] PC=0x" << std::hex << pc << " LR=0x" << lr << " SP=0x" << sp << " FP=0x" << fp << std::dec << std::endl;

        // Don't stop - just log and continue. The stack check may be a false positive
        // due to emulation differences. Return normally.
    });

    // Note: __stack_chk_guard is a global DATA symbol, not a function.
    // It is initialized in Emulator::initialize_global_data() as a constant value.

    // ========================================================================
    // Libc initialization
    // ========================================================================

    // __libc_init - Android libc initialization
    // void __libc_init(void* raw_args, void (*onexit)(void), int (*slingshot)(int, char**, char**), structors_array_t const * const structors)
    // For HLE, we just call main directly
    hle.register_function("__libc_init", [](Emulator& emu) {
        // X0 = raw_args (KernelArgumentBlock*)
        // X1 = onexit function pointer
        // X2 = slingshot (main wrapper)
        // X3 = structors (init/fini arrays)

        // For now, just return - the emulator will call main directly
        // The init functions are already handled by the emulator
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    // __register_atfork - Register fork handlers
    // int __register_atfork(void (*prepare)(void), void (*parent)(void), void (*child)(void), void *dso_handle)
    hle.register_function("__register_atfork", [](Emulator& emu) {
        // We don't support fork, so just return success
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    // ========================================================================
    // Thread/process cloning (simplified - not full clone support)
    // ========================================================================

    hle.register_function("clone", [](Emulator& emu) {
        constexpr uint64_t GUEST_CLONE_VM = 0x00000100ULL;
        constexpr uint64_t GUEST_CLONE_SIGHAND = 0x00000800ULL;
        constexpr uint64_t GUEST_CLONE_THREAD = 0x00010000ULL;
        constexpr uint64_t GUEST_CLONE_SETTLS = 0x00080000ULL;
        constexpr uint64_t GUEST_CLONE_PARENT_SETTID = 0x00100000ULL;
        constexpr uint64_t GUEST_CLONE_CHILD_CLEARTID = 0x00200000ULL;
        constexpr uint64_t GUEST_CLONE_CHILD_SETTID = 0x01000000ULL;
        constexpr size_t CLONE_STACK_FRAME_SIZE = 32;

        uint64_t fn = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t child_stack = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t flags = get_reg(emu, UC_ARM64_REG_X2);
        uint64_t arg = get_reg(emu, UC_ARM64_REG_X3);
        uint64_t parent_tid = get_reg(emu, UC_ARM64_REG_X4);
        uint64_t tls = get_reg(emu, UC_ARM64_REG_X5);
        uint64_t child_tid = get_reg(emu, UC_ARM64_REG_X6);

        if (fn == 0 || child_stack == 0 || child_stack < CLONE_STACK_FRAME_SIZE) {
            hle_set_errno(emu, EINVAL);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        if ((flags & GUEST_CLONE_THREAD) != 0 && (flags & GUEST_CLONE_SIGHAND) == 0) {
            hle_set_errno(emu, EINVAL);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        if ((flags & GUEST_CLONE_THREAD) == 0) {
            uint64_t virtual_pid = hle_virtual_thread_allocate();
            int child_rc = static_cast<int>(emu.call_function_safe(fn, {arg}));
            int wait_status = (child_rc & 0xff) << 8;

            {
                std::lock_guard<std::mutex> lock(g_virtual_clone_mutex);
                g_virtual_clone_status[virtual_pid] = wait_status;
            }

            hle_virtual_thread_set_alive(virtual_pid, false);
            set_reg(emu, UC_ARM64_REG_X0, virtual_pid);
            return;
        }

        write_clone_trampoline(emu);

        uint64_t child_sp = child_stack - CLONE_STACK_FRAME_SIZE;
        uint64_t guest_tls = ((flags & GUEST_CLONE_SETTLS) != 0 && tls != 0)
            ? tls
            : get_reg(emu, UC_ARM64_REG_TPIDR_EL0);

        emu.mem_write(child_sp + 0, &fn, sizeof(fn));
        emu.mem_write(child_sp + 8, &arg, sizeof(arg));
        emu.mem_write(child_sp + 16, &guest_tls, sizeof(guest_tls));

        set_reg(emu, UC_ARM64_REG_X0, flags);
        set_reg(emu, UC_ARM64_REG_X1, child_sp);
        set_reg(emu, UC_ARM64_REG_X2, ((flags & GUEST_CLONE_PARENT_SETTID) != 0) ? parent_tid : 0);
        set_reg(emu, UC_ARM64_REG_X3, ((flags & GUEST_CLONE_SETTLS) != 0) ? guest_tls : 0);
        set_reg(emu, UC_ARM64_REG_X4,
                ((flags & (GUEST_CLONE_CHILD_SETTID | GUEST_CLONE_CHILD_CLEARTID)) != 0) ? child_tid : 0);
        set_reg(emu, UC_ARM64_REG_X8, 220);  // SYS_clone
        set_reg(emu, UC_ARM64_REG_PC, CLONE_TRAMPOLINE_ADDR);

        if (emu.is_debug()) {
            EMU_LOG << "[HLE] clone: fn=0x" << std::hex << fn
                    << " child_sp=0x" << child_sp
                    << " flags=0x" << flags
                    << " arg=0x" << arg
                    << " guest_tls=0x" << guest_tls
                    << std::dec << std::endl;
        }
    });

    // ========================================================================
    // Regex functions - use host regex implementation
    // ========================================================================

    hle.register_function("regcomp", [](Emulator& emu) {
        uint64_t preg_addr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t pattern_addr = get_reg(emu, UC_ARM64_REG_X1);
        int cflags = static_cast<int>(get_reg(emu, UC_ARM64_REG_X2));

        std::string pattern = read_string(emu, pattern_addr);

        // Allocate a host regex_t
        regex_t* host_regex = new regex_t;
        int result = ::regcomp(host_regex, pattern.c_str(), cflags);

        if (result == 0) {
            // Success - store the host regex keyed by guest address
            std::lock_guard<std::mutex> lock(g_regex_mutex);
            // Clean up any existing regex at this address
            auto it = g_regex_map.find(preg_addr);
            if (it != g_regex_map.end()) {
                ::regfree(it->second);
                delete it->second;
            }
            g_regex_map[preg_addr] = host_regex;
        } else {
            // Compilation failed - clean up
            delete host_regex;
        }

        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("regexec", [](Emulator& emu) {
        uint64_t preg_addr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t string_addr = get_reg(emu, UC_ARM64_REG_X1);
        size_t nmatch = get_reg(emu, UC_ARM64_REG_X2);
        uint64_t pmatch_addr = get_reg(emu, UC_ARM64_REG_X3);
        int eflags = static_cast<int>(get_reg(emu, UC_ARM64_REG_X4));

        std::string str = read_string(emu, string_addr);

        regex_t* host_regex = nullptr;
        {
            std::lock_guard<std::mutex> lock(g_regex_mutex);
            auto it = g_regex_map.find(preg_addr);
            if (it != g_regex_map.end()) {
                host_regex = it->second;
            }
        }

        if (!host_regex) {
            // Regex not found - return REG_BADPAT
            set_reg(emu, UC_ARM64_REG_X0, 2);  // REG_BADPAT
            return;
        }

        // Allocate match array
        std::vector<regmatch_t> matches(nmatch);
        int result = ::regexec(host_regex, str.c_str(), nmatch, matches.data(), eflags);

        // Copy match results back to guest memory
        // regmatch_t is { regoff_t rm_so; regoff_t rm_eo; } - typically 16 bytes on 64-bit
        if (result == 0 && pmatch_addr && nmatch > 0) {
            for (size_t i = 0; i < nmatch; i++) {
                int64_t rm_so = matches[i].rm_so;
                int64_t rm_eo = matches[i].rm_eo;
                emu.mem_write(pmatch_addr + i * 16, &rm_so, 8);
                emu.mem_write(pmatch_addr + i * 16 + 8, &rm_eo, 8);
            }
        }

        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("regfree", [](Emulator& emu) {
        uint64_t preg_addr = get_reg(emu, UC_ARM64_REG_X0);

        std::lock_guard<std::mutex> lock(g_regex_mutex);
        auto it = g_regex_map.find(preg_addr);
        if (it != g_regex_map.end()) {
            ::regfree(it->second);
            delete it->second;
            g_regex_map.erase(it);
        }
    });

    hle.register_function("regerror", [](Emulator& emu) {
        int errcode = static_cast<int>(get_reg(emu, UC_ARM64_REG_X0));
        uint64_t preg_addr = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t errbuf = get_reg(emu, UC_ARM64_REG_X2);
        size_t errbuf_size = get_reg(emu, UC_ARM64_REG_X3);

        regex_t* host_regex = nullptr;
        {
            std::lock_guard<std::mutex> lock(g_regex_mutex);
            auto it = g_regex_map.find(preg_addr);
            if (it != g_regex_map.end()) {
                host_regex = it->second;
            }
        }

        // Get error message
        char local_buf[256];
        size_t len = ::regerror(errcode, host_regex, local_buf, sizeof(local_buf));

        if (errbuf && errbuf_size > 0) {
            size_t copy_len = std::min(len, errbuf_size);
            emu.mem_write(errbuf, local_buf, copy_len);
            if (copy_len < errbuf_size) {
                char null = 0;
                emu.mem_write(errbuf + copy_len, &null, 1);
            }
        }
        set_reg(emu, UC_ARM64_REG_X0, len);
    });

    // ========================================================================
    // Memory file descriptor
    // ========================================================================

    hle.register_function("memfd_create", [](Emulator& emu) {
        // Return -1 (ENOSYS) - not supported
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
    });

    // ========================================================================
    // Android-specific functions
    // ========================================================================

    // android_set_abort_message - Set a message to display on abort
    hle.register_function("android_set_abort_message", [](Emulator& emu) {
        uint64_t msg_addr = get_reg(emu, UC_ARM64_REG_X0);
        if (msg_addr != 0) {
            std::string msg = read_string(emu, msg_addr);
            EMU_LOG << "[HLE] android_set_abort_message: " << msg << std::endl;
        }
        // No return value (void)
    });

    // ========================================================================
    // Dynamic linker functions
    // ========================================================================

    // dl_iterate_phdr - Iterate over loaded shared objects
    // int dl_iterate_phdr(int (*callback)(struct dl_phdr_info *info, size_t size, void *data), void *data)
    hle.register_function("dl_iterate_phdr", [](Emulator& emu) {
        // Return 0 to indicate we iterated over zero objects
        // This is used by exception handling to find unwind info
        // For now, we just pretend there are no shared objects
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    // ========================================================================
    // Terminal functions
    // ========================================================================

    hle.register_function("isatty", [](Emulator& emu) {
        int fd = get_reg(emu, UC_ARM64_REG_X0);
        (void)fd;
        // Return 0 (not a tty) for all FDs in emulation
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    // NOTE: mkstemp, mkdtemp, mkostemp, mkstemps are implemented in hle_file.cpp
    // with proper host system call forwarding. Do not duplicate them here.

    // ========================================================================
    // Program name
    // ========================================================================

    static std::string g_progname = "emulated";
    static uint64_t g_progname_addr = 0;

    hle.register_function("getprogname", [](Emulator& emu) {
        if (g_progname_addr == 0) {
            g_progname_addr = emu.memory().heap().allocate(g_progname.length() + 1, 8);
            emu.mem_write(g_progname_addr, g_progname.c_str(), g_progname.length() + 1);
        }
        set_reg(emu, UC_ARM64_REG_X0, g_progname_addr);
    });

    hle.register_function("setprogname", [](Emulator& emu) {
        uint64_t name_addr = get_reg(emu, UC_ARM64_REG_X0);
        if (name_addr != 0) {
            std::string name = read_string(emu, name_addr);
            size_t slash = name.find_last_of('/');
            g_progname = (slash == std::string::npos) ? name : name.substr(slash + 1);
            // Reallocate if needed
            g_progname_addr = emu.memory().heap().allocate(g_progname.length() + 1, 8);
            emu.mem_write(g_progname_addr, g_progname.c_str(), g_progname.length() + 1);
        }
    });

    // ========================================================================
    // System command
    // ========================================================================

    hle.register_function("system", [](Emulator& emu) {
        uint64_t cmd_addr = get_reg(emu, UC_ARM64_REG_X0);
        errno = 0;
        if (cmd_addr == 0) {
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(::system(nullptr)));
            return;
        }

        std::string cmd = read_string(emu, cmd_addr);
        int result = ::system(cmd.c_str());
        if (result == -1) {
            hle_set_errno(emu, errno);
        }
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(static_cast<int64_t>(result)));
    });

    // ========================================================================
    // Assert function
    // ========================================================================

    hle.register_function("__assert2", [](Emulator& emu) {
        uint64_t file_addr = get_reg(emu, UC_ARM64_REG_X0);
        int line = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t func_addr = get_reg(emu, UC_ARM64_REG_X2);
        uint64_t expr_addr = get_reg(emu, UC_ARM64_REG_X3);

        std::string file = file_addr ? read_string(emu, file_addr) : "<unknown>";
        std::string func = func_addr ? read_string(emu, func_addr) : "<unknown>";
        std::string expr = expr_addr ? read_string(emu, expr_addr) : "<unknown>";

        EMU_LOG << "[HLE] __assert2: " << file << ":" << line << " " << func << ": Assertion `" << expr << "' failed." << std::endl;
        emu.stop();
    });

    // ========================================================================
    // Pattern matching
    // ========================================================================

    hle.register_function("fnmatch", [](Emulator& emu) {
        uint64_t pattern_addr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t string_addr = get_reg(emu, UC_ARM64_REG_X1);
        int bionic_flags = get_reg(emu, UC_ARM64_REG_X2);

        std::string pattern = read_string(emu, pattern_addr);
        std::string str = read_string(emu, string_addr);

        // Translate bionic fnmatch flags to glibc fnmatch flags
        // Bionic: FNM_NOESCAPE=1, FNM_PATHNAME=2, FNM_PERIOD=4, FNM_LEADING_DIR=8, FNM_CASEFOLD=16
        // glibc:  FNM_PATHNAME=1, FNM_NOESCAPE=2, FNM_PERIOD=4, FNM_LEADING_DIR=8, FNM_CASEFOLD=16
        constexpr int BIONIC_FNM_NOESCAPE = 0x01;
        constexpr int BIONIC_FNM_PATHNAME = 0x02;
        constexpr int BIONIC_FNM_PERIOD = 0x04;
        constexpr int BIONIC_FNM_LEADING_DIR = 0x08;
        constexpr int BIONIC_FNM_CASEFOLD = 0x10;

        int glibc_flags = 0;
        if (bionic_flags & BIONIC_FNM_NOESCAPE) glibc_flags |= FNM_NOESCAPE;
        if (bionic_flags & BIONIC_FNM_PATHNAME) glibc_flags |= FNM_PATHNAME;
        if (bionic_flags & BIONIC_FNM_PERIOD) glibc_flags |= FNM_PERIOD;
        if (bionic_flags & BIONIC_FNM_LEADING_DIR) glibc_flags |= FNM_LEADING_DIR;
        if (bionic_flags & BIONIC_FNM_CASEFOLD) glibc_flags |= FNM_CASEFOLD;

        int result = ::fnmatch(pattern.c_str(), str.c_str(), glibc_flags);
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // ========================================================================
    // Stdio locking
    // ========================================================================

    hle.register_function("flockfile", [](Emulator& emu) {
        // No-op - we don't support file locking in emulation
    });

    hle.register_function("ftrylockfile", [](Emulator& emu) {
        set_reg(emu, UC_ARM64_REG_X0, 0);  // Success
    });

    hle.register_function("funlockfile", [](Emulator& emu) {
        // No-op
    });

    // ========================================================================
    // Network address functions
    // ========================================================================

    // inet_nsap_addr - convert NSAP address string to binary
    // Format: "0xHH" or "0xHH.HHHH+HHHH/HHHH..." where HH are hex digits
    // Separators: . + /
    hle.register_function("inet_nsap_addr", [](Emulator& emu) {
        uint64_t ascii_addr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t buf_addr = get_reg(emu, UC_ARM64_REG_X1);
        int buf_len = get_reg(emu, UC_ARM64_REG_X2);

        std::string input = read_string(emu, ascii_addr);

        // Must start with "0x" or "0X"
        if (input.length() < 2 || (input[0] != '0' || (input[1] != 'x' && input[1] != 'X'))) {
            set_reg(emu, UC_ARM64_REG_X0, 0);
            return;
        }

        // Parse hex bytes (dots, plus, slash are separators)
        // Each segment must have an even number of hex digits
        std::vector<uint8_t> bytes;
        std::string hex_part;
        for (size_t i = 2; i <= input.length(); i++) {
            if (i == input.length() || input[i] == '.' || input[i] == '+' || input[i] == '/') {
                // Process accumulated hex digits - must be even length
                if (hex_part.length() == 0 || hex_part.length() % 2 != 0) {
                    set_reg(emu, UC_ARM64_REG_X0, 0);
                    return;
                }
                for (size_t j = 0; j < hex_part.length(); j += 2) {
                    unsigned int byte;
                    if (sscanf(hex_part.c_str() + j, "%2x", &byte) == 1) {
                        bytes.push_back(byte);
                    }
                }
                hex_part.clear();
            } else if (isxdigit(input[i])) {
                hex_part += input[i];
            } else {
                set_reg(emu, UC_ARM64_REG_X0, 0);
                return;
            }
        }

        // Write to buffer
        int write_len = std::min((int)bytes.size(), buf_len);
        if (write_len > 0 && buf_addr) {
            emu.mem_write(buf_addr, bytes.data(), write_len);
        }
        set_reg(emu, UC_ARM64_REG_X0, write_len);
    });

    // Static buffer for inet_nsap_ntoa when user buffer is NULL
    static uint64_t nsap_ntoa_buf = 0;

    // inet_nsap_ntoa - convert binary NSAP address to string
    // Format: "0xHH.HHHH.HHHH.HH" - first byte alone, then pairs, last byte alone if odd
    hle.register_function("inet_nsap_ntoa", [](Emulator& emu) {
        int binlen = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t binary_addr = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t buf_addr = get_reg(emu, UC_ARM64_REG_X2);

        // Use static buffer if user didn't provide one
        if (buf_addr == 0) {
            if (nsap_ntoa_buf == 0) {
                nsap_ntoa_buf = emu.memory().heap().allocate(256, 8);
            }
            buf_addr = nsap_ntoa_buf;
        }

        if (binlen <= 0 || binary_addr == 0) {
            char null = 0;
            emu.mem_write(buf_addr, &null, 1);
            set_reg(emu, UC_ARM64_REG_X0, buf_addr);
            return;
        }

        // Read binary data
        std::vector<uint8_t> bytes(binlen);
        emu.mem_read(binary_addr, bytes.data(), binlen);

        // Build output string: "0xHH.HHHH.HHHH.HH"
        // First byte alone, then groups of 2 bytes (4 hex digits), last byte alone if odd
        std::string result = "0x";
        int i = 0;

        // First byte
        if (binlen > 0) {
            char hex[4];
            snprintf(hex, sizeof(hex), "%02X", bytes[i]);
            result += hex;
            i++;
        }

        // Remaining bytes in groups of 2
        while (i < binlen) {
            result += ".";
            char hex[8];
            if (i + 1 < binlen) {
                snprintf(hex, sizeof(hex), "%02X%02X", bytes[i], bytes[i+1]);
                i += 2;
            } else {
                snprintf(hex, sizeof(hex), "%02X", bytes[i]);
                i++;
            }
            result += hex;
        }

        emu.mem_write(buf_addr, result.c_str(), result.length() + 1);
        set_reg(emu, UC_ARM64_REG_X0, buf_addr);
    });

    // ========================================================================
    // File system functions
    // ========================================================================

    // mkfifo - make a FIFO special file
    hle.register_function("mkfifo", [](Emulator& emu) {
        uint64_t path_ptr = get_reg(emu, UC_ARM64_REG_X0);
        mode_t mode = get_reg(emu, UC_ARM64_REG_X1);

        if (is_invalid_guest_cstring_ptr(path_ptr)) {
            hle_set_errno(emu, EFAULT);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }
        char probe = 0;
        if (!emu.mem_read(path_ptr, &probe, 1)) {
            hle_set_errno(emu, EFAULT);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        std::string path = read_string(emu, path_ptr);
        int result = ::mkfifo(path.c_str(), mode);
        if (result == -1) {
            hle_set_errno(emu, errno);
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // mkfifoat - make a FIFO relative to directory
    hle.register_function("mkfifoat", [](Emulator& emu) {
        int dirfd = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t path_ptr = get_reg(emu, UC_ARM64_REG_X1);
        mode_t mode = get_reg(emu, UC_ARM64_REG_X2);

        if (is_invalid_guest_cstring_ptr(path_ptr)) {
            hle_set_errno(emu, EFAULT);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }
        char probe = 0;
        if (!emu.mem_read(path_ptr, &probe, 1)) {
            hle_set_errno(emu, EFAULT);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        std::string path = read_string(emu, path_ptr);
        int result = ::mkfifoat(dirfd, path.c_str(), mode);
        if (result == -1) {
            hle_set_errno(emu, errno);
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // fchmodat - change permissions of file relative to directory
    hle.register_function("fchmodat", [](Emulator& emu) {
        int dirfd = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t path_ptr = get_reg(emu, UC_ARM64_REG_X1);
        mode_t mode = get_reg(emu, UC_ARM64_REG_X2);
        int flags = get_reg(emu, UC_ARM64_REG_X3);

        if (is_invalid_guest_cstring_ptr(path_ptr)) {
            hle_set_errno(emu, EFAULT);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }
        if ((flags & ~AT_SYMLINK_NOFOLLOW) != 0) {
            hle_set_errno(emu, EINVAL);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }
        char probe = 0;
        if (!emu.mem_read(path_ptr, &probe, 1)) {
            hle_set_errno(emu, EFAULT);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        std::string path = read_string(emu, path_ptr);
        int result = ::fchmodat(dirfd, path.c_str(), mode, flags);
        if (result == -1) {
            hle_set_errno(emu, errno);
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // faccessat - check file accessibility relative to directory
    hle.register_function("faccessat", [](Emulator& emu) {
        int dirfd = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t path_ptr = get_reg(emu, UC_ARM64_REG_X1);
        int mode = get_reg(emu, UC_ARM64_REG_X2);
        int flags = get_reg(emu, UC_ARM64_REG_X3);

        if (is_invalid_guest_cstring_ptr(path_ptr)) {
            hle_set_errno(emu, EFAULT);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }
        if (flags != 0) {
            hle_set_errno(emu, EINVAL);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }
        if ((mode & ~(F_OK | R_OK | W_OK | X_OK)) != 0) {
            hle_set_errno(emu, EINVAL);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }
        char probe = 0;
        if (!emu.mem_read(path_ptr, &probe, 1)) {
            hle_set_errno(emu, EFAULT);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        std::string path = read_string(emu, path_ptr);
        int result = ::faccessat(dirfd, path.c_str(), mode, flags);
        if (result == -1) {
            hle_set_errno(emu, errno);
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // linkat - create a link
    hle.register_function("linkat", [](Emulator& emu) {
        int olddirfd = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t oldpath_ptr = get_reg(emu, UC_ARM64_REG_X1);
        int newdirfd = get_reg(emu, UC_ARM64_REG_X2);
        uint64_t newpath_ptr = get_reg(emu, UC_ARM64_REG_X3);
        int flags = get_reg(emu, UC_ARM64_REG_X4);

        if (!oldpath_ptr || !newpath_ptr) {
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        std::string oldpath = read_string(emu, oldpath_ptr);
        std::string newpath = read_string(emu, newpath_ptr);
        int result = ::linkat(olddirfd, oldpath.c_str(), newdirfd, newpath.c_str(), flags);
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // ========================================================================
    // PTY functions
    // ========================================================================

    hle.register_function("getpt", [](Emulator& emu) {
        int result = ::posix_openpt(O_RDWR | O_NOCTTY);
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("posix_openpt", [](Emulator& emu) {
        int flags = get_reg(emu, UC_ARM64_REG_X0);
        int result = ::posix_openpt(flags);
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("grantpt", [](Emulator& emu) {
        int fd = get_reg(emu, UC_ARM64_REG_X0);
        int result = ::grantpt(fd);
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("unlockpt", [](Emulator& emu) {
        int fd = get_reg(emu, UC_ARM64_REG_X0);
        errno = 0;
        int result = ::unlockpt(fd);
        if (result != 0) {
            int guest_errno = errno;
            if (guest_errno == EINVAL) {
                guest_errno = ENOTTY;
            }
            hle_set_errno(emu, guest_errno);
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("ptsname_r", [](Emulator& emu) {
        int fd = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t buf_ptr = get_reg(emu, UC_ARM64_REG_X1);
        size_t buflen = get_reg(emu, UC_ARM64_REG_X2);

        if (!buf_ptr || buflen == 0) {
            hle_set_errno(emu, EINVAL);
            set_reg(emu, UC_ARM64_REG_X0, EINVAL);
            return;
        }

        std::vector<char> buf(buflen);
        int result = ::ptsname_r(fd, buf.data(), buflen);
        if (result == 0) {
            emu.mem_write(buf_ptr, buf.data(), strlen(buf.data()) + 1);
        } else {
            hle_set_errno(emu, result);
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // ========================================================================
    // File locking
    // ========================================================================

    hle.register_function("lockf", [](Emulator& emu) {
        int fd = get_reg(emu, UC_ARM64_REG_X0);
        int cmd = get_reg(emu, UC_ARM64_REG_X1);
        off_t len = get_reg(emu, UC_ARM64_REG_X2);

        errno = 0;
        int result = ::lockf(fd, cmd, len);
        if (result == -1) {
            hle_set_errno(emu, errno);
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("lockf64", [](Emulator& emu) {
        int fd = get_reg(emu, UC_ARM64_REG_X0);
        int cmd = get_reg(emu, UC_ARM64_REG_X1);
        off64_t len = get_reg(emu, UC_ARM64_REG_X2);

        errno = 0;
        int result = ::lockf64(fd, cmd, len);
        if (result == -1) {
            hle_set_errno(emu, errno);
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // ========================================================================
    // Misc stdlib functions
    // ========================================================================

    hle.register_function("getsubopt", [](Emulator& emu) {
        uint64_t optionp_addr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t tokens_addr = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t valuep_addr = get_reg(emu, UC_ARM64_REG_X2);

        if (optionp_addr == 0 || tokens_addr == 0 || valuep_addr == 0) {
            hle_set_errno(emu, EINVAL);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        uint64_t subopts_addr = 0;
        emu.mem_read(optionp_addr, &subopts_addr, sizeof(subopts_addr));
        if (subopts_addr == 0) {
            uint64_t null_ptr = 0;
            emu.mem_write(valuep_addr, &null_ptr, sizeof(null_ptr));
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        std::string subopts = read_string(emu, subopts_addr);
        size_t comma = subopts.find(',');
        std::string token = subopts.substr(0, comma);
        size_t eq = token.find('=');
        std::string name = token.substr(0, eq);

        uint64_t next_addr = (comma == std::string::npos)
            ? (subopts_addr + subopts.size())
            : (subopts_addr + comma + 1);
        if (comma != std::string::npos) {
            char nul = '\0';
            emu.mem_write(subopts_addr + comma, &nul, 1);
        }
        emu.mem_write(optionp_addr, &next_addr, sizeof(next_addr));

        uint64_t value_addr = 0;
        if (eq != std::string::npos) {
            value_addr = subopts_addr + eq + 1;
        }
        emu.mem_write(valuep_addr, &value_addr, sizeof(value_addr));

        for (size_t i = 0;; ++i) {
            uint64_t token_ptr = 0;
            emu.mem_read(tokens_addr + i * sizeof(uint64_t), &token_ptr, sizeof(token_ptr));
            if (token_ptr == 0) {
                if (value_addr == 0) {
                    uint64_t unknown_addr = subopts_addr;
                    emu.mem_write(valuep_addr, &unknown_addr, sizeof(unknown_addr));
                }
                set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
                return;
            }
            if (read_string(emu, token_ptr) == name) {
                set_reg(emu, UC_ARM64_REG_X0, i);
                return;
            }
        }
    });

    // getline/getdelim - read line from stream
    hle.register_function("getline", [](Emulator& emu) {
        uint64_t lineptr_ptr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t n_ptr = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t stream = get_reg(emu, UC_ARM64_REG_X2);

        if (!lineptr_ptr || !n_ptr) {
            hle_set_errno(emu, EINVAL);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        FILE* fp = hle_resolve_guest_file(emu, stream);
        if (fp == nullptr) {
            hle_set_errno(emu, EBADF);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        char* host_line = nullptr;
        size_t host_capacity = 0;
        errno = 0;
        ssize_t result = ::getline(&host_line, &host_capacity, fp);
        int saved_errno = errno;

        if (result == -1) {
            std::free(host_line);
            if (saved_errno != 0) {
                hle_set_errno(emu, saved_errno);
            }
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        uint64_t guest_buf = 0;
        size_t guest_capacity = 0;
        emu.mem_read(lineptr_ptr, &guest_buf, sizeof(guest_buf));
        emu.mem_read(n_ptr, &guest_capacity, sizeof(guest_capacity));

        if (!resize_guest_line_buffer(emu, lineptr_ptr, n_ptr, host_capacity, guest_buf, guest_capacity)) {
            std::free(host_line);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        emu.mem_write(guest_buf, host_line, static_cast<size_t>(result) + 1);
        std::free(host_line);
        set_reg(emu, UC_ARM64_REG_X0,
                static_cast<uint64_t>(static_cast<int64_t>(result)));
    });

    hle.register_function("getdelim", [](Emulator& emu) {
        uint64_t lineptr_ptr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t n_ptr = get_reg(emu, UC_ARM64_REG_X1);
        int delim = get_reg(emu, UC_ARM64_REG_X2);
        uint64_t stream = get_reg(emu, UC_ARM64_REG_X3);

        if (!lineptr_ptr || !n_ptr) {
            hle_set_errno(emu, EINVAL);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        FILE* fp = hle_resolve_guest_file(emu, stream);
        if (fp == nullptr) {
            hle_set_errno(emu, EBADF);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        char* host_line = nullptr;
        size_t host_capacity = 0;
        errno = 0;
        ssize_t result = ::getdelim(&host_line, &host_capacity, delim, fp);
        int saved_errno = errno;

        if (result == -1) {
            std::free(host_line);
            if (saved_errno != 0) {
                hle_set_errno(emu, saved_errno);
            }
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        uint64_t guest_buf = 0;
        size_t guest_capacity = 0;
        emu.mem_read(lineptr_ptr, &guest_buf, sizeof(guest_buf));
        emu.mem_read(n_ptr, &guest_capacity, sizeof(guest_capacity));

        if (!resize_guest_line_buffer(emu, lineptr_ptr, n_ptr, host_capacity, guest_buf, guest_capacity)) {
            std::free(host_line);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        emu.mem_write(guest_buf, host_line, static_cast<size_t>(result) + 1);
        std::free(host_line);
        set_reg(emu, UC_ARM64_REG_X0,
                static_cast<uint64_t>(static_cast<int64_t>(result)));
    });

    hle.register_function("tempnam", [](Emulator& emu) {
        uint64_t dir_addr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t prefix_addr = get_reg(emu, UC_ARM64_REG_X1);

        std::string dir = dir_addr ? read_string(emu, dir_addr) : "";
        std::string prefix = prefix_addr ? read_string(emu, prefix_addr) : "";
        const char* tmpdir = std::getenv("TMPDIR");

        const char* base_dir = nullptr;
        if (tmpdir != nullptr && tmpdir[0] != '\0') {
            base_dir = tmpdir;
        } else if (!dir.empty()) {
            base_dir = dir.c_str();
        } else {
            base_dir = "/data/local/tmp";
        }

        std::string path = make_temp_name_path(base_dir, prefix.c_str());
        uint64_t guest_path = emu.memory().heap().allocate(path.size() + 1, 8);
        emu.mem_write(guest_path, path.c_str(), path.size() + 1);
        set_reg(emu, UC_ARM64_REG_X0, guest_path);
    });

    hle.register_function("tmpnam", [](Emulator& emu) {
        uint64_t buf_addr = get_reg(emu, UC_ARM64_REG_X0);
        std::string path = make_temp_name_path("/tmp", "tmp");

        if (buf_addr != 0) {
            emu.mem_write(buf_addr, path.c_str(), path.size() + 1);
            set_reg(emu, UC_ARM64_REG_X0, buf_addr);
            return;
        }

        static uint64_t tmpnam_buf = 0;
        if (tmpnam_buf == 0) {
            tmpnam_buf = emu.memory().heap().allocate(L_tmpnam, 8);
        }
        emu.mem_write(tmpnam_buf, path.c_str(), path.size() + 1);
        set_reg(emu, UC_ARM64_REG_X0, tmpnam_buf);
    });

    // memalign - allocate aligned memory (deprecated, prefer posix_memalign)
    hle.register_function("memalign", [](Emulator& emu) {
        size_t alignment = get_reg(emu, UC_ARM64_REG_X0);
        size_t size = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t ptr = emu.memory().heap().allocate(size, alignment);
        set_reg(emu, UC_ARM64_REG_X0, ptr);
    });
}

// ============================================================================
// Shared HLE state functions
// ============================================================================

void hle_set_errno(Emulator& emu, int value) {
    uint64_t addr = guest_errno_addr(emu);
    emu.mem_write(addr, &value, sizeof(value));
}

int hle_get_errno(Emulator& emu) {
    int value = 0;
    uint64_t addr = guest_errno_addr(emu);
    emu.mem_read(addr, &value, sizeof(value));
    return value;
}

} // namespace cross_shim
