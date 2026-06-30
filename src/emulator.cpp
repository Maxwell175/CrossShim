/**
 * CrossShim - QEMU-based ARM64 Emulator
 *
 * This file implements the core emulator using LibAFL QEMU for ARM64 emulation.
 * QEMU provides:
 * - Full ARM64 instruction set support including LSE atomics
 * - JIT compilation for high performance
 * - MTTCG for true parallel thread execution
 * - Comprehensive syscall hook support
 */

#include "debug_log.h"
#include "cross_shim.h"
#include "qemu_api.h"
#include "elf_loader.h"
#include "hle_manager.h"
#include "memory_manager.h"
#include "relocation_handler.h"
#include "syscall_handler.h"
#include "thread_manager.h"
#include "tls_manager.h"
#include "bionic_types.h"
#include "hle_path_translation.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <set>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <shared_mutex>
#include <sys/mman.h>
#include <thread>
#include <unistd.h>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <signal.h>
#include <execinfo.h>
#include <cxxabi.h>
#include <sched.h>
#include <pthread.h>
#include <cerrno>

// QEMU's thread-local CPU variables - defined in QEMU
// current_cpu: general purpose current CPU
// thread_cpu: the thread-local CPU used by signal handlers - THIS IS THE ONE WE NEED
extern "C" {
extern __thread CPUState* current_cpu;
extern __thread CPUState* thread_cpu;  // Used by host_signal_handler!
}

namespace {

constexpr uint64_t SAFE_CALL_STACK_BASE = 0xA0000000ULL;
constexpr uint64_t SAFE_CALL_STACK_SIZE = 0x00800000ULL;
constexpr uint64_t SAFE_CALL_STACK_CHUNK = 0x00100000ULL;
constexpr uint64_t SAFE_CALL_TRAMPOLINE_ADDR = cross_shim::HLE_BASE + 0xFFF80ULL;
constexpr uint64_t SAFE_CALL_CONTEXT_SIZE = 0x50ULL;
// Return trampoline for C->guest calls (mov x8,#SYS_CALL_RETURN; svc #0; ret).
// Sits below the thread exit/resume trampolines at 0x...FFFF0 and the safe-call
// trampoline at 0x...FFF80, in the slot the old per-depth return addresses used.
constexpr uint64_t CALL_RETURN_STUB_ADDR = cross_shim::HLE_BASE + 0xFFF00ULL;

}


// Implementation of libafl_qemu_set_current_cpu
extern "C" void libafl_qemu_set_current_cpu(CPUState* cpu) {
    current_cpu = cpu;
}

// Override libafl_qemu_main - return without running
// We control execution by setting PC and calling libafl_qemu_run()
extern "C" {
int libafl_qemu_main(void) {
    // Return immediately - we set PC and call libafl_qemu_run() ourselves
    return 0;
}
}

// =============================================================================
// Signal Handler Wrapper - Intercepts ALL signals before QEMU
// =============================================================================
// This is critical because QEMU's host_signal_handler crashes when thread_cpu
// is NULL (on non-QEMU threads like .NET runtime threads). We need to wrap
// ALL signals that QEMU handles and check current_cpu before forwarding.
// =============================================================================

// Store QEMU's original handlers for all signals
static struct sigaction g_qemu_handlers[64];
static bool g_handlers_wrapped = false;

// Universal signal handler wrapper
static void universal_signal_wrapper(int sig, siginfo_t* info, void* context) {
    // CRITICAL: Check thread_cpu (NOT current_cpu!) BEFORE doing anything that might crash
    // QEMU's host_signal_handler uses thread_cpu which is different from current_cpu!
    if (thread_cpu == nullptr) {
        // This is a non-QEMU thread (e.g., .NET runtime thread).
        // We CANNOT forward to QEMU's handler as it will crash.
#if EMU_LOGGING_ENABLED
        // Note: Using write() for signal-safety (EMU_LOG uses mutex, not safe here)
        static const char* sig_names[] = {"?", "HUP", "INT", "QUIT", "ILL", "TRAP", "ABRT", "BUS", "FPE", "KILL", "USR1", "SEGV"};
        const char* sig_name = (sig >= 0 && sig <= 11) ? sig_names[sig] : "?";
        char msg[128];
        snprintf(msg, sizeof(msg), "[SIGNAL-WRAPPER] sig=%d (%s) on non-QEMU thread, blocking\n", sig, sig_name);
        (void)write(STDERR_FILENO, msg, strlen(msg));
#endif

        // For SIGSEGV/SIGBUS/SIGABRT on non-QEMU threads, we should exit.
        // For other signals, we can safely ignore them.
        if (sig == SIGSEGV || sig == SIGBUS || sig == SIGABRT) {
            // Fatal signal on non-QEMU thread - exit
            _exit(128 + sig);
        }
        // Non-fatal signal on non-QEMU thread - ignore
        return;
    }

    // We're on a QEMU thread - forward to QEMU's handler
    if (sig >= 0 && sig < 64 && g_qemu_handlers[sig].sa_handler != SIG_DFL &&
        g_qemu_handlers[sig].sa_handler != SIG_IGN) {
        if (g_qemu_handlers[sig].sa_flags & SA_SIGINFO) {
            g_qemu_handlers[sig].sa_sigaction(sig, info, context);
        } else {
            g_qemu_handlers[sig].sa_handler(sig);
        }
    }
}

// Block signals on the current thread using pthread_sigmask
// This is called EARLY before .NET spawns any worker threads, so all .NET
// threads will inherit the blocked signal mask and won't receive these signals.
static void block_signals_on_host_threads() {
    sigset_t block_set;
    sigemptyset(&block_set);

    // Block signals that QEMU handles - these crash on non-QEMU threads
    sigaddset(&block_set, SIGSEGV);
    sigaddset(&block_set, SIGBUS);
    sigaddset(&block_set, SIGFPE);
    sigaddset(&block_set, SIGILL);
    sigaddset(&block_set, SIGTRAP);
    sigaddset(&block_set, SIGUSR1);
    sigaddset(&block_set, SIGUSR2);
    sigaddset(&block_set, SIGPIPE);  // Common in network code - ignore rather than crash

    // Apply the block mask to this thread - child threads will inherit it
    int ret = pthread_sigmask(SIG_BLOCK, &block_set, nullptr);
    EMU_LOG << "[DEBUG] Blocked signals on host thread: ret=" << ret << std::endl;
}

// Wrap all signal handlers that QEMU installs
// Use raw syscall to install signal handler - this bypasses libc and competes with QEMU
#include <sys/syscall.h>

// Kernel's sigaction structure (different from glibc's on some platforms)
struct kernel_sigaction {
    void (*k_sa_handler)(int);
    unsigned long sa_flags;
    void (*sa_restorer)(void);
    unsigned long sa_mask;  // Simplified - kernel uses different layout
};

static long raw_rt_sigaction(int sig, const struct sigaction* act, struct sigaction* oldact) {
    // On x86_64: syscall 13 is rt_sigaction
    // Arguments: rdi=sig, rsi=act, rdx=oldact, r10=sigsetsize (must be 8 for x86_64)
    long ret;
    register long r10 __asm__("r10") = 8;  // sigsetsize
    __asm__ volatile (
        "syscall"
        : "=a" (ret)
        : "0" (__NR_rt_sigaction),
          "D" ((long)sig),
          "S" (act),
          "d" (oldact),
          "r" (r10)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static void wrap_qemu_signal_handlers() {
    if (g_handlers_wrapped) return;

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = universal_signal_wrapper;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_RESTART;
    sigfillset(&sa.sa_mask);  // Block all signals while handling

    // Wrap signals that QEMU typically handles
    // QEMU sets up handlers for: SIGSEGV, SIGBUS, SIGFPE, SIGILL, SIGTRAP, SIGABRT
    // and potentially others for synchronous signals
    int signals_to_wrap[] = {
        SIGSEGV, SIGBUS, SIGFPE, SIGILL, SIGTRAP, SIGABRT,
        SIGUSR1, SIGUSR2,  // QEMU might use these for thread control
        SIGPIPE,           // Common in network code
        -1  // Sentinel
    };

    EMU_LOG << "[DEBUG] Wrapping signal handlers (using raw syscall)..." << std::endl;
    for (int i = 0; signals_to_wrap[i] != -1; i++) {
        int sig = signals_to_wrap[i];
        struct sigaction old_handler;
        memset(&old_handler, 0, sizeof(old_handler));
        // Use RAW syscall to compete with QEMU's inline asm
        long ret = raw_rt_sigaction(sig, &sa, &old_handler);
        g_qemu_handlers[sig] = old_handler;
        EMU_LOG << "[DEBUG] Wrapped signal " << sig << ": old_handler="
                << (void*)old_handler.sa_sigaction
                << " flags=0x" << std::hex << old_handler.sa_flags << std::dec
                << " ret=" << ret << std::endl;
    }

    g_handlers_wrapped = true;
    EMU_LOG << "[DEBUG] Signal handlers wrapped for non-QEMU thread safety" << std::endl;
}

static void install_crash_handler() {
    // The actual handler wrapping is done AFTER QEMU init
    // via wrap_qemu_signal_handlers()
    EMU_LOG << "[DEBUG] Crash handler placeholder - actual wrapping after QEMU init" << std::endl;
}

// Library constructor - DISABLED for standalone use
// The signal blocking interferes with QEMU's memory fault handling.
// For .NET compatibility, the QEMU patches (pthread_key approach) handle thread safety.
#if 0  // DISABLED - breaks QEMU signal handling
__attribute__((constructor))
static void library_init() {
    // Block signals on the main thread - all child threads will inherit this
    block_signals_on_host_threads();
}
#endif

// =============================================================================
// Debug: Instruction hooks for tracing execution
// =============================================================================
static std::atomic<int> g_instruction_hook_count{0};
static std::vector<size_t> g_debug_instruction_hooks;

static void debug_instruction_hook(uint64_t data, uint64_t pc) {
    int count = ++g_instruction_hook_count;
    if (count <= 20) {  // Only log first 20 hits
        EMU_LOG << "[INSN] PC=0x" << std::hex << pc << std::dec
                  << " (hit #" << count << ")" << std::endl;

        // Try to read the instruction
        CPUState* cpu = libafl_qemu_current_cpu();
        if (cpu) {
            uint32_t insn = 0;
            int err = cpu_memory_rw_debug(cpu, pc, &insn, 4, 0);
            if (err == 0) {
                EMU_LOG << "       Instruction: 0x" << std::hex << insn << std::dec << std::endl;
            }
            EMU_LOG << "       SP=0x" << std::hex << qemu::read_reg(cpu, qemu::REG_SP)
                      << " LR=0x" << qemu::read_reg(cpu, qemu::REG_LR)
                      << " X0=0x" << qemu::read_reg(cpu, qemu::REG_X0)
                      << std::dec << std::endl;
        }
    }
}

static void setup_debug_instruction_hooks(uint64_t start_pc, int count) {
    // Clear previous hooks
    for (size_t hook_id : g_debug_instruction_hooks) {
        libafl_qemu_remove_instruction_hook(hook_id, 0);
    }
    g_debug_instruction_hooks.clear();
    g_instruction_hook_count = 0;

    // Add hooks for 'count' instructions starting at start_pc
    for (int i = 0; i < count; i++) {
        uint64_t pc = start_pc + (i * 4);  // ARM64 instructions are 4 bytes
        size_t hook_id = libafl_qemu_add_instruction_hooks(pc, debug_instruction_hook, 0, 1);
        g_debug_instruction_hooks.push_back(hook_id);
        EMU_LOG << "[DEBUG] Added instruction hook at 0x" << std::hex << pc
                  << " (id=" << std::dec << hook_id << ")" << std::endl;
    }
}

static void clear_debug_instruction_hooks() {
    for (size_t hook_id : g_debug_instruction_hooks) {
        libafl_qemu_remove_instruction_hook(hook_id, 1);
    }
    g_debug_instruction_hooks.clear();
    g_instruction_hook_count = 0;
}

// Find the QEMU stub binary path
static const char* find_qemu_stub() {
    static std::string stub_path;
    if (!stub_path.empty()) return stub_path.c_str();

    // Explicit override for non-standard layouts (set by the embedder if needed).
    if (const char* env = std::getenv("CROSSSHIM_QEMU_STUB")) {
        std::ifstream f(env);
        if (f.good()) {
            stub_path = env;
            return stub_path.c_str();
        }
    }

    // Check common locations relative to the working directory / binary.
    const char* locations[] = {
        "stubs/qemu_stub",
        "../stubs/qemu_stub",
        "../../stubs/qemu_stub",
        "../CrossShim/stubs/qemu_stub",
        "../../CrossShim/stubs/qemu_stub",
        nullptr
    };

    for (int i = 0; locations[i] != nullptr; i++) {
        std::ifstream f(locations[i]);
        if (f.good()) {
            stub_path = locations[i];
            return stub_path.c_str();
        }
    }

    return nullptr;
}

namespace cross_shim {

// Forward declarations for HLE registration (legacy)
void register_libc_hle(HleManager &hle);
void register_libm_hle(HleManager &hle);
void register_libdl_hle(HleManager &hle);
void register_pthread_hle(HleManager &hle);

// Forward declarations for new modular HLE registration
void register_hle_memory(HleManager &hle);
void register_hle_string(HleManager &hle);
void register_hle_mem_ops(HleManager &hle);
void register_hle_io(HleManager &hle);
void register_hle_file(HleManager &hle);
void register_hle_time(HleManager &hle);
void register_hle_network(HleManager &hle);
void register_hle_pthread(HleManager &hle);
void register_hle_misc(HleManager &hle);
void register_hle_math(HleManager &hle);
void register_hle_crypto(HleManager &hle);
void register_hle_process(HleManager &hle);
void register_hle_dir(HleManager &hle);
void register_hle_syslog(HleManager &hle);
void register_hle_user(HleManager &hle);
// Split from hle_misc.cpp
void register_hle_stdlib(HleManager &hle);
void register_hle_wchar(HleManager &hle);
void register_hle_locale(HleManager &hle);
void register_hle_ctype(HleManager &hle);
void register_hle_signal(HleManager &hle);
void register_hle_search(HleManager &hle);
void register_hle_sched(HleManager &hle);
void register_hle_setjmp(HleManager &hle);
void register_hle_sysconf(HleManager &hle);

// Global emulator pointer for hook callbacks
static Emulator* g_emulator = nullptr;

// Thread-local CPU pointer for HLE calls
static thread_local CPUState* tls_cpu = nullptr;

// Parallel vCPU worker pool: per-worker thread-local state.
// tl_is_worker is true on the main emulator thread AND every pool worker, so a
// reentrant call_function (HLE handler -> guest) runs inline on the current vCPU
// instead of cross-dispatching to another worker (which would corrupt context).
static thread_local bool tl_is_worker = false;
static thread_local int tl_worker_id = 0;            // 0 = main thread, 1..N = pool workers
static thread_local uint64_t tl_safe_stack_base = SAFE_CALL_STACK_BASE;

// Get the current CPU for this thread
CPUState* get_current_cpu(Emulator& emu) {
    if (tls_cpu != nullptr) {
        return tls_cpu;
    }
    // Fall back to QEMU's current CPU for this host thread.
    // In MTTCG HLE callbacks we explicitly seed tls_cpu from the syscall hook;
    // prefer that stable pointer over libafl_qemu_current_cpu(), which can race
    // and occasionally report CPU 0 for a worker thread.
    CPUState* cpu = libafl_qemu_current_cpu();
    if (cpu != nullptr) {
        return cpu;
    }
    // Last resort: use emulator's stored CPU (CPU 0)
    // NOTE: This happens during early initialization before QEMU is ready,
    // and is safe for HLE registration. It should NOT happen after QEMU init.
    static bool warned_fallback = false;
    if (!warned_fallback) {
        EMU_LOG << "[EMU] WARNING: get_current_cpu() falling back to CPU 0! "
                  << "This may cause race conditions in child threads." << std::endl;
        warned_fallback = true;
    }
    return emu.get_cpu();
}

// =============================================================================
// Syscall Hook - Handles all ARM64 syscalls via HLE
// =============================================================================

// Forward declaration for thread exit notification (defined in hle_pthread.cpp)
void notify_thread_exit(uint64_t sp, uint64_t retval, bool finalize);

// Custom syscall numbers for thread lifecycle
static constexpr int SYS_THREAD_DONE = 0x1234;
static constexpr int SYS_THREAD_START = 0x1235;  // Debug marker
static constexpr int SYS_CLONE_DEBUG = 0x1236;   // Debug after clone
static constexpr int SYS_CLONE_CHILD_EXIT = 0x1237; // Exit helper for HLE clone children
// C->guest call-return trampoline. When a guest function called via call_function()
// returns, LR points at the return stub which issues this syscall. The syscall hook
// forces a per-thread cpu_loop exit (libafl_qemu_trigger_breakpoint), replacing the
// old global-breakpoint return-trap that was not thread-safe across the vCPU worker pool.
static constexpr int SYS_CALL_RETURN = 0x1238;

// HLE syscall base and mapping (defined in allocate_stub, used in pre_syscall_hook)
static constexpr int HLE_SYSCALL_BASE = 0x2000;
static constexpr int HLE_SYSCALL_CAPACITY = 0x1000;
static std::array<std::atomic<uint64_t>, HLE_SYSCALL_CAPACITY> g_hle_syscall_to_addr{};
static std::atomic<int> g_next_hle_syscall{HLE_SYSCALL_BASE};

// CRITICAL FIX: Thread-local running flag to prevent race conditions
// Each thread (main thread and child threads created via clone) needs its own
// execution state flag. The old shared running_ caused races where a child
// thread finishing its start() call would set running_=false and terminate
// the main thread's execution loop prematurely.
static thread_local bool tl_running = false;

// Set by the syscall hook when this thread's C->guest call returns through the
// call-return trampoline (SYS_CALL_RETURN). start() consumes it to stop the run
// loop. Thread-local so each vCPU worker tracks its own call independently.
static thread_local bool tl_call_return_hit = false;

// Sticky worker affinity for a calling (non-worker) host thread: the pool worker id
// this thread's C->guest calls are always routed to. -1 until first assigned. Keeps a
// given session's calls on ONE guest CPU (see pick_affinity_worker / call_function).
static thread_local int tl_affinity_worker = -1;

// Diagnostic: how this thread's most recent start() run loop exited. A C->guest call is
// only TRUSTWORTHY (its X0 is the guest function's real return value) when start() exits via
// the call-return trampoline ("clean_return") or end_address ("end_address"). Any other exit
// (crash, silent break, tl_running cleared) means start() bailed mid-call and X0 is STALE —
// call_function_internal then hands that stale X0 back as if it were the result (e.g. a stale
// 0xffffffff surfaces to the C# layer as GetSessionId=-1). Set at every start() exit point.
static thread_local const char* tl_start_exit_reason = "none";

// CRITICAL FIX: Mutex for HLE handler serialization
// This provides the same synchronization that verbose logging provides
// (via EMU_LOG's mutex) without the performance overhead of actual logging.
// Using a separate recursive_mutex to avoid deadlock with EMU_LOG.
static std::recursive_mutex g_hle_sync_mutex;

static libafl_syshook_ret pre_syscall_hook(
    uint64_t data, int sys_num,
    uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3,
    uint64_t arg4, uint64_t arg5, uint64_t arg6, uint64_t arg7) {

    libafl_syshook_ret ret;

    // Defensive check: validate data pointer
    if (data == 0) {
        ret.tag = LIBAFL_SYSHOOK_RUN;
        return ret;
    }

    Emulator* emu = reinterpret_cast<Emulator*>(data);

    // Debug: Check for garbage syscall numbers
    if (sys_num < 0 || (sys_num > 1000 && sys_num < 0x1000)) {
        CPUState* cpu = libafl_qemu_current_cpu();
        uint64_t pc = qemu::read_reg(cpu, qemu::REG_PC);
        uint64_t x8 = qemu::read_reg(cpu, qemu::REG_X8);
        EMU_LOG << "[SYSCALL_DEBUG] Suspicious syscall number: " << sys_num
                  << " (0x" << std::hex << (unsigned int)sys_num << ")"
                  << " X8=0x" << x8 << " PC=0x" << pc << std::dec << std::endl;
        // Let QEMU handle it
        ret.tag = LIBAFL_SYSHOOK_RUN;
        return ret;
    }

    // Get current SP to identify thread
    CPUState* hook_cpu = libafl_qemu_current_cpu();
    if (!hook_cpu) {
        // CPU not available - let QEMU handle it
        ret.tag = LIBAFL_SYSHOOK_RUN;
        return ret;
    }
    uint64_t hook_sp = qemu::read_reg(hook_cpu, qemu::REG_SP);
    uint64_t hook_pc = qemu::read_reg(hook_cpu, qemu::REG_PC);

#if EMU_VERBOSE_LOGGING
    // Only log child thread syscalls (SP in 0x90xxxxxx range) or debug syscalls
    bool is_child_thread = (hook_sp >= 0x90000000 && hook_sp < 0x91000000);
    bool is_debug_syscall = (sys_num == SYS_THREAD_DONE || sys_num == SYS_THREAD_START ||
                             sys_num == SYS_CLONE_DEBUG || sys_num == SYS_CLONE_CHILD_EXIT);
    // Also log network-related syscalls (socket=198, connect=203, bind=200, sendto=206, recvfrom=207)
    bool is_network_syscall = (sys_num == 198 || sys_num == 200 || sys_num == 203 || sys_num == 206 || sys_num == 207);

    if (is_child_thread) {
        EMU_LOG_VERBOSE << "[CHILD_SYSCALL] #" << std::hex << sys_num << " SP=0x" << hook_sp
                  << " PC=0x" << hook_pc << std::dec << std::endl;
    } else if (is_debug_syscall || sys_num == 220 || sys_num == 93 || is_network_syscall) {
        EMU_LOG_VERBOSE << "[SYSCALL] #" << sys_num << " SP=0x" << std::hex << hook_sp
                  << " PC=0x" << hook_pc
                  << " (args: " << arg0 << ", " << arg1 << ", " << arg2
                  << ", " << arg3 << ", " << arg4 << ", " << arg5 << ")" << std::dec << std::endl;
    }
#endif

    // Handle debug after clone marker
    if (sys_num == SYS_CLONE_DEBUG) {
        CPUState* cpu = libafl_qemu_current_cpu();
        uint64_t sp = qemu::read_reg(cpu, qemu::REG_SP);
        uint64_t pc = qemu::read_reg(cpu, qemu::REG_PC);
        uint64_t lr = qemu::read_reg(cpu, qemu::REG_LR);
        uint64_t x0 = qemu::read_reg(cpu, qemu::REG_X0);
        uint64_t tpidr = qemu::read_reg(cpu, qemu::REG_TPIDR_EL0);
        EMU_LOG << "[SYSCALL] SYS_CLONE_DEBUG: After clone! SP=0x" << std::hex << sp
                  << " PC=0x" << pc << " LR=0x" << lr << " X0=0x" << x0
                  << " TPIDR_EL0=0x" << tpidr << std::dec << std::endl;
        ret.tag = LIBAFL_SYSHOOK_SKIP;
        ret.syshook_skip_retval = 0;
        return ret;
    }

    // Handle debug thread start marker
    if (sys_num == SYS_THREAD_START) {
        CPUState* cpu = libafl_qemu_current_cpu();
        uint64_t sp = qemu::read_reg(cpu, qemu::REG_SP);
        uint64_t pc = qemu::read_reg(cpu, qemu::REG_PC);
        uint64_t x4 = qemu::read_reg(cpu, qemu::REG_X4);
        // Read start_routine, arg, and tls from stack
        uint64_t start_routine = 0, arg = 0, tls_on_stack = 0;
        cpu_memory_rw_debug(cpu, sp, &start_routine, 8, 0);
        cpu_memory_rw_debug(cpu, sp + 8, &arg, 8, 0);
        cpu_memory_rw_debug(cpu, sp + 16, &tls_on_stack, 8, 0);

        // WORKAROUND: MSR TPIDR_EL0 doesn't work in QEMU usermode
        // Set TPIDR_EL0 via QEMU API instead
        if (tls_on_stack != 0) {
            qemu::write_reg(cpu, qemu::REG_TPIDR_EL0, tls_on_stack);
        }
        uint64_t tpidr = qemu::read_reg(cpu, qemu::REG_TPIDR_EL0);

        EMU_LOG << "[SYSCALL] SYS_THREAD_START: Child thread starting! SP=0x"
                  << std::hex << sp << " PC=0x" << pc
                  << " start_routine=0x" << start_routine
                  << " arg=0x" << arg
                  << " tls_on_stack=0x" << tls_on_stack
                  << " X4=0x" << x4
                  << " TPIDR_EL0=0x" << tpidr << std::dec << std::endl;
        ret.tag = LIBAFL_SYSHOOK_SKIP;
        ret.syshook_skip_retval = 0;
        return ret;
    }

    // Handle custom thread done syscall
    if (sys_num == SYS_THREAD_DONE) {
        CPUState* cpu = libafl_qemu_current_cpu();
        // Use stack pointer to identify the thread (each thread has unique stack)
        uint64_t sp = qemu::read_reg(cpu, qemu::REG_SP);
        uint64_t retval = arg0;  // Return value is in X0

        EMU_LOG << "[SYSCALL] SYS_THREAD_DONE: SP=0x" << std::hex << sp
                  << " retval=0x" << retval << std::dec << std::endl;

        // Notify thread completion - use SP as identifier since TLS is not accessible
        notify_thread_exit(sp, retval, false);

        // Return 0 (success)
        ret.tag = LIBAFL_SYSHOOK_SKIP;
        ret.syshook_skip_retval = 0;
        return ret;
    }

    if (sys_num == SYS_CLONE_CHILD_EXIT) {
        int exit_code = static_cast<int>(arg0);
        EMU_LOG << "[SYSCALL] SYS_CLONE_CHILD_EXIT(" << exit_code << ")" << std::endl;
        ::_exit(exit_code);
    }

    // C->guest call returned through the call-return trampoline. Force a clean,
    // per-thread exit from cpu_loop using only __thread exit state (no global
    // breakpoint list, no cross-CPU TB flush), then hand X0 back unchanged so the
    // guest function's return value survives cpu_loop's post-syscall X0 write-back.
    if (sys_num == SYS_CALL_RETURN) {
        uint64_t real_ret = qemu::read_reg(hook_cpu, qemu::REG_X0);
        tl_call_return_hit = true;
        libafl_qemu_trigger_breakpoint(hook_cpu);
        ret.tag = LIBAFL_SYSHOOK_SKIP;
        ret.syshook_skip_retval = real_ret;
        return ret;
    }

    if (sys_num == 22 /* SYS_epoll_pwait */) {
        const int epfd = static_cast<int>(arg0);
        const uint64_t events_ptr = arg1;
        const int maxevents = static_cast<int>(arg2);
        const int timeout = static_cast<int>(arg3);
        const uint64_t sigmask_ptr = arg4;
        const size_t sigset_size = static_cast<size_t>(arg5);

        // Keep only the true non-blocking poll case on the hook fast path.
        // Any timed or blocking wait must stay in QEMU's native syscall path;
        // otherwise the guest thread parks inside pre_syscall_hook and can
        // deadlock later thread startup/RCU synchronization.
        if (events_ptr != 0 && maxevents > 0 && timeout == 0 &&
            sigmask_ptr == 0 && sigset_size == 0) {
            std::vector<struct epoll_event> host_events(maxevents);
            const int rc = ::epoll_wait(epfd, host_events.data(), maxevents, timeout);

            if (rc > 0) {
                std::vector<cross_shim::bionic::epoll_event_arm64> guest_events(rc);
                for (int i = 0; i < rc; ++i) {
                    cross_shim::bionic::host_to_arm64_epoll_event(host_events[i], guest_events[i]);
                }

                if (!emu->mem_write(events_ptr, guest_events.data(),
                                    guest_events.size() * sizeof(cross_shim::bionic::epoll_event_arm64))) {
                    constexpr int raw_fault = -EFAULT;
                    qemu::write_reg(hook_cpu, qemu::REG_X0, static_cast<uint64_t>(raw_fault));
                    ret.tag = LIBAFL_SYSHOOK_SKIP;
                    ret.syshook_skip_retval = raw_fault;
                    return ret;
                }
            }

            const int raw_ret = (rc < 0) ? -errno : rc;
            qemu::write_reg(hook_cpu, qemu::REG_X0, static_cast<uint64_t>(raw_ret));
            ret.tag = LIBAFL_SYSHOOK_SKIP;
            ret.syshook_skip_retval = raw_ret;
            return ret;
        }
    }

    // Handle HLE syscalls (0x2000-0x2FFF range)
    // These are generated by HLE stubs to trigger HLE function execution
    if (sys_num >= 0x2000 && sys_num < 0x3000) {
#if EMU_VERBOSE_LOGGING
        EMU_LOG_VERBOSE << "[HLE_SYSCALL] Got HLE syscall 0x" << std::hex << sys_num
                        << " PC=0x" << hook_pc << std::dec << std::endl;
#endif
        const int hle_index = sys_num - HLE_SYSCALL_BASE;
        uint64_t hle_addr = 0;
        if (hle_index >= 0 && hle_index < HLE_SYSCALL_CAPACITY) {
            hle_addr = g_hle_syscall_to_addr[hle_index].load(std::memory_order_acquire);
        }

        if (hle_addr != 0) {

            // CRITICAL FIX: Cache the CPU pointer ONCE at the start
            // Multiple calls to libafl_qemu_current_cpu() in MTTCG mode may race
            CPUState* cached_cpu = hook_cpu;  // Already obtained at line 355

#if EMU_VERBOSE_LOGGING
            // Log child thread HLE syscalls for debugging
            if (hook_sp >= 0x90000000 && hook_sp < 0x91000000) {
                EMU_LOG_VERBOSE << "[HLE_SYSCALL] Child thread: #0x" << std::hex << sys_num
                          << " -> addr=0x" << hle_addr << " SP=0x" << hook_sp
                          << std::dec << std::endl;
            }
#endif

            // Call the HLE handler with cached CPU
            // NOTE: HLE handlers run on whichever thread triggered them. With MTTCG,
            // multiple threads can call HLE handlers simultaneously. Each handler must
            // be internally thread-safe. Don't use g_hle_sync_mutex here as it causes
            // deadlock when blocking HLE calls (like usleep) prevent other threads.
            try {
                emu->hle().handle_with_cpu(cached_cpu, hle_addr);
            } catch (const std::exception& e) {
                EMU_LOG << "[HLE_SYSCALL] Exception in HLE handler 0x" << std::hex
                          << hle_addr << ": " << e.what() << std::dec << std::endl;
                ret.tag = LIBAFL_SYSHOOK_SKIP;
                ret.syshook_skip_retval = -1;
                return ret;
            } catch (...) {
                EMU_LOG << "[HLE_SYSCALL] Unknown exception in HLE handler 0x" << std::hex
                          << hle_addr << std::dec << std::endl;
                ret.tag = LIBAFL_SYSHOOK_SKIP;
                ret.syshook_skip_retval = -1;
                return ret;
            }

            // Return the value from X0 (set by the HLE handler)
            // Use the SAME cached CPU pointer - don't call libafl_qemu_current_cpu() again
            uint64_t retval = qemu::read_reg(cached_cpu, qemu::REG_X0);
            // IMPORTANT: Explicitly set X0 to ensure the return value is used
            // The LIBAFL_SYSHOOK_SKIP mechanism may not properly set X0
            qemu::write_reg(cached_cpu, qemu::REG_X0, retval);
            ret.tag = LIBAFL_SYSHOOK_SKIP;
            ret.syshook_skip_retval = retval;
            return ret;
        } else {
            EMU_LOG << "[HLE_SYSCALL] Unknown HLE syscall 0x" << std::hex << sys_num
                      << std::dec << std::endl;
            ret.tag = LIBAFL_SYSHOOK_SKIP;
            ret.syshook_skip_retval = -1;
            return ret;
        }
    }

    // Handle exit/exit_group ourselves to capture the exit code.
    //
    // Guest worker threads sometimes terminate via SYS_exit without hitting the
    // custom SYS_THREAD_DONE path first, especially when pthread_exit is routed
    // through bionic's internal teardown. In that case we still need to mark the
    // thread complete so pthread_join can observe it.
    //
    // Note: We don't call ::_exit() in forked children because QEMU's internal
    // state isn't fully fork-safe and causes crashes. Death tests will timeout
    // but the suite won't take down the host process.
    if (sys_num == 93 /* SYS_exit */) {
        // A guest thread is terminating (typically pthread_exit, which MUST be no-return).
        // Two cases, distinguished by tl_running (set true ONLY inside the worker pool's
        // Emulator::start() loop; an ordinary guest thread runs QEMU's native cpu_loop and
        // leaves it false):
        //
        //  - Worker vCPU (tl_running): a C->guest call's guest code reached pthread_exit. We
        //    must NOT run native exit here — host pthread_exit does a forced stack unwind that
        //    would tear the persistent worker down through call_function's catch(...), which
        //    swallows it -> glibc "FATAL: exception not rethrown" -> abort. Instead end the
        //    call like the call-return trampoline: force this worker's cpu_loop to exit so
        //    Emulator::start() returns to the request loop; the worker survives, the call
        //    returns failure (-1).
        //
        //  - Ordinary guest thread (!tl_running): let QEMU run the NATIVE TARGET_NR_exit so the
        //    host thread truly terminates (+ cpu_list_remove / rcu_unregister, ending zombie-CPU
        //    buildup). Its forced unwind runs entirely on QEMU's C clone_func/cpu_loop stack
        //    (no C++ catch) so it is clean. Relying on emu->stop()+SKIP instead leaves the
        //    thread running -> it returns from the no-return pthread_exit and runs off the end
        //    of its caller into adjacent code -> SIGSEGV in code_gen_buffer (the original crash).
        if (tl_running) {
            // EXITDIAG: this is the cascade source. A guest SYS_exit while a C->guest call runs on
            // a worker ends the call with a full-64-bit -1 (skip_retval below). Log WHERE the guest
            // is exiting from (PC/LR/exit-code) so we can tell a legit pthread_exit from a
            // corrupted/mis-attributed one. fprintf = always visible.
            {
                static std::atomic<uint64_t> exitcnt{0};
                uint64_t c = exitcnt.fetch_add(1, std::memory_order_relaxed);
                if (c < 64 || (c % 1000) == 0) {
                    fprintf(stderr, "[EXITDIAG] SYS_exit on worker tl_worker=%d guest PC=0x%lx LR=0x%lx "
                            "exitcode=0x%lx (#%lu) -> call returns -1\n",
                            tl_worker_id,
                            (unsigned long)qemu::read_reg(hook_cpu, qemu::REG_PC),
                            (unsigned long)qemu::read_reg(hook_cpu, qemu::REG_LR),
                            (unsigned long)arg0, (unsigned long)c);
                }
            }
            tl_call_return_hit = true;
            libafl_qemu_trigger_breakpoint(hook_cpu);
            ret.tag = LIBAFL_SYSHOOK_SKIP;
            // Return the guest's X0 (already in arg0), NOT a hardcoded full-64-bit -1. If this
            // branch ever fires for what is really a normal C->guest return (the historical cause:
            // the call-return trampoline got mis-dispatched as SYS_exit), X0 already holds the
            // function's true return value, so handing it back avoids poisoning every call with -1
            // (a process-wide cascade). For a genuinely terminal worker pthread_exit this is the
            // exit code — as good as -1 and still SIGSEGV-safe (still breakpoint+SKIP, no native
            // unwind). EXITDIAG above still logs each occurrence so the root (if any) stays visible.
            ret.syshook_skip_retval = qemu::read_reg(hook_cpu, qemu::REG_X0);
            return ret;
        }
        notify_thread_exit(hook_sp, static_cast<uint64_t>(arg0), true);
        ret.tag = LIBAFL_SYSHOOK_RUN;
        return ret;
    }

    if (sys_num == 94 /* SYS_exit_group */) {
        // The guest wants the whole process down. Running TARGET_NR_exit_group natively
        // would _exit the host process (unsafe in forked death-test children; and the C#
        // host owns process lifetime). Keep skipping: just stop this thread's loop.
        int exit_code = static_cast<int>(arg0);
        EMU_LOG << "[SYSCALL] exit_group(" << exit_code << ") - stopping emulation" << std::endl;
        qemu::write_reg(hook_cpu, qemu::REG_X0, static_cast<uint64_t>(arg0));
        emu->stop();
        ret.tag = LIBAFL_SYSHOOK_SKIP;
        ret.syshook_skip_retval = exit_code;
        return ret;
    }

    // Syscalls that QEMU must handle natively.
    //
    // The critical set is thread/process synchronization (clone/futex/tid setup),
    // but we also let QEMU own the blocking socket/poll/sleep syscalls used by
    // guest libc wrappers. Running those waits inline inside our HLE syscall hook
    // keeps guest worker threads parked inside QEMU's RCU read-side path and can
    // stall later guest thread creation in clone_func/rcu_register_thread.
    if (sys_num == 20  /* SYS_epoll_create1 */ ||
        sys_num == 21  /* SYS_epoll_ctl */ ||
        sys_num == 22  /* SYS_epoll_pwait */ ||
        sys_num == 72  /* SYS_pselect6 */ ||
        sys_num == 73  /* SYS_ppoll */ ||
        sys_num == 96  /* SYS_set_tid_address */ ||
        sys_num == 98  /* SYS_futex */ ||
        sys_num == 99  /* SYS_set_robust_list */ ||
        sys_num == 101 /* SYS_nanosleep */ ||
        sys_num == 115 /* SYS_clock_nanosleep */ ||
        sys_num == 198 /* SYS_socket */ ||
        sys_num == 200 /* SYS_bind */ ||
        sys_num == 201 /* SYS_listen */ ||
        sys_num == 202 /* SYS_accept */ ||
        sys_num == 203 /* SYS_connect */ ||
        sys_num == 204 /* SYS_getsockname */ ||
        sys_num == 205 /* SYS_getpeername */ ||
        sys_num == 206 /* SYS_sendto */ ||
        sys_num == 207 /* SYS_recvfrom */ ||
        sys_num == 208 /* SYS_setsockopt */ ||
        sys_num == 209 /* SYS_getsockopt */ ||
        sys_num == 210 /* SYS_shutdown */ ||
        sys_num == 211 /* SYS_sendmsg */ ||
        sys_num == 212 /* SYS_recvmsg */ ||
        sys_num == 220 /* SYS_clone */ ||
        sys_num == 242 /* SYS_accept4 */ ||
        sys_num == 407 /* SYS_clock_nanosleep_time64 */ ||
        sys_num == 413 /* SYS_pselect6_time64 */ ||
        sys_num == 414 /* SYS_ppoll_time64 */ ||
        sys_num == 435 /* SYS_clone3 */ ||
        sys_num == 441 /* SYS_epoll_pwait2 */) {
        EMU_LOG << "[SYSCALL] Letting QEMU handle syscall " << sys_num << " natively" << std::endl;
        ret.tag = LIBAFL_SYSHOOK_RUN;
        return ret;
    }

    // Handle the syscall via our HLE syscall handler
    emu->handle_syscall(sys_num);

    // Skip QEMU's native syscall handling - we've handled it
    // Use cached CPU pointer from start of function
    uint64_t retval_final = qemu::read_reg(hook_cpu, qemu::REG_X0);
    // Explicitly set X0 to ensure the return value is used
    qemu::write_reg(hook_cpu, qemu::REG_X0, retval_final);
    ret.tag = LIBAFL_SYSHOOK_SKIP;
    ret.syshook_skip_retval = retval_final;
    return ret;
}

// =============================================================================
// HleManager Implementation
// =============================================================================

HleManager::HleManager(Emulator &emu, MemoryManager &memory)
    : emu_(emu), memory_(memory), next_stub_addr_(HLE_BASE) {}

void HleManager::register_defaults() {
    // Set up thread exit trampoline at HLE_BASE + 0xFFFF0
    uint64_t thread_exit_addr = HLE_BASE + 0xFFFF0;
    address_to_name_[thread_exit_addr] = "__thread_exit";
    callbacks_["__thread_exit"] = [](Emulator &emu) {
        CPUState* cpu = get_current_cpu(emu);
        uint64_t retval = qemu::read_reg(cpu, qemu::REG_X0);
        EMU_LOG << "[HLE] Thread exit trampoline called, retval=" << retval
                  << std::endl;
        emu.threads().pthread_exit(retval);
    };

    // Write infinite loop instruction (B .) at thread exit address
    uint32_t loop_insn = 0x14000000;  // B . (branch to self)
    memory_.write(thread_exit_addr, &loop_insn, sizeof(loop_insn));

    // RET instruction for other trampolines
    uint32_t ret_insn = 0xD65F03C0;

    // Set up pthread_cond_wait resume trampoline
    uint64_t cond_wait_resume_addr = HLE_BASE + 0xFFFF4;
    address_to_name_[cond_wait_resume_addr] = "__pthread_cond_wait_resume";
    callbacks_["__pthread_cond_wait_resume"] = [](Emulator &emu) {
        emu.threads().pthread_cond_wait_resume();
    };
    memory_.write(cond_wait_resume_addr, &ret_insn, sizeof(ret_insn));

    // Set up pthread_join resume trampoline
    uint64_t join_resume_addr = HLE_BASE + 0xFFFF8;
    address_to_name_[join_resume_addr] = "__pthread_join_resume";
    callbacks_["__pthread_join_resume"] = [](Emulator &emu) {
        emu.threads().pthread_join_resume();
    };
    memory_.write(join_resume_addr, &ret_insn, sizeof(ret_insn));

    // Set up pthread_mutex_lock resume trampoline
    uint64_t mutex_resume_addr = HLE_BASE + 0xFFFEC;
    address_to_name_[mutex_resume_addr] = "__pthread_mutex_lock_resume";
    callbacks_["__pthread_mutex_lock_resume"] = [](Emulator &emu) {
        emu.threads().pthread_mutex_lock_resume();
    };
    memory_.write(mutex_resume_addr, &ret_insn, sizeof(ret_insn));

    // Set up blocking recv resume trampoline
    uint64_t recv_resume_addr = HLE_BASE + 0xFFFE0;
    address_to_name_[recv_resume_addr] = "__blocking_recv_resume";
    callbacks_["__blocking_recv_resume"] = [](Emulator &emu) {
        emu.threads().blocking_recv_resume();
    };
    memory_.write(recv_resume_addr, &ret_insn, sizeof(ret_insn));

    // Set up blocking send resume trampoline
    uint64_t send_resume_addr = HLE_BASE + 0xFFFE4;
    address_to_name_[send_resume_addr] = "__blocking_send_resume";
    callbacks_["__blocking_send_resume"] = [](Emulator &emu) {
        emu.threads().blocking_send_resume();
    };
    memory_.write(send_resume_addr, &ret_insn, sizeof(ret_insn));

    // Set up blocking accept resume trampoline
    uint64_t accept_resume_addr = HLE_BASE + 0xFFFE8;
    address_to_name_[accept_resume_addr] = "__blocking_accept_resume";
    callbacks_["__blocking_accept_resume"] = [](Emulator &emu) {
        emu.threads().blocking_accept_resume();
    };
    memory_.write(accept_resume_addr, &ret_insn, sizeof(ret_insn));

    // Set up blocking read resume trampoline
    uint64_t read_resume_addr = HLE_BASE + 0xFFFC0;
    address_to_name_[read_resume_addr] = "__blocking_read_resume";
    callbacks_["__blocking_read_resume"] = [](Emulator &emu) {
        emu.threads().blocking_read_resume();
    };
    memory_.write(read_resume_addr, &ret_insn, sizeof(ret_insn));

    // Set up blocking write resume trampoline
    uint64_t write_resume_addr = HLE_BASE + 0xFFFC4;
    address_to_name_[write_resume_addr] = "__blocking_write_resume";
    callbacks_["__blocking_write_resume"] = [](Emulator &emu) {
        emu.threads().blocking_write_resume();
    };
    memory_.write(write_resume_addr, &ret_insn, sizeof(ret_insn));

    // Set up blocking epoll_wait resume trampoline
    uint64_t epoll_wait_resume_addr = HLE_BASE + 0xFFFC8;
    address_to_name_[epoll_wait_resume_addr] = "__blocking_epoll_wait_resume";
    callbacks_["__blocking_epoll_wait_resume"] = [](Emulator &emu) {
        emu.threads().blocking_epoll_wait_resume();
    };
    memory_.write(epoll_wait_resume_addr, &ret_insn, sizeof(ret_insn));

    // Set up blocking recvfrom resume trampoline
    uint64_t recvfrom_resume_addr = HLE_BASE + 0xFFFCC;
    address_to_name_[recvfrom_resume_addr] = "__blocking_recvfrom_resume";
    callbacks_["__blocking_recvfrom_resume"] = [](Emulator &emu) {
        emu.threads().blocking_recvfrom_resume();
    };
    memory_.write(recvfrom_resume_addr, &ret_insn, sizeof(ret_insn));

    // Set up blocking sendto resume trampoline
    uint64_t sendto_resume_addr = HLE_BASE + 0xFFFD0;
    address_to_name_[sendto_resume_addr] = "__blocking_sendto_resume";
    callbacks_["__blocking_sendto_resume"] = [](Emulator &emu) {
        emu.threads().blocking_sendto_resume();
    };
    memory_.write(sendto_resume_addr, &ret_insn, sizeof(ret_insn));

    // Set up pthread_barrier_wait resume trampoline
    uint64_t barrier_resume_addr = HLE_BASE + 0xFFFDC;
    address_to_name_[barrier_resume_addr] = "__pthread_barrier_wait_resume";
    callbacks_["__pthread_barrier_wait_resume"] = [](Emulator &emu) {
        emu.threads().pthread_barrier_wait_resume();
    };
    memory_.write(barrier_resume_addr, &ret_insn, sizeof(ret_insn));

    // Set up pthread_rwlock_rdlock resume trampoline
    uint64_t rwlock_rdlock_resume_addr = HLE_BASE + 0xFFFD8;
    address_to_name_[rwlock_rdlock_resume_addr] = "__pthread_rwlock_rdlock_resume";
    callbacks_["__pthread_rwlock_rdlock_resume"] = [](Emulator &emu) {
        emu.threads().pthread_rwlock_rdlock_resume();
    };
    memory_.write(rwlock_rdlock_resume_addr, &ret_insn, sizeof(ret_insn));

    // Set up pthread_rwlock_wrlock resume trampoline
    uint64_t rwlock_wrlock_resume_addr = HLE_BASE + 0xFFFD4;
    address_to_name_[rwlock_wrlock_resume_addr] = "__pthread_rwlock_wrlock_resume";
    callbacks_["__pthread_rwlock_wrlock_resume"] = [](Emulator &emu) {
        emu.threads().pthread_rwlock_wrlock_resume();
    };
    memory_.write(rwlock_wrlock_resume_addr, &ret_insn, sizeof(ret_insn));

    // Legacy HLE registrations
    register_libc_hle(*this);
    register_libm_hle(*this);
    register_libdl_hle(*this);
    register_pthread_hle(*this);

    // New modular HLE registrations
    register_hle_memory(*this);
    register_hle_string(*this);
    register_hle_mem_ops(*this);
    register_hle_io(*this);
    register_hle_file(*this);
    register_hle_time(*this);
    register_hle_network(*this);
    register_hle_pthread(*this);
    register_hle_misc(*this);
    register_hle_math(*this);
    register_hle_process(*this);
    register_hle_dir(*this);
    register_hle_syslog(*this);
    register_hle_user(*this);
    register_hle_crypto(*this);

    // Split from hle_misc.cpp
    register_hle_stdlib(*this);
    register_hle_wchar(*this);
    register_hle_locale(*this);
    register_hle_ctype(*this);
    register_hle_signal(*this);
    register_hle_search(*this);
    register_hle_sched(*this);
    register_hle_setjmp(*this);
    register_hle_sysconf(*this);

    // Allocate all HLE stubs eagerly before guest worker threads start.
    // The old lazy path could mutate stub lookup tables while other threads
    // were already resolving HLE syscalls inside pre_syscall_hook.
    for (const auto& pair : callbacks_) {
        (void)get_stub_address(pair.first);
    }
}

void HleManager::register_function(const std::string &name, HleCallback callback) {
    callbacks_[name] = callback;
}

void HleManager::register_function_at_address(uint64_t address, const std::string &name,
                                               HleCallback callback) {
    callbacks_[name] = callback;
    address_to_name_[address] = name;

    // Don't write inline code - it can corrupt adjacent functions.
    // HLE works via PLT/GOT resolution to stubs in the HLE region.
    // Just register the address mapping for debugging purposes.
    EMU_LOG << "[HLE] Registered " << name << " at address 0x" << std::hex
              << address << std::dec << " (PLT/GOT only, no inline code)" << std::endl;
}

void HleManager::register_address_for_function(uint64_t address, const std::string &name) {
    if (callbacks_.find(name) == callbacks_.end()) {
        EMU_ALWAYS_LOG << "[HLE] WARNING: No callback registered for " << name << std::endl;
        return;
    }

    address_to_name_[address] = name;

    // Don't write inline code - it can corrupt adjacent functions.
    // HLE works via PLT/GOT resolution to stubs in the HLE region.
}

uint64_t HleManager::get_stub_address(const std::string &name) {
    // Check if stub already exists
    auto it = stub_addresses_.find(name);
    if (it != stub_addresses_.end()) {
        return it->second;
    }

    // Only allocate stubs for functions that have HLE callbacks registered
    // Otherwise return 0 to let the resolver use the actual library function
    if (!has_hle(name)) {
        // Debug: log when FP functions are not found
        if (name == "strtod" || name == "strtof" || name == "difftime") {
            EMU_ALWAYS_LOG << "[HLE] WARNING: No HLE callback for '" << name << "'" << std::endl;
        }
        return 0;
    }

    // Allocate new stub for this HLE function
    uint64_t addr = allocate_stub(name);
    EMU_LOG << "[HLE] Allocated stub for '" << name << "' at 0x" << std::hex << addr << std::dec << std::endl;
    return addr;
}

bool HleManager::has_hle(const std::string &name) const {
    return callbacks_.find(name) != callbacks_.end();
}

bool HleManager::handle(uint64_t address) {
    auto it = address_to_name_.find(address);
    if (it == address_to_name_.end()) {
        return false;
    }

    auto cb_it = callbacks_.find(it->second);
    if (cb_it == callbacks_.end()) {
        // We have a name but no callback - this is a stub that was allocated
        // but the implementation wasn't provided
        EMU_ALWAYS_LOG << "[HLE] WARNING: No callback for '" << it->second
                  << "' at 0x" << std::hex << address << std::dec << std::endl;
        return false;
    }

    // Log which HLE function is being called (verbose logging)
    EMU_LOG_VERBOSE << "[HLE] Calling: " << it->second << " at 0x" << std::hex << address << std::dec << std::endl;

    // CRITICAL: Set tls_cpu so HLE callbacks can access the correct CPU
    // Without this, child threads would fall back to CPU 0 causing race conditions
    CPUState* old_tls = tls_cpu;
    CPUState* current_cpu = libafl_qemu_current_cpu();
    if (current_cpu != nullptr) {
        tls_cpu = current_cpu;
    } else if (tls_cpu == nullptr) {
        // Fallback to stored CPU if nothing else is available
        tls_cpu = emu_.get_cpu();
    }

    cb_it->second(emu_);

    tls_cpu = old_tls;
    return true;
}

#if EMU_LOGGING_ENABLED
// HLE call counter - no per-call locking overhead
static std::atomic<uint64_t> g_hle_total_calls{0};
#endif

bool HleManager::handle_with_cpu(void *cpu_ptr, uint64_t address) {
    auto it = address_to_name_.find(address);
    if (it == address_to_name_.end()) {
        return false;
    }

    auto cb_it = callbacks_.find(it->second);
    if (cb_it == callbacks_.end()) {
        EMU_ALWAYS_LOG << "[HLE] WARNING: No callback for '" << it->second
                  << "' at 0x" << std::hex << address << std::dec << std::endl;
        return false;
    }

    // CRITICAL FIX: Use the provided CPU pointer directly without calling
    // libafl_qemu_current_cpu() which may race in MTTCG mode
    CPUState* old_tls = tls_cpu;
    tls_cpu = static_cast<CPUState*>(cpu_ptr);

    cb_it->second(emu_);

    tls_cpu = old_tls;

#if EMU_LOGGING_ENABLED
    if (emu::is_profile_logging_enabled()) {
        uint64_t total_calls = ++g_hle_total_calls;
        if (total_calls % 50000 == 0) {
            EMU_PROFILE_LOG << "[HLE-STATS] Total HLE calls: " << total_calls << std::endl;
        }
    }
#endif

    return true;
}

bool HleManager::handle_for_engine(void *cpu_ptr, uint64_t address) {
    auto it = address_to_name_.find(address);
    if (it == address_to_name_.end()) {
        return false;
    }

    auto cb_it = callbacks_.find(it->second);
    if (cb_it == callbacks_.end()) {
        return false;
    }

    // Use thread-local storage to track the CPU for this thread
    CPUState* old_tls = tls_cpu;
    tls_cpu = static_cast<CPUState*>(cpu_ptr);

    cb_it->second(emu_);

    tls_cpu = old_tls;
    return true;
}

std::vector<std::string> HleManager::get_registered_functions() const {
    std::vector<std::string> names;
    for (const auto &pair : callbacks_) {
        names.push_back(pair.first);
    }
    return names;
}

uint64_t HleManager::allocate_stub(const std::string &name) {
    // NOTE: usleep was previously routed through a native guest-side nanosleep wrapper
    // because the HLE sleep handler parked the vCPU inside the syscall hook (holding the
    // exec/exclusive state) and stalled thread creation. The HLE sleep path now steps out
    // of that state while blocking (Emulator::cpu_exec_suspend/resume), so usleep can use
    // the normal HLE stub again — which makes it timer-aware (delivers POSIX timer signals
    // that expire during the sleep) instead of an opaque native block.

    uint64_t addr = next_stub_addr_;
    stub_addresses_[name] = addr;

    // Each generic stub is 12 bytes: MOV X8, #N; SVC #0; RET
    next_stub_addr_ += 12;
    address_to_name_[addr] = name;

    // Allocate a syscall number for this HLE function.
    int syscall_num = g_next_hle_syscall.fetch_add(1, std::memory_order_relaxed);
    if (syscall_num >= HLE_SYSCALL_BASE + HLE_SYSCALL_CAPACITY) {
        EMU_ALWAYS_LOG << "[HLE_ALLOC] ERROR: Exhausted HLE syscall slots while allocating '"
                       << name << "'" << std::endl;
        stub_addresses_.erase(name);
        address_to_name_.erase(addr);
        return 0;
    }

    // Log stub allocation for debugging
    // EMU_LOG << "[HLE_ALLOC] " << name << " at 0x" << std::hex << addr
    //           << " syscall=0x" << syscall_num << std::dec << std::endl;

    write_stub(addr, syscall_num);
    g_hle_syscall_to_addr[syscall_num - HLE_SYSCALL_BASE].store(addr, std::memory_order_release);
    return addr;
}

void HleManager::write_stub(uint64_t address, int syscall_num) {
    // Write syscall-based stub:
    //   MOV X8, #syscall_num  (MOVZ X8, #imm16)
    //   SVC #0
    //   RET
    //
    // MOVZ Xd, #imm16 encoding: 0xD2800000 | (imm16 << 5) | Rd
    // For X8 (Rd=8): 0xD2800008 | (imm16 << 5)
    // SVC #0 encoding: 0xD4000001
    // RET encoding: 0xD65F03C0

    uint32_t mov_insn = 0xD2800008 | ((syscall_num & 0xFFFF) << 5);
    uint32_t svc_insn = 0xD4000001;
    uint32_t ret_insn = 0xD65F03C0;

    uint32_t code[3] = { mov_insn, svc_insn, ret_insn };
    bool wrote = memory_.write(address, code, sizeof(code));

    // Debug: verify the stub was written
    EMU_LOG << "[HLE_STUB] Writing stub at 0x" << std::hex << address
              << " syscall=0x" << syscall_num
              << " MOV=0x" << mov_insn
              << " write_success=" << wrote << std::dec << std::endl;
}

// =============================================================================
// Android bionic _ctype_ table
// =============================================================================

static const unsigned char bionic_ctype_table[257] = {
    0,     // EOF (-1)
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,  // 0x00-0x07
    0x20, 0x28, 0x28, 0x28, 0x28, 0x28, 0x20, 0x20,  // 0x08-0x0F
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,  // 0x10-0x17
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,  // 0x18-0x1F
    0x88, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,  // 0x20-0x27
    0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,  // 0x28-0x2F
    0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,  // 0x30-0x37
    0x44, 0x44, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,  // 0x38-0x3F
    0x10, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x01,  // 0x40-0x47
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,  // 0x48-0x4F
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,  // 0x50-0x57
    0x01, 0x01, 0x01, 0x10, 0x10, 0x10, 0x10, 0x10,  // 0x58-0x5F
    0x10, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x02,  // 0x60-0x67
    0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,  // 0x68-0x6F
    0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,  // 0x70-0x77
    0x02, 0x02, 0x02, 0x10, 0x10, 0x10, 0x10, 0x20,  // 0x78-0x7F
    // 0x80-0xFF: all zeros (non-ASCII)
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

// =============================================================================
// Emulator Implementation
// =============================================================================

Emulator::Emulator() : Emulator(EmulatorConfig{}) {}

Emulator::Emulator(const EmulatorConfig &config)
    : cpu_(nullptr), config_(config), next_hle_addr_(HLE_BASE),
      next_load_addr_(CODE_BASE),
      debug_enabled_(config.enable_debug),
      profile_enabled_(config.enable_profile) {
    // Allow enabling profiling via env even when the embedding wrapper constructs the
    // Emulator with a default config. EMU_PROFILE=1 -> periodic
    // [EMU_PROFILE] per-call latency breakdown (alloc/queue/sched/exec/signal/TOTAL).
    if (const char* p = std::getenv("EMU_PROFILE")) {
        if (std::atoi(p) != 0) profile_enabled_ = true;
    }

    // Reserve module storage so push_back() (including runtime dlopen) never reallocates
    // and moves elements. Concurrent readers of modules() (thread setup, auxv) keep stable
    // references even while a dlopen on another vCPU appends a module.
    modules_.reserve(256);

    // Parallel vCPU worker pool size (extra worker threads/vCPUs beyond the main thread).
    // ON by default so C->guest calls run in parallel across cores.
    // Override with CROSSSHIM_VCPU_WORKERS (0 = legacy single-worker behavior).
    vcpu_worker_count_ = 8;
    if (const char* w = std::getenv("CROSSSHIM_VCPU_WORKERS")) {
        int v = std::atoi(w);
        vcpu_worker_count_ = (v < 0) ? 0 : v;
    }

    // One mailbox per worker slot: index 0 = main emulator thread, 1..N = pool workers.
    // Created before initialize() (which starts the emulator thread) so worker 0 has its
    // mailbox ready immediately.
    worker_mailboxes_.clear();
    for (int i = 0; i <= vcpu_worker_count_; ++i) {
        worker_mailboxes_.push_back(std::make_unique<WorkerMailbox>());
    }

    emu::set_debug_logging_enabled(debug_enabled_);
    emu::set_profile_logging_enabled(profile_enabled_);
    initialize();
}

Emulator::~Emulator() {
    // Stop emulator background thread
    stop_emulator_thread();

    // Destroy thread manager first
    threads_.reset();

    // Note: QEMU cleanup is handled by the library
}

void Emulator::set_debug(bool enabled) {
    debug_enabled_ = enabled;
    emu::set_debug_logging_enabled(enabled);
}

void Emulator::set_profile(bool enabled) {
    profile_enabled_ = enabled;
    emu::set_profile_logging_enabled(enabled);
}

void Emulator::initialize() {
    // Set global emulator pointer for callbacks
    g_emulator = this;

    // Create memory manager (doesn't depend on QEMU yet)
    memory_ = std::make_unique<MemoryManager>(nullptr);

    // Allocate memory regions in host memory first
    // These will be synced to QEMU's guest space after init
    memory_->map(0, HLE_BASE, MEM_READ | MEM_WRITE | MEM_EXEC, "LowMemory");
    memory_->map(HLE_BASE, HLE_SIZE, MEM_READ | MEM_WRITE | MEM_EXEC, "HLE");
    memory_->map(STACK_BASE - config_.stack_size, config_.stack_size,
                 MEM_READ | MEM_WRITE, "Stack");
    memory_->map(SAFE_CALL_STACK_BASE, SAFE_CALL_STACK_SIZE, MEM_READ | MEM_WRITE, "SafeCallStack");
    memory_->map(HEAP_BASE, config_.heap_size, MEM_READ | MEM_WRITE, "Heap");
    memory_->map(GLOBAL_DATA_BASE, GLOBAL_DATA_SIZE, MEM_READ | MEM_WRITE, "GlobalData");
    memory_->map(TLS_BASE - TLS_PRE_SIZE, TLS_SIZE + TLS_PRE_SIZE,
                 MEM_READ | MEM_WRITE, "TLS");

    // Create subsystems
    loader_ = std::make_unique<ElfLoader>();
    relocator_ = std::make_unique<RelocationHandler>(*memory_);
    syscall_ = std::make_unique<SyscallHandler>(*this, *memory_);
    hle_ = std::make_unique<HleManager>(*this, *memory_);
    tls_ = std::make_unique<TlsManager>(*this, *memory_);
    threads_ = std::make_unique<ThreadManager>(*this, *memory_);

    // Configure threading
    threads_->set_threading_enabled(config_.enable_threading);

    // Initialize TLS (writes to host memory)
    tls_->initialize();

    // Register default HLE functions (writes trampolines to host memory)
    hle_->register_defaults();

    // Write a RET instruction at address 0 for null function pointer handling
    uint32_t ret_insn = 0xD65F03C0;
    if (!memory_->write(0, &ret_insn, sizeof(ret_insn))) {
        EMU_ALWAYS_LOG << "[EMU] WARNING: Failed to write RET at address 0" << std::endl;
    } else {
        EMU_LOG << "[EMU] Installed RET at address 0 for null function pointer handling"
                  << std::endl;
    }

    // Write MSR instruction at HLE address for TLS initialization
    // msr tpidr_el0, x0 = 0xD51BD040
    // ret              = 0xD65F03C0
    uint64_t tls_init_addr = HLE_BASE + 0x10;  // Just after HLE_BASE
    uint32_t msr_tpidr_insn = 0xD51BD040;  // msr tpidr_el0, x0
    EMU_LOG << "[EMU] Writing TLS init code at 0x" << std::hex << tls_init_addr << std::dec << std::endl;
    if (!memory_->write(tls_init_addr, &msr_tpidr_insn, sizeof(msr_tpidr_insn))) {
        EMU_ALWAYS_LOG << "[EMU] WARNING: Failed to write MSR TPIDR_EL0 instruction" << std::endl;
    }
    if (!memory_->write(tls_init_addr + 4, &ret_insn, sizeof(ret_insn))) {
        EMU_ALWAYS_LOG << "[EMU] WARNING: Failed to write RET after MSR" << std::endl;
    }
    tls_init_addr_ = tls_init_addr;

    // Guest-side trampoline used for nested safe calls. The trampoline loads
    // X0-X7 and the target address from guest memory so callback dispatch does
    // not depend on host-side register writes while inside syscall hooks.
    static const uint32_t safe_call_trampoline[] = {
        0x910003E9,  // mov x9, sp
        0xF9400130,  // ldr x16, [x9]
        0xA9408520,  // ldp x0, x1, [x9, #0x8]
        0xA9418D22,  // ldp x2, x3, [x9, #0x18]
        0xA9429524,  // ldp x4, x5, [x9, #0x28]
        0xA9439D26,  // ldp x6, x7, [x9, #0x38]
        0x9101413F,  // add sp, x9, #0x50
        0xD61F0200,  // br x16
    };
    if (!memory_->write(SAFE_CALL_TRAMPOLINE_ADDR, safe_call_trampoline,
                        sizeof(safe_call_trampoline))) {
        EMU_ALWAYS_LOG << "[EMU] WARNING: Failed to write safe-call trampoline at 0x"
                << std::hex << SAFE_CALL_TRAMPOLINE_ADDR << std::dec << std::endl;
    }

    // Guest-side return trampoline for C->guest calls. call_function() sets LR to
    // this address; when the called function returns, the SVC triggers a per-thread
    // cpu_loop exit via the syscall hook (SYS_CALL_RETURN). This replaces the old
    // global-breakpoint return-trap, which raced across the parallel vCPU worker pool.
    // A single shared stub serves all workers and all nesting depths: the trap is
    // thread-local, so there is no address collision to avoid.
    static const uint32_t call_return_trampoline[] = {
        0xD2824708,  // mov x8, #0x1238   (SYS_CALL_RETURN)
        0xD4000001,  // svc #0
        0xD65F03C0,  // ret               (safety net; hook forces exit at the svc)
    };
    if (!memory_->write(CALL_RETURN_STUB_ADDR, call_return_trampoline,
                        sizeof(call_return_trampoline))) {
        EMU_ALWAYS_LOG << "[EMU] WARNING: Failed to write call-return trampoline at 0x"
                << std::hex << CALL_RETURN_STUB_ADDR << std::dec << std::endl;
    }

    // Initialize global data (writes ctype table, etc. to host memory)
    initialize_global_data();

    // IMPORTANT: Start the emulator background thread FIRST
    // QEMU must be initialized on the same thread that will call libafl_qemu_run()
    // So we defer QEMU initialization to the background thread
    start_emulator_thread();

    // Wait for QEMU to be initialized by the background thread
    EMU_LOG << "[EMU] Waiting for QEMU initialization on background thread..." << std::endl;
    {
        std::unique_lock<std::mutex> lock(qemu_init_mutex_);
        qemu_init_cv_.wait(lock, [this] { return qemu_initialized_; });
    }

    // Install crash handler for debugging SIGSEGV during JIT execution
    install_crash_handler();

    EMU_LOG << "[EMU] Emulator initialized with QEMU backend" << std::endl;
}

// Initialize QEMU on the current thread
// This must be called from the emulator background thread because
// libafl_qemu_run() must be called from the same thread that called libafl_qemu_init()
void Emulator::initialize_qemu_on_this_thread() {
    EMU_LOG << "[EMU] Initializing QEMU on this thread..." << std::endl;

    // Find and load QEMU stub binary
    const char* stub_path = find_qemu_stub();
    if (!stub_path) {
        EMU_ALWAYS_LOG << "[EMU] ERROR: Cannot find QEMU stub binary" << std::endl;
        EMU_ALWAYS_LOG << "[EMU] Please run: CrossShim/stubs/build_stub.sh" << std::endl;
        throw std::runtime_error("QEMU stub not found");
    }

    EMU_LOG << "[EMU] Initializing QEMU with stub: " << stub_path << std::endl;
    const char* argv[] = {"qemu-aarch64", stub_path, nullptr};
    libafl_qemu_init(2, const_cast<char**>(argv));

    // Get CPU
    cpu_ = libafl_qemu_get_cpu(0);
    if (!cpu_) {
        EMU_ALWAYS_LOG << "[EMU] ERROR: No CPU after QEMU init" << std::endl;
        throw std::runtime_error("QEMU CPU not available");
    }
    EMU_LOG << "[EMU] Got CPU from QEMU" << std::endl;

    // Note: User mode QEMU automatically uses real host threads via clone()
    // No MTTCG flag needed - it's a system mode feature

    // Get guest_base
    uint64_t load_addr = libafl_load_addr();
    uint64_t guest_base = 0;
    EMU_LOG << "[EMU] QEMU load_addr=0x" << std::hex << load_addr << std::dec << std::endl;

    // Sync memory regions to QEMU guest space
    memory_->set_qemu_ready(guest_base);

    // Initialize TPIDR_EL0 by executing MSR instruction
    EMU_LOG << "[EMU] Checking TLS init: tls_init_addr_=0x" << std::hex << tls_init_addr_ << std::dec << std::endl;
    if (tls_init_addr_ != 0) {
        uint64_t tpidr_value = TLS_BASE + 8;
        EMU_LOG << "[EMU] Setting TPIDR_EL0 to 0x" << std::hex << tpidr_value << std::dec << std::endl;

        uint64_t saved_x0 = qemu::read_reg(cpu_, qemu::REG_X0);
        qemu::write_reg(cpu_, qemu::REG_X0, tpidr_value);

        uint64_t saved_pc = qemu::read_reg(cpu_, qemu::REG_PC);
        uint64_t saved_lr = qemu::read_reg(cpu_, qemu::REG_LR);
        qemu::write_reg(cpu_, qemu::REG_PC, tls_init_addr_);
        qemu::write_reg(cpu_, qemu::REG_LR, tls_init_addr_ + 4);

        uint64_t break_addr = tls_init_addr_ + 8;
        qemu::write_reg(cpu_, qemu::REG_LR, break_addr);
        libafl_qemu_set_breakpoint(break_addr);

        EMU_LOG << "[EMU] Running MSR instruction at 0x" << std::hex << tls_init_addr_ << std::dec << std::endl;
        int run_result = libafl_qemu_run();
        EMU_LOG << "[EMU] libafl_qemu_run() returned " << run_result << std::endl;

        libafl_qemu_remove_breakpoint(break_addr);
        qemu::write_reg(cpu_, qemu::REG_X0, saved_x0);
        qemu::write_reg(cpu_, qemu::REG_PC, saved_pc);
        qemu::write_reg(cpu_, qemu::REG_LR, saved_lr);

        EMU_LOG << "[EMU] Initialized TPIDR_EL0" << std::endl;
    }

    // Set up syscall hooks
    setup_hooks();

    // Mark QEMU as initialized
    {
        std::lock_guard<std::mutex> lock(qemu_init_mutex_);
        qemu_initialized_ = true;
    }
    qemu_init_cv_.notify_all();

    // NOTE: Signal handler wrapping is DISABLED.
    // It interferes with QEMU's signal handling.
    // The QEMU patches (pthread_key approach) handle .NET thread safety.
    // wrap_qemu_signal_handlers();

    EMU_LOG << "[EMU] QEMU initialization complete on this thread" << std::endl;
}

void Emulator::initialize_global_data() {
    uint64_t ctype_ptr_addr = GLOBAL_DATA_BASE;
    uint64_t stack_chk_guard_addr = GLOBAL_DATA_BASE + 8;
    uint64_t ctype_table_addr = GLOBAL_DATA_BASE + 16;

    // Write the ctype table
    mem_write(ctype_table_addr, bionic_ctype_table, sizeof(bionic_ctype_table));

    // Write the pointer to the table
    uint64_t ctype_ptr_value = ctype_table_addr;
    mem_write(ctype_ptr_addr, &ctype_ptr_value, sizeof(ctype_ptr_value));

    // Register _ctype_ as a global symbol
    global_symbols_["_ctype_"] = ctype_ptr_addr;

    // Initialize __stack_chk_guard
    uint64_t stack_canary = 0xDEADBEEFCAFEBABEULL;
    mem_write(stack_chk_guard_addr, &stack_canary, sizeof(stack_canary));

    global_symbols_["__stack_chk_guard"] = stack_chk_guard_addr;

    // Initialize __sF (Android bionic's stdio FILE array: stdin, stdout, stderr)
    // Each FILE structure in bionic is approximately 152 bytes (0x98)
    // We allocate space for 3 FILE structures and initialize them minimally
    uint64_t sf_addr = GLOBAL_DATA_BASE + 0x200;  // After ctype table
    constexpr size_t FILE_SIZE = 0x98;  // bionic FILE structure size
    constexpr size_t NUM_FILES = 3;     // stdin, stdout, stderr

    // Zero-initialize the FILE structures
    uint8_t zeros[FILE_SIZE * NUM_FILES] = {0};
    mem_write(sf_addr, zeros, sizeof(zeros));

    // Set minimal valid FILE fields for each stream
    // Offset 0x00: _flags (int) - set to indicate valid file
    // Offset 0x70: _fileno (short) - file descriptor
    for (int i = 0; i < 3; i++) {
        uint64_t file_addr = sf_addr + i * FILE_SIZE;
        int32_t flags = 0x0001;  // _IO_MAGIC_BUF (indicates valid file)
        mem_write(file_addr, &flags, sizeof(flags));
        int16_t fileno = i;  // 0=stdin, 1=stdout, 2=stderr
        mem_write(file_addr + 0x70, &fileno, sizeof(fileno));
    }

    global_symbols_["__sF"] = sf_addr;  // legacy `FILE __sF[]` array (the &__sF[i] macro path)

    // bionic (API >= 23) declares stdin/stdout/stderr as `FILE*` POINTER VARIABLES,
    // not the FILE structs themselves. Reading e.g. `stdout` is a double indirection:
    // the GOT holds the address of the pointer variable, and the program derefs once
    // to obtain the FILE*. So these symbols must resolve to pointer slots holding the
    // FILE-struct addresses; pointing them straight at the structs makes the program
    // read the struct's first word (_flags) as the FILE* (yielding a bogus value of 1,
    // which breaks fileno()/fprintf on these streams). Allocate 3 pointer slots right
    // after the FILE structs.
    uint64_t std_ptrs_addr = sf_addr + NUM_FILES * FILE_SIZE;
    for (int i = 0; i < 3; i++) {
        uint64_t file_struct_addr = sf_addr + i * FILE_SIZE;
        mem_write(std_ptrs_addr + i * 8, &file_struct_addr, 8);
    }
    global_symbols_["stdin"]  = std_ptrs_addr;          // &(FILE* stdin)  -> &__sF[0]
    global_symbols_["stdout"] = std_ptrs_addr + 8;      // &(FILE* stdout) -> &__sF[1]
    global_symbols_["stderr"] = std_ptrs_addr + 16;     // &(FILE* stderr) -> &__sF[2]

    // Initialize sys_signame and sys_siglist arrays
    // These are arrays of pointers to signal name/description strings
    // On bionic, there are 64 signals (32 standard + 32 realtime)
    constexpr size_t NUM_SIGNALS = 65;  // 0-64, with 0 unused
    constexpr size_t PTR_SIZE = 8;      // 64-bit pointers

    // Allocate space for the arrays after __sF
    uint64_t signame_array_addr = sf_addr + FILE_SIZE * NUM_FILES + 0x100;
    uint64_t siglist_array_addr = signame_array_addr + NUM_SIGNALS * PTR_SIZE;
    uint64_t sigstrings_addr = siglist_array_addr + NUM_SIGNALS * PTR_SIZE;

    // Signal names and descriptions
    static const char* signames[] = {
        "", "HUP", "INT", "QUIT", "ILL", "TRAP", "ABRT", "BUS", "FPE", "KILL",
        "USR1", "SEGV", "USR2", "PIPE", "ALRM", "TERM", "STKFLT", "CHLD",
        "CONT", "STOP", "TSTP", "TTIN", "TTOU", "URG", "XCPU", "XFSZ",
        "VTALRM", "PROF", "WINCH", "IO", "PWR", "SYS"
    };

    static const char* sigdescs[] = {
        "Unknown signal 0", "Hangup", "Interrupt", "Quit", "Illegal instruction",
        "Trace/breakpoint trap", "Aborted", "Bus error", "Floating point exception",
        "Killed", "User defined signal 1", "Segmentation fault", "User defined signal 2",
        "Broken pipe", "Alarm clock", "Terminated", "Stack fault", "Child exited",
        "Continued", "Stopped (signal)", "Stopped", "Stopped (tty input)",
        "Stopped (tty output)", "Urgent I/O condition", "CPU time limit exceeded",
        "File size limit exceeded", "Virtual timer expired", "Profiling timer expired",
        "Window changed", "I/O possible", "Power failure", "Bad system call"
    };

    uint64_t string_offset = 0;
    for (size_t i = 0; i < NUM_SIGNALS; i++) {
        const char* name = (i < 32) ? signames[i] : "";
        const char* desc = (i < 32) ? sigdescs[i] : "Unknown signal";

        if (i == 0) {
            uint64_t null_ptr = 0;
            mem_write(signame_array_addr + i * PTR_SIZE, &null_ptr, PTR_SIZE);
            mem_write(siglist_array_addr + i * PTR_SIZE, &null_ptr, PTR_SIZE);
            continue;
        }

        // Write name string
        uint64_t name_addr = sigstrings_addr + string_offset;
        mem_write(name_addr, name, strlen(name) + 1);
        string_offset += strlen(name) + 1;

        // Write description string
        uint64_t desc_addr = sigstrings_addr + string_offset;
        mem_write(desc_addr, desc, strlen(desc) + 1);
        string_offset += strlen(desc) + 1;

        // Write pointers to arrays
        mem_write(signame_array_addr + i * PTR_SIZE, &name_addr, PTR_SIZE);
        mem_write(siglist_array_addr + i * PTR_SIZE, &desc_addr, PTR_SIZE);
    }

    global_symbols_["sys_signame"] = signame_array_addr;
    global_symbols_["sys_siglist"] = siglist_array_addr;

    // Initialize in6addr_loopback and in6addr_any (struct in6_addr = 16 bytes)
    // in6addr_loopback = ::1
    // in6addr_any = ::
    uint64_t in6addr_base = siglist_array_addr + NUM_SIGNALS * PTR_SIZE + 0x200;
    uint8_t loopback_addr[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1}; // ::1
    uint8_t any_addr[16] = {0}; // ::
    mem_write(in6addr_base, loopback_addr, 16);
    mem_write(in6addr_base + 16, any_addr, 16);
    global_symbols_["in6addr_loopback"] = in6addr_base;
    global_symbols_["in6addr_any"] = in6addr_base + 16;

    // environ: the `char **environ` data symbol. Programs (and allocators such as
    // mimalloc) read environ[i] directly, so it MUST be real data, not a function
    // stub. The symbol value is the array address; a single GOT load yields the
    // char** value, matching the stdin/stdout/stderr convention above. Start empty
    // (a lone NULL terminator).
    uint64_t environ_array_addr = in6addr_base + 0x40;
    uint64_t environ_null = 0;
    mem_write(environ_array_addr, &environ_null, PTR_SIZE);  // environ[0] = NULL
    global_symbols_["environ"] = environ_array_addr;
    global_symbols_["__environ"] = environ_array_addr;
    global_symbols_["_environ"] = environ_array_addr;
}

void Emulator::setup_hooks() {
    // Configure QEMU to return on crashes/traps instead of exiting
    // This allows us to handle BRK instructions (HLE traps) gracefully
    libafl_set_return_on_crash(true);

    // Add syscall hook
    syscall_hook_id_ = libafl_add_pre_syscall_hook(pre_syscall_hook,
                                                    reinterpret_cast<uint64_t>(this));

    EMU_LOG << "[EMU] Registered syscall hook (id=" << syscall_hook_id_ << ")" << std::endl;
}

void Emulator::add_mem_write_hook() {
    // Memory write hooks for debugging - not implemented for QEMU yet
    if (debug_enabled_) {
        EMU_LOG << "[EMU] Memory write hooks not yet implemented for QEMU backend"
                  << std::endl;
    }
}

void Emulator::enable_trace(uint64_t start, uint64_t end) {
    EMU_LOG << "[EMU] Tracing enabled for 0x" << std::hex << start << " - 0x"
              << end << std::dec << std::endl;
}

void Emulator::disable_trace() {
    // No-op for now
}

#if EMU_LOGGING_ENABLED
// Profiling for start() - tracks where time is spent in emulation
static std::atomic<uint64_t> g_start_count{0};
static std::atomic<uint64_t> g_total_setup_ns{0};
static std::atomic<uint64_t> g_total_qemu_run_ns{0};
static std::atomic<uint64_t> g_total_loop_iterations{0};
static std::chrono::steady_clock::time_point g_last_start_report = std::chrono::steady_clock::now();
#endif

bool Emulator::start(uint64_t address, uint64_t end_address) {
#if EMU_LOGGING_ENABLED
    const bool profile_logging_enabled = emu::is_profile_logging_enabled();
    std::chrono::steady_clock::time_point start_time{};
    if (profile_logging_enabled) {
        start_time = std::chrono::steady_clock::now();
    }
#endif

    tl_running = true;  // Thread-local: each thread tracks its own execution state

    // IMPORTANT: In MTTCG mode, we must use the CPU for the current thread
    // Try current_cpu first, then fall back to CPU 0
    CPUState* cpu = libafl_qemu_current_cpu();
    if (!cpu) {
        // If no current CPU, this thread might not have one assigned yet
        // Use CPU 0 (the main emulator CPU)
        cpu = libafl_qemu_get_cpu(0);
        EMU_LOG << "[EMU] WARNING: No current CPU, using CPU 0 at " << (void*)cpu << std::endl;
    } else {
        int cpu_idx = libafl_qemu_cpu_index(cpu);
        EMU_LOG_VERBOSE << "[EMU] Using current CPU " << cpu_idx << " at " << (void*)cpu << std::endl;
    }

    if (!cpu) {
        EMU_ALWAYS_LOG << "[EMU] ERROR: No CPU for start()" << std::endl;
        tl_running = false;
        return false;
    }

    // CRITICAL: Set this thread's current_cpu before calling libafl_qemu_run()
    // In MTTCG mode, QEMU requires current_cpu to be set for the executing thread
    libafl_qemu_set_current_cpu(cpu);
    EMU_LOG_VERBOSE << "[EMU] Set current_cpu for this thread to " << (void*)cpu << std::endl;

    // Set PC to the starting address
    qemu::write_reg(cpu, qemu::REG_PC, address);

    // Set up stack pointer if not already set
    uint64_t sp = qemu::read_reg(cpu, qemu::REG_SP);
    bool in_main_stack = sp >= STACK_BASE - config_.stack_size && sp <= STACK_BASE;
    bool in_safe_call_stack =
        sp >= tl_safe_stack_base && sp <= tl_safe_stack_base + SAFE_CALL_STACK_SIZE;
    bool in_mapped_stack = (sp != 0) && memory_ != nullptr && memory_->is_mapped(sp);
    if (sp == 0 || (!in_main_stack && !in_safe_call_stack && !in_mapped_stack)) {
        // Initialize stack pointer to top of stack
        sp = STACK_BASE - 16;  // Leave room at top
        qemu::write_reg(cpu, qemu::REG_SP, sp);
        EMU_LOG << "[EMU] Set SP to 0x" << std::hex << sp << std::dec << std::endl;
    }

    // NOTE: No breakpoint is set at end_address. C->guest calls stop via the
    // call-return trampoline (SYS_CALL_RETURN -> tl_call_return_hit), a per-thread
    // signal that is safe across the parallel vCPU worker pool. end_address is kept
    // only as a defensive secondary PC check below.

    EMU_LOG_VERBOSE << "[EMU] Starting execution at 0x" << std::hex << address
              << " (end=0x" << end_address << ")"
              << " SP=0x" << qemu::read_reg(cpu, qemu::REG_SP)
              << " LR=0x" << qemu::read_reg(cpu, qemu::REG_LR)
              << std::dec << std::endl;

    // Verify PC was set correctly
    uint64_t pc = qemu::read_reg(cpu, qemu::REG_PC);
    if (pc != address) {
        EMU_LOG << "[EMU] WARNING: PC is 0x" << std::hex << pc
                  << " instead of 0x" << address << std::dec << std::endl;
    }

    // Main execution loop - handles HLE breakpoints
    // No iteration limit - the periodic block yield provides safety
    int loop_count = 0;
    tl_start_exit_reason = "incomplete";  // overwritten by a clean exit below
    while (tl_running) {  // Thread-local: only this thread's state affects its loop
        // Debug: dump registers before run (reduced verbosity)
        if (loop_count < 3) {
            // Check CPU count and which CPUs exist
            int cpu_count = libafl_qemu_num_cpus();
            EMU_LOG_VERBOSE << "[EMU] Before run " << loop_count << ": num_cpus=" << cpu_count
                      << " PC=0x" << std::hex << qemu::read_reg(cpu, qemu::REG_PC)
                      << " SP=0x" << qemu::read_reg(cpu, qemu::REG_SP)
                      << " LR=0x" << qemu::read_reg(cpu, qemu::REG_LR)
                      << std::dec << std::endl;
        }

        // Run QEMU until it stops (breakpoint, syscall, etc.)
        EMU_LOG_VERBOSE << "[EMU] Calling libafl_qemu_run(), loop=" << loop_count << std::endl;
        int result = libafl_qemu_run();

        // Primary stop: our C->guest call-return trampoline fired. This is a
        // thread-local signal set by the syscall hook (SYS_CALL_RETURN), so it
        // identifies exactly this thread's call returning, with no global state.
        if (tl_call_return_hit) {
            tl_call_return_hit = false;
            tl_start_exit_reason = "clean_return";
            break;
        }

        EMU_LOG_VERBOSE << "[EMU] After run " << loop_count << ": result=" << result << std::endl;

        // Get current CPU and PC to check why we stopped
        // CRITICAL: In MTTCG mode, libafl_qemu_current_cpu() returns whichever CPU stopped.
        // We must check if it's OUR CPU (the one we're controlling). If a child CPU
        // stopped, we should not modify its registers - just continue and wait for our CPU.
        CPUState* cur_cpu = libafl_qemu_current_cpu();

        // Check if this is our CPU or a child CPU
        if (cur_cpu != cpu) {
            // A different CPU stopped (probably a child thread hitting an HLE call)
            // Just continue - let the child CPU handle its own business via syscall hooks
            // and wait for our CPU to stop
            if (loop_count < 5 || loop_count % 100 == 0) {
                int cur_idx = cur_cpu ? libafl_qemu_cpu_index(cur_cpu) : -1;
                int our_idx = libafl_qemu_cpu_index(cpu);
                EMU_LOG_VERBOSE << "[EMU] Loop " << loop_count << ": Different CPU stopped (cur="
                          << cur_idx << " ours=" << our_idx << "), continuing" << std::endl;
            }
            loop_count++;
            continue;
        }

        uint64_t current_pc = qemu::read_reg(cur_cpu, qemu::REG_PC);

        // CRITICAL: Check for PC=0 (null pointer execution) and debug it
        if (current_pc == 0) {
            uint64_t lr = qemu::read_reg(cur_cpu, qemu::REG_LR);
            uint64_t sp = qemu::read_reg(cur_cpu, qemu::REG_SP);
            uint64_t x0 = qemu::read_reg(cur_cpu, qemu::REG_X0);
            uint64_t x29 = qemu::read_reg(cur_cpu, qemu::REG_FP);
            uint64_t x30 = qemu::read_reg(cur_cpu, qemu::REG_LR);

            EMU_ALWAYS_LOG << "[EMU] CRASH: PC=0x0 (null pointer execution)!" << std::endl;
            EMU_ALWAYS_LOG << "[EMU]   LR=0x" << std::hex << lr << " (caller return address)" << std::endl;
            EMU_ALWAYS_LOG << "[EMU]   SP=0x" << sp << " FP=0x" << x29 << " X0=0x" << x0 << std::dec << std::endl;

            // Dump a few stack frames to help debug
            EMU_ALWAYS_LOG << "[EMU] Stack trace (recent return addresses):" << std::endl;
            uint64_t frame_ptr = x29;
            for (int i = 0; i < 10 && frame_ptr != 0 && frame_ptr >= sp; i++) {
                uint64_t saved_fp = 0, saved_lr = 0;
                if (mem_read(frame_ptr, &saved_fp, 8) && mem_read(frame_ptr + 8, &saved_lr, 8)) {
                    EMU_ALWAYS_LOG << "[EMU]   Frame " << i << ": FP=0x" << std::hex << saved_fp
                            << " LR=0x" << saved_lr << std::dec << std::endl;
                    frame_ptr = saved_fp;
                } else {
                    break;
                }
            }
            break;
        }

        // Debug iterations - show more progress
        EMU_LOG_VERBOSE << "[EMU] Loop " << loop_count << ": result=" << result
                      << " PC=0x" << std::hex << current_pc
                      << " end=0x" << end_address << std::dec << std::endl;
        loop_count++;
        // Safety check for infinite loops
        if (loop_count > 10000 && (loop_count % 10000 == 0)) {
            // Print detailed debug info every 10000 iterations
            uint64_t lr = qemu::read_reg(cur_cpu, qemu::REG_LR);
            uint64_t sp = qemu::read_reg(cur_cpu, qemu::REG_SP);
            uint64_t x0 = qemu::read_reg(cur_cpu, qemu::REG_X0);

            // Get exit reason for debugging
            struct libafl_exit_reason* exit_reason = libafl_get_exit_reason();
            const char* exit_kind_name = "UNKNOWN";
            if (exit_reason) {
                switch (exit_reason->kind) {
                    case LIBAFL_EXIT_INTERNAL: exit_kind_name = "INTERNAL"; break;
                    case LIBAFL_EXIT_BREAKPOINT: exit_kind_name = "BREAKPOINT"; break;
                    case LIBAFL_EXIT_CUSTOM_INSN: exit_kind_name = "CUSTOM_INSN"; break;
                    case LIBAFL_EXIT_CRASH: exit_kind_name = "CRASH"; break;
                    case LIBAFL_EXIT_TIMEOUT: exit_kind_name = "TIMEOUT"; break;
                }
            }

            // Read more registers for crash debugging
            uint64_t x19 = qemu::read_reg(cur_cpu, qemu::REG_X19);
            uint64_t x20 = qemu::read_reg(cur_cpu, qemu::REG_X20);
            uint64_t x21 = qemu::read_reg(cur_cpu, qemu::REG_X21);
            uint64_t x22 = qemu::read_reg(cur_cpu, qemu::REG_X22);
            uint64_t x23 = qemu::read_reg(cur_cpu, qemu::REG_X23);

            EMU_LOG << "[EMU] WARNING: Loop count " << loop_count << " PC=0x" << std::hex << current_pc
                    << " LR=0x" << lr << " SP=0x" << sp << " X0=0x" << x0
                    << " result=" << std::dec << result << " exit_kind=" << exit_kind_name << std::endl;

            // Additional register dump on first report
            if (loop_count == 20000) {
                EMU_LOG << "[EMU] CRASH DEBUG: x19=0x" << std::hex << x19
                        << " x20=0x" << x20 << " x21=0x" << x21
                        << " x22=0x" << x22 << " x23=0x" << x23 << std::dec << std::endl;
            }
        }

        // Check if we hit the end address
        if (end_address != 0 && current_pc == end_address) {
            uint64_t x0 = qemu::read_reg(cur_cpu, qemu::REG_X0);
            uint64_t lr = qemu::read_reg(cur_cpu, qemu::REG_LR);
            tl_start_exit_reason = "end_address";
            EMU_LOG_VERBOSE << "[EMU] HIT END ADDRESS 0x" << std::hex << end_address
                      << " X0=0x" << x0 << " LR=0x" << lr
                      << " after " << std::dec << loop_count << " iterations" << std::endl;
            break;
        }

        // Check if this is an HLE breakpoint
        bool is_hle_region = (current_pc >= HLE_BASE && current_pc < HLE_BASE + HLE_SIZE);
        if (hle_->handle(current_pc)) {
            // HLE handler was called
            // IMPORTANT: Use cur_cpu (the CPU that stopped) not cpu (initial CPU 0)
            // Check if the handler modified PC (e.g., pthread_create sets PC to trampoline)
            uint64_t new_pc = qemu::read_reg(cur_cpu, qemu::REG_PC);
            if (new_pc == current_pc) {
                // Handler didn't change PC, return to LR as normal
                uint64_t lr = qemu::read_reg(cur_cpu, qemu::REG_LR);

                // CRITICAL: Check for null LR before returning - this would cause PC=0 crash
                if (lr == 0) {
                    EMU_ALWAYS_LOG << "[EMU] ERROR: HLE at 0x" << std::hex << current_pc << " has LR=0!"
                            << " SP=0x" << qemu::read_reg(cur_cpu, qemu::REG_SP)
                            << " X0=0x" << qemu::read_reg(cur_cpu, qemu::REG_X0)
                            << " X29=0x" << qemu::read_reg(cur_cpu, qemu::REG_FP)
                            << std::dec << std::endl;
                    // Try to get the function name from hle_
                    EMU_ALWAYS_LOG << "[EMU] This indicates a call from code that didn't set LR correctly" << std::endl;
                    break;  // Don't return to address 0
                }

                qemu::write_reg(cur_cpu, qemu::REG_PC, lr);
                if (debug_enabled_) {
                    EMU_LOG << "[EMU] HLE handled at 0x" << std::hex << current_pc
                              << ", returning to 0x" << lr << std::dec << std::endl;
                }
            } else {
                // Handler changed PC (e.g., to clone trampoline)
                if (debug_enabled_) {
                    EMU_LOG << "[EMU] HLE handled at 0x" << std::hex << current_pc
                              << ", continuing at handler-set PC=0x" << new_pc << std::dec << std::endl;
                }
            }
            continue;
        } else if (is_hle_region) {
            // We're at an HLE address but it wasn't handled - this is an unregistered stub
            // The handle() function already logged the warning with the function name
            // Skip this instruction and return to caller (like a no-op HLE)
            // IMPORTANT: Use cur_cpu (the CPU that stopped) not cpu (initial CPU 0)
            uint64_t lr = qemu::read_reg(cur_cpu, qemu::REG_LR);
            uint64_t x0 = qemu::read_reg(cur_cpu, qemu::REG_X0);
            // Unhandled HLE stub (like RET instruction) - just return to caller
            qemu::write_reg(cur_cpu, qemu::REG_PC, lr);
            continue;
        }

        // Check if QEMU exited normally or due to periodic yield
        if (result != 0) {
            struct libafl_exit_reason* exit_reason = libafl_get_exit_reason();
            if (exit_reason && exit_reason->kind == LIBAFL_EXIT_CRASH) {
                uint64_t lr = qemu::read_reg(cur_cpu, qemu::REG_LR);
                uint64_t sp = qemu::read_reg(cur_cpu, qemu::REG_SP);
                uint64_t x0 = qemu::read_reg(cur_cpu, qemu::REG_X0);
                uint64_t x1 = qemu::read_reg(cur_cpu, qemu::REG_X1);
                uint64_t x19 = qemu::read_reg(cur_cpu, qemu::REG_X19);
                uint64_t x20 = qemu::read_reg(cur_cpu, qemu::REG_X20);
                uint64_t x21 = qemu::read_reg(cur_cpu, qemu::REG_X21);
                uint64_t x22 = qemu::read_reg(cur_cpu, qemu::REG_X22);
                uint64_t x23 = qemu::read_reg(cur_cpu, qemu::REG_X23);
                bool x1_mapped = x1 != 0 && memory_->is_mapped(x1, sizeof(uint32_t));
                uint32_t x1_value = 0;
                bool x1_read_ok = x1_mapped && memory_->read(x1, &x1_value, sizeof(x1_value));

                EMU_ALWAYS_LOG << "[EMU] Guest crash: PC=0x" << std::hex << current_pc
                        << " LR=0x" << lr
                        << " SP=0x" << sp
                        << " X0=0x" << x0
                        << " X1=0x" << x1
                        << " X19=0x" << x19
                        << " X20=0x" << x20
                        << " X21=0x" << x21
                        << " X22=0x" << x22
                        << " X23=0x" << x23
                        << std::dec
                        << " mapped_x1=" << x1_mapped
                        << " read_x1=" << x1_read_ok;
                if (x1_read_ok) {
                    EMU_ALWAYS_LOG << " x1_value=" << x1_value;
                }
                EMU_ALWAYS_LOG << std::endl;
                break;
            }

            // Check if this is a periodic yield (PC is valid execution address)
            // We continue execution unless we hit end address or HLE
            // Valid PC ranges: CODE_BASE (loaded binaries)
            bool valid_pc = (current_pc >= CODE_BASE && current_pc < CODE_BASE + CODE_SIZE);
            if (valid_pc) {
                // This is likely a periodic yield, continue execution
                continue;
            }

            // Debug: always log when we're about to break
            // Also check current CPU vs initial CPU
            CPUState* cur_cpu = libafl_qemu_current_cpu();
            EMU_LOG << "[EMU] Breaking loop: result=" << result
                      << " PC=0x" << std::hex << current_pc
                      << " (CODE_BASE=0x" << CODE_BASE << " HLE_BASE=0x" << HLE_BASE << ")"
                      << " cpu=" << (void*)cpu << " cur_cpu=" << (void*)cur_cpu
                      << std::dec << std::endl;

            // PC in stack region is likely wrong CPU - keep running
            if (current_pc >= 0x7F800000 && current_pc < 0x80000000) {
                EMU_LOG << "[EMU] PC in stack region - likely wrong CPU state, continuing" << std::endl;
                continue;
            }
            break;
        }

        // If we get here with result=0, continue (normal block completion)
        continue;
    }

    // No breakpoint to remove: call returns are trapped via the SVC trampoline,
    // not the global libafl breakpoint list.

    // Clean up any debug instruction hooks
    if (!g_debug_instruction_hooks.empty()) {
        clear_debug_instruction_hooks();
    }

    // Debug: check where we ended up
    uint64_t final_pc = qemu::read_reg(cpu, qemu::REG_PC);
    uint64_t final_x0 = qemu::read_reg(cpu, qemu::REG_X0);
    uint64_t final_lr = qemu::read_reg(cpu, qemu::REG_LR);
    if (debug_enabled_) {
        EMU_LOG << "[EMU] Execution completed, PC=0x" << std::hex << final_pc
                  << " X0=0x" << final_x0
                  << " LR=0x" << final_lr << std::dec << std::endl;
    }

    tl_running = false;

#if EMU_LOGGING_ENABLED
    if (profile_logging_enabled) {
        auto end_time = std::chrono::steady_clock::now();
        uint64_t total_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(end_time - start_time).count();
        g_start_count.fetch_add(1, std::memory_order_relaxed);
        g_total_qemu_run_ns.fetch_add(total_ns, std::memory_order_relaxed);
        g_total_loop_iterations.fetch_add(loop_count, std::memory_order_relaxed);

        auto now = std::chrono::steady_clock::now();
        auto since_report = std::chrono::duration_cast<std::chrono::seconds>(now - g_last_start_report).count();
        if (since_report >= 5) {
            uint64_t count = g_start_count.exchange(0, std::memory_order_relaxed);
            uint64_t total = g_total_qemu_run_ns.exchange(0, std::memory_order_relaxed);
            uint64_t loops = g_total_loop_iterations.exchange(0, std::memory_order_relaxed);

            if (count > 0) {
                double avg_us = (double)total / count / 1000.0;
                double avg_loops = (double)loops / count;
                double calls_per_sec = (double)count / since_report;
                EMU_PROFILE_LOG << "[EMU_START_PROFILE] " << count << " starts in " << since_report << "s"
                                << " (" << std::fixed << std::setprecision(1) << calls_per_sec << "/s)"
                                << " avg=" << avg_us << "us avg_loops=" << avg_loops << std::endl;
            }
            g_last_start_report = now;
        }
    }
#endif

    return true;
}

void Emulator::stop() {
    tl_running = false;
}

void Emulator::handle_syscall(uint64_t syscall_num) {
    syscall_->handle(syscall_num);
}

// =============================================================================
// Register Access
// =============================================================================

uint64_t Emulator::get_reg(int reg) const {
    CPUState* cpu = cpu_ ? cpu_ : libafl_qemu_current_cpu();
    if (!cpu) return 0;
    return qemu::read_reg(cpu, reg);
}

void Emulator::set_reg(int reg, uint64_t value) {
    CPUState* cpu = cpu_ ? cpu_ : libafl_qemu_current_cpu();
    if (!cpu) return;
    qemu::write_reg(cpu, reg, value);
}

float Emulator::get_sreg_value(int reg) const {
    CPUState* cpu = cpu_ ? cpu_ : libafl_qemu_current_cpu();
    if (!cpu) return 0.0f;

    int fp_reg = qemu::REG_V0 + reg;
    std::array<uint8_t, qemu::MAX_REGISTER_BYTES> buf{};
    qemu::read_reg_bytes(cpu, fp_reg, buf.data(), buf.size());

    float value = 0.0f;
    std::memcpy(&value, buf.data(), sizeof(value));
    return value;
}

// =============================================================================
// Memory Access
// =============================================================================

bool Emulator::mem_read(uint64_t address, void* buffer, size_t size) const {
    return memory_->read(address, buffer, size);
}

bool Emulator::mem_write(uint64_t address, const void* buffer, size_t size) {
    return memory_->write(address, buffer, size);
}

std::vector<uint8_t> Emulator::mem_read(uint64_t address, size_t size) const {
    std::vector<uint8_t> result(size);
    if (memory_->read(address, result.data(), size)) {
        return result;
    }
    return {};
}

// =============================================================================
// HLE Registration
// =============================================================================

void Emulator::register_hle(const std::string& name, HleCallback callback) {
    hle_->register_function(name, callback);
}

// =============================================================================
// Async Emulator Infrastructure
// =============================================================================

void Emulator::start_emulator_thread() {
    EMU_LOG << "[EMU] Starting emulator background thread" << std::endl;
    should_stop_ = false;
    emulator_thread_ = std::thread(&Emulator::emulator_thread_func, this);
}

void Emulator::stop_emulator_thread() {
    if (!emulator_thread_.joinable()) {
        return;
    }

    EMU_LOG << "[EMU] Stopping emulator background thread" << std::endl;
    should_stop_ = true;

    // Wake every worker waiting on its own mailbox so they observe should_stop_.
    for (auto& mb : worker_mailboxes_) {
        std::lock_guard<std::mutex> lock(mb->mtx);
        mb->cv.notify_all();
    }

    emulator_thread_.join();
    EMU_LOG << "[EMU] Emulator background thread stopped" << std::endl;
}

// libafl new-thread hook trampoline: every guest clone()'d thread passes through here
// before entering cpu_loop. We use it to divert OUR worker vCPUs into worker_vcpu_loop().
bool Emulator::vcpu_new_thread_hook_cb(uint64_t data, ::CPUArchState* env, uint32_t tid) {
    return reinterpret_cast<Emulator*>(data)->on_vcpu_new_thread(env, tid);
}

bool Emulator::on_vcpu_new_thread(::CPUArchState* env, uint32_t tid) {
    (void)tid;
    {
        std::lock_guard<std::mutex> lk(worker_handshake_mutex_);
        if (!spawning_workers_) {
            return true;  // ordinary guest thread -> clone_func runs cpu_loop(env)
        }
    }
    // Identify OUR worker clones by where they resume (the clone stub). Ordinary guest
    // threads created concurrently during the spawn window resume at the thread wrapper instead.
    CPUState* cpu = libafl_qemu_cpu_from_env(env);
    uint64_t pc = cpu ? qemu::read_reg(cpu, qemu::REG_PC) : 0;
    if (cpu == nullptr || pc < vcpu_worker_clone_addr_ || pc >= vcpu_worker_clone_addr_ + 0x10) {
        return true;  // not one of ours
    }

    int worker_id;
    {
        std::lock_guard<std::mutex> lk(worker_handshake_mutex_);
        worker_id = ++vcpu_workers_claimed_;
        worker_cpus_.push_back(cpu);
        worker_handshake_cv_.notify_all();  // let spawn_vcpu_workers() proceed
    }

    // Become a permanent worker on THIS vCPU. Never returns until shutdown, so clone_func
    // never enters cpu_loop for this thread. libafl_qemu_env was already set to this
    // thread's env by libafl_hook_new_thread_run; current_cpu is set in worker_vcpu_loop.
    worker_vcpu_loop(worker_id, cpu);
    return false;  // on shutdown: clone_func returns, host thread exits cleanly
}

void Emulator::spawn_vcpu_workers() {
    int n = vcpu_worker_count_;
    if (n <= 0) {
        EMU_ALWAYS_LOG << "[EMU] vCPU worker pool disabled (count=0)" << std::endl;
        return;
    }

    // Issue a DIRECT SYS_clone rather than going through pthread_create's HLE handler:
    // SYS_clone (220) is handled by QEMU natively (do_fork), which mints a vCPU + host
    // thread and fires our new-thread hook. (pthread_create's HLE redirects PC to a clone
    // trampoline, which isn't honored when invoked as an isolated call_function.)
    // Write a tiny guest stub once: mov x8,#220 ; svc #0 ; ret.
    const uint64_t clone_stub_addr = HLE_BASE + 0x90000;  // free slot in the exec HLE region
    {
        uint32_t code[3] = {
            0xD2801B88,  // movz x8, #220   (SYS_clone)
            0xD4000001,  // svc  #0
            0xD65F03C0,  // ret
        };
        if (!memory_->write(clone_stub_addr, code, sizeof(code))) {
            EMU_ALWAYS_LOG << "[EMU] vCPU pool: failed to write clone stub; staying single-worker"
                           << std::endl;
            return;
        }
    }
    // CLONE_VM|FS|FILES|SIGHAND|THREAD|SYSVSEM (no tid/tls flags so x2..x4 may be 0).
    const uint64_t clone_flags = 0x50F00;
    vcpu_worker_clone_addr_ = clone_stub_addr;  // workers resume at clone_stub_addr+8

    EMU_ALWAYS_LOG << "[EMU] vCPU pool: spawning " << n << " parallel worker vCPUs..." << std::endl;
    {
        std::lock_guard<std::mutex> lk(worker_handshake_mutex_);
        spawning_workers_ = true;
        vcpu_workers_claimed_ = 0;
    }

    int spawned = 0;
    for (int i = 1; i <= n; ++i) {
        // Per-worker safe-call stack region so nested HLE->guest (safe) calls on different
        // workers never collide on the shared 0xA0000000 region.
        uint64_t region = SAFE_CALL_STACK_BASE + static_cast<uint64_t>(i) * SAFE_CALL_STACK_SIZE;
        if (region + SAFE_CALL_STACK_SIZE > GLOBAL_DATA_BASE) {
            EMU_ALWAYS_LOG << "[EMU] vCPU pool: out of safe-stack space at " << (i - 1) << std::endl;
            break;
        }
        memory_->map(region, SAFE_CALL_STACK_SIZE, MEM_READ | MEM_WRITE, "WorkerSafeStack");

        // Per-worker child stack (do_fork needs a valid child stack pointer; the worker
        // never actually runs guest code on it -- the hook diverts before cpu_loop).
        const uint64_t child_stack_size = 0x40000;  // 256KB
        uint64_t child_stack = memory().heap().allocate(child_stack_size, 16);
        uint64_t child_sp = child_stack + child_stack_size - 16;

        int cpus_before = libafl_qemu_num_cpus();
        // Direct SYS_clone on CPU0 -> do_fork -> new vCPU + host thread -> new-thread hook,
        // which self-binds the worker (identified by the clone-stub PC) via env_cpu.
        call_function_internal(clone_stub_addr, {clone_flags, child_sp, 0, 0, 0}, false);
        if (libafl_qemu_num_cpus() <= cpus_before) {
            EMU_ALWAYS_LOG << "[EMU] vCPU pool: clone made no vCPU; stopping at " << (i - 1) << std::endl;
            break;
        }
        // Wait for the hook to claim this worker before issuing the next clone.
        {
            std::unique_lock<std::mutex> lk(worker_handshake_mutex_);
            worker_handshake_cv_.wait(lk, [this, i] { return vcpu_workers_claimed_ >= i; });
        }
        spawned = i;
    }

    {
        std::lock_guard<std::mutex> lk(worker_handshake_mutex_);
        spawning_workers_ = false;
        worker_handshake_cv_.notify_all();  // release workers from the post-spawn barrier
    }
    EMU_ALWAYS_LOG << "[EMU] vCPU pool: " << spawned << " parallel workers online" << std::endl;
}

void Emulator::worker_vcpu_loop(int worker_id, CPUState* cpu) {
    tl_worker_id = worker_id;
    tl_is_worker = true;
    tls_cpu = cpu;  // HLE handlers on this host thread use this vCPU
    tl_safe_stack_base = SAFE_CALL_STACK_BASE + static_cast<uint64_t>(worker_id) * SAFE_CALL_STACK_SIZE;
    libafl_qemu_set_current_cpu(cpu);  // current_cpu = this worker's vCPU

    // Barrier: don't start consuming requests until ALL workers are spawned, so the
    // spawn loop's libafl_qemu_get_cpu(num_cpus-1) bookkeeping isn't perturbed by a
    // worker running guest code (which could itself create CPUs).
    {
        std::unique_lock<std::mutex> lk(worker_handshake_mutex_);
        worker_handshake_cv_.wait(lk, [this] { return !spawning_workers_; });
    }

    EMU_ALWAYS_LOG << "[EMU] vCPU worker " << worker_id << " online (cpu_index="
                   << libafl_qemu_cpu_index(cpu) << ")" << std::endl;
    run_request_loop();
}

void Emulator::run_request_loop() {
    // Each worker consumes ONLY its own mailbox so affinity routing is honored: a calling
    // thread pinned to worker K is always serviced by worker K's vCPU.
    WorkerMailbox& mb = *worker_mailboxes_[tl_worker_id];
    while (!should_stop_) {
        std::shared_ptr<FunctionRequest> request;
        {
            std::unique_lock<std::mutex> lock(mb.mtx);
            mb.cv.wait(lock, [&] {
                return !mb.queue.empty() || should_stop_;
            });
            if (should_stop_) break;
            if (!mb.queue.empty()) {
                request = mb.queue.front();
                mb.queue.pop();
            }
        }
        if (!request) continue;

        // Lazily spawn the parallel vCPU worker pool once the guest has already created at
        // least one thread of its own (num_cpus > 1). That guarantees the clone trampoline
        // is written and the QEMU clone()/do_fork path is live, so our worker clones
        // actually mint vCPUs. Only the main thread (worker_id 0) spawns. workers_spawned_
        // is published only AFTER the pool is online, so affinity routing to 1..N can't
        // target a worker that isn't consuming its mailbox yet.
        if (tl_worker_id == 0 && !spawn_initiated_ && libafl_qemu_num_cpus() > 1) {
            spawn_initiated_ = true;
            spawn_vcpu_workers();
            workers_spawned_.store(true, std::memory_order_release);
        }

#if EMU_LOGGING_ENABLED
        if (emu::is_profile_logging_enabled()) {
            request->t_dequeued = std::chrono::steady_clock::now();
            request->t_exec_start = request->t_dequeued;
        }
#endif
        uint64_t result = call_function_internal(request->address, request->args,
                                                  request->is_safe_call,
                                                  request->safe_stack_top);
#if EMU_LOGGING_ENABLED
        if (emu::is_profile_logging_enabled()) {
            request->t_exec_end = std::chrono::steady_clock::now();
        }
#endif
        {
            // Publish result + completed WHILE HOLDING request->mutex so this store
            // happens-before the waiter's mutex-protected predicate check + park in
            // call_function / call_function_safe_on_stack. Without this lock, the
            // notify_one() below can fire in the window after the waiter read the predicate
            // (false) and released request->mutex inside cv.wait but BEFORE it registered on
            // the condvar's futex generation -> glibc drops the wakeup and the caller sleeps
            // forever even though the call already completed. std::atomic<bool> does NOT close
            // this race (it is a wakeup-registration ordering bug, not a visibility bug). This
            // mirrors the already-correct mailbox-push path. Observed as a ~70-min emulator
            // wedge after millions of recv polls across many concurrent sessions (completed==true, result
            // valid, one parked waiter, zero pending condvar signal in the core dump).
            std::lock_guard<std::mutex> lk(request->mutex);
            request->result = result;
            request->completed.store(true, std::memory_order_release);
        }
        request->cv.notify_one();  // outside the lock: avoid wake-then-immediately-block-on-mutex
    }
}

void Emulator::emulator_thread_func() {
    emulator_thread_id_ = std::this_thread::get_id();
    EMU_LOG << "[EMU] Emulator thread started" << std::endl;

    // If QEMU is not yet initialized, we need to initialize it on this thread
    // This is critical: libafl_qemu_run() must be called from the same thread
    // that called libafl_qemu_init()
    // NOTE: QEMU must be initialized BEFORE setting real-time scheduling,
    // otherwise QEMU's internal initialization may not complete properly.
    if (!qemu_initialized_) {
        EMU_LOG << "[EMU] Initializing QEMU from emulator thread..." << std::endl;
        initialize_qemu_on_this_thread();
        EMU_LOG << "[EMU] QEMU initialized on emulator thread" << std::endl;
    }

    // Configure thread for low-latency operation AFTER QEMU is initialized:
    // Try to set real-time scheduling (SCHED_FIFO) for predictable wakeup
    // Note: CPU pinning was tested but found to HURT performance by preventing
    // the scheduler from optimally placing the thread
    // Note: Setting real-time priority before QEMU init causes crashes
    // Set EMU_NO_REALTIME=1 to disable real-time scheduling
    {
        const char* no_realtime = std::getenv("EMU_NO_REALTIME");
        if (no_realtime && (std::string(no_realtime) == "1" || std::string(no_realtime) == "true")) {
            EMU_LOG << "[EMU] Real-time scheduling disabled via EMU_NO_REALTIME" << std::endl;
        } else {
            pthread_t self = pthread_self();

            // Try to set SCHED_FIFO with priority 50 (mid-range, 1-99)
            // This requires CAP_SYS_NICE or root privileges
            struct sched_param param;
            param.sched_priority = 50;
            int ret = pthread_setschedparam(self, SCHED_FIFO, &param);
            if (ret == 0) {
                EMU_LOG << "[EMU] Set SCHED_FIFO priority 50 for emulator thread" << std::endl;
            } else {
                // Fall back: try SCHED_RR (round-robin real-time)
                ret = pthread_setschedparam(self, SCHED_RR, &param);
                if (ret == 0) {
                    EMU_LOG << "[EMU] Set SCHED_RR priority 50 for emulator thread" << std::endl;
                } else {
                    // Can't get real-time, at least try to raise nice priority
                    // nice(-10) requires CAP_SYS_NICE or being in an appropriate group
                    errno = 0;
                    int new_nice = nice(-10);
                    if (errno == 0) {
                        EMU_LOG << "[EMU] Set nice=" << new_nice << " for emulator thread" << std::endl;
                    } else {
                        EMU_LOG << "[EMU] Note: Real-time priority not available (need CAP_SYS_NICE or root)" << std::endl;
                        EMU_LOG << "[EMU] Run with: sudo setcap cap_sys_nice+ep <binary> for real-time scheduling" << std::endl;
                    }
                }
            }
        }
    }

    // No need to register with TCG - we ARE the main QEMU thread now.
    // This is worker 0; pool workers (1..N) are minted lazily on the first request.
    tl_is_worker = true;
    tl_worker_id = 0;
    tl_safe_stack_base = SAFE_CALL_STACK_BASE;

    // Register the new-thread hook so the worker vCPUs we clone get diverted into
    // worker_vcpu_loop() instead of running cpu_loop(). Ordinary guest threads
    // are untouched (the hook returns true for them).
    if (vcpu_worker_count_ > 0) {
        libafl_add_new_thread_hook(vcpu_new_thread_hook_cb, reinterpret_cast<uint64_t>(this));
    }

    run_request_loop();

    EMU_LOG << "[EMU] Emulator thread exiting" << std::endl;
}

#if EMU_LOGGING_ENABLED
// Profiling stats for call_function - granular breakdown
static std::atomic<uint64_t> g_call_count{0};
static std::atomic<uint64_t> g_total_alloc_ns{0};     // Time for shared_ptr allocation
static std::atomic<uint64_t> g_total_queue_ns{0};     // Time waiting for queue mutex
static std::atomic<uint64_t> g_total_sched_ns{0};     // Time for scheduler wakeup
static std::atomic<uint64_t> g_total_exec_ns{0};      // Time for actual execution
static std::atomic<uint64_t> g_total_signal_ns{0};    // Time for result signal
static std::atomic<uint64_t> g_total_roundtrip_ns{0}; // Total round-trip

// Max values for each phase
static std::atomic<uint64_t> g_max_alloc_ns{0};
static std::atomic<uint64_t> g_max_queue_ns{0};
static std::atomic<uint64_t> g_max_sched_ns{0};
static std::atomic<uint64_t> g_max_exec_ns{0};
static std::atomic<uint64_t> g_max_signal_ns{0};
static std::atomic<uint64_t> g_max_roundtrip_ns{0};

// Histogram for spikes (>100us)
static std::atomic<uint64_t> g_spikes_100us{0};   // 100-200us
static std::atomic<uint64_t> g_spikes_200us{0};   // 200-500us
static std::atomic<uint64_t> g_spikes_500us{0};   // 500us-1ms
static std::atomic<uint64_t> g_spikes_1ms{0};     // >1ms

// Spin-wait effectiveness counters
static std::atomic<uint64_t> g_spin_hits{0};      // Completed during spin phase
static std::atomic<uint64_t> g_yield_hits{0};     // Completed during yield phase
static std::atomic<uint64_t> g_cv_waits{0};       // Had to use CV wait

static std::chrono::steady_clock::time_point g_last_profile_report = std::chrono::steady_clock::now();

// Helper to update max atomically
static inline void update_max(std::atomic<uint64_t>& max_val, uint64_t val) {
    uint64_t current = max_val.load(std::memory_order_relaxed);
    while (val > current &&
           !max_val.compare_exchange_weak(current, val, std::memory_order_relaxed));
}
#endif

// Choose the worker vCPU that should run this calling thread's C->guest calls.
// Sticky per-thread: the first call assigns a pool worker (round-robin over 1..N) and
// every later call from the same thread reuses it, so a session's calls never bounce
// across CPUs. Before the pool is up (or in legacy single-worker mode) we route to the
// main emulator thread (slot 0) and DON'T cache, so the thread upgrades to a real worker
// once the pool comes online.
int Emulator::pick_affinity_worker() {
    if (workers_spawned_.load(std::memory_order_acquire) && vcpu_worker_count_ > 0) {
        // Diagnostic override: CROSSSHIM_PIN_WORKER=K forces every C->guest call onto
        // worker K (no spreading). Lets us isolate "spreading across cpus breaks the guest"
        // (works when pinned) from "single worker cpu / HLE state is broken" (still stalls).
        static const int pinned = [] {
            const char* p = std::getenv("CROSSSHIM_PIN_WORKER");
            return p ? std::atoi(p) : -1;
        }();
        if (pinned >= 0) return (pinned > vcpu_worker_count_) ? vcpu_worker_count_ : pinned;

        if (tl_affinity_worker < 1) {
            tl_affinity_worker =
                1 + (next_affinity_worker_.fetch_add(1, std::memory_order_relaxed) %
                     vcpu_worker_count_);
        }
        return tl_affinity_worker;
    }
    return 0;
}

uint64_t Emulator::call_function(uint64_t address, const std::vector<uint64_t>& args) {
    // If we're already executing on a pool worker (or the main emulator thread), run
    // inline on THIS thread's vCPU. This covers reentrancy (an HLE handler calling back
    // into guest code) and avoids cross-dispatching to a different worker/vCPU.
    if (tl_is_worker) {
        return call_function_internal(address, args, false);
    }

#if EMU_LOGGING_ENABLED
    const bool profile_logging_enabled = emu::is_profile_logging_enabled();
    std::chrono::steady_clock::time_point t0{};
    std::chrono::steady_clock::time_point t1{};
    std::chrono::steady_clock::time_point t2{};
    if (profile_logging_enabled) {
        t0 = std::chrono::steady_clock::now();
    }
#endif

    auto request = std::make_shared<FunctionRequest>();
    request->address = address;
    request->args = args;
    request->completed.store(false, std::memory_order_relaxed);
    request->is_safe_call = false;

#if EMU_LOGGING_ENABLED
    if (profile_logging_enabled) {
        request->t_submit = t0;
        t1 = std::chrono::steady_clock::now();
    }
#endif

    {
        WorkerMailbox& mb = *worker_mailboxes_[pick_affinity_worker()];
        std::lock_guard<std::mutex> lock(mb.mtx);
        mb.queue.push(request);
        // CRITICAL: Notify WHILE holding the lock to prevent lost wakeups.
        // The race was: unlock -> worker checks queue (sees old state) -> notify (lost)
        mb.cv.notify_one();
    }

#if EMU_LOGGING_ENABLED
    if (profile_logging_enabled) {
        request->t_queued = std::chrono::steady_clock::now();
        t2 = request->t_queued;
    }
#endif

    {
        std::unique_lock<std::mutex> lock(request->mutex);
        // Defense-in-depth: re-check the atomic predicate on a fixed interval rather than
        // waiting indefinitely, so a dropped completion notify self-heals within one interval
        // (the primary cure is the synchronized store in run_request_loop). Logs once if a call
        // ever exceeds a sanity threshold well beyond any legitimate call timeout.
        auto wait_start = std::chrono::steady_clock::now();
        bool warned = false;
        while (!request->cv.wait_for(lock, std::chrono::seconds(5), [&request] {
            return request->completed.load(std::memory_order_acquire);
        })) {
            if (!warned) {
                auto age = std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::steady_clock::now() - wait_start).count();
                if (age >= 45) {
                    warned = true;
                    EMU_ALWAYS_LOG << "[EMU][WEDGE-WATCHDOG] call addr=0x" << std::hex
                        << request->address << std::dec << " incomplete after " << age
                        << "s (completed=" << request->completed.load()
                        << "); re-checking predicate" << std::endl;
                }
            }
        }
        if (warned) {
            auto total = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now() - wait_start).count();
            EMU_ALWAYS_LOG << "[EMU][WEDGE-WATCHDOG] call addr=0x" << std::hex << request->address
                << std::dec << " COMPLETED after " << total << "s (was slow, not orphaned)"
                << std::endl;
        }
    }

#if EMU_LOGGING_ENABLED
    if (profile_logging_enabled) {
        auto t3 = std::chrono::steady_clock::now();

        uint64_t alloc_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count();
        uint64_t queue_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(t2 - t1).count();
        uint64_t sched_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(request->t_dequeued - t2).count();
        uint64_t exec_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(request->t_exec_end - request->t_exec_start).count();
        uint64_t signal_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(t3 - request->t_exec_end).count();
        uint64_t roundtrip_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(t3 - t0).count();

        g_call_count.fetch_add(1, std::memory_order_relaxed);
        g_total_alloc_ns.fetch_add(alloc_ns, std::memory_order_relaxed);
        g_total_queue_ns.fetch_add(queue_ns, std::memory_order_relaxed);
        g_total_sched_ns.fetch_add(sched_ns, std::memory_order_relaxed);
        g_total_exec_ns.fetch_add(exec_ns, std::memory_order_relaxed);
        g_total_signal_ns.fetch_add(signal_ns, std::memory_order_relaxed);
        g_total_roundtrip_ns.fetch_add(roundtrip_ns, std::memory_order_relaxed);

        update_max(g_max_alloc_ns, alloc_ns);
        update_max(g_max_queue_ns, queue_ns);
        update_max(g_max_sched_ns, sched_ns);
        update_max(g_max_exec_ns, exec_ns);
        update_max(g_max_signal_ns, signal_ns);
        update_max(g_max_roundtrip_ns, roundtrip_ns);

        if (roundtrip_ns > 1000000) g_spikes_1ms.fetch_add(1, std::memory_order_relaxed);
        else if (roundtrip_ns > 500000) g_spikes_500us.fetch_add(1, std::memory_order_relaxed);
        else if (roundtrip_ns > 200000) g_spikes_200us.fetch_add(1, std::memory_order_relaxed);
        else if (roundtrip_ns > 100000) g_spikes_100us.fetch_add(1, std::memory_order_relaxed);

        auto now = std::chrono::steady_clock::now();
        auto since_report = std::chrono::duration_cast<std::chrono::seconds>(now - g_last_profile_report).count();
        if (since_report >= 5) {
            uint64_t count = g_call_count.exchange(0, std::memory_order_relaxed);
            uint64_t total_alloc = g_total_alloc_ns.exchange(0, std::memory_order_relaxed);
            uint64_t total_queue = g_total_queue_ns.exchange(0, std::memory_order_relaxed);
            uint64_t total_sched = g_total_sched_ns.exchange(0, std::memory_order_relaxed);
            uint64_t total_exec = g_total_exec_ns.exchange(0, std::memory_order_relaxed);
            uint64_t total_signal = g_total_signal_ns.exchange(0, std::memory_order_relaxed);
            uint64_t total_rt = g_total_roundtrip_ns.exchange(0, std::memory_order_relaxed);

            uint64_t max_alloc = g_max_alloc_ns.exchange(0, std::memory_order_relaxed);
            uint64_t max_queue = g_max_queue_ns.exchange(0, std::memory_order_relaxed);
            uint64_t max_sched = g_max_sched_ns.exchange(0, std::memory_order_relaxed);
            uint64_t max_exec = g_max_exec_ns.exchange(0, std::memory_order_relaxed);
            uint64_t max_signal = g_max_signal_ns.exchange(0, std::memory_order_relaxed);
            uint64_t max_rt = g_max_roundtrip_ns.exchange(0, std::memory_order_relaxed);

            uint64_t spk_100 = g_spikes_100us.exchange(0, std::memory_order_relaxed);
            uint64_t spk_200 = g_spikes_200us.exchange(0, std::memory_order_relaxed);
            uint64_t spk_500 = g_spikes_500us.exchange(0, std::memory_order_relaxed);
            uint64_t spk_1ms = g_spikes_1ms.exchange(0, std::memory_order_relaxed);

            if (count > 0) {
                EMU_PROFILE_LOG << "[EMU_PROFILE] " << count << " calls (" << std::fixed << std::setprecision(1)
                                << (double)count / since_report << "/s)\n";
                EMU_PROFILE_LOG << "  [AVG us] alloc=" << total_alloc / count / 1000.0
                                << " queue=" << total_queue / count / 1000.0
                                << " sched=" << total_sched / count / 1000.0
                                << " exec=" << total_exec / count / 1000.0
                                << " signal=" << total_signal / count / 1000.0
                                << " TOTAL=" << total_rt / count / 1000.0 << "\n";
                EMU_PROFILE_LOG << "  [MAX us] alloc=" << max_alloc / 1000.0
                                << " queue=" << max_queue / 1000.0
                                << " sched=" << max_sched / 1000.0
                                << " exec=" << max_exec / 1000.0
                                << " signal=" << max_signal / 1000.0
                                << " TOTAL=" << max_rt / 1000.0 << "\n";
                if (spk_100 + spk_200 + spk_500 + spk_1ms > 0) {
                    EMU_PROFILE_LOG << "  [SPIKES] 100-200us=" << spk_100
                                    << " 200-500us=" << spk_200
                                    << " 500us-1ms=" << spk_500
                                    << " >1ms=" << spk_1ms << "\n";
                }
            }
            g_last_profile_report = now;
        }
    }
#endif

    return request->result;
}

uint64_t Emulator::call_function_safe(uint64_t address, const std::vector<uint64_t>& args) {
    return call_function_safe_on_stack(address, 0, args);
}

// QEMU CPU execution-state primitives (exported by the QEMU library). cpu_exec_end clears
// cpu->running and releases any pending exclusive waiter; cpu_exec_start re-enters (waiting
// out an in-progress exclusive section). They let a vCPU that is about to block in an HLE
// handler step out of the exclusive set so tb_flush / thread creation don't stall on it.
extern "C" void cpu_exec_start(CPUState* cpu);
extern "C" void cpu_exec_end(CPUState* cpu);

namespace { thread_local CPUState* tl_suspended_cpu = nullptr; }

void Emulator::cpu_exec_suspend() {
    CPUState* cpu = libafl_qemu_current_cpu();
    tl_suspended_cpu = cpu;
    if (cpu != nullptr) {
        cpu_exec_end(cpu);
    }
}

void Emulator::cpu_exec_resume() {
    if (tl_suspended_cpu != nullptr) {
        cpu_exec_start(tl_suspended_cpu);
        tl_suspended_cpu = nullptr;
    }
}

uint64_t Emulator::call_function_safe_on_stack(uint64_t address, uint64_t stack_top,
                                               const std::vector<uint64_t>& args) {
    // If we're on the thread currently running QEMU (either background or direct),
    // call internal directly to avoid deadlock.
    //
    // In MTTCG mode, child guest threads run on their own host threads and do not
    // share `current_execution_thread_id_`. When an HLE handler on one of those
    // threads needs to make a nested guest call (for example a signal handler
    // delivery from `sigsuspend`), queueing back to the emulator thread can
    // deadlock if that thread is blocked in another HLE call such as
    // `pthread_join`. Detect an active QEMU CPU on the current thread and run the
    // nested safe call in-place.
    if (std::this_thread::get_id() == current_execution_thread_id_ ||
        std::this_thread::get_id() == emulator_thread_id_ ||
        libafl_qemu_current_cpu() != nullptr) {
        return call_function_internal(address, args, true, stack_top);
    }

    auto request = std::make_shared<FunctionRequest>();
    request->address = address;
    request->args = args;
    request->completed.store(false, std::memory_order_relaxed);
    request->is_safe_call = true;
    request->safe_stack_top = stack_top;

    {
        WorkerMailbox& mb = *worker_mailboxes_[pick_affinity_worker()];
        std::lock_guard<std::mutex> lock(mb.mtx);
        mb.queue.push(request);
        // CRITICAL: Notify WHILE holding the lock to prevent lost wakeups
        mb.cv.notify_one();
    }

    {
        std::unique_lock<std::mutex> lock(request->mutex);
        // Defense-in-depth re-checking wait (see call_function): self-heals a dropped
        // completion notify within one interval; the primary cure is the synchronized store
        // in run_request_loop.
        auto wait_start = std::chrono::steady_clock::now();
        bool warned = false;
        while (!request->cv.wait_for(lock, std::chrono::seconds(5), [&request] {
            return request->completed.load(std::memory_order_acquire);
        })) {
            if (!warned) {
                auto age = std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::steady_clock::now() - wait_start).count();
                if (age >= 45) {
                    warned = true;
                    EMU_ALWAYS_LOG << "[EMU][WEDGE-WATCHDOG] safe call addr=0x" << std::hex
                        << request->address << std::dec << " incomplete after " << age
                        << "s (completed=" << request->completed.load()
                        << "); re-checking predicate" << std::endl;
                }
            }
        }
        if (warned) {
            auto total = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now() - wait_start).count();
            EMU_ALWAYS_LOG << "[EMU][WEDGE-WATCHDOG] safe call addr=0x" << std::hex
                << request->address << std::dec << " COMPLETED after " << total
                << "s (was slow, not orphaned)" << std::endl;
        }
    }

    return request->result;
}

uint64_t Emulator::call_function_direct(uint64_t address, const std::vector<uint64_t>& args) {
    // IMPORTANT: In LibAFL QEMU, libafl_qemu_run() MUST be called from the same
    // thread that called libafl_qemu_init(). Since we now initialize QEMU on the
    // emulator background thread, we MUST route all calls through that thread.
    //
    // If we're on the emulator thread, run directly.
    // If not, queue to the emulator thread (same as call_function).
    if (std::this_thread::get_id() == emulator_thread_id_) {
        std::thread::id previous = current_execution_thread_id_;
        current_execution_thread_id_ = std::this_thread::get_id();
        uint64_t result = call_function_internal(address, args, false);
        current_execution_thread_id_ = previous;
        return result;
    }

    // Not on emulator thread - use the queue
    return call_function(address, args);
}

uint64_t Emulator::call_function_internal(uint64_t address, const std::vector<uint64_t>& args,
                                          bool is_safe, uint64_t safe_stack_top) {
    // Exception firewall. A C++ exception (std::bad_alloc, std::out_of_range from .at(),
    // std::runtime_error from QEMU, etc.) thrown below this point would otherwise escape
    // either the worker thread (-> std::terminate) or the extern "C"/P-Invoke boundary
    // (-> undefined behavior in the .NET runtime), killing the whole process and every
    // session. Convert it into a failed call so only the calling session sees the error
    // and can reconnect. (SIGSEGV is NOT a C++ exception and is handled separately.)
    try {
        return call_function_internal_impl(address, args, is_safe, safe_stack_top);
    } catch (const std::exception& e) {
        EMU_ALWAYS_LOG << "[EMU] EXCEPTION in guest call @0x" << std::hex << address << std::dec
                       << ": " << e.what() << " -- failing this call (-1)" << std::endl;
        last_call_succeeded_ = false;
        return (uint64_t)-1;
    } catch (...) {
        EMU_ALWAYS_LOG << "[EMU] UNKNOWN EXCEPTION in guest call @0x" << std::hex << address
                       << std::dec << " -- failing this call (-1)" << std::endl;
        last_call_succeeded_ = false;
        return (uint64_t)-1;
    }
}

uint64_t Emulator::call_function_internal_impl(uint64_t address, const std::vector<uint64_t>& args,
                                          bool is_safe, uint64_t safe_stack_top) {
    // CRITICAL: Full memory barrier before executing any function
    // This ensures all writes from previous operations (including those from
    // child threads running in QEMU) are visible to the emulated code.
    // This was needed to fix race conditions that manifested when verbose
    // logging was disabled (logging provides implicit memory barriers via mutex).
    std::atomic_thread_fence(std::memory_order_seq_cst);

    // Debug: check CPU state
    CPUState* cur_cpu = libafl_qemu_current_cpu();
    CPUState* cpu0 = libafl_qemu_get_cpu(0);
    int num_cpus = libafl_qemu_num_cpus();

    EMU_LOG_VERBOSE << "[EMU] call_function_internal: addr=0x" << std::hex << address << std::dec
              << " num_cpus=" << num_cpus
              << " current_cpu=" << (void*)cur_cpu
              << " cpu0=" << (void*)cpu0
              << " stored_cpu_=" << (void*)cpu_ << std::endl;

    // Try to get current CPU, fall back to stored CPU
    CPUState* cpu = cur_cpu;
    if (!cpu) {
        cpu = cpu0;  // Get first CPU
        EMU_LOG_VERBOSE << "[EMU] No current CPU, using CPU 0" << std::endl;
    } else {
        int cpu_idx = libafl_qemu_cpu_index(cpu);
        EMU_LOG_VERBOSE << "[EMU] Using current CPU (index " << cpu_idx << ")" << std::endl;
    }
    if (!cpu) {
        cpu = cpu_;  // Use stored CPU from init
        EMU_LOG_VERBOSE << "[EMU] Using stored CPU from init" << std::endl;
    }
    if (!cpu) {
        EMU_ALWAYS_LOG << "[EMU] ERROR: No CPU available for call_function" << std::endl;
        return (uint64_t)-1;
    }

    std::vector<uint64_t> arg_values(args.begin(), args.end());

    if (is_safe) {
        EMU_LOG << "[EMU] safe call args: count=" << arg_values.size();
        if (!arg_values.empty()) {
            EMU_LOG << " arg0_in=0x" << std::hex << arg_values[0] << std::dec;
        }
        if (arg_values.size() > 1) {
            EMU_LOG << " arg1_in=0x" << std::hex << arg_values[1] << std::dec;
        }
        EMU_LOG << std::endl;
    }

    static thread_local int call_depth = 0;
    int next_call_depth = call_depth + 1;

    struct SafeCallFrame {
        uint64_t target = 0;
        uint64_t arg_regs[8]{};
    };

    struct SafeCallContext {
        uint64_t x[31]{};
        uint64_t sp = 0;
        uint64_t pc = 0;
        uint64_t nzcv = 0;
        uint64_t tpidr_el0 = 0;
        uint8_t v[32][qemu::MAX_REGISTER_BYTES]{};
        uint32_t fpsr = 0;
        uint32_t fpcr = 0;
    };

    SafeCallContext saved_ctx{};
    bool saved_running = tl_running;  // Thread-local: save this thread's running state
    if (is_safe) {
        for (int reg = qemu::REG_X0; reg <= qemu::REG_X30; ++reg) {
            saved_ctx.x[reg] = qemu::read_reg(cpu, reg);
        }
        saved_ctx.sp = qemu::read_reg(cpu, qemu::REG_SP);
        saved_ctx.pc = qemu::read_reg(cpu, qemu::REG_PC);
        saved_ctx.nzcv = qemu::read_reg(cpu, qemu::REG_CPSR);
        saved_ctx.tpidr_el0 = qemu::read_reg(cpu, qemu::REG_TPIDR_EL0);
        for (int reg = qemu::REG_V0; reg <= qemu::REG_V31; ++reg) {
            qemu::read_reg_bytes(cpu, reg, saved_ctx.v[reg - qemu::REG_V0],
                                 qemu::MAX_REGISTER_BYTES);
        }
        saved_ctx.fpsr = static_cast<uint32_t>(qemu::read_reg(cpu, qemu::REG_FPSR));
        saved_ctx.fpcr = static_cast<uint32_t>(qemu::read_reg(cpu, qemu::REG_FPCR));

        size_t raw_stack_arg_bytes =
            arg_values.size() > 8 ? (arg_values.size() - 8) * sizeof(uint64_t) : 0;
        uint64_t stack_arg_bytes =
            raw_stack_arg_bytes == 0 ? 0 : MemoryManager::align_up(raw_stack_arg_bytes, 16);
        uint64_t target_sp = 0;
        uint64_t frame_base = 0;
        if (safe_stack_top != 0) {
            target_sp = MemoryManager::align_down(safe_stack_top - stack_arg_bytes, 16);
            frame_base = target_sp - SAFE_CALL_CONTEXT_SIZE;
        } else {
            uint64_t stack_offset = static_cast<uint64_t>(next_call_depth) * SAFE_CALL_STACK_CHUNK;
            if (stack_offset >= SAFE_CALL_STACK_SIZE) {
                EMU_ALWAYS_LOG << "[EMU] ERROR: safe call stack exhausted at depth "
                        << next_call_depth << std::endl;
                return static_cast<uint64_t>(-1);
            }

            target_sp =
                tl_safe_stack_base + SAFE_CALL_STACK_SIZE - stack_offset - 0x100 - stack_arg_bytes;
            frame_base = target_sp - SAFE_CALL_CONTEXT_SIZE;
            uint64_t chunk_base =
                tl_safe_stack_base + SAFE_CALL_STACK_SIZE - stack_offset - SAFE_CALL_STACK_CHUNK;
            if (frame_base < chunk_base + 0x100) {
                EMU_ALWAYS_LOG << "[EMU] ERROR: safe call frame exhausted stack chunk at depth "
                        << next_call_depth << std::endl;
                return static_cast<uint64_t>(-1);
            }
        }

        SafeCallFrame frame{};
        frame.target = address;
        for (size_t i = 0; i < arg_values.size() && i < 8; ++i) {
            uint64_t arg_value = arg_values[i];
            frame.arg_regs[i] = arg_value;
        }
        EMU_LOG << "[EMU] safe call local frame: target=0x" << std::hex << frame.target
                << " arg0=0x" << frame.arg_regs[0]
                << " arg1=0x" << frame.arg_regs[1]
                << std::dec << std::endl;
        memory_->write(frame_base, &frame, sizeof(frame));

        SafeCallFrame verify_frame{};
        bool verify_ok = memory_->read(frame_base, &verify_frame, sizeof(verify_frame));
        EMU_LOG << "[EMU] safe call frame: base=0x" << std::hex << frame_base
                << " target_sp=0x" << target_sp
                << " entry=0x" << SAFE_CALL_TRAMPOLINE_ADDR
                << " verify=" << std::dec << verify_ok;
        if (verify_ok) {
            EMU_LOG << " target=0x" << std::hex << verify_frame.target
                    << " arg0=0x" << verify_frame.arg_regs[0]
                    << " arg1=0x" << verify_frame.arg_regs[1]
                    << std::dec;
        }
        EMU_LOG << std::endl;

        if (arg_values.size() > 8) {
            for (size_t i = 8; i < arg_values.size(); ++i) {
                uint64_t stack_addr = target_sp + (i - 8) * sizeof(uint64_t);
                memory_->write(stack_addr, &arg_values[i], sizeof(uint64_t));
            }
        }

        qemu::write_reg(cpu, qemu::REG_SP, frame_base);
    }

    if (!is_safe) {
        // Set up arguments in X0-X7
        static const int kArgRegs[8] = {
            qemu::REG_X0, qemu::REG_X1, qemu::REG_X2, qemu::REG_X3,
            qemu::REG_X4, qemu::REG_X5, qemu::REG_X6, qemu::REG_X7
        };

        for (size_t i = 0; i < arg_values.size() && i < 8; i++) {
            qemu::write_reg(cpu, kArgRegs[i], arg_values[i]);
        }

        // Handle stack arguments
        if (arg_values.size() > 8) {
            uint64_t sp = qemu::read_reg(cpu, qemu::REG_SP);
            for (size_t i = 8; i < arg_values.size(); i++) {
                uint64_t stack_addr = sp + (i - 8) * 8;
                memory_->write(stack_addr, &arg_values[i], 8);
            }
        }
    }

    // Return through the shared call-return trampoline. A single address serves all
    // call levels and all vCPU workers: the SVC there traps back per-thread (via
    // tl_call_return_hit), so there is no cross-call or cross-worker address collision
    // to avoid, and nesting is handled by start()'s re-entrant run loop. call_depth is
    // still tracked because the safe-call stack chunk is selected by depth above.
    call_depth = next_call_depth;
    uint64_t ret_addr = CALL_RETURN_STUB_ADDR;
    qemu::write_reg(cpu, qemu::REG_LR, ret_addr);

    EMU_LOG_VERBOSE << "[EMU] call_function_internal: call_depth=" << call_depth
              << " ret_addr=0x" << std::hex << ret_addr << std::dec << std::endl;

    // Log key register values BEFORE the call for debugging
    if (is_safe && call_depth >= 2) {
        uint64_t x19 = qemu::read_reg(cpu, 19);  // X19 is callee-saved
        uint64_t x29 = qemu::read_reg(cpu, 29);  // X29/FP is frame pointer
        EMU_LOG_VERBOSE << "[EMU] BEFORE nested call: saved_sp=0x" << std::hex << saved_ctx.sp
                  << " saved_lr=0x" << saved_ctx.x[qemu::REG_LR]
                  << " saved_pc=0x" << saved_ctx.pc
                  << " X19=0x" << x19 << " X29(FP)=0x" << x29 << std::dec << std::endl;

        // Check critical stack address for corruption
        uint64_t critical_addr = 0x7ffffcb0;
        uint64_t critical_val = 0;
        memory_->read(critical_addr, &critical_val, 8);
        EMU_LOG_VERBOSE << "[EMU] BEFORE: [0x7ffffcb0]=0x" << std::hex << critical_val << std::dec << std::endl;
    }

    uint64_t entry_address = is_safe ? SAFE_CALL_TRAMPOLINE_ADDR : address;

    // Set PC to function address (or trampoline for nested safe calls)
    qemu::write_reg(cpu, qemu::REG_PC, entry_address);

    // Run emulation (TODO: implement proper execution loop)
    bool success = start(entry_address, ret_addr);
    call_depth--;
    uint64_t call_result = qemu::read_reg(cpu, qemu::REG_X0);

    // RESDIAG (fprintf = always visible): the storm hands back call_result==full-64-bit -1, which
    // the guest (32-bit int return) cannot produce. Capture the mechanism: success, how start()
    // exited, the cpu we read X0 from vs the current cpu, and X0 read from BOTH — if they differ,
    // the result read is off the wrong vCPU (MTTCG cross-cpu read); if equal & full -1, the guest
    // truly left X0 stale. Logged only for the pathological full -1 to avoid noise.
    if (call_result == static_cast<uint64_t>(-1)) {
        CPUState* now_cpu = libafl_qemu_current_cpu();
        uint64_t x0_now = now_cpu ? qemu::read_reg(now_cpu, qemu::REG_X0) : 0xBADBAD;
        int now_idx = now_cpu ? libafl_qemu_cpu_index(now_cpu) : -1;
        int cpu_idx = libafl_qemu_cpu_index(cpu);
        fprintf(stderr, "[RESDIAG] addr=0x%lx success=%d exit=%s tl_worker=%d cpu=%p(idx%d) "
                "cur=%p(idx%d) X0_cpu=0x%lx X0_cur=0x%lx\n",
                (unsigned long)address, (int)success, tl_start_exit_reason, tl_worker_id,
                (void*)cpu, cpu_idx, (void*)now_cpu, now_idx,
                (unsigned long)call_result, (unsigned long)x0_now);
    }

    // Diagnostic: a C->guest call's X0 is only the real guest return value when start() exited
    // via the call-return trampoline or end_address. Any other exit means start() bailed mid-call
    // and call_result (X0) is STALE — yet it is handed back as the result, surfacing e.g. as a
    // spurious GetSessionId=-1 (stale 0xffffffff) at the C# layer. The only other trace (the
    // run-loop "Breaking loop" line) is a release-suppressed EMU_LOG, so make this VISIBLE.
    if (std::strcmp(tl_start_exit_reason, "clean_return") != 0 &&
        std::strcmp(tl_start_exit_reason, "end_address") != 0) {
        EMU_ALWAYS_LOG << "[EMU][CALLDIAG] guest call @0x" << std::hex << address
                       << " exited start() abnormally (" << tl_start_exit_reason
                       << "); returning STALE X0=0x" << call_result << std::dec
                       << " depth=" << call_depth << std::endl;
    }

    // Log key register values AFTER the call for debugging
    if (is_safe && call_depth >= 1) {
        uint64_t x0_after = qemu::read_reg(cpu, qemu::REG_X0);
        uint64_t sp_after = qemu::read_reg(cpu, qemu::REG_SP);
        uint64_t x19_after = qemu::read_reg(cpu, 19);
        uint64_t x29_after = qemu::read_reg(cpu, 29);
        EMU_LOG_VERBOSE << "[EMU] AFTER nested call: X0=0x" << std::hex << x0_after
                  << " SP=0x" << sp_after << " X19=0x" << x19_after
                  << " X29(FP)=0x" << x29_after << std::dec << std::endl;

        // Check critical stack address for corruption
        uint64_t critical_addr = 0x7ffffcb0;
        uint64_t critical_val = 0;
        memory_->read(critical_addr, &critical_val, 8);
        EMU_LOG_VERBOSE << "[EMU] AFTER: [0x7ffffcb0]=0x" << std::hex << critical_val << std::dec << std::endl;
    }

    // Restore LR, PC, SP, and tl_running if safe call (so outer execution continues correctly)
    if (is_safe) {
        for (int reg = qemu::REG_X0; reg <= qemu::REG_X30; ++reg) {
            qemu::write_reg(cpu, reg, saved_ctx.x[reg]);
        }
        qemu::write_reg(cpu, qemu::REG_SP, saved_ctx.sp);
        qemu::write_reg(cpu, qemu::REG_PC, saved_ctx.pc);
        qemu::write_reg(cpu, qemu::REG_CPSR, saved_ctx.nzcv);
        qemu::write_reg(cpu, qemu::REG_TPIDR_EL0, saved_ctx.tpidr_el0);
        for (int reg = qemu::REG_V0; reg <= qemu::REG_V31; ++reg) {
            qemu::write_reg_bytes(cpu, reg, saved_ctx.v[reg - qemu::REG_V0],
                                  qemu::MAX_REGISTER_BYTES);
        }
        qemu::write_reg(cpu, qemu::REG_FPSR, saved_ctx.fpsr);
        qemu::write_reg(cpu, qemu::REG_FPCR, saved_ctx.fpcr);
        tl_running = saved_running;  // Thread-local: restore this thread's running state
    }

    if (!success) {
        EMU_LOG << "[EMU] call_function_internal FAILED for 0x" << std::hex
                  << address << std::dec << std::endl;
        return (uint64_t)-1;
    }

    return call_result;
}

// =============================================================================
// Library Loading (delegated to ElfLoader)
// =============================================================================

bool Emulator::load_library(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        EMU_LOG << "[EMU] Failed to open: " << path << std::endl;
        return false;
    }

    // Remember the main binary's path so dlopen() can search its directory for
    // bare sonames (the first load is the main program).
    if (first_binary_path_.empty()) {
        first_binary_path_ = path;
    }

    std::vector<uint8_t> data((std::istreambuf_iterator<char>(file)),
                               std::istreambuf_iterator<char>());

    size_t last_slash = path.find_last_of("/\\");
    std::string name = (last_slash == std::string::npos) ? path : path.substr(last_slash + 1);

    // QEMU is now initialized during Emulator construction
    // Just load the library into our managed memory
    return load_library(name, data);
}

bool Emulator::load_library(const std::string& name, const std::vector<uint8_t>& data) {
    EMU_LOG << "[EMU] Loading library: " << name << std::endl;

    // Parse ELF first
    if (!loader_->parse(data)) {
        EMU_LOG << "[EMU] Failed to parse ELF: " << name << std::endl;
        return false;
    }

    // Load ELF into memory
    LoadedModule module;
    module.name = name;
    module.data = data;

    if (!loader_->load(*memory_, next_load_addr_, module)) {
        EMU_LOG << "[EMU] Failed to load ELF: " << name << std::endl;
        return false;
    }

    next_load_addr_ = module.base_address + module.size;
    next_load_addr_ = (next_load_addr_ + 0xFFFFF) & ~0xFFFFFULL;  // Align to 1MB

    // The first module loaded is the main binary: record its host path so dlopen() can
    // search its directory for bare sonames. (Deterministic by load order, not basename.)
    if (modules_.empty() && !first_binary_path_.empty()) {
        module.path = first_binary_path_;
    }
    // Intern a guest-resident name string so dladdr() can return a valid dli_fname.
    module.guest_name_str = intern_guest_string(module.path.empty() ? name : module.path);

    // Process relocations using the shared import resolver (HLE -> globals -> module exports).
    auto resolver = [this](const std::string& sym_name) -> uint64_t {
        return resolve_import(sym_name);
    };
    if (!relocator_->process_relocations(*loader_, module.base_address, resolver)) {
        EMU_LOG << "[EMU] Failed to process relocations: " << name << std::endl;
        return false;
    }

    // Extract init_array functions for static constructors
    // These must be called before main() to register gtest tests, etc.
    auto [init_array_addr, init_array_size] = loader_->get_init_array_info();
    if (init_array_addr != 0 && init_array_size > 0) {
        // init_array_addr is relative to the file, needs to be adjusted for base address
        uint64_t min_vaddr = loader_->get_min_vaddr();
        uint64_t runtime_init_addr = init_array_addr - min_vaddr + module.base_address;

        size_t num_init_funcs = init_array_size / 8;  // Each entry is a 64-bit function pointer
        EMU_LOG << "[EMU] Found " << num_init_funcs << " init functions in init_array at 0x"
                << std::hex << runtime_init_addr << std::dec << std::endl;

        for (size_t i = 0; i < num_init_funcs; i++) {
            uint64_t func_ptr = 0;
            if (memory_->read(runtime_init_addr + i * 8, &func_ptr, 8)) {
                // Skip invalid function pointers
                if (func_ptr != 0 && func_ptr != static_cast<uint64_t>(-1)) {
                    EMU_LOG << "[EMU]   init[" << i << "] = 0x" << std::hex << func_ptr << std::dec << std::endl;
                    pending_init_funcs_.push_back(func_ptr);
                }
            }
        }
    }

    modules_.push_back(module);

    EMU_LOG << "[EMU] Loaded " << name << " at 0x" << std::hex
              << module.base_address << std::dec << std::endl;

    return true;
}

void Emulator::call_init_functions() {
    for (uint64_t init_addr : pending_init_funcs_) {
        EMU_LOG << "[EMU] Calling init function at 0x" << std::hex
                  << init_addr << std::dec << std::endl;
        call_function(init_addr, {});
    }
    pending_init_funcs_.clear();
}

uint64_t Emulator::get_symbol_nolock(const std::string& name) const {
    for (const auto& mod : modules_) {
        auto it = mod.exports.find(name);
        if (it != mod.exports.end()) {
            return it->second;
        }
    }

    auto it = global_symbols_.find(name);
    if (it != global_symbols_.end()) {
        return it->second;
    }

    // Fallback: full-symtab defined symbols (e.g. a PIE's local `main`, which is not
    // in .dynsym). Consulted after exports/globals so dynamic symbols win.
    for (const auto& mod : modules_) {
        auto lit = mod.local_symbols.find(name);
        if (lit != mod.local_symbols.end()) {
            return lit->second;
        }
    }
    return 0;
}

uint64_t Emulator::get_symbol(const std::string& name) const {
    std::shared_lock<std::shared_mutex> lk(modules_mutex_);
    uint64_t addr = get_symbol_nolock(name);
    if (addr != 0) {
        return addr;
    }

    // Diagnostic: a failed symbol lookup is the wrapper's ONLY source of a -1 return (e.g.
    // GetSessionId=-1). It should never happen for a loaded export. Log who/what failed:
    // emu=this distinguishes a phantom/unloaded Emulator instance from the loaded one;
    // modules/globals sizes reveal an empty (unloaded) table vs a present-but-missed symbol.
    EMU_ALWAYS_LOG << "[EMU][SYMDIAG] get_symbol(\"" << name << "\") -> 0 (NOT FOUND)"
                   << " emu=" << (const void*)this
                   << " modules=" << modules_.size()
                   << " globals=" << global_symbols_.size() << std::endl;
    return 0;
}

uint64_t Emulator::get_symbol_nolock(const std::string& module, const std::string& name) const {
    // Module-scoped lookup returns only EXPORTED symbols (matches the historical
    // behavior and the dlsym contract; local/.symtab symbols are not exposed here).
    for (const auto& mod : modules_) {
        if (mod.name == module) {
            auto it = mod.exports.find(name);
            if (it != mod.exports.end()) {
                return it->second;
            }
            return 0;
        }
    }
    return 0;
}

uint64_t Emulator::get_symbol(const std::string& module, const std::string& name) const {
    std::shared_lock<std::shared_mutex> lk(modules_mutex_);
    return get_symbol_nolock(module, name);
}

// ===========================================================================
// Dynamic loading (dlopen/dlsym/dlclose/dlerror/dladdr backends)
// ===========================================================================

// Per-thread last error, matching bionic's thread-local dlerror() semantics.
static thread_local std::string tl_dl_error;

uint64_t Emulator::resolve_import(const std::string& sym_name) const {
    // Strip version suffix (e.g., "calloc@LIBC" -> "calloc").
    std::string base_name = sym_name;
    size_t at_pos = sym_name.find('@');
    if (at_pos != std::string::npos) {
        base_name = sym_name.substr(0, at_pos);
    }

    // 1. HLE stubs first, so a loaded .so re-exporting a libc name cannot shadow HLE.
    uint64_t addr = hle_->get_stub_address(sym_name);
    if (addr != 0) return addr;
    if (base_name != sym_name) {
        addr = hle_->get_stub_address(base_name);
        if (addr != 0) return addr;
    }

    // 2. Emulator-synthesized global data symbols (__sF, environ, stdout, ...).
    auto it = global_symbols_.find(sym_name);
    if (it != global_symbols_.end()) return it->second;
    if (base_name != sym_name) {
        it = global_symbols_.find(base_name);
        if (it != global_symbols_.end()) return it->second;
    }

    // 3. Exports of already-loaded modules (lets a dlopen'd .so bind against them).
    for (const auto& mod : modules_) {
        auto exp_it = mod.exports.find(sym_name);
        if (exp_it != mod.exports.end()) return exp_it->second;
        if (base_name != sym_name) {
            exp_it = mod.exports.find(base_name);
            if (exp_it != mod.exports.end()) return exp_it->second;
        }
    }
    return 0;
}

const LoadedModule* Emulator::find_module_by_base(uint64_t base) const {
    for (const auto& mod : modules_) {
        if (mod.base_address == base) return &mod;
    }
    return nullptr;
}

std::string Emulator::resolve_library_path(const std::string& guest_path) const {
    auto readable = [](const std::string& p) {
        return !p.empty() && ::access(p.c_str(), R_OK) == 0;
    };

    // A path with a slash is explicit: translate guest->host then try as-is.
    if (guest_path.find('/') != std::string::npos) {
        std::string translated = translate_guest_host_path(guest_path);
        if (readable(translated)) return translated;
        if (readable(guest_path)) return guest_path;
        return "";
    }

    // Bare soname: search a list of directories.
    std::vector<std::string> dirs;
    auto add_dir_of = [&dirs](const std::string& file) {
        if (file.empty()) return;
        size_t s = file.find_last_of("/\\");
        dirs.push_back(s == std::string::npos ? std::string(".") : file.substr(0, s));
    };
    add_dir_of(first_binary_path_);                 // main binary's directory
    {
        std::shared_lock<std::shared_mutex> lk(modules_mutex_);
        for (const auto& mod : modules_) add_dir_of(mod.path);  // loaded modules' dirs
    }
    if (const char* llp = ::getenv("LD_LIBRARY_PATH")) {       // host LD_LIBRARY_PATH
        std::string s(llp), cur;
        for (char c : s) {
            if (c == ':') { if (!cur.empty()) dirs.push_back(cur); cur.clear(); }
            else cur.push_back(c);
        }
        if (!cur.empty()) dirs.push_back(cur);
    }
    dirs.push_back(".");                                        // host cwd

    for (const auto& d : dirs) {
        std::string cand = d + "/" + guest_path;
        if (readable(cand)) return cand;
    }
    return "";
}

bool Emulator::load_module_locked(const std::string& name, const std::string& host_path,
                                  const std::vector<uint8_t>& data,
                                  uint64_t& out_base, std::vector<uint64_t>& out_init_funcs) {
    if (!loader_->parse(data)) {
        EMU_LOG << "[EMU][dlopen] parse failed: " << name << std::endl;
        return false;
    }

    // Bound the arena BEFORE mapping. loader_->load() maps segments with MAP_FIXED, which
    // would overlay (clobber) the live guest heap if the module crossed HEAP_BASE. Reject
    // first, using the parsed virtual span, instead of detecting it after the damage.
    uint64_t span = loader_->get_memory_size();
    if (span == 0 ||
        next_load_addr_ + span < next_load_addr_ ||        // address overflow
        next_load_addr_ + span >= HEAP_BASE) {
        EMU_LOG << "[EMU][dlopen] module arena exhausted/oversized loading " << name
                << " (next=0x" << std::hex << next_load_addr_ << " span=0x" << span
                << " HEAP_BASE=0x" << HEAP_BASE << ")" << std::dec << std::endl;
        return false;
    }

    // Hard cap so modules_.push_back() never reallocates the vector. reserve(256) backs
    // this; a stable backing buffer keeps element addresses valid for concurrent readers.
    if (modules_.size() >= modules_.capacity()) {
        EMU_LOG << "[EMU][dlopen] module limit reached (" << modules_.capacity()
                << "); refusing to load " << name << std::endl;
        return false;
    }

    LoadedModule module;
    module.name = name;
    module.path = host_path;
    // module.data is intentionally NOT retained: the ELF is already parsed and the raw
    // bytes are never read after load; keeping a per-module copy wastes host RAM.

    if (!loader_->load(*memory_, next_load_addr_, module)) {
        EMU_LOG << "[EMU][dlopen] map/load failed: " << name << std::endl;
        return false;
    }
    next_load_addr_ = (module.base_address + module.size + 0xFFFFF) & ~0xFFFFFULL;

    auto resolver = [this](const std::string& sym) -> uint64_t { return resolve_import(sym); };
    if (!relocator_->process_relocations(*loader_, module.base_address, resolver)) {
        EMU_LOG << "[EMU][dlopen] relocation failed (unresolved symbol) in " << name << std::endl;
        return false;
    }

    // Collect this module's init_array (run by the caller, after the lock is released).
    auto [init_array_addr, init_array_size] = loader_->get_init_array_info();
    if (init_array_addr != 0 && init_array_size > 0) {
        uint64_t min_vaddr = loader_->get_min_vaddr();
        uint64_t runtime_init_addr = init_array_addr - min_vaddr + module.base_address;
        for (size_t i = 0; i < init_array_size / 8; i++) {
            uint64_t fp = 0;
            if (memory_->read(runtime_init_addr + i * 8, &fp, 8) &&
                fp != 0 && fp != static_cast<uint64_t>(-1)) {
                out_init_funcs.push_back(fp);
            }
        }
    }

    // Guest-resident copy of the path so dladdr() can return a valid dli_fname.
    module.guest_name_str = intern_guest_string(host_path);

    out_base = module.base_address;
    modules_.push_back(std::move(module));  // publish: exports now visible to dlsym + later loads
    return true;
}

uint64_t Emulator::dl_open(const std::string& guest_path, int flags) {
    constexpr int kRtldNoload = 0x00004;  // bionic RTLD_NOLOAD

    tl_dl_error.clear();  // a successful dlopen must not leave a stale error for dlerror()

    std::string host_path = resolve_library_path(guest_path);
    if (host_path.empty()) {
        tl_dl_error = "dlopen failed: cannot locate \"" + guest_path + "\"";
        return 0;
    }
    size_t slash = host_path.find_last_of("/\\");
    std::string base_name = (slash == std::string::npos) ? host_path : host_path.substr(slash + 1);

    uint64_t handle = 0;
    std::vector<uint64_t> init_funcs;
    {
        std::unique_lock<std::shared_mutex> lk(modules_mutex_);

        // Already loaded? Return the SAME handle and bump the refcount. Dedup on the
        // resolved host path; fall back to basename ONLY for modules with no recorded
        // path (startup-loaded libs), so two different files sharing a basename in
        // different directories are not wrongly aliased.
        for (const auto& mod : modules_) {
            if ((!mod.path.empty() && mod.path == host_path) ||
                (mod.path.empty() && mod.name == base_name)) {
                dl_refcounts_[mod.base_address]++;
                return mod.base_address;
            }
        }
        if (flags & kRtldNoload) {
            return 0;  // RTLD_NOLOAD: probe only, not present
        }

        std::ifstream f(host_path, std::ios::binary);
        if (!f) {
            tl_dl_error = "dlopen failed: cannot open \"" + host_path + "\"";
            return 0;
        }
        std::vector<uint8_t> data((std::istreambuf_iterator<char>(f)),
                                  std::istreambuf_iterator<char>());

        if (!load_module_locked(base_name, host_path, data, handle, init_funcs)) {
            tl_dl_error = "dlopen failed: could not load/relocate \"" + host_path + "\"";
            return 0;
        }
        dl_refcounts_[handle] = 1;

        // Queue a deferred (async) JIT flush. The freshly bump-allocated range has never
        // been executed, so there are no stale translation blocks to drop and correctness
        // does NOT depend on this draining before the constructors run. Kept defensive in
        // case the module arena is ever made to reuse a previously-executed range. Must
        // stay the async variant: a synchronous tb_flush under the unique lock could
        // rendezvous-deadlock against a vCPU parked in an HLE handler awaiting the lock.
        libafl_flush_jit();
    }

    // Run constructors AFTER releasing the lock: init_array re-enters guest code (which
    // takes the shared lock for symbol lookups) and may itself dlopen. call_function_safe
    // runs them in-place on the current worker vCPU's safe-call stack.
    for (uint64_t init_addr : init_funcs) {
        call_function_safe(init_addr, {});
    }
    return handle;
}

uint64_t Emulator::dl_sym(uint64_t handle, const std::string& name) {
    std::shared_lock<std::shared_mutex> lk(modules_mutex_);

    // RTLD_DEFAULT (0) / RTLD_NEXT (-1): global search (approximated as all modules).
    if (handle == 0 || handle == static_cast<uint64_t>(-1)) {
        uint64_t addr = get_symbol_nolock(name);
        if (addr != 0) return addr;
        // libc-style symbols live as HLE stubs, not in any module's exports.
        addr = hle_->get_stub_address(name);
        if (addr == 0) tl_dl_error = "dlsym: undefined symbol \"" + name + "\"";
        return addr;
    }

    const LoadedModule* mod = find_module_by_base(handle);
    if (!mod) {
        tl_dl_error = "dlsym: invalid handle";
        return 0;
    }
    // Only exported (default-visibility global/weak) symbols, per the dlsym contract.
    auto e = mod->exports.find(name);
    if (e != mod->exports.end()) return e->second;
    tl_dl_error = "dlsym: undefined symbol \"" + name + "\"";
    return 0;
}

int Emulator::dl_close(uint64_t handle) {
    std::unique_lock<std::shared_mutex> lk(modules_mutex_);
    auto it = dl_refcounts_.find(handle);
    if (it != dl_refcounts_.end() && it->second > 0) {
        it->second--;
    }
    // No real unload: the module stays mapped and its exports remain resolvable
    // (next_load_addr_ is a non-reclaiming bump pointer). Always report success.
    return 0;
}

std::string Emulator::dl_take_error() {
    std::string e = tl_dl_error;
    tl_dl_error.clear();
    return e;
}

int Emulator::dl_addr(uint64_t guest_addr, uint64_t info_ptr) {
    if (info_ptr == 0) return 0;
    std::shared_lock<std::shared_mutex> lk(modules_mutex_);
    for (const auto& mod : modules_) {
        if (guest_addr >= mod.base_address && guest_addr < mod.base_address + mod.size) {
            // The contract requires a valid dli_fname on success. If we have no
            // guest-resident path string for this module, report "not found" (return 0)
            // rather than success-with-NULL — a guest using info.dli_fname would otherwise
            // dereference NULL.
            if (mod.guest_name_str == 0) return 0;
            // Nearest preceding exported symbol address for dli_saddr (best effort).
            uint64_t best_addr = 0;
            for (const auto& kv : mod.exports) {
                if (kv.second <= guest_addr && kv.second >= best_addr) best_addr = kv.second;
            }
            // bionic Dl_info (LP64): { const char* dli_fname; void* dli_fbase;
            //                          const char* dli_sname; void* dli_saddr; }
            uint64_t dli_fname = mod.guest_name_str;
            uint64_t dli_fbase = mod.base_address;
            uint64_t dli_sname = 0;  // symbol-name string not interned into guest memory
            uint64_t dli_saddr = best_addr;
            bool ok = mem_write(info_ptr + 0,  &dli_fname, 8) &&
                      mem_write(info_ptr + 8,  &dli_fbase, 8) &&
                      mem_write(info_ptr + 16, &dli_sname, 8) &&
                      mem_write(info_ptr + 24, &dli_saddr, 8);
            return ok ? 1 : 0;
        }
    }
    return 0;
}

// Allocate a NUL-terminated guest-resident copy of a host string (for dladdr dli_fname).
uint64_t Emulator::intern_guest_string(const std::string& s) {
    uint64_t addr = memory_->allocate_guest_memory(s.size() + 1, 1);
    if (addr != 0) {
        memory_->write(addr, s.c_str(), s.size() + 1);
    }
    return addr;
}

// Locked accessors so callers outside the Emulator can read modules_ without racing a
// concurrent dlopen push_back (the raw modules() accessor is startup-only).
std::string Emulator::module_name_containing(uint64_t addr) const {
    std::shared_lock<std::shared_mutex> lk(modules_mutex_);
    for (const auto& mod : modules_) {
        if (addr >= mod.base_address && addr < mod.base_address + mod.size) {
            return mod.name;
        }
    }
    return "";
}

uint64_t Emulator::main_module_base() const {
    std::shared_lock<std::shared_mutex> lk(modules_mutex_);
    return modules_.empty() ? 0 : modules_.front().base_address;
}

void Emulator::hook_hle_functions_at_addresses() {
    auto should_skip_direct_hook = [](const std::string& name) {
        static const std::unordered_set<std::string> skipped_names = {
            "accept",
            "accept4",
            "bind",
            "clock_nanosleep",
            "connect",
            "epoll_create",
            "epoll_create1",
            "epoll_ctl",
            "epoll_pwait",
            "epoll_wait",
            "getpeername",
            "getsockname",
            "getsockopt",
            "listen",
            "nanosleep",
            "poll",
            "ppoll",
            "ppoll64",
            "pselect",
            "recvfrom",
            "recvmsg",
            "select",
            "sendmsg",
            "sendto",
            "setsockopt",
            "shutdown",
            "sleep",
            "socket",
            "usleep",
        };
        return skipped_names.find(name) != skipped_names.end();
    };

    // Hook HLE functions in loaded libraries
    for (const auto& mod : modules_) {
        for (const auto& exp : mod.exports) {
            std::string base_name = exp.first;
            size_t at_pos = base_name.find('@');
            if (at_pos != std::string::npos) {
                base_name = base_name.substr(0, at_pos);
            }

            if (should_skip_direct_hook(base_name)) {
                continue;
            }

            if (hle_->has_hle(exp.first)) {
                hle_->register_address_for_function(exp.second, exp.first);
            } else if (base_name != exp.first && hle_->has_hle(base_name)) {
                hle_->register_address_for_function(exp.second, base_name);
            }
        }
    }
}

uint64_t Emulator::allocate_hle_stub(const std::string& name) {
    return hle_->get_stub_address(name);
}

} // namespace cross_shim
