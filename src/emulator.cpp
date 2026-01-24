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

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <set>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <sys/mman.h>
#include <thread>
#include <unistd.h>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <signal.h>
#include <execinfo.h>
#include <cxxabi.h>

// Path to QEMU stub binary
static const char* QEMU_STUB_PATH = nullptr;

// QEMU's thread-local CPU variables - defined in QEMU
// current_cpu: general purpose current CPU
// thread_cpu: the thread-local CPU used by signal handlers - THIS IS THE ONE WE NEED
extern "C" {
extern __thread CPUState* current_cpu;
extern __thread CPUState* thread_cpu;  // Used by host_signal_handler!
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

static std::atomic<bool> g_in_signal_handler{false};

// Store QEMU's original handlers for all signals
static struct sigaction g_qemu_handlers[64];
static bool g_handlers_wrapped = false;

// Universal signal handler wrapper
static void universal_signal_wrapper(int sig, siginfo_t* info, void* context) {
    // Always log that we're in the wrapper - this proves we're being called
    {
        char msg[64];
        snprintf(msg, sizeof(msg), "[WRAPPER-CALLED] sig=%d thread_cpu=%p\n", sig, (void*)thread_cpu);
        (void)write(STDERR_FILENO, msg, strlen(msg));
    }

    // Debug: signal-safe write to stderr
    static const char* sig_names[] = {"?", "HUP", "INT", "QUIT", "ILL", "TRAP", "ABRT", "BUS", "FPE", "KILL", "USR1", "SEGV"};
    const char* sig_name = (sig >= 0 && sig <= 11) ? sig_names[sig] : "?";

    // CRITICAL: Check thread_cpu (NOT current_cpu!) BEFORE doing anything that might crash
    // QEMU's host_signal_handler uses thread_cpu which is different from current_cpu!
    if (thread_cpu == nullptr) {
        // This is a non-QEMU thread (e.g., .NET runtime thread).
        // We CANNOT forward to QEMU's handler as it will crash.
        char msg[128];
        snprintf(msg, sizeof(msg), "[SIGNAL-WRAPPER] sig=%d (%s) on non-QEMU thread (thread_cpu=NULL), blocking\n", sig, sig_name);
        (void)write(STDERR_FILENO, msg, strlen(msg));

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

// Library constructor - runs BEFORE main() when the library is loaded
// This is critical because we need to block signals on the main thread
// BEFORE .NET spawns any worker threads (which inherit the signal mask)
__attribute__((constructor))
static void library_init() {
    // Block signals on the main thread - all child threads will inherit this
    block_signals_on_host_threads();
}

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
        std::cerr.flush();
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

    // Check common locations
    const char* locations[] = {
        // Relative to working directory
        "stubs/qemu_stub",
        "../stubs/qemu_stub",
        "../../stubs/qemu_stub",
        // Relative to binary
        "../CrossShim/stubs/qemu_stub",
        "../../CrossShim/stubs/qemu_stub",
        // Absolute path fallback
        "/mnt/ExtraSSD/src/WyzeBridgeDotNet/CrossShim/stubs/qemu_stub",
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

// Global emulator pointer for hook callbacks
static Emulator* g_emulator = nullptr;

// Thread-local CPU pointer for HLE calls
static thread_local CPUState* tls_cpu = nullptr;

// Get the current CPU for this thread
CPUState* get_current_cpu(Emulator& emu) {
    // First try QEMU's current CPU for this host thread
    // This is the most reliable way to get the correct CPU in MTTCG mode
    // where each guest thread runs on a separate host thread
    CPUState* cpu = libafl_qemu_current_cpu();
    if (cpu != nullptr) {
        return cpu;
    }
    // Fall back to thread-local CPU if set
    if (tls_cpu != nullptr) {
        return tls_cpu;
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
void notify_thread_exit(uint64_t sp, uint64_t retval);

// Custom syscall numbers for thread lifecycle
static constexpr int SYS_THREAD_DONE = 0x1234;
static constexpr int SYS_THREAD_START = 0x1235;  // Debug marker
static constexpr int SYS_CLONE_DEBUG = 0x1236;   // Debug after clone

// HLE syscall base and mapping (defined in allocate_stub, used in pre_syscall_hook)
static constexpr int HLE_SYSCALL_BASE = 0x2000;
static std::unordered_map<int, uint64_t> g_hle_syscall_to_addr;
static std::atomic<int> g_next_hle_syscall{HLE_SYSCALL_BASE};

// CRITICAL FIX: Thread-local running flag to prevent race conditions
// Each thread (main thread and child threads created via clone) needs its own
// execution state flag. The old shared running_ caused races where a child
// thread finishing its start() call would set running_=false and terminate
// the main thread's execution loop prematurely.
static thread_local bool tl_running = false;

// CRITICAL FIX: Mutex for HLE handler serialization
// This provides the same synchronization that verbose logging provides
// (via EMU_LOG's mutex) without the performance overhead of actual logging.
// Using a separate recursive_mutex to avoid deadlock with EMU_LOG.
static std::recursive_mutex g_hle_sync_mutex;

static libafl_syshook_ret pre_syscall_hook(
    uint64_t data, int sys_num,
    uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3,
    uint64_t arg4, uint64_t arg5, uint64_t arg6, uint64_t arg7) {

    Emulator* emu = reinterpret_cast<Emulator*>(data);
    libafl_syshook_ret ret;

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
    uint64_t hook_sp = qemu::read_reg(hook_cpu, qemu::REG_SP);
    uint64_t hook_pc = qemu::read_reg(hook_cpu, qemu::REG_PC);

    // Only log child thread syscalls (SP in 0x90xxxxxx range) or debug syscalls
    bool is_child_thread = (hook_sp >= 0x90000000 && hook_sp < 0x91000000);
    bool is_debug_syscall = (sys_num == SYS_THREAD_DONE || sys_num == SYS_THREAD_START || sys_num == SYS_CLONE_DEBUG);
    // Also log network-related syscalls (socket=198, connect=203, bind=200, sendto=206, recvfrom=207)
    bool is_network_syscall = (sys_num == 198 || sys_num == 200 || sys_num == 203 || sys_num == 206 || sys_num == 207);
    // Log HLE syscalls from child threads
    bool is_hle_syscall = (sys_num >= 0x2000 && sys_num < 0x3000);

    if (is_child_thread) {
        EMU_LOG_VERBOSE << "[CHILD_SYSCALL] #" << std::hex << sys_num << " SP=0x" << hook_sp
                  << " PC=0x" << hook_pc << std::dec << std::endl;
    } else if (is_debug_syscall || sys_num == 220 || sys_num == 93 || is_network_syscall) {
        EMU_LOG_VERBOSE << "[SYSCALL] #" << sys_num << " SP=0x" << std::hex << hook_sp
                  << " PC=0x" << hook_pc
                  << " (args: " << arg0 << ", " << arg1 << ", " << arg2
                  << ", " << arg3 << ", " << arg4 << ", " << arg5 << ")" << std::dec << std::endl;
    }

    // Handle debug after clone marker
    if (sys_num == SYS_CLONE_DEBUG) {
        CPUState* cpu = libafl_qemu_current_cpu();
        uint64_t sp = qemu::read_reg(cpu, qemu::REG_SP);
        uint64_t pc = qemu::read_reg(cpu, qemu::REG_PC);
        uint64_t lr = qemu::read_reg(cpu, qemu::REG_LR);
        uint64_t x0 = qemu::read_reg(cpu, qemu::REG_X0);
        EMU_LOG << "[SYSCALL] SYS_CLONE_DEBUG: After clone! SP=0x" << std::hex << sp
                  << " PC=0x" << pc << " LR=0x" << lr << " X0=0x" << x0 << std::dec << std::endl;
        ret.tag = LIBAFL_SYSHOOK_SKIP;
        ret.syshook_skip_retval = 0;
        return ret;
    }

    // Handle debug thread start marker
    if (sys_num == SYS_THREAD_START) {
        CPUState* cpu = libafl_qemu_current_cpu();
        uint64_t sp = qemu::read_reg(cpu, qemu::REG_SP);
        uint64_t pc = qemu::read_reg(cpu, qemu::REG_PC);
        // Read start_routine and arg from stack
        uint64_t start_routine = 0, arg = 0;
        cpu_memory_rw_debug(cpu, sp, &start_routine, 8, 0);
        cpu_memory_rw_debug(cpu, sp + 8, &arg, 8, 0);
        EMU_LOG << "[SYSCALL] SYS_THREAD_START: Child thread starting! SP=0x"
                  << std::hex << sp << " PC=0x" << pc
                  << " start_routine=0x" << start_routine
                  << " arg=0x" << arg << std::dec << std::endl;
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
        notify_thread_exit(sp, retval);

        // Return 0 (success)
        ret.tag = LIBAFL_SYSHOOK_SKIP;
        ret.syshook_skip_retval = 0;
        return ret;
    }

    // Handle HLE syscalls (0x2000-0x2FFF range)
    // These are generated by HLE stubs to trigger HLE function execution
    if (sys_num >= 0x2000 && sys_num < 0x3000) {
        auto it = g_hle_syscall_to_addr.find(sys_num);
        if (it != g_hle_syscall_to_addr.end()) {
            uint64_t hle_addr = it->second;

            // CRITICAL FIX: Cache the CPU pointer ONCE at the start
            // Multiple calls to libafl_qemu_current_cpu() in MTTCG mode may race
            CPUState* cached_cpu = hook_cpu;  // Already obtained at line 355

            // Log child thread HLE syscalls for debugging
            if (is_child_thread) {
                EMU_LOG_VERBOSE << "[HLE_SYSCALL] Child thread: #0x" << std::hex << sys_num
                          << " -> addr=0x" << hle_addr << " SP=0x" << hook_sp
                          << std::dec << std::endl;
            }

            // Call the HLE handler with cached CPU
            // NOTE: HLE handlers run on whichever thread triggered them. With MTTCG,
            // multiple threads can call HLE handlers simultaneously. Each handler must
            // be internally thread-safe. Don't use g_hle_sync_mutex here as it causes
            // deadlock when blocking HLE calls (like usleep) prevent other threads.
            emu->hle().handle_with_cpu(cached_cpu, hle_addr);

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

    // Syscalls that QEMU must handle natively (threading, process control, synchronization)
    // 93 = exit, 94 = exit_group, 220 = clone, 221 = execve
    // 96 = set_tid_address, 99 = set_robust_list
    // 98 = futex (CRITICAL for MTTCG multi-threaded synchronization!)
    // 261 = prlimit64, 435 = clone3
    if (sys_num == 93 /* SYS_exit */ ||
        sys_num == 94 /* SYS_exit_group */ ||
        sys_num == 98 /* SYS_futex - CRITICAL for MTTCG threading! */ ||
        sys_num == 220 /* SYS_clone */ ||
        sys_num == 435 /* SYS_clone3 */ ||
        sys_num == 96 /* SYS_set_tid_address */ ||
        sys_num == 99 /* SYS_set_robust_list */) {
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
        EMU_LOG << "[HLE] WARNING: No callback registered for " << name << std::endl;
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
        return 0;
    }

    // Allocate new stub for this HLE function
    uint64_t addr = allocate_stub(name);
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
        EMU_LOG << "[HLE] WARNING: No callback for '" << it->second
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

// HLE call counter - no per-call locking overhead
static std::atomic<uint64_t> g_hle_total_calls{0};

bool HleManager::handle_with_cpu(void *cpu_ptr, uint64_t address) {
    auto it = address_to_name_.find(address);
    if (it == address_to_name_.end()) {
        return false;
    }

    auto cb_it = callbacks_.find(it->second);
    if (cb_it == callbacks_.end()) {
        EMU_LOG << "[HLE] WARNING: No callback for '" << it->second
                  << "' at 0x" << std::hex << address << std::dec << std::endl;
        return false;
    }

    // CRITICAL FIX: Use the provided CPU pointer directly without calling
    // libafl_qemu_current_cpu() which may race in MTTCG mode
    CPUState* old_tls = tls_cpu;
    tls_cpu = static_cast<CPUState*>(cpu_ptr);

    cb_it->second(emu_);

    tls_cpu = old_tls;

    // Simple counter - no locking
    uint64_t total_calls = ++g_hle_total_calls;
    if (total_calls % 50000 == 0) {
        EMU_LOG << "[HLE-STATS] Total HLE calls: " << total_calls << std::endl;
    }

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
    uint64_t addr = next_stub_addr_;
    // Each stub is 12 bytes: MOV X8, #N; SVC #0; RET
    next_stub_addr_ += 12;

    stub_addresses_[name] = addr;
    address_to_name_[addr] = name;

    // Allocate a syscall number for this HLE function
    int syscall_num = g_next_hle_syscall.fetch_add(1);
    g_hle_syscall_to_addr[syscall_num] = addr;

    // Log stub allocation for debugging
    // EMU_LOG << "[HLE_ALLOC] " << name << " at 0x" << std::hex << addr
    //           << " syscall=0x" << syscall_num << std::dec << std::endl;

    write_stub(addr, syscall_num);
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
    memory_.write(address, code, sizeof(code));
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
      debug_enabled_(config.enable_debug) {
    initialize();
}

Emulator::~Emulator() {
    // Stop emulator background thread
    stop_emulator_thread();

    // Destroy thread manager first
    threads_.reset();

    // Note: QEMU cleanup is handled by the library
}

void Emulator::initialize() {
    // Set global emulator pointer for callbacks
    g_emulator = this;

    // Create memory manager (doesn't depend on QEMU yet)
    memory_ = std::make_unique<MemoryManager>(nullptr);

    // Allocate memory regions in host memory first
    // These will be synced to QEMU's guest space after init
    memory_->map(0, HLE_BASE, MEM_READ | MEM_WRITE | MEM_EXEC, "LowMemory");
    memory_->map(HLE_BASE, HLE_SIZE, MEM_READ | MEM_EXEC, "HLE");
    memory_->map(STACK_BASE - config_.stack_size, config_.stack_size,
                 MEM_READ | MEM_WRITE, "Stack");
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
        EMU_LOG << "[EMU] WARNING: Failed to write RET at address 0" << std::endl;
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
        EMU_LOG << "[EMU] WARNING: Failed to write MSR TPIDR_EL0 instruction" << std::endl;
    }
    if (!memory_->write(tls_init_addr + 4, &ret_insn, sizeof(ret_insn))) {
        EMU_LOG << "[EMU] WARNING: Failed to write RET after MSR" << std::endl;
    }
    tls_init_addr_ = tls_init_addr;

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
        EMU_LOG << "[EMU] ERROR: Cannot find QEMU stub binary" << std::endl;
        EMU_LOG << "[EMU] Please run: CrossShim/stubs/build_stub.sh" << std::endl;
        throw std::runtime_error("QEMU stub not found");
    }

    EMU_LOG << "[EMU] Initializing QEMU with stub: " << stub_path << std::endl;
    const char* argv[] = {"qemu-aarch64", stub_path, nullptr};
    libafl_qemu_init(2, const_cast<char**>(argv));

    // Get CPU
    cpu_ = libafl_qemu_get_cpu(0);
    if (!cpu_) {
        EMU_LOG << "[EMU] ERROR: No CPU after QEMU init" << std::endl;
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

    // CRITICAL: Wrap QEMU's signal handlers AFTER QEMU has installed them
    // This protects non-QEMU threads (like .NET runtime) from crashes
    wrap_qemu_signal_handlers();

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

    global_symbols_["__sF"] = sf_addr;
}

// Block counter for periodic yielding
static thread_local uint64_t g_block_count = 0;
static constexpr uint64_t BLOCKS_PER_YIELD = 1000000;  // Yield every 1M blocks

// Block execution hook - forces periodic yields
static uint64_t block_pre_gen(uint64_t data, uint64_t pc) {
    // Return a unique ID for this block (we use the PC)
    return pc;
}

static void block_post_gen(uint64_t data, uint64_t pc, uint64_t block_length) {
    // Not used
}

static void block_exec(uint64_t data, uint64_t id) {
    // DISABLED: With QEMU MTTCG (multi-threaded TCG), threads run in parallel
    // on real host threads. The periodic yield mechanism is not needed and
    // calling libafl_exit_request_crash() can interfere with thread execution.
    //
    // Old cooperative threading code:
    // g_block_count++;
    // if (g_block_count >= BLOCKS_PER_YIELD) {
    //     g_block_count = 0;
    //     CPUState* cpu = libafl_qemu_current_cpu();
    //     if (cpu) {
    //         libafl_exit_request_crash(cpu);
    //     }
    // }
}

void Emulator::setup_hooks() {
    // Configure QEMU to return on crashes/traps instead of exiting
    // This allows us to handle BRK instructions (HLE traps) gracefully
    libafl_set_return_on_crash(true);

    // Add syscall hook
    syscall_hook_id_ = libafl_add_pre_syscall_hook(pre_syscall_hook,
                                                    reinterpret_cast<uint64_t>(this));

    // Add block execution hook for periodic yielding
    block_hook_id_ = libafl_add_block_hook(block_pre_gen, block_post_gen, block_exec,
                                            reinterpret_cast<uint64_t>(this));

    EMU_LOG << "[EMU] Registered syscall hook (id=" << syscall_hook_id_ << ")" << std::endl;
    EMU_LOG << "[EMU] Registered block hook for periodic yielding (id=" << block_hook_id_ << ")" << std::endl;
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

// Profiling for start() - tracks where time is spent in emulation
static std::atomic<uint64_t> g_start_count{0};
static std::atomic<uint64_t> g_total_setup_ns{0};
static std::atomic<uint64_t> g_total_qemu_run_ns{0};
static std::atomic<uint64_t> g_total_loop_iterations{0};
static std::chrono::steady_clock::time_point g_last_start_report = std::chrono::steady_clock::now();

bool Emulator::start(uint64_t address, uint64_t end_address) {
    auto start_time = std::chrono::steady_clock::now();

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
        EMU_LOG << "[EMU] ERROR: No CPU for start()" << std::endl;
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
    if (sp == 0 || sp < STACK_BASE - config_.stack_size || sp > STACK_BASE) {
        // Initialize stack pointer to top of stack
        sp = STACK_BASE - 16;  // Leave room at top
        qemu::write_reg(cpu, qemu::REG_SP, sp);
        EMU_LOG << "[EMU] Set SP to 0x" << std::hex << sp << std::dec << std::endl;
    }

    // Set up a breakpoint at the end address so we stop there
    if (end_address != 0) {
        libafl_qemu_set_breakpoint(end_address);
    }

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

        // Debug iterations - show more progress
        EMU_LOG_VERBOSE << "[EMU] Loop " << loop_count << ": result=" << result
                      << " PC=0x" << std::hex << current_pc
                      << " end=0x" << end_address << std::dec << std::endl;
        loop_count++;
        // Safety check for infinite loops
        if (loop_count > 10000) {
            EMU_LOG << "[EMU] WARNING: Loop count exceeded 10000, may be stuck" << std::endl;
        }

        // Check if we hit the end address
        if (end_address != 0 && current_pc == end_address) {
            uint64_t x0 = qemu::read_reg(cur_cpu, qemu::REG_X0);
            uint64_t lr = qemu::read_reg(cur_cpu, qemu::REG_LR);
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

    // Remove the breakpoint if we set one
    if (end_address != 0) {
        libafl_qemu_remove_breakpoint(end_address);
    }

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

    // Update profiling stats
    auto end_time = std::chrono::steady_clock::now();
    uint64_t total_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(end_time - start_time).count();
    g_start_count.fetch_add(1, std::memory_order_relaxed);
    g_total_qemu_run_ns.fetch_add(total_ns, std::memory_order_relaxed);
    g_total_loop_iterations.fetch_add(loop_count, std::memory_order_relaxed);

    // Report stats every 5 seconds
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
            std::cerr << "[EMU_START_PROFILE] " << count << " starts in " << since_report << "s"
                      << " (" << std::fixed << std::setprecision(1) << calls_per_sec << "/s)"
                      << " avg=" << avg_us << "us avg_loops=" << avg_loops << std::endl;
        }
        g_last_start_report = now;
    }

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

    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        request_cv_.notify_all();
    }

    emulator_thread_.join();
    EMU_LOG << "[EMU] Emulator background thread stopped" << std::endl;
}

void Emulator::emulator_thread_func() {
    emulator_thread_id_ = std::this_thread::get_id();
    EMU_LOG << "[EMU] Emulator thread started" << std::endl;

    // If QEMU is not yet initialized, we need to initialize it on this thread
    // This is critical: libafl_qemu_run() must be called from the same thread
    // that called libafl_qemu_init()
    if (!qemu_initialized_) {
        EMU_LOG << "[EMU] Initializing QEMU from emulator thread..." << std::endl;
        initialize_qemu_on_this_thread();
        EMU_LOG << "[EMU] QEMU initialized on emulator thread" << std::endl;
    }

    // No need to register with TCG - we ARE the main QEMU thread now

    while (!should_stop_) {
        std::shared_ptr<FunctionRequest> request;

        {
            std::unique_lock<std::mutex> lock(queue_mutex_);
            request_cv_.wait(lock, [this] {
                return !request_queue_.empty() || should_stop_;
            });

            if (should_stop_) break;

            if (!request_queue_.empty()) {
                request = request_queue_.front();
                request_queue_.pop();
            }
        }

        if (request) {
            uint64_t result = call_function_internal(request->address, request->args,
                                                      request->is_safe_call);
            {
                std::lock_guard<std::mutex> lock(request->mutex);
                request->result = result;
                request->completed = true;
            }
            request->cv.notify_one();
        }
    }

    EMU_LOG << "[EMU] Emulator thread exiting" << std::endl;
}

// Profiling stats for call_function
static std::atomic<uint64_t> g_call_count{0};
static std::atomic<uint64_t> g_total_queue_wait_ns{0};
static std::atomic<uint64_t> g_total_exec_ns{0};
static std::atomic<uint64_t> g_max_queue_wait_ns{0};
static std::atomic<uint64_t> g_max_exec_ns{0};
static std::chrono::steady_clock::time_point g_last_profile_report = std::chrono::steady_clock::now();

uint64_t Emulator::call_function(uint64_t address, const std::vector<uint64_t>& args) {
    if (std::this_thread::get_id() == emulator_thread_id_) {
        return call_function_internal(address, args, false);
    }

    auto request = std::make_shared<FunctionRequest>();
    request->address = address;
    request->args = args;
    request->completed = false;
    request->is_safe_call = false;

    // Record submit time for profiling
    auto submit_time = std::chrono::steady_clock::now();

    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        request_queue_.push(request);
    }
    request_cv_.notify_one();

    {
        std::unique_lock<std::mutex> lock(request->mutex);
        request->cv.wait(lock, [&request] { return request->completed; });
    }

    // Calculate timing
    auto end_time = std::chrono::steady_clock::now();
    uint64_t total_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(end_time - submit_time).count();

    // Update stats atomically
    g_call_count.fetch_add(1, std::memory_order_relaxed);
    g_total_exec_ns.fetch_add(total_ns, std::memory_order_relaxed);

    // Update max (CAS loop)
    uint64_t current_max = g_max_exec_ns.load(std::memory_order_relaxed);
    while (total_ns > current_max &&
           !g_max_exec_ns.compare_exchange_weak(current_max, total_ns, std::memory_order_relaxed));

    // Report stats every 5 seconds
    auto now = std::chrono::steady_clock::now();
    auto since_report = std::chrono::duration_cast<std::chrono::seconds>(now - g_last_profile_report).count();
    if (since_report >= 5) {
        uint64_t count = g_call_count.exchange(0, std::memory_order_relaxed);
        uint64_t total = g_total_exec_ns.exchange(0, std::memory_order_relaxed);
        uint64_t max_exec = g_max_exec_ns.exchange(0, std::memory_order_relaxed);

        if (count > 0) {
            double avg_us = (double)total / count / 1000.0;
            double max_us = max_exec / 1000.0;
            double calls_per_sec = (double)count / since_report;
            std::cerr << "[EMU_PROFILE] " << count << " calls in " << since_report << "s"
                      << " (" << std::fixed << std::setprecision(1) << calls_per_sec << "/s)"
                      << " avg=" << avg_us << "us max=" << max_us << "us" << std::endl;
        }
        g_last_profile_report = now;
    }

    return request->result;
}

uint64_t Emulator::call_function_safe(uint64_t address, const std::vector<uint64_t>& args) {
    // If we're on the thread currently running QEMU (either background or direct),
    // call internal directly to avoid deadlock
    if (std::this_thread::get_id() == current_execution_thread_id_ ||
        std::this_thread::get_id() == emulator_thread_id_) {
        return call_function_internal(address, args, true);
    }

    auto request = std::make_shared<FunctionRequest>();
    request->address = address;
    request->args = args;
    request->completed = false;
    request->is_safe_call = true;

    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        request_queue_.push(request);
    }
    request_cv_.notify_one();

    {
        std::unique_lock<std::mutex> lock(request->mutex);
        request->cv.wait(lock, [&request] { return request->completed; });
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
                                           bool is_safe) {
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
        EMU_LOG << "[EMU] ERROR: No CPU available for call_function" << std::endl;
        return (uint64_t)-1;
    }

    // Set up arguments in X0-X7
    static const int kArgRegs[8] = {
        qemu::REG_X0, qemu::REG_X1, qemu::REG_X2, qemu::REG_X3,
        qemu::REG_X4, qemu::REG_X5, qemu::REG_X6, qemu::REG_X7
    };

    for (size_t i = 0; i < args.size() && i < 8; i++) {
        qemu::write_reg(cpu, kArgRegs[i], args[i]);
    }

    // Handle stack arguments
    if (args.size() > 8) {
        uint64_t sp = qemu::read_reg(cpu, qemu::REG_SP);
        for (size_t i = 8; i < args.size(); i++) {
            uint64_t stack_addr = sp + (i - 8) * 8;
            memory_->write(stack_addr, &args[i], 8);
        }
    }

    // Save registers and state if this is a safe call (nested call from HLE handler)
    // CRITICAL: We must save and restore SP because nested calls use the stack,
    // and the outer function expects SP to be at the same position when it resumes.
    uint64_t saved_lr = 0;
    uint64_t saved_pc = 0;
    uint64_t saved_sp = 0;
    bool saved_running = tl_running;  // Thread-local: save this thread's running state
    if (is_safe) {
        saved_lr = qemu::read_reg(cpu, qemu::REG_LR);
        saved_pc = qemu::read_reg(cpu, qemu::REG_PC);
        saved_sp = qemu::read_reg(cpu, qemu::REG_SP);
    }

    // Use unique return address for each call level to support nested calls
    // Each nested call gets a different ret_addr so the inner call doesn't
    // prematurely terminate the outer call when it returns.
    // NOTE: We must avoid addresses that conflict with HLE trampolines:
    //   0x100ffff0-0x100ffffc are used for thread exit/resume trampolines
    // So we use 0x100fff00 - call_depth*4 to stay safely below those addresses.
    static thread_local int call_depth = 0;
    call_depth++;
    uint64_t ret_addr = HLE_BASE + 0xFFF00 - (call_depth * 4);
    qemu::write_reg(cpu, qemu::REG_LR, ret_addr);

    EMU_LOG_VERBOSE << "[EMU] call_function_internal: call_depth=" << call_depth
              << " ret_addr=0x" << std::hex << ret_addr << std::dec << std::endl;

    // Log key register values BEFORE the call for debugging
    if (is_safe && call_depth >= 2) {
        uint64_t x19 = qemu::read_reg(cpu, 19);  // X19 is callee-saved
        uint64_t x29 = qemu::read_reg(cpu, 29);  // X29/FP is frame pointer
        EMU_LOG_VERBOSE << "[EMU] BEFORE nested call: saved_sp=0x" << std::hex << saved_sp
                  << " saved_lr=0x" << saved_lr << " saved_pc=0x" << saved_pc
                  << " X19=0x" << x19 << " X29(FP)=0x" << x29 << std::dec << std::endl;

        // Check critical stack address for corruption
        uint64_t critical_addr = 0x7ffffcb0;
        uint64_t critical_val = 0;
        memory_->read(critical_addr, &critical_val, 8);
        EMU_LOG_VERBOSE << "[EMU] BEFORE: [0x7ffffcb0]=0x" << std::hex << critical_val << std::dec << std::endl;
    }

    // Set PC to function address
    qemu::write_reg(cpu, qemu::REG_PC, address);

    // Run emulation (TODO: implement proper execution loop)
    bool success = start(address, ret_addr);
    call_depth--;

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
        qemu::write_reg(cpu, qemu::REG_LR, saved_lr);
        qemu::write_reg(cpu, qemu::REG_PC, saved_pc);
        qemu::write_reg(cpu, qemu::REG_SP, saved_sp);  // CRITICAL: Restore SP for outer function
        tl_running = saved_running;  // Thread-local: restore this thread's running state
    }

    if (!success) {
        EMU_LOG << "[EMU] call_function_internal FAILED for 0x" << std::hex
                  << address << std::dec << std::endl;
        return (uint64_t)-1;
    }

    return qemu::read_reg(cpu, qemu::REG_X0);
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

    // Process relocations using a symbol resolver
    auto resolver = [this](const std::string& sym_name) -> uint64_t {
        // Strip version suffix (e.g., "calloc@LIBC" -> "calloc")
        std::string base_name = sym_name;
        size_t at_pos = sym_name.find('@');
        if (at_pos != std::string::npos) {
            base_name = sym_name.substr(0, at_pos);
        }

        // First check HLE hooks (try both full name and base name)
        uint64_t addr = hle_->get_stub_address(sym_name);
        if (addr != 0) {
            if (base_name == "calloc" || base_name == "epoll_create" || base_name == "memset" ||
                base_name == "pthread_create") {
                EMU_LOG << "[RELOC] Resolved " << sym_name << " to HLE at 0x"
                          << std::hex << addr << std::dec << std::endl;
            }
            return addr;
        }
        if (base_name != sym_name) {
            addr = hle_->get_stub_address(base_name);
            if (addr != 0) {
                if (base_name == "calloc" || base_name == "epoll_create" || base_name == "memset" ||
                    base_name == "pthread_create") {
                    EMU_LOG << "[RELOC] Resolved " << sym_name << " via base_name " << base_name
                              << " to HLE at 0x" << std::hex << addr << std::dec << std::endl;
                }
                return addr;
            }
        }

        // Then check global symbols
        auto it = global_symbols_.find(sym_name);
        if (it != global_symbols_.end()) return it->second;
        if (base_name != sym_name) {
            it = global_symbols_.find(base_name);
            if (it != global_symbols_.end()) return it->second;
        }

        // Finally check exports from already-loaded libraries
        for (const auto& mod : modules_) {
            auto exp_it = mod.exports.find(sym_name);
            if (exp_it != mod.exports.end()) {
                return exp_it->second;
            }
            if (base_name != sym_name) {
                exp_it = mod.exports.find(base_name);
                if (exp_it != mod.exports.end()) {
                    return exp_it->second;
                }
            }
        }

        // Debug: log unresolved symbols that look like tutk_platform functions
        if (sym_name.find("tutk_platform") != std::string::npos) {
            EMU_LOG << "[RELOC] WARNING: Could not resolve " << sym_name
                      << " - checking " << modules_.size() << " modules" << std::endl;
            for (const auto& mod : modules_) {
                EMU_LOG << "[RELOC]   Module " << mod.name << " has "
                          << mod.exports.size() << " exports" << std::endl;
            }
        }

        return 0;
    };
    if (!relocator_->process_relocations(*loader_, module.base_address, resolver)) {
        EMU_LOG << "[EMU] Failed to process relocations: " << name << std::endl;
        return false;
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

uint64_t Emulator::get_symbol(const std::string& name) const {
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

    return 0;
}

uint64_t Emulator::get_symbol(const std::string& module, const std::string& name) const {
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

void Emulator::hook_hle_functions_at_addresses() {
    // Hook HLE functions in loaded libraries
    for (const auto& mod : modules_) {
        for (const auto& exp : mod.exports) {
            if (hle_->has_hle(exp.first)) {
                hle_->register_address_for_function(exp.second, exp.first);
            }
        }
    }
}

uint64_t Emulator::allocate_hle_stub(const std::string& name) {
    return hle_->get_stub_address(name);
}

} // namespace cross_shim
