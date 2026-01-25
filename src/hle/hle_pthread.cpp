/**
 * HLE Pthread Functions
 *
 * This module provides High-Level Emulation for pthread functions.
 *
 * Threading Model (QEMU-native):
 * - pthread_create spawns a real host thread
 * - Each host thread runs its own QEMU execution loop
 * - Mutexes use real std::mutex for proper locking
 * - Condition variables use real std::condition_variable
 * - Thread-local storage is managed per-thread in guest memory
 */

#include "debug_log.h"
#include "hle_manager.h"
#include "cross_shim.h"
#include "memory_manager.h"
#include "qemu_api.h"
#include "emu_compat.h"
#include <cstring>
#include <iostream>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <unordered_map>
#include <atomic>
#include <chrono>
#include <cerrno>
#include <ctime>

namespace cross_shim {

// get_reg and set_reg are provided by emu_compat.h

// Trace logging for pthread debugging
static std::atomic<int> g_cond_wait_count{0};
static std::atomic<int> g_cond_signal_count{0};
static std::atomic<int> g_mutex_lock_count{0};
static std::atomic<int> g_mutex_unlock_count{0};
static constexpr bool TRACE_PTHREAD_SYNC = false; // Disabled to reduce overhead

// =============================================================================
// QEMU-Native Threading Infrastructure
// =============================================================================

// Thread state for QEMU-native threads
// With QEMU native clone, threads run in QEMU's thread infrastructure
struct QemuThread {
    uint64_t thread_id;
    uint64_t start_routine;
    uint64_t arg;
    uint64_t stack_base;
    uint64_t stack_size;
    uint64_t tls_base;

    // Thread completion tracking
    std::atomic<bool> started{false};
    std::atomic<bool> completed{false};
    uint64_t return_value{0};

    // For pthread_join to wait on completion
    std::mutex join_mutex;
    std::condition_variable join_cv;
};

// Global thread registry
static std::mutex g_threads_mutex;
static std::unordered_map<uint64_t, std::unique_ptr<QemuThread>> g_threads;
static std::atomic<uint64_t> g_next_thread_id{0x1000};

// Thread-local current thread ID
static thread_local uint64_t tl_current_thread_id = 0;

// =============================================================================
// QEMU-Native Mutex/Condvar Infrastructure
// =============================================================================
// With QEMU MTTCG, threads run in parallel on real host threads.
// We use real host std::mutex and std::condition_variable for synchronization.

// Recursive mutex to support recursive locking patterns
struct HostMutex {
    std::recursive_mutex mtx;
    std::atomic<uint64_t> owner_thread{0};
    std::atomic<int> lock_count{0};
};

// Map guest mutex address -> host mutex
static std::mutex g_mutexes_lock;
static std::unordered_map<uint64_t, std::shared_ptr<HostMutex>> g_host_mutexes;

// Get or create a host mutex for a guest mutex address
// Returns shared_ptr to keep mutex alive while in use
static std::shared_ptr<HostMutex> get_or_create_mutex(uint64_t guest_mutex_addr) {
    // Defensive check for obviously invalid addresses
    if (guest_mutex_addr == 0 || guest_mutex_addr < 0x1000) {
        static auto dummy_mutex = std::make_shared<HostMutex>();
        return dummy_mutex;
    }

    std::lock_guard<std::mutex> lock(g_mutexes_lock);
    try {
        auto it = g_host_mutexes.find(guest_mutex_addr);
        if (it == g_host_mutexes.end()) {
            auto mtx = std::make_shared<HostMutex>();
            g_host_mutexes[guest_mutex_addr] = mtx;
            return mtx;
        }
        return it->second;
    } catch (...) {
        // If something goes wrong, return a dummy mutex to avoid crashes
        static auto fallback_mutex = std::make_shared<HostMutex>();
        return fallback_mutex;
    }
}

// Map guest condvar address -> host condition variable + associated mutex
struct HostCondVar {
    std::condition_variable_any cv;
};

static std::mutex g_condvars_lock;
static std::unordered_map<uint64_t, std::shared_ptr<HostCondVar>> g_host_condvars;

// Returns shared_ptr to keep condvar alive while in use
static std::shared_ptr<HostCondVar> get_or_create_condvar(uint64_t guest_cond_addr) {
    // Defensive check for obviously invalid addresses
    if (guest_cond_addr == 0 || guest_cond_addr < 0x1000) {
        static auto dummy_cv = std::make_shared<HostCondVar>();
        return dummy_cv;
    }

    std::lock_guard<std::mutex> lock(g_condvars_lock);
    try {
        auto it = g_host_condvars.find(guest_cond_addr);
        if (it == g_host_condvars.end()) {
            auto cv = std::make_shared<HostCondVar>();
            g_host_condvars[guest_cond_addr] = cv;
            return cv;
        }
        return it->second;
    } catch (...) {
        static auto fallback_cv = std::make_shared<HostCondVar>();
        return fallback_cv;
    }
}

// =============================================================================
// QEMU-Native RWLock Infrastructure (for MTTCG)
// =============================================================================
// Using pthread_rwlock_t for native reader-writer lock semantics
// This properly handles unlock() for both read and write locks

#include <pthread.h>

struct HostRWLock {
    pthread_rwlock_t rwlock;
    bool initialized{false};

    HostRWLock() {
        pthread_rwlock_init(&rwlock, nullptr);
        initialized = true;
    }

    ~HostRWLock() {
        if (initialized) {
            pthread_rwlock_destroy(&rwlock);
        }
    }
};

static std::mutex g_rwlocks_lock;
static std::unordered_map<uint64_t, std::shared_ptr<HostRWLock>> g_host_rwlocks;

// Returns a shared_ptr that keeps the rwlock alive while in use
static std::shared_ptr<HostRWLock> get_or_create_rwlock(uint64_t guest_rwlock_addr) {
    // Defensive check for obviously invalid addresses
    if (guest_rwlock_addr == 0 || guest_rwlock_addr < 0x1000) {
        static auto dummy_rwl = std::make_shared<HostRWLock>();
        return dummy_rwl;
    }

    std::lock_guard<std::mutex> lock(g_rwlocks_lock);
    try {
        auto it = g_host_rwlocks.find(guest_rwlock_addr);
        if (it == g_host_rwlocks.end()) {
            auto rwl = std::make_shared<HostRWLock>();
            g_host_rwlocks[guest_rwlock_addr] = rwl;
            return rwl;
        }
        return it->second;
    } catch (...) {
        static auto fallback_rwl = std::make_shared<HostRWLock>();
        return fallback_rwl;
    }
}

static void destroy_rwlock(uint64_t guest_rwlock_addr) {
    std::lock_guard<std::mutex> lock(g_rwlocks_lock);
    g_host_rwlocks.erase(guest_rwlock_addr);
}

// =============================================================================
// QEMU-Native TLS Infrastructure (for MTTCG)
// =============================================================================
// Thread-local storage using thread-id based indexing

static std::mutex g_tls_mutex;
static std::unordered_map<uint64_t, uint64_t> g_tls_destructors;  // key -> destructor
static std::unordered_map<uint64_t, std::unordered_map<uint64_t, uint64_t>> g_tls_values;  // thread_id -> (key -> value)
static std::atomic<uint64_t> g_next_tls_key{1};

// =============================================================================
// QEMU-Native Barrier Infrastructure (for MTTCG)
// =============================================================================
// Using pthread_barrier_t for native barrier semantics

struct HostBarrier {
    pthread_barrier_t barrier;
    bool initialized{false};

    HostBarrier(unsigned int count) {
        pthread_barrier_init(&barrier, nullptr, count);
        initialized = true;
    }

    ~HostBarrier() {
        if (initialized) {
            pthread_barrier_destroy(&barrier);
        }
    }
};

static std::mutex g_barriers_lock;
static std::unordered_map<uint64_t, std::unique_ptr<HostBarrier>> g_host_barriers;

static HostBarrier* get_or_create_barrier(uint64_t guest_barrier_addr, unsigned int count) {
    std::lock_guard<std::mutex> lock(g_barriers_lock);
    auto it = g_host_barriers.find(guest_barrier_addr);
    if (it == g_host_barriers.end()) {
        auto b = std::make_unique<HostBarrier>(count);
        auto* ptr = b.get();
        g_host_barriers[guest_barrier_addr] = std::move(b);
        return ptr;
    }
    return it->second.get();
}

static void destroy_barrier(uint64_t guest_barrier_addr) {
    std::lock_guard<std::mutex> lock(g_barriers_lock);
    g_host_barriers.erase(guest_barrier_addr);
}

// Constants for thread memory allocation (defined early so get_thread_id_from_sp can use them)
static constexpr uint64_t QEMU_THREAD_STACK_SIZE = 0x100000;  // 1MB stack
static constexpr uint64_t QEMU_THREAD_TLS_SIZE = 0x10000;     // 64KB TLS
static constexpr uint64_t QEMU_THREAD_STACK_BASE = 0x90000000;
static constexpr uint64_t QEMU_THREAD_TLS_BASE = 0xD0000000;

// =============================================================================
// Thread ID helper (get current thread ID from SP)
// =============================================================================
static uint64_t get_thread_id_from_sp(uint64_t sp) {
    // Main thread uses stack in 0x7f800000 range
    if (sp >= 0x7f800000 && sp < 0x80000000) {
        return 0;  // Main thread
    }
    // Worker threads use stacks at 0x90000000+
    if (sp >= QEMU_THREAD_STACK_BASE) {
        uint64_t offset = sp - QEMU_THREAD_STACK_BASE;
        uint64_t thread_index = offset / QEMU_THREAD_STACK_SIZE;
        return 0x1000 + thread_index;
    }
    return 0;  // Unknown - assume main thread
}
static std::atomic<uint64_t> g_next_stack_addr{QEMU_THREAD_STACK_BASE};
static std::atomic<uint64_t> g_next_tls_addr{QEMU_THREAD_TLS_BASE};

// Thread exit address - special HLE address that terminates thread
static constexpr uint64_t THREAD_EXIT_ADDR = 0x100FFFF0;

// Allocate stack for a new thread
static uint64_t allocate_thread_stack(Emulator& emu) {
    uint64_t addr = g_next_stack_addr.fetch_add(QEMU_THREAD_STACK_SIZE);
    emu.memory().map(addr, QEMU_THREAD_STACK_SIZE, MEM_READ | MEM_WRITE);
    return addr + QEMU_THREAD_STACK_SIZE - 0x100;  // Return top of stack minus some space
}

// Allocate TLS for a new thread
static uint64_t allocate_thread_tls(Emulator& emu) {
    uint64_t addr = g_next_tls_addr.fetch_add(QEMU_THREAD_TLS_SIZE);
    emu.memory().map(addr, QEMU_THREAD_TLS_SIZE, MEM_READ | MEM_WRITE);

    // Initialize TLS with stack canary at offset 0x28
    uint64_t canary = 0xDEADBEEFCAFEBABEULL;
    emu.mem_write(addr + 0x28, &canary, sizeof(canary));
    emu.mem_write(addr + 0x30, &canary, sizeof(canary));

    // Return TLS base + 8 (the value for TPIDR_EL0)
    return addr + 8;
}

// Clone trampoline addresses
static constexpr uint64_t CLONE_TRAMPOLINE_ADDR = 0x10080000;
static constexpr uint64_t THREAD_WRAPPER_ADDR = 0x10080100;
static constexpr uint64_t THREAD_DONE_HLE_ADDR = 0x10010000;  // HLE callback before exit (unused now)

// Custom syscall number for thread completion notification
// This is handled by our syscall hook and works for all threads (including children)
static constexpr uint64_t SYS_THREAD_DONE = 0x1234;

// Forward declaration for thread exit notification
void notify_thread_exit(uint64_t tls_base, uint64_t retval);

// Store thread arguments on the child's stack:
// [SP+0]: start_routine
// [SP+8]: arg
// [SP+16]: thread_id (for identification)

// Write the clone trampoline and thread wrapper code to memory
// This is called once during initialization
static bool g_trampoline_written = false;

static void write_thread_wrapper(Emulator& emu) {
    if (g_trampoline_written) return;
    g_trampoline_written = true;

    // Thread wrapper code at THREAD_WRAPPER_ADDR
    // This is where the child thread starts after clone()
    // Stack layout: [SP+0]=start_routine, [SP+8]=arg
    //
    // Code:
    //   MOV X8, #0x1235        // Debug syscall to confirm child reached wrapper
    //   SVC #0                 // triggers syscall hook
    //   LDP X2, X3, [SP]       // X2=start_routine, X3=arg
    //   MOV X0, X3             // arg -> first parameter
    //   BLR X2                 // call start_routine(arg)
    //   // X0 now has return value from start_routine
    //   MOV X8, #0x1234        // Custom syscall (SYS_THREAD_DONE)
    //   SVC #0                 // triggers syscall hook to notify completion
    //   MOV X8, #93            // SYS_exit
    //   SVC #0                 // exit(0)

    // MOVZ Xd, #imm16 encoding: 0xD2800000 | (imm16 << 5) | Rd
    // MOVZ X8, #0x1235 = 0xD2800008 | (0x1235 << 5) = 0xD28246A8
    // MOVZ X8, #0x1234 = 0xD2800008 | (0x1234 << 5) = 0xD2824688
    // MOVZ X8, #93     = 0xD2800008 | (93 << 5)     = 0xD2800BA8
    uint32_t wrapper_code[] = {
        0xD28246A8,  // MOV X8, #0x1235   (SYS_THREAD_START - debug marker)
        0xD4000001,  // SVC #0            (debug syscall)
        0xA9400FE2,  // LDP X2, X3, [SP]  (X2=start_routine, X3=arg)
        0xAA0303E0,  // MOV X0, X3        (arg -> X0, first parameter)
        0xD63F0040,  // BLR X2            (call start_routine(arg))
        0xD2824688,  // MOV X8, #0x1234   (SYS_THREAD_DONE)
        0xD4000001,  // SVC #0            (custom syscall to notify thread done)
        0xD2800BA8,  // MOV X8, #93       (SYS_exit)
        0xD4000001,  // SVC #0            (exit syscall)
    };

    emu.mem_write(THREAD_WRAPPER_ADDR, wrapper_code, sizeof(wrapper_code));
    EMU_LOG << "[HLE] Thread wrapper written at 0x" << std::hex
              << THREAD_WRAPPER_ADDR << std::dec << std::endl;

    // Clone trampoline at CLONE_TRAMPOLINE_ADDR
    // This executes the clone syscall and branches appropriately
    // Registers set up by caller:
    //   X0 = flags, X1 = child_stack, X2 = parent_tid, X3 = tls, X4 = child_tid
    //   X8 = 220 (SYS_clone)
    //
    // Simplified code - child just immediately does debug syscall after clone:
    //   0x00: SVC #0                 // clone syscall
    //   0x04: CBNZ X0, parent        // if X0 != 0 (parent), jump to RET
    //   0x08: MOV X8, #0x1236        // Child: debug syscall
    //   0x0C: SVC #0
    //   0x10: B THREAD_WRAPPER       // child: jump to thread wrapper
    //   0x14: RET                    // parent returns
    //
    // B instruction at CLONE_TRAMPOLINE_ADDR + 0x10 = 0x10080010
    // Target: THREAD_WRAPPER_ADDR = 0x10080100
    // Offset = (0x10080100 - 0x10080010) / 4 = 0xF0 / 4 = 0x3C words

    // CBNZ X0, #5 means: if X0 != 0, branch to PC + (5 * 4) = PC + 20 bytes
    // From CBNZ at offset 0x04: target = 0x04 + 0x14 = 0x18 = MOV X0, #0
    // CBNZ X0, #5 encoding: sf=1 (64-bit) | 011010 | 1 | imm19=5 | Rt=0 = 0xB50000A0
    uint32_t trampoline_code[] = {
        0xD4000001,  // 0x00: SVC #0            (clone syscall)
        0xB50000A0,  // 0x04: CBNZ X0, +5       (if parent, jump to MOV at 0x18)
        0xD28246C8,  // 0x08: MOV X8, #0x1236   (SYS_CLONE_DEBUG - child only)
        0xD4000001,  // 0x0C: SVC #0            (debug syscall)
        0x1400003C,  // 0x10: B +0x3C           (child: jump to THREAD_WRAPPER_ADDR)
        0x00000000,  // 0x14: (padding - not reached)
        0xD2800000,  // 0x18: MOV X0, #0        (parent: pthread_create returns 0)
        0xD65F03C0,  // 0x1C: RET               (parent returns)
    };

    emu.mem_write(CLONE_TRAMPOLINE_ADDR, trampoline_code, sizeof(trampoline_code));
    EMU_LOG << "[HLE] Clone trampoline written at 0x" << std::hex
              << CLONE_TRAMPOLINE_ADDR << std::dec << std::endl;
}

void register_hle_pthread(HleManager& hle) {
    // ========================================================================
    // Thread completion callback (called before thread exits)
    // ========================================================================

    hle.register_function("__thread_done", [](Emulator& emu) {
        // Get the return value (in X0) and TLS base
        uint64_t retval = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t tls_base = get_reg(emu, UC_ARM64_REG_TPIDR_EL0);

        EMU_LOG << "[HLE] __thread_done: TLS=0x" << std::hex << tls_base
                  << " retval=0x" << retval << std::dec << std::endl;

        // Notify that this thread is done
        notify_thread_exit(tls_base, retval);

        // Return normally - the wrapper will then call exit()
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    // Register __thread_done at THREAD_DONE_HLE_ADDR
    // This is called when write_thread_wrapper writes the BRK instruction there
    hle.register_address_for_function(THREAD_DONE_HLE_ADDR, "__thread_done");

    // ========================================================================
    // Mutex attribute operations
    // ========================================================================

    hle.register_function("pthread_mutexattr_init", [](Emulator& emu) {
        uint64_t attr = get_reg(emu, UC_ARM64_REG_X0);
        // Initialize attr to zeros
        uint64_t zero = 0;
        emu.mem_write(attr, &zero, 8);
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("pthread_mutexattr_destroy", [](Emulator& emu) {
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("pthread_mutexattr_settype", [](Emulator& emu) {
        uint64_t attr = get_reg(emu, UC_ARM64_REG_X0);
        int type = static_cast<int>(get_reg(emu, UC_ARM64_REG_X1));
        // Store type at offset 4 in attr
        emu.mem_write(attr + 4, &type, sizeof(type));
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("pthread_mutexattr_gettype", [](Emulator& emu) {
        uint64_t attr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t type_ptr = get_reg(emu, UC_ARM64_REG_X1);
        int type = 0;
        emu.mem_read(attr + 4, &type, sizeof(type));
        emu.mem_write(type_ptr, &type, sizeof(type));
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    // ========================================================================
    // Mutex operations - use HOST mutexes for QEMU MTTCG
    // ========================================================================
    // With QEMU MTTCG, threads run in parallel on real host threads.
    // We use real std::recursive_mutex for proper blocking behavior.

    hle.register_function("pthread_mutex_init", [](Emulator& emu) {
        uint64_t mutex = get_reg(emu, UC_ARM64_REG_X0);
        // Just ensure the mutex exists in our map (lazy creation on first lock is fine too)
        get_or_create_mutex(mutex);
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("pthread_mutex_destroy", [](Emulator& emu) {
        uint64_t mutex = get_reg(emu, UC_ARM64_REG_X0);
        {
            std::lock_guard<std::mutex> lock(g_mutexes_lock);
            g_host_mutexes.erase(mutex);
        }
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("pthread_mutex_lock", [](Emulator& emu) {
        uint64_t mutex_addr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t sp = get_reg(emu, UC_ARM64_REG_SP);
        uint64_t tid = get_thread_id_from_sp(sp);

        int call_num = ++g_mutex_lock_count;
        auto start_time = std::chrono::steady_clock::now();

        if (emu.is_debug()) {
            EMU_LOG << "[HLE:T" << std::hex << tid << "] pthread_mutex_lock: mutex=0x"
                      << mutex_addr << " SP=0x" << sp << std::dec << std::endl;
        }

        // Handle NULL mutex - return EINVAL
        if (mutex_addr == 0) {
            if (emu.is_debug()) {
                EMU_LOG << "[HLE:T" << std::hex << tid << "] pthread_mutex_lock: NULL mutex, returning EINVAL" << std::dec << std::endl;
            }
            set_reg(emu, UC_ARM64_REG_X0, EINVAL);
            return;
        }

        // Get or create the host mutex and lock it
        // This will BLOCK the host thread until the mutex is available
        auto mtx = get_or_create_mutex(mutex_addr);
        mtx->mtx.lock();
        mtx->owner_thread.store(tid);
        mtx->lock_count++;

        auto end_time = std::chrono::steady_clock::now();
        auto duration_us = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time).count();

        // Log long lock acquisitions or periodically
        if (TRACE_PTHREAD_SYNC && (call_num <= 20 || call_num % 1000 == 0 || duration_us > 10000)) {
            EMU_LOG << "[SYNC-TRACE] mutex_lock #" << call_num << " tid=0x" << std::hex << tid
                    << " mutex=0x" << mutex_addr << std::dec << " wait=" << duration_us << "us" << std::endl;
        }

        if (emu.is_debug()) {
            EMU_LOG << "[HLE:T" << std::hex << tid << "] pthread_mutex_lock: acquired mutex=0x"
                      << mutex_addr << std::dec << std::endl;
        }
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("pthread_mutex_trylock", [](Emulator& emu) {
        uint64_t mutex_addr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t sp = get_reg(emu, UC_ARM64_REG_SP);
        uint64_t tid = get_thread_id_from_sp(sp);

        if (mutex_addr == 0) {
            set_reg(emu, UC_ARM64_REG_X0, EINVAL);
            return;
        }

        auto mtx = get_or_create_mutex(mutex_addr);
        if (mtx->mtx.try_lock()) {
            mtx->owner_thread.store(tid);
            mtx->lock_count++;
            set_reg(emu, UC_ARM64_REG_X0, 0);  // Success
        } else {
            set_reg(emu, UC_ARM64_REG_X0, EBUSY);  // Already locked
        }
    });

    hle.register_function("pthread_mutex_unlock", [](Emulator& emu) {
        uint64_t mutex_addr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t sp = get_reg(emu, UC_ARM64_REG_SP);
        uint64_t tid = get_thread_id_from_sp(sp);

        if (emu.is_debug()) {
            EMU_LOG << "[HLE:T" << std::hex << tid << "] pthread_mutex_unlock: mutex=0x"
                      << mutex_addr << std::dec << std::endl;
        }

        if (mutex_addr == 0) {
            set_reg(emu, UC_ARM64_REG_X0, EINVAL);
            return;
        }

        auto mtx = get_or_create_mutex(mutex_addr);
        mtx->lock_count--;
        mtx->mtx.unlock();

        if (emu.is_debug()) {
            EMU_LOG << "[HLE:T" << std::hex << tid << "] pthread_mutex_unlock: released mutex=0x"
                      << mutex_addr << std::dec << std::endl;
        }
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    // ========================================================================
    // Condition variable attribute operations
    // ========================================================================

    hle.register_function("pthread_condattr_init", [](Emulator& emu) {
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("pthread_condattr_destroy", [](Emulator& emu) {
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    // ========================================================================
    // Condition variable operations - use HOST condvars for QEMU MTTCG
    // ========================================================================

    hle.register_function("pthread_cond_init", [](Emulator& emu) {
        uint64_t cond = get_reg(emu, UC_ARM64_REG_X0);
        get_or_create_condvar(cond);
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("pthread_cond_destroy", [](Emulator& emu) {
        uint64_t cond = get_reg(emu, UC_ARM64_REG_X0);
        {
            std::lock_guard<std::mutex> lock(g_condvars_lock);
            g_host_condvars.erase(cond);
        }
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("pthread_cond_wait", [](Emulator& emu) {
        uint64_t cond_addr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t mutex_addr = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t sp = get_reg(emu, UC_ARM64_REG_SP);
        uint64_t tid = get_thread_id_from_sp(sp);

        int call_num = ++g_cond_wait_count;
        if (TRACE_PTHREAD_SYNC && (call_num <= 20 || call_num % 100 == 0)) {
            EMU_LOG << "[SYNC-TRACE] cond_wait ENTER #" << call_num << " cond=0x"
                    << std::hex << cond_addr << " mutex=0x" << mutex_addr
                    << " tid=0x" << tid << std::dec << std::endl;
        }

        auto cv = get_or_create_condvar(cond_addr);
        auto mtx = get_or_create_mutex(mutex_addr);

        // Wait on the condition variable (releases mutex, waits, reacquires)
        cv->cv.wait(mtx->mtx);

        if (TRACE_PTHREAD_SYNC && (call_num <= 20 || call_num % 100 == 0)) {
            EMU_LOG << "[SYNC-TRACE] cond_wait EXIT #" << call_num << std::endl;
        }

        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("pthread_cond_timedwait", [](Emulator& emu) {
        uint64_t cond_addr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t mutex_addr = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t abstime_ptr = get_reg(emu, UC_ARM64_REG_X2);
        uint64_t sp = get_reg(emu, UC_ARM64_REG_SP);
        uint64_t tid = get_thread_id_from_sp(sp);

        // Read timespec from guest memory
        struct timespec ts;
        emu.mem_read(abstime_ptr, &ts, sizeof(ts));

        if (emu.is_debug()) {
            EMU_LOG << "[HLE:T" << std::hex << tid << "] pthread_cond_timedwait: cond=0x"
                      << cond_addr << " mutex=0x" << mutex_addr
                      << " timeout=" << std::dec << ts.tv_sec << "s " << ts.tv_nsec << "ns" << std::endl;
        }

        auto cv = get_or_create_condvar(cond_addr);
        auto mtx = get_or_create_mutex(mutex_addr);

        // Convert timespec to time_point
        auto deadline = std::chrono::system_clock::from_time_t(ts.tv_sec)
                       + std::chrono::nanoseconds(ts.tv_nsec);

        // Wait with timeout
        if (cv->cv.wait_until(mtx->mtx, deadline) == std::cv_status::timeout) {
            set_reg(emu, UC_ARM64_REG_X0, ETIMEDOUT);
        } else {
            set_reg(emu, UC_ARM64_REG_X0, 0);
        }
    });

    hle.register_function("pthread_cond_signal", [](Emulator& emu) {
        uint64_t cond_addr = get_reg(emu, UC_ARM64_REG_X0);
        int call_num = ++g_cond_signal_count;
        if (TRACE_PTHREAD_SYNC && (call_num <= 20 || call_num % 100 == 0)) {
            EMU_LOG << "[SYNC-TRACE] cond_signal #" << call_num
                    << " cond=0x" << std::hex << cond_addr << std::dec << std::endl;
        }
        auto cv = get_or_create_condvar(cond_addr);
        cv->cv.notify_one();
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    static std::atomic<int> g_cond_broadcast_count{0};
    hle.register_function("pthread_cond_broadcast", [](Emulator& emu) {
        uint64_t cond_addr = get_reg(emu, UC_ARM64_REG_X0);
        int call_num = ++g_cond_broadcast_count;
        if (TRACE_PTHREAD_SYNC && (call_num <= 20 || call_num % 100 == 0)) {
            EMU_LOG << "[SYNC-TRACE] cond_broadcast #" << call_num
                    << " cond=0x" << std::hex << cond_addr << std::dec << std::endl;
        }
        auto cv = get_or_create_condvar(cond_addr);
        cv->cv.notify_all();
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    // ========================================================================
    // Read-write lock operations - native implementation for MTTCG
    // ========================================================================

    hle.register_function("pthread_rwlock_init", [](Emulator& emu) {
        uint64_t rwlock_addr = get_reg(emu, UC_ARM64_REG_X0);
        (void)get_reg(emu, UC_ARM64_REG_X1);  // attr - ignored
        get_or_create_rwlock(rwlock_addr);
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("pthread_rwlock_destroy", [](Emulator& emu) {
        uint64_t rwlock_addr = get_reg(emu, UC_ARM64_REG_X0);
        destroy_rwlock(rwlock_addr);
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("pthread_rwlock_rdlock", [](Emulator& emu) {
        uint64_t rwlock_addr = get_reg(emu, UC_ARM64_REG_X0);
        auto rwl = get_or_create_rwlock(rwlock_addr);
        int result = pthread_rwlock_rdlock(&rwl->rwlock);
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("pthread_rwlock_wrlock", [](Emulator& emu) {
        uint64_t rwlock_addr = get_reg(emu, UC_ARM64_REG_X0);
        auto rwl = get_or_create_rwlock(rwlock_addr);
        int result = pthread_rwlock_wrlock(&rwl->rwlock);
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("pthread_rwlock_unlock", [](Emulator& emu) {
        uint64_t rwlock_addr = get_reg(emu, UC_ARM64_REG_X0);
        auto rwl = get_or_create_rwlock(rwlock_addr);
        int result = pthread_rwlock_unlock(&rwl->rwlock);
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("pthread_rwlock_tryrdlock", [](Emulator& emu) {
        uint64_t rwlock_addr = get_reg(emu, UC_ARM64_REG_X0);
        auto rwl = get_or_create_rwlock(rwlock_addr);
        int result = pthread_rwlock_tryrdlock(&rwl->rwlock);
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("pthread_rwlock_trywrlock", [](Emulator& emu) {
        uint64_t rwlock_addr = get_reg(emu, UC_ARM64_REG_X0);
        auto rwl = get_or_create_rwlock(rwlock_addr);
        int result = pthread_rwlock_trywrlock(&rwl->rwlock);
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // ========================================================================
    // Thread operations - use ThreadManager
    // ========================================================================
    
    hle.register_function("pthread_create", [](Emulator& emu) {
        uint64_t thread_ptr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t attr = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t start_routine = get_reg(emu, UC_ARM64_REG_X2);
        uint64_t arg = get_reg(emu, UC_ARM64_REG_X3);
        uint64_t caller_lr = get_reg(emu, UC_ARM64_REG_LR);
        (void)attr;

        EMU_LOG << "[HLE] pthread_create: caller_lr=0x" << std::hex << caller_lr
                  << " routine=0x" << start_routine << std::dec << std::endl;

        if (start_routine == 0) {
            EMU_LOG << "[HLE] pthread_create: ERROR - null routine!" << std::endl;
            set_reg(emu, UC_ARM64_REG_X0, 22);  // EINVAL
            return;
        }

        // Ensure trampoline code is written to guest memory
        write_thread_wrapper(emu);

        // Allocate thread ID
        uint64_t thread_id = g_next_thread_id.fetch_add(1);

        // Allocate stack for new thread
        uint64_t child_stack_top = allocate_thread_stack(emu);
        uint64_t tls_base = allocate_thread_tls(emu);

        // Store start_routine and arg at child's stack
        // Stack layout: [SP+0]=start_routine, [SP+8]=arg
        emu.mem_write(child_stack_top, &start_routine, sizeof(start_routine));
        emu.mem_write(child_stack_top + 8, &arg, sizeof(arg));

        EMU_LOG << "[HLE] pthread_create: Creating thread " << thread_id
                  << " routine=0x" << std::hex << start_routine
                  << " arg=0x" << arg
                  << " child_stack=0x" << child_stack_top
                  << " tls=0x" << tls_base << std::dec << std::endl;

        // Store thread ID in user's pointer (use thread_id as pthread_t)
        if (thread_ptr != 0) {
            emu.mem_write(thread_ptr, &thread_id, sizeof(thread_id));
        }

        // Save the caller's return address - we'll need to return here after clone
        // (caller_lr already retrieved above for debug logging)

        // Register thread info for later (pthread_join)
        {
            auto thread = std::make_unique<QemuThread>();
            thread->thread_id = thread_id;
            thread->start_routine = start_routine;
            thread->arg = arg;
            thread->stack_base = child_stack_top;
            thread->stack_size = QEMU_THREAD_STACK_SIZE;
            thread->tls_base = tls_base;
            thread->started.store(true);

            std::lock_guard<std::mutex> lock(g_threads_mutex);
            g_threads[thread_id] = std::move(thread);
        }

        // Set up clone syscall parameters
        // ARM64 clone: x0=flags, x1=stack, x2=parent_tid, x3=tls, x4=child_tid
        // SYS_clone = 220
        //
        // Flags needed for pthread_create-like threads:
        // - CLONE_VM (0x100): Share memory space
        // - CLONE_FS (0x200): Share filesystem info
        // - CLONE_FILES (0x400): Share file descriptors
        // - CLONE_SIGHAND (0x800): Share signal handlers (required with CLONE_THREAD)
        // - CLONE_THREAD (0x10000): Same thread group
        // - CLONE_SYSVSEM (0x40000): Share SysV semaphores
        // - CLONE_SETTLS (0x80000): Set TLS for child
        // - CLONE_PARENT_SETTID (0x100000): Store parent TID
        // - CLONE_CHILD_CLEARTID (0x200000): Clear child TID on exit

        uint64_t clone_flags = 0x3D0F00;
        // = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD
        //   | CLONE_SYSVSEM | CLONE_SETTLS | CLONE_PARENT_SETTID | CLONE_CHILD_CLEARTID

        // Allocate storage for parent_tid and child_tid (on the child's stack)
        uint64_t parent_tid_addr = child_stack_top + 16;
        uint64_t child_tid_addr = child_stack_top + 24;

        set_reg(emu, UC_ARM64_REG_X0, clone_flags);
        set_reg(emu, UC_ARM64_REG_X1, child_stack_top);   // child_stack
        set_reg(emu, UC_ARM64_REG_X2, parent_tid_addr);   // parent_tid
        set_reg(emu, UC_ARM64_REG_X3, tls_base);          // tls
        set_reg(emu, UC_ARM64_REG_X4, child_tid_addr);    // child_tid
        set_reg(emu, UC_ARM64_REG_X8, 220);               // SYS_clone

        EMU_LOG << "[HLE] pthread_create: clone flags=0x" << std::hex << clone_flags
                  << " parent_tid_addr=0x" << parent_tid_addr
                  << " child_tid_addr=0x" << child_tid_addr << std::dec << std::endl;

        // Set LR to caller's LR so parent returns to the right place
        set_reg(emu, UC_ARM64_REG_LR, caller_lr);

        // Set PC to the clone trampoline - emulator will execute this next
        set_reg(emu, UC_ARM64_REG_PC, CLONE_TRAMPOLINE_ADDR);

        EMU_LOG << "[HLE] pthread_create: Set up clone syscall, jumping to trampoline at 0x"
                  << std::hex << CLONE_TRAMPOLINE_ADDR << std::dec << std::endl;

        // Don't set X0 return value - the clone syscall will set it
        // The trampoline returns to LR (caller) for parent with X0=child_tid
    });

    hle.register_function("pthread_join", [](Emulator& emu) {
        uint64_t thread_id = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t retval_ptr = get_reg(emu, UC_ARM64_REG_X1);

        EMU_LOG << "[HLE] pthread_join: Joining thread " << thread_id << std::endl;

        QemuThread* thread = nullptr;
        {
            std::lock_guard<std::mutex> lock(g_threads_mutex);
            auto it = g_threads.find(thread_id);
            if (it == g_threads.end()) {
                EMU_LOG << "[HLE] pthread_join: Thread " << thread_id << " not found!" << std::endl;
                set_reg(emu, UC_ARM64_REG_X0, 3);  // ESRCH
                return;
            }
            thread = it->second.get();
        }

        // Wait for thread to complete
        // With QEMU native clone, threads run in parallel
        // The exit syscall will mark the thread as completed
        {
            std::unique_lock<std::mutex> lock(thread->join_mutex);
            int wait_count = 0;
            while (!thread->completed.load()) {
                // Wait with timeout to allow checking for completion
                thread->join_cv.wait_for(lock, std::chrono::milliseconds(1000));
                wait_count++;
                EMU_LOG << "[HLE] pthread_join: Still waiting for thread " << thread_id
                          << " (wait " << wait_count << "s, completed=" << thread->completed.load() << ")" << std::endl;

                // Debug: dump all thread states every 5 seconds
                if (wait_count % 5 == 0) {
                    std::lock_guard<std::mutex> tlock(g_threads_mutex);
                    EMU_LOG << "[HLE] Thread states:" << std::endl;
                    for (auto& [id, t] : g_threads) {
                        EMU_LOG << "  Thread " << id << ": started=" << t->started.load()
                                  << " completed=" << t->completed.load() << std::endl;
                    }
                }
            }
        }

        // Get return value
        uint64_t retval = thread->return_value;
        if (retval_ptr != 0) {
            emu.mem_write(retval_ptr, &retval, sizeof(retval));
        }

        // Remove from registry
        {
            std::lock_guard<std::mutex> lock(g_threads_mutex);
            g_threads.erase(thread_id);
        }

        EMU_LOG << "[HLE] pthread_join: Thread " << thread_id
                  << " joined, retval=0x" << std::hex << retval << std::dec << std::endl;

        set_reg(emu, UC_ARM64_REG_X0, 0);  // Success
    });

    hle.register_function("pthread_detach", [](Emulator& emu) {
        uint64_t thread_id = get_reg(emu, UC_ARM64_REG_X0);

        std::lock_guard<std::mutex> lock(g_threads_mutex);
        auto it = g_threads.find(thread_id);
        if (it == g_threads.end()) {
            set_reg(emu, UC_ARM64_REG_X0, 3);  // ESRCH
            return;
        }

        // With QEMU native clone, threads run in QEMU's infrastructure
        // Mark as detached so we don't track it for joining
        // Thread resources will be cleaned up when it exits
        g_threads.erase(it);

        set_reg(emu, UC_ARM64_REG_X0, 0);  // Success
    });

    hle.register_function("pthread_self", [](Emulator& emu) {
        // Use thread-local ID, or main thread (0) if not set
        uint64_t thread_id = tl_current_thread_id;
        if (thread_id == 0) {
            thread_id = 1;  // Main thread ID
        }
        set_reg(emu, UC_ARM64_REG_X0, thread_id);
    });

    hle.register_function("pthread_equal", [](Emulator& emu) {
        uint64_t t1 = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t t2 = get_reg(emu, UC_ARM64_REG_X1);
        set_reg(emu, UC_ARM64_REG_X0, t1 == t2 ? 1 : 0);
    });

    hle.register_function("pthread_exit", [](Emulator& emu) {
        uint64_t retval = get_reg(emu, UC_ARM64_REG_X0);

        // Get current thread's SP to identify which thread is exiting
        uint64_t sp = get_reg(emu, UC_ARM64_REG_SP);

        // Notify thread exit (stores return value for pthread_join)
        notify_thread_exit(sp, retval);

        EMU_LOG << "[HLE] pthread_exit: retval=0x" << std::hex << retval
                  << " sp=0x" << sp << std::dec << std::endl;

        // Set X0 to the return value and trigger thread exit by setting PC
        // to the thread exit code sequence (MOV X8, #93; SVC #0)
        // We write this code sequence to a known location and jump there
        static constexpr uint64_t PTHREAD_EXIT_CODE_ADDR = 0x100FFF00;
        static bool exit_code_written = false;

        if (!exit_code_written) {
            // Write: MOV X8, #93; SVC #0
            uint32_t exit_code[] = {
                0xD2800BA8,  // MOV X8, #93 (SYS_exit)
                0xD4000001,  // SVC #0
            };
            emu.mem_write(PTHREAD_EXIT_CODE_ADDR, exit_code, sizeof(exit_code));
            exit_code_written = true;
        }

        // Set PC to exit code - thread will terminate when emulator resumes
        set_reg(emu, UC_ARM64_REG_PC, PTHREAD_EXIT_CODE_ADDR);
    });

    hle.register_function("pthread_once", [](Emulator& emu) {
        uint64_t once_control = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t init_routine = get_reg(emu, UC_ARM64_REG_X1);

        // Read once_control value
        int32_t once_value = 0;
        emu.mem_read(once_control, &once_value, sizeof(once_value));

        EMU_LOG_VERBOSE << "[HLE] pthread_once: once_control=0x" << std::hex << once_control
                << " init_routine=0x" << init_routine
                << " once_value=" << std::dec << once_value << std::endl;

        if (once_value == 0) {
            // Mark as done FIRST to prevent re-entry
            int32_t done = 1;
            emu.mem_write(once_control, &done, sizeof(done));

            // Call the init routine using call_function_safe to preserve LR
            if (init_routine != 0) {
                EMU_LOG_VERBOSE << "[HLE] pthread_once: calling init_routine at 0x" << std::hex << init_routine << std::dec << std::endl;
                uint64_t result = emu.call_function_safe(init_routine, {});
                EMU_LOG_VERBOSE << "[HLE] pthread_once: init_routine returned " << result
                        << ", X0 = 0x" << std::hex << get_reg(emu, UC_ARM64_REG_X0) << std::dec << std::endl;
            }
        }

        // IMPORTANT: Set X0 to 0 (success) AFTER all processing
        set_reg(emu, UC_ARM64_REG_X0, 0);

        // Verify X0 was set correctly
        uint64_t x0_after = get_reg(emu, UC_ARM64_REG_X0);
        if (x0_after != 0) {
            EMU_LOG << "[HLE] pthread_once: WARNING! X0 is " << x0_after << " after set_reg(0)!" << std::endl;
        }
    });

    // ========================================================================
    // Thread attribute operations
    // ========================================================================

    hle.register_function("pthread_attr_init", [](Emulator& emu) {
        uint64_t attr = get_reg(emu, UC_ARM64_REG_X0);
        // Zero out the attr structure (assume 64 bytes)
        uint8_t zeros[64] = {0};
        emu.mem_write(attr, zeros, sizeof(zeros));
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("pthread_attr_destroy", [](Emulator& emu) {
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("pthread_attr_setdetachstate", [](Emulator& emu) {
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("pthread_attr_getdetachstate", [](Emulator& emu) {
        uint64_t detachstate_ptr = get_reg(emu, UC_ARM64_REG_X1);
        int detachstate = 0;  // PTHREAD_CREATE_JOINABLE
        emu.mem_write(detachstate_ptr, &detachstate, sizeof(detachstate));
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("pthread_attr_setstacksize", [](Emulator& emu) {
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("pthread_attr_getstacksize", [](Emulator& emu) {
        uint64_t stacksize_ptr = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t stacksize = 8 * 1024 * 1024;  // 8MB default
        emu.mem_write(stacksize_ptr, &stacksize, sizeof(stacksize));
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    // ========================================================================
    // Thread-local storage - native implementation for MTTCG
    // ========================================================================

    hle.register_function("pthread_key_create", [](Emulator& emu) {
        uint64_t key_ptr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t destructor = get_reg(emu, UC_ARM64_REG_X1);

        // Defensive null check - invalid key_ptr would crash
        if (key_ptr == 0 || key_ptr < 0x1000) {
            set_reg(emu, UC_ARM64_REG_X0, EINVAL);
            return;
        }

        uint64_t key = g_next_tls_key.fetch_add(1);
        uint32_t key32 = static_cast<uint32_t>(key);

        try {
            emu.mem_write(key_ptr, &key32, sizeof(key32));
        } catch (...) {
            set_reg(emu, UC_ARM64_REG_X0, EFAULT);
            return;
        }

        if (destructor != 0) {
            std::lock_guard<std::mutex> lock(g_tls_mutex);
            g_tls_destructors[key] = destructor;
        }

        if (emu.is_debug()) {
            EMU_LOG << "[HLE] pthread_key_create: key_ptr=0x" << std::hex << key_ptr
                      << " key=" << std::dec << key << " destructor=0x" << std::hex << destructor
                      << std::dec << std::endl;
        }
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("pthread_key_delete", [](Emulator& emu) {
        uint64_t key = get_reg(emu, UC_ARM64_REG_X0);
        std::lock_guard<std::mutex> lock(g_tls_mutex);
        g_tls_destructors.erase(key);
        // Remove values for all threads
        for (auto& [tid, values] : g_tls_values) {
            values.erase(key);
        }
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("pthread_getspecific", [](Emulator& emu) {
        uint64_t key = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t sp = get_reg(emu, UC_ARM64_REG_SP);
        uint64_t thread_id = get_thread_id_from_sp(sp);

        uint64_t value = 0;
        {
            std::lock_guard<std::mutex> lock(g_tls_mutex);
            auto tid_it = g_tls_values.find(thread_id);
            if (tid_it != g_tls_values.end()) {
                auto key_it = tid_it->second.find(key);
                if (key_it != tid_it->second.end()) {
                    value = key_it->second;
                }
            }
        }
        if (emu.is_debug()) {
            EMU_LOG << "[HLE] pthread_getspecific: key=" << key << " value=0x" << std::hex << value << std::dec << std::endl;
        }
        set_reg(emu, UC_ARM64_REG_X0, value);
    });

    hle.register_function("pthread_setspecific", [](Emulator& emu) {
        uint64_t key = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t value = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t sp = get_reg(emu, UC_ARM64_REG_SP);
        uint64_t thread_id = get_thread_id_from_sp(sp);

        {
            std::lock_guard<std::mutex> lock(g_tls_mutex);
            g_tls_values[thread_id][key] = value;
        }
        if (emu.is_debug()) {
            EMU_LOG << "[HLE] pthread_setspecific: key=" << key << " value=0x" << std::hex << value << std::dec << std::endl;
        }
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    // ========================================================================
    // Spin locks - use native mutex infrastructure
    // ========================================================================

    hle.register_function("pthread_spin_init", [](Emulator& emu) {
        uint64_t lock = get_reg(emu, UC_ARM64_REG_X0);
        get_or_create_mutex(lock);  // Auto-create the mutex
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("pthread_spin_destroy", [](Emulator& emu) {
        uint64_t lock = get_reg(emu, UC_ARM64_REG_X0);
        std::lock_guard<std::mutex> guard(g_mutexes_lock);
        g_host_mutexes.erase(lock);
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("pthread_spin_lock", [](Emulator& emu) {
        uint64_t lock = get_reg(emu, UC_ARM64_REG_X0);
        auto mtx = get_or_create_mutex(lock);
        mtx->mtx.lock();
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("pthread_spin_trylock", [](Emulator& emu) {
        uint64_t lock = get_reg(emu, UC_ARM64_REG_X0);
        auto mtx = get_or_create_mutex(lock);
        bool success = mtx->mtx.try_lock();
        set_reg(emu, UC_ARM64_REG_X0, success ? 0 : EBUSY);
    });

    hle.register_function("pthread_spin_unlock", [](Emulator& emu) {
        uint64_t lock = get_reg(emu, UC_ARM64_REG_X0);
        auto mtx = get_or_create_mutex(lock);
        mtx->mtx.unlock();
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    // ========================================================================
    // Barriers - native implementation for MTTCG
    // ========================================================================

    hle.register_function("pthread_barrier_init", [](Emulator& emu) {
        uint64_t barrier_addr = get_reg(emu, UC_ARM64_REG_X0);
        (void)get_reg(emu, UC_ARM64_REG_X1);  // attr - ignored
        unsigned int count = get_reg(emu, UC_ARM64_REG_X2);
        if (count == 0) {
            set_reg(emu, UC_ARM64_REG_X0, EINVAL);
            return;
        }
        get_or_create_barrier(barrier_addr, count);
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("pthread_barrier_destroy", [](Emulator& emu) {
        uint64_t barrier_addr = get_reg(emu, UC_ARM64_REG_X0);
        destroy_barrier(barrier_addr);
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("pthread_barrier_wait", [](Emulator& emu) {
        uint64_t barrier_addr = get_reg(emu, UC_ARM64_REG_X0);
        HostBarrier* b = nullptr;
        {
            std::lock_guard<std::mutex> lock(g_barriers_lock);
            auto it = g_host_barriers.find(barrier_addr);
            if (it != g_host_barriers.end()) {
                b = it->second.get();
            }
        }
        if (!b) {
            set_reg(emu, UC_ARM64_REG_X0, EINVAL);
            return;
        }
        int result = pthread_barrier_wait(&b->barrier);
        // PTHREAD_BARRIER_SERIAL_THREAD is returned to exactly one thread
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // ========================================================================
    // Cancellation (not fully supported)
    // ========================================================================

    hle.register_function("pthread_cancel", [](Emulator& emu) {
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("pthread_setcancelstate", [](Emulator& emu) {
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("pthread_setcanceltype", [](Emulator& emu) {
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("pthread_testcancel", [](Emulator& emu) {
        // No-op
    });
}

// Notify that a thread has exited
// This is called from the syscall handler when SYS_THREAD_DONE is invoked
// We use the stack pointer (SP) to identify which thread - SP is within the thread's stack range
void notify_thread_exit(uint64_t sp, uint64_t retval) {
    std::lock_guard<std::mutex> lock(g_threads_mutex);

    // Find the thread by checking if SP falls within the thread's stack range
    for (auto& [id, thread] : g_threads) {
        // Stack was allocated as: addr to addr + QEMU_THREAD_STACK_SIZE
        // stack_base is at addr + QEMU_THREAD_STACK_SIZE - 0x100 (top of usable stack)
        // So valid SP range is: (stack_base - QEMU_THREAD_STACK_SIZE + 0x100) to stack_base
        uint64_t stack_bottom = thread->stack_base - QEMU_THREAD_STACK_SIZE + 0x100;
        uint64_t stack_top = thread->stack_base + 0x100;  // Include some margin

        if (sp >= stack_bottom && sp <= stack_top) {
            EMU_LOG << "[HLE] Thread " << id << " exiting (SP=0x" << std::hex << sp
                      << ") with retval=0x" << retval << std::dec << std::endl;

            thread->return_value = retval;
            thread->completed.store(true);
            thread->join_cv.notify_all();
            return;
        }
    }

    // Thread not found in our registry - this might be the main thread
    EMU_LOG << "[HLE] Unknown thread exiting (SP=0x" << std::hex << sp
              << ") with retval=0x" << retval << std::dec << std::endl;
}

} // namespace cross_shim
