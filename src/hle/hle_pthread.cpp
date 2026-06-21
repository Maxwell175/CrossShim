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
#include "hle_exit_state.h"
#include "hle_manager.h"
#include "hle_mmap_state.h"
#include "hle_sched_state.h"
#include "hle_signal_state.h"
#include "hle_virtual_threads.h"
#include "cross_shim.h"
#include "memory_manager.h"
#include "qemu_api.h"
#include "emu_compat.h"
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <unordered_map>
#include <sched.h>
#include <semaphore.h>
#include <atomic>
#include <chrono>
#include <cerrno>
#include <ctime>
#include <limits>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <unistd.h>
#include <unordered_set>
#include <vector>

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
    uint64_t reported_stack_size{0};
    uint64_t tls_base;
    uint64_t guest_stack_addr{0};
    uint64_t guest_guard_size{4096};
    int sched_policy{0};
    int sched_priority{0};
    bool detached{false};
    bool join_in_progress{false};
    std::string name{"thread"};

    // Thread completion tracking
    std::atomic<bool> started{false};
    std::atomic<bool> completed{false};
    std::atomic<bool> exit_reported{false};
    std::atomic<pid_t> visible_tid{0};
    uint64_t return_value{0};

    // For pthread_join to wait on completion
    std::mutex join_mutex;
    std::condition_variable join_cv;
};

// Global thread registry
static std::mutex g_threads_mutex;
static std::unordered_map<uint64_t, std::unique_ptr<QemuThread>> g_threads;
static std::atomic<uint64_t> g_next_thread_id{0x1000};
static std::string g_main_thread_name{"thread"};
static int g_main_thread_sched_policy{SCHED_OTHER};
static int g_main_thread_sched_priority{0};

// Thread-local current thread ID
static thread_local uint64_t tl_current_thread_id = 0;

// Runtime lock/cond tracing (CROSSSHIM_LOCK_TRACE=1) to diagnose the multi-camera
// concurrency deadlock: emits the mutex wait-for graph + cond wait/signal edges.
static const bool g_lock_trace = [] {
    const char* e = std::getenv("CROSSSHIM_LOCK_TRACE");
    return e && e[0] == '1';
}();

// =============================================================================
// QEMU-Native Mutex/Condvar Infrastructure
// =============================================================================
// With QEMU MTTCG, threads run in parallel on real host threads.
// We use real host std::mutex and std::condition_variable for synchronization.

static constexpr int GUEST_PTHREAD_PROCESS_PRIVATE = 0;
static constexpr int GUEST_PTHREAD_PROCESS_SHARED = 1;

// Mutex that tracks ownership for proper trylock semantics
struct HostMutex {
    std::recursive_timed_mutex mtx;
    std::atomic<uint64_t> owner_thread{0};
    std::atomic<int> lock_count{0};
    int type{PTHREAD_MUTEX_NORMAL};
    int protocol{PTHREAD_PRIO_NONE};
    int pshared{GUEST_PTHREAD_PROCESS_PRIVATE};
};

// Map guest mutex address -> host mutex
static std::mutex g_mutexes_lock;
static std::unordered_map<uint64_t, std::shared_ptr<HostMutex>> g_host_mutexes;

struct HostSpinLock {
    std::atomic<bool> locked{false};
    std::atomic<uint64_t> owner_thread{0};
};

static std::mutex g_spinlocks_lock;
static std::unordered_map<uint64_t, std::shared_ptr<HostSpinLock>> g_host_spinlocks;

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

static std::shared_ptr<HostSpinLock> get_or_create_spinlock(uint64_t guest_lock_addr) {
    if (guest_lock_addr == 0 || guest_lock_addr < 0x1000) {
        static auto dummy_spinlock = std::make_shared<HostSpinLock>();
        return dummy_spinlock;
    }

    std::lock_guard<std::mutex> lock(g_spinlocks_lock);
    auto it = g_host_spinlocks.find(guest_lock_addr);
    if (it == g_host_spinlocks.end()) {
        auto spin = std::make_shared<HostSpinLock>();
        g_host_spinlocks[guest_lock_addr] = spin;
        return spin;
    }
    return it->second;
}

// Map guest condvar address -> host condition variable + associated mutex
struct HostCondVar {
    std::condition_variable_any cv;
    int clockid{CLOCK_REALTIME};
    int pshared{GUEST_PTHREAD_PROCESS_PRIVATE};
};

static std::mutex g_condvars_lock;
static std::unordered_map<uint64_t, std::shared_ptr<HostCondVar>> g_host_condvars;

static constexpr uint64_t GUEST_PTHREAD_COND_SIZE = 12 * sizeof(int32_t);
static constexpr uint64_t GUEST_PTHREAD_COND_ATTR_SIZE = sizeof(int64_t);
static constexpr uint64_t GUEST_PTHREAD_BARRIER_ATTR_SIZE = sizeof(int32_t);
static constexpr uint64_t GUEST_PTHREAD_CONDATTR_SHARED_BIT = 1ULL << 0;
static constexpr uint64_t GUEST_PTHREAD_CONDATTR_MONOTONIC_BIT = 1ULL << 1;

static bool is_valid_guest_pshared(int pshared) {
    return pshared == GUEST_PTHREAD_PROCESS_PRIVATE ||
           pshared == GUEST_PTHREAD_PROCESS_SHARED;
}

static bool is_valid_guest_cond_clock(int clockid) {
    return clockid == CLOCK_REALTIME || clockid == CLOCK_MONOTONIC;
}

static uint64_t encode_guest_condattr_value(int clockid, int pshared) {
    uint64_t raw = 0;
    if (pshared == GUEST_PTHREAD_PROCESS_SHARED) {
        raw |= GUEST_PTHREAD_CONDATTR_SHARED_BIT;
    }
    if (clockid == CLOCK_MONOTONIC) {
        raw |= GUEST_PTHREAD_CONDATTR_MONOTONIC_BIT;
    }
    return raw;
}

static void decode_guest_condattr_value(uint64_t raw, int& clockid, int& pshared) {
    pshared = (raw & GUEST_PTHREAD_CONDATTR_SHARED_BIT) != 0
        ? GUEST_PTHREAD_PROCESS_SHARED
        : GUEST_PTHREAD_PROCESS_PRIVATE;
    clockid = (raw & GUEST_PTHREAD_CONDATTR_MONOTONIC_BIT) != 0
        ? CLOCK_MONOTONIC
        : CLOCK_REALTIME;
}

static bool read_guest_condattr(Emulator& emu, uint64_t attr_addr, int& clockid, int& pshared) {
    if (attr_addr == 0 || attr_addr < 0x1000) {
        return false;
    }

    uint64_t raw = 0;
    if (!emu.mem_read(attr_addr, &raw, sizeof(raw))) {
        return false;
    }

    decode_guest_condattr_value(raw, clockid, pshared);
    return true;
}

static bool write_guest_condattr(Emulator& emu, uint64_t attr_addr, int clockid, int pshared) {
    if (attr_addr == 0 || attr_addr < 0x1000 ||
        !is_valid_guest_cond_clock(clockid) ||
        !is_valid_guest_pshared(pshared)) {
        return false;
    }

    uint64_t raw = encode_guest_condattr_value(clockid, pshared);
    return emu.mem_write(attr_addr, &raw, sizeof(raw));
}

static bool read_guest_barrierattr(Emulator& emu, uint64_t attr_addr, int& pshared) {
    if (attr_addr == 0 || attr_addr < 0x1000) {
        return false;
    }

    int32_t raw = GUEST_PTHREAD_PROCESS_PRIVATE;
    if (!emu.mem_read(attr_addr, &raw, sizeof(raw)) || !is_valid_guest_pshared(raw)) {
        return false;
    }

    pshared = raw;
    return true;
}

static bool write_guest_barrierattr(Emulator& emu, uint64_t attr_addr, int pshared) {
    if (attr_addr == 0 || attr_addr < 0x1000 || !is_valid_guest_pshared(pshared)) {
        return false;
    }

    int32_t raw = pshared;
    return emu.mem_write(attr_addr, &raw, sizeof(raw));
}

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

static std::shared_ptr<HostCondVar> initialize_condvar(uint64_t guest_cond_addr, int clockid, int pshared) {
    if (guest_cond_addr == 0 || guest_cond_addr < 0x1000) {
        static auto dummy_cv = std::make_shared<HostCondVar>();
        return dummy_cv;
    }

    std::lock_guard<std::mutex> lock(g_condvars_lock);
    auto cv = std::make_shared<HostCondVar>();
    cv->clockid = clockid;
    cv->pshared = pshared;
    g_host_condvars[guest_cond_addr] = cv;
    return cv;
}

// =============================================================================
// QEMU-Native RWLock Infrastructure (for MTTCG)
// =============================================================================
// Using pthread_rwlock_t for native reader-writer lock semantics
// This properly handles unlock() for both read and write locks

#include <pthread.h>

static constexpr int GUEST_PTHREAD_RWLOCK_PREFER_READER_NP = 0;
static constexpr int GUEST_PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP = 1;
static constexpr uint64_t GUEST_PTHREAD_RWLOCK_SIZE = 14 * sizeof(int32_t);
static constexpr uint64_t GUEST_PTHREAD_RWLOCK_ATTR_SIZE = sizeof(int64_t);

struct GuestRWLockAttr {
    int pshared{GUEST_PTHREAD_PROCESS_PRIVATE};
    int kind{GUEST_PTHREAD_RWLOCK_PREFER_READER_NP};
};

struct HostRWLock {
    pthread_rwlock_t rwlock;
    bool initialized{false};
    int init_result{0};
    bool prefer_writer_nonrecursive{false};
    std::mutex state_mutex;
    std::condition_variable state_cv;
    std::unordered_map<uint64_t, int> reader_counts;
    int active_readers{0};
    int waiting_writers{0};
    bool writer_active{false};
    uint64_t writer_tid{0};

    HostRWLock(int pshared = GUEST_PTHREAD_PROCESS_PRIVATE,
               int guest_kind = GUEST_PTHREAD_RWLOCK_PREFER_READER_NP) {
        prefer_writer_nonrecursive =
            (guest_kind == GUEST_PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP);
        pthread_rwlockattr_t attr;
        int attr_result = pthread_rwlockattr_init(&attr);
        if (attr_result != 0) {
            init_result = attr_result;
            return;
        }

        auto cleanup_attr = [&attr]() {
            pthread_rwlockattr_destroy(&attr);
        };

        int host_pshared = (pshared == GUEST_PTHREAD_PROCESS_SHARED)
            ? PTHREAD_PROCESS_SHARED
            : PTHREAD_PROCESS_PRIVATE;
        int result = pthread_rwlockattr_setpshared(&attr, host_pshared);
        if (result != 0) {
            init_result = result;
            cleanup_attr();
            return;
        }

#if defined(PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP)
        int host_kind = (guest_kind == GUEST_PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP)
            ? PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP
            : PTHREAD_RWLOCK_PREFER_READER_NP;
        result = pthread_rwlockattr_setkind_np(&attr, host_kind);
        if (result != 0) {
            init_result = result;
            cleanup_attr();
            return;
        }
#endif

        init_result = pthread_rwlock_init(&rwlock, &attr);
        initialized = (init_result == 0);
        cleanup_attr();
    }

    ~HostRWLock() {
        if (initialized) {
            pthread_rwlock_destroy(&rwlock);
        }
    }
};

static std::mutex g_rwlocks_lock;
static std::unordered_map<uint64_t, std::shared_ptr<HostRWLock>> g_host_rwlocks;
static std::mutex g_rwlockattrs_lock;
static std::unordered_map<uint64_t, GuestRWLockAttr> g_guest_rwlockattrs;

static bool is_valid_guest_rwlock_pshared(int pshared) {
    return pshared == GUEST_PTHREAD_PROCESS_PRIVATE ||
           pshared == GUEST_PTHREAD_PROCESS_SHARED;
}

static bool is_valid_guest_rwlock_kind(int kind) {
    return kind == GUEST_PTHREAD_RWLOCK_PREFER_READER_NP ||
           kind == GUEST_PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP;
}

static GuestRWLockAttr get_guest_rwlock_attr(uint64_t guest_attr_addr) {
    if (guest_attr_addr == 0 || guest_attr_addr < 0x1000) {
        return GuestRWLockAttr{};
    }

    std::lock_guard<std::mutex> lock(g_rwlockattrs_lock);
    auto it = g_guest_rwlockattrs.find(guest_attr_addr);
    if (it == g_guest_rwlockattrs.end()) {
        return GuestRWLockAttr{};
    }
    return it->second;
}

static void initialize_guest_rwlock_attr(Emulator& emu, uint64_t guest_attr_addr) {
    if (guest_attr_addr == 0) {
        return;
    }

    uint8_t zeros[GUEST_PTHREAD_RWLOCK_ATTR_SIZE] = {0};
    emu.mem_write(guest_attr_addr, zeros, sizeof(zeros));

    std::lock_guard<std::mutex> lock(g_rwlockattrs_lock);
    g_guest_rwlockattrs[guest_attr_addr] = GuestRWLockAttr{};
}

static bool set_guest_rwlock_attr_pshared(uint64_t guest_attr_addr, int pshared) {
    std::lock_guard<std::mutex> lock(g_rwlockattrs_lock);
    auto it = g_guest_rwlockattrs.find(guest_attr_addr);
    if (it == g_guest_rwlockattrs.end()) {
        return false;
    }
    it->second.pshared = pshared;
    return true;
}

static bool set_guest_rwlock_attr_kind(uint64_t guest_attr_addr, int kind) {
    std::lock_guard<std::mutex> lock(g_rwlockattrs_lock);
    auto it = g_guest_rwlockattrs.find(guest_attr_addr);
    if (it == g_guest_rwlockattrs.end()) {
        return false;
    }
    it->second.kind = kind;
    return true;
}

static bool get_guest_rwlock_attr_pshared(uint64_t guest_attr_addr, int& pshared) {
    std::lock_guard<std::mutex> lock(g_rwlockattrs_lock);
    auto it = g_guest_rwlockattrs.find(guest_attr_addr);
    if (it == g_guest_rwlockattrs.end()) {
        return false;
    }
    pshared = it->second.pshared;
    return true;
}

static bool get_guest_rwlock_attr_kind(uint64_t guest_attr_addr, int& kind) {
    std::lock_guard<std::mutex> lock(g_rwlockattrs_lock);
    auto it = g_guest_rwlockattrs.find(guest_attr_addr);
    if (it == g_guest_rwlockattrs.end()) {
        return false;
    }
    kind = it->second.kind;
    return true;
}

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

static std::shared_ptr<HostRWLock> initialize_rwlock(uint64_t guest_rwlock_addr,
                                                     const GuestRWLockAttr& attr) {
    if (guest_rwlock_addr == 0 || guest_rwlock_addr < 0x1000) {
        static auto dummy_rwl = std::make_shared<HostRWLock>();
        return dummy_rwl;
    }

    std::lock_guard<std::mutex> lock(g_rwlocks_lock);
    auto rwl = std::make_shared<HostRWLock>(attr.pshared, attr.kind);
    g_host_rwlocks[guest_rwlock_addr] = rwl;
    return rwl;
}

static void destroy_rwlock(uint64_t guest_rwlock_addr) {
    std::lock_guard<std::mutex> lock(g_rwlocks_lock);
    g_host_rwlocks.erase(guest_rwlock_addr);
}

static int prepare_rwlock_deadline(const struct timespec* abstime, int clockid,
                                   std::chrono::steady_clock::time_point& deadline);

static bool read_guest_absolute_timespec(Emulator& emu, uint64_t guest_abstime_addr,
                                         struct timespec& ts) {
    if (guest_abstime_addr == 0) {
        return false;
    }

    int64_t sec = 0;
    int64_t nsec = 0;
    emu.mem_read(guest_abstime_addr, &sec, sizeof(sec));
    emu.mem_read(guest_abstime_addr + sizeof(sec), &nsec, sizeof(nsec));
    ts.tv_sec = static_cast<time_t>(sec);
    ts.tv_nsec = static_cast<long>(nsec);
    return true;
}

static int wait_cond_with_clock(HostCondVar& cv, HostMutex& mtx, int clockid,
                                const struct timespec* abstime, uint64_t visible_tid) {
    if (!is_valid_guest_cond_clock(clockid)) {
        return EINVAL;
    }

    int held_count = mtx.lock_count.load();
    if (held_count <= 0 || mtx.owner_thread.load() != visible_tid) {
        return EPERM;
    }

    // condition_variable_any releases and reacquires the underlying host mutex,
    // so our synthetic ownership bookkeeping must mirror that handoff.
    mtx.owner_thread.store(0);
    mtx.lock_count.store(0);

    auto restore_ownership = [&]() {
        mtx.owner_thread.store(visible_tid);
        mtx.lock_count.store(held_count);
    };

    if (abstime == nullptr) {
        cv.cv.wait(mtx.mtx);
        restore_ownership();
        return 0;
    }

    std::chrono::steady_clock::time_point deadline;
    int deadline_result = prepare_rwlock_deadline(abstime, clockid, deadline);
    if (deadline_result != 0) {
        restore_ownership();
        return deadline_result;
    }

    auto status = cv.cv.wait_until(mtx.mtx, deadline);
    restore_ownership();
    return status == std::cv_status::timeout ? ETIMEDOUT : 0;
}

static uint64_t get_current_host_thread_token() {
#ifdef SYS_gettid
    return static_cast<uint64_t>(::syscall(SYS_gettid));
#else
    return static_cast<uint64_t>(std::hash<std::thread::id>{}(std::this_thread::get_id()));
#endif
}

static pid_t get_current_host_visible_tid() {
    uint64_t token = get_current_host_thread_token();
    if (token == 0 || token > static_cast<uint64_t>(std::numeric_limits<pid_t>::max())) {
        return 0;
    }
    return static_cast<pid_t>(token);
}

static void remember_thread_visible_tid_locked(uint64_t pthread_id, pid_t tid) {
    if (pthread_id <= 1 || tid <= 0) {
        return;
    }
    auto it = g_threads.find(pthread_id);
    if (it != g_threads.end()) {
        it->second->visible_tid.store(tid, std::memory_order_release);
    }
}

static void remember_thread_visible_tid(uint64_t pthread_id, pid_t tid) {
    if (pthread_id <= 1 || tid <= 0) {
        return;
    }
    std::lock_guard<std::mutex> lock(g_threads_mutex);
    remember_thread_visible_tid_locked(pthread_id, tid);
}

static bool timespec_to_ns(const struct timespec& ts, int64_t& out_ns) {
    if (ts.tv_nsec < 0 || ts.tv_nsec >= 1000000000L) {
        return false;
    }

    __int128 value = static_cast<__int128>(ts.tv_sec) * 1000000000LL + ts.tv_nsec;
    if (value > std::numeric_limits<int64_t>::max()) {
        out_ns = std::numeric_limits<int64_t>::max();
    } else if (value < std::numeric_limits<int64_t>::min()) {
        out_ns = std::numeric_limits<int64_t>::min();
    } else {
        out_ns = static_cast<int64_t>(value);
    }
    return true;
}

static bool get_clock_now_ns(int clockid, int64_t& out_ns) {
    struct timespec now_ts{};
    if (::clock_gettime(clockid, &now_ts) != 0) {
        return false;
    }
    return timespec_to_ns(now_ts, out_ns);
}

static int prepare_rwlock_deadline(const struct timespec* abstime, int clockid,
                                   std::chrono::steady_clock::time_point& deadline) {
    if (abstime == nullptr) {
        return 0;
    }
    if (clockid != CLOCK_REALTIME && clockid != CLOCK_MONOTONIC) {
        return EINVAL;
    }

    int64_t abstime_ns = 0;
    if (!timespec_to_ns(*abstime, abstime_ns)) {
        return EINVAL;
    }

    int64_t now_ns = 0;
    if (!get_clock_now_ns(clockid, now_ns)) {
        return errno != 0 ? errno : EINVAL;
    }

    if (abstime_ns <= now_ns) {
        return ETIMEDOUT;
    }

    deadline = std::chrono::steady_clock::now() + std::chrono::nanoseconds(abstime_ns - now_ns);
    return 0;
}

static int lock_mutex_with_timeout(HostMutex& mtx, uint64_t tid, int clockid,
                                   const struct timespec* abstime) {
    if (mtx.owner_thread.load() == tid && mtx.lock_count.load() > 0) {
        if (mtx.type == PTHREAD_MUTEX_RECURSIVE) {
            mtx.mtx.lock();
            mtx.lock_count++;
            return 0;
        }
        if (mtx.type == PTHREAD_MUTEX_ERRORCHECK) {
            return EDEADLK;
        }
        if (abstime == nullptr) {
            return EDEADLK;
        }

        std::chrono::steady_clock::time_point deadline;
        int deadline_result = prepare_rwlock_deadline(abstime, clockid, deadline);
        if (deadline_result != 0) {
            return deadline_result;
        }
        std::this_thread::sleep_until(deadline);
        return ETIMEDOUT;
    }

    if (abstime == nullptr) {
        mtx.mtx.lock();
        mtx.owner_thread.store(tid);
        mtx.lock_count++;
        return 0;
    }

    std::chrono::steady_clock::time_point deadline;
    int deadline_result = prepare_rwlock_deadline(abstime, clockid, deadline);
    if (deadline_result != 0) {
        return deadline_result;
    }
    if (!mtx.mtx.try_lock_until(deadline)) {
        return ETIMEDOUT;
    }
    mtx.owner_thread.store(tid);
    mtx.lock_count++;
    return 0;
}

static bool can_acquire_writer_pref_reader_locked(const HostRWLock& rwlock, uint64_t tid) {
    if (rwlock.writer_active) {
        return false;
    }
    auto it = rwlock.reader_counts.find(tid);
    if (rwlock.waiting_writers > 0 && it == rwlock.reader_counts.end()) {
        return false;
    }
    return true;
}

static void acquire_writer_pref_reader_locked(HostRWLock& rwlock, uint64_t tid) {
    rwlock.reader_counts[tid]++;
    rwlock.active_readers++;
}

static int lock_writer_pref_reader(HostRWLock& rwlock, bool try_only, int clockid,
                                   const struct timespec* abstime) {
    uint64_t tid = get_current_host_thread_token();
    std::unique_lock<std::mutex> lock(rwlock.state_mutex);

    if (rwlock.writer_active && rwlock.writer_tid == tid) {
        return EDEADLK;
    }

    auto existing_reader = rwlock.reader_counts.find(tid);
    if (existing_reader != rwlock.reader_counts.end()) {
        acquire_writer_pref_reader_locked(rwlock, tid);
        return 0;
    }

    if (try_only) {
        if (!can_acquire_writer_pref_reader_locked(rwlock, tid)) {
            return EBUSY;
        }
        acquire_writer_pref_reader_locked(rwlock, tid);
        return 0;
    }

    if (abstime == nullptr) {
        rwlock.state_cv.wait(lock, [&rwlock, tid]() {
            return can_acquire_writer_pref_reader_locked(rwlock, tid);
        });
    } else {
        std::chrono::steady_clock::time_point deadline;
        int deadline_result = prepare_rwlock_deadline(abstime, clockid, deadline);
        if (deadline_result != 0) {
            return deadline_result;
        }

        while (!can_acquire_writer_pref_reader_locked(rwlock, tid)) {
            if (rwlock.state_cv.wait_until(lock, deadline) == std::cv_status::timeout &&
                !can_acquire_writer_pref_reader_locked(rwlock, tid)) {
                return ETIMEDOUT;
            }
        }
    }

    acquire_writer_pref_reader_locked(rwlock, tid);
    return 0;
}

static int lock_writer_pref_writer(HostRWLock& rwlock, bool try_only, int clockid,
                                   const struct timespec* abstime) {
    uint64_t tid = get_current_host_thread_token();
    std::unique_lock<std::mutex> lock(rwlock.state_mutex);

    if (rwlock.writer_active && rwlock.writer_tid == tid) {
        return EDEADLK;
    }
    if (rwlock.reader_counts.find(tid) != rwlock.reader_counts.end()) {
        return EDEADLK;
    }

    auto can_acquire = [&rwlock]() {
        return !rwlock.writer_active && rwlock.active_readers == 0;
    };

    if (try_only) {
        if (!can_acquire()) {
            return EBUSY;
        }
        rwlock.writer_active = true;
        rwlock.writer_tid = tid;
        return 0;
    }

    rwlock.waiting_writers++;
    auto clear_waiter = [&rwlock]() {
        rwlock.waiting_writers--;
        rwlock.state_cv.notify_all();
    };

    if (abstime == nullptr) {
        rwlock.state_cv.wait(lock, [&can_acquire]() {
            return can_acquire();
        });
        clear_waiter();
    } else {
        std::chrono::steady_clock::time_point deadline;
        int deadline_result = prepare_rwlock_deadline(abstime, clockid, deadline);
        if (deadline_result != 0) {
            clear_waiter();
            return deadline_result;
        }

        while (!can_acquire()) {
            if (rwlock.state_cv.wait_until(lock, deadline) == std::cv_status::timeout &&
                !can_acquire()) {
                clear_waiter();
                return ETIMEDOUT;
            }
        }
        clear_waiter();
    }

    rwlock.writer_active = true;
    rwlock.writer_tid = tid;
    return 0;
}

static int rdlock_rwlock(HostRWLock& rwlock) {
    if (!rwlock.prefer_writer_nonrecursive) {
        return pthread_rwlock_rdlock(&rwlock.rwlock);
    }
    return lock_writer_pref_reader(rwlock, false, CLOCK_REALTIME, nullptr);
}

static int wrlock_rwlock(HostRWLock& rwlock) {
    if (!rwlock.prefer_writer_nonrecursive) {
        return pthread_rwlock_wrlock(&rwlock.rwlock);
    }
    return lock_writer_pref_writer(rwlock, false, CLOCK_REALTIME, nullptr);
}

static int tryrdlock_rwlock(HostRWLock& rwlock) {
    if (!rwlock.prefer_writer_nonrecursive) {
        return pthread_rwlock_tryrdlock(&rwlock.rwlock);
    }
    return lock_writer_pref_reader(rwlock, true, CLOCK_REALTIME, nullptr);
}

static int trywrlock_rwlock(HostRWLock& rwlock) {
    if (!rwlock.prefer_writer_nonrecursive) {
        return pthread_rwlock_trywrlock(&rwlock.rwlock);
    }
    return lock_writer_pref_writer(rwlock, true, CLOCK_REALTIME, nullptr);
}

static int unlock_rwlock(HostRWLock& rwlock) {
    if (!rwlock.prefer_writer_nonrecursive) {
        return pthread_rwlock_unlock(&rwlock.rwlock);
    }

    uint64_t tid = get_current_host_thread_token();
    std::lock_guard<std::mutex> lock(rwlock.state_mutex);

    if (rwlock.writer_active && rwlock.writer_tid == tid) {
        rwlock.writer_active = false;
        rwlock.writer_tid = 0;
        rwlock.state_cv.notify_all();
        return 0;
    }

    auto it = rwlock.reader_counts.find(tid);
    if (it == rwlock.reader_counts.end() || it->second <= 0) {
        return EINVAL;
    }

    it->second--;
    rwlock.active_readers--;
    if (it->second == 0) {
        rwlock.reader_counts.erase(it);
    }
    if (rwlock.active_readers == 0) {
        rwlock.state_cv.notify_all();
    }
    return 0;
}

static int lock_rwlock_with_timeout(HostRWLock& rwlock, bool write_lock,
                                    const struct timespec* abstime) {
    if (rwlock.prefer_writer_nonrecursive) {
        return write_lock
            ? lock_writer_pref_writer(rwlock, false, CLOCK_REALTIME, abstime)
            : lock_writer_pref_reader(rwlock, false, CLOCK_REALTIME, abstime);
    }

    if (abstime == nullptr) {
        return write_lock ? wrlock_rwlock(rwlock) : rdlock_rwlock(rwlock);
    }

    return write_lock ? pthread_rwlock_timedwrlock(&rwlock.rwlock, abstime)
                      : pthread_rwlock_timedrdlock(&rwlock.rwlock, abstime);
}

static int lock_rwlock_with_clock(HostRWLock& rwlock, bool write_lock, int clockid,
                                  const struct timespec* abstime) {
    if (rwlock.prefer_writer_nonrecursive) {
        return write_lock
            ? lock_writer_pref_writer(rwlock, false, clockid, abstime)
            : lock_writer_pref_reader(rwlock, false, clockid, abstime);
    }

    if (abstime == nullptr) {
        if (clockid != CLOCK_REALTIME && clockid != CLOCK_MONOTONIC) {
            return EINVAL;
        }
        return write_lock ? wrlock_rwlock(rwlock) : rdlock_rwlock(rwlock);
    }

    if (clockid != CLOCK_REALTIME && clockid != CLOCK_MONOTONIC) {
        return EINVAL;
    }

    return write_lock ? pthread_rwlock_clockwrlock(&rwlock.rwlock, clockid, abstime)
                      : pthread_rwlock_clockrdlock(&rwlock.rwlock, clockid, abstime);
}

// =============================================================================
// QEMU-Native TLS Infrastructure (for MTTCG)
// =============================================================================
// Thread-local storage using thread-id based indexing

static std::mutex g_tls_mutex;
static std::unordered_map<uint64_t, uint64_t> g_tls_destructors;  // key -> destructor
static std::unordered_map<uint64_t, std::unordered_map<uint64_t, uint64_t>> g_tls_values;  // thread_id -> (key -> value)
static std::atomic<uint64_t> g_next_tls_key{1};
static std::unordered_set<uint64_t> g_tls_live_keys;
static std::vector<uint64_t> g_tls_free_keys;
static constexpr uint64_t GUEST_PTHREAD_KEYS_MAX = 128;
static constexpr uint64_t GUEST_PTHREAD_KEY_RESERVED_COUNT = 16;
static constexpr uint64_t GUEST_PTHREAD_DYNAMIC_KEY_LIMIT =
    GUEST_PTHREAD_KEYS_MAX - GUEST_PTHREAD_KEY_RESERVED_COUNT;

struct GuestCleanupHandler {
    uint64_t cleanup_addr{0};
    uint64_t routine{0};
    uint64_t arg{0};
};

static std::mutex g_cleanup_handlers_lock;
static std::unordered_map<uint64_t, std::vector<GuestCleanupHandler>> g_cleanup_handlers;
static std::mutex g_pending_pthread_exit_lock;
static std::unordered_map<uint64_t, uint64_t> g_pending_pthread_exit_values;
static std::once_flag g_cleanup_callback_trampoline_once;
static std::once_flag g_pthread_exit_code_once;
static constexpr uint64_t CLEANUP_CALLBACK_TRAMPOLINE_ADDR = 0x10080400ULL;
static constexpr uint64_t PTHREAD_EXIT_CODE_ADDR = 0x100FFF00ULL;

// =============================================================================
// QEMU-Native Barrier Infrastructure (for MTTCG)
// =============================================================================
struct HostBarrier {
    std::mutex mutex;
    std::condition_variable cv;
    unsigned int count{0};
    unsigned int waiting{0};
    unsigned int generation{0};
    bool initialized{false};

    explicit HostBarrier(unsigned int barrier_count)
        : count(barrier_count), initialized(barrier_count != 0) {}
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

static int destroy_barrier(uint64_t guest_barrier_addr) {
    std::lock_guard<std::mutex> lock(g_barriers_lock);
    auto it = g_host_barriers.find(guest_barrier_addr);
    if (it == g_host_barriers.end() || !it->second->initialized) {
        return EINVAL;
    }

    {
        std::lock_guard<std::mutex> barrier_lock(it->second->mutex);
        if (it->second->waiting != 0) {
            return EBUSY;
        }
        it->second->initialized = false;
    }

    g_host_barriers.erase(it);
    return 0;
}

static int wait_on_barrier(HostBarrier& barrier) {
    std::unique_lock<std::mutex> lock(barrier.mutex);
    if (!barrier.initialized || barrier.count == 0) {
        return EINVAL;
    }

    unsigned int generation = barrier.generation;
    barrier.waiting++;
    if (barrier.waiting == barrier.count) {
        barrier.waiting = 0;
        barrier.generation++;
        barrier.cv.notify_all();
        return PTHREAD_BARRIER_SERIAL_THREAD;
    }

    barrier.cv.wait(lock, [&barrier, generation]() {
        return !barrier.initialized || barrier.generation != generation;
    });

    return barrier.initialized ? 0 : EINVAL;
}

// Constants for thread memory allocation (defined early so get_thread_id_from_sp can use them)
static constexpr uint64_t QEMU_THREAD_STACK_SIZE = 0x100000;  // 1MB stack
static constexpr uint64_t QEMU_THREAD_TLS_SIZE = 0x10000;     // 64KB TLS
static constexpr uint64_t QEMU_THREAD_STACK_BASE = 0x90000000;
static constexpr uint64_t QEMU_THREAD_TLS_BASE = 0xD0000000;
static constexpr uint64_t SAFE_CALL_STACK_BASE_GUEST = 0xA0000000ULL;
static constexpr uint64_t SAFE_CALL_STACK_SIZE_GUEST = 0x00800000ULL;
// Upper bounds of the per-thread arenas. A fresh (non-recycled) allocation must never
// cross these: thread stacks (1MB each from 0x90000000) must not collide into the
// safe-call stack at 0xA0000000, and TLS (64KB each from 0xD0000000) stays below
// 0xE0000000. Recycling exited threads' regions (see freelists below) keeps us far
// from these ceilings under sustained reconnect churn; the checks turn genuine
// exhaustion into a clean pthread_create(EAGAIN) failure instead of memory corruption.
static constexpr uint64_t QEMU_THREAD_STACK_CEILING = SAFE_CALL_STACK_BASE_GUEST; // 0xA0000000
static constexpr uint64_t QEMU_THREAD_TLS_CEILING   = 0xE0000000ULL;
static constexpr uint64_t GUEST_PTHREAD_MUTEX_SIZE = 10 * sizeof(int32_t);
static constexpr uint64_t GUEST_PTHREAD_MUTEX_ATTR_SIZE = sizeof(int64_t);
static constexpr uint64_t GUEST_PTHREAD_ATTR_SIZE = 64;
static constexpr uint64_t GUEST_PTHREAD_ATTR_DETACHSTATE_OFFSET = 0;
static constexpr uint64_t GUEST_PTHREAD_ATTR_STACKADDR_OFFSET = 8;
static constexpr uint64_t GUEST_PTHREAD_ATTR_STACKSIZE_OFFSET = 16;
static constexpr uint64_t GUEST_PTHREAD_ATTR_GUARDSIZE_OFFSET = 24;
static constexpr uint64_t GUEST_PTHREAD_ATTR_INHERITSCHED_OFFSET = 32;
static constexpr uint64_t GUEST_PTHREAD_ATTR_SCHEDPOLICY_OFFSET = 36;
static constexpr uint64_t GUEST_PTHREAD_ATTR_SCHEDPRIORITY_OFFSET = 40;
static constexpr uint64_t GUEST_PTHREAD_ATTR_SCOPE_OFFSET = 44;
static constexpr int32_t GUEST_PTHREAD_CREATE_JOINABLE = 0;
static constexpr int32_t GUEST_PTHREAD_CREATE_DETACHED = 1;
static constexpr int32_t GUEST_PTHREAD_EXPLICIT_SCHED = 0;
static constexpr int32_t GUEST_PTHREAD_INHERIT_SCHED = 1;
static constexpr int32_t GUEST_PTHREAD_SCOPE_SYSTEM = 0;
static constexpr uint64_t GUEST_DEFAULT_PTHREAD_STACK_SIZE = 8 * 1024 * 1024;
static constexpr uint64_t GUEST_DEFAULT_PTHREAD_GUARD_SIZE = 4096;
static constexpr uint64_t GUEST_PTHREAD_STACK_MIN = 16 * 1024;
static constexpr uint64_t MAIN_THREAD_STACK_TOP_GUEST = 0x80000000ULL;
static constexpr uint64_t GUEST_PTHREAD_MUTEXATTR_TYPE_SHIFT = 0;
static constexpr uint64_t GUEST_PTHREAD_MUTEXATTR_PSHARED_SHIFT = 8;
static constexpr uint64_t GUEST_PTHREAD_MUTEXATTR_PROTOCOL_SHIFT = 16;

// =============================================================================
// Thread ID helper (get current thread ID from SP)
// =============================================================================
// The safe-call arena holds one 8MB stack slot PER pool worker:
//   slot k = SAFE_CALL_STACK_BASE_GUEST + k * SAFE_CALL_STACK_SIZE_GUEST
// spanning 0xA0000000 up to GLOBAL_DATA_BASE (0xB0000000). The original check covered only
// slot 0, so every worker's C->guest calls resolved to the SAME synthetic thread id (1) and
// collided on mutex ownership / TLS — deadlocking recursive locks across cameras.
static constexpr uint64_t SAFE_CALL_ARENA_END_GUEST = 0xB0000000ULL;
// Synthetic guest-thread-id base for pool-worker safe-call contexts. Must be disjoint from
// real guest thread ids (1 = main; 0x1000+index = cloned threads).
static constexpr uint64_t SAFE_CALL_TID_BASE = 0x40000000ULL;

static bool is_safe_call_stack_sp(uint64_t sp) {
    return sp >= SAFE_CALL_STACK_BASE_GUEST && sp < SAFE_CALL_ARENA_END_GUEST;
}

// Worker slot index (0 = main emulator thread) for a safe-call SP.
static uint64_t safe_call_slot_from_sp(uint64_t sp) {
    return (sp - SAFE_CALL_STACK_BASE_GUEST) / SAFE_CALL_STACK_SIZE_GUEST;
}

static uint64_t get_guest_page_size() {
    long page_size = ::sysconf(_SC_PAGESIZE);
    return (page_size > 0) ? static_cast<uint64_t>(page_size) : 4096ULL;
}

static uint64_t round_up_to_multiple(uint64_t value, uint64_t multiple) {
    if (multiple == 0) {
        return value;
    }
    uint64_t remainder = value % multiple;
    if (remainder == 0) {
        return value;
    }
    uint64_t addend = multiple - remainder;
    if (value > std::numeric_limits<uint64_t>::max() - addend) {
        return 0;
    }
    return value + addend;
}

static uint64_t get_effective_guard_size(uint64_t requested_guard_size) {
    if (requested_guard_size == 0) {
        return 0;
    }
    uint64_t page_size = get_guest_page_size();
    if (requested_guard_size < page_size) {
        return page_size;
    }
    uint64_t rounded = round_up_to_multiple(requested_guard_size, page_size);
    return rounded == 0 ? requested_guard_size : rounded;
}

static uint64_t get_effective_stack_size(uint64_t requested_stack_size) {
    if (requested_stack_size == 0) {
        requested_stack_size = GUEST_DEFAULT_PTHREAD_STACK_SIZE;
    }
    uint64_t page_size = get_guest_page_size();
    uint64_t rounded = round_up_to_multiple(requested_stack_size, page_size);
    return rounded == 0 ? requested_stack_size : rounded;
}

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

static uint64_t get_current_guest_pthread_id(Emulator& emu) {
    uint64_t virtual_tid = hle_virtual_thread_current_override();
    if (virtual_tid != 0) {
        return virtual_tid;
    }

    uint64_t sp = get_reg(emu, UC_ARM64_REG_SP);
    if (is_safe_call_stack_sp(sp)) {
        // Each pool worker owns its own safe-call slot. Slot 0 (main emulator thread) keeps
        // the legacy id 1; pool workers 1..N get a STABLE id UNIQUE per slot so concurrent
        // C->guest calls from different cameras never collide on mutex ownership.
        uint64_t slot = safe_call_slot_from_sp(sp);
        if (slot == 0) {
            return (tl_current_thread_id == 0) ? 1 : tl_current_thread_id;
        }
        return SAFE_CALL_TID_BASE + slot;
    }

    uint64_t thread_id = get_thread_id_from_sp(sp);
    uint64_t guest_thread_id = (thread_id == 0) ? 1 : thread_id;
    tl_current_thread_id = guest_thread_id;
    return guest_thread_id;
}

uint64_t hle_get_current_pthread_id(Emulator& emu) {
    return get_current_guest_pthread_id(emu);
}

static uint64_t get_current_sync_thread_id(Emulator& emu) {
    (void)emu;
    // Mutex/cond/rwlock ownership MUST track the HOST thread that actually owns the
    // underlying host recursive_timed_mutex — unlocking it from a DIFFERENT host thread is
    // undefined behavior. Guest-stack-derived ids collide for TUTK threads with custom
    // (heap) stacks (get_thread_id_from_sp -> 0 -> id 1), so multiple host threads shared
    // owner id 1 and unlocked each other's mutexes -> recursive_timed_mutex corruption ->
    // multi-camera deadlock. Each guest thread (and each pool worker) runs on exactly ONE
    // host thread, so a per-host-thread id is both unique AND matches host-mutex ownership.
    static thread_local uint64_t host_sync_id = 0;
    if (host_sync_id == 0) {
        static std::atomic<uint64_t> next_host_sync_id{0x80000000ULL};
        host_sync_id = next_host_sync_id.fetch_add(1, std::memory_order_relaxed);
    }
    return host_sync_id;
}

pid_t hle_get_current_visible_tid(Emulator& emu) {
    uint64_t pthread_id = get_current_guest_pthread_id(emu);
    if (pthread_id == 0) {
        return 0;
    }

    pid_t tid = 0;
    if (hle_virtual_thread_is_virtual(pthread_id)) {
        if (pthread_id <= static_cast<uint64_t>(std::numeric_limits<pid_t>::max())) {
            tid = static_cast<pid_t>(pthread_id);
        }
    } else if (pthread_id == 1) {
        tid = ::getpid();
    } else {
        {
            std::lock_guard<std::mutex> lock(g_threads_mutex);
            auto it = g_threads.find(pthread_id);
            if (it != g_threads.end()) {
                tid = it->second->visible_tid.load(std::memory_order_acquire);
            }
        }
        if (tid <= 0) {
            tid = get_current_host_visible_tid();
            remember_thread_visible_tid(pthread_id, tid);
        }
    }

    hle_sched_note_thread_tid(tid);
    return tid;
}

pid_t hle_lookup_pthread_tid(Emulator& emu, uint64_t pthread_id) {
    if (pthread_id == 0) {
        return 0;
    }
    if (hle_virtual_thread_is_virtual(pthread_id)) {
        if (pthread_id <= static_cast<uint64_t>(std::numeric_limits<pid_t>::max())) {
            return static_cast<pid_t>(pthread_id);
        }
        return 0;
    }
    if (pthread_id == 1) {
        pid_t tid = ::getpid();
        hle_sched_note_thread_tid(tid);
        return tid;
    }

    pid_t cached_tid = 0;
    uint64_t parent_tid_addr = 0;
    uint64_t child_tid_addr = 0;
    {
        std::lock_guard<std::mutex> lock(g_threads_mutex);
        auto it = g_threads.find(pthread_id);
        if (it != g_threads.end()) {
            cached_tid = it->second->visible_tid.load(std::memory_order_acquire);
            parent_tid_addr = it->second->stack_base + 24;
            child_tid_addr = it->second->stack_base + 32;
        }
    }

    if (cached_tid > 0) {
        hle_sched_note_thread_tid(cached_tid);
        return cached_tid;
    }

    if (pthread_id == get_current_sync_thread_id(emu)) {
        return hle_get_current_visible_tid(emu);
    }

    if (parent_tid_addr != 0) {
        int32_t tid = 0;
        if (emu.mem_read(parent_tid_addr, &tid, sizeof(tid)) && tid > 0) {
            remember_thread_visible_tid(pthread_id, tid);
            hle_sched_note_thread_tid(tid);
            return static_cast<pid_t>(tid);
        }
    }

    if (child_tid_addr != 0) {
        int32_t tid = 0;
        if (emu.mem_read(child_tid_addr, &tid, sizeof(tid)) && tid > 0) {
            remember_thread_visible_tid(pthread_id, tid);
            hle_sched_note_thread_tid(tid);
            return static_cast<pid_t>(tid);
        }
    }

    return 0;
}

static void push_cleanup_handler(uint64_t thread_id, uint64_t cleanup_addr,
                                 uint64_t routine, uint64_t arg) {
    std::lock_guard<std::mutex> lock(g_cleanup_handlers_lock);
    g_cleanup_handlers[thread_id].push_back({cleanup_addr, routine, arg});
}

static bool pop_cleanup_handler(uint64_t thread_id, uint64_t cleanup_addr,
                                GuestCleanupHandler& handler) {
    std::lock_guard<std::mutex> lock(g_cleanup_handlers_lock);
    auto it = g_cleanup_handlers.find(thread_id);
    if (it == g_cleanup_handlers.end()) {
        return false;
    }

    auto& handlers = it->second;
    for (auto rit = handlers.rbegin(); rit != handlers.rend(); ++rit) {
        if (rit->cleanup_addr == cleanup_addr) {
            handler = *rit;
            handlers.erase(std::next(rit).base());
            if (handlers.empty()) {
                g_cleanup_handlers.erase(it);
            }
            return true;
        }
    }

    return false;
}

static bool pop_top_cleanup_handler(uint64_t thread_id, GuestCleanupHandler& handler) {
    std::lock_guard<std::mutex> lock(g_cleanup_handlers_lock);
    auto it = g_cleanup_handlers.find(thread_id);
    if (it == g_cleanup_handlers.end()) {
        return false;
    }

    auto& handlers = it->second;
    if (handlers.empty()) {
        g_cleanup_handlers.erase(it);
        return false;
    }

    handler = handlers.back();
    handlers.pop_back();
    if (handlers.empty()) {
        g_cleanup_handlers.erase(it);
    }
    return true;
}

static void remember_pending_pthread_exit(uint64_t thread_id, uint64_t retval) {
    std::lock_guard<std::mutex> lock(g_pending_pthread_exit_lock);
    g_pending_pthread_exit_values[thread_id] = retval;
}

static bool get_pending_pthread_exit(uint64_t thread_id, uint64_t& retval) {
    std::lock_guard<std::mutex> lock(g_pending_pthread_exit_lock);
    auto it = g_pending_pthread_exit_values.find(thread_id);
    if (it == g_pending_pthread_exit_values.end()) {
        return false;
    }
    retval = it->second;
    return true;
}

static void clear_pending_pthread_exit(uint64_t thread_id) {
    std::lock_guard<std::mutex> lock(g_pending_pthread_exit_lock);
    g_pending_pthread_exit_values.erase(thread_id);
}

static void write_cleanup_callback_trampoline(Emulator& emu) {
    std::call_once(g_cleanup_callback_trampoline_once, [&emu]() {
        static const uint32_t trampoline_code[] = {
            0xD10043FF,  // sub sp, sp, #16
            0xA9007BF3,  // stp x19, x30, [sp]
            0xD63F0220,  // blr x17
            0xA9407BF3,  // ldp x19, x30, [sp]
            0x910043FF,  // add sp, sp, #16
            0xD65F03C0,  // ret
        };
        emu.mem_write(CLEANUP_CALLBACK_TRAMPOLINE_ADDR, trampoline_code,
                      sizeof(trampoline_code));
    });
}

static void ensure_pthread_exit_code(Emulator& emu) {
    std::call_once(g_pthread_exit_code_once, [&emu]() {
        static const uint32_t exit_code[] = {
            0xD2800BA8,  // mov x8, #93 (SYS_exit)
            0xD4000001,  // svc #0
        };
        emu.mem_write(PTHREAD_EXIT_CODE_ADDR, exit_code, sizeof(exit_code));
    });
}

static bool dispatch_guest_cleanup_handler(Emulator& emu, const GuestCleanupHandler& handler,
                                           uint64_t return_addr) {
    if (handler.routine == 0) {
        return false;
    }

    write_cleanup_callback_trampoline(emu);

    set_reg(emu, UC_ARM64_REG_X0, handler.arg);
    set_reg(emu, UC_ARM64_REG_X17, handler.routine);
    set_reg(emu, UC_ARM64_REG_LR, return_addr);
    set_reg(emu, UC_ARM64_REG_PC, CLEANUP_CALLBACK_TRAMPOLINE_ADDR);

    return true;
}

static bool dispatch_next_pthread_exit_cleanup(Emulator& emu, uint64_t thread_id) {
    const uint64_t continue_addr = emu.hle().get_stub_address("__pthread_exit_continue");
    GuestCleanupHandler handler{};
    while (pop_top_cleanup_handler(thread_id, handler)) {
        if (dispatch_guest_cleanup_handler(emu, handler, continue_addr)) {
            return true;
        }
    }
    return false;
}

static void finish_guest_pthread_exit(Emulator& emu, uint64_t thread_id, uint64_t retval) {
    clear_pending_pthread_exit(thread_id);
    ensure_pthread_exit_code(emu);
    set_reg(emu, UC_ARM64_REG_X0, retval);
    set_reg(emu, UC_ARM64_REG_PC, PTHREAD_EXIT_CODE_ADDR);
}

static uint64_t get_current_tls_thread_id(Emulator& emu) {
    uint64_t virtual_tid = hle_virtual_thread_current_override();
    if (virtual_tid != 0) {
        return virtual_tid;
    }

    uint64_t sp = get_reg(emu, UC_ARM64_REG_SP);
    if (is_safe_call_stack_sp(sp)) {
        // Per-worker TLS namespace: slot 0 (main) keeps the legacy id 0; pool workers 1..N
        // get a unique id so each camera's pthread TLS values are isolated, not shared.
        uint64_t slot = safe_call_slot_from_sp(sp);
        if (slot == 0) {
            if (tl_current_thread_id == 0 || tl_current_thread_id == 1) {
                return 0;
            }
            return tl_current_thread_id;
        }
        return SAFE_CALL_TID_BASE + slot;
    }

    uint64_t thread_id = get_thread_id_from_sp(sp);
    tl_current_thread_id = (thread_id == 0) ? 1 : thread_id;
    return thread_id;
}

static void write_guest_pthread_attr_i32(Emulator& emu, uint64_t attr_addr, uint64_t offset, int32_t value) {
    if (attr_addr != 0) {
        emu.mem_write(attr_addr + offset, &value, sizeof(value));
    }
}

static void write_guest_pthread_attr_u64(Emulator& emu, uint64_t attr_addr, uint64_t offset, uint64_t value) {
    if (attr_addr != 0) {
        emu.mem_write(attr_addr + offset, &value, sizeof(value));
    }
}

static void initialize_guest_pthread_attr(Emulator& emu, uint64_t attr_addr) {
    if (attr_addr == 0) {
        return;
    }

    uint8_t zeros[GUEST_PTHREAD_ATTR_SIZE] = {0};
    emu.mem_write(attr_addr, zeros, sizeof(zeros));

    int32_t detachstate = GUEST_PTHREAD_CREATE_JOINABLE;
    uint64_t stackaddr = 0;
    uint64_t stacksize = GUEST_DEFAULT_PTHREAD_STACK_SIZE;
    uint64_t guardsize = GUEST_DEFAULT_PTHREAD_GUARD_SIZE;
    int32_t inheritsched = GUEST_PTHREAD_EXPLICIT_SCHED;
    int32_t schedpolicy = SCHED_OTHER;
    int32_t schedpriority = 0;
    int32_t scope = GUEST_PTHREAD_SCOPE_SYSTEM;

    write_guest_pthread_attr_i32(emu, attr_addr, GUEST_PTHREAD_ATTR_DETACHSTATE_OFFSET, detachstate);
    write_guest_pthread_attr_u64(emu, attr_addr, GUEST_PTHREAD_ATTR_STACKADDR_OFFSET, stackaddr);
    write_guest_pthread_attr_u64(emu, attr_addr, GUEST_PTHREAD_ATTR_STACKSIZE_OFFSET, stacksize);
    write_guest_pthread_attr_u64(emu, attr_addr, GUEST_PTHREAD_ATTR_GUARDSIZE_OFFSET, guardsize);
    write_guest_pthread_attr_i32(emu, attr_addr, GUEST_PTHREAD_ATTR_INHERITSCHED_OFFSET, inheritsched);
    write_guest_pthread_attr_i32(emu, attr_addr, GUEST_PTHREAD_ATTR_SCHEDPOLICY_OFFSET, schedpolicy);
    write_guest_pthread_attr_i32(emu, attr_addr, GUEST_PTHREAD_ATTR_SCHEDPRIORITY_OFFSET, schedpriority);
    write_guest_pthread_attr_i32(emu, attr_addr, GUEST_PTHREAD_ATTR_SCOPE_OFFSET, scope);
}

static int32_t read_guest_pthread_attr_detachstate(Emulator& emu, uint64_t attr_addr) {
    int32_t detachstate = GUEST_PTHREAD_CREATE_JOINABLE;
    if (attr_addr != 0) {
        emu.mem_read(attr_addr + GUEST_PTHREAD_ATTR_DETACHSTATE_OFFSET, &detachstate, sizeof(detachstate));
    }
    return detachstate;
}

static int32_t read_guest_pthread_attr_i32(Emulator& emu, uint64_t attr_addr, uint64_t offset, int32_t default_value) {
    int32_t value = default_value;
    if (attr_addr != 0) {
        emu.mem_read(attr_addr + offset, &value, sizeof(value));
    }
    return value;
}

static uint64_t read_guest_pthread_attr_u64(Emulator& emu, uint64_t attr_addr, uint64_t offset, uint64_t default_value) {
    uint64_t value = default_value;
    if (attr_addr != 0) {
        emu.mem_read(attr_addr + offset, &value, sizeof(value));
    }
    return value;
}

static bool is_valid_guest_mutex_type(int type) {
    return type == PTHREAD_MUTEX_NORMAL ||
           type == PTHREAD_MUTEX_ERRORCHECK ||
           type == PTHREAD_MUTEX_RECURSIVE;
}

static bool is_valid_guest_mutex_protocol(int protocol) {
    return protocol == PTHREAD_PRIO_NONE ||
           protocol == PTHREAD_PRIO_INHERIT;
}

static uint64_t encode_guest_mutexattr_value(int type, int pshared, int protocol) {
    return (static_cast<uint64_t>(type & 0xff) << GUEST_PTHREAD_MUTEXATTR_TYPE_SHIFT) |
           (static_cast<uint64_t>(pshared & 0xff) << GUEST_PTHREAD_MUTEXATTR_PSHARED_SHIFT) |
           (static_cast<uint64_t>(protocol & 0xff) << GUEST_PTHREAD_MUTEXATTR_PROTOCOL_SHIFT);
}

static bool decode_guest_mutexattr_value(uint64_t raw, int& type, int& pshared, int& protocol) {
    type = static_cast<int>((raw >> GUEST_PTHREAD_MUTEXATTR_TYPE_SHIFT) & 0xff);
    pshared = static_cast<int>((raw >> GUEST_PTHREAD_MUTEXATTR_PSHARED_SHIFT) & 0xff);
    protocol = static_cast<int>((raw >> GUEST_PTHREAD_MUTEXATTR_PROTOCOL_SHIFT) & 0xff);
    return is_valid_guest_mutex_type(type) &&
           is_valid_guest_pshared(pshared) &&
           is_valid_guest_mutex_protocol(protocol);
}

static bool read_guest_mutexattr(Emulator& emu, uint64_t attr_addr, int& type, int& pshared,
                                 int& protocol) {
    if (attr_addr == 0 || attr_addr < 0x1000) {
        return false;
    }

    uint64_t raw = 0;
    if (!emu.mem_read(attr_addr, &raw, sizeof(raw))) {
        return false;
    }
    return decode_guest_mutexattr_value(raw, type, pshared, protocol);
}

static bool write_guest_mutexattr(Emulator& emu, uint64_t attr_addr, int type, int pshared,
                                  int protocol) {
    if (attr_addr == 0 || attr_addr < 0x1000 ||
        !is_valid_guest_mutex_type(type) ||
        !is_valid_guest_pshared(pshared) ||
        !is_valid_guest_mutex_protocol(protocol)) {
        return false;
    }

    uint64_t raw = encode_guest_mutexattr_value(type, pshared, protocol);
    return emu.mem_write(attr_addr, &raw, sizeof(raw));
}

static std::shared_ptr<HostMutex> initialize_mutex(uint64_t guest_mutex_addr, int type, int protocol,
                                                   int pshared) {
    if (guest_mutex_addr == 0 || guest_mutex_addr < 0x1000) {
        static auto dummy_mutex = std::make_shared<HostMutex>();
        return dummy_mutex;
    }

    std::lock_guard<std::mutex> lock(g_mutexes_lock);
    auto mtx = std::make_shared<HostMutex>();
    mtx->type = type;
    mtx->protocol = protocol;
    mtx->pshared = pshared;
    g_host_mutexes[guest_mutex_addr] = mtx;
    return mtx;
}

static int32_t encode_guest_mutex_word(int type) {
    return (type & 0x3) << 14;
}

static bool get_live_thread_sched_locked(uint64_t thread_id, int& sched_policy, int& sched_priority) {
    if (thread_id == 1) {
        sched_policy = g_main_thread_sched_policy;
        sched_priority = g_main_thread_sched_priority;
        return true;
    }

    auto it = g_threads.find(thread_id);
    if (it == g_threads.end() || it->second->completed.load()) {
        return false;
    }

    sched_policy = it->second->sched_policy;
    sched_priority = it->second->sched_priority;
    return true;
}

static bool validate_sched_params(int sched_policy, int sched_priority) {
    int base_policy = sched_policy;
#ifdef SCHED_RESET_ON_FORK
    base_policy &= ~SCHED_RESET_ON_FORK;
#endif

    switch (base_policy) {
        case SCHED_OTHER:
            return sched_priority == 0;
        case SCHED_FIFO:
        case SCHED_RR:
            {
                int min_priority = ::sched_get_priority_min(base_policy);
                int max_priority = ::sched_get_priority_max(base_policy);
                if (min_priority == -1 || max_priority == -1) {
                    return false;
                }
                return sched_priority >= min_priority && sched_priority <= max_priority;
            }
        default:
            return false;
    }
}

static bool read_guest_sched_priority(Emulator& emu, uint64_t sched_param_addr, int& sched_priority) {
    if (sched_param_addr == 0) {
        return false;
    }

    int32_t priority32 = 0;
    if (!emu.mem_read(sched_param_addr, &priority32, sizeof(priority32))) {
        return false;
    }

    sched_priority = priority32;
    return true;
}

static bool write_guest_sched_priority(Emulator& emu, uint64_t sched_param_addr, int sched_priority) {
    if (sched_param_addr == 0) {
        return false;
    }

    int32_t priority32 = sched_priority;
    return emu.mem_write(sched_param_addr, &priority32, sizeof(priority32));
}

static bool is_live_pthread_id_locked(uint64_t thread_id) {
    if (thread_id == 1) {
        return true;
    }

    auto it = g_threads.find(thread_id);
    if (it == g_threads.end()) {
        return false;
    }

    return !it->second->completed.load();
}

static bool is_valid_tls_key_locked(uint64_t key) {
    return key != 0 && g_tls_live_keys.find(key) != g_tls_live_keys.end();
}

static std::atomic<uint64_t> g_next_stack_addr{QEMU_THREAD_STACK_BASE};
static std::atomic<uint64_t> g_next_tls_addr{QEMU_THREAD_TLS_BASE};

// Freelists of exited threads' region base addresses (the raw `addr` the bump allocator
// produced, NOT the returned stack_top/tls_base). Recycling these is what bounds the
// arenas: without it every camera reconnect permanently consumes a 1MB stack slot and
// the 0x90000000..0xA0000000 arena exhausts after ~256 thread creations, which under
// sustained multi-camera reconnect churn manifests as periodic crashes / cameras that
// can no longer reconnect (AV_ER_FAIL_CREATE_THREAD). The region memory stays mapped
// after a thread exits, so a recycled region is reused WITHOUT re-mapping.
static std::mutex g_thread_arena_mutex;
static std::vector<uint64_t> g_free_stack_region_bases;
static std::vector<uint64_t> g_free_tls_region_bases;

// Thread exit address - special HLE address that terminates thread
static constexpr uint64_t THREAD_EXIT_ADDR = 0x100FFFF0;

// Allocate stack for a new thread (reuses an exited thread's region when available).
static uint64_t allocate_thread_stack(Emulator& emu) {
    uint64_t addr;
    bool recycled = false;
    {
        std::lock_guard<std::mutex> lk(g_thread_arena_mutex);
        if (!g_free_stack_region_bases.empty()) {
            addr = g_free_stack_region_bases.back();
            g_free_stack_region_bases.pop_back();
            recycled = true;
        } else {
            // Reserve a fresh slot, but never cross into the safe-call stack arena.
            uint64_t next = g_next_stack_addr.load(std::memory_order_relaxed);
            if (next + QEMU_THREAD_STACK_SIZE > QEMU_THREAD_STACK_CEILING) {
                EMU_ALWAYS_LOG << "[HLE] allocate_thread_stack: arena exhausted at 0x"
                               << std::hex << next << std::dec
                               << " (live threads too high); failing pthread_create" << std::endl;
                return 0;
            }
            addr = g_next_stack_addr.fetch_add(QEMU_THREAD_STACK_SIZE);
        }
    }
    uint64_t stack_top = addr + QEMU_THREAD_STACK_SIZE - 0x100;
    if (!hle_try_reserve_vmas(stack_top, 2)) {
        if (recycled) {
            std::lock_guard<std::mutex> lk(g_thread_arena_mutex);
            g_free_stack_region_bases.push_back(addr);
        }
        return 0;
    }
    // Recycled regions are already mapped (we never unmap on thread exit); only fresh
    // regions need mapping.
    if (!recycled && !emu.memory().map(addr, QEMU_THREAD_STACK_SIZE, MEM_READ | MEM_WRITE)) {
        hle_release_vmas(stack_top);
        std::lock_guard<std::mutex> lk(g_thread_arena_mutex);
        g_free_stack_region_bases.push_back(addr);
        return 0;
    }
    return stack_top;  // Return top of stack minus some space
}

// Allocate TLS for a new thread (reuses an exited thread's region when available).
static uint64_t allocate_thread_tls(Emulator& emu) {
    uint64_t addr;
    bool recycled = false;
    {
        std::lock_guard<std::mutex> lk(g_thread_arena_mutex);
        if (!g_free_tls_region_bases.empty()) {
            addr = g_free_tls_region_bases.back();
            g_free_tls_region_bases.pop_back();
            recycled = true;
        } else {
            uint64_t next = g_next_tls_addr.load(std::memory_order_relaxed);
            if (next + QEMU_THREAD_TLS_SIZE > QEMU_THREAD_TLS_CEILING) {
                EMU_ALWAYS_LOG << "[HLE] allocate_thread_tls: TLS arena exhausted at 0x"
                               << std::hex << next << std::dec << "; failing pthread_create" << std::endl;
                return 0;
            }
            addr = g_next_tls_addr.fetch_add(QEMU_THREAD_TLS_SIZE);
        }
    }
    uint64_t tls_base = addr + 8;
    if (!hle_try_reserve_vmas(tls_base, 1)) {
        if (recycled) {
            std::lock_guard<std::mutex> lk(g_thread_arena_mutex);
            g_free_tls_region_bases.push_back(addr);
        }
        return 0;
    }
    if (!recycled && !emu.memory().map(addr, QEMU_THREAD_TLS_SIZE, MEM_READ | MEM_WRITE)) {
        hle_release_vmas(tls_base);
        std::lock_guard<std::mutex> lk(g_thread_arena_mutex);
        g_free_tls_region_bases.push_back(addr);
        return 0;
    }

    // Initialize TLS with stack canary at offset 0x28 (re-init every time, including on
    // recycle, since a prior thread may have left stale bytes here).
    uint64_t canary = 0xDEADBEEFCAFEBABEULL;
    emu.mem_write(addr + 0x28, &canary, sizeof(canary));
    emu.mem_write(addr + 0x30, &canary, sizeof(canary));

    // Return TLS base + 8 (the value for TPIDR_EL0)
    return tls_base;
}

// Return an exited thread's arena regions to the freelists so the next pthread_create
// can reuse them. A stack is recycled ONLY if its region base falls within OUR arena
// address range — guest-provided custom stacks (allocated from the guest heap) land
// outside the range and are never touched. NOTE: guest_stack_addr is NOT a reliable
// "custom stack" flag (pthread_create sets it to a computed value for arena stacks too),
// so we key purely on the address range. MUST be called AFTER the thread's g_threads
// entry has been erased, so no live entry shares the recycled stack's SP range (which
// would corrupt the SP-based exit lookup in notify_thread_exit).
static void recycle_thread_arena(uint64_t stack_base, uint64_t guest_stack_addr, uint64_t tls_base) {
    (void)guest_stack_addr;
    std::lock_guard<std::mutex> lk(g_thread_arena_mutex);
    if (stack_base != 0) {
        uint64_t region = stack_base - QEMU_THREAD_STACK_SIZE + 0x100;
        if (region >= QEMU_THREAD_STACK_BASE && region < QEMU_THREAD_STACK_CEILING) {
            g_free_stack_region_bases.push_back(region);
        }
    }
    if (tls_base != 0) {
        uint64_t region = tls_base - 8;
        if (region >= QEMU_THREAD_TLS_BASE && region < QEMU_THREAD_TLS_CEILING) {
            g_free_tls_region_bases.push_back(region);
        }
    }
}

// Clone trampoline addresses
static constexpr uint64_t CLONE_TRAMPOLINE_ADDR = 0x10080000;
static constexpr uint64_t THREAD_WRAPPER_ADDR = 0x10080100;
static constexpr uint64_t THREAD_DONE_HLE_ADDR = 0x10010000;  // HLE callback before exit (unused now)

// Custom syscall number for thread completion notification
// This is handled by our syscall hook and works for all threads (including children)
static constexpr uint64_t SYS_THREAD_DONE = 0x1234;

// Forward declaration for thread exit notification
void notify_thread_exit(uint64_t thread_locator, uint64_t retval, bool finalize);

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
    // Stack layout: [SP+0]=start_routine, [SP+8]=arg, [SP+16]=tls
    //
    // Code:
    //   LDR X4, [SP, #16]      // X4 = tls
    //   MSR TPIDR_EL0, X4      // Set TPIDR_EL0 for this thread
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
    // LDR X4, [SP, #16] = 0xF9400BE4 (unsigned offset 16/8=2)
    // MSR TPIDR_EL0, X4 = 0xD51BD044
    uint32_t wrapper_code[] = {
        0xF9400BE4,  // LDR X4, [SP, #16] (X4 = tls)
        0xD51BD044,  // MSR TPIDR_EL0, X4 (set thread's TLS register)
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
        notify_thread_exit(tls_base, retval, false);

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
        if (!write_guest_mutexattr(
                emu, attr, PTHREAD_MUTEX_NORMAL, GUEST_PTHREAD_PROCESS_PRIVATE, PTHREAD_PRIO_NONE)) {
            set_reg(emu, UC_ARM64_REG_X0, EINVAL);
            return;
        }
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("pthread_mutexattr_destroy", [](Emulator& emu) {
        uint64_t attr = get_reg(emu, UC_ARM64_REG_X0);
        if (attr == 0 || attr < 0x1000) {
            set_reg(emu, UC_ARM64_REG_X0, EINVAL);
            return;
        }
        uint64_t zero = 0;
        emu.mem_write(attr, &zero, sizeof(zero));
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("pthread_mutexattr_settype", [](Emulator& emu) {
        uint64_t attr = get_reg(emu, UC_ARM64_REG_X0);
        int type = static_cast<int>(get_reg(emu, UC_ARM64_REG_X1));
        int old_type = PTHREAD_MUTEX_NORMAL;
        int pshared = GUEST_PTHREAD_PROCESS_PRIVATE;
        int protocol = PTHREAD_PRIO_NONE;
        if (!is_valid_guest_mutex_type(type) ||
            !read_guest_mutexattr(emu, attr, old_type, pshared, protocol) ||
            !write_guest_mutexattr(emu, attr, type, pshared, protocol)) {
            set_reg(emu, UC_ARM64_REG_X0, EINVAL);
            return;
        }
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("pthread_mutexattr_gettype", [](Emulator& emu) {
        uint64_t attr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t type_ptr = get_reg(emu, UC_ARM64_REG_X1);
        int type = PTHREAD_MUTEX_NORMAL;
        int pshared = GUEST_PTHREAD_PROCESS_PRIVATE;
        int protocol = PTHREAD_PRIO_NONE;
        if (type_ptr == 0 || !read_guest_mutexattr(emu, attr, type, pshared, protocol)) {
            set_reg(emu, UC_ARM64_REG_X0, EINVAL);
            return;
        }
        int32_t guest_type = type;
        emu.mem_write(type_ptr, &guest_type, sizeof(guest_type));
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("pthread_mutexattr_getpshared", [](Emulator& emu) {
        uint64_t attr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t shared_ptr = get_reg(emu, UC_ARM64_REG_X1);
        int type = PTHREAD_MUTEX_NORMAL;
        int pshared = GUEST_PTHREAD_PROCESS_PRIVATE;
        int protocol = PTHREAD_PRIO_NONE;
        if (shared_ptr == 0 || !read_guest_mutexattr(emu, attr, type, pshared, protocol)) {
            set_reg(emu, UC_ARM64_REG_X0, EINVAL);
            return;
        }
        int32_t guest_pshared = pshared;
        emu.mem_write(shared_ptr, &guest_pshared, sizeof(guest_pshared));
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("pthread_mutexattr_setpshared", [](Emulator& emu) {
        uint64_t attr = get_reg(emu, UC_ARM64_REG_X0);
        int pshared = static_cast<int>(get_reg(emu, UC_ARM64_REG_X1));
        int type = PTHREAD_MUTEX_NORMAL;
        int old_pshared = GUEST_PTHREAD_PROCESS_PRIVATE;
        int protocol = PTHREAD_PRIO_NONE;
        if (!is_valid_guest_pshared(pshared) ||
            !read_guest_mutexattr(emu, attr, type, old_pshared, protocol) ||
            !write_guest_mutexattr(emu, attr, type, pshared, protocol)) {
            set_reg(emu, UC_ARM64_REG_X0, EINVAL);
            return;
        }
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("pthread_mutexattr_getprotocol", [](Emulator& emu) {
        uint64_t attr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t protocol_ptr = get_reg(emu, UC_ARM64_REG_X1);
        int type = PTHREAD_MUTEX_NORMAL;
        int pshared = GUEST_PTHREAD_PROCESS_PRIVATE;
        int protocol = PTHREAD_PRIO_NONE;
        if (protocol_ptr == 0 || !read_guest_mutexattr(emu, attr, type, pshared, protocol)) {
            set_reg(emu, UC_ARM64_REG_X0, EINVAL);
            return;
        }
        int32_t guest_protocol = protocol;
        emu.mem_write(protocol_ptr, &guest_protocol, sizeof(guest_protocol));
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("pthread_mutexattr_setprotocol", [](Emulator& emu) {
        uint64_t attr = get_reg(emu, UC_ARM64_REG_X0);
        int protocol = static_cast<int>(get_reg(emu, UC_ARM64_REG_X1));
        int type = PTHREAD_MUTEX_NORMAL;
        int pshared = GUEST_PTHREAD_PROCESS_PRIVATE;
        int old_protocol = PTHREAD_PRIO_NONE;
        if (!is_valid_guest_mutex_protocol(protocol) ||
            !read_guest_mutexattr(emu, attr, type, pshared, old_protocol) ||
            !write_guest_mutexattr(emu, attr, type, pshared, protocol)) {
            set_reg(emu, UC_ARM64_REG_X0, EINVAL);
            return;
        }
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    // ========================================================================
    // Mutex operations - use HOST mutexes for QEMU MTTCG
    // ========================================================================
    // With QEMU MTTCG, threads run in parallel on real host threads.
    // We use real std::recursive_mutex for proper blocking behavior.

    hle.register_function("pthread_mutex_init", [](Emulator& emu) {
        uint64_t mutex = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t attr_addr = get_reg(emu, UC_ARM64_REG_X1);
        int type = PTHREAD_MUTEX_NORMAL;
        int pshared = GUEST_PTHREAD_PROCESS_PRIVATE;
        int protocol = PTHREAD_PRIO_NONE;
        if (attr_addr != 0 && !read_guest_mutexattr(emu, attr_addr, type, pshared, protocol)) {
            set_reg(emu, UC_ARM64_REG_X0, EINVAL);
            return;
        }

        uint8_t zeros[GUEST_PTHREAD_MUTEX_SIZE] = {0};
        emu.mem_write(mutex, zeros, sizeof(zeros));
        int32_t state = encode_guest_mutex_word(type);
        emu.mem_write(mutex, &state, sizeof(state));

        initialize_mutex(mutex, type, protocol, pshared);
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("pthread_mutex_destroy", [](Emulator& emu) {
        uint64_t mutex = get_reg(emu, UC_ARM64_REG_X0);
        {
            std::lock_guard<std::mutex> lock(g_mutexes_lock);
            g_host_mutexes.erase(mutex);
        }
        uint8_t zeros[GUEST_PTHREAD_MUTEX_SIZE] = {0};
        emu.mem_write(mutex, zeros, sizeof(zeros));
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("pthread_mutex_lock", [](Emulator& emu) {
        uint64_t mutex_addr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t sp = get_reg(emu, UC_ARM64_REG_SP);
        uint64_t tid = get_thread_id_from_sp(sp);
        uint64_t visible_tid = get_current_sync_thread_id(emu);

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

        auto mtx = get_or_create_mutex(mutex_addr);
        if (mtx->owner_thread.load() == visible_tid && mtx->lock_count.load() > 0) {
            if (mtx->type == PTHREAD_MUTEX_RECURSIVE) {
                mtx->mtx.lock();
                mtx->lock_count++;
                set_reg(emu, UC_ARM64_REG_X0, 0);
                return;
            }
            if (mtx->type == PTHREAD_MUTEX_ERRORCHECK) {
                set_reg(emu, UC_ARM64_REG_X0, EDEADLK);
                return;
            }
        }

        pid_t pi_owner_tid = 0;
        if (mtx->protocol == PTHREAD_PRIO_INHERIT && mtx->lock_count.load() > 0 &&
            mtx->owner_thread.load() != visible_tid) {
            pi_owner_tid = static_cast<pid_t>(mtx->owner_thread.load());
            hle_sched_pi_boost_begin(pi_owner_tid);
        }
        if (g_lock_trace && mtx->lock_count.load() > 0 && mtx->owner_thread.load() != visible_tid) {
            EMU_ALWAYS_LOG << "[LOCKTRACE] T0x" << std::hex << visible_tid << " WAIT mutex 0x"
                           << mutex_addr << " owner=T0x" << mtx->owner_thread.load()
                           << std::dec << std::endl;
        }
        mtx->mtx.lock();
        if (pi_owner_tid > 0) {
            hle_sched_pi_boost_end(pi_owner_tid);
        }
        mtx->owner_thread.store(visible_tid);
        mtx->lock_count++;
        if (g_lock_trace) {
            EMU_ALWAYS_LOG << "[LOCKTRACE] T0x" << std::hex << visible_tid << " ACQ  mutex 0x"
                           << mutex_addr << std::dec << std::endl;
        }

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
        uint64_t visible_tid = get_current_sync_thread_id(emu);

        if (mutex_addr == 0) {
            set_reg(emu, UC_ARM64_REG_X0, EINVAL);
            return;
        }

        auto mtx = get_or_create_mutex(mutex_addr);

        if (mtx->owner_thread.load() == visible_tid && mtx->lock_count.load() > 0) {
            if (mtx->type == PTHREAD_MUTEX_RECURSIVE) {
                if (mtx->mtx.try_lock()) {
                    mtx->lock_count++;
                    set_reg(emu, UC_ARM64_REG_X0, 0);
                } else {
                    set_reg(emu, UC_ARM64_REG_X0, EBUSY);
                }
                return;
            }
            if (mtx->type == PTHREAD_MUTEX_ERRORCHECK && mtx->protocol == PTHREAD_PRIO_INHERIT) {
                set_reg(emu, UC_ARM64_REG_X0, EDEADLK);
                return;
            }
            set_reg(emu, UC_ARM64_REG_X0, EBUSY);
            return;
        }

        if (mtx->mtx.try_lock()) {
            mtx->owner_thread.store(visible_tid);
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
        uint64_t visible_tid = get_current_sync_thread_id(emu);

        if (emu.is_debug()) {
            EMU_LOG << "[HLE:T" << std::hex << tid << "] pthread_mutex_unlock: mutex=0x"
                      << mutex_addr << std::dec << std::endl;
        }

        if (mutex_addr == 0) {
            set_reg(emu, UC_ARM64_REG_X0, EINVAL);
            return;
        }

        auto mtx = get_or_create_mutex(mutex_addr);
        if (mtx->lock_count.load() <= 0 || mtx->owner_thread.load() != visible_tid) {
            if (g_lock_trace) {
                EMU_ALWAYS_LOG << "[LOCKTRACE] T0x" << std::hex << visible_tid
                               << " UNLOCK-EPERM mutex 0x" << mutex_addr << " owner=T0x"
                               << mtx->owner_thread.load() << " count=" << std::dec
                               << mtx->lock_count.load() << std::endl;
            }
            set_reg(emu, UC_ARM64_REG_X0, EPERM);
            return;
        }

        mtx->lock_count--;
        if (mtx->lock_count.load() == 0) {
            mtx->owner_thread.store(0);
        }
        mtx->mtx.unlock();
        if (g_lock_trace) {
            EMU_ALWAYS_LOG << "[LOCKTRACE] T0x" << std::hex << visible_tid << " REL  mutex 0x"
                           << mutex_addr << std::dec << std::endl;
        }

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
        uint64_t attr_addr = get_reg(emu, UC_ARM64_REG_X0);
        if (!write_guest_condattr(emu, attr_addr, CLOCK_REALTIME, GUEST_PTHREAD_PROCESS_PRIVATE)) {
            set_reg(emu, UC_ARM64_REG_X0, EINVAL);
            return;
        }
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("pthread_condattr_destroy", [](Emulator& emu) {
        uint64_t attr_addr = get_reg(emu, UC_ARM64_REG_X0);
        if (attr_addr == 0 || attr_addr < 0x1000) {
            set_reg(emu, UC_ARM64_REG_X0, EINVAL);
            return;
        }
        uint64_t zero = 0;
        emu.mem_write(attr_addr, &zero, sizeof(zero));
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("pthread_condattr_getclock", [](Emulator& emu) {
        uint64_t attr_addr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t clock_ptr = get_reg(emu, UC_ARM64_REG_X1);
        int clockid = CLOCK_REALTIME;
        int pshared = GUEST_PTHREAD_PROCESS_PRIVATE;
        if (clock_ptr == 0 || !read_guest_condattr(emu, attr_addr, clockid, pshared)) {
            set_reg(emu, UC_ARM64_REG_X0, EINVAL);
            return;
        }
        int32_t guest_clockid = clockid;
        emu.mem_write(clock_ptr, &guest_clockid, sizeof(guest_clockid));
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("pthread_condattr_setclock", [](Emulator& emu) {
        uint64_t attr_addr = get_reg(emu, UC_ARM64_REG_X0);
        int clockid = static_cast<int>(get_reg(emu, UC_ARM64_REG_X1));
        int existing_clockid = CLOCK_REALTIME;
        int pshared = GUEST_PTHREAD_PROCESS_PRIVATE;
        if (!is_valid_guest_cond_clock(clockid) ||
            !read_guest_condattr(emu, attr_addr, existing_clockid, pshared) ||
            !write_guest_condattr(emu, attr_addr, clockid, pshared)) {
            set_reg(emu, UC_ARM64_REG_X0, EINVAL);
            return;
        }
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("pthread_condattr_getpshared", [](Emulator& emu) {
        uint64_t attr_addr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t shared_ptr = get_reg(emu, UC_ARM64_REG_X1);
        int clockid = CLOCK_REALTIME;
        int pshared = GUEST_PTHREAD_PROCESS_PRIVATE;
        if (shared_ptr == 0 || !read_guest_condattr(emu, attr_addr, clockid, pshared)) {
            set_reg(emu, UC_ARM64_REG_X0, EINVAL);
            return;
        }
        int32_t guest_pshared = pshared;
        emu.mem_write(shared_ptr, &guest_pshared, sizeof(guest_pshared));
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("pthread_condattr_setpshared", [](Emulator& emu) {
        uint64_t attr_addr = get_reg(emu, UC_ARM64_REG_X0);
        int pshared = static_cast<int>(get_reg(emu, UC_ARM64_REG_X1));
        int clockid = CLOCK_REALTIME;
        int existing_pshared = GUEST_PTHREAD_PROCESS_PRIVATE;
        if (!is_valid_guest_pshared(pshared) ||
            !read_guest_condattr(emu, attr_addr, clockid, existing_pshared) ||
            !write_guest_condattr(emu, attr_addr, clockid, pshared)) {
            set_reg(emu, UC_ARM64_REG_X0, EINVAL);
            return;
        }
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    // ========================================================================
    // Condition variable operations - use HOST condvars for QEMU MTTCG
    // ========================================================================

    hle.register_function("pthread_cond_init", [](Emulator& emu) {
        uint64_t cond = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t attr_addr = get_reg(emu, UC_ARM64_REG_X1);
        int clockid = CLOCK_REALTIME;
        int pshared = GUEST_PTHREAD_PROCESS_PRIVATE;
        if (attr_addr != 0 && !read_guest_condattr(emu, attr_addr, clockid, pshared)) {
            set_reg(emu, UC_ARM64_REG_X0, EINVAL);
            return;
        }

        uint8_t zeros[GUEST_PTHREAD_COND_SIZE] = {0};
        emu.mem_write(cond, zeros, sizeof(zeros));
        uint32_t encoded_attr = static_cast<uint32_t>(encode_guest_condattr_value(clockid, pshared));
        emu.mem_write(cond, &encoded_attr, sizeof(encoded_attr));

        initialize_condvar(cond, clockid, pshared);
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
        uint64_t visible_tid = get_current_sync_thread_id(emu);

        int call_num = ++g_cond_wait_count;
        if (TRACE_PTHREAD_SYNC && (call_num <= 20 || call_num % 100 == 0)) {
            EMU_LOG << "[SYNC-TRACE] cond_wait ENTER #" << call_num << " cond=0x"
                    << std::hex << cond_addr << " mutex=0x" << mutex_addr
                    << " tid=0x" << tid << std::dec << std::endl;
        }

        auto cv = get_or_create_condvar(cond_addr);
        auto mtx = get_or_create_mutex(mutex_addr);

        if (g_lock_trace) {
            EMU_ALWAYS_LOG << "[LOCKTRACE] T0x" << std::hex << visible_tid << " CWAIT cond 0x"
                           << cond_addr << " mutex 0x" << mutex_addr << std::dec << std::endl;
        }
        int result = wait_cond_with_clock(*cv, *mtx, cv->clockid, nullptr, visible_tid);
        if (g_lock_trace) {
            EMU_ALWAYS_LOG << "[LOCKTRACE] T0x" << std::hex << visible_tid << " CWAKE cond 0x"
                           << cond_addr << std::dec << std::endl;
        }

        if (TRACE_PTHREAD_SYNC && (call_num <= 20 || call_num % 100 == 0)) {
            EMU_LOG << "[SYNC-TRACE] cond_wait EXIT #" << call_num
                    << " result=" << result << std::endl;
        }

        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("pthread_cond_timedwait", [](Emulator& emu) {
        uint64_t cond_addr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t mutex_addr = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t abstime_ptr = get_reg(emu, UC_ARM64_REG_X2);
        uint64_t sp = get_reg(emu, UC_ARM64_REG_SP);
        uint64_t tid = get_thread_id_from_sp(sp);
        uint64_t visible_tid = get_current_sync_thread_id(emu);

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

        set_reg(emu, UC_ARM64_REG_X0, wait_cond_with_clock(*cv, *mtx, cv->clockid, &ts, visible_tid));
    });

    hle.register_function("pthread_cond_signal", [](Emulator& emu) {
        uint64_t cond_addr = get_reg(emu, UC_ARM64_REG_X0);
        int call_num = ++g_cond_signal_count;
        if (TRACE_PTHREAD_SYNC && (call_num <= 20 || call_num % 100 == 0)) {
            EMU_LOG << "[SYNC-TRACE] cond_signal #" << call_num
                    << " cond=0x" << std::hex << cond_addr << std::dec << std::endl;
        }
        auto cv = get_or_create_condvar(cond_addr);
        if (g_lock_trace) {
            EMU_ALWAYS_LOG << "[LOCKTRACE] T0x" << std::hex << get_current_sync_thread_id(emu)
                           << " SIGNAL cond 0x" << cond_addr << std::dec << std::endl;
        }
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

    hle.register_function("pthread_rwlockattr_init", [](Emulator& emu) {
        uint64_t attr_addr = get_reg(emu, UC_ARM64_REG_X0);
        if (attr_addr == 0 || attr_addr < 0x1000) {
            set_reg(emu, UC_ARM64_REG_X0, EINVAL);
            return;
        }

        initialize_guest_rwlock_attr(emu, attr_addr);
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("pthread_rwlockattr_destroy", [](Emulator& emu) {
        uint64_t attr_addr = get_reg(emu, UC_ARM64_REG_X0);
        if (attr_addr == 0 || attr_addr < 0x1000) {
            set_reg(emu, UC_ARM64_REG_X0, EINVAL);
            return;
        }

        uint8_t zeros[GUEST_PTHREAD_RWLOCK_ATTR_SIZE] = {0};
        emu.mem_write(attr_addr, zeros, sizeof(zeros));
        {
            std::lock_guard<std::mutex> lock(g_rwlockattrs_lock);
            g_guest_rwlockattrs.erase(attr_addr);
        }
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("pthread_rwlockattr_getpshared", [](Emulator& emu) {
        uint64_t attr_addr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t shared_ptr = get_reg(emu, UC_ARM64_REG_X1);
        int shared = GUEST_PTHREAD_PROCESS_PRIVATE;

        if (shared_ptr == 0 || !get_guest_rwlock_attr_pshared(attr_addr, shared)) {
            set_reg(emu, UC_ARM64_REG_X0, EINVAL);
            return;
        }

        emu.mem_write(shared_ptr, &shared, sizeof(shared));
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("pthread_rwlockattr_setpshared", [](Emulator& emu) {
        uint64_t attr_addr = get_reg(emu, UC_ARM64_REG_X0);
        int shared = static_cast<int>(get_reg(emu, UC_ARM64_REG_X1));
        if (!is_valid_guest_rwlock_pshared(shared) ||
            !set_guest_rwlock_attr_pshared(attr_addr, shared)) {
            set_reg(emu, UC_ARM64_REG_X0, EINVAL);
            return;
        }

        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("pthread_rwlockattr_getkind_np", [](Emulator& emu) {
        uint64_t attr_addr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t kind_ptr = get_reg(emu, UC_ARM64_REG_X1);
        int kind = GUEST_PTHREAD_RWLOCK_PREFER_READER_NP;

        if (kind_ptr == 0 || !get_guest_rwlock_attr_kind(attr_addr, kind)) {
            set_reg(emu, UC_ARM64_REG_X0, EINVAL);
            return;
        }

        emu.mem_write(kind_ptr, &kind, sizeof(kind));
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("pthread_rwlockattr_setkind_np", [](Emulator& emu) {
        uint64_t attr_addr = get_reg(emu, UC_ARM64_REG_X0);
        int kind = static_cast<int>(get_reg(emu, UC_ARM64_REG_X1));
        if (!is_valid_guest_rwlock_kind(kind) ||
            !set_guest_rwlock_attr_kind(attr_addr, kind)) {
            set_reg(emu, UC_ARM64_REG_X0, EINVAL);
            return;
        }

        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("pthread_rwlock_init", [](Emulator& emu) {
        uint64_t rwlock_addr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t attr_addr = get_reg(emu, UC_ARM64_REG_X1);

        if (rwlock_addr == 0 || rwlock_addr < 0x1000) {
            set_reg(emu, UC_ARM64_REG_X0, EINVAL);
            return;
        }

        uint8_t zero_rwlock[GUEST_PTHREAD_RWLOCK_SIZE] = {0};
        emu.mem_write(rwlock_addr, zero_rwlock, sizeof(zero_rwlock));

        GuestRWLockAttr attr = get_guest_rwlock_attr(attr_addr);
        auto rwl = initialize_rwlock(rwlock_addr, attr);
        set_reg(emu, UC_ARM64_REG_X0, rwl->init_result);
    });

    hle.register_function("pthread_rwlock_destroy", [](Emulator& emu) {
        uint64_t rwlock_addr = get_reg(emu, UC_ARM64_REG_X0);
        destroy_rwlock(rwlock_addr);
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("pthread_rwlock_rdlock", [](Emulator& emu) {
        uint64_t rwlock_addr = get_reg(emu, UC_ARM64_REG_X0);
        auto rwl = get_or_create_rwlock(rwlock_addr);
        int result = rdlock_rwlock(*rwl);
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("pthread_rwlock_wrlock", [](Emulator& emu) {
        uint64_t rwlock_addr = get_reg(emu, UC_ARM64_REG_X0);
        auto rwl = get_or_create_rwlock(rwlock_addr);
        int result = wrlock_rwlock(*rwl);
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("pthread_rwlock_unlock", [](Emulator& emu) {
        uint64_t rwlock_addr = get_reg(emu, UC_ARM64_REG_X0);
        auto rwl = get_or_create_rwlock(rwlock_addr);
        int result = unlock_rwlock(*rwl);
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("pthread_rwlock_tryrdlock", [](Emulator& emu) {
        uint64_t rwlock_addr = get_reg(emu, UC_ARM64_REG_X0);
        auto rwl = get_or_create_rwlock(rwlock_addr);
        int result = tryrdlock_rwlock(*rwl);
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("pthread_rwlock_trywrlock", [](Emulator& emu) {
        uint64_t rwlock_addr = get_reg(emu, UC_ARM64_REG_X0);
        auto rwl = get_or_create_rwlock(rwlock_addr);
        int result = trywrlock_rwlock(*rwl);
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

        EMU_LOG << "[HLE] pthread_create: caller_lr=0x" << std::hex << caller_lr
                  << " routine=0x" << start_routine << std::dec << std::endl;

        if (start_routine == 0) {
            EMU_LOG << "[HLE] pthread_create: ERROR - null routine!" << std::endl;
            set_reg(emu, UC_ARM64_REG_X0, 22);  // EINVAL
            return;
        }

        // Ensure trampoline code is written to guest memory
        write_thread_wrapper(emu);

        int32_t detachstate = read_guest_pthread_attr_detachstate(emu, attr);
        bool detached = (detachstate == GUEST_PTHREAD_CREATE_DETACHED);
        uint64_t requested_stackaddr = read_guest_pthread_attr_u64(
            emu, attr, GUEST_PTHREAD_ATTR_STACKADDR_OFFSET, 0);
        uint64_t requested_stacksize = read_guest_pthread_attr_u64(
            emu, attr, GUEST_PTHREAD_ATTR_STACKSIZE_OFFSET, GUEST_DEFAULT_PTHREAD_STACK_SIZE);
        uint64_t requested_guardsize = read_guest_pthread_attr_u64(
            emu, attr, GUEST_PTHREAD_ATTR_GUARDSIZE_OFFSET, GUEST_DEFAULT_PTHREAD_GUARD_SIZE);
        int32_t inheritsched = read_guest_pthread_attr_i32(
            emu, attr, GUEST_PTHREAD_ATTR_INHERITSCHED_OFFSET, GUEST_PTHREAD_EXPLICIT_SCHED);
        int32_t requested_schedpolicy = read_guest_pthread_attr_i32(
            emu, attr, GUEST_PTHREAD_ATTR_SCHEDPOLICY_OFFSET, SCHED_OTHER);
        int32_t requested_schedpriority = read_guest_pthread_attr_i32(
            emu, attr, GUEST_PTHREAD_ATTR_SCHEDPRIORITY_OFFSET, 0);

        uint64_t effective_stacksize = get_effective_stack_size(requested_stacksize);
        uint64_t effective_guardsize = get_effective_guard_size(requested_guardsize);
        if (effective_stacksize == 0 || effective_stacksize > (1ULL << 30)) {
            set_reg(emu, UC_ARM64_REG_X0, EAGAIN);
            return;
        }

        int thread_sched_policy = requested_schedpolicy;
        int thread_sched_priority = requested_schedpriority;
        if (inheritsched == GUEST_PTHREAD_INHERIT_SCHED) {
            std::lock_guard<std::mutex> lock(g_threads_mutex);
            if (!get_live_thread_sched_locked(get_current_guest_pthread_id(emu), thread_sched_policy, thread_sched_priority)) {
                thread_sched_policy = g_main_thread_sched_policy;
                thread_sched_priority = g_main_thread_sched_priority;
            }
        } else if (inheritsched != GUEST_PTHREAD_EXPLICIT_SCHED) {
            set_reg(emu, UC_ARM64_REG_X0, EINVAL);
            return;
        }

        if (!validate_sched_params(thread_sched_policy, thread_sched_priority)) {
            set_reg(emu, UC_ARM64_REG_X0, EINVAL);
            return;
        }

        if (hle_exit_is_in_progress()) {
            uint64_t thread_id = g_next_thread_id.fetch_add(1);
            if (thread_ptr != 0) {
                emu.mem_write(thread_ptr, &thread_id, sizeof(thread_id));
            }

            auto thread = std::make_unique<QemuThread>();
            thread->thread_id = thread_id;
            thread->start_routine = start_routine;
            thread->arg = arg;
            thread->sched_policy = thread_sched_policy;
            thread->sched_priority = thread_sched_priority;
            thread->detached = detached;
            thread->started.store(true);
            thread->completed.store(true);

            {
                std::lock_guard<std::mutex> lock(g_threads_mutex);
                g_threads[thread_id] = std::move(thread);
            }

            set_reg(emu, UC_ARM64_REG_X0, 0);
            return;
        }

        // Allocate thread ID
        uint64_t thread_id = g_next_thread_id.fetch_add(1);

        // Allocate or use the guest-provided stack for the new thread.
        uint64_t child_stack_top = 0;
        uint64_t actual_stack_size = QEMU_THREAD_STACK_SIZE;
        uint64_t guest_stack_base = 0;
        if (requested_stackaddr != 0) {
            child_stack_top = requested_stackaddr + effective_stacksize - 0x100;
            actual_stack_size = effective_stacksize;
            guest_stack_base = requested_stackaddr;
        } else {
            child_stack_top = allocate_thread_stack(emu);
            if (child_stack_top == 0) {
                set_reg(emu, UC_ARM64_REG_X0, EAGAIN);
                return;
            }
            guest_stack_base = child_stack_top + 0x100 - effective_stacksize;
        }
        uint64_t tls_base = allocate_thread_tls(emu);
        if (tls_base == 0) {
            if (requested_stackaddr == 0) {
                hle_release_vmas(child_stack_top);
                // Return the arena stack we just took so it isn't leaked on this failure.
                recycle_thread_arena(child_stack_top, 0, 0);
            }
            set_reg(emu, UC_ARM64_REG_X0, EAGAIN);
            return;
        }

        // Store start_routine, arg, and tls at child's stack
        // Stack layout: [SP+0]=start_routine, [SP+8]=arg, [SP+16]=tls
        emu.mem_write(child_stack_top, &start_routine, sizeof(start_routine));
        emu.mem_write(child_stack_top + 8, &arg, sizeof(arg));
        emu.mem_write(child_stack_top + 16, &tls_base, sizeof(tls_base));

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
            thread->stack_size = actual_stack_size;
            thread->reported_stack_size = effective_stacksize;
            thread->tls_base = tls_base;
            thread->guest_stack_addr = guest_stack_base;
            thread->guest_guard_size = effective_guardsize;
            thread->sched_policy = thread_sched_policy;
            thread->sched_priority = thread_sched_priority;
            thread->detached = detached;
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
        // Stack layout: [SP+0]=start_routine, [SP+8]=arg, [SP+16]=tls, [SP+24]=parent_tid, [SP+32]=child_tid
        uint64_t parent_tid_addr = child_stack_top + 24;
        uint64_t child_tid_addr = child_stack_top + 32;

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

        if (thread_id == 0) {
            set_reg(emu, UC_ARM64_REG_X0, ESRCH);
            return;
        }

        if (thread_id == get_current_guest_pthread_id(emu)) {
            set_reg(emu, UC_ARM64_REG_X0, EDEADLK);
            return;
        }

        QemuThread* thread = nullptr;
        {
            std::lock_guard<std::mutex> lock(g_threads_mutex);
            auto it = g_threads.find(thread_id);
            if (it == g_threads.end()) {
                EMU_LOG << "[HLE] pthread_join: Thread " << thread_id << " not found!" << std::endl;
                set_reg(emu, UC_ARM64_REG_X0, 3);  // ESRCH
                return;
            }
            if (it->second->detached) {
                set_reg(emu, UC_ARM64_REG_X0, EINVAL);
                return;
            }
            if (it->second->join_in_progress) {
                set_reg(emu, UC_ARM64_REG_X0, EINVAL);
                return;
            }
            it->second->join_in_progress = true;
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

        // Remove from registry and reclaim its arena regions for the next pthread_create.
        {
            std::lock_guard<std::mutex> lock(g_threads_mutex);
            auto jit = g_threads.find(thread_id);
            if (jit != g_threads.end()) {
                uint64_t sb = jit->second->stack_base;
                uint64_t gsa = jit->second->guest_stack_addr;
                uint64_t tb = jit->second->tls_base;
                g_threads.erase(jit);
                recycle_thread_arena(sb, gsa, tb);
            }
        }

        EMU_LOG << "[HLE] pthread_join: Thread " << thread_id
                  << " joined, retval=0x" << std::hex << retval << std::dec << std::endl;

        set_reg(emu, UC_ARM64_REG_X0, 0);  // Success
    });

    hle.register_function("pthread_detach", [](Emulator& emu) {
        uint64_t thread_id = get_reg(emu, UC_ARM64_REG_X0);

        if (thread_id == 0) {
            set_reg(emu, UC_ARM64_REG_X0, ESRCH);
            return;
        }

        std::lock_guard<std::mutex> lock(g_threads_mutex);
        auto it = g_threads.find(thread_id);
        if (it == g_threads.end()) {
            set_reg(emu, UC_ARM64_REG_X0, 3);  // ESRCH
            return;
        }

        if (it->second->detached || it->second->join_in_progress) {
            set_reg(emu, UC_ARM64_REG_X0, EINVAL);
            return;
        }

        it->second->detached = true;
        if (it->second->completed.load()) {
            // Already finished: detaching reclaims it now (no future join will run).
            uint64_t sb = it->second->stack_base;
            uint64_t gsa = it->second->guest_stack_addr;
            uint64_t tb = it->second->tls_base;
            g_threads.erase(it);
            recycle_thread_arena(sb, gsa, tb);
        }

        set_reg(emu, UC_ARM64_REG_X0, 0);  // Success
    });

    hle.register_function("pthread_self", [](Emulator& emu) {
        set_reg(emu, UC_ARM64_REG_X0, get_current_guest_pthread_id(emu));
    });

    hle.register_function("pthread_equal", [](Emulator& emu) {
        uint64_t t1 = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t t2 = get_reg(emu, UC_ARM64_REG_X1);
        set_reg(emu, UC_ARM64_REG_X0, t1 == t2 ? 1 : 0);
    });

    hle.register_function("__pthread_cleanup_push", [](Emulator& emu) {
        uint64_t cleanup_addr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t routine = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t arg = get_reg(emu, UC_ARM64_REG_X2);
        push_cleanup_handler(get_current_guest_pthread_id(emu), cleanup_addr, routine, arg);
    });

    hle.register_function("__pthread_cleanup_pop", [](Emulator& emu) {
        uint64_t cleanup_addr = get_reg(emu, UC_ARM64_REG_X0);
        int execute = static_cast<int>(get_reg(emu, UC_ARM64_REG_X1));
        GuestCleanupHandler handler{};
        if (pop_cleanup_handler(get_current_guest_pthread_id(emu), cleanup_addr, handler) &&
            execute != 0) {
            uint64_t guest_return_addr = get_reg(emu, UC_ARM64_REG_LR);
            dispatch_guest_cleanup_handler(emu, handler, guest_return_addr);
        }
    });

    hle.register_function("__pthread_exit_continue", [](Emulator& emu) {
        uint64_t thread_id = get_current_guest_pthread_id(emu);
        uint64_t retval = 0;
        if (!get_pending_pthread_exit(thread_id, retval)) {
            retval = get_reg(emu, UC_ARM64_REG_X0);
        }

        if (dispatch_next_pthread_exit_cleanup(emu, thread_id)) {
            return;
        }

        EMU_LOG << "[HLE] __pthread_exit_continue: Thread " << thread_id
                  << " finished cleanup callbacks, exiting with retval=0x"
                  << std::hex << retval << std::dec << std::endl;
        finish_guest_pthread_exit(emu, thread_id, retval);
    });
    hle.get_stub_address("__pthread_exit_continue");

    hle.register_function("pthread_exit", [](Emulator& emu) {
        uint64_t retval = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t thread_id = get_current_guest_pthread_id(emu);
        remember_pending_pthread_exit(thread_id, retval);

        if (dispatch_next_pthread_exit_cleanup(emu, thread_id)) {
            EMU_LOG << "[HLE] pthread_exit: Thread " << thread_id
                      << " dispatching cleanup callbacks before exit" << std::endl;
            return;
        }

        EMU_LOG << "[HLE] pthread_exit: Thread " << thread_id
                  << " exiting immediately with retval=0x" << std::hex << retval
                  << std::dec << std::endl;
        finish_guest_pthread_exit(emu, thread_id, retval);
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
        initialize_guest_pthread_attr(emu, attr);
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("pthread_attr_destroy", [](Emulator& emu) {
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("pthread_attr_setdetachstate", [](Emulator& emu) {
        uint64_t attr = get_reg(emu, UC_ARM64_REG_X0);
        int detachstate = static_cast<int>(get_reg(emu, UC_ARM64_REG_X1));
        if (detachstate != GUEST_PTHREAD_CREATE_JOINABLE &&
            detachstate != GUEST_PTHREAD_CREATE_DETACHED) {
            set_reg(emu, UC_ARM64_REG_X0, EINVAL);
            return;
        }
        write_guest_pthread_attr_i32(emu, attr, GUEST_PTHREAD_ATTR_DETACHSTATE_OFFSET, detachstate);
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("pthread_attr_getdetachstate", [](Emulator& emu) {
        uint64_t attr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t detachstate_ptr = get_reg(emu, UC_ARM64_REG_X1);
        int32_t detachstate = read_guest_pthread_attr_detachstate(emu, attr);
        emu.mem_write(detachstate_ptr, &detachstate, sizeof(detachstate));
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("pthread_attr_setstacksize", [](Emulator& emu) {
        uint64_t attr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t stacksize = get_reg(emu, UC_ARM64_REG_X1);
        if (stacksize < GUEST_PTHREAD_STACK_MIN) {
            set_reg(emu, UC_ARM64_REG_X0, EINVAL);
            return;
        }
        write_guest_pthread_attr_u64(emu, attr, GUEST_PTHREAD_ATTR_STACKSIZE_OFFSET, stacksize);
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("pthread_attr_setguardsize", [](Emulator& emu) {
        uint64_t attr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t guardsize = get_reg(emu, UC_ARM64_REG_X1);
        write_guest_pthread_attr_u64(emu, attr, GUEST_PTHREAD_ATTR_GUARDSIZE_OFFSET, guardsize);
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("pthread_attr_getguardsize", [](Emulator& emu) {
        uint64_t attr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t guardsize_ptr = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t guardsize = read_guest_pthread_attr_u64(
            emu, attr, GUEST_PTHREAD_ATTR_GUARDSIZE_OFFSET, GUEST_DEFAULT_PTHREAD_GUARD_SIZE);
        emu.mem_write(guardsize_ptr, &guardsize, sizeof(guardsize));
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("pthread_attr_getstacksize", [](Emulator& emu) {
        uint64_t attr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t stacksize_ptr = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t stacksize = read_guest_pthread_attr_u64(
            emu, attr, GUEST_PTHREAD_ATTR_STACKSIZE_OFFSET, GUEST_DEFAULT_PTHREAD_STACK_SIZE);
        emu.mem_write(stacksize_ptr, &stacksize, sizeof(stacksize));
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("pthread_attr_getstack", [](Emulator& emu) {
        uint64_t attr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t stackaddr_ptr = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t stacksize_ptr = get_reg(emu, UC_ARM64_REG_X2);
        uint64_t stackaddr = read_guest_pthread_attr_u64(emu, attr, GUEST_PTHREAD_ATTR_STACKADDR_OFFSET, 0);
        uint64_t stacksize = read_guest_pthread_attr_u64(
            emu, attr, GUEST_PTHREAD_ATTR_STACKSIZE_OFFSET, GUEST_DEFAULT_PTHREAD_STACK_SIZE);
        if (stackaddr_ptr != 0) {
            emu.mem_write(stackaddr_ptr, &stackaddr, sizeof(stackaddr));
        }
        if (stacksize_ptr != 0) {
            emu.mem_write(stacksize_ptr, &stacksize, sizeof(stacksize));
        }
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("pthread_attr_getscope", [](Emulator& emu) {
        uint64_t attr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t scope_ptr = get_reg(emu, UC_ARM64_REG_X1);
        int32_t scope = read_guest_pthread_attr_i32(
            emu, attr, GUEST_PTHREAD_ATTR_SCOPE_OFFSET, GUEST_PTHREAD_SCOPE_SYSTEM);
        emu.mem_write(scope_ptr, &scope, sizeof(scope));
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("pthread_attr_setinheritsched", [](Emulator& emu) {
        uint64_t attr = get_reg(emu, UC_ARM64_REG_X0);
        int inheritsched = static_cast<int>(get_reg(emu, UC_ARM64_REG_X1));
        if (inheritsched != GUEST_PTHREAD_INHERIT_SCHED &&
            inheritsched != GUEST_PTHREAD_EXPLICIT_SCHED) {
            set_reg(emu, UC_ARM64_REG_X0, EINVAL);
            return;
        }
        write_guest_pthread_attr_i32(emu, attr, GUEST_PTHREAD_ATTR_INHERITSCHED_OFFSET, inheritsched);
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("pthread_attr_getinheritsched", [](Emulator& emu) {
        uint64_t attr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t inheritsched_ptr = get_reg(emu, UC_ARM64_REG_X1);
        int32_t inheritsched = read_guest_pthread_attr_i32(
            emu, attr, GUEST_PTHREAD_ATTR_INHERITSCHED_OFFSET, GUEST_PTHREAD_EXPLICIT_SCHED);
        emu.mem_write(inheritsched_ptr, &inheritsched, sizeof(inheritsched));
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("pthread_attr_setschedpolicy", [](Emulator& emu) {
        uint64_t attr = get_reg(emu, UC_ARM64_REG_X0);
        int sched_policy = static_cast<int>(get_reg(emu, UC_ARM64_REG_X1));
        write_guest_pthread_attr_i32(emu, attr, GUEST_PTHREAD_ATTR_SCHEDPOLICY_OFFSET, sched_policy);
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("pthread_attr_getschedpolicy", [](Emulator& emu) {
        uint64_t attr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t policy_ptr = get_reg(emu, UC_ARM64_REG_X1);
        int32_t sched_policy = read_guest_pthread_attr_i32(
            emu, attr, GUEST_PTHREAD_ATTR_SCHEDPOLICY_OFFSET, SCHED_OTHER);
        emu.mem_write(policy_ptr, &sched_policy, sizeof(sched_policy));
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("pthread_attr_setschedparam", [](Emulator& emu) {
        uint64_t attr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t sched_param_addr = get_reg(emu, UC_ARM64_REG_X1);
        int sched_priority = 0;
        if (!read_guest_sched_priority(emu, sched_param_addr, sched_priority)) {
            set_reg(emu, UC_ARM64_REG_X0, EINVAL);
            return;
        }
        write_guest_pthread_attr_i32(emu, attr, GUEST_PTHREAD_ATTR_SCHEDPRIORITY_OFFSET, sched_priority);
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("pthread_attr_getschedparam", [](Emulator& emu) {
        uint64_t attr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t sched_param_addr = get_reg(emu, UC_ARM64_REG_X1);
        int sched_priority = read_guest_pthread_attr_i32(
            emu, attr, GUEST_PTHREAD_ATTR_SCHEDPRIORITY_OFFSET, 0);
        if (!write_guest_sched_priority(emu, sched_param_addr, sched_priority)) {
            set_reg(emu, UC_ARM64_REG_X0, EINVAL);
            return;
        }
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

        uint64_t key = 0;
        {
            std::lock_guard<std::mutex> lock(g_tls_mutex);

            if (!g_tls_free_keys.empty()) {
                key = g_tls_free_keys.back();
                g_tls_free_keys.pop_back();
            } else {
                key = g_next_tls_key.load();
                if (key == 0 || key > GUEST_PTHREAD_DYNAMIC_KEY_LIMIT ||
                    g_tls_live_keys.size() >= GUEST_PTHREAD_DYNAMIC_KEY_LIMIT) {
                    set_reg(emu, UC_ARM64_REG_X0, EAGAIN);
                    return;
                }
                g_next_tls_key.store(key + 1);
            }

            g_tls_live_keys.insert(key);
            if (destructor != 0) {
                g_tls_destructors[key] = destructor;
            } else {
                g_tls_destructors.erase(key);
            }
        }

        uint32_t key32 = static_cast<uint32_t>(key);

        try {
            emu.mem_write(key_ptr, &key32, sizeof(key32));
        } catch (...) {
            std::lock_guard<std::mutex> lock(g_tls_mutex);
            g_tls_live_keys.erase(key);
            g_tls_destructors.erase(key);
            g_tls_free_keys.push_back(key);
            set_reg(emu, UC_ARM64_REG_X0, EFAULT);
            return;
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

        if (!is_valid_tls_key_locked(key)) {
            set_reg(emu, UC_ARM64_REG_X0, EINVAL);
            return;
        }

        g_tls_live_keys.erase(key);
        g_tls_free_keys.push_back(key);
        g_tls_destructors.erase(key);

        // Remove values for all threads
        for (auto& [tid, values] : g_tls_values) {
            values.erase(key);
        }

        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("pthread_getspecific", [](Emulator& emu) {
        uint64_t key = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t thread_id = get_current_tls_thread_id(emu);

        uint64_t value = 0;
        {
            std::lock_guard<std::mutex> lock(g_tls_mutex);
            if (is_valid_tls_key_locked(key)) {
                auto tid_it = g_tls_values.find(thread_id);
                if (tid_it != g_tls_values.end()) {
                    auto key_it = tid_it->second.find(key);
                    if (key_it != tid_it->second.end()) {
                        value = key_it->second;
                    }
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
        uint64_t thread_id = get_current_tls_thread_id(emu);

        {
            std::lock_guard<std::mutex> lock(g_tls_mutex);
            if (!is_valid_tls_key_locked(key)) {
                set_reg(emu, UC_ARM64_REG_X0, EINVAL);
                return;
            }
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
        get_or_create_spinlock(lock);
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("pthread_spin_destroy", [](Emulator& emu) {
        uint64_t lock = get_reg(emu, UC_ARM64_REG_X0);
        std::lock_guard<std::mutex> guard(g_spinlocks_lock);
        g_host_spinlocks.erase(lock);
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("pthread_spin_lock", [](Emulator& emu) {
        uint64_t lock = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t owner = get_current_sync_thread_id(emu);
        auto spin = get_or_create_spinlock(lock);
        for (;;) {
            bool expected = false;
            if (spin->locked.compare_exchange_weak(expected, true,
                                                   std::memory_order_acquire,
                                                   std::memory_order_relaxed)) {
                spin->owner_thread.store(owner, std::memory_order_relaxed);
                break;
            }
            std::this_thread::yield();
        }
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("pthread_spin_trylock", [](Emulator& emu) {
        uint64_t lock = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t owner = get_current_sync_thread_id(emu);
        auto spin = get_or_create_spinlock(lock);
        bool expected = false;
        bool success = spin->locked.compare_exchange_strong(expected, true,
                                                            std::memory_order_acquire,
                                                            std::memory_order_relaxed);
        if (success) {
            spin->owner_thread.store(owner, std::memory_order_relaxed);
        }
        set_reg(emu, UC_ARM64_REG_X0, success ? 0 : EBUSY);
    });

    hle.register_function("pthread_spin_unlock", [](Emulator& emu) {
        uint64_t lock = get_reg(emu, UC_ARM64_REG_X0);
        auto spin = get_or_create_spinlock(lock);
        spin->owner_thread.store(0, std::memory_order_relaxed);
        spin->locked.store(false, std::memory_order_release);
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    // ========================================================================
    // Barriers - native implementation for MTTCG
    // ========================================================================

    hle.register_function("pthread_barrierattr_init", [](Emulator& emu) {
        uint64_t attr_addr = get_reg(emu, UC_ARM64_REG_X0);
        if (!write_guest_barrierattr(emu, attr_addr, GUEST_PTHREAD_PROCESS_PRIVATE)) {
            set_reg(emu, UC_ARM64_REG_X0, EINVAL);
            return;
        }
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("pthread_barrierattr_destroy", [](Emulator& emu) {
        uint64_t attr_addr = get_reg(emu, UC_ARM64_REG_X0);
        if (attr_addr == 0 || attr_addr < 0x1000) {
            set_reg(emu, UC_ARM64_REG_X0, EINVAL);
            return;
        }
        int32_t zero = 0;
        emu.mem_write(attr_addr, &zero, sizeof(zero));
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("pthread_barrierattr_getpshared", [](Emulator& emu) {
        uint64_t attr_addr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t shared_ptr = get_reg(emu, UC_ARM64_REG_X1);
        int pshared = GUEST_PTHREAD_PROCESS_PRIVATE;
        if (shared_ptr == 0 || !read_guest_barrierattr(emu, attr_addr, pshared)) {
            set_reg(emu, UC_ARM64_REG_X0, EINVAL);
            return;
        }
        int32_t raw = pshared;
        emu.mem_write(shared_ptr, &raw, sizeof(raw));
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("pthread_barrierattr_setpshared", [](Emulator& emu) {
        uint64_t attr_addr = get_reg(emu, UC_ARM64_REG_X0);
        int pshared = static_cast<int>(get_reg(emu, UC_ARM64_REG_X1));
        if (!write_guest_barrierattr(emu, attr_addr, pshared)) {
            set_reg(emu, UC_ARM64_REG_X0, EINVAL);
            return;
        }
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("pthread_barrier_init", [](Emulator& emu) {
        uint64_t barrier_addr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t attr_addr = get_reg(emu, UC_ARM64_REG_X1);
        unsigned int count = get_reg(emu, UC_ARM64_REG_X2);
        if (count == 0) {
            set_reg(emu, UC_ARM64_REG_X0, EINVAL);
            return;
        }
        if (attr_addr != 0) {
            int pshared = GUEST_PTHREAD_PROCESS_PRIVATE;
            if (!read_guest_barrierattr(emu, attr_addr, pshared)) {
                set_reg(emu, UC_ARM64_REG_X0, EINVAL);
                return;
            }
        }
        get_or_create_barrier(barrier_addr, count);
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("pthread_barrier_destroy", [](Emulator& emu) {
        uint64_t barrier_addr = get_reg(emu, UC_ARM64_REG_X0);
        set_reg(emu, UC_ARM64_REG_X0, destroy_barrier(barrier_addr));
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
        int result = wait_on_barrier(*b);
        // PTHREAD_BARRIER_SERIAL_THREAD is returned to exactly one thread
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // ========================================================================
    // Thread naming and signals
    // ========================================================================

    // pthread_kill - send signal to a thread
    hle.register_function("pthread_kill", [](Emulator& emu) {
        uint64_t thread = get_reg(emu, UC_ARM64_REG_X0);
        int sig = get_reg(emu, UC_ARM64_REG_X1);

        if (sig < 0 || sig > 64) {
            set_reg(emu, UC_ARM64_REG_X0, EINVAL);
            return;
        }

        {
            std::lock_guard<std::mutex> lock(g_threads_mutex);
            if (!is_live_pthread_id_locked(thread)) {
                set_reg(emu, UC_ARM64_REG_X0, ESRCH);
                return;
            }
        }

        if (sig == 0) {
            set_reg(emu, UC_ARM64_REG_X0, 0);
            return;
        }

        int result = hle_signal_queue(emu, sig, SI_TKILL, 0, false);
        set_reg(emu, UC_ARM64_REG_X0, result == 0 ? 0 : EINVAL);
    });

    // pthread_setname_np - set thread name (non-portable)
    hle.register_function("pthread_setname_np", [](Emulator& emu) {
        uint64_t thread = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t name_addr = get_reg(emu, UC_ARM64_REG_X1);

        if (thread == 0 || name_addr == 0) {
            set_reg(emu, UC_ARM64_REG_X0, thread == 0 ? ENOENT : EINVAL);
            return;
        }

        // Read the name (max 16 chars including null on Linux)
        std::string name;
        bool terminated = false;
        char c = '\0';
        for (int i = 0; i < 16; i++) {
            if (!emu.mem_read(name_addr + i, &c, 1)) {
                set_reg(emu, UC_ARM64_REG_X0, EINVAL);
                return;
            }
            if (c == '\0') {
                terminated = true;
                break;
            }
            name += c;
        }

        if (!terminated) {
            set_reg(emu, UC_ARM64_REG_X0, ERANGE);
            return;
        }

        if (thread == 1) {
            g_main_thread_name = name;
        } else {
            std::lock_guard<std::mutex> lock(g_threads_mutex);
            auto it = g_threads.find(thread);
            if (it == g_threads.end() || it->second->completed.load()) {
                set_reg(emu, UC_ARM64_REG_X0, ENOENT);
                return;
            }
            it->second->name = name;
        }

        if (emu.is_debug()) {
            EMU_LOG << "[HLE] pthread_setname_np: thread=0x" << std::hex << thread
                      << " name=\"" << name << "\"" << std::dec << std::endl;
        }

        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    // pthread_getname_np - get thread name (non-portable)
    hle.register_function("pthread_getname_np", [](Emulator& emu) {
        uint64_t thread = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t buf_addr = get_reg(emu, UC_ARM64_REG_X1);
        size_t len = get_reg(emu, UC_ARM64_REG_X2);

        if (thread == 0) {
            set_reg(emu, UC_ARM64_REG_X0, ENOENT);
            return;
        }

        if (!buf_addr || len == 0) {
            set_reg(emu, UC_ARM64_REG_X0, EINVAL);
            return;
        }

        if (len < 16) {
            set_reg(emu, UC_ARM64_REG_X0, ERANGE);
            return;
        }

        std::string name = g_main_thread_name;
        if (thread != 1) {
            std::lock_guard<std::mutex> lock(g_threads_mutex);
            auto it = g_threads.find(thread);
            if (it == g_threads.end() || it->second->completed.load()) {
                set_reg(emu, UC_ARM64_REG_X0, ENOENT);
                return;
            }
            name = it->second->name;
        }

        if (len <= name.length()) {
            set_reg(emu, UC_ARM64_REG_X0, ERANGE);
            return;
        }

        emu.mem_write(buf_addr, name.c_str(), name.length() + 1);
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("pthread_getcpuclockid", [](Emulator& emu) {
        uint64_t thread = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t clockid_ptr = get_reg(emu, UC_ARM64_REG_X1);

        if (thread == 0) {
            set_reg(emu, UC_ARM64_REG_X0, ESRCH);
            return;
        }

        {
            std::lock_guard<std::mutex> lock(g_threads_mutex);
            if (!is_live_pthread_id_locked(thread)) {
                set_reg(emu, UC_ARM64_REG_X0, ESRCH);
                return;
            }
        }

        if (clockid_ptr == 0) {
            set_reg(emu, UC_ARM64_REG_X0, EINVAL);
            return;
        }

        clockid_t clock_id = CLOCK_THREAD_CPUTIME_ID;
        emu.mem_write(clockid_ptr, &clock_id, sizeof(clock_id));
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("pthread_getschedparam", [](Emulator& emu) {
        uint64_t thread = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t policy_ptr = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t sched_param_addr = get_reg(emu, UC_ARM64_REG_X2);

        if (thread == 0) {
            set_reg(emu, UC_ARM64_REG_X0, ESRCH);
            return;
        }

        int sched_policy = SCHED_OTHER;
        int sched_priority = 0;
        {
            std::lock_guard<std::mutex> lock(g_threads_mutex);
            if (!get_live_thread_sched_locked(thread, sched_policy, sched_priority)) {
                set_reg(emu, UC_ARM64_REG_X0, ESRCH);
                return;
            }
        }

        int32_t sched_policy32 = sched_policy;
        if (policy_ptr != 0) {
            emu.mem_write(policy_ptr, &sched_policy32, sizeof(sched_policy32));
        }
        if (!write_guest_sched_priority(emu, sched_param_addr, sched_priority)) {
            set_reg(emu, UC_ARM64_REG_X0, EINVAL);
            return;
        }
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("pthread_setschedparam", [](Emulator& emu) {
        uint64_t thread = get_reg(emu, UC_ARM64_REG_X0);
        int sched_policy = static_cast<int>(get_reg(emu, UC_ARM64_REG_X1));
        uint64_t sched_param_addr = get_reg(emu, UC_ARM64_REG_X2);
        int sched_priority = 0;

        if (thread == 0) {
            set_reg(emu, UC_ARM64_REG_X0, ESRCH);
            return;
        }
        if (!read_guest_sched_priority(emu, sched_param_addr, sched_priority) ||
            !validate_sched_params(sched_policy, sched_priority)) {
            set_reg(emu, UC_ARM64_REG_X0, EINVAL);
            return;
        }

        std::lock_guard<std::mutex> lock(g_threads_mutex);
        if (thread == 1) {
            g_main_thread_sched_policy = sched_policy;
            g_main_thread_sched_priority = sched_priority;
            set_reg(emu, UC_ARM64_REG_X0, 0);
            return;
        }

        auto it = g_threads.find(thread);
        if (it == g_threads.end() || it->second->completed.load()) {
            set_reg(emu, UC_ARM64_REG_X0, ESRCH);
            return;
        }

        it->second->sched_policy = sched_policy;
        it->second->sched_priority = sched_priority;
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("pthread_setschedprio", [](Emulator& emu) {
        uint64_t thread = get_reg(emu, UC_ARM64_REG_X0);
        int sched_priority = static_cast<int>(get_reg(emu, UC_ARM64_REG_X1));

        if (thread == 0) {
            set_reg(emu, UC_ARM64_REG_X0, ESRCH);
            return;
        }

        std::lock_guard<std::mutex> lock(g_threads_mutex);
        if (thread == 1) {
            if (!validate_sched_params(g_main_thread_sched_policy, sched_priority)) {
                set_reg(emu, UC_ARM64_REG_X0, EINVAL);
                return;
            }
            g_main_thread_sched_priority = sched_priority;
            set_reg(emu, UC_ARM64_REG_X0, 0);
            return;
        }

        auto it = g_threads.find(thread);
        if (it == g_threads.end() || it->second->completed.load()) {
            set_reg(emu, UC_ARM64_REG_X0, ESRCH);
            return;
        }
        if (!validate_sched_params(it->second->sched_policy, sched_priority)) {
            set_reg(emu, UC_ARM64_REG_X0, EINVAL);
            return;
        }

        it->second->sched_priority = sched_priority;
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    // pthread_sigqueue - queue a signal with data to a thread
    hle.register_function("pthread_sigqueue", [](Emulator& emu) {
        // Just return success for now
        set_reg(emu, UC_ARM64_REG_X0, 0);
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

    // ========================================================================
    // Extended pthread functions
    // ========================================================================

    // pthread_attr_setstack - set stack address and size
    hle.register_function("pthread_attr_setstack", [](Emulator& emu) {
        uint64_t attr_addr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t stackaddr = get_reg(emu, UC_ARM64_REG_X1);
        size_t stacksize = get_reg(emu, UC_ARM64_REG_X2);

        // Store in the attr structure
        if (attr_addr) {
            write_guest_pthread_attr_u64(emu, attr_addr, GUEST_PTHREAD_ATTR_STACKADDR_OFFSET, stackaddr);
            write_guest_pthread_attr_u64(emu, attr_addr, GUEST_PTHREAD_ATTR_STACKSIZE_OFFSET, stacksize);
        }
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    // pthread_getattr_np - get thread attributes (non-portable)
    hle.register_function("pthread_getattr_np", [](Emulator& emu) {
        uint64_t thread = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t attr_addr = get_reg(emu, UC_ARM64_REG_X1);

        if (attr_addr) {
            initialize_guest_pthread_attr(emu, attr_addr);

            if (thread == 1) {
                struct rlimit rl{};
                uint64_t stacksize = GUEST_DEFAULT_PTHREAD_STACK_SIZE;
                if (::getrlimit(RLIMIT_STACK, &rl) == 0) {
                    stacksize = (rl.rlim_cur == RLIM_INFINITY)
                        ? GUEST_DEFAULT_PTHREAD_STACK_SIZE
                        : static_cast<uint64_t>(rl.rlim_cur);
                }
                uint64_t stackaddr = MAIN_THREAD_STACK_TOP_GUEST - stacksize;
                write_guest_pthread_attr_i32(emu, attr_addr, GUEST_PTHREAD_ATTR_DETACHSTATE_OFFSET, GUEST_PTHREAD_CREATE_JOINABLE);
                write_guest_pthread_attr_u64(emu, attr_addr, GUEST_PTHREAD_ATTR_STACKADDR_OFFSET, stackaddr);
                write_guest_pthread_attr_u64(emu, attr_addr, GUEST_PTHREAD_ATTR_STACKSIZE_OFFSET, stacksize);
                write_guest_pthread_attr_u64(emu, attr_addr, GUEST_PTHREAD_ATTR_GUARDSIZE_OFFSET, 0);
                write_guest_pthread_attr_i32(emu, attr_addr, GUEST_PTHREAD_ATTR_SCHEDPOLICY_OFFSET, g_main_thread_sched_policy);
                write_guest_pthread_attr_i32(emu, attr_addr, GUEST_PTHREAD_ATTR_SCHEDPRIORITY_OFFSET, g_main_thread_sched_priority);
            } else {
                std::lock_guard<std::mutex> lock(g_threads_mutex);
                auto it = g_threads.find(thread);
                if (it == g_threads.end()) {
                    set_reg(emu, UC_ARM64_REG_X0, ESRCH);
                    return;
                }

                write_guest_pthread_attr_i32(
                    emu, attr_addr, GUEST_PTHREAD_ATTR_DETACHSTATE_OFFSET,
                    it->second->detached ? GUEST_PTHREAD_CREATE_DETACHED : GUEST_PTHREAD_CREATE_JOINABLE);
                write_guest_pthread_attr_u64(emu, attr_addr, GUEST_PTHREAD_ATTR_STACKADDR_OFFSET, it->second->guest_stack_addr);
                write_guest_pthread_attr_u64(emu, attr_addr, GUEST_PTHREAD_ATTR_STACKSIZE_OFFSET, it->second->reported_stack_size);
                write_guest_pthread_attr_u64(emu, attr_addr, GUEST_PTHREAD_ATTR_GUARDSIZE_OFFSET, it->second->guest_guard_size);
                write_guest_pthread_attr_i32(emu, attr_addr, GUEST_PTHREAD_ATTR_SCHEDPOLICY_OFFSET, it->second->sched_policy);
                write_guest_pthread_attr_i32(emu, attr_addr, GUEST_PTHREAD_ATTR_SCHEDPRIORITY_OFFSET, it->second->sched_priority);
            }
        }
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    // pthread_mutex_timedlock - lock mutex with timeout
    hle.register_function("pthread_mutex_timedlock", [](Emulator& emu) {
        uint64_t mutex_addr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t abstime_addr = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t visible_tid = get_current_sync_thread_id(emu);

        auto m = get_or_create_mutex(mutex_addr);
        if (!m) {
            set_reg(emu, UC_ARM64_REG_X0, EINVAL);
            return;
        }

        struct timespec ts{};
        const struct timespec* ts_ptr = read_guest_absolute_timespec(emu, abstime_addr, ts) ? &ts : nullptr;
        pid_t pi_owner_tid = 0;
        if (m->protocol == PTHREAD_PRIO_INHERIT && m->lock_count.load() > 0 &&
            m->owner_thread.load() != visible_tid) {
            pi_owner_tid = static_cast<pid_t>(m->owner_thread.load());
            hle_sched_pi_boost_begin(pi_owner_tid);
        }
        int result = lock_mutex_with_timeout(*m, visible_tid, CLOCK_REALTIME, ts_ptr);
        if (pi_owner_tid > 0) {
            hle_sched_pi_boost_end(pi_owner_tid);
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // pthread_mutex_timedlock_monotonic_np - timedlock with CLOCK_MONOTONIC
    hle.register_function("pthread_mutex_timedlock_monotonic_np", [](Emulator& emu) {
        uint64_t mutex_addr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t abstime_addr = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t visible_tid = get_current_sync_thread_id(emu);

        auto m = get_or_create_mutex(mutex_addr);
        if (!m) {
            set_reg(emu, UC_ARM64_REG_X0, EINVAL);
            return;
        }

        struct timespec ts{};
        const struct timespec* ts_ptr = read_guest_absolute_timespec(emu, abstime_addr, ts) ? &ts : nullptr;
        pid_t pi_owner_tid = 0;
        if (m->protocol == PTHREAD_PRIO_INHERIT && m->lock_count.load() > 0 &&
            m->owner_thread.load() != visible_tid) {
            pi_owner_tid = static_cast<pid_t>(m->owner_thread.load());
            hle_sched_pi_boost_begin(pi_owner_tid);
        }
        int result = lock_mutex_with_timeout(*m, visible_tid, CLOCK_MONOTONIC, ts_ptr);
        if (pi_owner_tid > 0) {
            hle_sched_pi_boost_end(pi_owner_tid);
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("pthread_mutex_clocklock", [](Emulator& emu) {
        uint64_t mutex_addr = get_reg(emu, UC_ARM64_REG_X0);
        int clockid = static_cast<int>(get_reg(emu, UC_ARM64_REG_X1));
        uint64_t abstime_addr = get_reg(emu, UC_ARM64_REG_X2);
        uint64_t visible_tid = get_current_sync_thread_id(emu);

        auto m = get_or_create_mutex(mutex_addr);
        if (!m) {
            set_reg(emu, UC_ARM64_REG_X0, EINVAL);
            return;
        }

        struct timespec ts{};
        const struct timespec* ts_ptr = read_guest_absolute_timespec(emu, abstime_addr, ts) ? &ts : nullptr;
        pid_t pi_owner_tid = 0;
        if (m->protocol == PTHREAD_PRIO_INHERIT && m->lock_count.load() > 0 &&
            m->owner_thread.load() != visible_tid) {
            pi_owner_tid = static_cast<pid_t>(m->owner_thread.load());
            hle_sched_pi_boost_begin(pi_owner_tid);
        }
        int result = lock_mutex_with_timeout(*m, visible_tid, clockid, ts_ptr);
        if (pi_owner_tid > 0) {
            hle_sched_pi_boost_end(pi_owner_tid);
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // pthread_cond_timedwait_monotonic_np - timedwait with CLOCK_MONOTONIC
    hle.register_function("pthread_cond_timedwait_monotonic_np", [](Emulator& emu) {
        uint64_t cond_addr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t mutex_addr = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t abstime_addr = get_reg(emu, UC_ARM64_REG_X2);
        uint64_t visible_tid = get_current_sync_thread_id(emu);

        auto c = get_or_create_condvar(cond_addr);
        auto m = get_or_create_mutex(mutex_addr);

        if (!c || !m) {
            set_reg(emu, UC_ARM64_REG_X0, EINVAL);
            return;
        }

        struct timespec ts{};
        const struct timespec* ts_ptr = read_guest_absolute_timespec(emu, abstime_addr, ts) ? &ts : nullptr;
        set_reg(emu, UC_ARM64_REG_X0, wait_cond_with_clock(*c, *m, CLOCK_MONOTONIC, ts_ptr, visible_tid));
    });

    // pthread_cond_clockwait - timedwait with specified clock
    hle.register_function("pthread_cond_clockwait", [](Emulator& emu) {
        uint64_t cond_addr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t mutex_addr = get_reg(emu, UC_ARM64_REG_X1);
        int clockid = get_reg(emu, UC_ARM64_REG_X2);
        uint64_t abstime_addr = get_reg(emu, UC_ARM64_REG_X3);
        uint64_t visible_tid = get_current_sync_thread_id(emu);

        auto c = get_or_create_condvar(cond_addr);
        auto m = get_or_create_mutex(mutex_addr);

        if (!c || !m) {
            set_reg(emu, UC_ARM64_REG_X0, EINVAL);
            return;
        }

        struct timespec ts{};
        const struct timespec* ts_ptr = read_guest_absolute_timespec(emu, abstime_addr, ts) ? &ts : nullptr;
        set_reg(emu, UC_ARM64_REG_X0, wait_cond_with_clock(*c, *m, clockid, ts_ptr, visible_tid));
    });

    // pthread_rwlock_timedrdlock
    hle.register_function("pthread_rwlock_timedrdlock", [](Emulator& emu) {
        uint64_t rwlock_addr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t abstime_addr = get_reg(emu, UC_ARM64_REG_X1);

        auto rw = get_or_create_rwlock(rwlock_addr);
        if (!rw) {
            set_reg(emu, UC_ARM64_REG_X0, EINVAL);
            return;
        }

        struct timespec ts{};
        const struct timespec* ts_ptr = read_guest_absolute_timespec(emu, abstime_addr, ts) ? &ts : nullptr;
        set_reg(emu, UC_ARM64_REG_X0, lock_rwlock_with_timeout(*rw, false, ts_ptr));
    });

    // pthread_rwlock_timedwrlock
    hle.register_function("pthread_rwlock_timedwrlock", [](Emulator& emu) {
        uint64_t rwlock_addr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t abstime_addr = get_reg(emu, UC_ARM64_REG_X1);

        auto rw = get_or_create_rwlock(rwlock_addr);
        if (!rw) {
            set_reg(emu, UC_ARM64_REG_X0, EINVAL);
            return;
        }

        struct timespec ts{};
        const struct timespec* ts_ptr = read_guest_absolute_timespec(emu, abstime_addr, ts) ? &ts : nullptr;
        set_reg(emu, UC_ARM64_REG_X0, lock_rwlock_with_timeout(*rw, true, ts_ptr));
    });

    // pthread_rwlock_timedrdlock_monotonic_np
    hle.register_function("pthread_rwlock_timedrdlock_monotonic_np", [](Emulator& emu) {
        uint64_t rwlock_addr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t abstime_addr = get_reg(emu, UC_ARM64_REG_X1);

        auto rw = get_or_create_rwlock(rwlock_addr);
        if (!rw) {
            set_reg(emu, UC_ARM64_REG_X0, EINVAL);
            return;
        }

        struct timespec ts{};
        const struct timespec* ts_ptr = read_guest_absolute_timespec(emu, abstime_addr, ts) ? &ts : nullptr;
        set_reg(emu, UC_ARM64_REG_X0, lock_rwlock_with_clock(*rw, false, CLOCK_MONOTONIC, ts_ptr));
    });

    // pthread_rwlock_timedwrlock_monotonic_np
    hle.register_function("pthread_rwlock_timedwrlock_monotonic_np", [](Emulator& emu) {
        uint64_t rwlock_addr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t abstime_addr = get_reg(emu, UC_ARM64_REG_X1);

        auto rw = get_or_create_rwlock(rwlock_addr);
        if (!rw) {
            set_reg(emu, UC_ARM64_REG_X0, EINVAL);
            return;
        }

        struct timespec ts{};
        const struct timespec* ts_ptr = read_guest_absolute_timespec(emu, abstime_addr, ts) ? &ts : nullptr;
        set_reg(emu, UC_ARM64_REG_X0, lock_rwlock_with_clock(*rw, true, CLOCK_MONOTONIC, ts_ptr));
    });

    // pthread_rwlock_clockrdlock
    hle.register_function("pthread_rwlock_clockrdlock", [](Emulator& emu) {
        uint64_t rwlock_addr = get_reg(emu, UC_ARM64_REG_X0);
        int clockid = static_cast<int>(get_reg(emu, UC_ARM64_REG_X1));
        uint64_t abstime_addr = get_reg(emu, UC_ARM64_REG_X2);

        auto rw = get_or_create_rwlock(rwlock_addr);
        if (!rw) {
            set_reg(emu, UC_ARM64_REG_X0, EINVAL);
            return;
        }

        struct timespec ts{};
        const struct timespec* ts_ptr = read_guest_absolute_timespec(emu, abstime_addr, ts) ? &ts : nullptr;
        set_reg(emu, UC_ARM64_REG_X0, lock_rwlock_with_clock(*rw, false, clockid, ts_ptr));
    });

    // pthread_rwlock_clockwrlock
    hle.register_function("pthread_rwlock_clockwrlock", [](Emulator& emu) {
        uint64_t rwlock_addr = get_reg(emu, UC_ARM64_REG_X0);
        int clockid = static_cast<int>(get_reg(emu, UC_ARM64_REG_X1));
        uint64_t abstime_addr = get_reg(emu, UC_ARM64_REG_X2);

        auto rw = get_or_create_rwlock(rwlock_addr);
        if (!rw) {
            set_reg(emu, UC_ARM64_REG_X0, EINVAL);
            return;
        }

        struct timespec ts{};
        const struct timespec* ts_ptr = read_guest_absolute_timespec(emu, abstime_addr, ts) ? &ts : nullptr;
        set_reg(emu, UC_ARM64_REG_X0, lock_rwlock_with_clock(*rw, true, clockid, ts_ptr));
    });

    // ========================================================================
    // Semaphore functions
    // ========================================================================

    // sem_timedwait_monotonic_np - timedwait with CLOCK_MONOTONIC
    hle.register_function("sem_timedwait_monotonic_np", [](Emulator& emu) {
        uint64_t sem_addr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t abstime_addr = get_reg(emu, UC_ARM64_REG_X1);
        set_reg(emu, UC_ARM64_REG_X0,
                static_cast<uint64_t>(hle_sem_timedwait(emu, sem_addr, CLOCK_MONOTONIC, abstime_addr)));
    });

    // sem_clockwait - timedwait with specified clock
    hle.register_function("sem_clockwait", [](Emulator& emu) {
        uint64_t sem_addr = get_reg(emu, UC_ARM64_REG_X0);
        int clockid = static_cast<int>(get_reg(emu, UC_ARM64_REG_X1));
        uint64_t abstime_addr = get_reg(emu, UC_ARM64_REG_X2);
        set_reg(emu, UC_ARM64_REG_X0,
                static_cast<uint64_t>(hle_sem_timedwait(emu, sem_addr, clockid, abstime_addr)));
    });
}

// Notify that a thread has exited
// This is called from the syscall handler when SYS_THREAD_DONE is invoked
// We use the stack pointer (SP) to identify which thread - SP is within the thread's stack range
void notify_thread_exit(uint64_t sp, uint64_t retval, bool finalize) {
    std::lock_guard<std::mutex> lock(g_threads_mutex);

    // Find the thread by checking if SP falls within the thread's stack range
    for (auto it = g_threads.begin(); it != g_threads.end(); ++it) {
        auto& id = it->first;
        auto& thread = it->second;
        // Stack was allocated as: addr to addr + QEMU_THREAD_STACK_SIZE
        // stack_base is at addr + QEMU_THREAD_STACK_SIZE - 0x100 (top of usable stack)
        // So valid SP range is: (stack_base - QEMU_THREAD_STACK_SIZE + 0x100) to stack_base
        uint64_t stack_bottom = thread->stack_base - thread->stack_size + 0x100;
        uint64_t stack_top = thread->stack_base + 0x100;  // Include some margin

        if (sp >= stack_bottom && sp <= stack_top) {
            if (!thread->exit_reported.exchange(true, std::memory_order_acq_rel)) {
                thread->return_value = retval;
                EMU_LOG << "[HLE] Thread " << id << " reported exit (SP=0x" << std::hex << sp
                          << ") with retval=0x" << retval << std::dec << std::endl;
            } else if (thread->return_value != retval) {
                EMU_LOG << "[HLE] Thread " << id << " exit already reported, keeping retval=0x"
                          << std::hex << thread->return_value << " (new retval=0x" << retval
                          << ")" << std::dec << std::endl;
            }

            if (!finalize) {
                return;
            }

            if (thread->completed.exchange(true, std::memory_order_acq_rel)) {
                EMU_LOG << "[HLE] Thread " << id << " exit already finalized (SP=0x"
                          << std::hex << sp << ")" << std::dec << std::endl;
                thread->join_cv.notify_all();
                return;
            }

            EMU_LOG << "[HLE] Thread " << id << " finalizing exit (SP=0x" << std::hex << sp
                      << ") with retval=0x" << thread->return_value << std::dec << std::endl;

            thread->join_cv.notify_all();
            hle_release_vmas(thread->stack_base);
            hle_release_vmas(thread->tls_base);
            if (thread->detached) {
                // Detached + finished: nobody will join, so reclaim its arena regions.
                // Capture before erase; push to freelists only AFTER the entry is gone.
                uint64_t sb = thread->stack_base;
                uint64_t gsa = thread->guest_stack_addr;
                uint64_t tb = thread->tls_base;
                g_threads.erase(it);
                recycle_thread_arena(sb, gsa, tb);
            }
            return;
        }
    }

    // Thread not found in our registry - this might be the main thread
    EMU_LOG << "[HLE] Unknown thread " << (finalize ? "finalizing exit" : "reporting exit")
              << " (SP=0x" << std::hex << sp
              << ") with retval=0x" << retval << std::dec << std::endl;
}

} // namespace cross_shim
