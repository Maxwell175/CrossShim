#pragma once

#include <cstdint>
#include <string>
#include <memory>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <shared_mutex>
#include <unordered_map>
#include <deque>
#include <atomic>
#include <functional>
#include <chrono>

namespace cross_shim {

class Emulator;
class MemoryManager;
class HleManager;

// Thread states
enum class ThreadState {
    CREATED,
    RUNNABLE,      // Ready to run
    RUNNING,       // Currently executing
    BLOCKED,       // Blocked on synchronization primitive
    SLEEPING,      // Sleeping (sleep/usleep/nanosleep)
    IO_WAIT,       // Waiting for I/O
    TERMINATED
};

// Reason for context switch (for metrics/debugging)
enum class SwitchReason {
    BLOCKING_OPERATION,    // Tier 1: Natural blocking point
    PERIODIC_PREEMPTION,   // Tier 2: Time slice expired
    EMERGENCY_PREEMPTION,  // Tier 3: Pathological behavior
    THREAD_EXIT,
    THREAD_YIELD
};

// Special return value indicating a context switch occurred
// HLE handlers should NOT modify registers after receiving this value
constexpr int CONTEXT_SWITCH_OCCURRED = -999;

// Saved register state for context switching
struct RegisterState {
    uint64_t x[31];        // X0-X30 (general purpose registers)
    uint64_t sp;           // Stack pointer
    uint64_t pc;           // Program counter
    uint64_t tpidr_el0;    // Thread pointer (TLS)
    uint64_t lr;           // Link register (X30)
    uint64_t nzcv;         // Condition flags (NZCV) - critical for correct branch behavior
    // FP/SIMD registers - Q0-Q31 are 128-bit, stored as pairs of 64-bit values
    // ARM64 NEON registers: V0-V31 (128-bit each), also accessible as Q0-Q31, D0-D31, S0-S31, etc.
    uint64_t v[32][2];     // V0-V31 (128-bit SIMD registers, stored as 2x64-bit)
    uint32_t fpcr;         // Floating-point control register
    uint32_t fpsr;         // Floating-point status register
};

/**
 * ThreadContext - Thread state tracking
 *
 * With QEMU MTTCG, each thread runs on a real host thread. ThreadContext
 * tracks per-thread state like stack, TLS, and blocking information.
 */
struct ThreadContext {
    uint64_t thread_id = 0;
    uint64_t start_routine = 0;
    uint64_t arg = 0;
    uint64_t return_value = 0;
    uint64_t stack_base = 0;
    uint64_t stack_size = 0;
    uint64_t tls_base = 0;
    ThreadState state = ThreadState::CREATED;
    bool detached = false;

    // Saved register state when not running
    RegisterState registers;

    // Scheduling metrics
    std::chrono::steady_clock::time_point last_scheduled;
    std::chrono::steady_clock::time_point last_switch;
    uint64_t total_instructions = 0;
    uint64_t blocking_switches = 0;
    uint64_t periodic_switches = 0;
    uint64_t emergency_switches = 0;

    // Blocking information
    uint64_t blocked_on_resource = 0;  // Address of mutex/condvar/etc
    std::chrono::steady_clock::time_point sleep_until;

    // Join wait queue - threads waiting to join this thread
    std::deque<uint64_t> join_wait_queue;

    // Resume information for pthread_cond_wait
    uint64_t cond_wait_mutex = 0;  // Mutex to reacquire after cond_wait
    uint64_t cond_wait_return_addr = 0;  // Return address after cond_wait

    // Resume information for pthread_join
    uint64_t join_target_thread = 0;  // Thread ID we're waiting to join
    uint64_t join_retval_ptr = 0;  // Pointer to store return value
    uint64_t join_return_addr = 0;  // Return address after join

    // Resume information for pthread_mutex_lock
    uint64_t mutex_wait_ptr = 0;  // Mutex we're waiting for
    uint64_t mutex_wait_return_addr = 0;  // Return address after mutex_lock

    // Resume information for pthread_barrier_wait
    uint64_t barrier_wait_ptr = 0;  // Barrier we're waiting on
    uint64_t barrier_wait_return_addr = 0;  // Return address after barrier_wait

    // Resume information for futex wait
    uint64_t futex_wait_addr = 0;  // Futex address we're waiting on
    uint64_t futex_wait_return_addr = 0;  // Return address after futex wait

    // Resume information for pthread_rwlock_rdlock
    uint64_t rwlock_rdlock_ptr = 0;  // RWLock we're waiting for (read)
    uint64_t rwlock_rdlock_return_addr = 0;  // Return address after rdlock

    // Resume information for pthread_rwlock_wrlock
    uint64_t rwlock_wrlock_ptr = 0;  // RWLock we're waiting for (write)
    uint64_t rwlock_wrlock_return_addr = 0;  // Return address after wrlock

    // Resume information for blocking I/O operations
    enum class IoOperation { NONE, RECV, SEND, ACCEPT, CONNECT, RECVFROM, SENDTO, READ, WRITE };
    IoOperation io_operation = IoOperation::NONE;
    int io_fd = -1;
    uint64_t io_buf_ptr = 0;
    size_t io_len = 0;
    int io_flags = 0;
    uint64_t io_addr_ptr = 0;
    uint64_t io_addrlen_ptr = 0;
    uint64_t io_return_addr = 0;

    // Cooperative I/O state - tracks ongoing cooperative operations
    enum class CoopIoType { NONE, EPOLL_WAIT, POLL, SELECT, READ, WRITE, RECV, SEND, RECVFROM, SENDTO };
    CoopIoType coop_io_type = CoopIoType::NONE;
    std::chrono::steady_clock::time_point coop_io_start;  // When the operation started
    int coop_io_timeout_ms = 0;  // Original timeout in milliseconds
    int coop_io_fd = -1;  // File descriptor for the operation
    uint64_t coop_io_events_ptr = 0;  // Pointer to events buffer (for epoll_wait)
    int coop_io_maxevents = 0;  // Max events (for epoll_wait)
    uint64_t coop_io_return_addr = 0;  // Return address after operation completes

    // Grace period - prevents context switch for N instructions after restore
    // This prevents the "stuck at instruction" bug where a hook fires before
    // an instruction executes, context switch saves PC, restore returns to same PC,
    // and the instruction never executes.
    uint64_t grace_period_remaining = 0;  // Instructions remaining in grace period

    // Thread initialization - for synchronizing parent/child at pthread_create
    bool initialized = false;  // Set to true when thread reaches entry point and TLS is initialized

    // Immediate preemption protection - prevents context switch right after restore
    // Without this, a thread can be switched TO and then immediately switched AWAY
    // before executing even a single instruction, preventing grace_period from working
    bool block_next_switch = false;  // If true, block the next context_switch() call
};

// Emulated mutex (cooperative)
struct EmulatedMutex {
    bool is_locked = false;
    uint64_t owner_thread = 0;
    int lock_count = 0;
    int type = 0;  // PTHREAD_MUTEX_NORMAL, PTHREAD_MUTEX_RECURSIVE, etc.
    std::deque<uint64_t> wait_queue;  // Threads waiting for this mutex
};

// Emulated condition variable (cooperative)
struct EmulatedCondVar {
    std::deque<uint64_t> wait_queue;  // Threads waiting on this condvar
};

// Emulated read-write lock (cooperative)
struct EmulatedRWLock {
    int readers = 0;
    uint64_t writer = 0;  // Thread ID of writer (0 if no writer)
    int write_count = 0;  // Recursive write lock count
    std::deque<uint64_t> read_wait_queue;
    std::deque<uint64_t> write_wait_queue;
};

// Emulated barrier (cooperative)
struct EmulatedBarrier {
    unsigned int count = 0;           // Number of threads required
    unsigned int waiting = 0;         // Number of threads currently waiting
    unsigned int generation = 0;      // Generation counter to handle spurious wakeups
    std::deque<uint64_t> wait_queue;  // Threads waiting at the barrier
};

/**
 * ThreadManager - Thread State Tracking for QEMU MTTCG
 *
 * With LibAFL QEMU's MTTCG (Multi-Threaded TCG), each emulated thread runs
 * on a real host thread. The actual threading is handled by QEMU's clone()
 * syscall implementation, which creates real parallel host threads.
 *
 * ThreadManager provides:
 * - Thread lifecycle tracking (create, exit, join)
 * - Stack and TLS allocation for child threads
 * - pthread primitives (mutex, condvar, rwlock, barrier)
 * - Thread-local storage (pthread_key_*)
 *
 * Key features:
 * - Real parallel execution via QEMU MTTCG
 * - Each thread has its own stack and TLS
 * - LSE atomics handled natively by QEMU
 * - No cooperative scheduling needed
 */
class ThreadManager {
public:
    ThreadManager(Emulator& emu, MemoryManager& memory);
    ~ThreadManager();

    // Thread operations
    int pthread_create(uint64_t thread_ptr, uint64_t attr,
                       uint64_t start_routine, uint64_t arg);
    int pthread_join(uint64_t thread_id, uint64_t* retval);
    void pthread_join_resume();  // Resume after join (retrieve return value)
    int pthread_join_nonblocking(uint64_t thread_id, uint64_t* retval, int timeout_ms);
    int pthread_detach(uint64_t thread_id);
    uint64_t pthread_self();
    void pthread_exit(uint64_t retval);

    // Mutex operations
    int pthread_mutex_init(uint64_t mutex_ptr, uint64_t attr);
    int pthread_mutex_destroy(uint64_t mutex_ptr);
    int pthread_mutex_lock(uint64_t mutex_ptr);
    void pthread_mutex_lock_resume();  // Resume after mutex_lock (acquire mutex)
    int pthread_mutex_trylock(uint64_t mutex_ptr);
    int pthread_mutex_unlock(uint64_t mutex_ptr);

    // Condition variable operations
    int pthread_cond_init(uint64_t cond_ptr, uint64_t attr);
    int pthread_cond_destroy(uint64_t cond_ptr);
    int pthread_cond_wait(uint64_t cond_ptr, uint64_t mutex_ptr);
    void pthread_cond_wait_resume();  // Resume after cond_wait (reacquire mutex)
    int pthread_cond_timedwait(uint64_t cond_ptr, uint64_t mutex_ptr,
                                uint64_t abstime_ptr);
    int pthread_cond_signal(uint64_t cond_ptr);
    int pthread_cond_broadcast(uint64_t cond_ptr);

    // Read-write lock operations
    int pthread_rwlock_init(uint64_t rwlock_ptr, uint64_t attr);
    int pthread_rwlock_destroy(uint64_t rwlock_ptr);
    int pthread_rwlock_rdlock(uint64_t rwlock_ptr);
    void pthread_rwlock_rdlock_resume();
    int pthread_rwlock_tryrdlock(uint64_t rwlock_ptr);
    int pthread_rwlock_wrlock(uint64_t rwlock_ptr);
    void pthread_rwlock_wrlock_resume();
    int pthread_rwlock_trywrlock(uint64_t rwlock_ptr);
    int pthread_rwlock_unlock(uint64_t rwlock_ptr);

    // Barrier operations
    int pthread_barrier_init(uint64_t barrier_ptr, uint64_t attr, unsigned int count);
    int pthread_barrier_destroy(uint64_t barrier_ptr);
    int pthread_barrier_wait(uint64_t barrier_ptr);
    void pthread_barrier_wait_resume();

    // Thread-local storage
    int pthread_key_create(uint64_t key_ptr, uint64_t destructor);
    int pthread_key_delete(uint64_t key);
    uint64_t pthread_getspecific(uint64_t key);
    int pthread_setspecific(uint64_t key, uint64_t value);

    // Utility
    uint64_t get_current_thread_id() const;
    void set_threading_enabled(bool enabled) { threading_enabled_ = enabled; }
    bool is_threading_enabled() const { return threading_enabled_; }

    // Get thread context by ID
    ThreadContext* get_thread(uint64_t thread_id);
    ThreadContext* get_thread_unlocked(uint64_t thread_id);  // Internal - caller must hold threads_mutex_

    // Scheduler control
    void context_switch(SwitchReason reason = SwitchReason::PERIODIC_PREEMPTION);
    void yield(bool set_pc_to_lr = true);  // Voluntary yield. If set_pc_to_lr is false, don't modify PC.
    void block_current_thread(ThreadState new_state, uint64_t resource_id = 0);
    void unblock_thread(uint64_t thread_id);
    void unblock_thread_internal(uint64_t thread_id);  // Internal version - assumes threads_mutex_ is held
    void sleep_current_thread(uint64_t microseconds);

    // Futex support
    void block_on_futex(uint64_t futex_addr);
    void unblock_from_futex(uint64_t thread_id);

    // Get thread count
    size_t get_thread_count() const;

    // Blocking I/O operations (cooperative)
    // These return CONTEXT_SWITCH_OCCURRED if the operation would block
    // and the thread needs to be rescheduled
    ssize_t blocking_recv(int sockfd, uint64_t buf_ptr, size_t len, int flags);
    void blocking_recv_resume();
    ssize_t blocking_send(int sockfd, uint64_t buf_ptr, size_t len, int flags);
    void blocking_send_resume();
    int blocking_accept(int sockfd, uint64_t addr_ptr, uint64_t addrlen_ptr);
    void blocking_accept_resume();
    ssize_t blocking_read(int fd, uint64_t buf_ptr, size_t count);
    void blocking_read_resume();
    ssize_t blocking_write(int fd, uint64_t buf_ptr, size_t count);
    void blocking_write_resume();

    // Cooperative I/O state management
    // These methods manage the state of ongoing cooperative I/O operations
    void start_coop_epoll_wait(int epfd, uint64_t events_ptr, int maxevents, int timeout_ms);
    bool is_in_coop_io() const;
    ThreadContext::CoopIoType get_coop_io_type() const;
    int get_coop_io_remaining_timeout_ms() const;
    void clear_coop_io_state();

    // Cooperative yield - yields without modifying PC, for use in cooperative I/O loops
    void coop_yield();

    // Block current thread on I/O and yield (for wait_for_fd)
    // Sets thread to IO_WAIT state, saves fd/events, and yields once
    // When thread resumes, FD should be ready (scheduler woke us)
    void block_on_io_and_yield(int fd, short events);

    // Tier 2: Periodic preemption hook
    void periodic_check();
    void periodic_check(uint64_t instructions_executed);  // For block-level hooks
    void set_periodic_interval(uint64_t instructions) { periodic_check_interval_ = instructions; }

    // Clear block_next_switch flag for current thread
    // Uses a counter to only check for first N instructions after restore
    void clear_block_next_switch();

    // Tier 3: Emergency mode control
    void enable_emergency_mode();
    void disable_emergency_mode();
    bool is_emergency_mode() const { return emergency_mode_; }

private:
    uint64_t allocate_thread_id();
    uint64_t allocate_thread_stack();
    uint64_t allocate_thread_tls();

    // Scheduler internals
    void save_thread_state(ThreadContext* ctx);
    void restore_thread_state(ThreadContext* ctx);
    ThreadContext* select_next_thread();
    void run_scheduler();
    void watchdog_thread_func();

    // Helper to check if any threads are runnable
    bool has_runnable_threads() const;

    Emulator& emu_;
    MemoryManager& memory_;

    // Thread management (single engine, cooperative)
    std::unordered_map<uint64_t, std::unique_ptr<ThreadContext>> threads_;
    std::mutex threads_mutex_;
    std::atomic<uint64_t> next_thread_id_{4096};  // Start at 4096 to avoid conflicts
    uint64_t main_thread_id_ = 0;
    uint64_t current_thread_id_ = 0;  // Currently running thread

    // Scheduler state
    std::deque<uint64_t> runnable_queue_;  // Threads ready to run
    std::mutex scheduler_mutex_;
    bool scheduler_running_ = false;

    // Stack allocation
    std::mutex stack_mutex_;
    uint64_t next_stack_index_ = 0;

    // TLS allocation
    std::mutex tls_mutex_;
    uint64_t next_tls_index_ = 0;

    // Synchronization primitives (cooperative)
    std::unordered_map<uint64_t, std::unique_ptr<EmulatedMutex>> mutexes_;
    std::unordered_map<uint64_t, std::unique_ptr<EmulatedCondVar>> condvars_;
    std::unordered_map<uint64_t, std::unique_ptr<EmulatedRWLock>> rwlocks_;
    std::unordered_map<uint64_t, std::unique_ptr<EmulatedBarrier>> barriers_;

    // Thread-local storage
    std::unordered_map<uint64_t, std::unordered_map<uint64_t, uint64_t>> tls_data_;
    std::unordered_map<uint64_t, uint64_t> tls_destructors_;
    std::atomic<uint64_t> next_tls_key_{1};

    // Tier 2: Periodic preemption
    uint64_t instruction_count_ = 0;
    uint64_t periodic_check_interval_ = 10000;  // Check every 10k instructions (low overhead)
    std::chrono::steady_clock::time_point last_periodic_check_;
    void periodic_check_internal();  // Internal implementation

    // Tier 3: Emergency mode
    bool emergency_mode_ = false;
    std::thread watchdog_thread_;
    std::atomic<bool> watchdog_running_{false};
    uint64_t emergency_check_interval_ = 1000;  // Very aggressive in emergency mode

    bool threading_enabled_ = true;
};

} // namespace cross_shim
