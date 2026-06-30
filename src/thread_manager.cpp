/**
 * Thread Manager Implementation - Thread State Tracking for QEMU MTTCG
 *
 * With LibAFL QEMU MTTCG, each emulated thread runs on a real host thread.
 * ThreadManager tracks thread state, allocates stacks/TLS, and provides
 * pthread primitives. Actual thread creation is handled by QEMU's clone().
 */

#include "debug_log.h"
#include "thread_manager.h"
#include "cross_shim.h"
#include "memory_manager.h"
#include "hle_manager.h"
#include "memory_manager.h"
#include "emu_compat.h"
#include "bionic_types.h"
#include <iostream>
#include <chrono>
#include <cerrno>
#include <cstring>
#include <algorithm>
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <poll.h>
#include <vector>

namespace cross_shim {

namespace {

constexpr int kMaxHleEpollWaitSliceMs = 20;

int clamp_hle_epoll_wait_timeout(int timeout_ms) {
    if (timeout_ms == 0) {
        return 0;
    }
    if (timeout_ms < 0) {
        return kMaxHleEpollWaitSliceMs;
    }
    return std::min(timeout_ms, kMaxHleEpollWaitSliceMs);
}

bool write_epoll_events_to_guest(Emulator& emu, uint64_t events_ptr,
                                 const std::vector<struct epoll_event>& host_events,
                                 int result_count) {
    if (result_count <= 0) {
        return true;
    }

    std::vector<bionic::epoll_event_arm64> guest_events(result_count);
    for (int i = 0; i < result_count; ++i) {
        bionic::host_to_arm64_epoll_event(host_events[i], guest_events[i]);
    }

    return emu.mem_write(events_ptr, guest_events.data(),
                         result_count * sizeof(bionic::epoll_event_arm64));
}

}  // namespace

// Thread stack size (1MB per thread)
constexpr uint64_t THREAD_STACK_SIZE = 0x100000;

// Base address for thread stacks (separate from main stack)
constexpr uint64_t THREAD_STACK_BASE = 0x90000000ULL;

// Base address for thread TLS (separate from main TLS)
constexpr uint64_t THREAD_TLS_BASE = 0xD0000000ULL;
constexpr uint64_t THREAD_TLS_SIZE = 0x10000;  // 64KB per thread

ThreadManager::ThreadManager(Emulator& emu, MemoryManager& memory)
    : emu_(emu), memory_(memory) {
    // Main thread gets ID 1
    main_thread_id_ = 1;
    current_thread_id_ = main_thread_id_;

    // Create main thread entry (uses the shared engine)
    auto main_thread = std::make_unique<ThreadContext>();
    main_thread->thread_id = main_thread_id_;
    main_thread->state = ThreadState::RUNNING;
    main_thread->stack_base = STACK_BASE + STACK_SIZE - 0x100;
    main_thread->stack_size = STACK_SIZE;
    main_thread->last_scheduled = std::chrono::steady_clock::now();
    main_thread->last_switch = std::chrono::steady_clock::now();
    main_thread->initialized = true;  // Main thread is already running and initialized
    threads_[main_thread_id_] = std::move(main_thread);

    // Start watchdog thread for Tier 3 emergency detection
    watchdog_running_ = true;
    watchdog_thread_ = std::thread(&ThreadManager::watchdog_thread_func, this);

    last_periodic_check_ = std::chrono::steady_clock::now();
}

ThreadManager::~ThreadManager() {
    // Stop watchdog
    watchdog_running_ = false;
    if (watchdog_thread_.joinable()) {
        watchdog_thread_.join();
    }

    // Clean up threads
    std::lock_guard<std::mutex> lock(threads_mutex_);
    threads_.clear();
}

uint64_t ThreadManager::allocate_thread_id() {
    return next_thread_id_++;
}

uint64_t ThreadManager::get_current_thread_id() const {
    return current_thread_id_;
}

ThreadContext* ThreadManager::get_thread(uint64_t thread_id) {
    std::lock_guard<std::mutex> lock(threads_mutex_);
    return get_thread_unlocked(thread_id);
}

// Internal version that doesn't take the lock - caller must hold threads_mutex_
ThreadContext* ThreadManager::get_thread_unlocked(uint64_t thread_id) {
    auto it = threads_.find(thread_id);
    if (it != threads_.end()) {
        return it->second.get();
    }
    return nullptr;
}

// Save current thread's register state
void ThreadManager::save_thread_state(ThreadContext* ctx) {
    if (!ctx) return;

    // Save general purpose registers X0-X30 using QEMU API
    static const int kXRegs[31] = {
        UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
        UC_ARM64_REG_X4, UC_ARM64_REG_X5, UC_ARM64_REG_X6, UC_ARM64_REG_X7,
        UC_ARM64_REG_X8, UC_ARM64_REG_X9, UC_ARM64_REG_X10, UC_ARM64_REG_X11,
        UC_ARM64_REG_X12, UC_ARM64_REG_X13, UC_ARM64_REG_X14, UC_ARM64_REG_X15,
        UC_ARM64_REG_X16, UC_ARM64_REG_X17, UC_ARM64_REG_X18, UC_ARM64_REG_X19,
        UC_ARM64_REG_X20, UC_ARM64_REG_X21, UC_ARM64_REG_X22, UC_ARM64_REG_X23,
        UC_ARM64_REG_X24, UC_ARM64_REG_X25, UC_ARM64_REG_X26, UC_ARM64_REG_X27,
        UC_ARM64_REG_X28, UC_ARM64_REG_X29, UC_ARM64_REG_X30,
    };

    for (int i = 0; i < 31; i++) {
        ctx->registers.x[i] = get_reg(emu_, kXRegs[i]);
    }

    // Save special registers (stack pointer, PC, LR, TLS base, NZCV)
    ctx->registers.sp = get_reg(emu_, UC_ARM64_REG_SP);
    ctx->registers.pc = get_reg(emu_, UC_ARM64_REG_PC);
    ctx->registers.lr = get_reg(emu_, UC_ARM64_REG_LR);
    ctx->registers.tpidr_el0 = get_reg(emu_, UC_ARM64_REG_TPIDR_EL0);
    ctx->registers.nzcv = get_reg(emu_, UC_ARM64_REG_NZCV);

    // Save NEON/SIMD registers Q0-Q31 (128-bit each)
    static const int kQRegs[32] = {
        UC_ARM64_REG_Q0,  UC_ARM64_REG_Q1,  UC_ARM64_REG_Q2,  UC_ARM64_REG_Q3,
        UC_ARM64_REG_Q4,  UC_ARM64_REG_Q5,  UC_ARM64_REG_Q6,  UC_ARM64_REG_Q7,
        UC_ARM64_REG_Q8,  UC_ARM64_REG_Q9,  UC_ARM64_REG_Q10, UC_ARM64_REG_Q11,
        UC_ARM64_REG_Q12, UC_ARM64_REG_Q13, UC_ARM64_REG_Q14, UC_ARM64_REG_Q15,
        UC_ARM64_REG_Q16, UC_ARM64_REG_Q17, UC_ARM64_REG_Q18, UC_ARM64_REG_Q19,
        UC_ARM64_REG_Q20, UC_ARM64_REG_Q21, UC_ARM64_REG_Q22, UC_ARM64_REG_Q23,
        UC_ARM64_REG_Q24, UC_ARM64_REG_Q25, UC_ARM64_REG_Q26, UC_ARM64_REG_Q27,
        UC_ARM64_REG_Q28, UC_ARM64_REG_Q29, UC_ARM64_REG_Q30, UC_ARM64_REG_Q31,
    };
    for (int i = 0; i < 32; i++) {
        // Q registers are 128-bit, read as two 64-bit values
        get_vreg(emu_, kQRegs[i], ctx->registers.v[i]);
    }

    // Save FPCR and FPSR (floating-point control and status registers)
    ctx->registers.fpcr = static_cast<uint32_t>(get_reg(emu_, UC_ARM64_REG_FPCR));
    ctx->registers.fpsr = static_cast<uint32_t>(get_reg(emu_, UC_ARM64_REG_FPSR));

    if (emu_.is_debug() && ctx->registers.tpidr_el0 == 0) {
        EMU_LOG << "[SCHED] WARNING: Thread " << ctx->thread_id
                  << " saved with TPIDR_EL0=0! PC=0x" << std::hex << ctx->registers.pc << std::dec << std::endl;
    }

    // Check if X22 contains a host address (0x7f... range)
    uint64_t x22 = ctx->registers.x[22];
    if ((x22 >> 32) != 0 && x22 > 0x7f0000000000ULL && x22 < 0x800000000000ULL) {
        EMU_LOG << "[SCHED] WARNING: Thread " << ctx->thread_id
                  << " saved with X22=0x" << std::hex << x22
                  << " (host address!) PC=0x" << ctx->registers.pc << std::dec << std::endl;
    }
}

// Restore thread's register state
void ThreadManager::restore_thread_state(ThreadContext* ctx) {
    if (!ctx) return;

    static const int kXRegs[31] = {
        UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
        UC_ARM64_REG_X4, UC_ARM64_REG_X5, UC_ARM64_REG_X6, UC_ARM64_REG_X7,
        UC_ARM64_REG_X8, UC_ARM64_REG_X9, UC_ARM64_REG_X10, UC_ARM64_REG_X11,
        UC_ARM64_REG_X12, UC_ARM64_REG_X13, UC_ARM64_REG_X14, UC_ARM64_REG_X15,
        UC_ARM64_REG_X16, UC_ARM64_REG_X17, UC_ARM64_REG_X18, UC_ARM64_REG_X19,
        UC_ARM64_REG_X20, UC_ARM64_REG_X21, UC_ARM64_REG_X22, UC_ARM64_REG_X23,
        UC_ARM64_REG_X24, UC_ARM64_REG_X25, UC_ARM64_REG_X26, UC_ARM64_REG_X27,
        UC_ARM64_REG_X28, UC_ARM64_REG_X29, UC_ARM64_REG_X30,
    };

    // Restore general purpose registers X0-X30
    for (int i = 0; i < 31; i++) {
        set_reg(emu_, kXRegs[i], ctx->registers.x[i]);
    }

    // Restore special registers
    set_reg(emu_, UC_ARM64_REG_SP, ctx->registers.sp);
    set_reg(emu_, UC_ARM64_REG_PC, ctx->registers.pc);
    set_reg(emu_, UC_ARM64_REG_LR, ctx->registers.lr);
    set_reg(emu_, UC_ARM64_REG_TPIDR_EL0, ctx->registers.tpidr_el0);
    set_reg(emu_, UC_ARM64_REG_NZCV, ctx->registers.nzcv);

    // Restore NEON/SIMD registers Q0-Q31 (128-bit each)
    static const int kQRegs[32] = {
        UC_ARM64_REG_Q0,  UC_ARM64_REG_Q1,  UC_ARM64_REG_Q2,  UC_ARM64_REG_Q3,
        UC_ARM64_REG_Q4,  UC_ARM64_REG_Q5,  UC_ARM64_REG_Q6,  UC_ARM64_REG_Q7,
        UC_ARM64_REG_Q8,  UC_ARM64_REG_Q9,  UC_ARM64_REG_Q10, UC_ARM64_REG_Q11,
        UC_ARM64_REG_Q12, UC_ARM64_REG_Q13, UC_ARM64_REG_Q14, UC_ARM64_REG_Q15,
        UC_ARM64_REG_Q16, UC_ARM64_REG_Q17, UC_ARM64_REG_Q18, UC_ARM64_REG_Q19,
        UC_ARM64_REG_Q20, UC_ARM64_REG_Q21, UC_ARM64_REG_Q22, UC_ARM64_REG_Q23,
        UC_ARM64_REG_Q24, UC_ARM64_REG_Q25, UC_ARM64_REG_Q26, UC_ARM64_REG_Q27,
        UC_ARM64_REG_Q28, UC_ARM64_REG_Q29, UC_ARM64_REG_Q30, UC_ARM64_REG_Q31,
    };
    for (int i = 0; i < 32; i++) {
        set_vreg(emu_, kQRegs[i], ctx->registers.v[i]);
    }

    // Restore FPCR and FPSR (floating-point control and status registers)
    set_reg(emu_, UC_ARM64_REG_FPCR, ctx->registers.fpcr);
    set_reg(emu_, UC_ARM64_REG_FPSR, ctx->registers.fpsr);

    if (emu_.is_debug()) {
        if (ctx->registers.tpidr_el0 == 0) {
            EMU_LOG << "[SCHED] WARNING: Thread " << ctx->thread_id
                      << " restored with TPIDR_EL0=0! PC=0x" << std::hex << ctx->registers.pc << std::dec << std::endl;
        }
        // Log TPIDR_EL0 for non-main threads to debug stack check issues
        if (ctx->thread_id >= 4096) {
            EMU_LOG << "[SCHED] Thread " << ctx->thread_id
                      << " TPIDR_EL0=0x" << std::hex << ctx->registers.tpidr_el0
                      << " tls_base=0x" << ctx->tls_base << std::dec << std::endl;
        }
    }

    // MEMORY SYNCHRONIZATION FIX: Force memory state sync after context switch
    // Perform a dummy read at a known valid address (the restored SP register)
    {
        uint64_t dummy;
        emu_.mem_read(ctx->registers.sp, &dummy, 8);
    }

    // GRACE PERIOD: Set to 100 instructions after restore
    ctx->grace_period_remaining = 100;

    // IMMEDIATE PREEMPTION FIX: Block the next context_switch() call
    ctx->block_next_switch = true;
}

// Select next thread to run (round-robin from runnable queue)
ThreadContext* ThreadManager::select_next_thread() {
    std::lock_guard<std::mutex> lock(scheduler_mutex_);

    // Check for sleeping threads that should wake up
    auto now = std::chrono::steady_clock::now();
    for (auto& pair : threads_) {
        if (pair.second->state == ThreadState::SLEEPING) {
            if (now >= pair.second->sleep_until) {
                pair.second->state = ThreadState::RUNNABLE;
                runnable_queue_.push_back(pair.first);
            }
        }
    }

    // Check for I/O waiting threads that are now ready
    for (auto& pair : threads_) {
        if (pair.second->state == ThreadState::IO_WAIT) {
            int fd = pair.second->io_fd;
            bool wake_for_timeout = false;
            if (pair.second->coop_io_type == ThreadContext::CoopIoType::EPOLL_WAIT &&
                pair.second->coop_io_timeout_ms >= 0) {
                auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                    now - pair.second->coop_io_start).count();
                wake_for_timeout = elapsed >= pair.second->coop_io_timeout_ms;
            }

            if (wake_for_timeout) {
                pair.second->state = ThreadState::RUNNABLE;
                runnable_queue_.push_back(pair.first);
                continue;
            }

            if (fd >= 0) {
                struct pollfd pfd;
                pfd.fd = fd;
                // Check for read or write depending on operation
                if (pair.second->io_operation == ThreadContext::IoOperation::RECV ||
                    pair.second->io_operation == ThreadContext::IoOperation::ACCEPT ||
                    pair.second->io_operation == ThreadContext::IoOperation::RECVFROM) {
                    pfd.events = POLLIN;
                } else {
                    pfd.events = POLLOUT;
                }
                pfd.revents = 0;

                // Non-blocking poll
                int ret = poll(&pfd, 1, 0);
                if (emu_.is_debug()) {
                    EMU_LOG << "[SCHED] IO poll for thread " << pair.first
                              << " fd=" << fd << " op=" << static_cast<int>(pair.second->io_operation)
                              << " ret=" << ret << " revents=0x" << std::hex << pfd.revents << std::dec
                              << std::endl;
                }
                if (ret > 0 && (pfd.revents & pfd.events)) {
                    // I/O is ready, wake up the thread
                    if (emu_.is_debug()) {
                        EMU_LOG << "[SCHED] Waking up IO thread " << pair.first << std::endl;
                    }
                    pair.second->state = ThreadState::RUNNABLE;
                    runnable_queue_.push_back(pair.first);
                }
            }
        }
    }

    // Get next runnable thread
    while (!runnable_queue_.empty()) {
        uint64_t thread_id = runnable_queue_.front();
        runnable_queue_.pop_front();

        auto it = threads_.find(thread_id);
        if (it != threads_.end() && it->second->state == ThreadState::RUNNABLE) {
            return it->second.get();
        }
    }
    return nullptr;
}

// Check if any threads are runnable
bool ThreadManager::has_runnable_threads() const {
    std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(scheduler_mutex_));

    for (const auto& pair : threads_) {
        if (pair.second->state == ThreadState::RUNNABLE) {
            return true;
        }
    }

    return false;
}

// Context switch to another thread
void ThreadManager::context_switch(SwitchReason reason) {
    // Debug logging disabled for performance
    // EMU_LOG << "[CONTEXT_SWITCH] ENTRY: thread=" << current_thread_id_
    //           << " reason=" << static_cast<int>(reason) << std::endl;

    std::lock_guard<std::mutex> lock(threads_mutex_);

    // Get current thread
    auto current_it = threads_.find(current_thread_id_);
    if (current_it == threads_.end()) {
        EMU_LOG << "[CONTEXT_SWITCH] Thread " << current_thread_id_ << " not found!" << std::endl;
        return;
    }

    ThreadContext* current = current_it->second.get();

    // IMMEDIATE PREEMPTION FIX: Block context switch if thread was just restored
    // This ensures the thread executes at least ONE instruction before being preempted
    // EXCEPTION: YIELD, BLOCKING_OPERATION, and THREAD_EXIT must always be allowed
    // because these are voluntary switches (the thread explicitly wants to switch)
    if (current->block_next_switch &&
        reason != SwitchReason::THREAD_YIELD &&
        reason != SwitchReason::BLOCKING_OPERATION &&
        reason != SwitchReason::THREAD_EXIT) {
        if (emu_.is_debug()) {
            EMU_LOG << "[CTX] Blocked context_switch for Thread " << current_thread_id_
                      << ", reason=" << static_cast<int>(reason) << std::endl;
        }
        return;
    }
    // Clear block_next_switch if we're proceeding with the switch
    if (current->block_next_switch) {
        current->block_next_switch = false;
    }

    // Don't allow context switch if thread has an active exclusive monitor
    // This prevents interrupting LDXR/STXR sequences
    // Exception: blocking operations must be allowed to switch
    if (reason != SwitchReason::BLOCKING_OPERATION &&
        reason != SwitchReason::THREAD_EXIT) {
        if (false) { // QEMU handles atomics natively
            return;
        }
    }

    // Update metrics
    switch (reason) {
        case SwitchReason::BLOCKING_OPERATION:
            current->blocking_switches++;
            break;
        case SwitchReason::PERIODIC_PREEMPTION:
            current->periodic_switches++;
            break;
        case SwitchReason::EMERGENCY_PREEMPTION:
            current->emergency_switches++;
            break;
        default:
            break;
    }

    // Save current thread state if it's still runnable
    if (current->state == ThreadState::RUNNING) {
        save_thread_state(current);
        current->state = ThreadState::RUNNABLE;

        // Add back to runnable queue
        std::lock_guard<std::mutex> sched_lock(scheduler_mutex_);
        runnable_queue_.push_back(current_thread_id_);
        // No I/O in critical path - removed to prevent timing issues
        if (emu_.is_debug()) {
            EMU_LOG << "[SCHED] Thread " << current_thread_id_ << " added to runnable queue (size=" << runnable_queue_.size() << ") reason=" << static_cast<int>(reason) << std::endl;
        }
    } else {
        // Thread is blocked/sleeping/terminated
        // Save the resume PC before save_thread_state overwrites it
        // Only preserve if the thread has a pending I/O operation or other blocking operation
        // that requires resuming at a specific HLE address
        uint64_t saved_resume_pc = current->registers.pc;
        bool has_resume_pc = false;

        // Check if this is a blocking operation that needs a resume address
        if (current->state == ThreadState::IO_WAIT &&
            current->io_operation != ThreadContext::IoOperation::NONE) {
            has_resume_pc = (saved_resume_pc >= HLE_BASE && saved_resume_pc < HLE_BASE + HLE_SIZE);
        } else if (current->state == ThreadState::BLOCKED) {
            // Check for mutex, condvar, join, barrier, or futex blocking
            if (current->mutex_wait_ptr != 0 ||
                current->cond_wait_mutex != 0 ||
                current->join_target_thread != 0 ||
                current->barrier_wait_ptr != 0 ||
                current->futex_wait_addr != 0) {
                has_resume_pc = (saved_resume_pc >= HLE_BASE && saved_resume_pc < HLE_BASE + HLE_SIZE);
            }
        }

        save_thread_state(current);

        // Restore the resume PC if it was set for a blocking operation
        if (has_resume_pc) {
            current->registers.pc = saved_resume_pc;
        }
    }

    current->last_switch = std::chrono::steady_clock::now();

    // Select next thread
    ThreadContext* next = select_next_thread();
    if (!next) {
        // No runnable threads - check if there are sleeping or blocked threads
        bool has_sleeping_or_blocked = false;
        std::chrono::steady_clock::time_point earliest_wakeup = std::chrono::steady_clock::time_point::max();

        for (const auto& pair : threads_) {
            if (pair.second->state == ThreadState::SLEEPING) {
                has_sleeping_or_blocked = true;
                if (pair.second->sleep_until < earliest_wakeup) {
                    earliest_wakeup = pair.second->sleep_until;
                }
            } else if (pair.second->state == ThreadState::BLOCKED ||
                       pair.second->state == ThreadState::IO_WAIT) {
                has_sleeping_or_blocked = true;
            }
        }

        if (has_sleeping_or_blocked) {
            // Wait for the earliest sleeping thread to wake up
            auto now = std::chrono::steady_clock::now();
            if (earliest_wakeup != std::chrono::steady_clock::time_point::max() && earliest_wakeup > now) {
                auto wait_time = std::chrono::duration_cast<std::chrono::milliseconds>(earliest_wakeup - now);
                if (wait_time.count() > 0) {
                    // Release the lock and wait
                    // Use a short wait to allow checking for I/O readiness
                    auto actual_wait = std::min(wait_time, std::chrono::milliseconds(10));
                    std::this_thread::sleep_for(actual_wait);
                }
            } else {
                // No sleeping threads with known wakeup time, just yield briefly
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }

            // Try again to select a thread
            next = select_next_thread();
        }

        if (!next) {
            if (current->state == ThreadState::TERMINATED) {
                // Current thread is terminated and no other threads are runnable
                // Check if all threads are terminated
                bool all_terminated = true;
                for (const auto& pair : threads_) {
                    if (pair.second->state != ThreadState::TERMINATED) {
                        all_terminated = false;
                        break;
                    }
                }

                if (all_terminated) {
                    EMU_LOG << "[SCHED] All threads terminated, stopping emulator" << std::endl;
                    // Set PC to 0 to stop execution
                    uint64_t stop_pc = 0;
                    set_reg(emu_, UC_ARM64_REG_PC, stop_pc);
                    return;
                }

                // Some threads are still alive but not runnable
                // Log thread states for debugging
                EMU_LOG << "[SCHED] Thread " << current_thread_id_
                          << " terminated, waiting for other threads. Thread states:" << std::endl;
                for (const auto& pair : threads_) {
                    EMU_LOG << "  Thread " << pair.first << ": state="
                              << static_cast<int>(pair.second->state) << std::endl;
                }

                // Wait longer and retry multiple times
                for (int retry = 0; retry < 10 && !next; retry++) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    next = select_next_thread();
                    if (next) {
                        EMU_LOG << "[SCHED] Found runnable thread " << next->thread_id
                                  << " after " << (retry + 1) * 100 << "ms" << std::endl;
                    }
                }

                if (!next) {
                    // Still no runnable threads, stop the emulator
                    EMU_LOG << "[SCHED] No runnable threads after 1s wait, stopping" << std::endl;
                    uint64_t stop_pc = 0;
                    set_reg(emu_, UC_ARM64_REG_PC, stop_pc);
                    return;
                }
            } else {
                // Keep current thread running if it's still runnable
                if (current->state == ThreadState::RUNNABLE) {
                    current->state = ThreadState::RUNNING;
                }
                return;
            }
        }
    }

    // Switch to next thread
    uint64_t old_thread = current_thread_id_;
    current_thread_id_ = next->thread_id;
    next->state = ThreadState::RUNNING;
    next->last_scheduled = std::chrono::steady_clock::now();

    // Debug logging disabled for performance
    restore_thread_state(next);
}

// Allocate a stack for a new thread
uint64_t ThreadManager::allocate_thread_stack() {
    std::lock_guard<std::mutex> lock(stack_mutex_);

    uint64_t stack_base = THREAD_STACK_BASE + (next_stack_index_ * THREAD_STACK_SIZE);
    next_stack_index_++;

    // Allocate stack using MemoryManager
    if (!memory_.map(stack_base, THREAD_STACK_SIZE,
                     MEM_READ | MEM_WRITE, "ThreadStack")) {
        EMU_LOG << "[THREAD] Failed to allocate stack at 0x" << std::hex
                  << stack_base << std::dec << std::endl;
        return 0;
    }

    return stack_base + THREAD_STACK_SIZE - 0x100;  // Return top of stack minus some space
}

// Allocate TLS for a new thread
uint64_t ThreadManager::allocate_thread_tls() {
    std::lock_guard<std::mutex> lock(tls_mutex_);

    uint64_t tls_base = THREAD_TLS_BASE + (next_tls_index_ * THREAD_TLS_SIZE);
    next_tls_index_++;

    // Allocate TLS using MemoryManager
    if (!memory_.map(tls_base, THREAD_TLS_SIZE,
                     MEM_READ | MEM_WRITE, "ThreadTLS")) {
        EMU_LOG << "[THREAD] Failed to allocate TLS at 0x" << std::hex
                  << tls_base << std::dec << std::endl;
        return 0;
    }

    // Initialize TLS slots similar to main thread (TlsManager::initialize)
    // The TPIDR_EL0 will be set to tls_base + 8 (bionic convention)
    // So offsets from TPIDR_EL0 are: slot_offset - 8

    // Slot 0: Self pointer (at tls_base + 0)
    memory_.write(tls_base + 0, &tls_base, sizeof(tls_base));

    // Slot 2: errno location (at tls_base + 16)
    uint64_t errno_location = tls_base + 0x100;
    memory_.write(tls_base + 16, &errno_location, sizeof(errno_location));
    memory_.zero(errno_location, 4);  // Initialize errno to 0

    // Stack guard canary - use the same value as main thread for consistency
    // The compiler reads from [TPIDR_EL0 + 0x28]
    // With TPIDR_EL0 = tls_base + 8, this is tls_base + 8 + 0x28 = tls_base + 0x30
    uint64_t canary = 0xDEADBEEFCAFEBABE;
    memory_.write(tls_base + 0x30, &canary, sizeof(canary));

    // Also store at slot 5 (offset 0x28) for compatibility
    memory_.write(tls_base + 0x28, &canary, sizeof(canary));

    // Return tls_base + 8 (the value to set in TPIDR_EL0)
    return tls_base + 8;
}

// Block current thread on a resource
void ThreadManager::block_current_thread(ThreadState new_state, uint64_t resource_id) {
    std::lock_guard<std::mutex> lock(threads_mutex_);

    auto it = threads_.find(current_thread_id_);
    if (it != threads_.end()) {
        it->second->state = new_state;
        it->second->blocked_on_resource = resource_id;

        if (emu_.is_debug()) {
            EMU_LOG << "[SCHED] Thread " << current_thread_id_ << " blocked on resource 0x"
                      << std::hex << resource_id << std::dec << std::endl;
        }
    }
}

// Internal unblock - assumes threads_mutex_ is already held
void ThreadManager::unblock_thread_internal(uint64_t thread_id) {
    auto it = threads_.find(thread_id);
    if (it == threads_.end()) {
        if (emu_.is_debug()) {
            EMU_LOG << "[SCHED] unblock_thread_internal: thread " << thread_id << " not found" << std::endl;
        }
        return;
    }
    if (it->second->state != ThreadState::BLOCKED) {
        if (emu_.is_debug()) {
            EMU_LOG << "[SCHED] unblock_thread_internal: thread " << thread_id
                      << " not blocked (state=" << static_cast<int>(it->second->state) << ")" << std::endl;
        }
        return;
    }
    it->second->state = ThreadState::RUNNABLE;
    it->second->blocked_on_resource = 0;

    // Add to runnable queue
    std::lock_guard<std::mutex> sched_lock(scheduler_mutex_);
    runnable_queue_.push_back(thread_id);

    if (emu_.is_debug()) {
        EMU_LOG << "[SCHED] Thread " << thread_id << " unblocked" << std::endl;
    }
}

// Unblock a thread
void ThreadManager::unblock_thread(uint64_t thread_id) {
    std::lock_guard<std::mutex> lock(threads_mutex_);
    unblock_thread_internal(thread_id);
}

// Get thread count
size_t ThreadManager::get_thread_count() const {
    // Note: This is not thread-safe, but it's only used for quick checks
    return threads_.size();
}

// Block current thread on a futex
void ThreadManager::block_on_futex(uint64_t futex_addr) {

    // Get return address from LR
    uint64_t return_addr;
    return_addr = get_reg(emu_, UC_ARM64_REG_LR);

    {
        std::lock_guard<std::mutex> lock(threads_mutex_);
        auto it = threads_.find(current_thread_id_);
        if (it != threads_.end()) {
            ThreadContext* ctx = it->second.get();
            ctx->state = ThreadState::BLOCKED;
            ctx->blocked_on_resource = futex_addr;
            ctx->futex_wait_addr = futex_addr;
            ctx->futex_wait_return_addr = return_addr;

            if (emu_.is_debug()) {
                EMU_LOG << "[SCHED] Thread " << current_thread_id_
                          << " blocked on futex 0x" << std::hex << futex_addr
                          << std::dec << std::endl;
            }
        }
    }

    // Trigger context switch
    context_switch(SwitchReason::BLOCKING_OPERATION);
}

// Unblock a thread from futex wait
void ThreadManager::unblock_from_futex(uint64_t thread_id) {
    std::lock_guard<std::mutex> lock(threads_mutex_);

    auto it = threads_.find(thread_id);
    if (it != threads_.end() && it->second->state == ThreadState::BLOCKED) {
        ThreadContext* ctx = it->second.get();

        // Clear futex wait state
        ctx->futex_wait_addr = 0;
        ctx->futex_wait_return_addr = 0;
        ctx->blocked_on_resource = 0;
        ctx->state = ThreadState::RUNNABLE;

        // Add to runnable queue
        {
            std::lock_guard<std::mutex> sched_lock(scheduler_mutex_);
            runnable_queue_.push_back(thread_id);
        }

        if (emu_.is_debug()) {
            EMU_LOG << "[SCHED] Thread " << thread_id
                      << " unblocked from futex" << std::endl;
        }
    }
}

// Sleep current thread
void ThreadManager::sleep_current_thread(uint64_t microseconds) {
    std::lock_guard<std::mutex> lock(threads_mutex_);

    auto it = threads_.find(current_thread_id_);
    if (it != threads_.end()) {
        it->second->state = ThreadState::SLEEPING;
        it->second->sleep_until = std::chrono::steady_clock::now() +
                                  std::chrono::microseconds(microseconds);

        if (emu_.is_debug()) {
            EMU_LOG << "[SCHED] Thread " << current_thread_id_ << " sleeping for "
                      << microseconds << " us" << std::endl;
        }
    }
}

// Voluntary yield
// If set_pc_to_lr is true (default), and we're in an HLE handler, set PC to LR
// so the thread returns to the caller after the context switch.
// If set_pc_to_lr is false, don't modify PC - used by cooperative I/O functions
// that loop and need to continue after yield.
void ThreadManager::yield(bool set_pc_to_lr) {
    uint64_t pc;
    pc = get_reg(emu_, UC_ARM64_REG_PC);

    // Yield logging disabled for performance
    // EMU_LOG << "[YIELD] Thread " << current_thread_id_ << " yielding, PC=0x"
    //           << std::hex << pc << std::dec << std::endl;

    // Only set PC to LR if requested and we're in an HLE handler
    if (set_pc_to_lr) {
        // Check if we're in an HLE handler (using the flag set by hook_code)
        // This is more reliable than checking the PC because the PC may have been
        // restored to a different address after a context switch
        if (emu_.is_in_hle_handler()) {
            // Set PC to LR so we return to the caller after the context switch
            uint64_t lr;
            lr = get_reg(emu_, UC_ARM64_REG_LR);
            if (emu_.is_debug()) {
                EMU_LOG << "[YIELD] Thread " << current_thread_id_ << " in HLE handler (addr=0x"
                          << std::hex << emu_.get_current_hle_address() << "), setting PC to LR=0x"
                          << lr << std::dec << std::endl;
            }
            set_reg(emu_, UC_ARM64_REG_PC, lr);
        } else if (pc >= HLE_BASE && pc < HLE_BASE + HLE_SIZE) {
            // Fallback: check if PC is in the HLE region
            uint64_t lr;
            lr = get_reg(emu_, UC_ARM64_REG_LR);
            if (emu_.is_debug()) {
                EMU_LOG << "[YIELD] Thread " << current_thread_id_ << " in HLE region, setting PC to LR=0x"
                          << std::hex << lr << std::dec << std::endl;
            }
            set_reg(emu_, UC_ARM64_REG_PC, lr);
        }
    }

    context_switch(SwitchReason::THREAD_YIELD);
}

// Cooperative yield - yields without modifying PC, for use in cooperative I/O loops
void ThreadManager::coop_yield() {
    if (emu_.is_debug()) {
        uint64_t pc;
        pc = get_reg(emu_, UC_ARM64_REG_PC);
        EMU_LOG << "[COOP_YIELD] Thread " << current_thread_id_ << " cooperative yield, PC=0x"
                  << std::hex << pc << std::dec << std::endl;
    }
    // Don't modify PC - just yield to scheduler
    context_switch(SwitchReason::THREAD_YIELD);
}

// Block current thread on I/O and yield once
// The scheduler will poll the FD and wake us when ready
void ThreadManager::block_on_io_and_yield(int fd, short events) {
    if (emu_.is_debug()) {
        EMU_LOG << "[IO_BLOCK] Thread " << current_thread_id_
                  << " blocking on fd=" << fd
                  << " events=0x" << std::hex << events << std::dec << std::endl;
    }

    {
        std::lock_guard<std::mutex> lock(threads_mutex_);
        auto it = threads_.find(current_thread_id_);
        if (it != threads_.end()) {
            // Set thread state to IO_WAIT
            it->second->state = ThreadState::IO_WAIT;
            it->second->io_fd = fd;

            // Set io_operation based on events
            // The scheduler uses this to determine poll direction
            if (events & POLLIN) {
                it->second->io_operation = ThreadContext::IoOperation::RECVFROM;
            } else if (events & POLLOUT) {
                it->second->io_operation = ThreadContext::IoOperation::SENDTO;
            } else {
                it->second->io_operation = ThreadContext::IoOperation::RECV; // Default to read
            }

            if (emu_.is_debug()) {
                EMU_LOG << "[IO_BLOCK] Set thread " << current_thread_id_
                          << " to IO_WAIT state with fd=" << fd
                          << " operation=" << static_cast<int>(it->second->io_operation) << std::endl;
            }
        }
    }

    // Yield ONCE - scheduler will wake us when FD is ready
    // Use yield(false) to not modify PC - we want to continue from where we left off
    yield(false);

    if (emu_.is_debug()) {
        EMU_LOG << "[IO_BLOCK] Thread " << current_thread_id_
                  << " resumed after I/O wait on fd=" << fd << std::endl;
    }
}

// Start a cooperative epoll_wait operation
void ThreadManager::start_coop_epoll_wait(int epfd, uint64_t events_ptr, int maxevents, int timeout_ms) {
    if (emu_.is_debug()) {
        EMU_LOG << "[COOP_IO] start_coop_epoll_wait: acquiring lock..." << std::endl;
    }
    std::lock_guard<std::mutex> lock(threads_mutex_);
    if (emu_.is_debug()) {
        EMU_LOG << "[COOP_IO] start_coop_epoll_wait: lock acquired, getting thread " << current_thread_id_ << std::endl;
    }
    ThreadContext* ctx = get_thread_unlocked(current_thread_id_);
    if (!ctx) {
        if (emu_.is_debug()) {
            EMU_LOG << "[COOP_IO] start_coop_epoll_wait: thread not found!" << std::endl;
        }
        return;
    }

    ctx->coop_io_type = ThreadContext::CoopIoType::EPOLL_WAIT;
    ctx->coop_io_start = std::chrono::steady_clock::now();
    ctx->coop_io_timeout_ms = timeout_ms;
    ctx->coop_io_fd = epfd;
    ctx->coop_io_events_ptr = events_ptr;
    ctx->coop_io_maxevents = maxevents;

    // Save return address
    ctx->coop_io_return_addr = get_reg(emu_, UC_ARM64_REG_LR);

    if (emu_.is_debug()) {
        EMU_LOG << "[COOP_IO] Thread " << current_thread_id_ << " starting epoll_wait on fd=" << epfd
                  << " timeout=" << timeout_ms << "ms" << std::endl;
    }
}

// Check if current thread is in a cooperative I/O operation
bool ThreadManager::is_in_coop_io() const {
    std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(threads_mutex_));
    auto it = threads_.find(current_thread_id_);
    if (it == threads_.end()) return false;
    return it->second->coop_io_type != ThreadContext::CoopIoType::NONE;
}

// Get the type of cooperative I/O operation
ThreadContext::CoopIoType ThreadManager::get_coop_io_type() const {
    std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(threads_mutex_));
    auto it = threads_.find(current_thread_id_);
    if (it == threads_.end()) return ThreadContext::CoopIoType::NONE;
    return it->second->coop_io_type;
}

// Get remaining timeout for cooperative I/O operation
int ThreadManager::get_coop_io_remaining_timeout_ms() const {
    std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(threads_mutex_));
    auto it = threads_.find(current_thread_id_);
    if (it == threads_.end()) return 0;

    const ThreadContext* ctx = it->second.get();
    if (ctx->coop_io_type == ThreadContext::CoopIoType::NONE) return 0;
    if (ctx->coop_io_timeout_ms < 0) return -1;  // Infinite timeout

    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - ctx->coop_io_start).count();
    int remaining = ctx->coop_io_timeout_ms - static_cast<int>(elapsed);
    return remaining > 0 ? remaining : 0;
}

// Clear cooperative I/O state
void ThreadManager::clear_coop_io_state() {
    std::lock_guard<std::mutex> lock(threads_mutex_);
    ThreadContext* ctx = get_thread_unlocked(current_thread_id_);
    if (!ctx) return;

    if (emu_.is_debug() && ctx->coop_io_type != ThreadContext::CoopIoType::NONE) {
        EMU_LOG << "[COOP_IO] Thread " << current_thread_id_ << " clearing coop I/O state" << std::endl;
    }

    ctx->coop_io_type = ThreadContext::CoopIoType::NONE;
    ctx->coop_io_fd = -1;
    ctx->coop_io_events_ptr = 0;
    ctx->coop_io_maxevents = 0;
    ctx->coop_io_timeout_ms = 0;
    ctx->coop_io_return_addr = 0;
}

// Tier 2: Periodic preemption check
// Overload for block-level hooks - takes number of instructions executed
void ThreadManager::periodic_check(uint64_t instructions_executed) {
    instruction_count_ += instructions_executed;
    periodic_check_internal();
}

// Standard periodic check (increments by 1)
void ThreadManager::periodic_check() {
    instruction_count_++;
    periodic_check_internal();
}

// Internal implementation
void ThreadManager::periodic_check_internal() {

    // DEBUG: Log which threads are running during critical period
    static bool logged_4099_created = false;
    if (!logged_4099_created) {
        std::lock_guard<std::mutex> lock(threads_mutex_);
        if (threads_.find(4099) != threads_.end()) {
            logged_4099_created = true;
            EMU_LOG << "[DEBUG] Thread 4099 exists in threads map, current_thread=" << current_thread_id_ << std::endl;
        }
    }

    // GRACE PERIOD: Decrement grace period counter if active
    // This prevents context switches for N instructions after thread restore
    ThreadContext* current = get_thread(current_thread_id_);

    // IMMEDIATE PREEMPTION FIX: Clear block_next_switch flag
    // If we're here, the thread has executed at least ONE instruction, so it's safe to allow context switches
    if (current && current->block_next_switch) {
        current->block_next_switch = false;
    }

    if (current && current->grace_period_remaining > 0) {
        current->grace_period_remaining--;

        // THREAD INITIALIZATION: Mark thread as initialized after grace period completes
        if (current->grace_period_remaining == 0 && !current->initialized) {
            current->initialized = true;
        }

        // Skip all context switch checks during grace period
        return;
    }

    // Only check periodically
    uint64_t check_interval = emergency_mode_ ? emergency_check_interval_ : periodic_check_interval_;
    if (instruction_count_ < check_interval) {
        return;
    }

    instruction_count_ = 0;

    auto now = std::chrono::steady_clock::now();
    auto runtime = now - last_periodic_check_;
    last_periodic_check_ = now;

    // Get current thread (we already checked it above, but keeping for clarity)
    if (!current) return;

    auto thread_runtime = now - current->last_scheduled;

    // Time-based preemption (100ms time slice in both normal and emergency modes)
    // Note: We increased this from 20ms to 100ms because OpenSSL code is very sensitive
    // to preemption and can have memory corruption if preempted at the wrong time.
    auto max_runtime = std::chrono::milliseconds(100);

    if (thread_runtime > max_runtime) {
        context_switch(SwitchReason::PERIODIC_PREEMPTION);
        return;
    }

    // Also check if other threads are waiting
    // Balance between letting threads make progress (50ms) and not starving network threads
    if (has_runnable_threads() && thread_runtime > std::chrono::milliseconds(50)) {
        context_switch(SwitchReason::PERIODIC_PREEMPTION);
    }
}

// Tier 3: Watchdog thread function
void ThreadManager::watchdog_thread_func() {
    // Track periodic preemption rate to detect pathological spinning
    int preemption_count_last_check = 0;

    while (watchdog_running_) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        ThreadContext* current = get_thread(current_thread_id_);
        if (!current) continue;

        // Count total periodic preemptions across all threads
        int total_periodic_preemptions = 0;
        {
            std::lock_guard<std::mutex> lock(threads_mutex_);
            for (const auto& pair : threads_) {
                total_periodic_preemptions += pair.second->periodic_switches;
            }
        }

        // Calculate preemption rate (preemptions per 100ms)
        int preemptions_this_period = total_periodic_preemptions - preemption_count_last_check;
        preemption_count_last_check = total_periodic_preemptions;

        // Debug: Always log preemption rate during tests
        if (emu_.is_debug() && preemptions_this_period > 0) {
            EMU_LOG << "[WATCHDOG] Preemption rate: " << preemptions_this_period
                      << " in 100ms, emergency_mode=" << (emergency_mode_ ? "true" : "false") << std::endl;
        }

        // Emergency threshold: >=5 periodic preemptions in 100ms indicates pathological spinning
        // This means threads are constantly hitting their time slices without blocking
        if (preemptions_this_period >= 5) {
            if (!emergency_mode_) {
                if (emu_.is_debug()) {
                    EMU_LOG << "[SCHED] Tier 3: High preemption rate (" << preemptions_this_period
                              << " in 100ms), enabling emergency mode" << std::endl;
                }
                enable_emergency_mode();
            }
        } else if (emergency_mode_ && preemptions_this_period < 3) {
            // Normal behavior restored - low preemption rate
            if (emu_.is_debug()) {
                EMU_LOG << "[SCHED] Tier 3: Normal behavior restored, disabling emergency mode" << std::endl;
            }
            disable_emergency_mode();
        }
    }
}

// Enable emergency mode (Tier 3)
void ThreadManager::enable_emergency_mode() {
    emergency_mode_ = true;
    // Reduce periodic check interval for more aggressive preemption
    // The periodic_check() function will use emergency_check_interval_
}

// Disable emergency mode
void ThreadManager::disable_emergency_mode() {
    emergency_mode_ = false;
    // Return to normal periodic check interval
}

int ThreadManager::pthread_create(uint64_t thread_ptr, uint64_t attr,
                                   uint64_t start_routine, uint64_t arg) {
    (void)attr;

    EMU_LOG << "[THREAD_MGR] pthread_create called" << std::endl;

    uint64_t thread_id = allocate_thread_id();

    auto ctx = std::make_unique<ThreadContext>();
    ctx->thread_id = thread_id;
    ctx->start_routine = start_routine;
    ctx->arg = arg;
    ctx->state = ThreadState::RUNNABLE;  // Start as runnable
    ctx->detached = false;
    ctx->grace_period_remaining = 100;  // Start with grace period to allow initialization

    // DEBUG: Confirm grace period was set
    EMU_LOG << "[THREAD_CREATE] Thread " << thread_id << " created with grace_period="
              << ctx->grace_period_remaining << std::endl;

    // Allocate stack and TLS for this thread
    ctx->stack_base = allocate_thread_stack();
    ctx->stack_size = THREAD_STACK_SIZE;
    ctx->tls_base = allocate_thread_tls();

    // Initialize register state for new thread
    // First, zero all general purpose registers
    memset(ctx->registers.x, 0, sizeof(ctx->registers.x));

    ctx->registers.sp = ctx->stack_base;
    ctx->registers.pc = start_routine;
    ctx->registers.x[0] = arg;  // First argument in X0
    ctx->registers.tpidr_el0 = ctx->tls_base;
    ctx->registers.x[18] = ctx->tls_base;  // X18 is the platform register, same as TPIDR_EL0 on Android
    ctx->registers.lr = HLE_BASE + 0xFFFF0;  // Thread exit address
    ctx->registers.x[30] = HLE_BASE + 0xFFFF0;  // X30 is LR, must match
    ctx->registers.nzcv = 0;  // Initialize condition flags to 0
    // Initialize NEON/SIMD registers to zero
    memset(ctx->registers.v, 0, sizeof(ctx->registers.v));
    ctx->registers.fpcr = 0;
    ctx->registers.fpsr = 0;

    // Debug: Log the initial register state for new threads
    EMU_LOG << "[THREAD] Thread " << thread_id << " initial state:" << std::endl;
    EMU_LOG << "  X0=0x" << std::hex << ctx->registers.x[0]
              << " X18=0x" << ctx->registers.x[18]
              << " X30=0x" << ctx->registers.x[30]
              << " SP=0x" << ctx->registers.sp
              << " PC=0x" << ctx->registers.pc
              << std::dec << std::endl;
    // Check the value at arg+120 (this is what x20 will be loaded from)
    uint64_t arg_plus_120 = 0;
    if (arg != 0) {
        emu_.mem_read(arg + 120, &arg_plus_120, sizeof(arg_plus_120));
        EMU_LOG << "  arg+120 (x20 source) = 0x" << std::hex << arg_plus_120 << std::dec << std::endl;
    }

    // Don't set last_scheduled here - it will be set when the thread is actually scheduled
    // ctx->last_scheduled = std::chrono::steady_clock::now();
    ctx->last_switch = std::chrono::steady_clock::now();

    // Write thread ID to the thread pointer
    if (thread_ptr != 0 && thread_ptr != 0xFFFFFFFFFFFFFFFFULL && thread_ptr < 0xFFFF000000000000ULL) {
        emu_.mem_write(thread_ptr, &thread_id, sizeof(thread_id));
    }

    // Always log TLS info for debugging stack check issues
    EMU_LOG << "[THREAD] pthread_create: thread_id=" << thread_id
              << " routine=0x" << std::hex << start_routine
              << " arg=0x" << arg
              << " tls_base=0x" << ctx->tls_base
              << " tpidr_el0=0x" << ctx->registers.tpidr_el0
              << std::dec << std::endl;

    // Find which module the routine belongs to (locked accessor: safe against a
    // concurrent runtime dlopen mutating modules_ on another vCPU).
    std::string routine_module = emu_.module_name_containing(start_routine);
    if (!routine_module.empty()) {
        EMU_LOG << "[THREAD] pthread_create: routine is in module '" << routine_module
                  << "'" << std::endl;
    }

    // Add to threads and runnable queue
    {
        std::lock_guard<std::mutex> lock(threads_mutex_);
        threads_[thread_id] = std::move(ctx);
    }

    {
        std::lock_guard<std::mutex> lock(scheduler_mutex_);
        // PRIORITY FIX: Add newly created threads to the FRONT of the runnable queue
        // This ensures they get CPU time immediately to initialize, which is critical
        // for time-sensitive guest library initialization sequences. Some guest libraries
        // create background threads that must signal ready within a short timeout, or the
        // main thread fails.
        runnable_queue_.push_front(thread_id);
        EMU_LOG << "[THREAD] New thread " << thread_id << " added to FRONT of runnable queue for priority initialization" << std::endl;
    }

    // Return immediately - matches real pthread_create behavior.
    // The new thread runs on its own host thread (via QEMU MTTCG).
    EMU_LOG << "[THREAD] pthread_create returning immediately (no deadlock wait)" << std::endl;

    return 0;  // Success
}

int ThreadManager::pthread_join(uint64_t thread_id, uint64_t* retval) {
    // Check if thread exists and get its state
    {
        std::lock_guard<std::mutex> lock(threads_mutex_);
        auto it = threads_.find(thread_id);
        if (it == threads_.end()) {
            return ESRCH;  // No such thread
        }

        if (it->second->detached) {
            return EINVAL;  // Thread is detached
        }

        // Check if thread has already terminated
        if (it->second->state == ThreadState::TERMINATED) {
            if (retval) {
                *retval = it->second->return_value;
            }

            // Remove thread from map
            threads_.erase(thread_id);
            return 0;
        }

        // Thread still running, add current thread to join wait queue
        it->second->join_wait_queue.push_back(current_thread_id_);

        if (emu_.is_debug()) {
            EMU_LOG << "[THREAD] Thread " << current_thread_id_
                      << " waiting to join thread " << thread_id << std::endl;
        }

        // Save join information for resume
        auto current_it = threads_.find(current_thread_id_);
        if (current_it != threads_.end()) {
            current_it->second->join_target_thread = thread_id;

            // Save the guest address (X1 register) directly, not the host pointer
            uint64_t guest_retval_ptr;
            guest_retval_ptr = get_reg(emu_, UC_ARM64_REG_X1);
            current_it->second->join_retval_ptr = guest_retval_ptr;

            // Save the current LR (return address)
            current_it->second->join_return_addr = get_reg(emu_, UC_ARM64_REG_LR);

            // Set PC to the resume function
            // When the thread is rescheduled, it will execute the resume function
            uint64_t resume_addr = HLE_BASE + 0xFFFF8;
            current_it->second->registers.pc = resume_addr;
        }
    }

    // Block current thread until target thread terminates
    // Use thread_id as the resource ID
    block_current_thread(ThreadState::BLOCKED, thread_id);

    // Tier 1: Blocking operation (natural blocking point)
    context_switch(SwitchReason::BLOCKING_OPERATION);

    // NOTE: After context_switch returns, we are now running a DIFFERENT thread!
    // The HLE handler should NOT modify any registers after receiving this value.
    return CONTEXT_SWITCH_OCCURRED;
}

void ThreadManager::pthread_join_resume() {
    // This function is called when a thread is woken up from pthread_join
    // It retrieves the return value and cleans up the terminated thread

    uint64_t thread_id;
    uint64_t retval_ptr;
    uint64_t return_addr;
    uint64_t retval = 0;

    {
        std::lock_guard<std::mutex> lock(threads_mutex_);
        auto current_it = threads_.find(current_thread_id_);
        if (current_it == threads_.end()) {
            return;
        }

        thread_id = current_it->second->join_target_thread;
        retval_ptr = current_it->second->join_retval_ptr;
        return_addr = current_it->second->join_return_addr;

        // Clear the saved values
        current_it->second->join_target_thread = 0;
        current_it->second->join_retval_ptr = 0;
        current_it->second->join_return_addr = 0;

        // Get the return value from the terminated thread
        auto it = threads_.find(thread_id);
        if (it != threads_.end() && it->second->state == ThreadState::TERMINATED) {
            retval = it->second->return_value;

            // Remove thread from map
            threads_.erase(thread_id);
        }
    }

    // Write return value if requested
    if (retval_ptr != 0) {
        emu_.mem_write(retval_ptr, &retval, sizeof(retval));
    }

    // Set LR to the saved return address so we return to the original caller
    set_reg(emu_, UC_ARM64_REG_LR, return_addr);

    // Set X0 to 0 (success)
    uint64_t zero = 0;
    set_reg(emu_, UC_ARM64_REG_X0, zero);
}

int ThreadManager::pthread_join_nonblocking(uint64_t thread_id, uint64_t* retval, int timeout_ms) {
    if (emu_.is_debug()) {
        EMU_LOG << "[THREAD] pthread_join_nonblocking: thread=" << thread_id
                  << " timeout=" << timeout_ms << "ms" << std::endl;
    }

    ThreadContext* ctx = nullptr;

    {
        std::lock_guard<std::mutex> lock(threads_mutex_);
        auto it = threads_.find(thread_id);
        if (it == threads_.end()) {
            return ESRCH;  // No such thread
        }
        ctx = it->second.get();

        if (ctx->detached) {
            return EINVAL;  // Thread is detached
        }
    }

    // Check if thread is already terminated
    if (ctx->state == ThreadState::TERMINATED) {
        if (retval) {
            *retval = ctx->return_value;
        }

        // Remove thread from map
        {
            std::lock_guard<std::mutex> lock(threads_mutex_);
            threads_.erase(thread_id);
        }

        return 0;
    }

    if (emu_.is_debug()) {
        EMU_LOG << "[THREAD] pthread_join_nonblocking: waiting for thread to complete..." << std::endl;
    }

    // Wait for a short time to see if the thread completes
    auto start = std::chrono::steady_clock::now();
    while (ctx->state != ThreadState::TERMINATED) {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - start).count();
        if (elapsed >= timeout_ms) {
            // Thread didn't complete in time, detach it and return success
            // This is a workaround for threads that spin forever
            if (emu_.is_debug()) {
                EMU_LOG << "[THREAD] pthread_join_nonblocking: thread " << thread_id
                          << " didn't complete in " << timeout_ms << "ms, detaching" << std::endl;
            }

            // Detach the thread so it can be cleaned up later
            ctx->detached = true;

            if (retval) {
                *retval = 0;
            }

            return 0;  // Return success even though we didn't really join
        }

        // Yield to scheduler
        yield();
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    // Thread completed
    if (retval) {
        *retval = ctx->return_value;
    }

    // Remove thread from map
    {
        std::lock_guard<std::mutex> lock(threads_mutex_);
        threads_.erase(thread_id);
    }

    return 0;
}

int ThreadManager::pthread_detach(uint64_t thread_id) {
    std::lock_guard<std::mutex> lock(threads_mutex_);
    
    auto it = threads_.find(thread_id);
    if (it == threads_.end()) {
        return ESRCH;
    }
    
    it->second->detached = true;

    // If thread is already terminated, clean it up
    if (it->second->state == ThreadState::TERMINATED) {
        threads_.erase(it);
    }

    return 0;
}

uint64_t ThreadManager::pthread_self() {
    return current_thread_id_;
}

void ThreadManager::pthread_exit(uint64_t retval) {
    // Collect threads to wake up before releasing lock
    std::vector<uint64_t> threads_to_wake;

    {
        std::lock_guard<std::mutex> lock(threads_mutex_);
        auto it = threads_.find(current_thread_id_);
        if (it != threads_.end()) {
            it->second->return_value = retval;
            it->second->state = ThreadState::TERMINATED;

            // Collect threads waiting to join this thread
            threads_to_wake = std::vector<uint64_t>(it->second->join_wait_queue.begin(),
                                                     it->second->join_wait_queue.end());
            it->second->join_wait_queue.clear();
        }
    }

    // Wake up waiting threads (outside the lock to avoid deadlock)
    for (uint64_t waiting_thread_id : threads_to_wake) {
        if (emu_.is_debug()) {
            EMU_LOG << "[THREAD] Thread " << current_thread_id_
                      << " terminating, waking up thread " << waiting_thread_id << std::endl;
        }
        unblock_thread(waiting_thread_id);
    }

    // Context switch to another thread
    context_switch(SwitchReason::THREAD_EXIT);

    // pthread_exit should NEVER return!
    // If we get here, the thread is TERMINATED but context_switch returned to it
    // This can happen if there are no other runnable threads
    // With async emulator mode, we just return and let the emulator continue
    // until it hits the return address, which will complete the function call
    // The emulator thread will then wait for the next request
    EMU_LOG << "[THREAD] pthread_exit returned (no runnable threads). Thread "
              << current_thread_id_ << " exiting." << std::endl;
}

// Mutex operations
int ThreadManager::pthread_mutex_init(uint64_t mutex_ptr, uint64_t attr) {
    auto mutex = std::make_unique<EmulatedMutex>();

    // Read mutex type from attr if provided
    // Our HLE pthread_mutexattr_settype stores the type at offset 4 in the attr structure
    // PTHREAD_MUTEX_NORMAL = 0, PTHREAD_MUTEX_RECURSIVE = 1, PTHREAD_MUTEX_ERRORCHECK = 2
    if (attr != 0) {
        int type = 0;
        // Read type from offset 4 where pthread_mutexattr_settype stores it
        emu_.mem_read(attr + 4, &type, sizeof(type));
        mutex->type = type;
        if (emu_.is_debug()) {
            EMU_LOG << "[MUTEX] init: mutex 0x" << std::hex << mutex_ptr
                      << " attr=0x" << attr << " type=" << std::dec << type << std::endl;
        }
    } else {
        if (emu_.is_debug()) {
            EMU_LOG << "[MUTEX] init: mutex 0x" << std::hex << mutex_ptr
                      << " attr=NULL type=0 (normal)" << std::dec << std::endl;
        }
    }

    std::lock_guard<std::mutex> lock(threads_mutex_);
    mutexes_[mutex_ptr] = std::move(mutex);

    return 0;
}

int ThreadManager::pthread_mutex_destroy(uint64_t mutex_ptr) {
    std::lock_guard<std::mutex> lock(threads_mutex_);
    mutexes_.erase(mutex_ptr);
    return 0;
}

int ThreadManager::pthread_mutex_lock(uint64_t mutex_ptr) {
    EmulatedMutex* mutex = nullptr;
    {
        std::lock_guard<std::mutex> lock(threads_mutex_);
        auto it = mutexes_.find(mutex_ptr);
        if (it == mutexes_.end()) {
            // Auto-initialize mutex - read type from bionic static initializer
            // Bionic encodes mutex type in bits 14-15 of the first word:
            // PTHREAD_MUTEX_NORMAL = 0, PTHREAD_MUTEX_RECURSIVE = 1, PTHREAD_MUTEX_ERRORCHECK = 2
            auto new_mutex = std::make_unique<EmulatedMutex>();
            uint32_t mutex_state = 0;
            emu_.mem_read(mutex_ptr, &mutex_state, sizeof(mutex_state));
            int mutex_type = (mutex_state >> 14) & 0x3;
            new_mutex->type = mutex_type;
            if (emu_.is_debug()) {
                EMU_LOG << "[MUTEX] auto-init: mutex 0x" << std::hex << mutex_ptr
                          << " state=0x" << mutex_state << " type=" << std::dec << mutex_type << std::endl;
            }
            mutex = new_mutex.get();
            mutexes_[mutex_ptr] = std::move(new_mutex);
        } else {
            mutex = it->second.get();
        }

        // Handle recursive mutex
        // NOTE: We allow recursive locking for ALL mutex types as a workaround for guest
        // libraries that incorrectly use non-recursive mutexes recursively. This is
        // technically incorrect behavior for PTHREAD_MUTEX_NORMAL, but it's necessary for
        // compatibility with such libraries.

        // Get PC for debugging
        uint64_t pc = 0;
        pc = get_reg(emu_, UC_ARM64_REG_PC);

        // Handle recursive mutex
        if (mutex->is_locked && mutex->lock_count > 0) {
            if (mutex->owner_thread == current_thread_id_) {
                mutex->lock_count++;
                if (emu_.is_debug()) {
                    EMU_LOG << "[MUTEX] recursive lock on mutex 0x"
                              << std::hex << mutex_ptr << std::dec
                              << " lock_count=" << mutex->lock_count << std::endl;
                }
                return 0;
            }
        }

        // Try to acquire mutex
        if (!mutex->is_locked) {
            mutex->is_locked = true;
            mutex->owner_thread = current_thread_id_;
            mutex->lock_count = 1;
            if (emu_.is_debug()) {
                EMU_LOG << "[MUTEX] lock: acquired mutex 0x" << std::hex << mutex_ptr
                          << " by thread " << std::dec << current_thread_id_ << std::endl;
            }
            return 0;
        }

        // Mutex is locked by another thread, will block
        if (emu_.is_debug()) {
            EMU_LOG << "[MUTEX] lock: mutex 0x" << std::hex << mutex_ptr
                      << " owned by thread " << std::dec << mutex->owner_thread
                      << " current_thread=" << current_thread_id_
                      << " - will block" << std::endl;
        }

        // Mutex is locked, add to wait queue
        if (std::find(mutex->wait_queue.begin(), mutex->wait_queue.end(), current_thread_id_)
            == mutex->wait_queue.end()) {
            mutex->wait_queue.push_back(current_thread_id_);
        }

        // Save mutex_ptr for resume
        auto current_it = threads_.find(current_thread_id_);
        if (current_it != threads_.end()) {
            current_it->second->mutex_wait_ptr = mutex_ptr;

            // Save the current LR (return address)
            current_it->second->mutex_wait_return_addr = get_reg(emu_, UC_ARM64_REG_LR);

            // Set PC to the resume function
            // When the thread is rescheduled, it will execute the resume function
            uint64_t resume_addr = HLE_BASE + 0xFFFEC;  // New resume address for mutex
            current_it->second->registers.pc = resume_addr;
        }
    }

    // Tier 1: Block on mutex (natural blocking point)
    block_current_thread(ThreadState::BLOCKED, mutex_ptr);
    context_switch(SwitchReason::BLOCKING_OPERATION);

    // NOTE: After context_switch returns, we are now running a DIFFERENT thread!
    // The HLE handler should NOT modify any registers after receiving this value.
    return CONTEXT_SWITCH_OCCURRED;
}

void ThreadManager::pthread_mutex_lock_resume() {
    // This function is called when a thread is woken up from pthread_mutex_lock
    // It tries to acquire the mutex and returns to the original caller

    uint64_t mutex_ptr;
    uint64_t return_addr;

    {
        std::lock_guard<std::mutex> lock(threads_mutex_);
        auto current_it = threads_.find(current_thread_id_);
        if (current_it == threads_.end()) {
            return;
        }

        mutex_ptr = current_it->second->mutex_wait_ptr;
        return_addr = current_it->second->mutex_wait_return_addr;

        // Clear the saved values
        current_it->second->mutex_wait_ptr = 0;
        current_it->second->mutex_wait_return_addr = 0;
    }

    if (emu_.is_debug()) {
        EMU_LOG << "[MUTEX] resume: thread " << current_thread_id_
                  << " trying to acquire mutex 0x" << std::hex << mutex_ptr << std::dec << std::endl;
    }

    // Try to acquire the mutex (this should succeed since we were woken up)
    // Use a loop in case of spurious wakeups
    while (true) {
        EmulatedMutex* mutex = nullptr;
        {
            std::lock_guard<std::mutex> lock(threads_mutex_);
            auto it = mutexes_.find(mutex_ptr);
            if (it == mutexes_.end()) {
                if (emu_.is_debug()) {
                    EMU_LOG << "[MUTEX] resume: mutex 0x" << std::hex << mutex_ptr << std::dec << " was destroyed" << std::endl;
                }
                break;  // Mutex was destroyed
            }
            mutex = it->second.get();

            // Try to acquire mutex
            if (!mutex->is_locked) {
                mutex->is_locked = true;
                mutex->owner_thread = current_thread_id_;
                mutex->lock_count = 1;
                if (emu_.is_debug()) {
                    EMU_LOG << "[MUTEX] resume: thread " << current_thread_id_
                              << " acquired mutex 0x" << std::hex << mutex_ptr << std::dec << std::endl;
                }
                break;  // Success
            }

            if (emu_.is_debug()) {
                EMU_LOG << "[MUTEX] resume: mutex 0x" << std::hex << mutex_ptr << std::dec
                          << " still locked by thread " << mutex->owner_thread
                          << ", blocking again" << std::endl;
            }

            // Mutex is still locked, add back to wait queue and block again
            if (std::find(mutex->wait_queue.begin(), mutex->wait_queue.end(), current_thread_id_)
                == mutex->wait_queue.end()) {
                mutex->wait_queue.push_back(current_thread_id_);
            }

            // Save mutex_ptr for next resume
            auto current_it = threads_.find(current_thread_id_);
            if (current_it != threads_.end()) {
                current_it->second->mutex_wait_ptr = mutex_ptr;
                current_it->second->mutex_wait_return_addr = return_addr;
                current_it->second->registers.pc = HLE_BASE + 0xFFFEC;
            }
        }

        // Block and wait again
        block_current_thread(ThreadState::BLOCKED, mutex_ptr);
        context_switch(SwitchReason::BLOCKING_OPERATION);
        return;  // Context switch occurred, don't continue
    }

    // Set LR to the saved return address so we return to the original caller
    set_reg(emu_, UC_ARM64_REG_LR, return_addr);

    // Set X0 to 0 (success)
    uint64_t result = 0;
    set_reg(emu_, UC_ARM64_REG_X0, result);
}

int ThreadManager::pthread_mutex_trylock(uint64_t mutex_ptr) {
    EmulatedMutex* mutex = nullptr;
    {
        std::lock_guard<std::mutex> lock(threads_mutex_);
        auto it = mutexes_.find(mutex_ptr);
        if (it == mutexes_.end()) {
            auto new_mutex = std::make_unique<EmulatedMutex>();
            mutex = new_mutex.get();
            mutexes_[mutex_ptr] = std::move(new_mutex);
        } else {
            mutex = it->second.get();
        }

        // Check if already locked by this thread (recursive mutex)
        if (mutex->owner_thread == current_thread_id_ && mutex->lock_count > 0) {
            if (mutex->type == 1) {  // PTHREAD_MUTEX_RECURSIVE
                mutex->lock_count++;
                return 0;
            }
            return EBUSY;
        }

        // Try to acquire mutex
        if (!mutex->is_locked) {
            mutex->is_locked = true;
            mutex->owner_thread = current_thread_id_;
            mutex->lock_count = 1;
            return 0;
        }
    }

    return EBUSY;
}

int ThreadManager::pthread_mutex_unlock(uint64_t mutex_ptr) {
    std::lock_guard<std::mutex> lock(threads_mutex_);
    auto it = mutexes_.find(mutex_ptr);
    if (it == mutexes_.end()) {
        if (emu_.is_debug()) {
            EMU_LOG << "[MUTEX] unlock: mutex 0x" << std::hex << mutex_ptr << std::dec << " not found" << std::endl;
        }
        return EINVAL;
    }

    EmulatedMutex* mutex = it->second.get();

    // Check if mutex is actually locked
    if (!mutex->is_locked || mutex->lock_count <= 0) {
        if (emu_.is_debug()) {
            EMU_LOG << "[MUTEX] unlock: mutex 0x" << std::hex << mutex_ptr << std::dec
                      << " not locked (is_locked=" << mutex->is_locked
                      << " lock_count=" << mutex->lock_count << "), returning EPERM" << std::endl;
        }
        return EPERM;  // Mutex not locked
    }

    mutex->lock_count--;
    if (emu_.is_debug()) {
        EMU_LOG << "[MUTEX] unlock: mutex 0x" << std::hex << mutex_ptr << std::dec
                  << " lock_count=" << mutex->lock_count
                  << " wait_queue_size=" << mutex->wait_queue.size() << std::endl;
    }
    if (mutex->lock_count == 0) {
        mutex->is_locked = false;
        mutex->owner_thread = 0;

        // Wake up first waiting thread
        if (!mutex->wait_queue.empty()) {
            uint64_t waiting_thread = mutex->wait_queue.front();
            mutex->wait_queue.pop_front();
            if (emu_.is_debug()) {
                EMU_LOG << "[MUTEX] unlock: waking thread " << waiting_thread << " from mutex 0x" << std::hex << mutex_ptr << std::dec << std::endl;
            }
            unblock_thread_internal(waiting_thread);  // Use internal version - we already hold the lock
        }
    }

    return 0;
}

// Condition variable operations
int ThreadManager::pthread_cond_init(uint64_t cond_ptr, uint64_t attr) {
    (void)attr;
    std::lock_guard<std::mutex> lock(threads_mutex_);
    condvars_[cond_ptr] = std::make_unique<EmulatedCondVar>();
    return 0;
}

int ThreadManager::pthread_cond_destroy(uint64_t cond_ptr) {
    std::lock_guard<std::mutex> lock(threads_mutex_);
    condvars_.erase(cond_ptr);
    return 0;
}

int ThreadManager::pthread_cond_wait(uint64_t cond_ptr, uint64_t mutex_ptr) {
    // Always log condvar wait for debugging
    EMU_LOG << "[CONDVAR:T" << current_thread_id_ << "] wait: cond=0x" << std::hex << cond_ptr
              << " mutex=0x" << mutex_ptr << std::dec << std::endl;

    // Add to condvar wait queue and release mutex
    {
        std::lock_guard<std::mutex> lock(threads_mutex_);

        auto cond_it = condvars_.find(cond_ptr);
        if (cond_it == condvars_.end()) {
            condvars_[cond_ptr] = std::make_unique<EmulatedCondVar>();
            cond_it = condvars_.find(cond_ptr);
        }
        EmulatedCondVar* cond = cond_it->second.get();

        // Add to wait queue
        cond->wait_queue.push_back(current_thread_id_);

        // Save mutex address and return address for resume
        auto it = threads_.find(current_thread_id_);
        if (it != threads_.end()) {
            it->second->cond_wait_mutex = mutex_ptr;

            // Save the current LR (return address)
            it->second->cond_wait_return_addr = get_reg(emu_, UC_ARM64_REG_LR);

            // Set PC to the resume function
            // When the thread is rescheduled, it will execute the resume function
            uint64_t resume_addr = HLE_BASE + 0xFFFF4;
            it->second->registers.pc = resume_addr;
        }
    }

    // Release mutex
    pthread_mutex_unlock(mutex_ptr);

    // Tier 1: Block on condvar (natural blocking point)
    block_current_thread(ThreadState::BLOCKED, cond_ptr);
    context_switch(SwitchReason::BLOCKING_OPERATION);

    // NOTE: After context_switch returns, we are now running a DIFFERENT thread!
    // The HLE handler should NOT modify any registers after receiving this value.
    return CONTEXT_SWITCH_OCCURRED;
}

void ThreadManager::pthread_cond_wait_resume() {
    // This function is called when a thread is woken up from pthread_cond_wait
    // It reacquires the mutex and returns to the original caller

    uint64_t mutex_ptr;
    uint64_t return_addr;

    {
        std::lock_guard<std::mutex> lock(threads_mutex_);
        auto it = threads_.find(current_thread_id_);
        if (it == threads_.end()) {
            return;
        }

        mutex_ptr = it->second->cond_wait_mutex;
        return_addr = it->second->cond_wait_return_addr;

        // Clear the saved values
        it->second->cond_wait_mutex = 0;
        it->second->cond_wait_return_addr = 0;
    }

    // Reacquire the mutex - this may block if the mutex is contended
    int result = pthread_mutex_lock(mutex_ptr);
    if (result == CONTEXT_SWITCH_OCCURRED) {
        // Context switch occurred, we're now blocked on the mutex
        // The mutex_wait_return_addr should be set to our return_addr
        // so that when we resume from the mutex, we return to the original caller
        std::lock_guard<std::mutex> lock(threads_mutex_);
        auto it = threads_.find(current_thread_id_);
        if (it != threads_.end()) {
            it->second->mutex_wait_return_addr = return_addr;
        }
        return;
    }

    // Set LR to the saved return address so we return to the original caller
    set_reg(emu_, UC_ARM64_REG_LR, return_addr);

    // Set X0 to 0 (success)
    uint64_t zero = 0;
    set_reg(emu_, UC_ARM64_REG_X0, zero);
}

int ThreadManager::pthread_cond_timedwait(uint64_t cond_ptr, uint64_t mutex_ptr,
                                           uint64_t abstime_ptr) {
    // Read timespec from emulator memory
    int64_t tv_sec = 0, tv_nsec = 0;
    emu_.mem_read(abstime_ptr, &tv_sec, sizeof(tv_sec));
    emu_.mem_read(abstime_ptr + 8, &tv_nsec, sizeof(tv_nsec));

    auto timeout = std::chrono::system_clock::time_point(
        std::chrono::seconds(tv_sec) + std::chrono::nanoseconds(tv_nsec));

    // Add to condvar wait queue and release mutex
    {
        std::lock_guard<std::mutex> lock(threads_mutex_);

        auto cond_it = condvars_.find(cond_ptr);
        if (cond_it == condvars_.end()) {
            condvars_[cond_ptr] = std::make_unique<EmulatedCondVar>();
            cond_it = condvars_.find(cond_ptr);
        }
        EmulatedCondVar* cond = cond_it->second.get();

        // Add to wait queue
        cond->wait_queue.push_back(current_thread_id_);
    }

    // Release mutex
    pthread_mutex_unlock(mutex_ptr);

    // Block with timeout
    auto current = get_thread(current_thread_id_);
    if (current) {
        current->state = ThreadState::SLEEPING;
        current->sleep_until = std::chrono::steady_clock::time_point(
            std::chrono::duration_cast<std::chrono::steady_clock::duration>(
                timeout.time_since_epoch()));
    }

    context_switch(SwitchReason::BLOCKING_OPERATION);

    // Check if we timed out
    bool timed_out = false;
    {
        std::lock_guard<std::mutex> lock(threads_mutex_);
        auto cond_it = condvars_.find(cond_ptr);
        if (cond_it != condvars_.end()) {
            auto& wait_queue = cond_it->second->wait_queue;
            auto it = std::find(wait_queue.begin(), wait_queue.end(), current_thread_id_);
            if (it != wait_queue.end()) {
                // Still in wait queue, must have timed out
                wait_queue.erase(it);
                timed_out = true;
            }
        }
    }

    // Reacquire mutex
    pthread_mutex_lock(mutex_ptr);

    return timed_out ? ETIMEDOUT : 0;
}

int ThreadManager::pthread_cond_signal(uint64_t cond_ptr) {
    std::lock_guard<std::mutex> lock(threads_mutex_);
    auto it = condvars_.find(cond_ptr);
    if (it != condvars_.end() && !it->second->wait_queue.empty()) {
        uint64_t waiting_thread = it->second->wait_queue.front();
        it->second->wait_queue.pop_front();
        unblock_thread_internal(waiting_thread);  // Use internal version - we already hold the lock
    }
    return 0;
}

int ThreadManager::pthread_cond_broadcast(uint64_t cond_ptr) {
    std::lock_guard<std::mutex> lock(threads_mutex_);
    auto it = condvars_.find(cond_ptr);
    if (it != condvars_.end()) {
        // Wake all waiting threads
        for (uint64_t thread_id : it->second->wait_queue) {
            unblock_thread_internal(thread_id);  // Use internal version - we already hold the lock
        }
        it->second->wait_queue.clear();
    }
    return 0;
}

// Read-write lock operations (cooperative)
int ThreadManager::pthread_rwlock_init(uint64_t rwlock_ptr, uint64_t attr) {
    (void)attr;
    std::lock_guard<std::mutex> lock(threads_mutex_);
    rwlocks_[rwlock_ptr] = std::make_unique<EmulatedRWLock>();
    return 0;
}

int ThreadManager::pthread_rwlock_destroy(uint64_t rwlock_ptr) {
    std::lock_guard<std::mutex> lock(threads_mutex_);
    rwlocks_.erase(rwlock_ptr);
    return 0;
}

int ThreadManager::pthread_rwlock_rdlock(uint64_t rwlock_ptr) {
    {
        std::lock_guard<std::mutex> lock(threads_mutex_);
        auto it = rwlocks_.find(rwlock_ptr);
        if (it == rwlocks_.end()) {
            rwlocks_[rwlock_ptr] = std::make_unique<EmulatedRWLock>();
            it = rwlocks_.find(rwlock_ptr);
        }

        EmulatedRWLock* rwlock = it->second.get();

        // Can acquire read lock if no writer
        if (rwlock->writer == 0) {
            rwlock->readers++;
            return 0;
        }

        // Add to read wait queue
        if (std::find(rwlock->read_wait_queue.begin(), rwlock->read_wait_queue.end(), current_thread_id_)
            == rwlock->read_wait_queue.end()) {
            rwlock->read_wait_queue.push_back(current_thread_id_);
        }

        // Save rwlock_ptr for resume
        auto current_it = threads_.find(current_thread_id_);
        if (current_it != threads_.end()) {
            current_it->second->rwlock_rdlock_ptr = rwlock_ptr;

            // Save the current LR (return address)
            current_it->second->rwlock_rdlock_return_addr = get_reg(emu_, UC_ARM64_REG_LR);

            // Set PC to the resume function
            // When the thread is rescheduled, it will execute the resume function
            uint64_t resume_addr = HLE_BASE + 0xFFFD8;  // Resume address for rwlock_rdlock
            current_it->second->registers.pc = resume_addr;
        }
    }

    // Block and wait
    block_current_thread(ThreadState::BLOCKED, rwlock_ptr);
    context_switch(SwitchReason::BLOCKING_OPERATION);

    // NOTE: After context_switch returns, we are now running a DIFFERENT thread!
    // The HLE handler should NOT modify any registers after receiving this value.
    return CONTEXT_SWITCH_OCCURRED;
}

void ThreadManager::pthread_rwlock_rdlock_resume() {
    // This function is called when a thread is woken up from pthread_rwlock_rdlock
    // It tries to acquire the read lock and returns to the original caller

    uint64_t rwlock_ptr;
    uint64_t return_addr;

    {
        std::lock_guard<std::mutex> lock(threads_mutex_);
        auto current_it = threads_.find(current_thread_id_);
        if (current_it == threads_.end()) {
            return;
        }

        rwlock_ptr = current_it->second->rwlock_rdlock_ptr;
        return_addr = current_it->second->rwlock_rdlock_return_addr;

        // Clear the saved values
        current_it->second->rwlock_rdlock_ptr = 0;
        current_it->second->rwlock_rdlock_return_addr = 0;
    }

    if (emu_.is_debug()) {
        EMU_LOG << "[RWLOCK] rdlock resume: thread " << current_thread_id_
                  << " trying to acquire rwlock 0x" << std::hex << rwlock_ptr << std::dec << std::endl;
    }

    // Try to acquire the read lock (this should succeed since we were woken up)
    // Use a loop in case of spurious wakeups
    while (true) {
        EmulatedRWLock* rwlock = nullptr;
        {
            std::lock_guard<std::mutex> lock(threads_mutex_);
            auto it = rwlocks_.find(rwlock_ptr);
            if (it == rwlocks_.end()) {
                if (emu_.is_debug()) {
                    EMU_LOG << "[RWLOCK] rdlock resume: rwlock 0x" << std::hex << rwlock_ptr << std::dec << " was destroyed" << std::endl;
                }
                break;  // RWLock was destroyed
            }
            rwlock = it->second.get();

            // Try to acquire read lock
            if (rwlock->writer == 0) {
                rwlock->readers++;
                if (emu_.is_debug()) {
                    EMU_LOG << "[RWLOCK] rdlock resume: thread " << current_thread_id_
                              << " acquired rdlock 0x" << std::hex << rwlock_ptr << std::dec << std::endl;
                }
                break;  // Success
            }

            if (emu_.is_debug()) {
                EMU_LOG << "[RWLOCK] rdlock resume: rwlock 0x" << std::hex << rwlock_ptr << std::dec
                          << " still has writer " << rwlock->writer
                          << ", blocking again" << std::endl;
            }

            // RWLock still has a writer, add back to wait queue and block again
            if (std::find(rwlock->read_wait_queue.begin(), rwlock->read_wait_queue.end(), current_thread_id_)
                == rwlock->read_wait_queue.end()) {
                rwlock->read_wait_queue.push_back(current_thread_id_);
            }

            // Save rwlock_ptr for next resume
            auto current_it = threads_.find(current_thread_id_);
            if (current_it != threads_.end()) {
                current_it->second->rwlock_rdlock_ptr = rwlock_ptr;
                current_it->second->rwlock_rdlock_return_addr = return_addr;
                current_it->second->registers.pc = HLE_BASE + 0xFFFD8;
            }
        }

        // Block and wait again
        block_current_thread(ThreadState::BLOCKED, rwlock_ptr);
        context_switch(SwitchReason::BLOCKING_OPERATION);
        return;  // Context switch occurred, don't continue
    }

    // Set LR to the saved return address so we return to the original caller
    set_reg(emu_, UC_ARM64_REG_LR, return_addr);

    // Set X0 to 0 (success)
    uint64_t result = 0;
    set_reg(emu_, UC_ARM64_REG_X0, result);
}

int ThreadManager::pthread_rwlock_tryrdlock(uint64_t rwlock_ptr) {
    std::lock_guard<std::mutex> lock(threads_mutex_);
    auto it = rwlocks_.find(rwlock_ptr);
    if (it == rwlocks_.end()) {
        rwlocks_[rwlock_ptr] = std::make_unique<EmulatedRWLock>();
        it = rwlocks_.find(rwlock_ptr);
    }

    EmulatedRWLock* rwlock = it->second.get();

    // Can acquire read lock if no writer
    if (rwlock->writer == 0) {
        rwlock->readers++;
        return 0;
    }

    // Lock is held by a writer, return EBUSY
    return EBUSY;
}

int ThreadManager::pthread_rwlock_wrlock(uint64_t rwlock_ptr) {
    {
        std::lock_guard<std::mutex> lock(threads_mutex_);
        auto it = rwlocks_.find(rwlock_ptr);
        if (it == rwlocks_.end()) {
            rwlocks_[rwlock_ptr] = std::make_unique<EmulatedRWLock>();
            it = rwlocks_.find(rwlock_ptr);
        }

        EmulatedRWLock* rwlock = it->second.get();

        // Allow recursive write lock by the same thread
        if (rwlock->writer == current_thread_id_) {
            rwlock->write_count++;
            if (emu_.is_debug()) {
                EMU_LOG << "[RWLOCK] wrlock: thread " << current_thread_id_
                          << " recursive lock on 0x" << std::hex << rwlock_ptr
                          << " count=" << std::dec << rwlock->write_count << std::endl;
            }
            return 0;
        }

        // Can acquire write lock if no readers and no writer
        if (rwlock->readers == 0 && rwlock->writer == 0) {
            rwlock->writer = current_thread_id_;
            rwlock->write_count = 1;
            return 0;
        }

        // Debug: log why we can't acquire the lock
        EMU_LOG << "[RWLOCK] wrlock: thread " << current_thread_id_
                  << " blocked on 0x" << std::hex << rwlock_ptr << std::dec
                  << " readers=" << rwlock->readers << " writer=" << rwlock->writer << std::endl;

        // Add to write wait queue
        if (std::find(rwlock->write_wait_queue.begin(), rwlock->write_wait_queue.end(), current_thread_id_)
            == rwlock->write_wait_queue.end()) {
            rwlock->write_wait_queue.push_back(current_thread_id_);
        }

        // Save rwlock_ptr for resume
        auto current_it = threads_.find(current_thread_id_);
        if (current_it != threads_.end()) {
            current_it->second->rwlock_wrlock_ptr = rwlock_ptr;

            // Save the current LR (return address)
            current_it->second->rwlock_wrlock_return_addr = get_reg(emu_, UC_ARM64_REG_LR);

            // Set PC to the resume function
            // When the thread is rescheduled, it will execute the resume function
            uint64_t resume_addr = HLE_BASE + 0xFFFD4;  // Resume address for rwlock_wrlock
            current_it->second->registers.pc = resume_addr;
        }
    }

    // Block and wait
    block_current_thread(ThreadState::BLOCKED, rwlock_ptr);
    context_switch(SwitchReason::BLOCKING_OPERATION);

    // NOTE: After context_switch returns, we are now running a DIFFERENT thread!
    // The HLE handler should NOT modify any registers after receiving this value.
    return CONTEXT_SWITCH_OCCURRED;
}

void ThreadManager::pthread_rwlock_wrlock_resume() {
    // This function is called when a thread is woken up from pthread_rwlock_wrlock
    // It tries to acquire the write lock and returns to the original caller

    uint64_t rwlock_ptr;
    uint64_t return_addr;

    {
        std::lock_guard<std::mutex> lock(threads_mutex_);
        auto current_it = threads_.find(current_thread_id_);
        if (current_it == threads_.end()) {
            return;
        }

        rwlock_ptr = current_it->second->rwlock_wrlock_ptr;
        return_addr = current_it->second->rwlock_wrlock_return_addr;

        // Clear the saved values
        current_it->second->rwlock_wrlock_ptr = 0;
        current_it->second->rwlock_wrlock_return_addr = 0;
    }

    if (emu_.is_debug()) {
        EMU_LOG << "[RWLOCK] wrlock resume: thread " << current_thread_id_
                  << " trying to acquire rwlock 0x" << std::hex << rwlock_ptr << std::dec << std::endl;
    }

    // Try to acquire the write lock (this should succeed since we were woken up)
    // Use a loop in case of spurious wakeups
    while (true) {
        EmulatedRWLock* rwlock = nullptr;
        {
            std::lock_guard<std::mutex> lock(threads_mutex_);
            auto it = rwlocks_.find(rwlock_ptr);
            if (it == rwlocks_.end()) {
                if (emu_.is_debug()) {
                    EMU_LOG << "[RWLOCK] wrlock resume: rwlock 0x" << std::hex << rwlock_ptr << std::dec << " was destroyed" << std::endl;
                }
                break;  // RWLock was destroyed
            }
            rwlock = it->second.get();

            // Try to acquire write lock
            if (rwlock->readers == 0 && rwlock->writer == 0) {
                rwlock->writer = current_thread_id_;
                if (emu_.is_debug()) {
                    EMU_LOG << "[RWLOCK] wrlock resume: thread " << current_thread_id_
                              << " acquired wrlock 0x" << std::hex << rwlock_ptr << std::dec << std::endl;
                }
                break;  // Success
            }

            if (emu_.is_debug()) {
                EMU_LOG << "[RWLOCK] wrlock resume: rwlock 0x" << std::hex << rwlock_ptr << std::dec
                          << " still has readers=" << rwlock->readers << " or writer=" << rwlock->writer
                          << ", blocking again" << std::endl;
            }

            // RWLock still has readers or writer, add back to wait queue and block again
            if (std::find(rwlock->write_wait_queue.begin(), rwlock->write_wait_queue.end(), current_thread_id_)
                == rwlock->write_wait_queue.end()) {
                rwlock->write_wait_queue.push_back(current_thread_id_);
            }

            // Save rwlock_ptr for next resume
            auto current_it = threads_.find(current_thread_id_);
            if (current_it != threads_.end()) {
                current_it->second->rwlock_wrlock_ptr = rwlock_ptr;
                current_it->second->rwlock_wrlock_return_addr = return_addr;
                current_it->second->registers.pc = HLE_BASE + 0xFFFD4;
            }
        }

        // Block and wait again
        block_current_thread(ThreadState::BLOCKED, rwlock_ptr);
        context_switch(SwitchReason::BLOCKING_OPERATION);
        return;  // Context switch occurred, don't continue
    }

    // Set LR to the saved return address so we return to the original caller
    set_reg(emu_, UC_ARM64_REG_LR, return_addr);

    // Set X0 to 0 (success)
    uint64_t result = 0;
    set_reg(emu_, UC_ARM64_REG_X0, result);
}

int ThreadManager::pthread_rwlock_trywrlock(uint64_t rwlock_ptr) {
    std::lock_guard<std::mutex> lock(threads_mutex_);
    auto it = rwlocks_.find(rwlock_ptr);
    if (it == rwlocks_.end()) {
        rwlocks_[rwlock_ptr] = std::make_unique<EmulatedRWLock>();
        it = rwlocks_.find(rwlock_ptr);
    }

    EmulatedRWLock* rwlock = it->second.get();

    // Can acquire write lock if no readers and no writer
    if (rwlock->readers == 0 && rwlock->writer == 0) {
        rwlock->writer = current_thread_id_;
        return 0;
    }

    // Lock is held, return EBUSY
    return EBUSY;
}

int ThreadManager::pthread_rwlock_unlock(uint64_t rwlock_ptr) {
    std::lock_guard<std::mutex> lock(threads_mutex_);
    auto it = rwlocks_.find(rwlock_ptr);
    if (it == rwlocks_.end()) {
        return EINVAL;
    }

    EmulatedRWLock* rwlock = it->second.get();

    // Release write lock
    if (rwlock->writer == current_thread_id_) {
        // Handle recursive write lock
        if (rwlock->write_count > 1) {
            rwlock->write_count--;
            if (emu_.is_debug()) {
                EMU_LOG << "[RWLOCK] unlock: thread " << current_thread_id_
                          << " recursive unlock on 0x" << std::hex << rwlock_ptr
                          << " count=" << std::dec << rwlock->write_count << std::endl;
            }
            return 0;
        }

        rwlock->writer = 0;
        rwlock->write_count = 0;

        // Wake up waiting writers first (writer preference)
        if (!rwlock->write_wait_queue.empty()) {
            uint64_t waiting_thread = rwlock->write_wait_queue.front();
            rwlock->write_wait_queue.pop_front();
            unblock_thread_internal(waiting_thread);  // Use internal version - we already hold the lock
        } else {
            // Wake up all waiting readers
            for (uint64_t thread_id : rwlock->read_wait_queue) {
                unblock_thread_internal(thread_id);  // Use internal version - we already hold the lock
            }
            rwlock->read_wait_queue.clear();
        }
    }
    // Release read lock
    else if (rwlock->readers > 0) {
        rwlock->readers--;

        // If no more readers, wake up a waiting writer
        if (rwlock->readers == 0 && !rwlock->write_wait_queue.empty()) {
            uint64_t waiting_thread = rwlock->write_wait_queue.front();
            rwlock->write_wait_queue.pop_front();
            unblock_thread_internal(waiting_thread);  // Use internal version - we already hold the lock
        }
    }

    return 0;
}

// Barrier operations (cooperative)
int ThreadManager::pthread_barrier_init(uint64_t barrier_ptr, uint64_t attr, unsigned int count) {
    (void)attr;
    if (count == 0) {
        return EINVAL;
    }
    std::lock_guard<std::mutex> lock(threads_mutex_);
    auto barrier = std::make_unique<EmulatedBarrier>();
    barrier->count = count;
    barrier->waiting = 0;
    barrier->generation = 0;
    barriers_[barrier_ptr] = std::move(barrier);
    return 0;
}

int ThreadManager::pthread_barrier_destroy(uint64_t barrier_ptr) {
    std::lock_guard<std::mutex> lock(threads_mutex_);
    auto it = barriers_.find(barrier_ptr);
    if (it == barriers_.end()) {
        return EINVAL;
    }
    if (it->second->waiting > 0) {
        return EBUSY;  // Threads are still waiting
    }
    barriers_.erase(it);
    return 0;
}

int ThreadManager::pthread_barrier_wait(uint64_t barrier_ptr) {
    {
        std::lock_guard<std::mutex> lock(threads_mutex_);
        auto it = barriers_.find(barrier_ptr);
        if (it == barriers_.end()) {
            // Auto-initialize with count=1 (single thread barrier)
            auto barrier = std::make_unique<EmulatedBarrier>();
            barrier->count = 1;
            barriers_[barrier_ptr] = std::move(barrier);
            it = barriers_.find(barrier_ptr);
        }

        EmulatedBarrier* barrier = it->second.get();
        barrier->waiting++;

        // Check if we're the last thread to arrive
        if (barrier->waiting >= barrier->count) {
            // All threads have arrived - release them all
            barrier->waiting = 0;
            barrier->generation++;  // New generation for next use

            // Wake up all waiting threads
            for (uint64_t thread_id : barrier->wait_queue) {
                unblock_thread_internal(thread_id);
            }
            barrier->wait_queue.clear();

            // Return PTHREAD_BARRIER_SERIAL_THREAD for the releasing thread
            return -1;  // PTHREAD_BARRIER_SERIAL_THREAD is typically -1
        }

        // Not the last thread - save state for resume and add to wait queue
        auto current_it = threads_.find(current_thread_id_);
        if (current_it != threads_.end()) {
            // Save return address and barrier pointer for resume
            uint64_t return_addr;
            return_addr = get_reg(emu_, UC_ARM64_REG_LR);
            current_it->second->barrier_wait_ptr = barrier_ptr;
            current_it->second->barrier_wait_return_addr = return_addr;

            // Set PC to the resume function
            // When the thread is rescheduled, it will execute the resume function
            uint64_t resume_addr = HLE_BASE + 0xFFFDC;  // Resume address for barrier
            current_it->second->registers.pc = resume_addr;
        }
        barrier->wait_queue.push_back(current_thread_id_);
    }

    // Block and wait for other threads
    block_current_thread(ThreadState::BLOCKED, barrier_ptr);
    context_switch(SwitchReason::BLOCKING_OPERATION);

    // NOTE: After context_switch returns, we are now running a DIFFERENT thread!
    return CONTEXT_SWITCH_OCCURRED;
}

void ThreadManager::pthread_barrier_wait_resume() {
    // This function is called when a thread is woken up from pthread_barrier_wait
    // It returns 0 to the original caller

    uint64_t return_addr;

    {
        std::lock_guard<std::mutex> lock(threads_mutex_);
        auto it = threads_.find(current_thread_id_);
        if (it == threads_.end()) {
            return;
        }
        return_addr = it->second->barrier_wait_return_addr;

        // Clear the saved values
        it->second->barrier_wait_ptr = 0;
        it->second->barrier_wait_return_addr = 0;
    }

    // Set LR to the saved return address so we return to the original caller
    set_reg(emu_, UC_ARM64_REG_LR, return_addr);

    // Set X0 to 0 (normal return for non-serial threads)
    uint64_t result = 0;
    set_reg(emu_, UC_ARM64_REG_X0, result);
}

// Thread-local storage
int ThreadManager::pthread_key_create(uint64_t key_ptr, uint64_t destructor) {
    uint64_t key = next_tls_key_++;

    {
        std::lock_guard<std::mutex> lock(threads_mutex_);
        if (destructor != 0) {
            tls_destructors_[key] = destructor;
        }
    }

    // Write as 32-bit value (pthread_key_t is typically 32-bit)
    // Use Emulator's mem_write which accesses all mapped memory (including library data sections)
    uint32_t key32 = static_cast<uint32_t>(key);
    emu_.mem_write(key_ptr, &key32, sizeof(key32));

    return 0;
}

int ThreadManager::pthread_key_delete(uint64_t key) {
    std::lock_guard<std::mutex> lock(threads_mutex_);
    tls_destructors_.erase(key);

    // Remove key from all threads' TLS data
    for (auto& pair : tls_data_) {
        pair.second.erase(key);
    }

    return 0;
}

uint64_t ThreadManager::pthread_getspecific(uint64_t key) {
    std::lock_guard<std::mutex> lock(threads_mutex_);

    auto thread_it = tls_data_.find(current_thread_id_);
    if (thread_it == tls_data_.end()) {
        return 0;
    }

    auto key_it = thread_it->second.find(key);
    if (key_it == thread_it->second.end()) {
        return 0;
    }

    return key_it->second;
}

int ThreadManager::pthread_setspecific(uint64_t key, uint64_t value) {
    std::lock_guard<std::mutex> lock(threads_mutex_);
    tls_data_[current_thread_id_][key] = value;
    return 0;
}

// ============================================================================
// Blocking I/O Operations (Cooperative)
// ============================================================================

ssize_t ThreadManager::blocking_recv(int sockfd, uint64_t buf_ptr, size_t len, int flags) {
    // MTTCG: each worker (and each guest thread) runs on its own host thread, so we issue
    // the recv directly and honor the socket's OWN blocking mode. A blocking socket blocks
    // only this host thread; a non-blocking socket returns EAGAIN for the guest to poll.
    // The old cooperative path (force O_NONBLOCK + block_current_thread + context_switch)
    // mutated shared scheduler state (current_thread_id_/runnable_queue_) and clobbered
    // another worker's guest registers when two workers raced here. (connect was already
    // converted to a direct host call for the same reason.)
    std::vector<char> buf(len);
    ssize_t result = ::recv(sockfd, buf.data(), len, flags);
    if (result > 0) {
        emu_.mem_write(buf_ptr, buf.data(), result);
    }
    return result;
}

void ThreadManager::blocking_recv_resume() {
    int sockfd;
    uint64_t buf_ptr;
    size_t len;
    int flags;
    uint64_t return_addr;

    {
        std::lock_guard<std::mutex> lock(threads_mutex_);
        auto it = threads_.find(current_thread_id_);
        if (it == threads_.end()) return;

        sockfd = it->second->io_fd;
        buf_ptr = it->second->io_buf_ptr;
        len = it->second->io_len;
        flags = it->second->io_flags;
        return_addr = it->second->io_return_addr;

        // Clear I/O state
        it->second->io_operation = ThreadContext::IoOperation::NONE;
        it->second->io_fd = -1;
    }

    // Try recv again (non-blocking)
    int orig_flags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, orig_flags | O_NONBLOCK);

    std::vector<char> buf(len);
    ssize_t result = ::recv(sockfd, buf.data(), len, flags);

    if (result >= 0) {
        // Success
        if (result > 0) {
            emu_.mem_write(buf_ptr, buf.data(), result);
        }
        fcntl(sockfd, F_SETFL, orig_flags);

        // Set return value and return address
        set_reg(emu_, UC_ARM64_REG_X0, result);
        set_reg(emu_, UC_ARM64_REG_LR, return_addr);
        return;
    }

    if (errno == EAGAIN || errno == EWOULDBLOCK) {
        // Still would block - save state and block again
        {
            std::lock_guard<std::mutex> lock(threads_mutex_);
            auto it = threads_.find(current_thread_id_);
            if (it != threads_.end()) {
                it->second->io_operation = ThreadContext::IoOperation::RECV;
                it->second->io_fd = sockfd;
                it->second->io_buf_ptr = buf_ptr;
                it->second->io_len = len;
                it->second->io_flags = flags;
                it->second->io_return_addr = return_addr;

                uint64_t resume_addr = HLE_BASE + 0xFFFE0;
                it->second->registers.pc = resume_addr;
            }
        }

        fcntl(sockfd, F_SETFL, orig_flags);
        block_current_thread(ThreadState::IO_WAIT, sockfd);
        context_switch(SwitchReason::BLOCKING_OPERATION);
        return;
    }

    // Error
    fcntl(sockfd, F_SETFL, orig_flags);
    set_reg(emu_, UC_ARM64_REG_X0, result);
    set_reg(emu_, UC_ARM64_REG_LR, return_addr);
}

ssize_t ThreadManager::blocking_send(int sockfd, uint64_t buf_ptr, size_t len, int flags) {
    // MTTCG: direct send honoring the socket's own mode (see blocking_recv). No cooperative
    // context switch — that raced concurrent workers on the shared scheduler state.
    std::vector<char> buf(len);
    emu_.mem_read(buf_ptr, buf.data(), len);
    return ::send(sockfd, buf.data(), len, flags);
}

void ThreadManager::blocking_send_resume() {
    int sockfd;
    uint64_t buf_ptr;
    size_t len;
    int flags;
    uint64_t return_addr;

    {
        std::lock_guard<std::mutex> lock(threads_mutex_);
        auto it = threads_.find(current_thread_id_);
        if (it == threads_.end()) return;

        sockfd = it->second->io_fd;
        buf_ptr = it->second->io_buf_ptr;
        len = it->second->io_len;
        flags = it->second->io_flags;
        return_addr = it->second->io_return_addr;

        it->second->io_operation = ThreadContext::IoOperation::NONE;
        it->second->io_fd = -1;
    }

    std::vector<char> buf(len);
    emu_.mem_read(buf_ptr, buf.data(), len);

    int orig_flags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, orig_flags | O_NONBLOCK);

    ssize_t result = ::send(sockfd, buf.data(), len, flags);

    if (result >= 0) {
        fcntl(sockfd, F_SETFL, orig_flags);
        set_reg(emu_, UC_ARM64_REG_X0, result);
        set_reg(emu_, UC_ARM64_REG_LR, return_addr);
        return;
    }

    if (errno == EAGAIN || errno == EWOULDBLOCK) {
        {
            std::lock_guard<std::mutex> lock(threads_mutex_);
            auto it = threads_.find(current_thread_id_);
            if (it != threads_.end()) {
                it->second->io_operation = ThreadContext::IoOperation::SEND;
                it->second->io_fd = sockfd;
                it->second->io_buf_ptr = buf_ptr;
                it->second->io_len = len;
                it->second->io_flags = flags;
                it->second->io_return_addr = return_addr;

                uint64_t resume_addr = HLE_BASE + 0xFFFE4;
                it->second->registers.pc = resume_addr;
            }
        }

        fcntl(sockfd, F_SETFL, orig_flags);
        block_current_thread(ThreadState::IO_WAIT, sockfd);
        context_switch(SwitchReason::BLOCKING_OPERATION);
        return;
    }

    fcntl(sockfd, F_SETFL, orig_flags);
    set_reg(emu_, UC_ARM64_REG_X0, result);
    set_reg(emu_, UC_ARM64_REG_LR, return_addr);
}

ssize_t ThreadManager::blocking_recvfrom(int sockfd, uint64_t buf_ptr, size_t len, int flags,
                                         uint64_t addr_ptr, uint64_t addrlen_ptr) {
    // MTTCG: direct recvfrom honoring the socket's own mode (see blocking_recv). No
    // cooperative context switch — that raced concurrent workers on shared scheduler state.
    std::vector<char> buf(len);
    struct sockaddr_storage addr {};
    socklen_t addrlen = sizeof(addr);
    struct sockaddr* addr_out = addr_ptr ? reinterpret_cast<struct sockaddr*>(&addr) : nullptr;
    socklen_t* addrlen_out = addr_ptr ? &addrlen : nullptr;

    ssize_t result = ::recvfrom(sockfd, buf.data(), len, flags, addr_out, addrlen_out);

    if (result >= 0) {
        if (result > 0) {
            emu_.mem_write(buf_ptr, buf.data(), result);
        }
        if (addr_ptr && addrlen_out != nullptr) {
            emu_.mem_write(addr_ptr, &addr, addrlen);
        }
        if (addrlen_ptr) {
            emu_.mem_write(addrlen_ptr, &addrlen, sizeof(addrlen));
        }
    }
    return result;
}

void ThreadManager::blocking_recvfrom_resume() {
    int sockfd;
    uint64_t buf_ptr;
    size_t len;
    int flags;
    uint64_t addr_ptr;
    uint64_t addrlen_ptr;
    uint64_t return_addr;

    {
        std::lock_guard<std::mutex> lock(threads_mutex_);
        auto it = threads_.find(current_thread_id_);
        if (it == threads_.end()) return;

        sockfd = it->second->io_fd;
        buf_ptr = it->second->io_buf_ptr;
        len = it->second->io_len;
        flags = it->second->io_flags;
        addr_ptr = it->second->io_addr_ptr;
        addrlen_ptr = it->second->io_addrlen_ptr;
        return_addr = it->second->io_return_addr;

        it->second->io_operation = ThreadContext::IoOperation::NONE;
        it->second->io_fd = -1;
        it->second->io_addr_ptr = 0;
        it->second->io_addrlen_ptr = 0;
    }

    int orig_flags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, orig_flags | O_NONBLOCK);

    std::vector<char> buf(len);
    struct sockaddr_storage addr {};
    socklen_t addrlen = sizeof(addr);
    struct sockaddr* addr_out = addr_ptr ? reinterpret_cast<struct sockaddr*>(&addr) : nullptr;
    socklen_t* addrlen_out = addr_ptr ? &addrlen : nullptr;

    ssize_t result = ::recvfrom(sockfd, buf.data(), len, flags, addr_out, addrlen_out);

    if (result >= 0) {
        if (result > 0) {
            emu_.mem_write(buf_ptr, buf.data(), result);
        }
        if (addr_ptr && addrlen_out != nullptr) {
            emu_.mem_write(addr_ptr, &addr, addrlen);
        }
        if (addrlen_ptr) {
            emu_.mem_write(addrlen_ptr, &addrlen, sizeof(addrlen));
        }
        fcntl(sockfd, F_SETFL, orig_flags);
        set_reg(emu_, UC_ARM64_REG_X0, result);
        set_reg(emu_, UC_ARM64_REG_LR, return_addr);
        return;
    }

    if (errno == EAGAIN || errno == EWOULDBLOCK) {
        {
            std::lock_guard<std::mutex> lock(threads_mutex_);
            auto it = threads_.find(current_thread_id_);
            if (it != threads_.end()) {
                it->second->io_operation = ThreadContext::IoOperation::RECVFROM;
                it->second->io_fd = sockfd;
                it->second->io_buf_ptr = buf_ptr;
                it->second->io_len = len;
                it->second->io_flags = flags;
                it->second->io_addr_ptr = addr_ptr;
                it->second->io_addrlen_ptr = addrlen_ptr;
                it->second->io_return_addr = return_addr;
                it->second->registers.pc = HLE_BASE + 0xFFFCC;
            }
        }

        fcntl(sockfd, F_SETFL, orig_flags);
        block_current_thread(ThreadState::IO_WAIT, sockfd);
        context_switch(SwitchReason::BLOCKING_OPERATION);
        return;
    }

    fcntl(sockfd, F_SETFL, orig_flags);
    set_reg(emu_, UC_ARM64_REG_X0, result);
    set_reg(emu_, UC_ARM64_REG_LR, return_addr);
}

ssize_t ThreadManager::blocking_sendto(int sockfd, uint64_t buf_ptr, size_t len, int flags,
                                       uint64_t addr_ptr, uint64_t addrlen) {
    // MTTCG: direct sendto honoring the socket's own mode (see blocking_recv). No
    // cooperative context switch — that raced concurrent workers on shared scheduler state.
    std::vector<char> buf(len);
    emu_.mem_read(buf_ptr, buf.data(), len);

    std::vector<char> addr_buf(addr_ptr && addrlen > 0 ? addrlen : 1);
    if (addr_ptr && addrlen > 0) {
        emu_.mem_read(addr_ptr, addr_buf.data(), addrlen);
    }

    return ::sendto(
        sockfd,
        buf.data(),
        len,
        flags,
        (addr_ptr && addrlen > 0) ? reinterpret_cast<struct sockaddr*>(addr_buf.data()) : nullptr,
        static_cast<socklen_t>(addrlen));
}

void ThreadManager::blocking_sendto_resume() {
    int sockfd;
    uint64_t buf_ptr;
    size_t len;
    int flags;
    uint64_t addr_ptr;
    uint64_t addrlen;
    uint64_t return_addr;

    {
        std::lock_guard<std::mutex> lock(threads_mutex_);
        auto it = threads_.find(current_thread_id_);
        if (it == threads_.end()) return;

        sockfd = it->second->io_fd;
        buf_ptr = it->second->io_buf_ptr;
        len = it->second->io_len;
        flags = it->second->io_flags;
        addr_ptr = it->second->io_addr_ptr;
        addrlen = it->second->io_addrlen_ptr;
        return_addr = it->second->io_return_addr;

        it->second->io_operation = ThreadContext::IoOperation::NONE;
        it->second->io_fd = -1;
        it->second->io_addr_ptr = 0;
        it->second->io_addrlen_ptr = 0;
    }

    std::vector<char> buf(len);
    emu_.mem_read(buf_ptr, buf.data(), len);

    std::vector<char> addr_buf(addr_ptr && addrlen > 0 ? addrlen : 1);
    if (addr_ptr && addrlen > 0) {
        emu_.mem_read(addr_ptr, addr_buf.data(), addrlen);
    }

    int orig_flags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, orig_flags | O_NONBLOCK);

    ssize_t result = ::sendto(
        sockfd,
        buf.data(),
        len,
        flags,
        (addr_ptr && addrlen > 0) ? reinterpret_cast<struct sockaddr*>(addr_buf.data()) : nullptr,
        static_cast<socklen_t>(addrlen));

    if (result >= 0) {
        fcntl(sockfd, F_SETFL, orig_flags);
        set_reg(emu_, UC_ARM64_REG_X0, result);
        set_reg(emu_, UC_ARM64_REG_LR, return_addr);
        return;
    }

    if (errno == EAGAIN || errno == EWOULDBLOCK) {
        {
            std::lock_guard<std::mutex> lock(threads_mutex_);
            auto it = threads_.find(current_thread_id_);
            if (it != threads_.end()) {
                it->second->io_operation = ThreadContext::IoOperation::SENDTO;
                it->second->io_fd = sockfd;
                it->second->io_buf_ptr = buf_ptr;
                it->second->io_len = len;
                it->second->io_flags = flags;
                it->second->io_addr_ptr = addr_ptr;
                it->second->io_addrlen_ptr = addrlen;
                it->second->io_return_addr = return_addr;
                it->second->registers.pc = HLE_BASE + 0xFFFD0;
            }
        }

        fcntl(sockfd, F_SETFL, orig_flags);
        block_current_thread(ThreadState::IO_WAIT, sockfd);
        context_switch(SwitchReason::BLOCKING_OPERATION);
        return;
    }

    fcntl(sockfd, F_SETFL, orig_flags);
    set_reg(emu_, UC_ARM64_REG_X0, result);
    set_reg(emu_, UC_ARM64_REG_LR, return_addr);
}

int ThreadManager::blocking_accept(int sockfd, uint64_t addr_ptr, uint64_t addrlen_ptr) {
    // Set socket to non-blocking
    int orig_flags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, orig_flags | O_NONBLOCK);

    struct sockaddr_storage addr;
    socklen_t addrlen = sizeof(addr);

    int result = ::accept(sockfd, (struct sockaddr*)&addr, &addrlen);

    if (result >= 0) {
        // Success - write address to emulator memory
        if (addr_ptr) {
            emu_.mem_write(addr_ptr, &addr, addrlen);
        }
        if (addrlen_ptr) {
            emu_.mem_write(addrlen_ptr, &addrlen, sizeof(addrlen));
        }
        fcntl(sockfd, F_SETFL, orig_flags);
        return result;
    }

    if (errno == EAGAIN || errno == EWOULDBLOCK) {
        // Would block - save state and context switch
        {
            std::lock_guard<std::mutex> lock(threads_mutex_);
            auto it = threads_.find(current_thread_id_);
            if (it != threads_.end()) {
                it->second->io_operation = ThreadContext::IoOperation::ACCEPT;
                it->second->io_fd = sockfd;
                it->second->io_addr_ptr = addr_ptr;
                it->second->io_addrlen_ptr = addrlen_ptr;

                it->second->io_return_addr = get_reg(emu_, UC_ARM64_REG_LR);

                uint64_t resume_addr = HLE_BASE + 0xFFFE8;  // accept resume address
                it->second->registers.pc = resume_addr;
            }
        }

        fcntl(sockfd, F_SETFL, orig_flags);
        block_current_thread(ThreadState::IO_WAIT, sockfd);
        context_switch(SwitchReason::BLOCKING_OPERATION);
        return CONTEXT_SWITCH_OCCURRED;
    }

    fcntl(sockfd, F_SETFL, orig_flags);
    return result;
}

void ThreadManager::blocking_accept_resume() {
    int sockfd;
    uint64_t addr_ptr;
    uint64_t addrlen_ptr;
    uint64_t return_addr;

    {
        std::lock_guard<std::mutex> lock(threads_mutex_);
        auto it = threads_.find(current_thread_id_);
        if (it == threads_.end()) return;

        sockfd = it->second->io_fd;
        addr_ptr = it->second->io_addr_ptr;
        addrlen_ptr = it->second->io_addrlen_ptr;
        return_addr = it->second->io_return_addr;

        it->second->io_operation = ThreadContext::IoOperation::NONE;
        it->second->io_fd = -1;
    }

    int orig_flags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, orig_flags | O_NONBLOCK);

    struct sockaddr_storage addr;
    socklen_t addrlen = sizeof(addr);

    int result = ::accept(sockfd, (struct sockaddr*)&addr, &addrlen);

    if (result >= 0) {
        if (addr_ptr) {
            emu_.mem_write(addr_ptr, &addr, addrlen);
        }
        if (addrlen_ptr) {
            emu_.mem_write(addrlen_ptr, &addrlen, sizeof(addrlen));
        }
        fcntl(sockfd, F_SETFL, orig_flags);

        uint64_t res = result;
        set_reg(emu_, UC_ARM64_REG_X0, res);
        set_reg(emu_, UC_ARM64_REG_LR, return_addr);
        return;
    }

    if (errno == EAGAIN || errno == EWOULDBLOCK) {
        {
            std::lock_guard<std::mutex> lock(threads_mutex_);
            auto it = threads_.find(current_thread_id_);
            if (it != threads_.end()) {
                it->second->io_operation = ThreadContext::IoOperation::ACCEPT;
                it->second->io_fd = sockfd;
                it->second->io_addr_ptr = addr_ptr;
                it->second->io_addrlen_ptr = addrlen_ptr;
                it->second->io_return_addr = return_addr;

                uint64_t resume_addr = HLE_BASE + 0xFFFE8;
                it->second->registers.pc = resume_addr;
            }
        }

        fcntl(sockfd, F_SETFL, orig_flags);
        block_current_thread(ThreadState::IO_WAIT, sockfd);
        context_switch(SwitchReason::BLOCKING_OPERATION);
        return;
    }

    fcntl(sockfd, F_SETFL, orig_flags);
    uint64_t res = result;
    set_reg(emu_, UC_ARM64_REG_X0, res);
    set_reg(emu_, UC_ARM64_REG_LR, return_addr);
}

int ThreadManager::blocking_epoll_wait(int epfd, uint64_t events_ptr, int maxevents, int timeout_ms) {
    if (maxevents <= 0 || events_ptr == 0) {
        errno = EINVAL;
        return -1;
    }

    std::vector<struct epoll_event> host_events(maxevents);
    errno = 0;
    const int host_timeout_ms = clamp_hle_epoll_wait_timeout(timeout_ms);
    const int result = ::epoll_wait(epfd, host_events.data(), maxevents, host_timeout_ms);

    if (result > 0 && !write_epoll_events_to_guest(emu_, events_ptr, host_events, result)) {
        errno = EFAULT;
        return -1;
    }

    return result;
}

void ThreadManager::blocking_epoll_wait_resume() {
    int epfd;
    uint64_t events_ptr;
    int maxevents;
    int timeout_ms;
    uint64_t return_addr;
    std::chrono::steady_clock::time_point start_time;

    {
        std::lock_guard<std::mutex> lock(threads_mutex_);
        auto it = threads_.find(current_thread_id_);
        if (it == threads_.end()) return;

        epfd = it->second->coop_io_fd;
        events_ptr = it->second->coop_io_events_ptr;
        maxevents = it->second->coop_io_maxevents;
        timeout_ms = it->second->coop_io_timeout_ms;
        return_addr = it->second->coop_io_return_addr;
        start_time = it->second->coop_io_start;

        it->second->io_operation = ThreadContext::IoOperation::NONE;
        it->second->io_fd = -1;
        it->second->coop_io_type = ThreadContext::CoopIoType::NONE;
        it->second->coop_io_fd = -1;
        it->second->coop_io_events_ptr = 0;
        it->second->coop_io_maxevents = 0;
        it->second->coop_io_timeout_ms = 0;
        it->second->coop_io_return_addr = 0;
    }

    (void)start_time;

    const int result = blocking_epoll_wait(epfd, events_ptr, maxevents, timeout_ms);
    if (result < 0) {
        hle_set_errno(emu_, errno);
    }
    set_reg(emu_, UC_ARM64_REG_X0, -1);
    if (result >= 0) {
        set_reg(emu_, UC_ARM64_REG_X0, result);
    }
    set_reg(emu_, UC_ARM64_REG_LR, return_addr);
}

ssize_t ThreadManager::blocking_read(int fd, uint64_t buf_ptr, size_t count) {
    // Set fd to non-blocking
    int orig_flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, orig_flags | O_NONBLOCK);

    // Try the read
    std::vector<char> buf(count);
    ssize_t result = ::read(fd, buf.data(), count);

    if (result >= 0) {
        // Success - write data to emulator memory
        if (result > 0) {
            emu_.mem_write(buf_ptr, buf.data(), result);
        }
        fcntl(fd, F_SETFL, orig_flags);  // Restore blocking mode
        return result;
    }

    if (errno == EAGAIN || errno == EWOULDBLOCK) {
        // Would block - save state and context switch
        {
            std::lock_guard<std::mutex> lock(threads_mutex_);
            auto it = threads_.find(current_thread_id_);
            if (it != threads_.end()) {
                it->second->io_operation = ThreadContext::IoOperation::READ;
                it->second->io_fd = fd;
                it->second->io_buf_ptr = buf_ptr;
                it->second->io_len = count;

                // Save return address
                it->second->io_return_addr = get_reg(emu_, UC_ARM64_REG_LR);

                // Set PC to resume function
                uint64_t resume_addr = HLE_BASE + 0xFFFC0;  // read resume address
                it->second->registers.pc = resume_addr;
            }
        }

        fcntl(fd, F_SETFL, orig_flags);  // Restore blocking mode
        block_current_thread(ThreadState::IO_WAIT, fd);
        context_switch(SwitchReason::BLOCKING_OPERATION);
        return CONTEXT_SWITCH_OCCURRED;
    }

    // Real error
    fcntl(fd, F_SETFL, orig_flags);
    return result;
}

void ThreadManager::blocking_read_resume() {
    int fd;
    uint64_t buf_ptr;
    size_t count;
    uint64_t return_addr;

    {
        std::lock_guard<std::mutex> lock(threads_mutex_);
        auto it = threads_.find(current_thread_id_);
        if (it == threads_.end()) return;

        fd = it->second->io_fd;
        buf_ptr = it->second->io_buf_ptr;
        count = it->second->io_len;
        return_addr = it->second->io_return_addr;

        // Clear I/O state
        it->second->io_operation = ThreadContext::IoOperation::NONE;
        it->second->io_fd = -1;
    }

    // Try read again (non-blocking)
    int orig_flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, orig_flags | O_NONBLOCK);

    std::vector<char> buf(count);
    ssize_t result = ::read(fd, buf.data(), count);

    if (result >= 0) {
        // Success
        if (result > 0) {
            emu_.mem_write(buf_ptr, buf.data(), result);
        }
        fcntl(fd, F_SETFL, orig_flags);

        // Set return value and return address
        set_reg(emu_, UC_ARM64_REG_X0, result);
        set_reg(emu_, UC_ARM64_REG_LR, return_addr);
        return;
    }

    if (errno == EAGAIN || errno == EWOULDBLOCK) {
        // Still would block - save state and context switch again
        {
            std::lock_guard<std::mutex> lock(threads_mutex_);
            auto it = threads_.find(current_thread_id_);
            if (it != threads_.end()) {
                it->second->io_operation = ThreadContext::IoOperation::READ;
                it->second->io_fd = fd;
                it->second->io_buf_ptr = buf_ptr;
                it->second->io_len = count;
                it->second->io_return_addr = return_addr;

                uint64_t resume_addr = HLE_BASE + 0xFFFC0;  // read resume address
                it->second->registers.pc = resume_addr;
            }
        }

        fcntl(fd, F_SETFL, orig_flags);
        block_current_thread(ThreadState::IO_WAIT, fd);
        context_switch(SwitchReason::BLOCKING_OPERATION);
        return;
    }

    // Error
    fcntl(fd, F_SETFL, orig_flags);
    set_reg(emu_, UC_ARM64_REG_X0, result);
    set_reg(emu_, UC_ARM64_REG_LR, return_addr);
}

ssize_t ThreadManager::blocking_write(int fd, uint64_t buf_ptr, size_t count) {
    // Read data from emulator memory
    std::vector<char> buf(count);
    emu_.mem_read(buf_ptr, buf.data(), count);

    // Set fd to non-blocking
    int orig_flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, orig_flags | O_NONBLOCK);

    ssize_t result = ::write(fd, buf.data(), count);

    if (result >= 0) {
        fcntl(fd, F_SETFL, orig_flags);
        return result;
    }

    if (errno == EAGAIN || errno == EWOULDBLOCK) {
        // Would block - save state and context switch
        {
            std::lock_guard<std::mutex> lock(threads_mutex_);
            auto it = threads_.find(current_thread_id_);
            if (it != threads_.end()) {
                it->second->io_operation = ThreadContext::IoOperation::WRITE;
                it->second->io_fd = fd;
                it->second->io_buf_ptr = buf_ptr;
                it->second->io_len = count;

                it->second->io_return_addr = get_reg(emu_, UC_ARM64_REG_LR);

                uint64_t resume_addr = HLE_BASE + 0xFFFC4;  // write resume address
                it->second->registers.pc = resume_addr;
            }
        }

        fcntl(fd, F_SETFL, orig_flags);
        block_current_thread(ThreadState::IO_WAIT, fd);
        context_switch(SwitchReason::BLOCKING_OPERATION);
        return CONTEXT_SWITCH_OCCURRED;
    }

    fcntl(fd, F_SETFL, orig_flags);
    return result;
}

void ThreadManager::blocking_write_resume() {
    int fd;
    uint64_t buf_ptr;
    size_t count;
    uint64_t return_addr;

    {
        std::lock_guard<std::mutex> lock(threads_mutex_);
        auto it = threads_.find(current_thread_id_);
        if (it == threads_.end()) return;

        fd = it->second->io_fd;
        buf_ptr = it->second->io_buf_ptr;
        count = it->second->io_len;
        return_addr = it->second->io_return_addr;

        it->second->io_operation = ThreadContext::IoOperation::NONE;
        it->second->io_fd = -1;
    }

    std::vector<char> buf(count);
    emu_.mem_read(buf_ptr, buf.data(), count);

    int orig_flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, orig_flags | O_NONBLOCK);

    ssize_t result = ::write(fd, buf.data(), count);

    if (result >= 0) {
        fcntl(fd, F_SETFL, orig_flags);
        set_reg(emu_, UC_ARM64_REG_X0, result);
        set_reg(emu_, UC_ARM64_REG_LR, return_addr);
        return;
    }

    if (errno == EAGAIN || errno == EWOULDBLOCK) {
        {
            std::lock_guard<std::mutex> lock(threads_mutex_);
            auto it = threads_.find(current_thread_id_);
            if (it != threads_.end()) {
                it->second->io_operation = ThreadContext::IoOperation::WRITE;
                it->second->io_fd = fd;
                it->second->io_buf_ptr = buf_ptr;
                it->second->io_len = count;
                it->second->io_return_addr = return_addr;

                uint64_t resume_addr = HLE_BASE + 0xFFFC4;  // write resume address
                it->second->registers.pc = resume_addr;
            }
        }

        fcntl(fd, F_SETFL, orig_flags);
        block_current_thread(ThreadState::IO_WAIT, fd);
        context_switch(SwitchReason::BLOCKING_OPERATION);
        return;
    }

    fcntl(fd, F_SETFL, orig_flags);
    set_reg(emu_, UC_ARM64_REG_X0, result);
    set_reg(emu_, UC_ARM64_REG_LR, return_addr);
}

} // namespace cross_shim
