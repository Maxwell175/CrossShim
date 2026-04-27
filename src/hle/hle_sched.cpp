/**
 * HLE Scheduler and Semaphore Functions
 * CPU affinity: __sched_cpucount, __sched_cpualloc, __sched_cpufree, sched_getaffinity, sched_setaffinity, sched_getcpu
 * Scheduler: sched_get_priority_min, sched_get_priority_max, sched_getscheduler, sched_setscheduler
 *            sched_getparam, sched_setparam, sched_rr_get_interval
 * Semaphore: sem_init, sem_destroy, sem_wait, sem_trywait, sem_timedwait, sem_post, sem_getvalue
 */

#include "debug_log.h"
#include "hle_manager.h"
#include "hle_sched_state.h"
#include "cross_shim.h"
#include "memory_manager.h"
#include "emu_compat.h"
#include <sched.h>
#include <cerrno>
#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <unordered_map>
#include <unistd.h>
#include <vector>

namespace cross_shim {

static constexpr int EINVAL_VALUE = 22;
static constexpr uint32_t GUEST_SEM_VALUE_MAX = 0x3fffffffU;

struct HleSchedState {
    int nice_value{0};
    int base_priority{20};
    int effective_priority{20};
    int pi_waiters{0};
};

static std::mutex g_hle_sched_state_lock;
static std::unordered_map<pid_t, HleSchedState> g_hle_sched_state;

struct guest_sem_arm64 {
    uint32_t count;
    int32_t reserved[3];
};

static_assert(sizeof(guest_sem_arm64) == 16, "guest_sem_arm64 must match bionic LP64 layout");

struct HleSemaphoreState {
    std::mutex mutex;
    std::condition_variable cv;
    uint32_t value{0};
    bool initialized{false};
    bool destroyed{false};
};

static std::mutex g_hle_sem_state_lock;
static std::unordered_map<uint64_t, std::shared_ptr<HleSemaphoreState>> g_hle_sem_state;

static void write_guest_sem_state(Emulator& emu, uint64_t sem_ptr, uint32_t value) {
    if (sem_ptr == 0) {
        return;
    }
    guest_sem_arm64 guest_sem{};
    guest_sem.count = value;
    emu.mem_write(sem_ptr, &guest_sem, sizeof(guest_sem));
}

static std::shared_ptr<HleSemaphoreState> get_or_create_sem_state(uint64_t sem_ptr) {
    if (sem_ptr == 0) {
        return nullptr;
    }
    std::lock_guard<std::mutex> lock(g_hle_sem_state_lock);
    auto& entry = g_hle_sem_state[sem_ptr];
    if (!entry) {
        entry = std::make_shared<HleSemaphoreState>();
    }
    return entry;
}

static std::shared_ptr<HleSemaphoreState> get_sem_state(uint64_t sem_ptr) {
    if (sem_ptr == 0) {
        return nullptr;
    }
    std::lock_guard<std::mutex> lock(g_hle_sem_state_lock);
    auto it = g_hle_sem_state.find(sem_ptr);
    if (it == g_hle_sem_state.end()) {
        return nullptr;
    }
    return it->second;
}

static void erase_sem_state(uint64_t sem_ptr) {
    std::lock_guard<std::mutex> lock(g_hle_sem_state_lock);
    g_hle_sem_state.erase(sem_ptr);
}

static bool read_guest_timespec(Emulator& emu, uint64_t guest_addr, struct timespec& host_ts) {
    if (guest_addr == 0) {
        return false;
    }

    int64_t tv_sec = 0;
    int64_t tv_nsec = 0;
    if (!emu.mem_read(guest_addr, &tv_sec, sizeof(tv_sec)) ||
        !emu.mem_read(guest_addr + sizeof(tv_sec), &tv_nsec, sizeof(tv_nsec))) {
        return false;
    }

    host_ts.tv_sec = static_cast<time_t>(tv_sec);
    host_ts.tv_nsec = static_cast<long>(tv_nsec);
    return true;
}

static bool timespec_is_valid(const struct timespec& ts) {
    return ts.tv_nsec >= 0 && ts.tv_nsec < 1000000000L;
}

static bool timespec_deadline_passed(const struct timespec& deadline, const struct timespec& now) {
    return (now.tv_sec > deadline.tv_sec) ||
           (now.tv_sec == deadline.tv_sec && now.tv_nsec >= deadline.tv_nsec);
}

static std::chrono::nanoseconds timespec_difference(const struct timespec& end,
                                                    const struct timespec& start) {
    int64_t sec = static_cast<int64_t>(end.tv_sec) - static_cast<int64_t>(start.tv_sec);
    int64_t nsec = static_cast<int64_t>(end.tv_nsec) - static_cast<int64_t>(start.tv_nsec);
    if (nsec < 0) {
        --sec;
        nsec += 1000000000LL;
    }
    if (sec < 0) {
        return std::chrono::nanoseconds::zero();
    }
    return std::chrono::seconds(sec) + std::chrono::nanoseconds(nsec);
}

static int sem_wait_internal(Emulator& emu, uint64_t sem_ptr, bool try_only,
                             int clockid, const struct timespec* abs_timeout) {
    auto sem = get_sem_state(sem_ptr);
    if (!sem) {
        hle_set_errno(emu, EINVAL);
        return -1;
    }

    std::unique_lock<std::mutex> lock(sem->mutex);
    if (!sem->initialized || sem->destroyed) {
        hle_set_errno(emu, EINVAL);
        return -1;
    }

    auto ready = [&sem]() {
        return sem->destroyed || !sem->initialized || sem->value > 0;
    };

    if (sem->value == 0) {
        if (try_only) {
            hle_set_errno(emu, EAGAIN);
            return -1;
        }

        if (abs_timeout == nullptr) {
            sem->cv.wait(lock, ready);
        } else {
            if (!timespec_is_valid(*abs_timeout)) {
                hle_set_errno(emu, EINVAL);
                return -1;
            }

            while (sem->value == 0 && sem->initialized && !sem->destroyed) {
                struct timespec now{};
                if (::clock_gettime(clockid, &now) != 0) {
                    hle_set_errno(emu, errno);
                    return -1;
                }
                if (timespec_deadline_passed(*abs_timeout, now)) {
                    hle_set_errno(emu, ETIMEDOUT);
                    return -1;
                }
                auto remaining = timespec_difference(*abs_timeout, now);
                sem->cv.wait_for(lock, remaining, ready);
            }
        }
    }

    if (!sem->initialized || sem->destroyed) {
        hle_set_errno(emu, EINVAL);
        return -1;
    }

    --sem->value;
    write_guest_sem_state(emu, sem_ptr, sem->value);
    return 0;
}

int hle_sem_init(Emulator& emu, uint64_t sem_ptr, int pshared, uint32_t value) {
    (void)pshared;
    if (sem_ptr == 0) {
        hle_set_errno(emu, EINVAL);
        return -1;
    }
    if (value > GUEST_SEM_VALUE_MAX) {
        hle_set_errno(emu, EINVAL);
        return -1;
    }

    auto sem = get_or_create_sem_state(sem_ptr);
    if (!sem) {
        hle_set_errno(emu, EINVAL);
        return -1;
    }

    {
        std::lock_guard<std::mutex> lock(sem->mutex);
        sem->value = value;
        sem->initialized = true;
        sem->destroyed = false;
        write_guest_sem_state(emu, sem_ptr, sem->value);
    }
    sem->cv.notify_all();
    return 0;
}

int hle_sem_destroy(Emulator& emu, uint64_t sem_ptr) {
    auto sem = get_sem_state(sem_ptr);
    if (sem) {
        {
            std::lock_guard<std::mutex> lock(sem->mutex);
            sem->value = 0;
            sem->initialized = false;
            sem->destroyed = true;
            write_guest_sem_state(emu, sem_ptr, 0);
        }
        sem->cv.notify_all();
        erase_sem_state(sem_ptr);
    }
    return 0;
}

int hle_sem_wait(Emulator& emu, uint64_t sem_ptr) {
    return sem_wait_internal(emu, sem_ptr, false, CLOCK_REALTIME, nullptr);
}

int hle_sem_trywait(Emulator& emu, uint64_t sem_ptr) {
    return sem_wait_internal(emu, sem_ptr, true, CLOCK_REALTIME, nullptr);
}

int hle_sem_timedwait(Emulator& emu, uint64_t sem_ptr, int clockid, uint64_t abstime_ptr) {
    struct timespec timeout{};
    if (abstime_ptr == 0 || !read_guest_timespec(emu, abstime_ptr, timeout)) {
        hle_set_errno(emu, EINVAL);
        return -1;
    }
    return sem_wait_internal(emu, sem_ptr, false, clockid, &timeout);
}

int hle_sem_post(Emulator& emu, uint64_t sem_ptr) {
    auto sem = get_sem_state(sem_ptr);
    if (!sem) {
        hle_set_errno(emu, EINVAL);
        return -1;
    }

    {
        std::lock_guard<std::mutex> lock(sem->mutex);
        if (!sem->initialized || sem->destroyed) {
            hle_set_errno(emu, EINVAL);
            return -1;
        }
        if (sem->value == GUEST_SEM_VALUE_MAX) {
            hle_set_errno(emu, EOVERFLOW);
            return -1;
        }
        ++sem->value;
        write_guest_sem_state(emu, sem_ptr, sem->value);
    }

    sem->cv.notify_one();
    return 0;
}

int hle_sem_getvalue(Emulator& emu, uint64_t sem_ptr, uint64_t value_ptr) {
    auto sem = get_sem_state(sem_ptr);
    if (!sem || value_ptr == 0) {
        hle_set_errno(emu, EINVAL);
        return -1;
    }

    int32_t value = 0;
    {
        std::lock_guard<std::mutex> lock(sem->mutex);
        if (!sem->initialized || sem->destroyed) {
            hle_set_errno(emu, EINVAL);
            return -1;
        }
        value = static_cast<int32_t>(sem->value);
    }
    emu.mem_write(value_ptr, &value, sizeof(value));
    return 0;
}

static HleSchedState& get_or_create_sched_state_locked(pid_t tid) {
    return g_hle_sched_state[tid];
}

static void refresh_sched_state_locked(HleSchedState& state) {
    state.base_priority = 20 + state.nice_value;
    state.effective_priority = (state.pi_waiters > 0)
        ? std::min(state.base_priority, 20)
        : state.base_priority;
}

void hle_sched_note_thread_tid(pid_t tid) {
    if (tid <= 0) {
        return;
    }
    std::lock_guard<std::mutex> lock(g_hle_sched_state_lock);
    auto& state = get_or_create_sched_state_locked(tid);
    refresh_sched_state_locked(state);
}

void hle_sched_set_thread_nice(pid_t tid, int nice_value) {
    if (tid <= 0) {
        return;
    }
    std::lock_guard<std::mutex> lock(g_hle_sched_state_lock);
    auto& state = get_or_create_sched_state_locked(tid);
    state.nice_value = nice_value;
    refresh_sched_state_locked(state);
}

bool hle_sched_get_effective_priority(pid_t tid, int& priority) {
    std::lock_guard<std::mutex> lock(g_hle_sched_state_lock);
    auto it = g_hle_sched_state.find(tid);
    if (it == g_hle_sched_state.end()) {
        return false;
    }
    priority = it->second.effective_priority;
    return true;
}

bool hle_sched_get_nice(pid_t tid, int& nice_value) {
    std::lock_guard<std::mutex> lock(g_hle_sched_state_lock);
    auto it = g_hle_sched_state.find(tid);
    if (it == g_hle_sched_state.end()) {
        return false;
    }
    nice_value = it->second.nice_value;
    return true;
}

void hle_sched_pi_boost_begin(pid_t tid) {
    if (tid <= 0) {
        return;
    }
    std::lock_guard<std::mutex> lock(g_hle_sched_state_lock);
    auto& state = get_or_create_sched_state_locked(tid);
    state.pi_waiters++;
    refresh_sched_state_locked(state);
}

void hle_sched_pi_boost_end(pid_t tid) {
    if (tid <= 0) {
        return;
    }
    std::lock_guard<std::mutex> lock(g_hle_sched_state_lock);
    auto it = g_hle_sched_state.find(tid);
    if (it == g_hle_sched_state.end()) {
        return;
    }
    if (it->second.pi_waiters > 0) {
        it->second.pi_waiters--;
    }
    refresh_sched_state_locked(it->second);
}

void register_hle_sched(HleManager& hle) {
    // ========================================================================
    // CPU affinity functions
    // ========================================================================

    // __sched_cpucount - count number of CPUs in cpu_set_t
    hle.register_function("__sched_cpucount", [](Emulator& emu) {
        size_t setsize = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t setp = get_reg(emu, UC_ARM64_REG_X1);

        int count = 0;
        if (setp && setsize > 0) {
            std::vector<uint8_t> set(setsize);
            emu.mem_read(setp, set.data(), setsize);

            for (size_t i = 0; i < setsize; i++) {
                uint8_t byte = set[i];
                while (byte) {
                    byte &= byte - 1;
                    count++;
                }
            }
        }
        set_reg(emu, UC_ARM64_REG_X0, count);
    });

    // __sched_cpualloc - allocate cpu_set_t for given number of CPUs
    hle.register_function("__sched_cpualloc", [](Emulator& emu) {
        size_t count = get_reg(emu, UC_ARM64_REG_X0);
        size_t size = (count + 63) / 64 * 8;  // Round up to 64-bit boundary
        if (size == 0) size = 8;
        uint64_t ptr = emu.memory().heap().allocate(size, 8);
        // Zero out the allocation
        std::vector<uint8_t> zeros(size, 0);
        emu.mem_write(ptr, zeros.data(), size);
        set_reg(emu, UC_ARM64_REG_X0, ptr);
    });

    // __sched_cpufree - free cpu_set_t
    hle.register_function("__sched_cpufree", [](Emulator& emu) {
        uint64_t ptr = get_reg(emu, UC_ARM64_REG_X0);
        if (ptr) {
            emu.memory().heap().free(ptr);
        }
    });

    // sched_getaffinity - get CPU affinity mask
    hle.register_function("sched_getaffinity", [](Emulator& emu) {
        // pid_t pid = get_reg(emu, UC_ARM64_REG_X0);
        size_t cpusetsize = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t mask = get_reg(emu, UC_ARM64_REG_X2);

        // Check for invalid arguments
        if (cpusetsize == 0 || mask == 0) {
            int err = EINVAL_VALUE;
            hle_set_errno(emu, err);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        // Return a mask with all CPUs set
        std::vector<uint8_t> set(cpusetsize, 0xFF);  // All CPUs available
        emu.mem_write(mask, set.data(), cpusetsize);
        set_reg(emu, UC_ARM64_REG_X0, 0);  // Success
    });

    // sched_setaffinity - set CPU affinity mask
    hle.register_function("sched_setaffinity", [](Emulator& emu) {
        // pid_t pid = get_reg(emu, UC_ARM64_REG_X0);
        size_t cpusetsize = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t mask = get_reg(emu, UC_ARM64_REG_X2);

        // Check for invalid arguments
        if (cpusetsize == 0 || mask == 0) {
            int err = EINVAL_VALUE;
            hle_set_errno(emu, err);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        // We don't actually set affinity, just return success
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    // sched_getcpu - get CPU where calling thread is running
    hle.register_function("sched_getcpu", [](Emulator& emu) {
        // Return CPU 0
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    // ========================================================================
    // Scheduler priority and policy
    // ========================================================================

    // sched_get_priority_min - get minimum scheduling priority
    hle.register_function("sched_get_priority_min", [](Emulator& emu) {
        int policy = get_reg(emu, UC_ARM64_REG_X0);
        int result = ::sched_get_priority_min(policy);
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // sched_get_priority_max - get maximum scheduling priority
    hle.register_function("sched_get_priority_max", [](Emulator& emu) {
        int policy = get_reg(emu, UC_ARM64_REG_X0);
        int result = ::sched_get_priority_max(policy);
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // sched_getscheduler - get scheduling policy
    hle.register_function("sched_getscheduler", [](Emulator& emu) {
        pid_t pid = get_reg(emu, UC_ARM64_REG_X0);
        int result = ::sched_getscheduler(pid);
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // sched_setscheduler - set scheduling policy
    hle.register_function("sched_setscheduler", [](Emulator& emu) {
        pid_t pid = get_reg(emu, UC_ARM64_REG_X0);
        int policy = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t param_ptr = get_reg(emu, UC_ARM64_REG_X2);

        struct sched_param param;
        if (param_ptr) {
            int32_t prio;
            emu.mem_read(param_ptr, &prio, 4);
            param.sched_priority = prio;
        }
        errno = 0;
        int result = ::sched_setscheduler(pid, policy, param_ptr ? &param : nullptr);
        if (result == -1 && errno != 0) {
            int err = errno;
            hle_set_errno(emu, err);
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // sched_getparam - get scheduling parameters
    hle.register_function("sched_getparam", [](Emulator& emu) {
        pid_t pid = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t param_ptr = get_reg(emu, UC_ARM64_REG_X1);

        struct sched_param param;
        int result = ::sched_getparam(pid, &param);
        if (result == 0 && param_ptr) {
            int32_t prio = param.sched_priority;
            emu.mem_write(param_ptr, &prio, 4);
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // sched_setparam - set scheduling parameters
    hle.register_function("sched_setparam", [](Emulator& emu) {
        pid_t pid = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t param_ptr = get_reg(emu, UC_ARM64_REG_X1);

        struct sched_param param;
        if (param_ptr) {
            int32_t prio;
            emu.mem_read(param_ptr, &prio, 4);
            param.sched_priority = prio;
        }
        int result = ::sched_setparam(pid, param_ptr ? &param : nullptr);
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // sched_rr_get_interval - get SCHED_RR interval
    hle.register_function("sched_rr_get_interval", [](Emulator& emu) {
        pid_t pid = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t tp_ptr = get_reg(emu, UC_ARM64_REG_X1);

        struct timespec tp;
        int result = ::sched_rr_get_interval(pid, &tp);
        if (result == 0 && tp_ptr) {
            int64_t sec = tp.tv_sec;
            int64_t nsec = tp.tv_nsec;
            emu.mem_write(tp_ptr, &sec, 8);
            emu.mem_write(tp_ptr + 8, &nsec, 8);
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("setpriority", [](Emulator& emu) {
        int which = static_cast<int>(get_reg(emu, UC_ARM64_REG_X0));
        int who = static_cast<int>(get_reg(emu, UC_ARM64_REG_X1));
        int prio = static_cast<int>(get_reg(emu, UC_ARM64_REG_X2));

        if (which != PRIO_PROCESS || prio < -20 || prio > 19) {
            hle_set_errno(emu, EINVAL);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        pid_t target = static_cast<pid_t>(who);
        if (target == 0) {
            target = hle_get_current_visible_tid(emu);
        }

        hle_sched_note_thread_tid(target);
        hle_sched_set_thread_nice(target, prio);
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("getpriority", [](Emulator& emu) {
        int which = static_cast<int>(get_reg(emu, UC_ARM64_REG_X0));
        int who = static_cast<int>(get_reg(emu, UC_ARM64_REG_X1));

        if (which != PRIO_PROCESS) {
            hle_set_errno(emu, EINVAL);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        pid_t target = static_cast<pid_t>(who);
        if (target == 0) {
            target = hle_get_current_visible_tid(emu);
        }

        int nice_value = 0;
        if (!hle_sched_get_nice(target, nice_value)) {
            hle_sched_note_thread_tid(target);
        }
        hle_sched_get_nice(target, nice_value);
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(nice_value));
    });

    // ========================================================================
    // Semaphore functions
    // ========================================================================

    // sem_init - initialize semaphore
    hle.register_function("sem_init", [](Emulator& emu) {
        uint64_t sem_ptr = get_reg(emu, UC_ARM64_REG_X0);
        int pshared = static_cast<int>(get_reg(emu, UC_ARM64_REG_X1));
        uint32_t value = get_reg(emu, UC_ARM64_REG_X2);
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(hle_sem_init(emu, sem_ptr, pshared, value)));
    });

    // sem_destroy - destroy semaphore
    hle.register_function("sem_destroy", [](Emulator& emu) {
        uint64_t sem_ptr = get_reg(emu, UC_ARM64_REG_X0);
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(hle_sem_destroy(emu, sem_ptr)));
    });

    // sem_wait - wait on semaphore (may block)
    hle.register_function("sem_wait", [](Emulator& emu) {
        uint64_t sem_ptr = get_reg(emu, UC_ARM64_REG_X0);
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(hle_sem_wait(emu, sem_ptr)));
    });

    // sem_trywait - try to decrement semaphore without blocking
    hle.register_function("sem_trywait", [](Emulator& emu) {
        uint64_t sem_ptr = get_reg(emu, UC_ARM64_REG_X0);
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(hle_sem_trywait(emu, sem_ptr)));
    });

    // sem_timedwait - wait on semaphore with timeout
    hle.register_function("sem_timedwait", [](Emulator& emu) {
        uint64_t sem_ptr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t abstime_ptr = get_reg(emu, UC_ARM64_REG_X1);
        set_reg(emu, UC_ARM64_REG_X0,
                static_cast<uint64_t>(hle_sem_timedwait(emu, sem_ptr, CLOCK_REALTIME, abstime_ptr)));
    });

    // sem_post - increment semaphore
    hle.register_function("sem_post", [](Emulator& emu) {
        uint64_t sem_ptr = get_reg(emu, UC_ARM64_REG_X0);
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(hle_sem_post(emu, sem_ptr)));
    });

    // sem_getvalue - get semaphore value
    hle.register_function("sem_getvalue", [](Emulator& emu) {
        uint64_t sem_ptr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t value_ptr = get_reg(emu, UC_ARM64_REG_X1);
        set_reg(emu, UC_ARM64_REG_X0,
                static_cast<uint64_t>(hle_sem_getvalue(emu, sem_ptr, value_ptr)));
    });
}

} // namespace cross_shim
