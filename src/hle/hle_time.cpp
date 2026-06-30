/**
 * HLE Time Functions
 * time, gettimeofday, clock_gettime, localtime_r, gmtime_r, strftime, strptime,
 * timezone extensions, and timer APIs with guest/host ABI remapping.
 */

#include "hle_manager.h"
#include "cross_shim.h"
#include "memory_manager.h"
#include "bionic_types.h"
#include "emu_compat.h"
#include "debug_log.h"
#include "hle_signal_state.h"
#include "hle_virtual_threads.h"
#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cctype>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <mutex>
#include <optional>
#include <signal.h>
#include <string>
#include <sys/stat.h>
#include <sys/time.h>
#include <thread>
#include <unordered_map>
#include <vector>
#include <unistd.h>

using namespace cross_shim::bionic;

namespace cross_shim {

namespace {

constexpr uint64_t LOCALTIME_BUF = 0xB0000200;
constexpr uint64_t GMTIME_BUF = 0xB0000280;
constexpr uint64_t ASCTIME_BUF = 0xB0000300;
constexpr uint64_t CTIME_BUF = 0xB0000320;
constexpr long GUEST_PAGE_SIZE = 4096;
constexpr long GUEST_SEM_VALUE_MAX = 0x3fffffffL;

constexpr uint64_t VIRTUAL_THREAD_BASE = 0x70000000ULL;
constexpr int MAX_STRPTIME_ZONE_LEN = 128;

struct itimerspec_arm64 {
    timespec_arm64 it_interval;
    timespec_arm64 it_value;
};
static_assert(sizeof(itimerspec_arm64) == 32, "itimerspec_arm64 must be 32 bytes");

struct guest_sigevent_arm64 {
    uint64_t sigev_value;
    int32_t sigev_signo;
    int32_t sigev_notify;
    union {
        int32_t _pad[12];
        int32_t _tid;
        struct {
            uint64_t function;
            uint64_t attribute;
        } thread;
    } sigev_un;
};
static_assert(sizeof(guest_sigevent_arm64) == 64, "guest_sigevent_arm64 must be 64 bytes");

struct GuestTimezone {
    std::string zone_id;
};

struct GuestTimer {
    uint64_t id = 0;
    pid_t owner_pid = 0;
    int clock_id = CLOCK_REALTIME;
    int notify = SIGEV_SIGNAL;
    int signo = SIGALRM;
    uint64_t callback = 0;
    uint64_t sigval_raw = 0;
    bool armed = false;
    bool deleted = false;
    bool in_callback = false;
    uint64_t active_virtual_tid = 0;
    int64_t due_ns = 0;
    int64_t interval_ns = 0;
};

struct CurrentTimezoneInfo {
    std::string std_name;
    std::string dst_name;
    long std_offset = 0;
    long dst_offset = 0;
    bool has_dst = false;
};

std::recursive_mutex g_time_state_mutex;
std::unordered_map<std::string, uint64_t> g_guest_string_cache;
std::unordered_map<uint64_t, GuestTimezone> g_timezones;
std::unordered_map<uint64_t, GuestTimer> g_timers;
std::atomic<uint64_t> g_next_timezone_handle{0x60000000ULL};
std::atomic<uint64_t> g_next_timer_id{0x68000000ULL};
std::atomic<uint64_t> g_next_virtual_tid{VIRTUAL_THREAD_BASE};
thread_local uint64_t tl_virtual_tid_override = 0;
thread_local bool tl_processing_timers = false;

enum class GuestSysconfKind {
    kHost,
    kConstant,
    kUnsupported,
    kUnknown,
};

struct GuestSysconfResolution {
    GuestSysconfKind kind = GuestSysconfKind::kUnknown;
    int host_name = 0;
    long value = 0;
};

GuestSysconfResolution resolve_guest_sysconf(int name) {
    switch (name) {
        case 0x0000: return {GuestSysconfKind::kHost, _SC_ARG_MAX, 0};                      // _SC_ARG_MAX
        case 0x0001: return {GuestSysconfKind::kHost, _SC_BC_BASE_MAX, 0};                  // _SC_BC_BASE_MAX
        case 0x0002: return {GuestSysconfKind::kHost, _SC_BC_DIM_MAX, 0};                   // _SC_BC_DIM_MAX
        case 0x0003: return {GuestSysconfKind::kHost, _SC_BC_SCALE_MAX, 0};                 // _SC_BC_SCALE_MAX
        case 0x0005: return {GuestSysconfKind::kHost, _SC_CHILD_MAX, 0};                    // _SC_CHILD_MAX
        case 0x0006: return {GuestSysconfKind::kHost, _SC_CLK_TCK, 0};                      // _SC_CLK_TCK
        case 0x0007: return {GuestSysconfKind::kHost, _SC_COLL_WEIGHTS_MAX, 0};             // _SC_COLL_WEIGHTS_MAX
        case 0x0008: return {GuestSysconfKind::kHost, _SC_EXPR_NEST_MAX, 0};                // _SC_EXPR_NEST_MAX
        case 0x0009: return {GuestSysconfKind::kHost, _SC_LINE_MAX, 0};                     // _SC_LINE_MAX
        case 0x000a: return {GuestSysconfKind::kHost, _SC_NGROUPS_MAX, 0};                  // _SC_NGROUPS_MAX
        case 0x000b: return {GuestSysconfKind::kHost, _SC_OPEN_MAX, 0};                     // _SC_OPEN_MAX
        case 0x000c: return {GuestSysconfKind::kHost, _SC_PASS_MAX, 0};                     // _SC_PASS_MAX
        case 0x000d: return {GuestSysconfKind::kHost, _SC_2_C_BIND, 0};                     // _SC_2_C_BIND
        case 0x000e: return {GuestSysconfKind::kUnsupported, 0, 0};                         // _SC_2_C_DEV
        case 0x0011: return {GuestSysconfKind::kUnsupported, 0, 0};                         // _SC_2_FORT_DEV
        case 0x0012: return {GuestSysconfKind::kUnsupported, 0, 0};                         // _SC_2_FORT_RUN
        case 0x0013: return {GuestSysconfKind::kUnsupported, 0, 0};                         // _SC_2_LOCALEDEF
        case 0x0014: return {GuestSysconfKind::kUnsupported, 0, 0};                         // _SC_2_SW_DEV
        case 0x0015: return {GuestSysconfKind::kUnsupported, 0, 0};                         // _SC_2_UPE
        case 0x0016: return {GuestSysconfKind::kHost, _SC_2_VERSION, 0};                    // _SC_2_VERSION
        case 0x0017: return {GuestSysconfKind::kHost, _SC_JOB_CONTROL, 0};                  // _SC_JOB_CONTROL
        case 0x0018: return {GuestSysconfKind::kHost, _SC_SAVED_IDS, 0};                    // _SC_SAVED_IDS
        case 0x0019: return {GuestSysconfKind::kHost, _SC_VERSION, 0};                      // _SC_VERSION
        case 0x001a: return {GuestSysconfKind::kHost, _SC_RE_DUP_MAX, 0};                   // _SC_RE_DUP_MAX
        case 0x001b: return {GuestSysconfKind::kHost, _SC_STREAM_MAX, 0};                   // _SC_STREAM_MAX
        case 0x001c: return {GuestSysconfKind::kHost, _SC_TZNAME_MAX, 0};                   // _SC_TZNAME_MAX
        case 0x001d: return {GuestSysconfKind::kUnsupported, 0, 0};                         // _SC_XOPEN_CRYPT
        case 0x0020: return {GuestSysconfKind::kHost, _SC_XOPEN_VERSION, 0};                // _SC_XOPEN_VERSION
        case 0x0024: return {GuestSysconfKind::kUnsupported, 0, 0};                         // _SC_XOPEN_LEGACY
        case 0x0025: return {GuestSysconfKind::kHost, _SC_ATEXIT_MAX, 0};                   // _SC_ATEXIT_MAX
        case 0x0026: return {GuestSysconfKind::kHost, _SC_IOV_MAX, 0};                      // _SC_IOV_MAX/_SC_UIO_MAXIOV
        case 0x0027: return {GuestSysconfKind::kConstant, 0, GUEST_PAGE_SIZE};              // _SC_PAGESIZE
        case 0x0028: return {GuestSysconfKind::kConstant, 0, GUEST_PAGE_SIZE};              // _SC_PAGE_SIZE
        case 0x0029: return {GuestSysconfKind::kHost, _SC_XOPEN_UNIX, 0};                   // _SC_XOPEN_UNIX
        case 0x002e: return {GuestSysconfKind::kHost, _SC_AIO_LISTIO_MAX, 0};               // _SC_AIO_LISTIO_MAX
        case 0x002f: return {GuestSysconfKind::kHost, _SC_AIO_MAX, 0};                      // _SC_AIO_MAX
        case 0x0030: return {GuestSysconfKind::kHost, _SC_AIO_PRIO_DELTA_MAX, 0};           // _SC_AIO_PRIO_DELTA_MAX
        case 0x0031: return {GuestSysconfKind::kHost, _SC_DELAYTIMER_MAX, 0};               // _SC_DELAYTIMER_MAX
        case 0x0032: return {GuestSysconfKind::kHost, _SC_MQ_OPEN_MAX, 0};                  // _SC_MQ_OPEN_MAX
        case 0x0033: return {GuestSysconfKind::kHost, _SC_MQ_PRIO_MAX, 0};                  // _SC_MQ_PRIO_MAX
        case 0x0034: return {GuestSysconfKind::kHost, _SC_RTSIG_MAX, 0};                    // _SC_RTSIG_MAX
        case 0x0035: return {GuestSysconfKind::kHost, _SC_SEM_NSEMS_MAX, 0};                // _SC_SEM_NSEMS_MAX
        case 0x0036: return {GuestSysconfKind::kConstant, 0, GUEST_SEM_VALUE_MAX};          // _SC_SEM_VALUE_MAX
        case 0x0038: return {GuestSysconfKind::kHost, _SC_TIMER_MAX, 0};                    // _SC_TIMER_MAX
        case 0x0039: return {GuestSysconfKind::kUnsupported, 0, 0};                         // _SC_ASYNCHRONOUS_IO
        case 0x003a: return {GuestSysconfKind::kHost, _SC_FSYNC, 0};                        // _SC_FSYNC
        case 0x003b: return {GuestSysconfKind::kHost, _SC_MAPPED_FILES, 0};                 // _SC_MAPPED_FILES
        case 0x003c: return {GuestSysconfKind::kHost, _SC_MEMLOCK, 0};                      // _SC_MEMLOCK
        case 0x003d: return {GuestSysconfKind::kHost, _SC_MEMLOCK_RANGE, 0};                // _SC_MEMLOCK_RANGE
        case 0x003e: return {GuestSysconfKind::kHost, _SC_MEMORY_PROTECTION, 0};            // _SC_MEMORY_PROTECTION
        case 0x003f: return {GuestSysconfKind::kUnsupported, 0, 0};                         // _SC_MESSAGE_PASSING
        case 0x0040: return {GuestSysconfKind::kUnsupported, 0, 0};                         // _SC_PRIORITIZED_IO
        case 0x0041: return {GuestSysconfKind::kHost, _SC_PRIORITY_SCHEDULING, 0};          // _SC_PRIORITY_SCHEDULING
        case 0x0042: return {GuestSysconfKind::kHost, _SC_REALTIME_SIGNALS, 0};             // _SC_REALTIME_SIGNALS
        case 0x0043: return {GuestSysconfKind::kHost, _SC_SEMAPHORES, 0};                   // _SC_SEMAPHORES
        case 0x0044: return {GuestSysconfKind::kUnsupported, 0, 0};                         // _SC_SHARED_MEMORY_OBJECTS
        case 0x0045: return {GuestSysconfKind::kHost, _SC_SYNCHRONIZED_IO, 0};              // _SC_SYNCHRONIZED_IO
        case 0x0046: return {GuestSysconfKind::kHost, _SC_TIMERS, 0};                       // _SC_TIMERS
        case 0x0047: return {GuestSysconfKind::kHost, _SC_GETGR_R_SIZE_MAX, 0};             // _SC_GETGR_R_SIZE_MAX
        case 0x0048: return {GuestSysconfKind::kHost, _SC_GETPW_R_SIZE_MAX, 0};             // _SC_GETPW_R_SIZE_MAX
        case 0x0049: return {GuestSysconfKind::kHost, _SC_LOGIN_NAME_MAX, 0};               // _SC_LOGIN_NAME_MAX
        case 0x004a: return {GuestSysconfKind::kHost, _SC_THREAD_DESTRUCTOR_ITERATIONS, 0}; // _SC_THREAD_DESTRUCTOR_ITERATIONS
        case 0x004b: return {GuestSysconfKind::kConstant, 0, 128};                          // _SC_THREAD_KEYS_MAX
        case 0x004c: return {GuestSysconfKind::kHost, _SC_THREAD_STACK_MIN, 0};             // _SC_THREAD_STACK_MIN
        case 0x004d: return {GuestSysconfKind::kHost, _SC_THREAD_THREADS_MAX, 0};           // _SC_THREAD_THREADS_MAX
        case 0x004e: return {GuestSysconfKind::kHost, _SC_TTY_NAME_MAX, 0};                 // _SC_TTY_NAME_MAX
        case 0x004f: return {GuestSysconfKind::kHost, _SC_THREADS, 0};                      // _SC_THREADS
        case 0x0050: return {GuestSysconfKind::kHost, _SC_THREAD_ATTR_STACKADDR, 0};        // _SC_THREAD_ATTR_STACKADDR
        case 0x0051: return {GuestSysconfKind::kHost, _SC_THREAD_ATTR_STACKSIZE, 0};        // _SC_THREAD_ATTR_STACKSIZE
        case 0x0052: return {GuestSysconfKind::kHost, _SC_THREAD_PRIORITY_SCHEDULING, 0};   // _SC_THREAD_PRIORITY_SCHEDULING
        case 0x0053: return {GuestSysconfKind::kUnsupported, 0, 0};                         // _SC_THREAD_PRIO_INHERIT
        case 0x0054: return {GuestSysconfKind::kUnsupported, 0, 0};                         // _SC_THREAD_PRIO_PROTECT
        case 0x0055: return {GuestSysconfKind::kHost, _SC_THREAD_SAFE_FUNCTIONS, 0};        // _SC_THREAD_SAFE_FUNCTIONS
        case 0x0060: return {GuestSysconfKind::kHost, _SC_NPROCESSORS_CONF, 0};             // _SC_NPROCESSORS_CONF
        case 0x0061: return {GuestSysconfKind::kHost, _SC_NPROCESSORS_ONLN, 0};             // _SC_NPROCESSORS_ONLN
        case 0x0062: return {GuestSysconfKind::kHost, _SC_PHYS_PAGES, 0};                   // _SC_PHYS_PAGES
        case 0x0063: return {GuestSysconfKind::kHost, _SC_AVPHYS_PAGES, 0};                 // _SC_AVPHYS_PAGES
        case 0x0064: return {GuestSysconfKind::kHost, _SC_MONOTONIC_CLOCK, 0};              // _SC_MONOTONIC_CLOCK
        case 0x0065: return {GuestSysconfKind::kUnsupported, 0, 0};                         // _SC_2_PBS
        case 0x0066: return {GuestSysconfKind::kUnsupported, 0, 0};                         // _SC_2_PBS_ACCOUNTING
        case 0x0067: return {GuestSysconfKind::kUnsupported, 0, 0};                         // _SC_2_PBS_CHECKPOINT
        case 0x0068: return {GuestSysconfKind::kUnsupported, 0, 0};                         // _SC_2_PBS_LOCATE
        case 0x0069: return {GuestSysconfKind::kUnsupported, 0, 0};                         // _SC_2_PBS_MESSAGE
        case 0x006a: return {GuestSysconfKind::kUnsupported, 0, 0};                         // _SC_2_PBS_TRACK
        case 0x006b: return {GuestSysconfKind::kHost, _SC_ADVISORY_INFO, 0};                // _SC_ADVISORY_INFO
        case 0x006c: return {GuestSysconfKind::kHost, _SC_BARRIERS, 0};                     // _SC_BARRIERS
        case 0x006d: return {GuestSysconfKind::kHost, _SC_CLOCK_SELECTION, 0};              // _SC_CLOCK_SELECTION
        case 0x006e: return {GuestSysconfKind::kHost, _SC_CPUTIME, 0};                      // _SC_CPUTIME
        case 0x006f: return {GuestSysconfKind::kHost, _SC_HOST_NAME_MAX, 0};                // _SC_HOST_NAME_MAX
        case 0x0070: return {GuestSysconfKind::kHost, _SC_IPV6, 0};                         // _SC_IPV6
        case 0x0071: return {GuestSysconfKind::kHost, _SC_RAW_SOCKETS, 0};                  // _SC_RAW_SOCKETS
        case 0x0072: return {GuestSysconfKind::kHost, _SC_READER_WRITER_LOCKS, 0};          // _SC_READER_WRITER_LOCKS
        case 0x0073: return {GuestSysconfKind::kHost, _SC_REGEXP, 0};                       // _SC_REGEXP
        case 0x0074: return {GuestSysconfKind::kHost, _SC_SHELL, 0};                        // _SC_SHELL
        case 0x0075: return {GuestSysconfKind::kHost, _SC_SPAWN, 0};                        // _SC_SPAWN
        case 0x0076: return {GuestSysconfKind::kHost, _SC_SPIN_LOCKS, 0};                   // _SC_SPIN_LOCKS
        case 0x0077: return {GuestSysconfKind::kUnsupported, 0, 0};                         // _SC_SPORADIC_SERVER
        case 0x0079: return {GuestSysconfKind::kHost, _SC_SYMLOOP_MAX, 0};                  // _SC_SYMLOOP_MAX
        case 0x007a: return {GuestSysconfKind::kHost, _SC_THREAD_CPUTIME, 0};               // _SC_THREAD_CPUTIME
        case 0x007b: return {GuestSysconfKind::kHost, _SC_THREAD_PROCESS_SHARED, 0};        // _SC_THREAD_PROCESS_SHARED
        case 0x007c: return {GuestSysconfKind::kUnsupported, 0, 0};                         // _SC_THREAD_ROBUST_PRIO_INHERIT
        case 0x007d: return {GuestSysconfKind::kUnsupported, 0, 0};                         // _SC_THREAD_ROBUST_PRIO_PROTECT
        case 0x007e: return {GuestSysconfKind::kUnsupported, 0, 0};                         // _SC_THREAD_SPORADIC_SERVER
        case 0x007f: return {GuestSysconfKind::kHost, _SC_TIMEOUTS, 0};                     // _SC_TIMEOUTS
        case 0x0080: return {GuestSysconfKind::kUnsupported, 0, 0};                         // _SC_TRACE
        case 0x0081: return {GuestSysconfKind::kUnsupported, 0, 0};                         // _SC_TRACE_EVENT_FILTER
        case 0x0082: return {GuestSysconfKind::kUnsupported, 0, 0};                         // _SC_TRACE_EVENT_NAME_MAX
        case 0x0083: return {GuestSysconfKind::kUnsupported, 0, 0};                         // _SC_TRACE_INHERIT
        case 0x0084: return {GuestSysconfKind::kUnsupported, 0, 0};                         // _SC_TRACE_LOG
        case 0x0085: return {GuestSysconfKind::kUnsupported, 0, 0};                         // _SC_TRACE_NAME_MAX
        case 0x0086: return {GuestSysconfKind::kUnsupported, 0, 0};                         // _SC_TRACE_SYS_MAX
        case 0x0087: return {GuestSysconfKind::kUnsupported, 0, 0};                         // _SC_TRACE_USER_EVENT_MAX
        case 0x0088: return {GuestSysconfKind::kUnsupported, 0, 0};                         // _SC_TYPED_MEMORY_OBJECTS
        case 0x0089: return {GuestSysconfKind::kUnsupported, 0, 0};                         // _SC_V7_ILP32_OFF32
        case 0x008a: return {GuestSysconfKind::kUnsupported, 0, 0};                         // _SC_V7_ILP32_OFFBIG
        case 0x008b: return {GuestSysconfKind::kHost, _SC_V7_LP64_OFF64, 0};                // _SC_V7_LP64_OFF64
        case 0x008c: return {GuestSysconfKind::kHost, _SC_V7_LPBIG_OFFBIG, 0};              // _SC_V7_LPBIG_OFFBIG
        case 0x008d: return {GuestSysconfKind::kUnsupported, 0, 0};                         // _SC_XOPEN_STREAMS
        case 0x008e: return {GuestSysconfKind::kUnsupported, 0, 0};                         // _SC_XOPEN_UUCP
        case 0x008f: return {GuestSysconfKind::kHost, _SC_LEVEL1_ICACHE_SIZE, 0};           // _SC_LEVEL1_ICACHE_SIZE
        case 0x0090: return {GuestSysconfKind::kHost, _SC_LEVEL1_ICACHE_ASSOC, 0};          // _SC_LEVEL1_ICACHE_ASSOC
        case 0x0091: return {GuestSysconfKind::kHost, _SC_LEVEL1_ICACHE_LINESIZE, 0};       // _SC_LEVEL1_ICACHE_LINESIZE
        case 0x0092: return {GuestSysconfKind::kHost, _SC_LEVEL1_DCACHE_SIZE, 0};           // _SC_LEVEL1_DCACHE_SIZE
        case 0x0093: return {GuestSysconfKind::kHost, _SC_LEVEL1_DCACHE_ASSOC, 0};          // _SC_LEVEL1_DCACHE_ASSOC
        case 0x0094: return {GuestSysconfKind::kHost, _SC_LEVEL1_DCACHE_LINESIZE, 0};       // _SC_LEVEL1_DCACHE_LINESIZE
        case 0x0095: return {GuestSysconfKind::kHost, _SC_LEVEL2_CACHE_SIZE, 0};            // _SC_LEVEL2_CACHE_SIZE
        case 0x0096: return {GuestSysconfKind::kHost, _SC_LEVEL2_CACHE_ASSOC, 0};           // _SC_LEVEL2_CACHE_ASSOC
        case 0x0097: return {GuestSysconfKind::kHost, _SC_LEVEL2_CACHE_LINESIZE, 0};        // _SC_LEVEL2_CACHE_LINESIZE
        case 0x0098: return {GuestSysconfKind::kHost, _SC_LEVEL3_CACHE_SIZE, 0};            // _SC_LEVEL3_CACHE_SIZE
        case 0x0099: return {GuestSysconfKind::kHost, _SC_LEVEL3_CACHE_ASSOC, 0};           // _SC_LEVEL3_CACHE_ASSOC
        case 0x009a: return {GuestSysconfKind::kHost, _SC_LEVEL3_CACHE_LINESIZE, 0};        // _SC_LEVEL3_CACHE_LINESIZE
        case 0x009b: return {GuestSysconfKind::kHost, _SC_LEVEL4_CACHE_SIZE, 0};            // _SC_LEVEL4_CACHE_SIZE
        case 0x009c: return {GuestSysconfKind::kHost, _SC_LEVEL4_CACHE_ASSOC, 0};           // _SC_LEVEL4_CACHE_ASSOC
        case 0x009d: return {GuestSysconfKind::kHost, _SC_LEVEL4_CACHE_LINESIZE, 0};        // _SC_LEVEL4_CACHE_LINESIZE
        case 0x009e: return {GuestSysconfKind::kConstant, 0, static_cast<long>(NSIG)};      // _SC_NSIG
        default:     return {GuestSysconfKind::kUnknown, 0, 0};
    }
}

std::string read_string(Emulator& emu, uint64_t addr, size_t max_len = 4096) {
    std::string result;
    char c = '\0';
    for (size_t i = 0; i < max_len; ++i) {
        if (!emu.mem_read(addr + i, &c, 1) || c == '\0') {
            break;
        }
        result += c;
    }
    return result;
}

bool format_contains_conversion(const std::string& format, char code) {
    for (size_t i = 0; i < format.size(); ++i) {
        if (format[i] != '%') {
            continue;
        }
        ++i;
        if (i >= format.size()) {
            break;
        }
        if (format[i] == '%') {
            continue;
        }
        if (format[i] == code) {
            return true;
        }
    }
    return false;
}

int64_t timespec_to_ns(const struct timespec& ts) {
    return static_cast<int64_t>(ts.tv_sec) * 1000000000LL + static_cast<int64_t>(ts.tv_nsec);
}

int64_t timespec_to_ns(const timespec_arm64& ts) {
    return static_cast<int64_t>(ts.tv_sec) * 1000000000LL + static_cast<int64_t>(ts.tv_nsec);
}

timespec_arm64 ns_to_guest_timespec(int64_t ns) {
    if (ns < 0) {
        ns = 0;
    }
    timespec_arm64 out{};
    out.tv_sec = ns / 1000000000LL;
    out.tv_nsec = ns % 1000000000LL;
    return out;
}

bool valid_timespec(const struct timespec& ts) {
    return ts.tv_sec >= 0 && ts.tv_nsec >= 0 && ts.tv_nsec < 1000000000L;
}

int64_t now_ns_for_clock(int clock_id) {
    struct timespec ts{};
    if (::clock_gettime(clock_id, &ts) != 0) {
        return -1;
    }
    return timespec_to_ns(ts);
}

int map_timespec_base_to_clock(int base) {
    switch (base) {
        case CLOCK_REALTIME + 1:
            return CLOCK_REALTIME;
        case CLOCK_MONOTONIC + 1:
            return CLOCK_MONOTONIC;
        case CLOCK_PROCESS_CPUTIME_ID + 1:
            return CLOCK_PROCESS_CPUTIME_ID;
        case CLOCK_THREAD_CPUTIME_ID + 1:
            return CLOCK_THREAD_CPUTIME_ID;
        default:
            return -1;
    }
}

std::string detect_system_timezone_id() {
    char link_buf[PATH_MAX + 1] = {};
    ssize_t link_len = ::readlink("/etc/localtime", link_buf, PATH_MAX);
    if (link_len > 0) {
        link_buf[link_len] = '\0';
        std::string link_target(link_buf);
        const std::string marker = "/zoneinfo/";
        size_t marker_pos = link_target.find(marker);
        if (marker_pos != std::string::npos) {
            return link_target.substr(marker_pos + marker.size());
        }
    }

    FILE* tz_file = std::fopen("/etc/timezone", "r");
    if (tz_file != nullptr) {
        char line[256] = {};
        if (std::fgets(line, sizeof(line), tz_file) != nullptr) {
            std::fclose(tz_file);
            std::string result(line);
            while (!result.empty() && (result.back() == '\n' || result.back() == '\r')) {
                result.pop_back();
            }
            if (!result.empty()) {
                return result;
            }
        } else {
            std::fclose(tz_file);
        }
    }

    return "UTC";
}

bool timezone_exists(const std::string& zone_id) {
    if (zone_id.empty()) {
        return false;
    }
    std::string path = "/usr/share/zoneinfo/" + zone_id;
    return ::access(path.c_str(), F_OK) == 0;
}

std::optional<std::string> get_env_var_locked(const char* name) {
    const char* value = std::getenv(name);
    if (value == nullptr) {
        return std::nullopt;
    }
    return std::string(value);
}

class ScopedTimezoneOverride {
public:
    explicit ScopedTimezoneOverride(const std::string& zone_id)
        : had_original_(false) {
        std::optional<std::string> original = get_env_var_locked("TZ");
        if (original.has_value()) {
            had_original_ = true;
            original_tz_ = *original;
        }
        ::setenv("TZ", zone_id.c_str(), 1);
        ::tzset();
    }

    ~ScopedTimezoneOverride() {
        if (had_original_) {
            ::setenv("TZ", original_tz_.c_str(), 1);
        } else {
            ::unsetenv("TZ");
        }
        ::tzset();
    }

private:
    bool had_original_;
    std::string original_tz_;
};

uint64_t cache_guest_string_locked(Emulator& emu, const std::string& value) {
    if (value.empty()) {
        return 0;
    }
    auto it = g_guest_string_cache.find(value);
    if (it != g_guest_string_cache.end()) {
        return it->second;
    }

    uint64_t addr = emu.memory().heap().allocate(value.size() + 1, 8);
    emu.mem_write(addr, value.c_str(), value.size() + 1);
    g_guest_string_cache[value] = addr;
    return addr;
}

void guest_tm_to_host_tm(Emulator& emu, const tm_arm64& guest_tm, struct tm& host_tm, std::string& zone_storage) {
    arm64_to_host_tm(guest_tm, host_tm);
    zone_storage.clear();
    if (guest_tm.tm_zone != 0) {
        zone_storage = read_string(emu, guest_tm.tm_zone, MAX_STRPTIME_ZONE_LEN);
        if (!zone_storage.empty()) {
            host_tm.tm_zone = zone_storage.data();
        }
    }
}

void host_tm_to_guest_tm_locked(Emulator& emu, uint64_t tm_addr, const struct tm& host_tm,
                                const std::string* explicit_zone = nullptr) {
    std::string zone_name;
    if (explicit_zone != nullptr) {
        zone_name = *explicit_zone;
    } else if (host_tm.tm_zone != nullptr) {
        zone_name = host_tm.tm_zone;
    }

    tm_arm64 guest_tm{};
    host_to_arm64_tm(host_tm, guest_tm, cache_guest_string_locked(emu, zone_name));
    emu.mem_write(tm_addr, &guest_tm, sizeof(guest_tm));
}

void load_guest_tm(Emulator& emu, uint64_t tm_addr, tm_arm64& guest_tm, struct tm& host_tm,
                   std::string& zone_storage) {
    emu.mem_read(tm_addr, &guest_tm, sizeof(guest_tm));
    guest_tm_to_host_tm(emu, guest_tm, host_tm, zone_storage);
}

CurrentTimezoneInfo query_current_timezone_info_locked() {
    ::tzset();

    CurrentTimezoneInfo info;
    if (tzname[0] != nullptr) {
        info.std_name = tzname[0];
    }
    if (tzname[1] != nullptr) {
        info.dst_name = tzname[1];
    }

    auto sample_local_time = [](int year, int month, int day) {
        struct tm tm_val{};
        tm_val.tm_year = year - 1900;
        tm_val.tm_mon = month - 1;
        tm_val.tm_mday = day;
        tm_val.tm_hour = 12;
        tm_val.tm_isdst = -1;
        ::mktime(&tm_val);
        return tm_val;
    };

    struct tm jan = sample_local_time(2024, 1, 15);
    struct tm jul = sample_local_time(2024, 7, 15);

    auto absorb_sample = [&](const struct tm& sample) {
        if (sample.tm_isdst > 0) {
            info.has_dst = true;
            info.dst_offset = sample.tm_gmtoff;
            if (info.dst_name.empty() && sample.tm_zone != nullptr) {
                info.dst_name = sample.tm_zone;
            }
        } else {
            info.std_offset = sample.tm_gmtoff;
            if (info.std_name.empty() && sample.tm_zone != nullptr) {
                info.std_name = sample.tm_zone;
            }
        }
    };

    absorb_sample(jan);
    absorb_sample(jul);
    if (!info.has_dst) {
        info.dst_offset = info.std_offset;
    }
    return info;
}

bool timezone_has_dst_locked(const std::optional<std::string>& zone_id = std::nullopt) {
    if (zone_id.has_value()) {
        ScopedTimezoneOverride scoped(*zone_id);
        return query_current_timezone_info_locked().has_dst;
    }
    return query_current_timezone_info_locked().has_dst;
}

bool invalid_positive_dst_request_locked(const tm_arm64& guest_tm,
                                         const std::optional<std::string>& zone_id = std::nullopt) {
    if (guest_tm.tm_isdst <= 0) {
        return false;
    }
    return !timezone_has_dst_locked(zone_id);
}

bool timer_owned_by_current_process(const GuestTimer& timer) {
    return timer.owner_pid == ::getpid();
}

void synthesize_zone_for_strftime_locked(const std::string& format, const tm_arm64& guest_tm,
                                         struct tm& host_tm, std::string& zone_storage) {
    if (guest_tm.tm_zone != 0 || !format_contains_conversion(format, 'Z') || host_tm.tm_isdst < 0) {
        return;
    }

    CurrentTimezoneInfo tz_info = query_current_timezone_info_locked();
    if (host_tm.tm_isdst == 0) {
        if (!tz_info.std_name.empty()) {
            zone_storage = tz_info.std_name;
            host_tm.tm_zone = zone_storage.data();
            host_tm.tm_gmtoff = tz_info.std_offset;
        }
        return;
    }

    if (host_tm.tm_isdst > 0 && tz_info.has_dst &&
        !tz_info.dst_name.empty() && tz_info.dst_name != tz_info.std_name) {
        zone_storage = tz_info.dst_name;
        host_tm.tm_zone = zone_storage.data();
        host_tm.tm_gmtoff = tz_info.dst_offset;
    }
}

bool parse_numeric_offset(const std::string& text, long& gmtoff_seconds) {
    if (text.empty()) {
        return false;
    }

    int sign = 1;
    size_t pos = 0;
    if (text[pos] == '+') {
        sign = 1;
        ++pos;
    } else if (text[pos] == '-') {
        sign = -1;
        ++pos;
    } else {
        return false;
    }

    auto parse_two = [&](size_t index) -> int {
        if (index + 1 >= text.size() || !std::isdigit(text[index]) || !std::isdigit(text[index + 1])) {
            return -1;
        }
        return (text[index] - '0') * 10 + (text[index + 1] - '0');
    };

    int hour = -1;
    int minute = 0;
    if (text.size() == pos + 2) {
        hour = parse_two(pos);
    } else if (text.size() == pos + 4) {
        hour = parse_two(pos);
        minute = parse_two(pos + 2);
    } else if (text.size() == pos + 5 && text[pos + 2] == ':') {
        hour = parse_two(pos);
        minute = parse_two(pos + 3);
    } else {
        return false;
    }

    if (hour < 0 || minute < 0 || hour > 23 || minute > 59) {
        return false;
    }

    gmtoff_seconds = sign * (hour * 3600 + minute * 60);
    return true;
}

bool parse_special_offset(const std::string& text, struct tm& host_tm, std::optional<std::string>& zone_name) {
    if (text == "UT" || text == "GMT" || text == "Z") {
        host_tm.tm_isdst = 0;
        host_tm.tm_gmtoff = 0;
        zone_name = "UTC";
        return true;
    }
    if (text == "PST") {
        host_tm.tm_isdst = 0;
        host_tm.tm_gmtoff = -8 * 3600;
        zone_name = "PST";
        return true;
    }
    if (text == "PDT") {
        host_tm.tm_isdst = 1;
        host_tm.tm_gmtoff = -7 * 3600;
        zone_name = "PDT";
        return true;
    }

    long gmtoff = 0;
    if (!parse_numeric_offset(text, gmtoff)) {
        return false;
    }

    host_tm.tm_isdst = 0;
    host_tm.tm_gmtoff = gmtoff;
    zone_name.reset();
    return true;
}

bool parse_named_timezone_locked(const std::string& text, struct tm& host_tm, std::optional<std::string>& zone_name) {
    if (text == "GMT") {
        host_tm.tm_isdst = 0;
        host_tm.tm_gmtoff = 0;
        zone_name = "GMT";
        return true;
    }
    if (text == "UTC") {
        host_tm.tm_isdst = 0;
        host_tm.tm_gmtoff = 0;
        zone_name = "UTC";
        return true;
    }

    CurrentTimezoneInfo tz_info = query_current_timezone_info_locked();
    if (!tz_info.std_name.empty() && text == tz_info.std_name) {
        host_tm.tm_isdst = 0;
        host_tm.tm_gmtoff = tz_info.std_offset;
        zone_name = text;
        return true;
    }
    if (tz_info.has_dst && !tz_info.dst_name.empty() && text == tz_info.dst_name) {
        host_tm.tm_isdst = 1;
        host_tm.tm_gmtoff = tz_info.std_offset;
        zone_name = text;
        return true;
    }
    return false;
}

std::string translate_strptime_format(const std::string& format) {
    std::string translated;
    translated.reserve(format.size() + 8);

    for (size_t i = 0; i < format.size(); ++i) {
        if (format[i] == '%' && i + 1 < format.size()) {
            char code = format[i + 1];
            if (code == 'P') {
                translated += "%p";
                ++i;
                continue;
            }
            if (code == 'v') {
                translated += "%e-%b-%Y";
                ++i;
                continue;
            }
        }
        translated += format[i];
    }
    return translated;
}

bool process_strptime_locked(Emulator& emu, uint64_t s_addr, const std::string& input,
                             const std::string& format, uint64_t tm_addr, uint64_t locale_addr,
                             uint64_t* result_addr) {
    (void)locale_addr;

    tm_arm64 guest_tm{};
    struct tm host_tm{};
    std::string zone_storage;
    load_guest_tm(emu, tm_addr, guest_tm, host_tm, zone_storage);

    std::optional<std::string> parsed_zone;
    const char* result = nullptr;

    if (format == "%p" || format == "%P") {
        std::string lower = input;
        std::transform(lower.begin(), lower.end(), lower.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (lower == "am") {
            if (host_tm.tm_hour == 12) {
                host_tm.tm_hour = 0;
            }
            result = input.c_str() + input.size();
        } else if (lower == "pm") {
            if (host_tm.tm_hour < 12) {
                host_tm.tm_hour += 12;
            }
            result = input.c_str() + input.size();
        }
    } else if (format == "%Z") {
        if (parse_named_timezone_locked(input, host_tm, parsed_zone)) {
            result = input.c_str() + input.size();
        }
    } else if (format == "%z") {
        if (parse_special_offset(input, host_tm, parsed_zone)) {
            result = input.c_str() + input.size();
        }
    } else {
        std::string translated = translate_strptime_format(format);
        result = ::strptime(input.c_str(), translated.c_str(), &host_tm);
        if (result != nullptr && host_tm.tm_zone != nullptr) {
            parsed_zone = std::string(host_tm.tm_zone);
        }
    }

    if (result == nullptr) {
        *result_addr = 0;
        return false;
    }

    host_tm_to_guest_tm_locked(emu, tm_addr, host_tm, parsed_zone ? &*parsed_zone : nullptr);
    *result_addr = s_addr + static_cast<uint64_t>(result - input.c_str());
    return true;
}

bool manual_strftime_zone_only_locked(const std::string& format, const tm_arm64& guest_tm,
                                      const struct tm& host_tm, std::string& output) {
    if (guest_tm.tm_zone != 0 || format != "<%Z>") {
        return false;
    }

    std::string zone_name;
    if (host_tm.tm_isdst == 0) {
        CurrentTimezoneInfo tz_info = query_current_timezone_info_locked();
        zone_name = tz_info.std_name;
    } else if (host_tm.tm_isdst > 0) {
        CurrentTimezoneInfo tz_info = query_current_timezone_info_locked();
        if (tz_info.has_dst && !tz_info.dst_name.empty() && tz_info.dst_name != tz_info.std_name) {
            zone_name = tz_info.dst_name;
        }
    }

    output = "<" + zone_name + ">";
    return true;
}

void read_guest_itimerspec(Emulator& emu, uint64_t addr, itimerspec_arm64& spec) {
    std::memset(&spec, 0, sizeof(spec));
    if (addr != 0) {
        emu.mem_read(addr, &spec, sizeof(spec));
    }
}

void write_guest_itimerspec(Emulator& emu, uint64_t addr, int64_t value_ns, int64_t interval_ns) {
    if (addr == 0) {
        return;
    }
    itimerspec_arm64 spec{};
    spec.it_value = ns_to_guest_timespec(value_ns);
    spec.it_interval = ns_to_guest_timespec(interval_ns);
    emu.mem_write(addr, &spec, sizeof(spec));
}

std::optional<int64_t> next_timer_deadline_delta_ns_locked() {
    std::optional<int64_t> best;
    for (const auto& [id, timer] : g_timers) {
        (void)id;
        if (timer.deleted || !timer.armed || !timer_owned_by_current_process(timer)) {
            continue;
        }
        int64_t now_ns = now_ns_for_clock(timer.clock_id);
        if (now_ns < 0) {
            continue;
        }
        int64_t delta = timer.due_ns - now_ns;
        if (!best.has_value() || delta < *best) {
            best = delta;
        }
    }
    return best;
}

void process_due_timers(Emulator& emu) {
    if (tl_processing_timers) {
        return;
    }

    tl_processing_timers = true;
    struct DueEvent {
        uint64_t timer_id;
        int notify;
        int signo;
        uint64_t callback;
        uint64_t sigval_raw;
        uint64_t virtual_tid;
    };

    std::vector<DueEvent> due_events;
    {
        std::lock_guard<std::recursive_mutex> lock(g_time_state_mutex);
        for (auto& [timer_id, timer] : g_timers) {
            if (timer.deleted || !timer.armed || timer.in_callback ||
                !timer_owned_by_current_process(timer)) {
                continue;
            }

            int64_t now_ns = now_ns_for_clock(timer.clock_id);
            if (now_ns < 0 || now_ns < timer.due_ns) {
                continue;
            }

            timer.in_callback = true;
            uint64_t virtual_tid = 0;
            if (timer.notify == SIGEV_THREAD) {
                virtual_tid = hle_virtual_thread_allocate();
                timer.active_virtual_tid = virtual_tid;
            }

            due_events.push_back({timer_id, timer.notify, timer.signo, timer.callback,
                                  timer.sigval_raw, virtual_tid});

            if (timer.interval_ns > 0) {
                timer.due_ns += timer.interval_ns;
                if (timer.due_ns <= now_ns) {
                    timer.due_ns = now_ns + timer.interval_ns;
                }
            } else {
                timer.armed = false;
            }
        }
    }

    for (const DueEvent& event : due_events) {
        if (event.notify == SIGEV_SIGNAL) {
#ifdef SI_TIMER
            int si_code = SI_TIMER;
#else
            int si_code = SI_USER;
#endif
            hle_signal_queue(emu, event.signo, si_code, static_cast<int32_t>(event.sigval_raw), true);
        } else if (event.notify == SIGEV_THREAD && event.callback != 0) {
            EMU_LOG << "[HLE_TIME] timer callback: timer_id=0x" << std::hex
                    << event.timer_id
                    << " callback=0x" << event.callback
                    << " sigval=0x" << event.sigval_raw
                    << " virtual_tid=0x" << event.virtual_tid
                    << std::dec << std::endl;
            uint64_t previous_override = hle_virtual_thread_current_override();
            hle_virtual_thread_set_current_override(event.virtual_tid);
            emu.call_function_safe(event.callback, {event.sigval_raw});
            hle_virtual_thread_set_current_override(previous_override);
            hle_virtual_thread_set_alive(event.virtual_tid, false);
        }

        std::lock_guard<std::recursive_mutex> lock(g_time_state_mutex);
        auto timer_it = g_timers.find(event.timer_id);
        if (timer_it != g_timers.end()) {
            timer_it->second.in_callback = false;
            timer_it->second.active_virtual_tid = 0;
            if (timer_it->second.deleted) {
                g_timers.erase(timer_it);
            }
        }
    }
    tl_processing_timers = false;
}

int sleep_with_timer_processing(Emulator& emu, int clock_id, int flags,
                                const struct timespec& req, struct timespec* rem_out) {
    if (!valid_timespec(req)) {
        return EINVAL;
    }

    if (clock_id != CLOCK_REALTIME && clock_id != CLOCK_MONOTONIC) {
        return EINVAL;
    }

    constexpr int kTimerAbstime = 1;  // TIMER_ABSTIME
    if (flags != 0 && flags != kTimerAbstime) {
        return EINVAL;
    }

    int64_t start_ns = now_ns_for_clock(clock_id);
    if (start_ns < 0) {
        return EINVAL;
    }
    // TIMER_ABSTIME: `req` is an absolute deadline in `clock_id`'s timescale (used by
    // CPython's time.sleep via clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, ...)).
    // Otherwise it is a relative duration. An already-past absolute deadline returns
    // immediately (the loop below exits at once).
    int64_t deadline_ns = (flags == kTimerAbstime)
                              ? timespec_to_ns(req)
                              : start_ns + timespec_to_ns(req);

    while (true) {
        process_due_timers(emu);

        int64_t now_ns = now_ns_for_clock(clock_id);
        if (now_ns < 0 || now_ns >= deadline_ns) {
            break;
        }

        int64_t remaining_ns = deadline_ns - now_ns;
        int64_t chunk_ns = std::min<int64_t>(remaining_ns, 10LL * 1000 * 1000);
        {
            std::lock_guard<std::recursive_mutex> lock(g_time_state_mutex);
            std::optional<int64_t> next_due = next_timer_deadline_delta_ns_locked();
            if (next_due.has_value() && *next_due > 0) {
                chunk_ns = std::min<int64_t>(chunk_ns, *next_due);
            }
        }
        if (chunk_ns <= 0) {
            chunk_ns = 1000;
        }
        // Step out of QEMU's CPU exec/exclusive state while blocking so this sleeping
        // vCPU doesn't stall tb_flush / thread creation (the reason usleep was previously
        // routed natively). Timer delivery (process_due_timers above) runs guest code and
        // stays inside the exec state; only the host sleep is done suspended.
        emu.cpu_exec_suspend();
        std::this_thread::sleep_for(std::chrono::nanoseconds(chunk_ns));
        emu.cpu_exec_resume();
    }

    if (rem_out != nullptr) {
        rem_out->tv_sec = 0;
        rem_out->tv_nsec = 0;
    }
    return 0;
}

} // namespace

uint64_t hle_virtual_thread_current_override() {
    return tl_virtual_tid_override;
}

void hle_virtual_thread_set_current_override(uint64_t tid) {
    tl_virtual_tid_override = tid;
}

uint64_t hle_virtual_thread_allocate() {
    uint64_t tid = g_next_virtual_tid.fetch_add(1, std::memory_order_relaxed);
    hle_virtual_thread_set_alive(tid, true);
    return tid;
}

void hle_virtual_thread_set_alive(uint64_t tid, bool alive) {
    (void)tid;
    (void)alive;
}

bool hle_virtual_thread_is_alive(uint64_t tid) {
    std::lock_guard<std::recursive_mutex> lock(g_time_state_mutex);
    for (const auto& [timer_id, timer] : g_timers) {
        (void)timer_id;
        if (timer.active_virtual_tid == tid && timer.in_callback && !timer.deleted) {
            return true;
        }
    }
    return false;
}

bool hle_virtual_thread_is_virtual(uint64_t tid) {
    return tid >= VIRTUAL_THREAD_BASE;
}

void register_hle_time(HleManager& hle) {
    hle.register_function("time", [](Emulator& emu) {
        process_due_timers(emu);
        uint64_t tloc = get_reg(emu, UC_ARM64_REG_X0);
        time_t t = ::time(nullptr);
        if (tloc != 0) {
            emu.mem_write(tloc, &t, sizeof(t));
        }
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(t));
    });

    hle.register_function("gettimeofday", [](Emulator& emu) {
        process_due_timers(emu);
        uint64_t tv_addr = get_reg(emu, UC_ARM64_REG_X0);

        struct timeval tv{};
        int result = ::gettimeofday(&tv, nullptr);
        if (result == 0 && tv_addr != 0) {
            timeval_arm64 guest_tv{};
            host_to_arm64_timeval(tv, guest_tv);
            emu.mem_write(tv_addr, &guest_tv, sizeof(guest_tv));
        } else if (result != 0) {
            hle_set_errno(emu, errno);
        }
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(result));
    });

    hle.register_function("clock_gettime", [](Emulator& emu) {
        process_due_timers(emu);
        int clk_id = static_cast<int>(get_reg(emu, UC_ARM64_REG_X0));
        uint64_t tp_addr = get_reg(emu, UC_ARM64_REG_X1);

        struct timespec ts{};
        int result = ::clock_gettime(clk_id, &ts);
        if (result == 0 && tp_addr != 0) {
            timespec_arm64 guest_ts{};
            host_to_arm64_timespec(ts, guest_ts);
            emu.mem_write(tp_addr, &guest_ts, sizeof(guest_ts));
        } else if (result != 0) {
            EMU_LOG << "[HLE_TIME] clock_gettime failed: clk_id=" << clk_id
                    << " errno=" << errno << std::endl;
            hle_set_errno(emu, errno);
        }
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(result));
    });

    hle.register_function("localtime_r", [](Emulator& emu) {
        process_due_timers(emu);
        uint64_t timep = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t result_addr = get_reg(emu, UC_ARM64_REG_X1);

        time_t t = 0;
        emu.mem_read(timep, &t, sizeof(t));

        struct tm result{};
        {
            std::lock_guard<std::recursive_mutex> lock(g_time_state_mutex);
            ::tzset();
            ::localtime_r(&t, &result);
            host_tm_to_guest_tm_locked(emu, result_addr, result);
        }
        set_reg(emu, UC_ARM64_REG_X0, result_addr);
    });

    hle.register_function("gmtime_r", [](Emulator& emu) {
        process_due_timers(emu);
        uint64_t timep = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t result_addr = get_reg(emu, UC_ARM64_REG_X1);

        time_t t = 0;
        emu.mem_read(timep, &t, sizeof(t));

        struct tm result{};
        ::gmtime_r(&t, &result);
        std::lock_guard<std::recursive_mutex> lock(g_time_state_mutex);
        host_tm_to_guest_tm_locked(emu, result_addr, result);
        set_reg(emu, UC_ARM64_REG_X0, result_addr);
    });

    hle.register_function("localtime", [](Emulator& emu) {
        process_due_timers(emu);
        uint64_t timep = get_reg(emu, UC_ARM64_REG_X0);

        time_t t = 0;
        emu.mem_read(timep, &t, sizeof(t));

        struct tm result{};
        {
            std::lock_guard<std::recursive_mutex> lock(g_time_state_mutex);
            ::tzset();
            ::localtime_r(&t, &result);
            host_tm_to_guest_tm_locked(emu, LOCALTIME_BUF, result);
        }
        set_reg(emu, UC_ARM64_REG_X0, LOCALTIME_BUF);
    });

    hle.register_function("gmtime", [](Emulator& emu) {
        process_due_timers(emu);
        uint64_t timep = get_reg(emu, UC_ARM64_REG_X0);

        time_t t = 0;
        emu.mem_read(timep, &t, sizeof(t));

        struct tm result{};
        ::gmtime_r(&t, &result);
        std::lock_guard<std::recursive_mutex> lock(g_time_state_mutex);
        host_tm_to_guest_tm_locked(emu, GMTIME_BUF, result);
        set_reg(emu, UC_ARM64_REG_X0, GMTIME_BUF);
    });

    hle.register_function("mktime", [](Emulator& emu) {
        process_due_timers(emu);
        uint64_t tm_addr = get_reg(emu, UC_ARM64_REG_X0);

        tm_arm64 guest_tm{};
        struct tm host_tm{};
        std::string zone_storage;
        load_guest_tm(emu, tm_addr, guest_tm, host_tm, zone_storage);

        errno = 0;
        time_t result = 0;
        {
            std::lock_guard<std::recursive_mutex> lock(g_time_state_mutex);
            if (invalid_positive_dst_request_locked(guest_tm)) {
                errno = EOVERFLOW;
                result = static_cast<time_t>(-1);
            } else {
                result = ::mktime(&host_tm);
            }
            host_tm_to_guest_tm_locked(emu, tm_addr, host_tm);
        }

        if (result == static_cast<time_t>(-1) && errno != 0) {
            hle_set_errno(emu, errno);
        }
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(result));
    });

    hle.register_function("strftime", [](Emulator& emu) {
        process_due_timers(emu);
        uint64_t s = get_reg(emu, UC_ARM64_REG_X0);
        size_t max = static_cast<size_t>(get_reg(emu, UC_ARM64_REG_X1));
        uint64_t format_addr = get_reg(emu, UC_ARM64_REG_X2);
        uint64_t tm_addr = get_reg(emu, UC_ARM64_REG_X3);

        std::string format = read_string(emu, format_addr);
        tm_arm64 guest_tm{};
        struct tm host_tm{};
        std::string zone_storage;
        load_guest_tm(emu, tm_addr, guest_tm, host_tm, zone_storage);

        std::vector<char> buffer(max == 0 ? 1 : max);
        size_t result = 0;
        {
            std::lock_guard<std::recursive_mutex> lock(g_time_state_mutex);
            std::string manual_output;
            if (manual_strftime_zone_only_locked(format, guest_tm, host_tm, manual_output)) {
                if (max != 0 && manual_output.size() < max) {
                    std::memcpy(buffer.data(), manual_output.c_str(), manual_output.size() + 1);
                    result = manual_output.size();
                } else {
                    result = 0;
                }
            } else {
                synthesize_zone_for_strftime_locked(format, guest_tm, host_tm, zone_storage);
                result = ::strftime(buffer.data(), max, format.c_str(), &host_tm);
            }
        }

        if (result > 0) {
            emu.mem_write(s, buffer.data(), result + 1);
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("usleep", [](Emulator& emu) {
        useconds_t usec = static_cast<useconds_t>(get_reg(emu, UC_ARM64_REG_X0));
        struct timespec req{};
        req.tv_sec = usec / 1000000U;
        req.tv_nsec = static_cast<long>(usec % 1000000U) * 1000L;
        int result = sleep_with_timer_processing(emu, CLOCK_MONOTONIC, 0, req, nullptr);
        if (result != 0) {
            hle_set_errno(emu, result);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
        } else {
            set_reg(emu, UC_ARM64_REG_X0, 0);
        }
    });

    hle.register_function("nanosleep", [](Emulator& emu) {
        uint64_t req_ptr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t rem_ptr = get_reg(emu, UC_ARM64_REG_X1);

        timespec_arm64 guest_req{};
        emu.mem_read(req_ptr, &guest_req, sizeof(guest_req));

        struct timespec req{};
        arm64_to_host_timespec(guest_req, req);
        struct timespec rem{};
        int result = sleep_with_timer_processing(emu, CLOCK_MONOTONIC, 0, req, &rem);
        if (result != 0) {
            if (rem_ptr != 0) {
                timespec_arm64 guest_rem{};
                host_to_arm64_timespec(rem, guest_rem);
                emu.mem_write(rem_ptr, &guest_rem, sizeof(guest_rem));
            }
            hle_set_errno(emu, result);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
        } else {
            set_reg(emu, UC_ARM64_REG_X0, 0);
        }
    });

    hle.register_function("sleep", [](Emulator& emu) {
        unsigned int seconds = static_cast<unsigned int>(get_reg(emu, UC_ARM64_REG_X0));
        struct timespec req{};
        req.tv_sec = seconds;
        req.tv_nsec = 0;
        int result = sleep_with_timer_processing(emu, CLOCK_MONOTONIC, 0, req, nullptr);
        set_reg(emu, UC_ARM64_REG_X0, result == 0 ? 0 : seconds);
    });

    hle.register_function("sysconf", [](Emulator& emu) {
        process_due_timers(emu);
        int name = static_cast<int>(get_reg(emu, UC_ARM64_REG_X0));
        const GuestSysconfResolution resolved = resolve_guest_sysconf(name);

        long result = -1;
        switch (resolved.kind) {
            case GuestSysconfKind::kConstant:
                result = resolved.value;
                break;
            case GuestSysconfKind::kHost:
                errno = 0;
                result = ::sysconf(resolved.host_name);
                if (result == -1 && errno != 0) {
                    hle_set_errno(emu, errno);
                }
                break;
            case GuestSysconfKind::kUnsupported:
                result = -1;
                break;
            case GuestSysconfKind::kUnknown:
                hle_set_errno(emu, EINVAL);
                result = -1;
                break;
        }

        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(result));
    });

    hle.register_function("difftime", [](Emulator& emu) {
        time_t time1 = static_cast<time_t>(get_reg(emu, UC_ARM64_REG_X0));
        time_t time0 = static_cast<time_t>(get_reg(emu, UC_ARM64_REG_X1));
        set_dreg(emu, 0, ::difftime(time1, time0));
    });

    hle.register_function("clock", [](Emulator& emu) {
        process_due_timers(emu);
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(::clock()));
    });

    hle.register_function("asctime", [](Emulator& emu) {
        process_due_timers(emu);
        uint64_t tm_addr = get_reg(emu, UC_ARM64_REG_X0);

        tm_arm64 guest_tm{};
        struct tm host_tm{};
        std::string zone_storage;
        load_guest_tm(emu, tm_addr, guest_tm, host_tm, zone_storage);

        char* result = ::asctime(&host_tm);
        if (result != nullptr) {
            emu.mem_write(ASCTIME_BUF, result, std::strlen(result) + 1);
            set_reg(emu, UC_ARM64_REG_X0, ASCTIME_BUF);
        } else {
            set_reg(emu, UC_ARM64_REG_X0, 0);
        }
    });

    hle.register_function("asctime_r", [](Emulator& emu) {
        process_due_timers(emu);
        uint64_t tm_addr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t buf_addr = get_reg(emu, UC_ARM64_REG_X1);

        tm_arm64 guest_tm{};
        struct tm host_tm{};
        std::string zone_storage;
        load_guest_tm(emu, tm_addr, guest_tm, host_tm, zone_storage);

        char buffer[26] = {};
        char* result = ::asctime_r(&host_tm, buffer);
        if (result != nullptr) {
            emu.mem_write(buf_addr, buffer, sizeof(buffer));
            set_reg(emu, UC_ARM64_REG_X0, buf_addr);
        } else {
            set_reg(emu, UC_ARM64_REG_X0, 0);
        }
    });

    hle.register_function("ctime", [](Emulator& emu) {
        process_due_timers(emu);
        uint64_t timep = get_reg(emu, UC_ARM64_REG_X0);
        time_t t = 0;
        emu.mem_read(timep, &t, sizeof(t));

        char* result = ::ctime(&t);
        if (result != nullptr) {
            emu.mem_write(CTIME_BUF, result, std::strlen(result) + 1);
            set_reg(emu, UC_ARM64_REG_X0, CTIME_BUF);
        } else {
            set_reg(emu, UC_ARM64_REG_X0, 0);
        }
    });

    hle.register_function("ctime_r", [](Emulator& emu) {
        process_due_timers(emu);
        uint64_t timep = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t buf_addr = get_reg(emu, UC_ARM64_REG_X1);
        time_t t = 0;
        emu.mem_read(timep, &t, sizeof(t));

        char buffer[26] = {};
        char* result = ::ctime_r(&t, buffer);
        if (result != nullptr) {
            emu.mem_write(buf_addr, buffer, sizeof(buffer));
            set_reg(emu, UC_ARM64_REG_X0, buf_addr);
        } else {
            set_reg(emu, UC_ARM64_REG_X0, 0);
        }
    });

    hle.register_function("clock_getres", [](Emulator& emu) {
        process_due_timers(emu);
        int clk_id = static_cast<int>(get_reg(emu, UC_ARM64_REG_X0));
        uint64_t res_addr = get_reg(emu, UC_ARM64_REG_X1);

        struct timespec res{};
        int result = ::clock_getres(clk_id, &res);
        if (result == 0 && res_addr != 0) {
            timespec_arm64 guest_res{};
            host_to_arm64_timespec(res, guest_res);
            emu.mem_write(res_addr, &guest_res, sizeof(guest_res));
        } else if (result != 0) {
            hle_set_errno(emu, errno);
        }
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(result));
    });

    hle.register_function("clock_settime", [](Emulator& emu) {
        process_due_timers(emu);
        int clk_id = static_cast<int>(get_reg(emu, UC_ARM64_REG_X0));
        uint64_t tp_addr = get_reg(emu, UC_ARM64_REG_X1);

        timespec_arm64 guest_ts{};
        struct timespec ts{};
        if (tp_addr != 0) {
            emu.mem_read(tp_addr, &guest_ts, sizeof(guest_ts));
            arm64_to_host_timespec(guest_ts, ts);
        }

        int result = ::clock_settime(clk_id, &ts);
        if (result != 0) {
            hle_set_errno(emu, errno);
        }
        set_reg(emu, UC_ARM64_REG_X0, result == 0 ? 0 : static_cast<uint64_t>(-1));
    });

    hle.register_function("clock_nanosleep", [](Emulator& emu) {
        int clock_id = static_cast<int>(get_reg(emu, UC_ARM64_REG_X0));
        int flags = static_cast<int>(get_reg(emu, UC_ARM64_REG_X1));
        uint64_t req_addr = get_reg(emu, UC_ARM64_REG_X2);
        uint64_t rem_addr = get_reg(emu, UC_ARM64_REG_X3);

        timespec_arm64 guest_req{};
        emu.mem_read(req_addr, &guest_req, sizeof(guest_req));
        struct timespec req{};
        arm64_to_host_timespec(guest_req, req);

        struct timespec rem{};
        int result = sleep_with_timer_processing(emu, clock_id, flags, req, &rem);
        if (result == EINTR && rem_addr != 0) {
            timespec_arm64 guest_rem{};
            host_to_arm64_timespec(rem, guest_rem);
            emu.mem_write(rem_addr, &guest_rem, sizeof(guest_rem));
        }
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(result));
    });

    hle.register_function("clock_getcpuclockid", [](Emulator& emu) {
        process_due_timers(emu);
        pid_t pid = static_cast<pid_t>(get_reg(emu, UC_ARM64_REG_X0));
        uint64_t clock_id_addr = get_reg(emu, UC_ARM64_REG_X1);

        clockid_t clock_id{};
        int result = ::clock_getcpuclockid(pid, &clock_id);
        if (result == 0 && clock_id_addr != 0) {
            emu.mem_write(clock_id_addr, &clock_id, sizeof(clock_id));
        }
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(result));
    });

    hle.register_function("tzset", [](Emulator& emu) {
        (void)emu;
        std::lock_guard<std::recursive_mutex> lock(g_time_state_mutex);
        ::tzset();
    });

    hle.register_function("tzalloc", [](Emulator& emu) {
        uint64_t name_addr = get_reg(emu, UC_ARM64_REG_X0);
        std::string zone_id = (name_addr == 0) ? detect_system_timezone_id() : read_string(emu, name_addr);
        if (!timezone_exists(zone_id) && zone_id != "UTC") {
            hle_set_errno(emu, ENOENT);
            set_reg(emu, UC_ARM64_REG_X0, 0);
            return;
        }

        uint64_t handle = g_next_timezone_handle.fetch_add(0x10, std::memory_order_relaxed);
        std::lock_guard<std::recursive_mutex> lock(g_time_state_mutex);
        g_timezones[handle] = GuestTimezone{zone_id};
        set_reg(emu, UC_ARM64_REG_X0, handle);
    });

    hle.register_function("tzfree", [](Emulator& emu) {
        uint64_t tz_handle = get_reg(emu, UC_ARM64_REG_X0);
        if (tz_handle == 0) {
            return;
        }
        std::lock_guard<std::recursive_mutex> lock(g_time_state_mutex);
        g_timezones.erase(tz_handle);
    });

    hle.register_function("localtime_rz", [](Emulator& emu) {
        process_due_timers(emu);
        uint64_t tz_handle = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t timep = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t result_addr = get_reg(emu, UC_ARM64_REG_X2);

        time_t t = 0;
        emu.mem_read(timep, &t, sizeof(t));

        std::string zone_id;
        {
            std::lock_guard<std::recursive_mutex> lock(g_time_state_mutex);
            auto it = g_timezones.find(tz_handle);
            if (it == g_timezones.end()) {
                hle_set_errno(emu, EINVAL);
                set_reg(emu, UC_ARM64_REG_X0, 0);
                return;
            }
            zone_id = it->second.zone_id;
        }

        struct tm result{};
        {
            std::lock_guard<std::recursive_mutex> lock(g_time_state_mutex);
            ScopedTimezoneOverride scoped(zone_id);
            ::localtime_r(&t, &result);
            host_tm_to_guest_tm_locked(emu, result_addr, result);
        }
        set_reg(emu, UC_ARM64_REG_X0, result_addr);
    });

    hle.register_function("mktime_z", [](Emulator& emu) {
        process_due_timers(emu);
        uint64_t tz_handle = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t tm_addr = get_reg(emu, UC_ARM64_REG_X1);

        std::string zone_id;
        {
            std::lock_guard<std::recursive_mutex> lock(g_time_state_mutex);
            auto it = g_timezones.find(tz_handle);
            if (it == g_timezones.end()) {
                hle_set_errno(emu, EINVAL);
                set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
                return;
            }
            zone_id = it->second.zone_id;
        }

        tm_arm64 guest_tm{};
        struct tm host_tm{};
        std::string zone_storage;
        load_guest_tm(emu, tm_addr, guest_tm, host_tm, zone_storage);

        errno = 0;
        time_t result = 0;
        {
            std::lock_guard<std::recursive_mutex> lock(g_time_state_mutex);
            if (invalid_positive_dst_request_locked(guest_tm, zone_id)) {
                errno = EOVERFLOW;
                result = static_cast<time_t>(-1);
            } else {
                ScopedTimezoneOverride scoped(zone_id);
                result = ::mktime(&host_tm);
            }
            host_tm_to_guest_tm_locked(emu, tm_addr, host_tm);
        }

        if (result == static_cast<time_t>(-1) && errno != 0) {
            hle_set_errno(emu, errno);
        }
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(result));
    });

    hle.register_function("timer_create", [](Emulator& emu) {
        process_due_timers(emu);
        int clock_id = static_cast<int>(get_reg(emu, UC_ARM64_REG_X0));
        uint64_t sevp_addr = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t timerid_addr = get_reg(emu, UC_ARM64_REG_X2);

        if (clock_id != CLOCK_REALTIME && clock_id != CLOCK_MONOTONIC) {
            hle_set_errno(emu, EINVAL);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        GuestTimer timer{};
        timer.id = g_next_timer_id.fetch_add(0x10, std::memory_order_relaxed);
        timer.owner_pid = ::getpid();
        timer.clock_id = clock_id;
        timer.notify = SIGEV_SIGNAL;
        timer.signo = SIGALRM;

        if (sevp_addr != 0) {
            guest_sigevent_arm64 guest_event{};
            emu.mem_read(sevp_addr, &guest_event, sizeof(guest_event));
            timer.notify = guest_event.sigev_notify;
            timer.signo = guest_event.sigev_signo;
            timer.sigval_raw = guest_event.sigev_value;

            if (timer.notify == SIGEV_THREAD) {
                timer.callback = guest_event.sigev_un.thread.function;
                if (timer.callback == 0) {
                    hle_set_errno(emu, EINVAL);
                    set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
                    return;
                }
            } else if (timer.notify != SIGEV_SIGNAL) {
                hle_set_errno(emu, EINVAL);
                set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
                return;
            }

            if (timer.notify == SIGEV_THREAD) {
                EMU_LOG << "[HLE_TIME] timer_create SIGEV_THREAD: sevp=0x" << std::hex
                        << sevp_addr
                        << " sigev_value=0x" << guest_event.sigev_value
                        << " callback=0x" << timer.callback
                        << " attr=0x" << guest_event.sigev_un.thread.attribute
                        << " signo=" << std::dec << guest_event.sigev_signo
                        << " notify=" << guest_event.sigev_notify
                        << std::endl;
            }
        }

        {
            std::lock_guard<std::recursive_mutex> lock(g_time_state_mutex);
            g_timers[timer.id] = timer;
        }
        emu.mem_write(timerid_addr, &timer.id, sizeof(timer.id));
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("timer_delete", [](Emulator& emu) {
        process_due_timers(emu);
        uint64_t timer_id = get_reg(emu, UC_ARM64_REG_X0);

        std::lock_guard<std::recursive_mutex> lock(g_time_state_mutex);
        auto it = g_timers.find(timer_id);
        if (it == g_timers.end() || it->second.deleted || !timer_owned_by_current_process(it->second)) {
            EMU_LOG << "[HLE_TIME] timer_delete failed: timer_id=0x" << std::hex
                    << timer_id << std::dec
                    << " found=" << (it != g_timers.end())
                    << " deleted=" << ((it != g_timers.end()) ? it->second.deleted : false)
                    << " owner_pid=" << ((it != g_timers.end()) ? it->second.owner_pid : -1)
                    << " current_pid=" << ::getpid()
                    << " active_timers=" << g_timers.size() << std::endl;
            hle_set_errno(emu, EINVAL);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        it->second.deleted = true;
        it->second.armed = false;
        if (!it->second.in_callback) {
            g_timers.erase(it);
        }
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("timer_settime", [](Emulator& emu) {
        process_due_timers(emu);
        uint64_t timer_id = get_reg(emu, UC_ARM64_REG_X0);
        int flags = static_cast<int>(get_reg(emu, UC_ARM64_REG_X1));
        uint64_t new_value_addr = get_reg(emu, UC_ARM64_REG_X2);
        uint64_t old_value_addr = get_reg(emu, UC_ARM64_REG_X3);

        if (flags != 0) {
            hle_set_errno(emu, EINVAL);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        itimerspec_arm64 new_spec{};
        read_guest_itimerspec(emu, new_value_addr, new_spec);
        struct timespec new_value{};
        struct timespec new_interval{};
        arm64_to_host_timespec(new_spec.it_value, new_value);
        arm64_to_host_timespec(new_spec.it_interval, new_interval);

        if (!valid_timespec(new_value) || !valid_timespec(new_interval)) {
            hle_set_errno(emu, EINVAL);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        std::lock_guard<std::recursive_mutex> lock(g_time_state_mutex);
        auto it = g_timers.find(timer_id);
        if (it == g_timers.end() || it->second.deleted || !timer_owned_by_current_process(it->second)) {
            EMU_LOG << "[HLE_TIME] timer_settime failed: timer_id=0x" << std::hex
                    << timer_id << std::dec
                    << " found=" << (it != g_timers.end())
                    << " deleted=" << ((it != g_timers.end()) ? it->second.deleted : false)
                    << " owner_pid=" << ((it != g_timers.end()) ? it->second.owner_pid : -1)
                    << " current_pid=" << ::getpid()
                    << " active_timers=" << g_timers.size() << std::endl;
            hle_set_errno(emu, EINVAL);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        int64_t now_ns = now_ns_for_clock(it->second.clock_id);
        int64_t old_value_ns = 0;
        if (it->second.armed && it->second.due_ns > now_ns) {
            old_value_ns = it->second.due_ns - now_ns;
        }
        write_guest_itimerspec(emu, old_value_addr, old_value_ns, it->second.interval_ns);

        it->second.interval_ns = timespec_to_ns(new_interval);
        int64_t new_value_ns = timespec_to_ns(new_value);
        if (new_value_ns == 0) {
            it->second.armed = false;
            it->second.due_ns = 0;
        } else {
            it->second.armed = true;
            it->second.due_ns = now_ns + new_value_ns;
        }
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("timespec_get", [](Emulator& emu) {
        process_due_timers(emu);
        uint64_t ts_addr = get_reg(emu, UC_ARM64_REG_X0);
        int base = static_cast<int>(get_reg(emu, UC_ARM64_REG_X1));

        int clock_id = map_timespec_base_to_clock(base);
        if (ts_addr == 0 || clock_id == -1) {
            set_reg(emu, UC_ARM64_REG_X0, 0);
            return;
        }

        struct timespec ts{};
        if (::clock_gettime(clock_id, &ts) != 0) {
            set_reg(emu, UC_ARM64_REG_X0, 0);
            return;
        }

        timespec_arm64 guest_ts{};
        host_to_arm64_timespec(ts, guest_ts);
        emu.mem_write(ts_addr, &guest_ts, sizeof(guest_ts));
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(base));
    });

    hle.register_function("timespec_getres", [](Emulator& emu) {
        process_due_timers(emu);
        uint64_t ts_addr = get_reg(emu, UC_ARM64_REG_X0);
        int base = static_cast<int>(get_reg(emu, UC_ARM64_REG_X1));

        int clock_id = map_timespec_base_to_clock(base);
        if (ts_addr == 0 || clock_id == -1) {
            set_reg(emu, UC_ARM64_REG_X0, 0);
            return;
        }

        struct timespec res{};
        if (::clock_getres(clock_id, &res) != 0) {
            set_reg(emu, UC_ARM64_REG_X0, 0);
            return;
        }

        timespec_arm64 guest_res{};
        host_to_arm64_timespec(res, guest_res);
        emu.mem_write(ts_addr, &guest_res, sizeof(guest_res));
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(base));
    });

    hle.register_function("strptime", [](Emulator& emu) {
        process_due_timers(emu);
        uint64_t s_addr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t format_addr = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t tm_addr = get_reg(emu, UC_ARM64_REG_X2);

        std::string input = read_string(emu, s_addr);
        std::string format = read_string(emu, format_addr);
        uint64_t result_addr = 0;
        {
            std::lock_guard<std::recursive_mutex> lock(g_time_state_mutex);
            process_strptime_locked(emu, s_addr, input, format, tm_addr, 0, &result_addr);
        }
        set_reg(emu, UC_ARM64_REG_X0, result_addr);
    });

    hle.register_function("strptime_l", [](Emulator& emu) {
        process_due_timers(emu);
        uint64_t s_addr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t format_addr = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t tm_addr = get_reg(emu, UC_ARM64_REG_X2);
        uint64_t locale_addr = get_reg(emu, UC_ARM64_REG_X3);

        std::string input = read_string(emu, s_addr);
        std::string format = read_string(emu, format_addr);
        uint64_t result_addr = 0;
        {
            std::lock_guard<std::recursive_mutex> lock(g_time_state_mutex);
            process_strptime_locked(emu, s_addr, input, format, tm_addr, locale_addr, &result_addr);
        }
        set_reg(emu, UC_ARM64_REG_X0, result_addr);
    });

    hle.register_function("strftime_l", [](Emulator& emu) {
        process_due_timers(emu);
        uint64_t s = get_reg(emu, UC_ARM64_REG_X0);
        size_t max = static_cast<size_t>(get_reg(emu, UC_ARM64_REG_X1));
        uint64_t format_addr = get_reg(emu, UC_ARM64_REG_X2);
        uint64_t tm_addr = get_reg(emu, UC_ARM64_REG_X3);

        std::string format = read_string(emu, format_addr);
        tm_arm64 guest_tm{};
        struct tm host_tm{};
        std::string zone_storage;
        load_guest_tm(emu, tm_addr, guest_tm, host_tm, zone_storage);

        std::vector<char> buffer(max == 0 ? 1 : max);
        size_t result = 0;
        {
            std::lock_guard<std::recursive_mutex> lock(g_time_state_mutex);
            std::string manual_output;
            if (manual_strftime_zone_only_locked(format, guest_tm, host_tm, manual_output)) {
                if (max != 0 && manual_output.size() < max) {
                    std::memcpy(buffer.data(), manual_output.c_str(), manual_output.size() + 1);
                    result = manual_output.size();
                } else {
                    result = 0;
                }
            } else {
                synthesize_zone_for_strftime_locked(format, guest_tm, host_tm, zone_storage);
                result = ::strftime(buffer.data(), max, format.c_str(), &host_tm);
            }
        }

        if (result > 0) {
            emu.mem_write(s, buffer.data(), result + 1);
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // ========================================================================
    // File time modification
    // ========================================================================

    // utimes - change file last access and modification times
    hle.register_function("utimes", [](Emulator& emu) {
        uint64_t filename_addr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t times_addr = get_reg(emu, UC_ARM64_REG_X1);

        std::string filename = read_string(emu, filename_addr);

        if (times_addr == 0) {
            // Set to current time
            int result = ::utimes(filename.c_str(), nullptr);
            if (result == -1) {
                hle_set_errno(emu, errno);
            }
            set_reg(emu, UC_ARM64_REG_X0, result);
            return;
        }

        // Read two timeval structures from ARM64 bionic format
        timeval_arm64 times_arm[2];
        emu.mem_read(times_addr, times_arm, sizeof(times_arm));

        struct timeval times[2];
        arm64_to_host_timeval(times_arm[0], times[0]);
        arm64_to_host_timeval(times_arm[1], times[1]);

        int result = ::utimes(filename.c_str(), times);
        if (result == -1) {
            hle_set_errno(emu, errno);
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // futimes - change file last access and modification times by fd
    hle.register_function("futimes", [](Emulator& emu) {
        int fd = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t times_addr = get_reg(emu, UC_ARM64_REG_X1);

        if (times_addr == 0) {
            int result = ::futimes(fd, nullptr);
            if (result == -1) {
                hle_set_errno(emu, errno);
            }
            set_reg(emu, UC_ARM64_REG_X0, result);
            return;
        }

        timeval_arm64 times_arm[2];
        emu.mem_read(times_addr, times_arm, sizeof(times_arm));

        struct timeval times[2];
        arm64_to_host_timeval(times_arm[0], times[0]);
        arm64_to_host_timeval(times_arm[1], times[1]);

        int result = ::futimes(fd, times);
        if (result == -1) {
            hle_set_errno(emu, errno);
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // lutimes - change symbolic link last access and modification times
    hle.register_function("lutimes", [](Emulator& emu) {
        uint64_t filename_addr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t times_addr = get_reg(emu, UC_ARM64_REG_X1);

        std::string filename = read_string(emu, filename_addr);

        if (times_addr == 0) {
            int result = ::lutimes(filename.c_str(), nullptr);
            if (result == -1) {
                hle_set_errno(emu, errno);
            }
            set_reg(emu, UC_ARM64_REG_X0, result);
            return;
        }

        timeval_arm64 times_arm[2];
        emu.mem_read(times_addr, times_arm, sizeof(times_arm));

        struct timeval times[2];
        arm64_to_host_timeval(times_arm[0], times[0]);
        arm64_to_host_timeval(times_arm[1], times[1]);

        int result = ::lutimes(filename.c_str(), times);
        if (result == -1) {
            hle_set_errno(emu, errno);
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // futimens - change file timestamps with nanosecond precision by fd
    hle.register_function("futimens", [](Emulator& emu) {
        int fd = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t times_addr = get_reg(emu, UC_ARM64_REG_X1);

        if (times_addr == 0) {
            int result = ::futimens(fd, nullptr);
            if (result == -1) {
                hle_set_errno(emu, errno);
            }
            set_reg(emu, UC_ARM64_REG_X0, result);
            return;
        }

        timespec_arm64 times_arm[2];
        emu.mem_read(times_addr, times_arm, sizeof(times_arm));

        struct timespec times[2];
        arm64_to_host_timespec(times_arm[0], times[0]);
        arm64_to_host_timespec(times_arm[1], times[1]);

        int result = ::futimens(fd, times);
        if (result == -1) {
            hle_set_errno(emu, errno);
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // utimensat - change file timestamps with nanosecond precision
    hle.register_function("utimensat", [](Emulator& emu) {
        int dirfd = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t pathname_addr = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t times_addr = get_reg(emu, UC_ARM64_REG_X2);
        int flags = get_reg(emu, UC_ARM64_REG_X3);

        std::string pathname = read_string(emu, pathname_addr);

        if (times_addr == 0) {
            int result = ::utimensat(dirfd, pathname.c_str(), nullptr, flags);
            if (result == -1) {
                hle_set_errno(emu, errno);
            }
            set_reg(emu, UC_ARM64_REG_X0, result);
            return;
        }

        timespec_arm64 times_arm[2];
        emu.mem_read(times_addr, times_arm, sizeof(times_arm));

        struct timespec times[2];
        arm64_to_host_timespec(times_arm[0], times[0]);
        arm64_to_host_timespec(times_arm[1], times[1]);

        int result = ::utimensat(dirfd, pathname.c_str(), times, flags);
        if (result == -1) {
            hle_set_errno(emu, errno);
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // futimesat - change file timestamps at directory fd
    hle.register_function("futimesat", [](Emulator& emu) {
        int dirfd = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t pathname_addr = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t times_addr = get_reg(emu, UC_ARM64_REG_X2);

        std::string pathname = read_string(emu, pathname_addr);

        if (times_addr == 0) {
            int result = ::futimesat(dirfd, pathname.c_str(), nullptr);
            if (result == -1) {
                hle_set_errno(emu, errno);
            }
            set_reg(emu, UC_ARM64_REG_X0, result);
            return;
        }

        timeval_arm64 times_arm[2];
        emu.mem_read(times_addr, times_arm, sizeof(times_arm));

        struct timeval times[2];
        arm64_to_host_timeval(times_arm[0], times[0]);
        arm64_to_host_timeval(times_arm[1], times[1]);

        int result = ::futimesat(dirfd, pathname.c_str(), times);
        if (result == -1) {
            hle_set_errno(emu, errno);
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });
}

} // namespace cross_shim
