/**
 * HLE Time Functions
 * time, gettimeofday, clock_gettime, localtime_r, gmtime_r, strftime, usleep, nanosleep
 *
 * NOTE: With QEMU MTTCG (real parallel threads), sleep functions use direct
 * blocking calls. Guest threads run on real host threads, so sleeping in the
 * HLE handler blocks only that specific host thread.
 */

#include "hle_manager.h"
#include "cross_shim.h"
#include "memory_manager.h"
#include "bionic_types.h"
#include "emu_compat.h"
#include "debug_log.h"
#include <ctime>
#include <sys/time.h>
#include <unistd.h>
#include <atomic>

using namespace cross_shim::bionic;

namespace cross_shim {

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

void register_hle_time(HleManager& hle) {
    hle.register_function("time", [](Emulator& emu) {
        uint64_t tloc = get_reg(emu, UC_ARM64_REG_X0);
        time_t t = time(nullptr);
        if (tloc) {
            emu.mem_write(tloc, &t, sizeof(t));
        }
        set_reg(emu, UC_ARM64_REG_X0, t);
    });

    hle.register_function("gettimeofday", [](Emulator& emu) {
        uint64_t tv_addr = get_reg(emu, UC_ARM64_REG_X0);
        // uint64_t tz_addr = get_reg(emu, UC_ARM64_REG_X1);

        struct timeval tv;
        gettimeofday(&tv, nullptr);

        if (tv_addr) {
            // Convert host timeval to ARM64 bionic format
            timeval_arm64 tv_arm64;
            host_to_arm64_timeval(tv, tv_arm64);
            emu.mem_write(tv_addr, &tv_arm64, sizeof(tv_arm64));
        }
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("clock_gettime", [](Emulator& emu) {
        int clk_id = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t tp_addr = get_reg(emu, UC_ARM64_REG_X1);

        struct timespec ts;
        int result = clock_gettime(clk_id, &ts);

        if (tp_addr && result == 0) {
            // Convert host timespec to ARM64 bionic format
            timespec_arm64 ts_arm64;
            host_to_arm64_timespec(ts, ts_arm64);
            emu.mem_write(tp_addr, &ts_arm64, sizeof(ts_arm64));
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("localtime_r", [](Emulator& emu) {
        uint64_t timep = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t result_addr = get_reg(emu, UC_ARM64_REG_X1);

        time_t t;
        emu.mem_read(timep, &t, sizeof(t));

        struct tm result;
        localtime_r(&t, &result);

        // Convert host tm to ARM64 bionic format (56 bytes)
        tm_arm64 tm_arm;
        host_to_arm64_tm(result, tm_arm, 0);  // tm_zone pointer not used
        emu.mem_write(result_addr, &tm_arm, sizeof(tm_arm));
        set_reg(emu, UC_ARM64_REG_X0, result_addr);
    });

    hle.register_function("gmtime_r", [](Emulator& emu) {
        uint64_t timep = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t result_addr = get_reg(emu, UC_ARM64_REG_X1);

        time_t t;
        emu.mem_read(timep, &t, sizeof(t));

        struct tm result;
        gmtime_r(&t, &result);

        // Convert host tm to ARM64 bionic format (56 bytes)
        tm_arm64 tm_arm;
        host_to_arm64_tm(result, tm_arm, 0);
        emu.mem_write(result_addr, &tm_arm, sizeof(tm_arm));
        set_reg(emu, UC_ARM64_REG_X0, result_addr);
    });

    // Static buffer addresses for localtime/gmtime (allocated in global data region)
    // GLOBAL_DATA_BASE + 0x200 = localtime buffer
    // GLOBAL_DATA_BASE + 0x280 = gmtime buffer
    static const uint64_t LOCALTIME_BUF = 0xB0000200;
    static const uint64_t GMTIME_BUF = 0xB0000280;

    hle.register_function("localtime", [](Emulator& emu) {
        uint64_t timep = get_reg(emu, UC_ARM64_REG_X0);

        time_t t;
        emu.mem_read(timep, &t, sizeof(t));

        struct tm result;
        localtime_r(&t, &result);

        // Convert host tm to ARM64 bionic format and write to static buffer
        tm_arm64 tm_arm;
        host_to_arm64_tm(result, tm_arm, 0);
        emu.mem_write(LOCALTIME_BUF, &tm_arm, sizeof(tm_arm));
        set_reg(emu, UC_ARM64_REG_X0, LOCALTIME_BUF);
    });

    hle.register_function("gmtime", [](Emulator& emu) {
        uint64_t timep = get_reg(emu, UC_ARM64_REG_X0);

        time_t t;
        emu.mem_read(timep, &t, sizeof(t));

        struct tm result;
        gmtime_r(&t, &result);

        // Convert host tm to ARM64 bionic format and write to static buffer
        tm_arm64 tm_arm;
        host_to_arm64_tm(result, tm_arm, 0);
        emu.mem_write(GMTIME_BUF, &tm_arm, sizeof(tm_arm));
        set_reg(emu, UC_ARM64_REG_X0, GMTIME_BUF);
    });

    hle.register_function("mktime", [](Emulator& emu) {
        uint64_t tm_addr = get_reg(emu, UC_ARM64_REG_X0);

        // Read ARM64 bionic tm structure
        tm_arm64 tm_arm;
        emu.mem_read(tm_addr, &tm_arm, sizeof(tm_arm));

        // Convert to host tm
        struct tm tm_val;
        arm64_to_host_tm(tm_arm, tm_val);

        time_t result = mktime(&tm_val);

        // mktime normalizes the tm structure, so convert back and write
        host_to_arm64_tm(tm_val, tm_arm, 0);
        emu.mem_write(tm_addr, &tm_arm, sizeof(tm_arm));

        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("strftime", [](Emulator& emu) {
        uint64_t s = get_reg(emu, UC_ARM64_REG_X0);
        size_t max = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t format_addr = get_reg(emu, UC_ARM64_REG_X2);
        uint64_t tm_addr = get_reg(emu, UC_ARM64_REG_X3);

        std::string format = read_string(emu, format_addr);

        // Read ARM64 bionic tm structure and convert to host
        tm_arm64 tm_arm;
        emu.mem_read(tm_addr, &tm_arm, sizeof(tm_arm));
        struct tm tm_val;
        arm64_to_host_tm(tm_arm, tm_val);

        std::vector<char> buf(max);
        size_t result = strftime(buf.data(), max, format.c_str(), &tm_val);

        if (result > 0) {
            emu.mem_write(s, buf.data(), result + 1);
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    static std::atomic<int> g_usleep_count{0};
    hle.register_function("usleep", [](Emulator& emu) {
        useconds_t usec = get_reg(emu, UC_ARM64_REG_X0);
        int call_num = ++g_usleep_count;

        // Cap usleep to 10ms to prevent long delays while maintaining TUTK timing
        useconds_t actual_usec = usec;
        if (usec > 10000) {
            actual_usec = 10000;  // Cap at 10ms
        }

        if (call_num <= 20 || call_num % 100 == 0 || usec > 100000) {
            EMU_LOG << "[HLE-TRACE] usleep(" << usec << "us, actual=" << actual_usec << "us) call #" << call_num << std::endl;
        }

        // Direct blocking usleep - with MTTCG, this blocks only this host thread
        int result = ::usleep(actual_usec);

        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    static std::atomic<int> g_nanosleep_count{0};
    hle.register_function("nanosleep", [](Emulator& emu) {
        uint64_t req_ptr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t rem_ptr = get_reg(emu, UC_ARM64_REG_X1);

        struct timespec req = {0, 0};
        struct timespec rem = {0, 0};

        if (req_ptr != 0) {
            // Read ARM64 timespec (same layout as x86_64)
            emu.mem_read(req_ptr, &req.tv_sec, 8);
            emu.mem_read(req_ptr + 8, &req.tv_nsec, 8);
        }

        int call_num = ++g_nanosleep_count;
        long total_us = req.tv_sec * 1000000 + req.tv_nsec / 1000;

        // Cap nanosleep to 10ms to prevent long delays while maintaining TUTK timing
        struct timespec actual_req = req;
        if (total_us > 10000) {
            actual_req.tv_sec = 0;
            actual_req.tv_nsec = 10000000;  // 10ms
        }

        if (call_num <= 20 || call_num % 100 == 0 || total_us > 100000) {
            EMU_LOG << "[HLE-TRACE] nanosleep(" << req.tv_sec << "s + " << req.tv_nsec << "ns = "
                    << total_us << "us, capped to 10ms) call #" << call_num << std::endl;
        }

        // Direct blocking nanosleep - with MTTCG, this blocks only this host thread
        int result = ::nanosleep(&actual_req, &rem);

        if (result != 0 && rem_ptr != 0) {
            // Write remaining time if interrupted
            emu.mem_write(rem_ptr, &rem.tv_sec, 8);
            emu.mem_write(rem_ptr + 8, &rem.tv_nsec, 8);
        }

        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("sleep", [](Emulator& emu) {
        unsigned int seconds = get_reg(emu, UC_ARM64_REG_X0);
        // Cap at 1 second
        if (seconds > 1) seconds = 1;
        if (seconds > 0) {
            ::sleep(seconds);
        }
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("sysconf", [](Emulator& emu) {
        int name = get_reg(emu, UC_ARM64_REG_X0);
        long result = sysconf(name);
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("difftime", [](Emulator& emu) {
        // difftime returns a double, which goes in D0 (floating point register)
        time_t time1 = get_reg(emu, UC_ARM64_REG_X0);
        time_t time0 = get_reg(emu, UC_ARM64_REG_X1);

        double result = difftime(time1, time0);

        // Write result to D0 (floating point return register)
        set_dreg(emu, 0, result);
    });

    hle.register_function("clock", [](Emulator& emu) {
        clock_t result = clock();
        set_reg(emu, UC_ARM64_REG_X0, result);
    });
}

} // namespace cross_shim

