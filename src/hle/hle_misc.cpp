/**
 * HLE Miscellaneous Functions
 * getenv, setenv, atoi, atol, strtol, strtoul, strtod
 * qsort, bsearch, rand, srand, arc4random
 * exit, abort, atexit, __cxa_atexit
 * errno, strerror, getpid, getuid
 */

#include "debug_log.h"
#include "hle_manager.h"
#include "cross_shim.h"
#include "memory_manager.h"
#include "emu_compat.h"
#include <cstring>
#include <cstdlib>
#include <vector>
#include <unordered_map>
#include <random>
#include <iostream>
#include <unistd.h>
#include <cerrno>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/epoll.h>

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

// Environment variables simulation
static std::unordered_map<std::string, std::string> g_env = {
    {"OPENSSL_CONF", "/etc/ssl/openssl.cnf"},
};

// Errno location
static uint64_t g_errno_addr = 0;
static int g_errno_value = 0;

// Random number generator
static std::mt19937 g_rng(std::random_device{}());

void register_hle_misc(HleManager& hle) {
    // ========================================================================
    // Environment
    // ========================================================================
    
    hle.register_function("getenv", [](Emulator& emu) {
        uint64_t name_addr = get_reg(emu, UC_ARM64_REG_X0);
        std::string name = read_string(emu, name_addr);

        if (emu.is_debug()) {
            EMU_LOG << "[HLE] getenv: name=" << name << std::endl;
        }

        // Check our simulated env first, then real env
        auto it = g_env.find(name);
        if (it != g_env.end()) {
            uint64_t ptr = emu.memory().heap().allocate(it->second.length() + 1, 8);
            emu.mem_write(ptr, it->second.c_str(), it->second.length() + 1);
            set_reg(emu, UC_ARM64_REG_X0, ptr);
        } else {
            const char* val = getenv(name.c_str());
            if (val) {
                uint64_t ptr = emu.memory().heap().allocate(strlen(val) + 1, 8);
                emu.mem_write(ptr, val, strlen(val) + 1);
                set_reg(emu, UC_ARM64_REG_X0, ptr);
            } else {
                set_reg(emu, UC_ARM64_REG_X0, 0);
            }
        }
    });

    hle.register_function("setenv", [](Emulator& emu) {
        uint64_t name_addr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t value_addr = get_reg(emu, UC_ARM64_REG_X1);
        int overwrite = get_reg(emu, UC_ARM64_REG_X2);

        std::string name = read_string(emu, name_addr);
        std::string value = read_string(emu, value_addr);

        // Only set if overwrite is non-zero or the variable doesn't exist
        if (overwrite || g_env.find(name) == g_env.end()) {
            g_env[name] = value;
        }
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("unsetenv", [](Emulator& emu) {
        uint64_t name_addr = get_reg(emu, UC_ARM64_REG_X0);
        std::string name = read_string(emu, name_addr);
        g_env.erase(name);
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    // ========================================================================
    // String to number conversion
    // ========================================================================
    
    hle.register_function("atoi", [](Emulator& emu) {
        uint64_t s = get_reg(emu, UC_ARM64_REG_X0);
        std::string str = read_string(emu, s);
        set_reg(emu, UC_ARM64_REG_X0, atoi(str.c_str()));
    });

    hle.register_function("atol", [](Emulator& emu) {
        uint64_t s = get_reg(emu, UC_ARM64_REG_X0);
        std::string str = read_string(emu, s);
        set_reg(emu, UC_ARM64_REG_X0, atol(str.c_str()));
    });

    hle.register_function("atoll", [](Emulator& emu) {
        uint64_t s = get_reg(emu, UC_ARM64_REG_X0);
        std::string str = read_string(emu, s);
        set_reg(emu, UC_ARM64_REG_X0, atoll(str.c_str()));
    });

    hle.register_function("strtol", [](Emulator& emu) {
        uint64_t nptr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t endptr = get_reg(emu, UC_ARM64_REG_X1);
        int base = get_reg(emu, UC_ARM64_REG_X2);
        
        std::string str = read_string(emu, nptr);
        char* end;
        long result = strtol(str.c_str(), &end, base);
        
        if (endptr) {
            uint64_t end_offset = end - str.c_str();
            uint64_t end_addr = nptr + end_offset;
            emu.mem_write(endptr, &end_addr, sizeof(end_addr));
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("strtoul", [](Emulator& emu) {
        uint64_t nptr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t endptr = get_reg(emu, UC_ARM64_REG_X1);
        int base = get_reg(emu, UC_ARM64_REG_X2);

        std::string str = read_string(emu, nptr);
        char* end;
        unsigned long result = strtoul(str.c_str(), &end, base);

        if (endptr) {
            uint64_t end_offset = end - str.c_str();
            uint64_t end_addr = nptr + end_offset;
            emu.mem_write(endptr, &end_addr, sizeof(end_addr));
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("strtoll", [](Emulator& emu) {
        uint64_t nptr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t endptr = get_reg(emu, UC_ARM64_REG_X1);
        int base = get_reg(emu, UC_ARM64_REG_X2);
        std::string str = read_string(emu, nptr);
        char* end;
        long long result = strtoll(str.c_str(), &end, base);
        if (endptr) {
            uint64_t end_addr = nptr + (end - str.c_str());
            emu.mem_write(endptr, &end_addr, sizeof(end_addr));
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("strtoull", [](Emulator& emu) {
        uint64_t nptr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t endptr = get_reg(emu, UC_ARM64_REG_X1);
        int base = get_reg(emu, UC_ARM64_REG_X2);
        std::string str = read_string(emu, nptr);
        char* end;
        unsigned long long result = strtoull(str.c_str(), &end, base);
        if (endptr) {
            uint64_t end_addr = nptr + (end - str.c_str());
            emu.mem_write(endptr, &end_addr, sizeof(end_addr));
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("strtod", [](Emulator& emu) {
        uint64_t nptr = get_reg(emu, UC_ARM64_REG_X0);
        std::string str = read_string(emu, nptr);
        double result = strtod(str.c_str(), nullptr);
        set_dreg(emu, 0, result);
    });

    // ========================================================================
    // Random numbers
    // ========================================================================

    hle.register_function("rand", [](Emulator& emu) {
        set_reg(emu, UC_ARM64_REG_X0, g_rng() % RAND_MAX);
    });

    hle.register_function("srand", [](Emulator& emu) {
        unsigned int seed = get_reg(emu, UC_ARM64_REG_X0);
        g_rng.seed(seed);
    });

    hle.register_function("srand48", [](Emulator& emu) {
        long seed = get_reg(emu, UC_ARM64_REG_X0);
        g_rng.seed(seed);
    });

    hle.register_function("lrand48", [](Emulator& emu) {
        static int lrand48_call_count = 0;
        lrand48_call_count++;
        if (lrand48_call_count <= 10 || (lrand48_call_count % 100) == 0) {
            EMU_LOG << "[HLE-TRACE] lrand48() called (call #" << lrand48_call_count << ") - tutk_platform_rand is executing" << std::endl;
        }
        set_reg(emu, UC_ARM64_REG_X0, g_rng() & 0x7FFFFFFF);
    });

    hle.register_function("arc4random", [](Emulator& emu) {
        static int arc4random_call_count = 0;
        arc4random_call_count++;
        if (arc4random_call_count <= 10 || (arc4random_call_count % 100) == 0) {
            EMU_LOG << "[HLE-TRACE] arc4random() called (call #" << arc4random_call_count << ")" << std::endl;
        }
        set_reg(emu, UC_ARM64_REG_X0, g_rng());
    });

    // getentropy - fill buffer with random bytes
    hle.register_function("getentropy", [](Emulator& emu) {
        uint64_t buf = get_reg(emu, UC_ARM64_REG_X0);
        size_t len = get_reg(emu, UC_ARM64_REG_X1);

        static int getentropy_call_count = 0;
        getentropy_call_count++;
        if (getentropy_call_count <= 10 || (getentropy_call_count % 100) == 0) {
            EMU_LOG << "[HLE-TRACE] getentropy(buf=0x" << std::hex << buf << ", len=" << std::dec << len << ") called (call #" << getentropy_call_count << ")" << std::endl;
        }

        if (len > 256) {
            // getentropy fails if len > 256
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        std::vector<uint8_t> data(len);
        for (size_t i = 0; i < len; i++) {
            data[i] = g_rng() & 0xFF;
        }
        emu.mem_write(buf, data.data(), len);
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    // ========================================================================
    // Error handling
    // ========================================================================

    hle.register_function("__errno", [](Emulator& emu) {
        if (g_errno_addr == 0) {
            g_errno_addr = emu.memory().heap().allocate(4, 4);
        }
        emu.mem_write(g_errno_addr, &g_errno_value, sizeof(g_errno_value));
        set_reg(emu, UC_ARM64_REG_X0, g_errno_addr);
    });

    hle.register_function("strerror", [](Emulator& emu) {
        // Use a static buffer in emulated memory to avoid heap fragmentation
        static uint64_t strerror_buf = 0;
        static const size_t STRERROR_BUF_SIZE = 256;

        if (strerror_buf == 0) {
            strerror_buf = emu.memory().heap().allocate(STRERROR_BUF_SIZE, 8);
        }

        int errnum = get_reg(emu, UC_ARM64_REG_X0);
        const char* msg = strerror(errnum);
        size_t len = std::min(strlen(msg), STRERROR_BUF_SIZE - 1);
        emu.mem_write(strerror_buf, msg, len);
        char null = 0;
        emu.mem_write(strerror_buf + len, &null, 1);
        set_reg(emu, UC_ARM64_REG_X0, strerror_buf);
    });

    hle.register_function("strerror_r", [](Emulator& emu) {
        int errnum = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t buf = get_reg(emu, UC_ARM64_REG_X1);
        size_t buflen = get_reg(emu, UC_ARM64_REG_X2);
        const char* msg = strerror(errnum);
        size_t len = std::min(strlen(msg), buflen - 1);
        emu.mem_write(buf, msg, len);
        char null = 0;
        emu.mem_write(buf + len, &null, 1);
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    // ========================================================================
    // Process control
    // ========================================================================

    hle.register_function("exit", [](Emulator& emu) {
        int status = get_reg(emu, UC_ARM64_REG_X0);
        // Always log exit calls since they're critical
        EMU_LOG << "[HLE] exit(" << status << ") called!" << std::endl;
        // Set LR to the final return address so the code hook doesn't continue execution
        uint64_t final_ret_addr = 0x10000000 + 0x00100000 - 4;  // HLE_BASE + HLE_SIZE - 4
        set_reg(emu, UC_ARM64_REG_LR, final_ret_addr);
        emu.stop();
    });

    hle.register_function("_exit", [](Emulator& emu) {
        int status = get_reg(emu, UC_ARM64_REG_X0);
        if (emu.is_debug()) {
            EMU_LOG << "[HLE] _exit(" << status << ")" << std::endl;
        }
        // Set LR to the final return address so the code hook doesn't continue execution
        uint64_t final_ret_addr = 0x10000000 + 0x00100000 - 4;  // HLE_BASE + HLE_SIZE - 4
        set_reg(emu, UC_ARM64_REG_LR, final_ret_addr);
        emu.stop();
    });

    hle.register_function("abort", [](Emulator& emu) {
        emu.stop();
    });

    hle.register_function("__cxa_atexit", [](Emulator& emu) {
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("__cxa_finalize", [](Emulator& emu) {
        // No-op
    });

    hle.register_function("atexit", [](Emulator& emu) {
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    // ========================================================================
    // Process info
    // ========================================================================

    hle.register_function("getpid", [](Emulator& emu) {
        set_reg(emu, UC_ARM64_REG_X0, 1000);  // Fake PID
    });

    hle.register_function("getuid", [](Emulator& emu) {
        set_reg(emu, UC_ARM64_REG_X0, 1000);  // Fake UID
    });

    hle.register_function("geteuid", [](Emulator& emu) {
        set_reg(emu, UC_ARM64_REG_X0, 1000);
    });

    hle.register_function("getgid", [](Emulator& emu) {
        set_reg(emu, UC_ARM64_REG_X0, 1000);
    });

    hle.register_function("getegid", [](Emulator& emu) {
        set_reg(emu, UC_ARM64_REG_X0, 1000);
    });

    // ========================================================================
    // Sorting and searching
    // ========================================================================

    hle.register_function("qsort", [](Emulator& emu) {
        uint64_t base = get_reg(emu, UC_ARM64_REG_X0);
        size_t nmemb = get_reg(emu, UC_ARM64_REG_X1);
        size_t size = get_reg(emu, UC_ARM64_REG_X2);
        uint64_t compar = get_reg(emu, UC_ARM64_REG_X3);

        if (nmemb <= 1 || size == 0 || compar == 0) {
            return;
        }

        // Read all elements into host memory
        std::vector<std::vector<uint8_t>> elements(nmemb);
        for (size_t i = 0; i < nmemb; i++) {
            elements[i].resize(size);
            emu.mem_read(base + i * size, elements[i].data(), size);
        }

        // Simple bubble sort using the emulated comparison function
        for (size_t i = 0; i < nmemb - 1; i++) {
            for (size_t j = 0; j < nmemb - i - 1; j++) {
                uint64_t addr_a = base + j * size;
                uint64_t addr_b = base + (j + 1) * size;

                // Call comparison function: compar(a, b)
                // Use call_function_safe to preserve LR
                uint64_t result = emu.call_function_safe(compar, {addr_a, addr_b});
                int32_t cmp = (int32_t)(result & 0xFFFFFFFF);

                if (cmp > 0) {
                    // Swap elements in our local copy
                    std::swap(elements[j], elements[j + 1]);
                    // Also swap in emulated memory so next comparison sees correct values
                    emu.mem_write(addr_a, elements[j].data(), size);
                    emu.mem_write(addr_b, elements[j + 1].data(), size);
                }

                // DO NOT yield in a loop from an HLE handler!
                // Yielding in a loop causes the wrong thread to call yield() after the first
                // iteration, because current_thread_id_ changes but the C++ loop continues.
                // Rely on periodic preemption (Tier 2) instead for cooperative behavior.
            }
        }
    });

    hle.register_function("bsearch", [](Emulator& emu) {
        uint64_t key = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t base = get_reg(emu, UC_ARM64_REG_X1);
        size_t nmemb = get_reg(emu, UC_ARM64_REG_X2);
        size_t size = get_reg(emu, UC_ARM64_REG_X3);
        uint64_t compar = get_reg(emu, UC_ARM64_REG_X4);

        if (nmemb == 0 || size == 0 || compar == 0) {
            set_reg(emu, UC_ARM64_REG_X0, 0);
            return;
        }

        // Binary search
        size_t low = 0;
        size_t high = nmemb;

        while (low < high) {
            size_t mid = low + (high - low) / 2;
            uint64_t mid_addr = base + mid * size;

            // Call comparison function: compar(key, mid_element)
            // Use call_function_safe to preserve LR
            uint64_t result = emu.call_function_safe(compar, {key, mid_addr});
            int32_t cmp = (int32_t)(result & 0xFFFFFFFF);

            if (cmp == 0) {
                set_reg(emu, UC_ARM64_REG_X0, mid_addr);
                return;
            } else if (cmp < 0) {
                high = mid;
            } else {
                low = mid + 1;
            }
        }

        set_reg(emu, UC_ARM64_REG_X0, 0);  // Not found
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

        // Read X0 which typically contains the saved canary value that didn't match
        uint64_t x0 = get_reg(emu, UC_ARM64_REG_X0);

        // Read FP (X29) - frame pointer
        uint64_t fp = get_reg(emu, UC_ARM64_REG_X29);

        // Read X18 (platform register, should be same as TPIDR_EL0 on Android)
        uint64_t x18 = get_reg(emu, UC_ARM64_REG_X18);

        // Read stack guard from X18 + 0x28 (what the code actually uses)
        uint64_t stack_guard_from_x18 = 0;
        emu.mem_read(x18 + 0x28, &stack_guard_from_x18, sizeof(stack_guard_from_x18));

        EMU_LOG << "[HLE] __stack_chk_fail called! Stack corruption detected.\n";
        EMU_LOG << "[HLE] TPIDR_EL0=0x" << std::hex << tpidr
                  << " stack_guard@0x" << (tpidr + 0x28) << "=0x" << stack_guard_from_tls
                  << std::dec << std::endl;
        EMU_LOG << "[HLE] X18=0x" << std::hex << x18
                  << " stack_guard@0x" << (x18 + 0x28) << "=0x" << stack_guard_from_x18
                  << std::dec << std::endl;
        EMU_LOG << "[HLE] PC=0x" << std::hex << pc << " LR=0x" << lr << " SP=0x" << sp << " FP=0x" << fp << " X0=0x" << x0 << std::dec << std::endl;

        // Dump some stack values to see what's there
        EMU_LOG << "[HLE] Stack dump around SP:" << std::endl;
        for (int i = -4; i <= 8; i++) {
            uint64_t addr = sp + (i * 8);
            uint64_t val = 0;
            emu.mem_read(addr, &val, sizeof(val));
            EMU_LOG << "  [SP" << (i >= 0 ? "+" : "") << (i * 8) << "]=0x" << std::hex << val << std::dec << std::endl;
        }

        // Also dump around FP
        EMU_LOG << "[HLE] Stack dump around FP:" << std::endl;
        for (int i = -4; i <= 4; i++) {
            uint64_t addr = fp + (i * 8);
            uint64_t val = 0;
            emu.mem_read(addr, &val, sizeof(val));
            EMU_LOG << "  [FP" << (i >= 0 ? "+" : "") << (i * 8) << "]=0x" << std::hex << val << std::dec << std::endl;
        }

        // Read x20 which holds the TPIDR_EL0 value used in the comparison
        uint64_t x20 = get_reg(emu, UC_ARM64_REG_X20);
        uint64_t stack_guard_from_x20 = 0;
        emu.mem_read(x20 + 0x28, &stack_guard_from_x20, sizeof(stack_guard_from_x20));
        EMU_LOG << "[HLE] X20=0x" << std::hex << x20
                  << " stack_guard@0x" << (x20 + 0x28) << "=0x" << stack_guard_from_x20
                  << std::dec << std::endl;

        // Don't stop - just log and continue. The stack check may be a false positive
        // due to emulation differences. Return normally.
    });

    // Note: __stack_chk_guard is a global DATA symbol, not a function.
    // It is initialized in Emulator::initialize_global_data() as a constant value.

    // ========================================================================
    // Locale functions
    // ========================================================================

    hle.register_function("setlocale", [](Emulator& emu) {
        // Return "C" locale
        static const char* c_locale = "C";
        uint64_t ptr = emu.memory().heap().allocate(2, 8);
        emu.mem_write(ptr, c_locale, 2);
        set_reg(emu, UC_ARM64_REG_X0, ptr);
    });

    hle.register_function("localeconv", [](Emulator& emu) {
        // Return null (use default)
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("nl_langinfo", [](Emulator& emu) {
        static const char* empty = "";
        uint64_t ptr = emu.memory().heap().allocate(1, 8);
        emu.mem_write(ptr, empty, 1);
        set_reg(emu, UC_ARM64_REG_X0, ptr);
    });

    // ========================================================================
    // Wide character functions
    // ========================================================================

    hle.register_function("wcslen", [](Emulator& emu) {
        uint64_t s = get_reg(emu, UC_ARM64_REG_X0);
        size_t len = 0;
        while (true) {
            uint32_t wc;
            emu.mem_read(s + len * 4, &wc, 4);
            if (wc == 0) break;
            len++;
        }
        set_reg(emu, UC_ARM64_REG_X0, len);
    });

    hle.register_function("wcscpy", [](Emulator& emu) {
        uint64_t dest = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t src = get_reg(emu, UC_ARM64_REG_X1);
        size_t i = 0;
        while (true) {
            uint32_t wc;
            emu.mem_read(src + i * 4, &wc, 4);
            emu.mem_write(dest + i * 4, &wc, 4);
            if (wc == 0) break;
            i++;
        }
        set_reg(emu, UC_ARM64_REG_X0, dest);
    });

    hle.register_function("wcsncpy", [](Emulator& emu) {
        uint64_t dest = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t src = get_reg(emu, UC_ARM64_REG_X1);
        size_t n = get_reg(emu, UC_ARM64_REG_X2);
        size_t i = 0;
        bool null_found = false;
        while (i < n) {
            uint32_t wc;
            if (!null_found) {
                emu.mem_read(src + i * 4, &wc, 4);
                if (wc == 0) null_found = true;
            } else {
                wc = 0;
            }
            emu.mem_write(dest + i * 4, &wc, 4);
            i++;
        }
        set_reg(emu, UC_ARM64_REG_X0, dest);
    });

    hle.register_function("wcscmp", [](Emulator& emu) {
        uint64_t s1 = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t s2 = get_reg(emu, UC_ARM64_REG_X1);
        size_t i = 0;
        while (true) {
            uint32_t wc1, wc2;
            emu.mem_read(s1 + i * 4, &wc1, 4);
            emu.mem_read(s2 + i * 4, &wc2, 4);
            if (wc1 != wc2 || wc1 == 0) {
                set_reg(emu, UC_ARM64_REG_X0, (int32_t)wc1 - (int32_t)wc2);
                return;
            }
            i++;
        }
    });

    hle.register_function("wcsncmp", [](Emulator& emu) {
        uint64_t s1 = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t s2 = get_reg(emu, UC_ARM64_REG_X1);
        size_t n = get_reg(emu, UC_ARM64_REG_X2);
        for (size_t i = 0; i < n; i++) {
            uint32_t wc1, wc2;
            emu.mem_read(s1 + i * 4, &wc1, 4);
            emu.mem_read(s2 + i * 4, &wc2, 4);
            if (wc1 != wc2 || wc1 == 0) {
                set_reg(emu, UC_ARM64_REG_X0, (int32_t)wc1 - (int32_t)wc2);
                return;
            }
        }
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("mbstowcs", [](Emulator& emu) {
        uint64_t dest = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t src = get_reg(emu, UC_ARM64_REG_X1);
        size_t n = get_reg(emu, UC_ARM64_REG_X2);

        std::string s = read_string(emu, src);
        size_t converted = std::min(s.length(), n);

        for (size_t i = 0; i < converted; i++) {
            uint32_t wc = (unsigned char)s[i];
            emu.mem_write(dest + i * 4, &wc, 4);
        }
        if (converted < n) {
            uint32_t null = 0;
            emu.mem_write(dest + converted * 4, &null, 4);
        }
        set_reg(emu, UC_ARM64_REG_X0, converted);
    });

    hle.register_function("wcstombs", [](Emulator& emu) {
        uint64_t dest = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t src = get_reg(emu, UC_ARM64_REG_X1);
        size_t n = get_reg(emu, UC_ARM64_REG_X2);

        std::string result;
        size_t i = 0;
        while (result.length() < n) {
            uint32_t wc;
            emu.mem_read(src + i * 4, &wc, 4);
            if (wc == 0) break;
            if (wc < 128) {
                result += (char)wc;
            }
            i++;
        }

        if (dest && n > 0) {
            size_t copy_len = std::min(result.length(), n);
            emu.mem_write(dest, result.c_str(), copy_len);
            if (copy_len < n) {
                char null = 0;
                emu.mem_write(dest + copy_len, &null, 1);
            }
        }
        set_reg(emu, UC_ARM64_REG_X0, result.length());
    });

    // ========================================================================
    // Character classification
    // ========================================================================

    hle.register_function("isalpha", [](Emulator& emu) {
        int c = get_reg(emu, UC_ARM64_REG_X0);
        set_reg(emu, UC_ARM64_REG_X0, isalpha(c) ? 1 : 0);
    });

    hle.register_function("isdigit", [](Emulator& emu) {
        int c = get_reg(emu, UC_ARM64_REG_X0);
        set_reg(emu, UC_ARM64_REG_X0, isdigit(c) ? 1 : 0);
    });

    hle.register_function("isalnum", [](Emulator& emu) {
        int c = get_reg(emu, UC_ARM64_REG_X0);
        set_reg(emu, UC_ARM64_REG_X0, isalnum(c) ? 1 : 0);
    });

    hle.register_function("isspace", [](Emulator& emu) {
        int c = get_reg(emu, UC_ARM64_REG_X0);
        set_reg(emu, UC_ARM64_REG_X0, isspace(c) ? 1 : 0);
    });

    hle.register_function("isupper", [](Emulator& emu) {
        int c = get_reg(emu, UC_ARM64_REG_X0);
        set_reg(emu, UC_ARM64_REG_X0, isupper(c) ? 1 : 0);
    });

    hle.register_function("islower", [](Emulator& emu) {
        int c = get_reg(emu, UC_ARM64_REG_X0);
        set_reg(emu, UC_ARM64_REG_X0, islower(c) ? 1 : 0);
    });

    hle.register_function("isprint", [](Emulator& emu) {
        int c = get_reg(emu, UC_ARM64_REG_X0);
        set_reg(emu, UC_ARM64_REG_X0, isprint(c) ? 1 : 0);
    });

    hle.register_function("ispunct", [](Emulator& emu) {
        int c = get_reg(emu, UC_ARM64_REG_X0);
        set_reg(emu, UC_ARM64_REG_X0, ispunct(c) ? 1 : 0);
    });

    hle.register_function("isxdigit", [](Emulator& emu) {
        int c = get_reg(emu, UC_ARM64_REG_X0);
        set_reg(emu, UC_ARM64_REG_X0, isxdigit(c) ? 1 : 0);
    });

    hle.register_function("iscntrl", [](Emulator& emu) {
        int c = get_reg(emu, UC_ARM64_REG_X0);
        set_reg(emu, UC_ARM64_REG_X0, iscntrl(c) ? 1 : 0);
    });

    hle.register_function("isgraph", [](Emulator& emu) {
        int c = get_reg(emu, UC_ARM64_REG_X0);
        set_reg(emu, UC_ARM64_REG_X0, isgraph(c) ? 1 : 0);
    });

    hle.register_function("isblank", [](Emulator& emu) {
        int c = get_reg(emu, UC_ARM64_REG_X0);
        set_reg(emu, UC_ARM64_REG_X0, isblank(c) ? 1 : 0);
    });

    hle.register_function("toupper", [](Emulator& emu) {
        int c = get_reg(emu, UC_ARM64_REG_X0);
        set_reg(emu, UC_ARM64_REG_X0, toupper(c));
    });

    hle.register_function("tolower", [](Emulator& emu) {
        int c = get_reg(emu, UC_ARM64_REG_X0);
        set_reg(emu, UC_ARM64_REG_X0, tolower(c));
    });

    // ========================================================================
    // Additional conversion functions
    // ========================================================================

    hle.register_function("strtof", [](Emulator& emu) {
        uint64_t nptr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t endptr = get_reg(emu, UC_ARM64_REG_X1);

        std::string s = read_string(emu, nptr);
        char* end;
        float result = strtof(s.c_str(), &end);

        if (endptr) {
            uint64_t end_addr = nptr + (end - s.c_str());
            emu.mem_write(endptr, &end_addr, sizeof(end_addr));
        }

        set_sreg(emu, 0, result);
    });

    hle.register_function("strtod", [](Emulator& emu) {
        uint64_t nptr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t endptr = get_reg(emu, UC_ARM64_REG_X1);

        std::string s = read_string(emu, nptr);
        char* end;
        double result = strtod(s.c_str(), &end);

        if (endptr) {
            uint64_t end_addr = nptr + (end - s.c_str());
            emu.mem_write(endptr, &end_addr, sizeof(end_addr));
        }

        set_dreg(emu, 0, result);
    });

    hle.register_function("strtold", [](Emulator& emu) {
        uint64_t nptr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t endptr = get_reg(emu, UC_ARM64_REG_X1);

        std::string s = read_string(emu, nptr);
        char* end;
        double result = strtod(s.c_str(), &end);  // Use double as approximation

        if (endptr) {
            uint64_t end_addr = nptr + (end - s.c_str());
            emu.mem_write(endptr, &end_addr, sizeof(end_addr));
        }

        set_dreg(emu, 0, result);
    });

    hle.register_function("strtoll", [](Emulator& emu) {
        uint64_t nptr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t endptr = get_reg(emu, UC_ARM64_REG_X1);
        int base = get_reg(emu, UC_ARM64_REG_X2);

        std::string s = read_string(emu, nptr);
        char* end;
        long long result = strtoll(s.c_str(), &end, base);

        if (endptr) {
            uint64_t end_addr = nptr + (end - s.c_str());
            emu.mem_write(endptr, &end_addr, sizeof(end_addr));
        }

        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("strtoull", [](Emulator& emu) {
        uint64_t nptr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t endptr = get_reg(emu, UC_ARM64_REG_X1);
        int base = get_reg(emu, UC_ARM64_REG_X2);

        std::string s = read_string(emu, nptr);
        char* end;
        unsigned long long result = strtoull(s.c_str(), &end, base);

        if (endptr) {
            uint64_t end_addr = nptr + (end - s.c_str());
            emu.mem_write(endptr, &end_addr, sizeof(end_addr));
        }

        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("atof", [](Emulator& emu) {
        uint64_t nptr = get_reg(emu, UC_ARM64_REG_X0);
        std::string s = read_string(emu, nptr);
        double result = atof(s.c_str());
        set_dreg(emu, 0, result);
    });

    hle.register_function("atoll", [](Emulator& emu) {
        uint64_t nptr = get_reg(emu, UC_ARM64_REG_X0);
        std::string s = read_string(emu, nptr);
        set_reg(emu, UC_ARM64_REG_X0, atoll(s.c_str()));
    });

    hle.register_function("llabs", [](Emulator& emu) {
        int64_t n = get_reg(emu, UC_ARM64_REG_X0);
        set_reg(emu, UC_ARM64_REG_X0, llabs(n));
    });

    hle.register_function("labs", [](Emulator& emu) {
        int64_t n = get_reg(emu, UC_ARM64_REG_X0);
        set_reg(emu, UC_ARM64_REG_X0, labs(n));
    });

    hle.register_function("abs", [](Emulator& emu) {
        int32_t n = get_reg(emu, UC_ARM64_REG_X0);
        set_reg(emu, UC_ARM64_REG_X0, abs(n));
    });

    // div returns a struct {int quot, int rem} - 8 bytes total
    // In ARM64 ABI, this fits in X0 (quot in lower 32 bits, rem in upper 32 bits)
    hle.register_function("div", [](Emulator& emu) {
        int32_t numer = get_reg(emu, UC_ARM64_REG_X0);
        int32_t denom = get_reg(emu, UC_ARM64_REG_X1);
        if (denom != 0) {
            int32_t quot = numer / denom;
            int32_t rem = numer % denom;
            // Pack into X0: quot in lower 32 bits, rem in upper 32 bits
            uint64_t result = ((uint64_t)(uint32_t)rem << 32) | (uint32_t)quot;
            set_reg(emu, UC_ARM64_REG_X0, result);
        } else {
            set_reg(emu, UC_ARM64_REG_X0, 0);
        }
    });

    // ldiv returns a struct {long quot, long rem} - 16 bytes total
    // In ARM64 ABI, this is returned in X0 (quot) and X1 (rem)
    hle.register_function("ldiv", [](Emulator& emu) {
        int64_t numer = get_reg(emu, UC_ARM64_REG_X0);
        int64_t denom = get_reg(emu, UC_ARM64_REG_X1);
        if (denom != 0) {
            int64_t quot = numer / denom;
            int64_t rem = numer % denom;
            set_reg(emu, UC_ARM64_REG_X0, quot);
            set_reg(emu, UC_ARM64_REG_X1, rem);
        } else {
            set_reg(emu, UC_ARM64_REG_X0, 0);
            set_reg(emu, UC_ARM64_REG_X1, 0);
        }
    });

    // lldiv returns a struct {long long quot, long long rem} - 16 bytes total
    // In ARM64 ABI, this is returned in X0 (quot) and X1 (rem)
    hle.register_function("lldiv", [](Emulator& emu) {
        int64_t numer = get_reg(emu, UC_ARM64_REG_X0);
        int64_t denom = get_reg(emu, UC_ARM64_REG_X1);
        if (denom != 0) {
            int64_t quot = numer / denom;
            int64_t rem = numer % denom;
            set_reg(emu, UC_ARM64_REG_X0, quot);
            set_reg(emu, UC_ARM64_REG_X1, rem);
        } else {
            set_reg(emu, UC_ARM64_REG_X0, 0);
            set_reg(emu, UC_ARM64_REG_X1, 0);
        }
    });

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
}

// ============================================================================
// Shared HLE state functions
// ============================================================================

void hle_set_errno(int value) {
    g_errno_value = value;
}

int hle_get_errno() {
    return g_errno_value;
}

} // namespace cross_shim
