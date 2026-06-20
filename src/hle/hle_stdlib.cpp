/**
 * HLE Standard Library Functions
 * Environment: getenv, setenv, unsetenv
 * String to number: atoi, atol, atoll, strtol, strtoul, strtoll, strtoull, strtof, strtod, strtold, atof
 * Random: rand, srand, srand48, lrand48, drand48, erand48, jrand48, lcong48, mrand48, random, srandom, arc4random, getentropy
 * Sorting: qsort, bsearch
 * Math: abs, labs, llabs, div, ldiv, lldiv, imaxabs, imaxdiv, strtoimax, strtoumax
 */

#include "debug_log.h"
#include "hle_manager.h"
#include "cross_shim.h"
#include "memory_manager.h"
#include "hle_env_state.h"
#include "emu_compat.h"
#include "hle_manager.h"
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cerrno>
#include <cctype>
#include <vector>
#include <unordered_map>
#include <random>
#include <algorithm>

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
std::unordered_map<std::string, std::string> g_env = {
    {"OPENSSL_CONF", "/etc/ssl/openssl.cnf"},
};
std::unordered_map<std::string, uint64_t> g_putenv_guest_strings;
std::mutex g_env_mutex;

// Random number generator (shared with other modules via extern if needed)
static std::mt19937 g_rng(std::random_device{}());

static bool is_valid_strto_base(int base) {
    return !(base < 0 || base == 1 || base > 36);
}

static bool has_bionic_binary_prefix(const std::string& input, int base, size_t& prefix_pos) {
    if (!(base == 0 || base == 2)) {
        return false;
    }

    size_t i = 0;
    while (i < input.size() && std::isspace(static_cast<unsigned char>(input[i]))) {
        ++i;
    }
    if (i < input.size() && (input[i] == '+' || input[i] == '-')) {
        ++i;
    }
    if (i + 2 >= input.size()) {
        return false;
    }
    if (input[i] != '0' || (input[i + 1] != 'b' && input[i + 1] != 'B')) {
        return false;
    }
    if (input[i + 2] != '0' && input[i + 2] != '1') {
        return false;
    }

    prefix_pos = i;
    return true;
}

template <typename Result, Result (*ParseFn)(const char*, char**, int)>
static Result parse_guest_integer(Emulator& emu, uint64_t nptr, uint64_t endptr, int base) {
    std::string input = read_string(emu, nptr);
    auto write_end = [&](size_t offset) {
        if (endptr != 0) {
            uint64_t end_addr = nptr + offset;
            emu.mem_write(endptr, &end_addr, sizeof(end_addr));
        }
    };

    if (!is_valid_strto_base(base)) {
        hle_set_errno(emu, EINVAL);
        write_end(0);
        return 0;
    }

    std::string normalized = input;
    const char* parse_input = normalized.c_str();
    size_t binary_prefix_pos = 0;
    bool stripped_binary_prefix = has_bionic_binary_prefix(input, base, binary_prefix_pos);
    int parse_base = base;
    if (stripped_binary_prefix) {
        normalized.erase(binary_prefix_pos, 2);
        parse_input = normalized.c_str();
        parse_base = 2;
    }

    errno = 0;
    char* end = nullptr;
    Result result = ParseFn(parse_input, &end, parse_base);
    int saved_errno = errno;

    size_t end_offset = static_cast<size_t>(end - parse_input);
    if (stripped_binary_prefix && end_offset > binary_prefix_pos) {
        end_offset += 2;
    }
    write_end(end_offset);

    if (saved_errno != 0) {
        hle_set_errno(emu, saved_errno);
    }
    return result;
}

void register_hle_stdlib(HleManager& hle) {
    // ========================================================================
    // Environment
    // ========================================================================

    hle.register_function("getenv", [](Emulator& emu) {
        std::lock_guard<std::mutex> _el(g_env_mutex);
        uint64_t name_addr = get_reg(emu, UC_ARM64_REG_X0);
        std::string name = read_string(emu, name_addr);

        if (emu.is_debug()) {
            EMU_LOG << "[HLE] getenv: name=" << name << std::endl;
        }

        auto putenv_it = g_putenv_guest_strings.find(name);
        if (putenv_it != g_putenv_guest_strings.end()) {
            std::string assignment = read_string(emu, putenv_it->second);
            size_t eq = assignment.find('=');
            if (eq != std::string::npos && assignment.compare(0, eq, name) == 0) {
                set_reg(emu, UC_ARM64_REG_X0, putenv_it->second + eq + 1);
                return;
            }
        }

        auto it = g_env.find(name);
        if (it != g_env.end()) {
            uint64_t ptr = emu.memory().heap().allocate(it->second.length() + 1, 8);
            emu.mem_write(ptr, it->second.c_str(), it->second.length() + 1);
            set_reg(emu, UC_ARM64_REG_X0, ptr);
            return;
        }

        const char* val = getenv(name.c_str());
        if (val) {
            uint64_t ptr = emu.memory().heap().allocate(strlen(val) + 1, 8);
            emu.mem_write(ptr, val, strlen(val) + 1);
            set_reg(emu, UC_ARM64_REG_X0, ptr);
        } else {
            set_reg(emu, UC_ARM64_REG_X0, 0);
        }
    });

    hle.register_function("setenv", [](Emulator& emu) {
        std::lock_guard<std::mutex> _el(g_env_mutex);
        uint64_t name_addr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t value_addr = get_reg(emu, UC_ARM64_REG_X1);
        int overwrite = get_reg(emu, UC_ARM64_REG_X2);

        if (name_addr == 0 || value_addr == 0) {
            hle_set_errno(emu, EINVAL);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        std::string name = read_string(emu, name_addr);
        std::string value = read_string(emu, value_addr);

        int result = ::setenv(name.c_str(), value.c_str(), overwrite);
        if (result == -1) {
            hle_set_errno(emu, errno);
        } else {
            if (overwrite || g_env.find(name) == g_env.end()) {
                g_env[name] = value;
            }
            g_putenv_guest_strings.erase(name);
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("unsetenv", [](Emulator& emu) {
        std::lock_guard<std::mutex> _el(g_env_mutex);
        uint64_t name_addr = get_reg(emu, UC_ARM64_REG_X0);
        if (name_addr == 0) {
            hle_set_errno(emu, EINVAL);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }
        std::string name = read_string(emu, name_addr);
        int result = ::unsetenv(name.c_str());
        if (result == -1) {
            hle_set_errno(emu, errno);
        } else {
            g_env.erase(name);
            g_putenv_guest_strings.erase(name);
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // Environment variable (global)
    hle.register_function("environ", [](Emulator& emu) {
        // Return a pointer to an empty environ array (just NULL)
        static uint64_t environ_ptr = 0;
        if (environ_ptr == 0) {
            environ_ptr = emu.memory().heap().allocate(8, 8);
            uint64_t null = 0;
            emu.mem_write(environ_ptr, &null, 8);
        }
        set_reg(emu, UC_ARM64_REG_X0, environ_ptr);
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

        long result = parse_guest_integer<long, ::strtol>(emu, nptr, endptr, base);
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(result));
    });

    hle.register_function("strtoul", [](Emulator& emu) {
        uint64_t nptr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t endptr = get_reg(emu, UC_ARM64_REG_X1);
        int base = get_reg(emu, UC_ARM64_REG_X2);

        unsigned long result = parse_guest_integer<unsigned long, ::strtoul>(emu, nptr, endptr, base);
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("strtoll", [](Emulator& emu) {
        uint64_t nptr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t endptr = get_reg(emu, UC_ARM64_REG_X1);
        int base = get_reg(emu, UC_ARM64_REG_X2);

        long long result = parse_guest_integer<long long, ::strtoll>(emu, nptr, endptr, base);
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(result));
    });

    hle.register_function("strtoull", [](Emulator& emu) {
        uint64_t nptr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t endptr = get_reg(emu, UC_ARM64_REG_X1);
        int base = get_reg(emu, UC_ARM64_REG_X2);

        unsigned long long result =
            parse_guest_integer<unsigned long long, ::strtoull>(emu, nptr, endptr, base);
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

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
        errno = 0;
        long double result = ::strtold(s.c_str(), &end);

        if (endptr) {
            uint64_t end_addr = nptr + (end - s.c_str());
            emu.mem_write(endptr, &end_addr, sizeof(end_addr));
        }
        if (errno != 0) {
            hle_set_errno(emu, errno);
        }
        set_ldreg(emu, 0, result);
    });

    hle.register_function("atof", [](Emulator& emu) {
        uint64_t nptr = get_reg(emu, UC_ARM64_REG_X0);
        std::string s = read_string(emu, nptr);
        double result = atof(s.c_str());
        set_dreg(emu, 0, result);
    });

    // ========================================================================
    // Random numbers
    // ========================================================================

    hle.register_function("rand", [](Emulator& emu) {
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(::rand()));
    });

    hle.register_function("srand", [](Emulator& emu) {
        unsigned int seed = get_reg(emu, UC_ARM64_REG_X0);
        ::srand(seed);
    });

    hle.register_function("srand48", [](Emulator& emu) {
        long seed = get_reg(emu, UC_ARM64_REG_X0);
        ::srand48(seed);
    });

    hle.register_function("lrand48", [](Emulator& emu) {
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(::lrand48()));
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

    hle.register_function("drand48", [](Emulator& emu) {
        double result = ::drand48();
        set_dreg(emu, 0, result);
    });

    hle.register_function("erand48", [](Emulator& emu) {
        uint64_t xsubi_addr = get_reg(emu, UC_ARM64_REG_X0);
        unsigned short xsubi[3] = {};
        emu.mem_read(xsubi_addr, xsubi, sizeof(xsubi));
        double result = ::erand48(xsubi);
        emu.mem_write(xsubi_addr, xsubi, sizeof(xsubi));
        set_dreg(emu, 0, result);
    });

    hle.register_function("jrand48", [](Emulator& emu) {
        uint64_t xsubi_addr = get_reg(emu, UC_ARM64_REG_X0);
        unsigned short xsubi[3] = {};
        emu.mem_read(xsubi_addr, xsubi, sizeof(xsubi));
        long result = ::jrand48(xsubi);
        emu.mem_write(xsubi_addr, xsubi, sizeof(xsubi));
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(static_cast<int64_t>(result)));
    });

    hle.register_function("lcong48", [](Emulator& emu) {
        uint64_t param_addr = get_reg(emu, UC_ARM64_REG_X0);
        unsigned short params[7] = {};
        emu.mem_read(param_addr, params, sizeof(params));
        ::lcong48(params);
    });

    hle.register_function("mrand48", [](Emulator& emu) {
        long result = ::mrand48();
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(static_cast<int64_t>(result)));
    });

    hle.register_function("random", [](Emulator& emu) {
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(::random()));
    });

    hle.register_function("srandom", [](Emulator& emu) {
        unsigned int seed = get_reg(emu, UC_ARM64_REG_X0);
        ::srandom(seed);
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
    // Absolute value and division
    // ========================================================================

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

    // ========================================================================
    // Integer conversion functions from inttypes.h
    // ========================================================================

    hle.register_function("imaxabs", [](Emulator& emu) {
        int64_t n = get_reg(emu, UC_ARM64_REG_X0);
        set_reg(emu, UC_ARM64_REG_X0, n < 0 ? -n : n);
    });

    // imaxdiv returns struct {intmax_t quot, intmax_t rem} - 16 bytes
    // Returned in X0 (quot) and X1 (rem) on ARM64
    hle.register_function("imaxdiv", [](Emulator& emu) {
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

    hle.register_function("strtoimax", [](Emulator& emu) {
        uint64_t nptr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t endptr = get_reg(emu, UC_ARM64_REG_X1);
        int base = get_reg(emu, UC_ARM64_REG_X2);
        long long result = parse_guest_integer<long long, ::strtoll>(emu, nptr, endptr, base);
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(result));
    });

    hle.register_function("strtoumax", [](Emulator& emu) {
        uint64_t nptr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t endptr = get_reg(emu, UC_ARM64_REG_X1);
        int base = get_reg(emu, UC_ARM64_REG_X2);
        unsigned long long result =
            parse_guest_integer<unsigned long long, ::strtoull>(emu, nptr, endptr, base);
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // Locale-aware string conversion functions (*_l variants)
    hle.register_function("strtoll_l", [](Emulator& emu) {
        uint64_t nptr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t endptr = get_reg(emu, UC_ARM64_REG_X1);
        int base = get_reg(emu, UC_ARM64_REG_X2);
        // locale_t ignored

        long long result = parse_guest_integer<long long, ::strtoll>(emu, nptr, endptr, base);
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(result));
    });

    hle.register_function("strtoull_l", [](Emulator& emu) {
        uint64_t nptr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t endptr = get_reg(emu, UC_ARM64_REG_X1);
        int base = get_reg(emu, UC_ARM64_REG_X2);
        // locale_t ignored

        unsigned long long result =
            parse_guest_integer<unsigned long long, ::strtoull>(emu, nptr, endptr, base);
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("strtold_l", [](Emulator& emu) {
        uint64_t nptr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t endptr = get_reg(emu, UC_ARM64_REG_X1);
        // locale_t ignored

        std::string s = read_string(emu, nptr);
        char* end;
        errno = 0;
        long double result = ::strtold(s.c_str(), &end);

        if (endptr) {
            uint64_t end_addr = nptr + (end - s.c_str());
            emu.mem_write(endptr, &end_addr, sizeof(end_addr));
        }
        if (errno != 0) {
            hle_set_errno(emu, errno);
        }
        set_ldreg(emu, 0, result);
    });
}

} // namespace cross_shim
