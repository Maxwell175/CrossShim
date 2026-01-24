/**
 * HLE String Functions
 * strlen, strcpy, strcmp, strncpy, strncmp, strcat, strchr, strstr, strdup,
 * memcpy, memset, memcmp, memmove, memchr
 */

#include "debug_log.h"
#include "hle_manager.h"
#include "cross_shim.h"
#include "memory_manager.h"
#include "emu_compat.h"
#include <cstring>
#include <vector>
#include <algorithm>
#include <iostream>

namespace cross_shim {

// get_reg and set_reg are provided by emu_compat.h

// Helper to read null-terminated string from emulated memory
// Uses direct host memory access when possible, falls back to batched reads
static std::string read_string(Emulator& emu, uint64_t addr, size_t max_len = 4096) {
    // Try direct host memory access first (fastest path)
    void* host_ptr = emu.memory().get_host_ptr(addr);
    if (host_ptr) {
        const char* str = static_cast<const char*>(host_ptr);
        size_t len = strnlen(str, max_len);
        return std::string(str, len);
    }

    // Fall back to batched emulated reads
    std::string result;
    result.reserve(256);  // Pre-allocate for common case

    constexpr size_t CHUNK_SIZE = 256;
    char chunk[CHUNK_SIZE];

    size_t offset = 0;
    while (offset < max_len) {
        size_t to_read = std::min(CHUNK_SIZE, max_len - offset);
        if (!emu.mem_read(addr + offset, chunk, to_read)) break;

        // Search for null terminator in chunk
        for (size_t i = 0; i < to_read; i++) {
            if (chunk[i] == '\0') {
                result.append(chunk, i);
                return result;
            }
        }

        result.append(chunk, to_read);
        offset += to_read;
    }
    return result;
}

void register_hle_string(HleManager& hle) {
    // ========================================================================
    // String length
    // ========================================================================
    
    hle.register_function("strlen", [](Emulator& emu) {
        uint64_t s = get_reg(emu, UC_ARM64_REG_X0);
        std::string str = read_string(emu, s);
        set_reg(emu, UC_ARM64_REG_X0, str.length());
    });

    hle.register_function("strnlen", [](Emulator& emu) {
        uint64_t s = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t maxlen = get_reg(emu, UC_ARM64_REG_X1);
        std::string str = read_string(emu, s, maxlen);
        set_reg(emu, UC_ARM64_REG_X0, str.length());
    });

    hle.register_function("__strlen_chk", [](Emulator& emu) {
        uint64_t s = get_reg(emu, UC_ARM64_REG_X0);
        std::string str = read_string(emu, s);
        set_reg(emu, UC_ARM64_REG_X0, str.length());
    });

    // ========================================================================
    // String copy
    // ========================================================================
    
    hle.register_function("strcpy", [](Emulator& emu) {
        uint64_t dest = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t src = get_reg(emu, UC_ARM64_REG_X1);
        std::string str = read_string(emu, src);
        emu.mem_write(dest, str.c_str(), str.length() + 1);
        set_reg(emu, UC_ARM64_REG_X0, dest);
    });

    hle.register_function("__strcpy_chk", [](Emulator& emu) {
        uint64_t dest = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t src = get_reg(emu, UC_ARM64_REG_X1);
        std::string str = read_string(emu, src);
        emu.mem_write(dest, str.c_str(), str.length() + 1);
        set_reg(emu, UC_ARM64_REG_X0, dest);
    });

    hle.register_function("strncpy", [](Emulator& emu) {
        uint64_t dest = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t src = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t n = get_reg(emu, UC_ARM64_REG_X2);
        std::string str = read_string(emu, src, n);
        std::vector<char> buf(n, 0);
        std::copy(str.begin(), str.begin() + std::min(str.length(), (size_t)n), buf.begin());
        emu.mem_write(dest, buf.data(), n);
        set_reg(emu, UC_ARM64_REG_X0, dest);
    });

    hle.register_function("__strncpy_chk", [](Emulator& emu) {
        uint64_t dest = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t src = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t n = get_reg(emu, UC_ARM64_REG_X2);
        std::string str = read_string(emu, src, n);
        std::vector<char> buf(n, 0);
        std::copy(str.begin(), str.begin() + std::min(str.length(), (size_t)n), buf.begin());
        emu.mem_write(dest, buf.data(), n);
        set_reg(emu, UC_ARM64_REG_X0, dest);
    });

    // __strncpy_chk2 - same as __strncpy_chk but with different signature
    hle.register_function("__strncpy_chk2", [](Emulator& emu) {
        uint64_t dest = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t src = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t n = get_reg(emu, UC_ARM64_REG_X2);
        std::string str = read_string(emu, src, n);
        std::vector<char> buf(n, 0);
        std::copy(str.begin(), str.begin() + std::min(str.length(), (size_t)n), buf.begin());
        emu.mem_write(dest, buf.data(), n);
        set_reg(emu, UC_ARM64_REG_X0, dest);
    });

    // __strncat_chk - checked version of strncat
    hle.register_function("__strncat_chk", [](Emulator& emu) {
        uint64_t dest = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t src = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t n = get_reg(emu, UC_ARM64_REG_X2);
        std::string dest_str = read_string(emu, dest);
        std::string src_str = read_string(emu, src, n);
        std::string result = dest_str + src_str;
        emu.mem_write(dest, result.c_str(), result.length() + 1);
        set_reg(emu, UC_ARM64_REG_X0, dest);
    });

    hle.register_function("strdup", [](Emulator& emu) {
        uint64_t s = get_reg(emu, UC_ARM64_REG_X0);
        std::string str = read_string(emu, s);
        uint64_t ptr = emu.memory().heap().allocate(str.length() + 1, 8);
        if (ptr) emu.mem_write(ptr, str.c_str(), str.length() + 1);
        set_reg(emu, UC_ARM64_REG_X0, ptr);
    });

    hle.register_function("strndup", [](Emulator& emu) {
        uint64_t s = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t n = get_reg(emu, UC_ARM64_REG_X1);
        std::string str = read_string(emu, s, n);
        uint64_t ptr = emu.memory().heap().allocate(str.length() + 1, 8);
        if (ptr) emu.mem_write(ptr, str.c_str(), str.length() + 1);
        set_reg(emu, UC_ARM64_REG_X0, ptr);
    });

    // ========================================================================
    // String concatenation
    // ========================================================================
    
    hle.register_function("strcat", [](Emulator& emu) {
        uint64_t dest = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t src = get_reg(emu, UC_ARM64_REG_X1);
        std::string dest_str = read_string(emu, dest);
        std::string src_str = read_string(emu, src);
        std::string result = dest_str + src_str;
        emu.mem_write(dest, result.c_str(), result.length() + 1);
        set_reg(emu, UC_ARM64_REG_X0, dest);
    });

    hle.register_function("strncat", [](Emulator& emu) {
        uint64_t dest = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t src = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t n = get_reg(emu, UC_ARM64_REG_X2);
        std::string dest_str = read_string(emu, dest);
        std::string src_str = read_string(emu, src, n);
        std::string result = dest_str + src_str;
        emu.mem_write(dest, result.c_str(), result.length() + 1);
        set_reg(emu, UC_ARM64_REG_X0, dest);
    });

    // ========================================================================
    // String comparison
    // ========================================================================

    hle.register_function("strcmp", [](Emulator& emu) {
        uint64_t s1 = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t s2 = get_reg(emu, UC_ARM64_REG_X1);
        std::string str1 = read_string(emu, s1);
        std::string str2 = read_string(emu, s2);
        set_reg(emu, UC_ARM64_REG_X0, strcmp(str1.c_str(), str2.c_str()));
    });

    hle.register_function("strncmp", [](Emulator& emu) {
        uint64_t s1 = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t s2 = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t n = get_reg(emu, UC_ARM64_REG_X2);
        std::string str1 = read_string(emu, s1, n);
        std::string str2 = read_string(emu, s2, n);
        set_reg(emu, UC_ARM64_REG_X0, strncmp(str1.c_str(), str2.c_str(), n));
    });

    hle.register_function("strcasecmp", [](Emulator& emu) {
        uint64_t s1 = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t s2 = get_reg(emu, UC_ARM64_REG_X1);
        std::string str1 = read_string(emu, s1);
        std::string str2 = read_string(emu, s2);
        set_reg(emu, UC_ARM64_REG_X0, strcasecmp(str1.c_str(), str2.c_str()));
    });

    hle.register_function("strncasecmp", [](Emulator& emu) {
        uint64_t s1 = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t s2 = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t n = get_reg(emu, UC_ARM64_REG_X2);
        std::string str1 = read_string(emu, s1, n);
        std::string str2 = read_string(emu, s2, n);
        set_reg(emu, UC_ARM64_REG_X0, strncasecmp(str1.c_str(), str2.c_str(), n));
    });

    // ========================================================================
    // String search
    // ========================================================================

    hle.register_function("strchr", [](Emulator& emu) {
        uint64_t s = get_reg(emu, UC_ARM64_REG_X0);
        int c = get_reg(emu, UC_ARM64_REG_X1) & 0xFF;
        std::string str = read_string(emu, s);
        const char* p = strchr(str.c_str(), c);
        uint64_t result = p ? s + (p - str.c_str()) : 0;
        if (emu.is_debug() && str.length() < 100) {
            EMU_LOG << "[HLE] strchr: s=\"" << str << "\" c='" << (char)c << "' result=0x" << std::hex << result << std::dec << std::endl;
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("strrchr", [](Emulator& emu) {
        uint64_t s = get_reg(emu, UC_ARM64_REG_X0);
        int c = get_reg(emu, UC_ARM64_REG_X1) & 0xFF;
        std::string str = read_string(emu, s);
        const char* p = strrchr(str.c_str(), c);
        set_reg(emu, UC_ARM64_REG_X0, p ? s + (p - str.c_str()) : 0);
    });

    hle.register_function("strstr", [](Emulator& emu) {
        uint64_t haystack = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t needle = get_reg(emu, UC_ARM64_REG_X1);
        std::string h = read_string(emu, haystack);
        std::string n = read_string(emu, needle);
        const char* p = strstr(h.c_str(), n.c_str());
        set_reg(emu, UC_ARM64_REG_X0, p ? haystack + (p - h.c_str()) : 0);
    });

    hle.register_function("strpbrk", [](Emulator& emu) {
        uint64_t s = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t accept = get_reg(emu, UC_ARM64_REG_X1);
        std::string str = read_string(emu, s);
        std::string acc = read_string(emu, accept);
        const char* p = strpbrk(str.c_str(), acc.c_str());
        set_reg(emu, UC_ARM64_REG_X0, p ? s + (p - str.c_str()) : 0);
    });

    hle.register_function("strspn", [](Emulator& emu) {
        uint64_t s = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t accept = get_reg(emu, UC_ARM64_REG_X1);
        std::string str = read_string(emu, s);
        std::string acc = read_string(emu, accept);
        set_reg(emu, UC_ARM64_REG_X0, strspn(str.c_str(), acc.c_str()));
    });

    hle.register_function("strcspn", [](Emulator& emu) {
        uint64_t s = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t reject = get_reg(emu, UC_ARM64_REG_X1);
        std::string str = read_string(emu, s);
        std::string rej = read_string(emu, reject);
        set_reg(emu, UC_ARM64_REG_X0, strcspn(str.c_str(), rej.c_str()));
    });

    // strtok_r - thread-safe tokenizer
    hle.register_function("strtok_r", [](Emulator& emu) {
        uint64_t str = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t delim_addr = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t saveptr = get_reg(emu, UC_ARM64_REG_X2);

        std::string delim = read_string(emu, delim_addr);

        // Read the saved pointer
        uint64_t current;
        if (str == 0) {
            emu.mem_read(saveptr, &current, sizeof(current));
        } else {
            current = str;
        }

        if (current == 0) {
            set_reg(emu, UC_ARM64_REG_X0, 0);
            return;
        }

        std::string s = read_string(emu, current);

        // Skip leading delimiters
        size_t start = s.find_first_not_of(delim);
        if (start == std::string::npos) {
            uint64_t null_ptr = 0;
            emu.mem_write(saveptr, &null_ptr, sizeof(null_ptr));
            set_reg(emu, UC_ARM64_REG_X0, 0);
            return;
        }

        // Find end of token
        size_t end = s.find_first_of(delim, start);

        uint64_t token_addr = current + start;

        if (end != std::string::npos) {
            // Write null terminator
            char null = 0;
            emu.mem_write(current + end, &null, 1);
            uint64_t next = current + end + 1;
            emu.mem_write(saveptr, &next, sizeof(next));
        } else {
            uint64_t null_ptr = 0;
            emu.mem_write(saveptr, &null_ptr, sizeof(null_ptr));
        }

        set_reg(emu, UC_ARM64_REG_X0, token_addr);
    });

    hle.register_function("strtok", [](Emulator& emu) {
        // Use static saveptr for non-reentrant version
        static uint64_t static_saveptr = 0;
        uint64_t str = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t delim_addr = get_reg(emu, UC_ARM64_REG_X1);

        std::string delim = read_string(emu, delim_addr);

        uint64_t current = (str != 0) ? str : static_saveptr;

        if (current == 0) {
            set_reg(emu, UC_ARM64_REG_X0, 0);
            return;
        }

        std::string s = read_string(emu, current);
        size_t start = s.find_first_not_of(delim);
        if (start == std::string::npos) {
            static_saveptr = 0;
            set_reg(emu, UC_ARM64_REG_X0, 0);
            return;
        }

        size_t end = s.find_first_of(delim, start);
        uint64_t token_addr = current + start;

        if (end != std::string::npos) {
            char null = 0;
            emu.mem_write(current + end, &null, 1);
            static_saveptr = current + end + 1;
        } else {
            static_saveptr = 0;
        }

        set_reg(emu, UC_ARM64_REG_X0, token_addr);
    });

    hle.register_function("strcoll", [](Emulator& emu) {
        uint64_t s1 = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t s2 = get_reg(emu, UC_ARM64_REG_X1);
        std::string str1 = read_string(emu, s1);
        std::string str2 = read_string(emu, s2);
        set_reg(emu, UC_ARM64_REG_X0, strcoll(str1.c_str(), str2.c_str()));
    });

    hle.register_function("strxfrm", [](Emulator& emu) {
        uint64_t dest = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t src = get_reg(emu, UC_ARM64_REG_X1);
        size_t n = get_reg(emu, UC_ARM64_REG_X2);

        std::string s = read_string(emu, src);
        std::vector<char> buf(n + 1);
        size_t result = strxfrm(buf.data(), s.c_str(), n);
        if (dest && n > 0) {
            emu.mem_write(dest, buf.data(), std::min(result + 1, n));
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("strsep", [](Emulator& emu) {
        uint64_t stringp = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t delim_addr = get_reg(emu, UC_ARM64_REG_X1);

        uint64_t str;
        emu.mem_read(stringp, &str, sizeof(str));

        if (str == 0) {
            set_reg(emu, UC_ARM64_REG_X0, 0);
            return;
        }

        std::string s = read_string(emu, str);
        std::string delim = read_string(emu, delim_addr);

        size_t pos = s.find_first_of(delim);

        if (pos != std::string::npos) {
            char null = 0;
            emu.mem_write(str + pos, &null, 1);
            uint64_t next = str + pos + 1;
            emu.mem_write(stringp, &next, sizeof(next));
        } else {
            uint64_t null_ptr = 0;
            emu.mem_write(stringp, &null_ptr, sizeof(null_ptr));
        }

        set_reg(emu, UC_ARM64_REG_X0, str);
    });

    hle.register_function("stpcpy", [](Emulator& emu) {
        uint64_t dest = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t src = get_reg(emu, UC_ARM64_REG_X1);
        std::string s = read_string(emu, src);
        emu.mem_write(dest, s.c_str(), s.length() + 1);
        set_reg(emu, UC_ARM64_REG_X0, dest + s.length());
    });

    hle.register_function("stpncpy", [](Emulator& emu) {
        uint64_t dest = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t src = get_reg(emu, UC_ARM64_REG_X1);
        size_t n = get_reg(emu, UC_ARM64_REG_X2);

        std::string s = read_string(emu, src, n);
        size_t copy_len = std::min(s.length(), n);
        emu.mem_write(dest, s.c_str(), copy_len);

        // Pad with nulls if needed
        if (copy_len < n) {
            std::vector<char> nulls(n - copy_len, 0);
            emu.mem_write(dest + copy_len, nulls.data(), nulls.size());
        }

        set_reg(emu, UC_ARM64_REG_X0, dest + copy_len);
    });

    hle.register_function("strnstr", [](Emulator& emu) {
        uint64_t haystack = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t needle = get_reg(emu, UC_ARM64_REG_X1);
        size_t len = get_reg(emu, UC_ARM64_REG_X2);

        std::string h = read_string(emu, haystack, len);
        std::string n = read_string(emu, needle);

        size_t pos = h.find(n);
        if (pos != std::string::npos && pos + n.length() <= len) {
            set_reg(emu, UC_ARM64_REG_X0, haystack + pos);
        } else {
            set_reg(emu, UC_ARM64_REG_X0, 0);
        }
    });

    hle.register_function("strcasestr", [](Emulator& emu) {
        uint64_t haystack = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t needle = get_reg(emu, UC_ARM64_REG_X1);

        std::string h = read_string(emu, haystack);
        std::string n = read_string(emu, needle);

        // Convert to lowercase for comparison
        std::string h_lower = h, n_lower = n;
        for (auto& c : h_lower) c = tolower(c);
        for (auto& c : n_lower) c = tolower(c);

        size_t pos = h_lower.find(n_lower);
        if (pos != std::string::npos) {
            set_reg(emu, UC_ARM64_REG_X0, haystack + pos);
        } else {
            set_reg(emu, UC_ARM64_REG_X0, 0);
        }
    });
}

} // namespace cross_shim
