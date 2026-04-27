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
#include <map>
#include <mutex>

namespace cross_shim {

// get_reg and set_reg are provided by emu_compat.h

constexpr size_t kMaxGuestStringLen = 1 << 20;

// Helper to read null-terminated string from emulated memory
// Uses direct host memory access when possible, falls back to batched reads
static std::string read_string(Emulator& emu, uint64_t addr, size_t max_len = kMaxGuestStringLen) {
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

    // ========================================================================
    // Additional string functions
    // ========================================================================

    // __gnu_strerror_r - GNU-specific thread-safe strerror (returns char*)
    hle.register_function("__gnu_strerror_r", [](Emulator& emu) {
        int errnum = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t buf = get_reg(emu, UC_ARM64_REG_X1);
        size_t buflen = get_reg(emu, UC_ARM64_REG_X2);

        const char* msg = strerror(errnum);
        size_t len = strlen(msg);
        if (buflen > 0 && buf != 0) {
            size_t copy_len = std::min(len, buflen - 1);
            emu.mem_write(buf, msg, copy_len);
            char null = 0;
            emu.mem_write(buf + copy_len, &null, 1);
        }
        set_reg(emu, UC_ARM64_REG_X0, buf);  // GNU version returns buf
    });

    // strerror_r - XSI-compliant version (returns int)
    hle.register_function("strerror_r", [](Emulator& emu) {
        int errnum = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t buf = get_reg(emu, UC_ARM64_REG_X1);
        size_t buflen = get_reg(emu, UC_ARM64_REG_X2);

        const char* msg = strerror(errnum);
        size_t len = strlen(msg);
        if (buflen > 0 && buf != 0) {
            size_t copy_len = std::min(len, buflen - 1);
            emu.mem_write(buf, msg, copy_len);
            char null = 0;
            emu.mem_write(buf + copy_len, &null, 1);
            set_reg(emu, UC_ARM64_REG_X0, 0);  // Success
        } else {
            set_reg(emu, UC_ARM64_REG_X0, ERANGE);
        }
    });

    // strerror - Get error string (thread-safe using thread-local buffers)
    // Uses mutex to protect the TLS buffer map
    // IMPORTANT: Uses strerror_r instead of strerror to avoid race conditions with host libc
    hle.register_function("strerror", [](Emulator& emu) {
        int errnum = get_reg(emu, UC_ARM64_REG_X0);

        // Thread-local buffer map (keyed by TLS base address) with mutex protection
        static std::mutex tls_mutex;
        static std::map<uint64_t, uint64_t> tls_buffers;
        uint64_t tls_base = get_reg(emu, UC_ARM64_REG_TPIDR_EL0);
        uint64_t buf;

        {
            std::lock_guard<std::mutex> lock(tls_mutex);
            auto it = tls_buffers.find(tls_base);
            if (it == tls_buffers.end()) {
                buf = emu.memory().heap().allocate(256, 8);
                tls_buffers[tls_base] = buf;
            } else {
                buf = it->second;
            }
        }

        // Format the error message - use strerror_r for thread safety
        // Then write directly to guest buffer
        char msg_buf[256];
        if (errnum < 0 || errnum > 133) {  // EHWPOISON = 133 on Linux
            snprintf(msg_buf, sizeof(msg_buf), "Unknown error %d", errnum);
        } else {
            // Use strerror_r (GNU version returns char*) for thread safety
            char* result = strerror_r(errnum, msg_buf, sizeof(msg_buf));
            if (result != msg_buf) {
                // GNU strerror_r may return a static string for known errors
                snprintf(msg_buf, sizeof(msg_buf), "%s", result);
            }
        }

        size_t len = strlen(msg_buf);
        emu.mem_write(buf, msg_buf, len + 1);
        set_reg(emu, UC_ARM64_REG_X0, buf);
    });

    // strerrorname_np - Get error name (GNU extension)
    hle.register_function("strerrorname_np", [](Emulator& emu) {
        int errnum = get_reg(emu, UC_ARM64_REG_X0);

        static uint64_t buf = 0;
        if (buf == 0) {
            buf = emu.memory().heap().allocate(32, 8);
        }

        // Map common error numbers to names
        const char* name = nullptr;
        switch (errnum) {
            case 0: name = "0"; break;
            case EPERM: name = "EPERM"; break;
            case ENOENT: name = "ENOENT"; break;
            case ESRCH: name = "ESRCH"; break;
            case EINTR: name = "EINTR"; break;
            case EIO: name = "EIO"; break;
            case ENXIO: name = "ENXIO"; break;
            case E2BIG: name = "E2BIG"; break;
            case ENOEXEC: name = "ENOEXEC"; break;
            case EBADF: name = "EBADF"; break;
            case ECHILD: name = "ECHILD"; break;
            case EAGAIN: name = "EAGAIN"; break;
            case ENOMEM: name = "ENOMEM"; break;
            case EACCES: name = "EACCES"; break;
            case EFAULT: name = "EFAULT"; break;
            case EBUSY: name = "EBUSY"; break;
            case EEXIST: name = "EEXIST"; break;
            case EXDEV: name = "EXDEV"; break;
            case ENODEV: name = "ENODEV"; break;
            case ENOTDIR: name = "ENOTDIR"; break;
            case EISDIR: name = "EISDIR"; break;
            case EINVAL: name = "EINVAL"; break;
            case ENFILE: name = "ENFILE"; break;
            case EMFILE: name = "EMFILE"; break;
            case ENOTTY: name = "ENOTTY"; break;
            case EFBIG: name = "EFBIG"; break;
            case ENOSPC: name = "ENOSPC"; break;
            case ESPIPE: name = "ESPIPE"; break;
            case EROFS: name = "EROFS"; break;
            case EMLINK: name = "EMLINK"; break;
            case EPIPE: name = "EPIPE"; break;
            case EDOM: name = "EDOM"; break;
            case ERANGE: name = "ERANGE"; break;
            case ENOSYS: name = "ENOSYS"; break;
            default:
                // Unknown error - return NULL
                set_reg(emu, UC_ARM64_REG_X0, 0);
                return;
        }

        emu.mem_write(buf, name, strlen(name) + 1);
        set_reg(emu, UC_ARM64_REG_X0, buf);
    });

    // strlcpy - Safe string copy (returns strlen(src))
    hle.register_function("strlcpy", [](Emulator& emu) {
        uint64_t dest = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t src = get_reg(emu, UC_ARM64_REG_X1);
        size_t size = get_reg(emu, UC_ARM64_REG_X2);

        std::string s = read_string(emu, src);
        if (size > 0 && dest != 0) {
            size_t copy_len = std::min(s.length(), size - 1);
            emu.mem_write(dest, s.c_str(), copy_len);
            char null = 0;
            emu.mem_write(dest + copy_len, &null, 1);
        }
        set_reg(emu, UC_ARM64_REG_X0, s.length());
    });

    // strlcat - Safe string concatenation
    hle.register_function("strlcat", [](Emulator& emu) {
        uint64_t dest = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t src = get_reg(emu, UC_ARM64_REG_X1);
        size_t size = get_reg(emu, UC_ARM64_REG_X2);

        std::string d = read_string(emu, dest, size);
        std::string s = read_string(emu, src);

        size_t dlen = d.length();
        if (dlen >= size) {
            set_reg(emu, UC_ARM64_REG_X0, size + s.length());
            return;
        }

        size_t copy_len = std::min(s.length(), size - dlen - 1);
        if (copy_len > 0) {
            emu.mem_write(dest + dlen, s.c_str(), copy_len);
            char null = 0;
            emu.mem_write(dest + dlen + copy_len, &null, 1);
        }
        set_reg(emu, UC_ARM64_REG_X0, dlen + s.length());
    });

    // strchrnul - Like strchr but returns end of string if not found
    hle.register_function("strchrnul", [](Emulator& emu) {
        uint64_t s = get_reg(emu, UC_ARM64_REG_X0);
        int c = get_reg(emu, UC_ARM64_REG_X1) & 0xFF;
        std::string str = read_string(emu, s);
        const char* p = strchr(str.c_str(), c);
        if (p) {
            set_reg(emu, UC_ARM64_REG_X0, s + (p - str.c_str()));
        } else {
            set_reg(emu, UC_ARM64_REG_X0, s + str.length());
        }
    });

    // strcasecmp_l - Locale-aware case-insensitive compare
    hle.register_function("strcasecmp_l", [](Emulator& emu) {
        uint64_t s1 = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t s2 = get_reg(emu, UC_ARM64_REG_X1);
        // Ignore locale (X2)
        std::string str1 = read_string(emu, s1);
        std::string str2 = read_string(emu, s2);
        set_reg(emu, UC_ARM64_REG_X0, strcasecmp(str1.c_str(), str2.c_str()));
    });

    // strncasecmp_l - Locale-aware case-insensitive compare with length
    hle.register_function("strncasecmp_l", [](Emulator& emu) {
        uint64_t s1 = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t s2 = get_reg(emu, UC_ARM64_REG_X1);
        size_t n = get_reg(emu, UC_ARM64_REG_X2);
        // Ignore locale (X3)
        std::string str1 = read_string(emu, s1, n);
        std::string str2 = read_string(emu, s2, n);
        set_reg(emu, UC_ARM64_REG_X0, strncasecmp(str1.c_str(), str2.c_str(), n));
    });

    // strcoll_l - Locale-aware string collation
    hle.register_function("strcoll_l", [](Emulator& emu) {
        uint64_t s1 = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t s2 = get_reg(emu, UC_ARM64_REG_X1);
        // Ignore locale (X2)
        std::string str1 = read_string(emu, s1);
        std::string str2 = read_string(emu, s2);
        set_reg(emu, UC_ARM64_REG_X0, strcoll(str1.c_str(), str2.c_str()));
    });

    // strxfrm_l - Locale-aware string transformation
    hle.register_function("strxfrm_l", [](Emulator& emu) {
        uint64_t dest = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t src = get_reg(emu, UC_ARM64_REG_X1);
        size_t n = get_reg(emu, UC_ARM64_REG_X2);
        // Ignore locale (X3)
        std::string s = read_string(emu, src);
        std::vector<char> buf(n + 1);
        size_t result = strxfrm(buf.data(), s.c_str(), n);
        if (dest && n > 0) {
            emu.mem_write(dest, buf.data(), std::min(result + 1, n));
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // strsignal - Get signal description string (bionic-compatible)
    // Bionic: __SIGRTMIN=32 (reserved), public SIGRTMIN=34, SIGRTMAX=64
    // Uses thread-local storage with mutex protection for thread safety
    hle.register_function("strsignal", [](Emulator& emu) {
        int sig = get_reg(emu, UC_ARM64_REG_X0);

        // Thread-local buffer map (keyed by TLS base address) with mutex protection
        static std::mutex tls_mutex;
        static std::map<uint64_t, uint64_t> tls_buffers;
        uint64_t tls_base = get_reg(emu, UC_ARM64_REG_TPIDR_EL0);
        uint64_t buf;

        {
            std::lock_guard<std::mutex> lock(tls_mutex);
            auto it = tls_buffers.find(tls_base);
            if (it == tls_buffers.end()) {
                buf = emu.memory().heap().allocate(64, 8);
                tls_buffers[tls_base] = buf;
            } else {
                buf = it->second;
            }
        }

        // Bionic signal names
        static const char* sig_names[] = {
            nullptr,           // 0
            "Hangup",          // 1 SIGHUP
            "Interrupt",       // 2 SIGINT
            "Quit",            // 3 SIGQUIT
            "Illegal instruction", // 4 SIGILL
            "Trace/breakpoint trap", // 5 SIGTRAP
            "Aborted",         // 6 SIGABRT
            "Bus error",       // 7 SIGBUS
            "Floating point exception", // 8 SIGFPE
            "Killed",          // 9 SIGKILL
            "User defined signal 1", // 10 SIGUSR1
            "Segmentation fault", // 11 SIGSEGV
            "User defined signal 2", // 12 SIGUSR2
            "Broken pipe",     // 13 SIGPIPE
            "Alarm clock",     // 14 SIGALRM
            "Terminated",      // 15 SIGTERM
            "Stack fault",     // 16 SIGSTKFLT
            "Child exited",    // 17 SIGCHLD
            "Continued",       // 18 SIGCONT
            "Stopped (signal)", // 19 SIGSTOP
            "Stopped",         // 20 SIGTSTP
            "Stopped (tty input)", // 21 SIGTTIN
            "Stopped (tty output)", // 22 SIGTTOU
            "Urgent I/O condition", // 23 SIGURG
            "CPU time limit exceeded", // 24 SIGXCPU
            "File size limit exceeded", // 25 SIGXFSZ
            "Virtual timer expired", // 26 SIGVTALRM
            "Profiling timer expired", // 27 SIGPROF
            "Window changed",  // 28 SIGWINCH
            "I/O possible",    // 29 SIGIO/SIGPOLL
            "Power failure",   // 30 SIGPWR
            "Bad system call", // 31 SIGSYS
        };

        // Bionic: __SIGRTMIN=32 (reserved), public SIGRTMIN=34
        constexpr int BIONIC_SIGRTMIN_INTERNAL = 32;  // __SIGRTMIN (reserved)
        constexpr int BIONIC_SIGRTMIN_PUBLIC = 34;    // public SIGRTMIN
        constexpr int BIONIC_SIGRTMAX = 64;

        char msg[64];
        if (sig >= 1 && sig <= 31) {
            snprintf(msg, sizeof(msg), "%s", sig_names[sig]);
        } else if (sig >= BIONIC_SIGRTMIN_PUBLIC && sig <= BIONIC_SIGRTMAX) {
            // Public real-time signals (34-64)
            int rt_num = sig - BIONIC_SIGRTMIN_PUBLIC;
            snprintf(msg, sizeof(msg), "Real-time signal %d", rt_num);
        } else {
            // Unknown: 0, negative, 32-33 (reserved __SIGRTMIN), or > 64
            snprintf(msg, sizeof(msg), "Unknown signal %d", sig);
        }

        emu.mem_write(buf, msg, strlen(msg) + 1);
        set_reg(emu, UC_ARM64_REG_X0, buf);
    });

    // __gnu_basename - GNU version of basename (doesn't modify input)
    hle.register_function("__gnu_basename", [](Emulator& emu) {
        uint64_t path = get_reg(emu, UC_ARM64_REG_X0);
        std::string p = read_string(emu, path);

        size_t pos = p.rfind('/');
        if (pos != std::string::npos) {
            set_reg(emu, UC_ARM64_REG_X0, path + pos + 1);
        } else {
            set_reg(emu, UC_ARM64_REG_X0, path);
        }
    });

    // memmem - Find memory subsequence
    hle.register_function("memmem", [](Emulator& emu) {
        uint64_t haystack = get_reg(emu, UC_ARM64_REG_X0);
        size_t haystacklen = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t needle = get_reg(emu, UC_ARM64_REG_X2);
        size_t needlelen = get_reg(emu, UC_ARM64_REG_X3);

        if (needlelen == 0) {
            set_reg(emu, UC_ARM64_REG_X0, haystack);
            return;
        }

        if (needlelen > haystacklen) {
            set_reg(emu, UC_ARM64_REG_X0, 0);
            return;
        }

        std::vector<uint8_t> h(haystacklen);
        std::vector<uint8_t> n(needlelen);
        emu.mem_read(haystack, h.data(), haystacklen);
        emu.mem_read(needle, n.data(), needlelen);

        void* result = memmem(h.data(), haystacklen, n.data(), needlelen);
        if (result) {
            set_reg(emu, UC_ARM64_REG_X0, haystack + ((uint8_t*)result - h.data()));
        } else {
            set_reg(emu, UC_ARM64_REG_X0, 0);
        }
    });

    // memset_explicit - Like memset but won't be optimized out
    hle.register_function("memset_explicit", [](Emulator& emu) {
        uint64_t s = get_reg(emu, UC_ARM64_REG_X0);
        int c = get_reg(emu, UC_ARM64_REG_X1) & 0xFF;
        size_t n = get_reg(emu, UC_ARM64_REG_X2);

        std::vector<uint8_t> buf(n, c);
        emu.mem_write(s, buf.data(), n);
        set_reg(emu, UC_ARM64_REG_X0, s);
    });
}

} // namespace cross_shim
