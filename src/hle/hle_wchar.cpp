/**
 * HLE Wide Character Functions
 * Basic: wcslen, wcscpy, wcsncpy, wcscmp, wcsncmp, wcscat, wcsncat, wcsdup, wcsnlen
 * Memory: wmemchr, wmemcmp, wmemcpy, wmemmove, wmempcpy, wmemset
 * Conversion: wcstol, wcstoul, wcstoll, wcstoull, wcstoimax, wcstoumax, wcstod, wcstof, wcstold
 * Comparison: wcscoll, wcsxfrm, wcscasecmp, wcsncasecmp
 * Search: wcsstr, wcscspn, wcsspn, wcspbrk, wcstok, wcschr, wcsrchr
 * Other: wcpcpy, wcpncpy, wcslcpy, wcslcat
 * I/O: ungetwc, getwc, fgetwc, fputwc, putwc, putwchar, getwchar, fgetws, fputws, fwide
 * Formatting: swprintf, fwprintf, wprintf, swscanf, vswprintf, wcsftime
 */

#include "debug_log.h"
#include "hle_format.h"
#include "hle_manager.h"
#include "hle_scan.h"
#include "hle_stdio_state.h"
#include "cross_shim.h"
#include "memory_manager.h"
#include "emu_compat.h"
#include <cerrno>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cwchar>
#include <quadmath.h>
#include <iostream>
#include <vector>
#include <algorithm>
#include <ctime>

namespace cross_shim {

namespace {

enum class Utf8DecodeStatus {
    Ok,
    Incomplete,
    Invalid,
};

static int utf8_length(uint32_t wc) {
    if (wc <= 0x7f) return 1;
    if (wc <= 0x7ff) return 2;
    if (wc <= 0xffff && (wc < 0xd800 || wc > 0xdfff)) return 3;
    if (wc <= 0x10ffff) return 4;
    return -1;
}

static int utf8_expected_length_from_lead(unsigned char lead) {
    if (lead < 0x80) return 1;
    if (lead >= 0xc2 && lead <= 0xdf) return 2;
    if (lead >= 0xe0 && lead <= 0xef) return 3;
    if (lead >= 0xf0 && lead <= 0xf4) return 4;
    return -1;
}

static int encode_utf8(uint32_t wc, char* out) {
    if (wc <= 0x7f) {
        out[0] = static_cast<char>(wc);
        return 1;
    }
    if (wc <= 0x7ff) {
        out[0] = static_cast<char>(0xc0 | (wc >> 6));
        out[1] = static_cast<char>(0x80 | (wc & 0x3f));
        return 2;
    }
    if (wc <= 0xffff && (wc < 0xd800 || wc > 0xdfff)) {
        out[0] = static_cast<char>(0xe0 | (wc >> 12));
        out[1] = static_cast<char>(0x80 | ((wc >> 6) & 0x3f));
        out[2] = static_cast<char>(0x80 | (wc & 0x3f));
        return 3;
    }
    if (wc <= 0x10ffff) {
        out[0] = static_cast<char>(0xf0 | (wc >> 18));
        out[1] = static_cast<char>(0x80 | ((wc >> 12) & 0x3f));
        out[2] = static_cast<char>(0x80 | ((wc >> 6) & 0x3f));
        out[3] = static_cast<char>(0x80 | (wc & 0x3f));
        return 4;
    }
    return -1;
}

static Utf8DecodeStatus decode_utf8(const unsigned char* input, size_t available, uint32_t& wc,
                                    size_t& consumed) {
    if (available == 0) {
        return Utf8DecodeStatus::Incomplete;
    }

    unsigned char b0 = input[0];
    if (b0 < 0x80) {
        wc = b0;
        consumed = 1;
        return Utf8DecodeStatus::Ok;
    }

    if (b0 >= 0xc2 && b0 <= 0xdf) {
        if (available < 2) return Utf8DecodeStatus::Incomplete;
        unsigned char b1 = input[1];
        if ((b1 & 0xc0) != 0x80) return Utf8DecodeStatus::Invalid;
        wc = ((b0 & 0x1f) << 6) | (b1 & 0x3f);
        consumed = 2;
        return Utf8DecodeStatus::Ok;
    }

    if (b0 >= 0xe0 && b0 <= 0xef) {
        if (available < 3) return Utf8DecodeStatus::Incomplete;
        unsigned char b1 = input[1];
        unsigned char b2 = input[2];
        if ((b1 & 0xc0) != 0x80 || (b2 & 0xc0) != 0x80) return Utf8DecodeStatus::Invalid;
        if ((b0 == 0xe0 && b1 < 0xa0) || (b0 == 0xed && b1 >= 0xa0)) return Utf8DecodeStatus::Invalid;
        wc = ((b0 & 0x0f) << 12) | ((b1 & 0x3f) << 6) | (b2 & 0x3f);
        consumed = 3;
        return Utf8DecodeStatus::Ok;
    }

    if (b0 >= 0xf0 && b0 <= 0xf4) {
        if (available < 4) return Utf8DecodeStatus::Incomplete;
        unsigned char b1 = input[1];
        unsigned char b2 = input[2];
        unsigned char b3 = input[3];
        if ((b1 & 0xc0) != 0x80 || (b2 & 0xc0) != 0x80 || (b3 & 0xc0) != 0x80) return Utf8DecodeStatus::Invalid;
        if ((b0 == 0xf0 && b1 < 0x90) || (b0 == 0xf4 && b1 >= 0x90)) return Utf8DecodeStatus::Invalid;
        wc = ((b0 & 0x07) << 18) | ((b1 & 0x3f) << 12) | ((b2 & 0x3f) << 6) | (b3 & 0x3f);
        consumed = 4;
        return Utf8DecodeStatus::Ok;
    }

    return Utf8DecodeStatus::Invalid;
}

static wint_t read_utf8_wchar(FILE* fp, int& out_errno) {
    out_errno = 0;
    int first = ::fgetc(fp);
    if (first == EOF) {
        if (std::ferror(fp)) {
            out_errno = errno;
        }
        return WEOF;
    }

    unsigned char bytes[4] = {static_cast<unsigned char>(first), 0, 0, 0};
    int expected = utf8_expected_length_from_lead(bytes[0]);
    if (expected == -1) {
        out_errno = EILSEQ;
        return WEOF;
    }

    for (int i = 1; i < expected; ++i) {
        int next = ::fgetc(fp);
        if (next == EOF) {
            out_errno = std::ferror(fp) ? errno : EILSEQ;
            return WEOF;
        }
        bytes[i] = static_cast<unsigned char>(next);
    }

    uint32_t wc = 0;
    size_t consumed = 0;
    Utf8DecodeStatus status = decode_utf8(bytes, expected, wc, consumed);
    if (status != Utf8DecodeStatus::Ok || static_cast<int>(consumed) != expected) {
        out_errno = EILSEQ;
        return WEOF;
    }
    return static_cast<wint_t>(wc);
}

static wint_t write_utf8_wchar(FILE* fp, uint32_t wc, int& out_errno) {
    out_errno = 0;
    char bytes[4];
    int len = encode_utf8(wc, bytes);
    if (len == -1) {
        out_errno = EILSEQ;
        return WEOF;
    }

    size_t written = std::fwrite(bytes, 1, len, fp);
    if (written != static_cast<size_t>(len)) {
        out_errno = errno != 0 ? errno : EIO;
        return WEOF;
    }
    return static_cast<wint_t>(wc);
}

static wint_t unread_utf8_wchar(FILE* fp, uint32_t wc, int& out_errno) {
    out_errno = 0;
    char bytes[4];
    int len = encode_utf8(wc, bytes);
    if (len == -1) {
        out_errno = EILSEQ;
        return WEOF;
    }

    for (int i = len - 1; i >= 0; --i) {
        if (::ungetc(static_cast<unsigned char>(bytes[i]), fp) == EOF) {
            out_errno = errno != 0 ? errno : EIO;
            return WEOF;
        }
    }
    return static_cast<wint_t>(wc);
}

static bool decode_utf8_string(const std::string& input, std::vector<uint32_t>& output) {
    output.clear();

    size_t pos = 0;
    while (pos < input.size()) {
        uint32_t wc = 0;
        size_t consumed = 0;
        Utf8DecodeStatus status = decode_utf8(
            reinterpret_cast<const unsigned char*>(input.data() + pos), input.size() - pos, wc, consumed);
        if (status != Utf8DecodeStatus::Ok || consumed == 0) {
            return false;
        }
        output.push_back(wc);
        pos += consumed;
    }

    return true;
}

static int write_guest_wide_output(Emulator& emu, uint64_t ws, size_t n, const std::string& utf8,
                                   int& out_errno) {
    out_errno = 0;
    std::vector<uint32_t> codepoints;
    if (!decode_utf8_string(utf8, codepoints)) {
        out_errno = EILSEQ;
        return -1;
    }

    if (n == 0) {
        return -1;
    }

    size_t copy_count = codepoints.size();
    if (copy_count >= n) {
        copy_count = n - 1;
    }

    for (size_t i = 0; i < copy_count; ++i) {
        emu.mem_write(ws + i * 4, &codepoints[i], 4);
    }
    uint32_t zero = 0;
    emu.mem_write(ws + copy_count * 4, &zero, 4);

    if (codepoints.size() >= n) {
        return -1;
    }
    return static_cast<int>(codepoints.size());
}

static bool is_valid_strto_base(int base) {
    return base == 0 || (base >= 2 && base <= 36);
}

static std::string read_ascii_guest_wide_string(Emulator& emu, uint64_t addr, size_t max_len = 4096) {
    std::string result;
    for (size_t i = 0; i < max_len; ++i) {
        uint32_t wc = 0;
        if (!emu.mem_read(addr + i * 4, &wc, 4) || wc == 0) {
            break;
        }
        if (wc > 0x7f) {
            break;
        }
        result.push_back(static_cast<char>(wc));
    }
    return result;
}

static void write_guest_wide_endptr(Emulator& emu, uint64_t nptr, uint64_t endptr,
                                    const char* begin, const char* end) {
    if (endptr == 0) {
        return;
    }
    uint64_t end_addr = nptr + static_cast<uint64_t>(end - begin) * 4;
    emu.mem_write(endptr, &end_addr, sizeof(end_addr));
}

template <typename T, typename ParseFn>
static T parse_guest_wide_integer(Emulator& emu, uint64_t nptr, uint64_t endptr, int base,
                                  ParseFn parse_fn, int& out_errno) {
    if (!is_valid_strto_base(base)) {
        out_errno = EINVAL;
        if (endptr != 0) {
            emu.mem_write(endptr, &nptr, sizeof(nptr));
        }
        return static_cast<T>(0);
    }

    std::string narrow = read_ascii_guest_wide_string(emu, nptr);
    errno = 0;
    char* end = nullptr;
    T result = parse_fn(narrow.c_str(), &end, base);
    out_errno = errno;
    write_guest_wide_endptr(emu, nptr, endptr, narrow.c_str(), end);
    return result;
}

template <typename T, typename ParseFn>
static T parse_guest_wide_float(Emulator& emu, uint64_t nptr, uint64_t endptr,
                                ParseFn parse_fn, int& out_errno) {
    std::string narrow = read_ascii_guest_wide_string(emu, nptr);
    errno = 0;
    char* end = nullptr;
    T result = parse_fn(narrow.c_str(), &end);
    out_errno = errno;
    write_guest_wide_endptr(emu, nptr, endptr, narrow.c_str(), end);
    return result;
}

static __float128 parse_guest_wide_quad(Emulator& emu, uint64_t nptr, uint64_t endptr,
                                        int& out_errno) {
    std::string narrow = read_ascii_guest_wide_string(emu, nptr);
    errno = 0;
    char* end = nullptr;
    __float128 result = ::strtoflt128(narrow.c_str(), &end);
    out_errno = errno;
    write_guest_wide_endptr(emu, nptr, endptr, narrow.c_str(), end);
    return result;
}

static void set_guest_quad_result(Emulator& emu, __float128 value) {
    uint8_t buf[16] = {0};
    memcpy(buf, &value, sizeof(value));
    set_qreg(emu, UC_ARM64_REG_Q0, buf);
}

static bool is_valid_unicode_scalar(uint32_t wc) {
    return wc <= 0x10ffff && !(wc >= 0xd800 && wc <= 0xdfff);
}

static size_t guest_concat_length(Emulator& emu, uint64_t dest, size_t max_len = 4096) {
    for (size_t i = 0; i < max_len; ++i) {
        uint32_t wc = 0;
        emu.mem_read(dest + i * 4, &wc, 4);
        if (wc == 0) {
            return i;
        }
        if (i == 0 && !is_valid_unicode_scalar(wc)) {
            return 0;
        }
    }
    return 0;
}

}  // namespace

static std::string read_string(Emulator& emu, uint64_t addr, size_t max_len = 4096) {
    std::string result;
    char c;
    for (size_t i = 0; i < max_len; i++) {
        if (!emu.mem_read(addr + i, &c, 1) || c == '\0') break;
        result += c;
    }
    return result;
}

void register_hle_wchar(HleManager& hle) {
    // ========================================================================
    // Basic wide string functions
    // ========================================================================

    hle.register_function("wmemcmp", [](Emulator& emu) {
        uint64_t s1 = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t s2 = get_reg(emu, UC_ARM64_REG_X1);
        size_t n = get_reg(emu, UC_ARM64_REG_X2);

        for (size_t i = 0; i < n; ++i) {
            uint32_t wc1 = 0;
            uint32_t wc2 = 0;
            emu.mem_read(s1 + i * 4, &wc1, 4);
            emu.mem_read(s2 + i * 4, &wc2, 4);
            if (wc1 != wc2) {
                set_reg(emu, UC_ARM64_REG_X0, wc1 < wc2 ? static_cast<uint64_t>(-1) : 1);
                return;
            }
        }

        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("wmemchr", [](Emulator& emu) {
        uint64_t s = get_reg(emu, UC_ARM64_REG_X0);
        uint32_t target = static_cast<uint32_t>(get_reg(emu, UC_ARM64_REG_X1));
        size_t n = get_reg(emu, UC_ARM64_REG_X2);

        for (size_t i = 0; i < n; ++i) {
            uint32_t wc = 0;
            emu.mem_read(s + i * 4, &wc, 4);
            if (wc == target) {
                set_reg(emu, UC_ARM64_REG_X0, s + i * 4);
                return;
            }
        }

        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("wmemcpy", [](Emulator& emu) {
        uint64_t dest = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t src = get_reg(emu, UC_ARM64_REG_X1);
        size_t n = get_reg(emu, UC_ARM64_REG_X2);

        std::vector<uint32_t> buffer(n);
        emu.mem_read(src, buffer.data(), n * 4);
        emu.mem_write(dest, buffer.data(), n * 4);
        set_reg(emu, UC_ARM64_REG_X0, dest);
    });

    hle.register_function("wmemmove", [](Emulator& emu) {
        uint64_t dest = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t src = get_reg(emu, UC_ARM64_REG_X1);
        size_t n = get_reg(emu, UC_ARM64_REG_X2);

        std::vector<uint32_t> buffer(n);
        emu.mem_read(src, buffer.data(), n * 4);
        emu.mem_write(dest, buffer.data(), n * 4);
        set_reg(emu, UC_ARM64_REG_X0, dest);
    });

    hle.register_function("wmempcpy", [](Emulator& emu) {
        uint64_t dest = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t src = get_reg(emu, UC_ARM64_REG_X1);
        size_t n = get_reg(emu, UC_ARM64_REG_X2);

        std::vector<uint32_t> buffer(n);
        emu.mem_read(src, buffer.data(), n * 4);
        emu.mem_write(dest, buffer.data(), n * 4);
        set_reg(emu, UC_ARM64_REG_X0, dest + n * 4);
    });

    hle.register_function("wmemset", [](Emulator& emu) {
        uint64_t dest = get_reg(emu, UC_ARM64_REG_X0);
        uint32_t value = static_cast<uint32_t>(get_reg(emu, UC_ARM64_REG_X1));
        size_t n = get_reg(emu, UC_ARM64_REG_X2);

        for (size_t i = 0; i < n; ++i) {
            emu.mem_write(dest + i * 4, &value, 4);
        }
        set_reg(emu, UC_ARM64_REG_X0, dest);
    });

    hle.register_function("wcslen", [](Emulator& emu) {
        uint64_t s = get_reg(emu, UC_ARM64_REG_X0);
        size_t len = 0;
        uint32_t wc;
        while (true) {
            emu.mem_read(s + len * 4, &wc, 4);
            if (wc == 0) break;
            len++;
        }
        set_reg(emu, UC_ARM64_REG_X0, len);
    });

    hle.register_function("wcscpy", [](Emulator& emu) {
        uint64_t dest = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t src = get_reg(emu, UC_ARM64_REG_X1);

        uint64_t d = dest;
        uint32_t wc;
        do {
            emu.mem_read(src, &wc, 4);
            emu.mem_write(d, &wc, 4);
            src += 4;
            d += 4;
        } while (wc != 0);

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
                set_reg(emu, UC_ARM64_REG_X0, (wc1 < wc2) ? -1 : ((wc1 > wc2) ? 1 : 0));
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
                set_reg(emu, UC_ARM64_REG_X0, (wc1 < wc2) ? -1 : ((wc1 > wc2) ? 1 : 0));
                return;
            }
        }
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("wcsnlen", [](Emulator& emu) {
        uint64_t s = get_reg(emu, UC_ARM64_REG_X0);
        size_t maxlen = get_reg(emu, UC_ARM64_REG_X1);

        size_t len = 0;
        while (len < maxlen) {
            uint32_t wc;
            emu.mem_read(s + len * 4, &wc, 4);
            if (wc == 0) break;
            len++;
        }
        set_reg(emu, UC_ARM64_REG_X0, len);
    });

    hle.register_function("wcsdup", [](Emulator& emu) {
        uint64_t s = get_reg(emu, UC_ARM64_REG_X0);

        size_t len = 0;
        while (true) {
            uint32_t wc;
            emu.mem_read(s + len * 4, &wc, 4);
            if (wc == 0) break;
            len++;
        }

        uint64_t ptr = emu.memory().heap().allocate((len + 1) * 4, 8);
        if (ptr) {
            std::vector<uint32_t> buf(len + 1);
            emu.mem_read(s, buf.data(), (len + 1) * 4);
            emu.mem_write(ptr, buf.data(), (len + 1) * 4);
        }
        set_reg(emu, UC_ARM64_REG_X0, ptr);
    });

    hle.register_function("wcscat", [](Emulator& emu) {
        uint64_t dest = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t src = get_reg(emu, UC_ARM64_REG_X1);

        size_t dest_len = guest_concat_length(emu, dest);

        // Copy src
        size_t i = 0;
        while (true) {
            uint32_t wc;
            emu.mem_read(src + i * 4, &wc, 4);
            emu.mem_write(dest + (dest_len + i) * 4, &wc, 4);
            if (wc == 0) break;
            i++;
        }

        set_reg(emu, UC_ARM64_REG_X0, dest);
    });

    hle.register_function("wcsncat", [](Emulator& emu) {
        uint64_t dest = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t src = get_reg(emu, UC_ARM64_REG_X1);
        size_t n = get_reg(emu, UC_ARM64_REG_X2);

        size_t dest_len = guest_concat_length(emu, dest);

        // Copy src up to n chars
        size_t i = 0;
        while (i < n) {
            uint32_t wc;
            emu.mem_read(src + i * 4, &wc, 4);
            emu.mem_write(dest + (dest_len + i) * 4, &wc, 4);
            if (wc == 0) break;
            i++;
        }

        // Ensure null termination
        if (i == n) {
            uint32_t null = 0;
            emu.mem_write(dest + (dest_len + n) * 4, &null, 4);
        }

        set_reg(emu, UC_ARM64_REG_X0, dest);
    });

    // ========================================================================
    // Wide string search functions
    // ========================================================================

    hle.register_function("wcsstr", [](Emulator& emu) {
        uint64_t haystack = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t needle = get_reg(emu, UC_ARM64_REG_X1);

        // Get needle length
        size_t needle_len = 0;
        while (true) {
            uint32_t wc;
            emu.mem_read(needle + needle_len * 4, &wc, 4);
            if (wc == 0) break;
            needle_len++;
        }

        if (needle_len == 0) {
            set_reg(emu, UC_ARM64_REG_X0, haystack);
            return;
        }

        // Read needle into memory
        std::vector<uint32_t> needle_buf(needle_len);
        emu.mem_read(needle, needle_buf.data(), needle_len * 4);

        // Search
        size_t i = 0;
        while (true) {
            uint32_t wc;
            emu.mem_read(haystack + i * 4, &wc, 4);
            if (wc == 0) break;

            // Check for match
            bool match = true;
            for (size_t j = 0; j < needle_len && match; j++) {
                uint32_t hc;
                emu.mem_read(haystack + (i + j) * 4, &hc, 4);
                if (hc != needle_buf[j]) match = false;
            }

            if (match) {
                set_reg(emu, UC_ARM64_REG_X0, haystack + i * 4);
                return;
            }
            i++;
        }

        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("wcschr", [](Emulator& emu) {
        uint64_t ws = get_reg(emu, UC_ARM64_REG_X0);
        uint32_t wc = get_reg(emu, UC_ARM64_REG_X1);

        size_t i = 0;
        while (true) {
            uint32_t c;
            emu.mem_read(ws + i * 4, &c, 4);
            if (c == wc) {
                set_reg(emu, UC_ARM64_REG_X0, ws + i * 4);
                return;
            }
            if (c == 0) break;
            i++;
        }
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("wcsrchr", [](Emulator& emu) {
        uint64_t ws = get_reg(emu, UC_ARM64_REG_X0);
        uint32_t wc = get_reg(emu, UC_ARM64_REG_X1);

        uint64_t last = 0;
        size_t i = 0;
        while (true) {
            uint32_t c;
            emu.mem_read(ws + i * 4, &c, 4);
            if (c == wc) {
                last = ws + i * 4;
            }
            if (c == 0) break;
            i++;
        }
        set_reg(emu, UC_ARM64_REG_X0, last);
    });

    hle.register_function("wcscspn", [](Emulator& emu) {
        uint64_t ws = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t reject = get_reg(emu, UC_ARM64_REG_X1);

        // Get reject set
        std::vector<uint32_t> reject_set;
        size_t i = 0;
        while (true) {
            uint32_t wc;
            emu.mem_read(reject + i * 4, &wc, 4);
            if (wc == 0) break;
            reject_set.push_back(wc);
            i++;
        }

        // Find first character in reject set
        size_t j = 0;
        while (true) {
            uint32_t wc;
            emu.mem_read(ws + j * 4, &wc, 4);
            if (wc == 0) break;
            if (std::find(reject_set.begin(), reject_set.end(), wc) != reject_set.end()) {
                break;
            }
            j++;
        }
        set_reg(emu, UC_ARM64_REG_X0, j);
    });

    hle.register_function("wcsspn", [](Emulator& emu) {
        uint64_t ws = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t accept = get_reg(emu, UC_ARM64_REG_X1);

        // Get accept set
        std::vector<uint32_t> accept_set;
        size_t i = 0;
        while (true) {
            uint32_t wc;
            emu.mem_read(accept + i * 4, &wc, 4);
            if (wc == 0) break;
            accept_set.push_back(wc);
            i++;
        }

        // Find first character NOT in accept set
        size_t j = 0;
        while (true) {
            uint32_t wc;
            emu.mem_read(ws + j * 4, &wc, 4);
            if (wc == 0) break;
            if (std::find(accept_set.begin(), accept_set.end(), wc) == accept_set.end()) {
                break;
            }
            j++;
        }
        set_reg(emu, UC_ARM64_REG_X0, j);
    });

    hle.register_function("wcspbrk", [](Emulator& emu) {
        uint64_t ws = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t accept = get_reg(emu, UC_ARM64_REG_X1);

        // Get accept set
        std::vector<uint32_t> accept_set;
        size_t i = 0;
        while (true) {
            uint32_t wc;
            emu.mem_read(accept + i * 4, &wc, 4);
            if (wc == 0) break;
            accept_set.push_back(wc);
            i++;
        }

        // Find first character in accept set
        size_t j = 0;
        while (true) {
            uint32_t wc;
            emu.mem_read(ws + j * 4, &wc, 4);
            if (wc == 0) {
                set_reg(emu, UC_ARM64_REG_X0, 0);
                return;
            }
            if (std::find(accept_set.begin(), accept_set.end(), wc) != accept_set.end()) {
                set_reg(emu, UC_ARM64_REG_X0, ws + j * 4);
                return;
            }
            j++;
        }
    });

    hle.register_function("wcstok", [](Emulator& emu) {
        uint64_t ws = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t delim = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t ptr = get_reg(emu, UC_ARM64_REG_X2);

        uint64_t s;
        if (ws == 0) {
            emu.mem_read(ptr, &s, 8);
        } else {
            s = ws;
        }

        if (s == 0) {
            set_reg(emu, UC_ARM64_REG_X0, 0);
            return;
        }

        // Get delimiters
        std::vector<uint32_t> delims;
        size_t i = 0;
        while (true) {
            uint32_t wc;
            emu.mem_read(delim + i * 4, &wc, 4);
            if (wc == 0) break;
            delims.push_back(wc);
            i++;
        }

        // Skip leading delimiters
        size_t j = 0;
        while (true) {
            uint32_t wc;
            emu.mem_read(s + j * 4, &wc, 4);
            if (wc == 0) {
                uint64_t null = 0;
                emu.mem_write(ptr, &null, 8);
                set_reg(emu, UC_ARM64_REG_X0, 0);
                return;
            }
            if (std::find(delims.begin(), delims.end(), wc) == delims.end()) break;
            j++;
        }

        uint64_t token = s + j * 4;

        // Find end of token
        while (true) {
            uint32_t wc;
            emu.mem_read(s + j * 4, &wc, 4);
            if (wc == 0) {
                uint64_t null = 0;
                emu.mem_write(ptr, &null, 8);
                break;
            }
            if (std::find(delims.begin(), delims.end(), wc) != delims.end()) {
                uint32_t null = 0;
                emu.mem_write(s + j * 4, &null, 4);
                uint64_t next = s + (j + 1) * 4;
                emu.mem_write(ptr, &next, 8);
                break;
            }
            j++;
        }

        set_reg(emu, UC_ARM64_REG_X0, token);
    });

    // ========================================================================
    // Wide string copy variants
    // ========================================================================

    hle.register_function("wcpcpy", [](Emulator& emu) {
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
        set_reg(emu, UC_ARM64_REG_X0, dest + i * 4);  // Return end of dest
    });

    hle.register_function("wcpncpy", [](Emulator& emu) {
        uint64_t dest = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t src = get_reg(emu, UC_ARM64_REG_X1);
        size_t n = get_reg(emu, UC_ARM64_REG_X2);

        size_t i = 0;
        while (i < n) {
            uint32_t wc = 0;
            emu.mem_read(src + i * 4, &wc, 4);
            emu.mem_write(dest + i * 4, &wc, 4);
            if (wc == 0) {
                size_t return_index = i;
                ++i;
                while (i < n) {
                    uint32_t zero = 0;
                    emu.mem_write(dest + i * 4, &zero, 4);
                    ++i;
                }
                set_reg(emu, UC_ARM64_REG_X0, dest + return_index * 4);
                return;
            }
            ++i;
        }
        set_reg(emu, UC_ARM64_REG_X0, dest + n * 4);
    });

    hle.register_function("wcslcpy", [](Emulator& emu) {
        uint64_t dest = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t src = get_reg(emu, UC_ARM64_REG_X1);
        size_t size = get_reg(emu, UC_ARM64_REG_X2);

        size_t src_len = 0;
        while (true) {
            uint32_t wc;
            emu.mem_read(src + src_len * 4, &wc, 4);
            if (wc == 0) break;
            src_len++;
        }

        if (size > 0) {
            size_t copy_len = (src_len < size) ? src_len : (size - 1);
            for (size_t i = 0; i < copy_len; i++) {
                uint32_t wc;
                emu.mem_read(src + i * 4, &wc, 4);
                emu.mem_write(dest + i * 4, &wc, 4);
            }
            uint32_t null = 0;
            emu.mem_write(dest + copy_len * 4, &null, 4);
        }
        set_reg(emu, UC_ARM64_REG_X0, src_len);
    });

    hle.register_function("wcslcat", [](Emulator& emu) {
        uint64_t dest = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t src = get_reg(emu, UC_ARM64_REG_X1);
        size_t size = get_reg(emu, UC_ARM64_REG_X2);

        size_t dest_len = 0;
        while (dest_len < size) {
            uint32_t wc;
            emu.mem_read(dest + dest_len * 4, &wc, 4);
            if (wc == 0) break;
            dest_len++;
        }

        size_t src_len = 0;
        while (true) {
            uint32_t wc;
            emu.mem_read(src + src_len * 4, &wc, 4);
            if (wc == 0) break;
            src_len++;
        }

        if (dest_len >= size) {
            set_reg(emu, UC_ARM64_REG_X0, size + src_len);
            return;
        }

        size_t copy_len = (src_len < size - dest_len - 1) ? src_len : (size - dest_len - 1);
        for (size_t i = 0; i < copy_len; i++) {
            uint32_t wc;
            emu.mem_read(src + i * 4, &wc, 4);
            emu.mem_write(dest + (dest_len + i) * 4, &wc, 4);
        }
        uint32_t null = 0;
        emu.mem_write(dest + (dest_len + copy_len) * 4, &null, 4);

        set_reg(emu, UC_ARM64_REG_X0, dest_len + src_len);
    });

    // ========================================================================
    // Wide string comparison functions
    // ========================================================================

    hle.register_function("wcscoll", [](Emulator& emu) {
        uint64_t s1 = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t s2 = get_reg(emu, UC_ARM64_REG_X1);

        size_t i = 0;
        while (true) {
            uint32_t wc1, wc2;
            emu.mem_read(s1 + i * 4, &wc1, 4);
            emu.mem_read(s2 + i * 4, &wc2, 4);
            if (wc1 != wc2 || wc1 == 0) {
                set_reg(emu, UC_ARM64_REG_X0, (wc1 < wc2) ? -1 : ((wc1 > wc2) ? 1 : 0));
                return;
            }
            i++;
        }
    });

    hle.register_function("wcscoll_l", [](Emulator& emu) {
        uint64_t s1 = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t s2 = get_reg(emu, UC_ARM64_REG_X1);
        // locale ignored

        size_t i = 0;
        while (true) {
            uint32_t wc1, wc2;
            emu.mem_read(s1 + i * 4, &wc1, 4);
            emu.mem_read(s2 + i * 4, &wc2, 4);
            if (wc1 != wc2 || wc1 == 0) {
                set_reg(emu, UC_ARM64_REG_X0, (wc1 < wc2) ? -1 : ((wc1 > wc2) ? 1 : 0));
                return;
            }
            i++;
        }
    });

    hle.register_function("wcsxfrm", [](Emulator& emu) {
        uint64_t dest = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t src = get_reg(emu, UC_ARM64_REG_X1);
        size_t n = get_reg(emu, UC_ARM64_REG_X2);

        size_t src_len = 0;
        while (true) {
            uint32_t wc;
            emu.mem_read(src + src_len * 4, &wc, 4);
            if (wc == 0) break;
            src_len++;
        }

        if (n > 0 && dest) {
            size_t copy_len = (src_len < n) ? src_len : (n - 1);
            for (size_t i = 0; i < copy_len; i++) {
                uint32_t wc;
                emu.mem_read(src + i * 4, &wc, 4);
                emu.mem_write(dest + i * 4, &wc, 4);
            }
            uint32_t null = 0;
            emu.mem_write(dest + copy_len * 4, &null, 4);
        }
        set_reg(emu, UC_ARM64_REG_X0, src_len);
    });

    hle.register_function("wcsxfrm_l", [](Emulator& emu) {
        uint64_t dest = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t src = get_reg(emu, UC_ARM64_REG_X1);
        size_t n = get_reg(emu, UC_ARM64_REG_X2);
        // locale ignored

        size_t src_len = 0;
        while (true) {
            uint32_t wc;
            emu.mem_read(src + src_len * 4, &wc, 4);
            if (wc == 0) break;
            src_len++;
        }

        if (n > 0 && dest) {
            size_t copy_len = (src_len < n) ? src_len : (n - 1);
            for (size_t i = 0; i < copy_len; i++) {
                uint32_t wc;
                emu.mem_read(src + i * 4, &wc, 4);
                emu.mem_write(dest + i * 4, &wc, 4);
            }
            uint32_t null = 0;
            emu.mem_write(dest + copy_len * 4, &null, 4);
        }
        set_reg(emu, UC_ARM64_REG_X0, src_len);
    });

    // Case-insensitive comparison
    hle.register_function("wcscasecmp", [](Emulator& emu) {
        uint64_t s1 = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t s2 = get_reg(emu, UC_ARM64_REG_X1);

        size_t i = 0;
        while (true) {
            uint32_t wc1, wc2;
            emu.mem_read(s1 + i * 4, &wc1, 4);
            emu.mem_read(s2 + i * 4, &wc2, 4);

            // Simple ASCII lowercase
            if (wc1 >= 'A' && wc1 <= 'Z') wc1 = wc1 - 'A' + 'a';
            if (wc2 >= 'A' && wc2 <= 'Z') wc2 = wc2 - 'A' + 'a';

            if (wc1 != wc2 || wc1 == 0) {
                set_reg(emu, UC_ARM64_REG_X0, (wc1 < wc2) ? -1 : ((wc1 > wc2) ? 1 : 0));
                return;
            }
            i++;
        }
    });

    hle.register_function("wcsncasecmp", [](Emulator& emu) {
        uint64_t s1 = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t s2 = get_reg(emu, UC_ARM64_REG_X1);
        size_t n = get_reg(emu, UC_ARM64_REG_X2);

        for (size_t i = 0; i < n; i++) {
            uint32_t wc1, wc2;
            emu.mem_read(s1 + i * 4, &wc1, 4);
            emu.mem_read(s2 + i * 4, &wc2, 4);

            if (wc1 >= 'A' && wc1 <= 'Z') wc1 = wc1 - 'A' + 'a';
            if (wc2 >= 'A' && wc2 <= 'Z') wc2 = wc2 - 'A' + 'a';

            if (wc1 != wc2 || wc1 == 0) {
                set_reg(emu, UC_ARM64_REG_X0, (wc1 < wc2) ? -1 : ((wc1 > wc2) ? 1 : 0));
                return;
            }
        }
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    // ========================================================================
    // Wide string conversion functions
    // ========================================================================

    hle.register_function("wcstol", [](Emulator& emu) {
        uint64_t nptr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t endptr = get_reg(emu, UC_ARM64_REG_X1);
        int base = get_reg(emu, UC_ARM64_REG_X2);
        int err = 0;
        long result = parse_guest_wide_integer<long>(
            emu, nptr, endptr, base,
            [](const char* s, char** end, int parse_base) { return ::strtol(s, end, parse_base); },
            err);
        if (err != 0) {
            hle_set_errno(emu, err);
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("wcstoul", [](Emulator& emu) {
        uint64_t nptr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t endptr = get_reg(emu, UC_ARM64_REG_X1);
        int base = get_reg(emu, UC_ARM64_REG_X2);
        int err = 0;
        unsigned long result = parse_guest_wide_integer<unsigned long>(
            emu, nptr, endptr, base,
            [](const char* s, char** end, int parse_base) { return ::strtoul(s, end, parse_base); },
            err);
        if (err != 0) {
            hle_set_errno(emu, err);
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("wcstoll", [](Emulator& emu) {
        uint64_t nptr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t endptr = get_reg(emu, UC_ARM64_REG_X1);
        int base = get_reg(emu, UC_ARM64_REG_X2);
        int err = 0;
        long long result = parse_guest_wide_integer<long long>(
            emu, nptr, endptr, base,
            [](const char* s, char** end, int parse_base) { return ::strtoll(s, end, parse_base); },
            err);
        if (err != 0) {
            hle_set_errno(emu, err);
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("wcstoull", [](Emulator& emu) {
        uint64_t nptr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t endptr = get_reg(emu, UC_ARM64_REG_X1);
        int base = get_reg(emu, UC_ARM64_REG_X2);
        int err = 0;
        unsigned long long result = parse_guest_wide_integer<unsigned long long>(
            emu, nptr, endptr, base,
            [](const char* s, char** end, int parse_base) { return ::strtoull(s, end, parse_base); },
            err);
        if (err != 0) {
            hle_set_errno(emu, err);
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("wcstoll_l", [](Emulator& emu) {
        uint64_t nptr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t endptr = get_reg(emu, UC_ARM64_REG_X1);
        int base = get_reg(emu, UC_ARM64_REG_X2);
        // locale ignored
        int err = 0;
        long long result = parse_guest_wide_integer<long long>(
            emu, nptr, endptr, base,
            [](const char* s, char** end, int parse_base) { return ::strtoll(s, end, parse_base); },
            err);
        if (err != 0) {
            hle_set_errno(emu, err);
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("wcstoull_l", [](Emulator& emu) {
        uint64_t nptr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t endptr = get_reg(emu, UC_ARM64_REG_X1);
        int base = get_reg(emu, UC_ARM64_REG_X2);
        // locale ignored
        int err = 0;
        unsigned long long result = parse_guest_wide_integer<unsigned long long>(
            emu, nptr, endptr, base,
            [](const char* s, char** end, int parse_base) { return ::strtoull(s, end, parse_base); },
            err);
        if (err != 0) {
            hle_set_errno(emu, err);
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("wcstoimax", [](Emulator& emu) {
        uint64_t nptr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t endptr = get_reg(emu, UC_ARM64_REG_X1);
        int base = get_reg(emu, UC_ARM64_REG_X2);

        std::string narrow;
        size_t i = 0;
        while (true) {
            uint32_t wc;
            emu.mem_read(nptr + i * 4, &wc, 4);
            if (wc == 0 || wc > 127) break;
            narrow += (char)wc;
            i++;
        }

        char* end;
        errno = 0;
        long long result = strtoll(narrow.c_str(), &end, base);
        if (errno != 0) {
            hle_set_errno(emu, errno);
        }

        if (endptr) {
            uint64_t end_addr = nptr + (end - narrow.c_str()) * 4;
            emu.mem_write(endptr, &end_addr, sizeof(end_addr));
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("wcstoumax", [](Emulator& emu) {
        uint64_t nptr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t endptr = get_reg(emu, UC_ARM64_REG_X1);
        int base = get_reg(emu, UC_ARM64_REG_X2);

        std::string narrow;
        size_t i = 0;
        while (true) {
            uint32_t wc;
            emu.mem_read(nptr + i * 4, &wc, 4);
            if (wc == 0 || wc > 127) break;
            narrow += (char)wc;
            i++;
        }

        char* end;
        errno = 0;
        unsigned long long result = strtoull(narrow.c_str(), &end, base);
        if (errno != 0) {
            hle_set_errno(emu, errno);
        }

        if (endptr) {
            uint64_t end_addr = nptr + (end - narrow.c_str()) * 4;
            emu.mem_write(endptr, &end_addr, sizeof(end_addr));
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("wcstod", [](Emulator& emu) {
        uint64_t nptr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t endptr = get_reg(emu, UC_ARM64_REG_X1);

        std::string narrow;
        size_t i = 0;
        while (true) {
            uint32_t wc;
            emu.mem_read(nptr + i * 4, &wc, 4);
            if (wc == 0 || wc > 127) break;
            narrow += (char)wc;
            i++;
        }

        char* end;
        double result = strtod(narrow.c_str(), &end);

        if (endptr) {
            uint64_t end_addr = nptr + (end - narrow.c_str()) * 4;
            emu.mem_write(endptr, &end_addr, sizeof(end_addr));
        }
        set_dreg(emu, 0, result);
    });

    hle.register_function("wcstof", [](Emulator& emu) {
        uint64_t nptr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t endptr = get_reg(emu, UC_ARM64_REG_X1);

        std::string narrow;
        size_t i = 0;
        while (true) {
            uint32_t wc;
            emu.mem_read(nptr + i * 4, &wc, 4);
            if (wc == 0 || wc > 127) break;
            narrow += (char)wc;
            i++;
        }

        char* end;
        float result = strtof(narrow.c_str(), &end);

        if (endptr) {
            uint64_t end_addr = nptr + (end - narrow.c_str()) * 4;
            emu.mem_write(endptr, &end_addr, sizeof(end_addr));
        }
        set_sreg(emu, 0, result);
    });

    hle.register_function("wcstold", [](Emulator& emu) {
        uint64_t nptr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t endptr = get_reg(emu, UC_ARM64_REG_X1);
        int err = 0;
        __float128 result = parse_guest_wide_quad(emu, nptr, endptr, err);
        if (err != 0) {
            hle_set_errno(emu, err);
        }
        set_guest_quad_result(emu, result);
    });

    hle.register_function("wcstold_l", [](Emulator& emu) {
        uint64_t nptr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t endptr = get_reg(emu, UC_ARM64_REG_X1);
        // locale ignored
        int err = 0;
        __float128 result = parse_guest_wide_quad(emu, nptr, endptr, err);
        if (err != 0) {
            hle_set_errno(emu, err);
        }
        set_guest_quad_result(emu, result);
    });

    // ========================================================================
    // Wide character I/O
    // ========================================================================

    hle.register_function("ungetwc", [](Emulator& emu) {
        uint32_t wc = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t stream = get_reg(emu, UC_ARM64_REG_X1);
        FILE* fp = hle_resolve_guest_file(emu, stream);
        if (fp == nullptr) {
            hle_set_errno(emu, EBADF);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(WEOF));
            return;
        }
        int err = 0;
        wint_t result = unread_utf8_wchar(fp, wc, err);
        if (result == WEOF) {
            hle_set_errno(emu, err);
        }
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(result));
    });

    hle.register_function("getwc", [](Emulator& emu) {
        uint64_t stream = get_reg(emu, UC_ARM64_REG_X0);
        FILE* fp = hle_resolve_guest_file(emu, stream);
        if (fp == nullptr) {
            hle_set_errno(emu, EBADF);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(WEOF));
            return;
        }
        int err = 0;
        wint_t result = read_utf8_wchar(fp, err);
        if (result == WEOF && err != 0) {
            hle_set_errno(emu, err);
        }
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(result));
    });

    hle.register_function("fgetwc", [](Emulator& emu) {
        uint64_t stream = get_reg(emu, UC_ARM64_REG_X0);
        FILE* fp = hle_resolve_guest_file(emu, stream);
        if (fp == nullptr) {
            hle_set_errno(emu, EBADF);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(WEOF));
            return;
        }
        int err = 0;
        wint_t result = read_utf8_wchar(fp, err);
        if (result == WEOF && err != 0) {
            hle_set_errno(emu, err);
        }
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(result));
    });

    hle.register_function("fputwc", [](Emulator& emu) {
        uint32_t wc = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t stream = get_reg(emu, UC_ARM64_REG_X1);
        FILE* fp = hle_resolve_guest_file(emu, stream);
        if (fp == nullptr) {
            hle_set_errno(emu, EBADF);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(WEOF));
            return;
        }
        int err = 0;
        wint_t result = write_utf8_wchar(fp, wc, err);
        if (result == WEOF) {
            hle_set_errno(emu, err);
        } else {
            hle_sync_stream_after_write(emu, stream);
        }
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(result));
    });

    hle.register_function("putwc", [](Emulator& emu) {
        uint32_t wc = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t stream = get_reg(emu, UC_ARM64_REG_X1);
        FILE* fp = hle_resolve_guest_file(emu, stream);
        if (fp == nullptr) {
            hle_set_errno(emu, EBADF);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(WEOF));
            return;
        }
        int err = 0;
        wint_t result = write_utf8_wchar(fp, wc, err);
        if (result == WEOF) {
            hle_set_errno(emu, err);
        } else {
            hle_sync_stream_after_write(emu, stream);
        }
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(result));
    });

    hle.register_function("putwchar", [](Emulator& emu) {
        uint32_t wc = get_reg(emu, UC_ARM64_REG_X0);
        int err = 0;
        wint_t result = write_utf8_wchar(stdout, wc, err);
        if (result == WEOF) {
            hle_set_errno(emu, err);
        }
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(result));
    });

    hle.register_function("getwchar", [](Emulator& emu) {
        int err = 0;
        wint_t result = read_utf8_wchar(stdin, err);
        if (result == WEOF && err != 0) {
            hle_set_errno(emu, err);
        }
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(result));
    });

    hle.register_function("fgetws", [](Emulator& emu) {
        uint64_t buf_addr = get_reg(emu, UC_ARM64_REG_X0);
        int n = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t stream = get_reg(emu, UC_ARM64_REG_X2);
        FILE* fp = hle_resolve_guest_file(emu, stream);
        if (buf_addr == 0 || n <= 0 || fp == nullptr) {
            if (fp == nullptr) {
                hle_set_errno(emu, EBADF);
            }
            set_reg(emu, UC_ARM64_REG_X0, 0);
            return;
        }

        int i = 0;
        for (; i < n - 1; ++i) {
            int err = 0;
            wint_t wc = read_utf8_wchar(fp, err);
            if (wc == WEOF) {
                if (i == 0) {
                    if (err != 0) {
                        hle_set_errno(emu, err);
                    }
                    set_reg(emu, UC_ARM64_REG_X0, 0);
                    return;
                }
                break;
            }
            uint32_t guest_wc = static_cast<uint32_t>(wc);
            emu.mem_write(buf_addr + static_cast<uint64_t>(i) * 4, &guest_wc, 4);
            if (wc == L'\n') {
                ++i;
                break;
            }
        }

        uint32_t zero = 0;
        emu.mem_write(buf_addr + static_cast<uint64_t>(i) * 4, &zero, 4);
        set_reg(emu, UC_ARM64_REG_X0, buf_addr);
    });

    hle.register_function("fputws", [](Emulator& emu) {
        uint64_t str_addr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t stream = get_reg(emu, UC_ARM64_REG_X1);
        FILE* fp = hle_resolve_guest_file(emu, stream);
        if (fp == nullptr) {
            hle_set_errno(emu, EBADF);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        size_t index = 0;
        while (true) {
            uint32_t wc = 0;
            emu.mem_read(str_addr + index * 4, &wc, 4);
            if (wc == 0) {
                break;
            }
            int err = 0;
            if (write_utf8_wchar(fp, wc, err) == WEOF) {
                hle_set_errno(emu, err);
                set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
                return;
            }
            ++index;
        }

        hle_sync_stream_after_write(emu, stream);
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("fwide", [](Emulator& emu) {
        int mode = get_reg(emu, UC_ARM64_REG_X1);
        set_reg(emu, UC_ARM64_REG_X0, mode != 0 ? mode : 0);
    });

    // ========================================================================
    // Wide string formatting (simplified)
    // ========================================================================

    hle.register_function("swprintf", [](Emulator& emu) {
        uint64_t ws = get_reg(emu, UC_ARM64_REG_X0);
        size_t n = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t format_addr = get_reg(emu, UC_ARM64_REG_X2);

        if (n == 0) {
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        HleFormatResult formatted = hle_format_from_regs(emu, format_addr, 3, true);
        if (!formatted.ok) {
            hle_set_errno(emu, formatted.error);
            if (ws && n > 0) {
                uint32_t null = 0;
                emu.mem_write(ws, &null, 4);
            }
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        int err = 0;
        int written = write_guest_wide_output(emu, ws, n, formatted.output, err);
        if (written < 0 && err != 0) {
            hle_set_errno(emu, err);
        }
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(written));
    });

    hle.register_function("fwprintf", [](Emulator& emu) {
        uint64_t stream = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t format_addr = get_reg(emu, UC_ARM64_REG_X1);
        HleFormatResult formatted = hle_format_from_regs(emu, format_addr, 2, true);
        if (!formatted.ok) {
            hle_set_errno(emu, formatted.error);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(WEOF));
            return;
        }

        FILE* fp = hle_resolve_guest_file(emu, stream);
        if (fp == nullptr) {
            hle_set_errno(emu, EBADF);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(WEOF));
            return;
        }

        errno = 0;
        if (std::fputs(formatted.output.c_str(), fp) == EOF) {
            hle_set_errno(emu, errno);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(WEOF));
            return;
        }

        std::vector<uint32_t> codepoints;
        if (!decode_utf8_string(formatted.output, codepoints)) {
            hle_set_errno(emu, EILSEQ);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(WEOF));
            return;
        }
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(codepoints.size()));
    });

    hle.register_function("wprintf", [](Emulator& emu) {
        uint64_t format_addr = get_reg(emu, UC_ARM64_REG_X0);
        HleFormatResult formatted = hle_format_from_regs(emu, format_addr, 1, true);
        if (!formatted.ok) {
            hle_set_errno(emu, formatted.error);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(WEOF));
            return;
        }

        std::cout << formatted.output;
        std::cout.flush();

        std::vector<uint32_t> codepoints;
        if (!decode_utf8_string(formatted.output, codepoints)) {
            hle_set_errno(emu, EILSEQ);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(WEOF));
            return;
        }
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(codepoints.size()));
    });

    hle.register_function("swscanf", [](Emulator& emu) {
        HleScanResult scanned = hle_scan_from_regs(
            emu,
            get_reg(emu, UC_ARM64_REG_X0),
            get_reg(emu, UC_ARM64_REG_X1),
            2,
            true);
        if (!scanned.ok) {
            hle_set_errno(emu, scanned.error);
        }
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(static_cast<int64_t>(scanned.result)));
    });

    hle.register_function("vswprintf", [](Emulator& emu) {
        uint64_t ws = get_reg(emu, UC_ARM64_REG_X0);
        size_t n = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t format_addr = get_reg(emu, UC_ARM64_REG_X2);
        uint64_t va_list_addr = get_reg(emu, UC_ARM64_REG_X3);

        if (n == 0) {
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        HleFormatResult formatted = hle_format_from_va_list(emu, format_addr, va_list_addr, true);
        if (!formatted.ok) {
            hle_set_errno(emu, formatted.error);
            if (ws && n > 0) {
                uint32_t null = 0;
                emu.mem_write(ws, &null, 4);
            }
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        int err = 0;
        int written = write_guest_wide_output(emu, ws, n, formatted.output, err);
        if (written < 0 && err != 0) {
            hle_set_errno(emu, err);
        }
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(written));
    });

    // ========================================================================
    // Wide string time formatting
    // ========================================================================

    hle.register_function("wcsftime", [](Emulator& emu) {
        uint64_t ws = get_reg(emu, UC_ARM64_REG_X0);
        size_t maxsize = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t format_addr = get_reg(emu, UC_ARM64_REG_X2);
        uint64_t tm_addr = get_reg(emu, UC_ARM64_REG_X3);

        // Read wide format and convert to narrow
        std::string narrow_fmt;
        size_t i = 0;
        while (i < 256) {
            uint32_t wc;
            emu.mem_read(format_addr + i * 4, &wc, 4);
            if (wc == 0) break;
            if (wc <= 127) narrow_fmt += (char)wc;
            i++;
        }

        // Read tm structure
        struct tm tm_val = {};
        int32_t vals[9];
        emu.mem_read(tm_addr, vals, sizeof(vals));
        tm_val.tm_sec = vals[0];
        tm_val.tm_min = vals[1];
        tm_val.tm_hour = vals[2];
        tm_val.tm_mday = vals[3];
        tm_val.tm_mon = vals[4];
        tm_val.tm_year = vals[5];
        tm_val.tm_wday = vals[6];
        tm_val.tm_yday = vals[7];
        tm_val.tm_isdst = vals[8];

        // Format to narrow string
        std::vector<char> buf(maxsize);
        size_t result = strftime(buf.data(), maxsize, narrow_fmt.c_str(), &tm_val);

        // Convert to wide and write
        if (result > 0 && ws && maxsize > 0) {
            for (size_t j = 0; j <= result && j < maxsize; j++) {
                uint32_t wc = (unsigned char)buf[j];
                emu.mem_write(ws + j * 4, &wc, 4);
            }
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("wcsftime_l", [](Emulator& emu) {
        uint64_t ws = get_reg(emu, UC_ARM64_REG_X0);
        size_t maxsize = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t format_addr = get_reg(emu, UC_ARM64_REG_X2);
        uint64_t tm_addr = get_reg(emu, UC_ARM64_REG_X3);
        // locale ignored

        std::string narrow_fmt;
        size_t i = 0;
        while (i < 256) {
            uint32_t wc;
            emu.mem_read(format_addr + i * 4, &wc, 4);
            if (wc == 0) break;
            if (wc <= 127) narrow_fmt += (char)wc;
            i++;
        }

        struct tm tm_val = {};
        int32_t vals[9];
        emu.mem_read(tm_addr, vals, sizeof(vals));
        tm_val.tm_sec = vals[0];
        tm_val.tm_min = vals[1];
        tm_val.tm_hour = vals[2];
        tm_val.tm_mday = vals[3];
        tm_val.tm_mon = vals[4];
        tm_val.tm_year = vals[5];
        tm_val.tm_wday = vals[6];
        tm_val.tm_yday = vals[7];
        tm_val.tm_isdst = vals[8];

        std::vector<char> buf(maxsize);
        size_t result = strftime(buf.data(), maxsize, narrow_fmt.c_str(), &tm_val);

        if (result > 0 && ws && maxsize > 0) {
            for (size_t j = 0; j <= result && j < maxsize; j++) {
                uint32_t wc = (unsigned char)buf[j];
                emu.mem_write(ws + j * 4, &wc, 4);
            }
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // ========================================================================
    // Wide memory stream
    // ========================================================================

    hle.register_function("open_wmemstream", [](Emulator& emu) {
        uint64_t ptr_ptr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t sizeloc_ptr = get_reg(emu, UC_ARM64_REG_X1);
        int err = 0;
        uint64_t stream = hle_open_wmemstream(emu, ptr_ptr, sizeloc_ptr, err);
        if (stream == 0) {
            hle_set_errno(emu, err);
        }
        set_reg(emu, UC_ARM64_REG_X0, stream);
    });
}

} // namespace cross_shim
