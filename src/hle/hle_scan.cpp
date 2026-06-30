/**
 * Shared scanf/swscanf helpers for stdio/wchar HLE.
 */

#include "hle_scan.h"

#include "cross_shim.h"
#include "emu_compat.h"
#include "hle_manager.h"
#include "memory_manager.h"

#include <array>
#include <algorithm>
#include <cerrno>
#include <climits>
#include <clocale>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <cwctype>
#include <inttypes.h>
#include <limits>
#include <locale.h>
#include <string>
#include <string_view>
#include <vector>

namespace cross_shim {

namespace {

static constexpr size_t kMaxGuestStringLen = 1 << 20;

static uint64_t align_up_u64(uint64_t value, uint64_t alignment) {
    return (value + alignment - 1) & ~(alignment - 1);
}

static std::string read_c_string(Emulator& emu, uint64_t addr, size_t max_len = kMaxGuestStringLen) {
    std::string result;
    if (addr == 0) {
        return result;
    }

    result.reserve(std::min<size_t>(max_len, 256));
    for (size_t i = 0; i < max_len; ++i) {
        char c = 0;
        if (!emu.mem_read(addr + i, &c, 1) || c == '\0') {
            break;
        }
        result.push_back(c);
    }
    return result;
}

static std::wstring read_wide_string(Emulator& emu, uint64_t addr, size_t max_len = kMaxGuestStringLen) {
    std::wstring result;
    if (addr == 0) {
        return result;
    }

    result.reserve(std::min<size_t>(max_len, 256));
    for (size_t i = 0; i < max_len; ++i) {
        uint32_t wc = 0;
        if (!emu.mem_read(addr + i * 4, &wc, 4) || wc == 0) {
            break;
        }
        result.push_back(static_cast<wchar_t>(wc));
    }
    return result;
}

static bool append_utf8(std::string& out, uint32_t wc) {
    if (wc <= 0x7f) {
        out.push_back(static_cast<char>(wc));
        return true;
    }
    if (wc <= 0x7ff) {
        out.push_back(static_cast<char>(0xc0 | (wc >> 6)));
        out.push_back(static_cast<char>(0x80 | (wc & 0x3f)));
        return true;
    }
    if (wc <= 0xffff && (wc < 0xd800 || wc > 0xdfff)) {
        out.push_back(static_cast<char>(0xe0 | (wc >> 12)));
        out.push_back(static_cast<char>(0x80 | ((wc >> 6) & 0x3f)));
        out.push_back(static_cast<char>(0x80 | (wc & 0x3f)));
        return true;
    }
    if (wc <= 0x10ffff) {
        out.push_back(static_cast<char>(0xf0 | (wc >> 18)));
        out.push_back(static_cast<char>(0x80 | ((wc >> 12) & 0x3f)));
        out.push_back(static_cast<char>(0x80 | ((wc >> 6) & 0x3f)));
        out.push_back(static_cast<char>(0x80 | (wc & 0x3f)));
        return true;
    }
    return false;
}

static std::string read_wide_string_utf8(Emulator& emu, uint64_t addr,
                                         size_t max_len = kMaxGuestStringLen) {
    std::string result;
    if (addr == 0) {
        return result;
    }

    for (size_t i = 0; i < max_len; ++i) {
        uint32_t wc = 0;
        if (!emu.mem_read(addr + i * 4, &wc, 4) || wc == 0) {
            break;
        }
        if (!append_utf8(result, wc)) {
            break;
        }
    }
    return result;
}

enum class Utf8DecodeStatus {
    Ok,
    Incomplete,
    Invalid,
};

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

static std::wstring utf8_to_wstring(const std::string& input) {
    std::wstring output;
    size_t pos = 0;
    while (pos < input.size()) {
        uint32_t wc = 0;
        size_t consumed = 0;
        Utf8DecodeStatus status = decode_utf8(
            reinterpret_cast<const unsigned char*>(input.data() + pos), input.size() - pos, wc, consumed);
        if (status != Utf8DecodeStatus::Ok || consumed == 0) {
            break;
        }
        output.push_back(static_cast<wchar_t>(wc));
        pos += consumed;
    }
    return output;
}

class ScopedUtf8Locale {
public:
    ScopedUtf8Locale() {
        locale_t utf8 = get_utf8_locale();
        if (utf8 != nullptr) {
            old_ = uselocale(utf8);
        }
    }

    ~ScopedUtf8Locale() {
        if (old_ != nullptr) {
            uselocale(old_);
        }
    }

private:
    static locale_t get_utf8_locale() {
        static locale_t utf8 = []() -> locale_t {
            locale_t loc = newlocale(LC_ALL_MASK, "C.UTF-8", nullptr);
            if (loc == nullptr) {
                loc = newlocale(LC_ALL_MASK, "C.utf8", nullptr);
            }
            return loc;
        }();
        return utf8;
    }

    locale_t old_ = nullptr;
};

enum class ScanLengthMod {
    None,
    HH,
    H,
    L,
    LL,
    BigL,
    J,
    Z,
    T,
    ExactW,
    FastW,
};

struct ScanDirective {
    std::string original;
    bool suppress = false;
    bool assign_alloc = false;
    bool has_width = false;
    int width = 0;
    ScanLengthMod length = ScanLengthMod::None;
    int w_bits = 0;
    char conv = '\0';
};

struct ScanToken {
    bool is_literal = true;
    std::string literal;
    ScanDirective spec;
};

struct ScanParseResult {
    bool ok = true;
    int error = 0;
    std::string fatal_message;
    std::vector<ScanToken> tokens;
};

static ScanParseResult parse_scan_format(const std::string& fmt) {
    ScanParseResult parsed;
    std::string pending_literal;

    auto flush_literal = [&]() {
        if (pending_literal.empty()) {
            return;
        }
        ScanToken token;
        token.is_literal = true;
        token.literal = pending_literal;
        parsed.tokens.push_back(std::move(token));
        pending_literal.clear();
    };

    for (size_t i = 0; i < fmt.size(); ++i) {
        if (fmt[i] != '%') {
            pending_literal.push_back(fmt[i]);
            continue;
        }

        if (i + 1 < fmt.size() && fmt[i + 1] == '%') {
            pending_literal.push_back('%');
            ++i;
            continue;
        }

        flush_literal();

        ScanDirective spec;
        size_t start = i;
        ++i;
        if (i >= fmt.size()) {
            parsed.ok = false;
            parsed.error = EINVAL;
            return parsed;
        }

        if (fmt[i] == '*') {
            spec.suppress = true;
            ++i;
        }

        if (i < fmt.size() && std::isdigit(static_cast<unsigned char>(fmt[i]))) {
            unsigned long long width = 0;
            spec.has_width = true;
            while (i < fmt.size() && std::isdigit(static_cast<unsigned char>(fmt[i]))) {
                width = width * 10 + static_cast<unsigned long long>(fmt[i] - '0');
                if (width > static_cast<unsigned long long>(INT_MAX)) {
                    parsed.ok = false;
                    parsed.error = ENOMEM;
                    return parsed;
                }
                ++i;
            }
            spec.width = static_cast<int>(width);
        }

        if (i < fmt.size() && fmt[i] == 'm') {
            spec.assign_alloc = true;
            ++i;
        }

        if (i < fmt.size()) {
            if (fmt[i] == 'w') {
                size_t w_start = i;
                ++i;
                spec.length = ScanLengthMod::ExactW;
                if (i < fmt.size() && fmt[i] == 'f') {
                    spec.length = ScanLengthMod::FastW;
                    ++i;
                }

                std::string digits;
                while (i < fmt.size() && std::isdigit(static_cast<unsigned char>(fmt[i]))) {
                    digits.push_back(fmt[i]);
                    ++i;
                }

                if (digits != "8" && digits != "16" && digits != "32" && digits != "64") {
                    parsed.fatal_message = "%" + fmt.substr(w_start, i - w_start);
                    parsed.ok = false;
                    parsed.error = EINVAL;
                    return parsed;
                }
                spec.w_bits = std::stoi(digits);
            } else if (fmt[i] == 'h') {
                ++i;
                if (i < fmt.size() && fmt[i] == 'h') {
                    spec.length = ScanLengthMod::HH;
                    ++i;
                } else {
                    spec.length = ScanLengthMod::H;
                }
            } else if (fmt[i] == 'l') {
                ++i;
                if (i < fmt.size() && fmt[i] == 'l') {
                    spec.length = ScanLengthMod::LL;
                    ++i;
                } else {
                    spec.length = ScanLengthMod::L;
                }
            } else if (fmt[i] == 'L') {
                spec.length = ScanLengthMod::BigL;
                ++i;
            } else if (fmt[i] == 'j') {
                spec.length = ScanLengthMod::J;
                ++i;
            } else if (fmt[i] == 'z') {
                spec.length = ScanLengthMod::Z;
                ++i;
            } else if (fmt[i] == 't') {
                spec.length = ScanLengthMod::T;
                ++i;
            }
        }

        if (i >= fmt.size()) {
            parsed.ok = false;
            parsed.error = EINVAL;
            return parsed;
        }

        spec.conv = fmt[i];
        if (spec.conv == '[') {
            ++i;
            if (i < fmt.size() && (fmt[i] == ']' || fmt[i] == '^')) {
                if (fmt[i] == '^') {
                    ++i;
                    if (i < fmt.size() && fmt[i] == ']') {
                        ++i;
                    }
                } else {
                    ++i;
                }
            }
            while (i < fmt.size() && fmt[i] != ']') {
                ++i;
            }
            if (i >= fmt.size() || fmt[i] != ']') {
                parsed.ok = false;
                parsed.error = EINVAL;
                return parsed;
            }
        }

        spec.original = fmt.substr(start, i - start + 1);
        ScanToken token;
        token.is_literal = false;
        token.spec = std::move(spec);
        parsed.tokens.push_back(std::move(token));
    }

    flush_literal();
    return parsed;
}

struct arm64_va_list {
    uint64_t __stack;
    uint64_t __gr_top;
    uint64_t __vr_top;
    int32_t __gr_offs;
    int32_t __vr_offs;
};

struct RegisterArgSource {
    explicit RegisterArgSource(Emulator& emu_in, int first_gp_reg)
        : emu(emu_in), next_gp_reg(first_gp_reg), stack_addr(get_reg(emu_in, UC_ARM64_REG_SP)) {}

    uint64_t next_ptr() {
        if (next_gp_reg <= 7) {
            uint64_t value = get_reg(emu, UC_ARM64_REG_X0 + next_gp_reg);
            ++next_gp_reg;
            return value;
        }

        stack_addr = align_up_u64(stack_addr, 8);
        uint64_t value = 0;
        emu.mem_read(stack_addr, &value, sizeof(value));
        stack_addr += 8;
        return value;
    }

    Emulator& emu;
    int next_gp_reg = 0;
    uint64_t stack_addr = 0;
};

struct VaListArgSource {
    VaListArgSource(Emulator& emu_in, uint64_t va_list_addr) : emu(emu_in) {
        emu.mem_read(va_list_addr, &va, sizeof(va));
    }

    uint64_t next_ptr() {
        if (va.__gr_offs < 0) {
            uint64_t addr = va.__gr_top + static_cast<uint64_t>(va.__gr_offs);
            uint64_t value = 0;
            emu.mem_read(addr, &value, sizeof(value));
            va.__gr_offs += 8;
            return value;
        }

        va.__stack = align_up_u64(va.__stack, 8);
        uint64_t value = 0;
        emu.mem_read(va.__stack, &value, sizeof(value));
        va.__stack += 8;
        return value;
    }

    Emulator& emu;
    arm64_va_list va{};
};

template <typename CharT>
static bool input_is_space(CharT ch) {
    if constexpr (sizeof(CharT) == sizeof(char)) {
        return std::isspace(static_cast<unsigned char>(ch)) != 0;
    } else {
        return std::iswspace(static_cast<wint_t>(ch)) != 0;
    }
}

template <typename CharT>
static size_t skip_input_space(const std::basic_string<CharT>& input, size_t pos) {
    while (pos < input.size() && input_is_space(input[pos])) {
        ++pos;
    }
    return pos;
}

template <typename CharT>
static bool ascii_equals(CharT ch, char expected) {
    return static_cast<uint32_t>(ch) == static_cast<unsigned char>(expected);
}

template <typename CharT>
static bool ascii_is_sign(CharT ch) {
    return ascii_equals(ch, '+') || ascii_equals(ch, '-');
}

template <typename CharT>
static bool ascii_is_digit(CharT ch) {
    return ch >= static_cast<CharT>('0') && ch <= static_cast<CharT>('9');
}

template <typename CharT>
static int digit_value(CharT ch) {
    uint32_t code = static_cast<uint32_t>(ch);
    if (code >= '0' && code <= '9') {
        return static_cast<int>(code - '0');
    }
    if (code >= 'a' && code <= 'z') {
        return static_cast<int>(code - 'a') + 10;
    }
    if (code >= 'A' && code <= 'Z') {
        return static_cast<int>(code - 'A') + 10;
    }
    return -1;
}

static bool is_integer_conv(char conv) {
    switch (conv) {
        case 'd':
        case 'i':
        case 'u':
        case 'o':
        case 'x':
        case 'X':
        case 'p':
        case 'b':
            return true;
        default:
            return false;
    }
}

static bool is_float_conv(char conv) {
    switch (conv) {
        case 'a':
        case 'A':
        case 'e':
        case 'E':
        case 'f':
        case 'F':
        case 'g':
        case 'G':
            return true;
        default:
            return false;
    }
}

static bool is_stringish_conv(char conv) {
    return conv == 'c' || conv == 's' || conv == '[' || conv == 'C' || conv == 'S';
}

static bool spec_skips_leading_space(const ScanDirective& spec) {
    return spec.conv != 'c' && spec.conv != '[' && spec.conv != 'n' &&
           spec.conv != 'C';
}

template <typename CharT>
static bool parse_integer_value(const std::basic_string<CharT>& input, size_t pos,
                                const ScanDirective& spec, size_t& consumed, uint64_t& bits_out) {
    size_t limit = input.size() - pos;
    if (spec.has_width) {
        limit = std::min(limit, static_cast<size_t>(spec.width));
    }
    if (limit == 0) {
        return false;
    }

    size_t cursor = 0;
    bool negative = false;
    if (ascii_is_sign(input[pos + cursor]) && spec.conv != 'p') {
        negative = ascii_equals(input[pos + cursor], '-');
        ++cursor;
    }
    if (cursor >= limit) {
        return false;
    }

    int base = 10;
    bool allow_prefix = false;
    switch (spec.conv) {
        case 'd':
        case 'u':
            base = 10;
            break;
        case 'o':
            base = 8;
            break;
        case 'x':
        case 'X':
        case 'p':
            base = 16;
            allow_prefix = true;
            break;
        case 'b':
            base = 2;
            allow_prefix = true;
            break;
        case 'i':
            base = 0;
            break;
        default:
            return false;
    }

    if (base == 0) {
        if (ascii_equals(input[pos + cursor], '0')) {
            if (cursor + 2 < limit &&
                (ascii_equals(input[pos + cursor + 1], 'x') || ascii_equals(input[pos + cursor + 1], 'X')) &&
                digit_value(input[pos + cursor + 2]) >= 0 &&
                digit_value(input[pos + cursor + 2]) < 16) {
                base = 16;
                cursor += 2;
            } else if (cursor + 2 < limit &&
                       (ascii_equals(input[pos + cursor + 1], 'b') || ascii_equals(input[pos + cursor + 1], 'B')) &&
                       digit_value(input[pos + cursor + 2]) >= 0 &&
                       digit_value(input[pos + cursor + 2]) < 2) {
                base = 2;
                cursor += 2;
            } else {
                base = 8;
            }
        } else {
            base = 10;
        }
    } else if (allow_prefix) {
        int prefix_base = base;
        char prefix_ch = prefix_base == 16 ? 'x' : 'b';
        if (cursor + 2 < limit &&
            ascii_equals(input[pos + cursor], '0') &&
            (ascii_equals(input[pos + cursor + 1], prefix_ch) || ascii_equals(input[pos + cursor + 1], static_cast<char>(std::toupper(prefix_ch)))) &&
            digit_value(input[pos + cursor + 2]) >= 0 &&
            digit_value(input[pos + cursor + 2]) < prefix_base) {
            cursor += 2;
        }
    }

    size_t digits_start = cursor;
    unsigned __int128 value = 0;
    while (cursor < limit) {
        int digit = digit_value(input[pos + cursor]);
        if (digit < 0 || digit >= base) {
            break;
        }
        value = value * static_cast<unsigned>(base) + static_cast<unsigned>(digit);
        ++cursor;
    }

    if (cursor == digits_start) {
        return false;
    }

    uint64_t magnitude = static_cast<uint64_t>(value);
    bits_out = negative ? (uint64_t{0} - magnitude) : magnitude;
    consumed = cursor;
    return true;
}

static size_t fast_integer_size(bool signed_conv, int bits) {
    switch (bits) {
        case 8:
            return signed_conv ? sizeof(int_fast8_t) : sizeof(uint_fast8_t);
        case 16:
            return signed_conv ? sizeof(int_fast16_t) : sizeof(uint_fast16_t);
        case 32:
            return signed_conv ? sizeof(int_fast32_t) : sizeof(uint_fast32_t);
        case 64:
            return signed_conv ? sizeof(int_fast64_t) : sizeof(uint_fast64_t);
        default:
            return 0;
    }
}

static size_t storage_size_for_integer(const ScanDirective& spec) {
    bool signed_conv = spec.conv == 'd' || spec.conv == 'i' || spec.conv == 'n';
    if (spec.length == ScanLengthMod::ExactW) {
        return static_cast<size_t>(spec.w_bits / 8);
    }
    if (spec.length == ScanLengthMod::FastW) {
        return fast_integer_size(signed_conv, spec.w_bits);
    }

    switch (spec.length) {
        case ScanLengthMod::HH:
            return 1;
        case ScanLengthMod::H:
            return 2;
        case ScanLengthMod::L:
            return sizeof(long);
        case ScanLengthMod::LL:
            return sizeof(long long);
        case ScanLengthMod::J:
            return signed_conv ? sizeof(intmax_t) : sizeof(uintmax_t);
        case ScanLengthMod::Z:
            return signed_conv ? sizeof(ssize_t) : sizeof(size_t);
        case ScanLengthMod::T:
            return sizeof(ptrdiff_t);
        case ScanLengthMod::None:
            if (spec.conv == 'p') {
                return sizeof(uint64_t);
            }
            return sizeof(int);
        default:
            return sizeof(int);
    }
}

static void write_integer_bits(Emulator& emu, uint64_t addr, uint64_t bits, size_t size) {
    switch (size) {
        case 1: {
            uint8_t v = static_cast<uint8_t>(bits);
            emu.mem_write(addr, &v, 1);
            break;
        }
        case 2: {
            uint16_t v = static_cast<uint16_t>(bits);
            emu.mem_write(addr, &v, 2);
            break;
        }
        case 4: {
            uint32_t v = static_cast<uint32_t>(bits);
            emu.mem_write(addr, &v, 4);
            break;
        }
        default: {
            uint64_t v = bits;
            emu.mem_write(addr, &v, 8);
            break;
        }
    }
}

static std::wstring build_wide_scan_format(const ScanDirective& spec) {
    return utf8_to_wstring(spec.original + "%n");
}

template <typename... Args>
static int host_scan_narrow(const char* input, const std::string& fmt, Args... args) {
    ScopedUtf8Locale locale_guard;
    return std::sscanf(input, fmt.c_str(), args...);
}

template <typename... Args>
static int host_scan_wide(const wchar_t* input, const std::wstring& fmt, Args... args) {
    ScopedUtf8Locale locale_guard;
    return std::swscanf(input, fmt.c_str(), args...);
}

struct ParsedScanSet {
    std::array<bool, 256> table{};
    bool negate = false;

    bool matches(uint32_t codepoint) const {
        bool in_set = codepoint < table.size() ? table[codepoint] : false;
        return negate ? !in_set : in_set;
    }
};

static ParsedScanSet parse_scanset(const ScanDirective& spec) {
    ParsedScanSet parsed;
    size_t open = spec.original.find('[');
    size_t close = spec.original.rfind(']');
    if (open == std::string::npos || close == std::string::npos || close <= open) {
        return parsed;
    }

    std::string_view body(spec.original.data() + open + 1, close - open - 1);
    size_t i = 0;
    if (i < body.size() && body[i] == '^') {
        parsed.negate = true;
        ++i;
    }

    int prev = -1;
    auto add_char = [&](unsigned char ch) {
        parsed.table[ch] = true;
        prev = ch;
    };

    if (i < body.size() && (body[i] == ']' || body[i] == '-')) {
        add_char(static_cast<unsigned char>(body[i]));
        ++i;
    }

    while (i < body.size()) {
        unsigned char ch = static_cast<unsigned char>(body[i]);
        if (ch == '-' && prev != -1 && i + 1 < body.size() && body[i + 1] != ']') {
            unsigned char end = static_cast<unsigned char>(body[i + 1]);
            if (static_cast<unsigned>(prev) <= static_cast<unsigned>(end)) {
                for (unsigned value = static_cast<unsigned>(prev) + 1; value <= static_cast<unsigned>(end); ++value) {
                    parsed.table[value] = true;
                }
                prev = end;
                i += 2;
                continue;
            }
        }
        add_char(ch);
        ++i;
    }

    return parsed;
}

template <typename StringT>
static size_t max_narrow_bytes_for_string_output(const StringT& input, size_t pos,
                                                 const ScanDirective& spec, bool wide_input) {
    size_t remaining = input.size() - pos;
    size_t limit = spec.has_width ? std::min(remaining, static_cast<size_t>(spec.width)) : remaining;
    if (!wide_input) {
        return limit + 1;
    }
    return limit * MB_CUR_MAX + 1;
}

template <typename StringT>
static size_t max_wide_units_for_output(const StringT& input, size_t pos, const ScanDirective& spec,
                                        bool wide_input) {
    size_t remaining = input.size() - pos;
    if (spec.has_width) {
        return std::min(remaining, static_cast<size_t>(spec.width)) + 1;
    }
    return wide_input ? (remaining + 1) : (remaining + 1);
}

template <typename InputT>
static bool handle_manual_alloc_char_scan(Emulator& emu, const InputT& input, size_t pos,
                                          const ScanDirective& spec, uint64_t arg_ptr,
                                          size_t& consumed) {
    size_t remaining = input.size() - pos;
    size_t width = spec.has_width ? static_cast<size_t>(spec.width) : 1;
    width = std::min(width, remaining);
    if (width == 0) {
        return false;
    }

    bool wide_dest = spec.conv == 'C' || spec.length == ScanLengthMod::L;
    uint64_t guest_ptr = 0;
    if (wide_dest) {
        std::vector<wchar_t> value(width);
        for (size_t i = 0; i < width; ++i) {
            if constexpr (std::is_same_v<InputT, std::wstring>) {
                value[i] = input[pos + i];
            } else {
                value[i] = static_cast<unsigned char>(input[pos + i]);
            }
        }
        guest_ptr = emu.memory().heap().allocate(width * sizeof(wchar_t), 8);
        emu.mem_write(guest_ptr, value.data(), width * sizeof(wchar_t));
    } else {
        std::vector<char> value(width);
        for (size_t i = 0; i < width; ++i) {
            if constexpr (std::is_same_v<InputT, std::wstring>) {
                value[i] = static_cast<char>(input[pos + i] & 0xff);
            } else {
                value[i] = input[pos + i];
            }
        }
        guest_ptr = emu.memory().heap().allocate(width, 8);
        emu.mem_write(guest_ptr, value.data(), width);
    }

    emu.mem_write(arg_ptr, &guest_ptr, sizeof(guest_ptr));
    consumed = width;
    return true;
}

template <typename InputT>
static bool handle_manual_scanset_scan(Emulator& emu, const InputT& input, size_t pos,
                                       const ScanDirective& spec, uint64_t arg_ptr,
                                       size_t& consumed) {
    ParsedScanSet scan_set = parse_scanset(spec);
    size_t remaining = input.size() - pos;
    size_t limit = spec.has_width ? std::min(remaining, static_cast<size_t>(spec.width)) : remaining;
    size_t width = 0;

    while (width < limit) {
        uint32_t codepoint = 0;
        if constexpr (std::is_same_v<InputT, std::wstring>) {
            codepoint = static_cast<uint32_t>(input[pos + width]);
        } else {
            codepoint = static_cast<unsigned char>(input[pos + width]);
        }

        if (!scan_set.matches(codepoint)) {
            break;
        }
        ++width;
    }

    if (width == 0) {
        return false;
    }

    bool wide_dest = spec.conv == 'S' || spec.length == ScanLengthMod::L;
    if (!spec.suppress) {
        if (spec.assign_alloc) {
            uint64_t guest_ptr = 0;
            if (wide_dest) {
                std::vector<wchar_t> value(width + 1, 0);
                for (size_t i = 0; i < width; ++i) {
                    if constexpr (std::is_same_v<InputT, std::wstring>) {
                        value[i] = input[pos + i];
                    } else {
                        value[i] = static_cast<unsigned char>(input[pos + i]);
                    }
                }
                guest_ptr = emu.memory().heap().allocate((width + 1) * sizeof(wchar_t), 8);
                emu.mem_write(guest_ptr, value.data(), (width + 1) * sizeof(wchar_t));
            } else {
                std::vector<char> value(width + 1, 0);
                for (size_t i = 0; i < width; ++i) {
                    if constexpr (std::is_same_v<InputT, std::wstring>) {
                        value[i] = static_cast<char>(input[pos + i] & 0xff);
                    } else {
                        value[i] = input[pos + i];
                    }
                }
                guest_ptr = emu.memory().heap().allocate(width + 1, 8);
                emu.mem_write(guest_ptr, value.data(), width + 1);
            }
            emu.mem_write(arg_ptr, &guest_ptr, sizeof(guest_ptr));
        } else if (wide_dest) {
            std::vector<wchar_t> value(width + 1, 0);
            for (size_t i = 0; i < width; ++i) {
                if constexpr (std::is_same_v<InputT, std::wstring>) {
                    value[i] = input[pos + i];
                } else {
                    value[i] = static_cast<unsigned char>(input[pos + i]);
                }
            }
            emu.mem_write(arg_ptr, value.data(), (width + 1) * sizeof(wchar_t));
        } else {
            std::vector<char> value(width + 1, 0);
            for (size_t i = 0; i < width; ++i) {
                if constexpr (std::is_same_v<InputT, std::wstring>) {
                    value[i] = static_cast<char>(input[pos + i] & 0xff);
                } else {
                    value[i] = input[pos + i];
                }
            }
            emu.mem_write(arg_ptr, value.data(), width + 1);
        }
    }

    consumed = width;
    return true;
}

template <typename InputT>
static bool handle_host_float_scan(Emulator& emu, const InputT& input, size_t pos,
                                   const ScanDirective& spec, uint64_t arg_ptr, size_t& consumed,
                                   bool wide_input) {
    int count = 0;
    if constexpr (std::is_same_v<InputT, std::string>) {
        const char* view = input.c_str() + pos;
        std::string fmt = spec.original + "%n";
        if (spec.suppress) {
            int rc = host_scan_narrow(view, fmt, &count);
            consumed = static_cast<size_t>(count);
            return rc == 0 && count > 0;
        }

        if (spec.length == ScanLengthMod::L) {
            double value = 0.0;
            int rc = host_scan_narrow(view, fmt, &value, &count);
            if (rc != 1 || count <= 0) return false;
            emu.mem_write(arg_ptr, &value, sizeof(value));
        } else if (spec.length == ScanLengthMod::BigL) {
            long double value = 0.0L;
            int rc = host_scan_narrow(view, fmt, &value, &count);
            if (rc != 1 || count <= 0) return false;
            alignas(16) unsigned char out[16] = {};
            std::memcpy(out, &value, std::min(sizeof(value), sizeof(out)));
            emu.mem_write(arg_ptr, out, sizeof(out));
        } else {
            float value = 0.0f;
            int rc = host_scan_narrow(view, fmt, &value, &count);
            if (rc != 1 || count <= 0) return false;
            emu.mem_write(arg_ptr, &value, sizeof(value));
        }
    } else {
        const wchar_t* view = input.c_str() + pos;
        std::wstring fmt = build_wide_scan_format(spec);
        if (spec.suppress) {
            int rc = host_scan_wide(view, fmt, &count);
            consumed = static_cast<size_t>(count);
            return rc == 0 && count > 0;
        }

        if (spec.length == ScanLengthMod::L) {
            double value = 0.0;
            int rc = host_scan_wide(view, fmt, &value, &count);
            if (rc != 1 || count <= 0) return false;
            emu.mem_write(arg_ptr, &value, sizeof(value));
        } else if (spec.length == ScanLengthMod::BigL) {
            long double value = 0.0L;
            int rc = host_scan_wide(view, fmt, &value, &count);
            if (rc != 1 || count <= 0) return false;
            alignas(16) unsigned char out[16] = {};
            std::memcpy(out, &value, std::min(sizeof(value), sizeof(out)));
            emu.mem_write(arg_ptr, out, sizeof(out));
        } else {
            float value = 0.0f;
            int rc = host_scan_wide(view, fmt, &value, &count);
            if (rc != 1 || count <= 0) return false;
            emu.mem_write(arg_ptr, &value, sizeof(value));
        }
    }

    consumed = static_cast<size_t>(count);
    return true;
}

template <typename InputT>
static bool handle_host_string_scan(Emulator& emu, const InputT& input, size_t pos,
                                    const ScanDirective& spec, uint64_t arg_ptr, size_t& consumed,
                                    bool wide_input) {
    bool wide_dest = spec.conv == 'C' || spec.conv == 'S' ||
                     spec.length == ScanLengthMod::L;
    size_t width = spec.has_width ? static_cast<size_t>(spec.width) : 1;
    int count = 0;

    if constexpr (std::is_same_v<InputT, std::string>) {
        const char* view = input.c_str() + pos;
        std::string fmt = spec.original + "%n";

        if (spec.suppress) {
            int rc = host_scan_narrow(view, fmt, &count);
            consumed = static_cast<size_t>(count);
            return rc == 0 && count > 0;
        }

        if (spec.assign_alloc) {
            if (wide_dest) {
                wchar_t* value = nullptr;
                int rc = host_scan_narrow(view, fmt, &value, &count);
                if (rc != 1 || count <= 0 || value == nullptr) {
                    std::free(value);
                    return false;
                }

                size_t bytes = 0;
                if (spec.conv == 'c' || spec.conv == 'C') {
                    bytes = width * sizeof(wchar_t);
                } else {
                    bytes = (std::wcslen(value) + 1) * sizeof(wchar_t);
                }

                uint64_t guest_ptr = emu.memory().heap().allocate(bytes, 8);
                emu.mem_write(guest_ptr, value, bytes);
                emu.mem_write(arg_ptr, &guest_ptr, sizeof(guest_ptr));
                std::free(value);
            } else {
                char* value = nullptr;
                int rc = host_scan_narrow(view, fmt, &value, &count);
                if (rc != 1 || count <= 0 || value == nullptr) {
                    std::free(value);
                    return false;
                }

                size_t bytes = (spec.conv == 'c') ? width : (std::strlen(value) + 1);
                uint64_t guest_ptr = emu.memory().heap().allocate(bytes, 8);
                emu.mem_write(guest_ptr, value, bytes);
                emu.mem_write(arg_ptr, &guest_ptr, sizeof(guest_ptr));
                std::free(value);
            }
        } else if (wide_dest) {
            std::vector<wchar_t> value(max_wide_units_for_output(input, pos, spec, wide_input), 0);
            int rc = host_scan_narrow(view, fmt, value.data(), &count);
            if (rc != 1 || count <= 0) {
                return false;
            }

            size_t bytes = 0;
            if (spec.conv == 'c' || spec.conv == 'C') {
                bytes = width * sizeof(wchar_t);
            } else {
                bytes = (std::wcslen(value.data()) + 1) * sizeof(wchar_t);
            }
            emu.mem_write(arg_ptr, value.data(), bytes);
        } else {
            std::vector<char> value(max_narrow_bytes_for_string_output(input, pos, spec, wide_input), 0);
            int rc = host_scan_narrow(view, fmt, value.data(), &count);
            if (rc != 1 || count <= 0) {
                return false;
            }

            size_t bytes = 0;
            if (spec.conv == 'c') {
                bytes = width;
            } else {
                bytes = std::strlen(value.data()) + 1;
            }
            emu.mem_write(arg_ptr, value.data(), bytes);
        }
    } else {
        const wchar_t* view = input.c_str() + pos;
        std::wstring fmt = build_wide_scan_format(spec);

        if (spec.suppress) {
            int rc = host_scan_wide(view, fmt, &count);
            consumed = static_cast<size_t>(count);
            return rc == 0 && count > 0;
        }

        if (wide_dest) {
            std::vector<wchar_t> value(max_wide_units_for_output(input, pos, spec, wide_input), 0);
            int rc = host_scan_wide(view, fmt, value.data(), &count);
            if (rc != 1 || count <= 0) {
                return false;
            }

            size_t bytes = 0;
            if (spec.conv == 'c' || spec.conv == 'C') {
                bytes = width * sizeof(wchar_t);
            } else {
                bytes = (std::wcslen(value.data()) + 1) * sizeof(wchar_t);
            }
            emu.mem_write(arg_ptr, value.data(), bytes);
        } else {
            std::vector<char> value(max_narrow_bytes_for_string_output(input, pos, spec, wide_input), 0);
            int rc = host_scan_wide(view, fmt, value.data(), &count);
            if (rc != 1 || count <= 0) {
                return false;
            }

            size_t bytes = 0;
            if (spec.conv == 'c') {
                bytes = spec.has_width ? static_cast<size_t>(spec.width) : 1;
            } else {
                bytes = std::strlen(value.data()) + 1;
            }
            emu.mem_write(arg_ptr, value.data(), bytes);
        }
    }

    consumed = static_cast<size_t>(count);
    return true;
}

template <typename InputT>
static bool handle_conversion(Emulator& emu, const InputT& input, size_t pos,
                              const ScanDirective& spec, uint64_t arg_ptr, size_t& consumed,
                              bool wide_input) {
    if (is_integer_conv(spec.conv)) {
        uint64_t bits = 0;
        if (!parse_integer_value(input, pos, spec, consumed, bits)) {
            return false;
        }
        if (!spec.suppress) {
            write_integer_bits(emu, arg_ptr, bits, storage_size_for_integer(spec));
        }
        return true;
    }

    if (is_float_conv(spec.conv)) {
        return handle_host_float_scan(emu, input, pos, spec, arg_ptr, consumed, wide_input);
    }

    if (is_stringish_conv(spec.conv)) {
        if (spec.conv == '[') {
            return handle_manual_scanset_scan(emu, input, pos, spec, arg_ptr, consumed);
        }
        if (spec.assign_alloc && (spec.conv == 'c' || spec.conv == 'C')) {
            if (spec.suppress) {
                size_t remaining = input.size() - pos;
                size_t width = spec.has_width ? static_cast<size_t>(spec.width) : 1;
                consumed = std::min(width, remaining);
                return consumed > 0;
            }
            return handle_manual_alloc_char_scan(emu, input, pos, spec, arg_ptr, consumed);
        }
        return handle_host_string_scan(emu, input, pos, spec, arg_ptr, consumed, wide_input);
    }

    return false;
}

template <typename InputT, typename Source>
static HleScanResult scan_with_input(Emulator& emu, const InputT& input,
                                     const std::vector<ScanToken>& tokens, Source& source,
                                     bool wide_input) {
    size_t pos = 0;
    int assigned = 0;

    for (const ScanToken& token : tokens) {
        if (token.is_literal) {
            for (char fc : token.literal) {
                if (std::isspace(static_cast<unsigned char>(fc))) {
                    pos = skip_input_space(input, pos);
                    continue;
                }

                if (pos >= input.size()) {
                    return {.ok = true, .result = assigned == 0 ? EOF : assigned, .error = 0};
                }
                if (!ascii_equals(input[pos], fc)) {
                    return {.ok = true, .result = assigned, .error = 0};
                }
                ++pos;
            }
            continue;
        }

        const ScanDirective& spec = token.spec;
        if (spec_skips_leading_space(spec)) {
            pos = skip_input_space(input, pos);
        }

        if (spec.conv == 'n') {
            if (!spec.suppress) {
                uint64_t arg_ptr = source.next_ptr();
                write_integer_bits(emu, arg_ptr, static_cast<uint64_t>(pos), storage_size_for_integer(spec));
            }
            continue;
        }

        if (pos >= input.size()) {
            return {.ok = true, .result = assigned == 0 ? EOF : assigned, .error = 0};
        }

        uint64_t arg_ptr = 0;
        if (!spec.suppress) {
            arg_ptr = source.next_ptr();
        }

        size_t consumed = 0;
        if (!handle_conversion(emu, input, pos, spec, arg_ptr, consumed, wide_input)) {
            return {.ok = true, .result = assigned, .error = 0};
        }

        pos += consumed;
        if (!spec.suppress) {
            ++assigned;
        }
    }

    return {.ok = true, .result = assigned, .error = 0};
}

template <typename Source>
static HleScanResult scan_with_source(Emulator& emu, uint64_t input_addr, uint64_t fmt_addr,
                                      bool wide_strings, Source& source) {
    std::string fmt = wide_strings ? read_wide_string_utf8(emu, fmt_addr) : read_c_string(emu, fmt_addr);
    ScanParseResult parsed = parse_scan_format(fmt);
    if (!parsed.fatal_message.empty()) {
        // Generic HLE must never abort the whole process on guest-controlled input.
        // An unsupported format string makes only this scanf call fail (EOF) so the
        // calling session sees a normal failure instead of the whole process dying.
        std::fprintf(stderr, "[HLE] scanf: unsupported format token (%s); failing call\n",
                     parsed.fatal_message.c_str());
        std::fflush(stderr);
        return {.ok = false, .result = -1, .error = parsed.error};
    }
    if (!parsed.ok) {
        return {.ok = false, .result = -1, .error = parsed.error};
    }

    if (wide_strings) {
        std::wstring input = read_wide_string(emu, input_addr);
        return scan_with_input(emu, input, parsed.tokens, source, true);
    }

    std::string input = read_c_string(emu, input_addr);
    return scan_with_input(emu, input, parsed.tokens, source, false);
}

}  // namespace

HleScanResult hle_scan_from_regs(Emulator& emu, uint64_t input_addr, uint64_t fmt_addr,
                                 int first_arg_reg, bool wide_strings) {
    RegisterArgSource source(emu, first_arg_reg);
    return scan_with_source(emu, input_addr, fmt_addr, wide_strings, source);
}

HleScanResult hle_scan_from_va_list(Emulator& emu, uint64_t input_addr, uint64_t fmt_addr,
                                    uint64_t va_list_addr, bool wide_strings) {
    VaListArgSource source(emu, va_list_addr);
    return scan_with_source(emu, input_addr, fmt_addr, wide_strings, source);
}

}  // namespace cross_shim
