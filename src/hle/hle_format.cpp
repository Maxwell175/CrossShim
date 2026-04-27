/**
 * Shared formatting helpers for stdio/wchar HLE.
 */

#include "hle_format.h"

#include "cross_shim.h"
#include "debug_log.h"
#include "emu_compat.h"
#include "hle_manager.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <climits>
#include <clocale>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <inttypes.h>
#include <limits>
#include <locale.h>
#include <optional>
#include <quadmath.h>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

namespace cross_shim {

namespace {

static constexpr size_t kMaxStringLen = 1 << 20;

static uint64_t align_up_u64(uint64_t value, uint64_t alignment) {
    return (value + alignment - 1) & ~(alignment - 1);
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

static std::string read_c_string(Emulator& emu, uint64_t addr, size_t max_len = kMaxStringLen) {
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

static std::wstring read_wide_string(Emulator& emu, uint64_t addr, size_t max_len = kMaxStringLen) {
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

static std::string read_wide_string_utf8(Emulator& emu, uint64_t addr, size_t max_len = kMaxStringLen) {
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

enum class ArgKind {
    None,
    Int,
    UInt,
    Long,
    ULong,
    LongLong,
    ULongLong,
    IntMax,
    UIntMax,
    SSize,
    Size,
    PtrDiff,
    Pointer,
    CString,
    WString,
    Double,
    Quad,
};

enum class LengthMod {
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

struct PrintArg {
    ArgKind kind = ArgKind::None;
    int64_t s64 = 0;
    uint64_t u64 = 0;
    double d = 0.0;
    __float128 q = 0;
};

struct FormatSpec {
    std::string original;
    std::string flags;
    bool has_width = false;
    bool width_from_arg = false;
    int width = 0;
    int width_position = 0;
    bool has_precision = false;
    bool precision_from_arg = false;
    int precision = 0;
    int precision_position = 0;
    int value_position = 0;
    LengthMod length = LengthMod::None;
    int w_bits = 0;
    char conv = '\0';
};

struct FormatItem {
    bool is_literal = true;
    std::string literal;
    FormatSpec spec;
};

struct ParsedFormat {
    bool ok = true;
    int error = 0;
    std::vector<FormatItem> items;
    std::vector<ArgKind> arg_kinds;
};

struct arm64_va_list {
    uint64_t __stack;
    uint64_t __gr_top;
    uint64_t __vr_top;
    int32_t __gr_offs;
    int32_t __vr_offs;
};

static bool is_signed_int_conv(char conv) {
    return conv == 'd' || conv == 'i';
}

static bool is_unsigned_int_conv(char conv) {
    return conv == 'u' || conv == 'o' || conv == 'x' || conv == 'X' || conv == 'b' || conv == 'B';
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

static bool spec_takes_value_arg(const FormatSpec& spec) {
    if (spec.conv == '%') return false;
    if (spec.conv == 'm') return false;
    return true;
}

static int fast_int_bytes(bool is_signed, int bits) {
    switch (bits) {
        case 8:
            return static_cast<int>(is_signed ? sizeof(int_fast8_t) : sizeof(uint_fast8_t));
        case 16:
            return static_cast<int>(is_signed ? sizeof(int_fast16_t) : sizeof(uint_fast16_t));
        case 32:
            return static_cast<int>(is_signed ? sizeof(int_fast32_t) : sizeof(uint_fast32_t));
        case 64:
            return static_cast<int>(is_signed ? sizeof(int_fast64_t) : sizeof(uint_fast64_t));
        default:
            return 0;
    }
}

static ArgKind resolve_w_arg_kind(const FormatSpec& spec) {
    bool is_signed = is_signed_int_conv(spec.conv);
    bool is_unsigned = is_unsigned_int_conv(spec.conv);
    if (!is_signed && !is_unsigned) {
        return ArgKind::None;
    }

    int bytes = 0;
    if (spec.length == LengthMod::ExactW) {
        bytes = spec.w_bits / 8;
    } else {
        bytes = fast_int_bytes(is_signed, spec.w_bits);
    }

    if (bytes <= 0) {
        return ArgKind::None;
    }

    if (bytes <= 4) {
        return is_signed ? ArgKind::Int : ArgKind::UInt;
    }
    return is_signed ? ArgKind::LongLong : ArgKind::ULongLong;
}

static ArgKind determine_arg_kind(const FormatSpec& spec) {
    if (spec.length == LengthMod::ExactW || spec.length == LengthMod::FastW) {
        return resolve_w_arg_kind(spec);
    }

    if (is_float_conv(spec.conv)) {
        return spec.length == LengthMod::BigL ? ArgKind::Quad : ArgKind::Double;
    }

    if (is_signed_int_conv(spec.conv)) {
        switch (spec.length) {
            case LengthMod::J:
                return ArgKind::IntMax;
            case LengthMod::Z:
                return ArgKind::SSize;
            case LengthMod::T:
                return ArgKind::PtrDiff;
            case LengthMod::L:
                return ArgKind::Long;
            case LengthMod::LL:
                return ArgKind::LongLong;
            default:
                return ArgKind::Int;
        }
    }

    if (is_unsigned_int_conv(spec.conv)) {
        switch (spec.length) {
            case LengthMod::J:
                return ArgKind::UIntMax;
            case LengthMod::Z:
                return ArgKind::Size;
            case LengthMod::L:
                return ArgKind::ULong;
            case LengthMod::LL:
                return ArgKind::ULongLong;
            default:
                return ArgKind::UInt;
        }
    }

    switch (spec.conv) {
        case 'c':
            return ArgKind::Int;
        case 'C':
            return ArgKind::Int;
        case 's':
            return spec.length == LengthMod::L ? ArgKind::WString : ArgKind::CString;
        case 'S':
            return ArgKind::WString;
        case 'p':
            return ArgKind::Pointer;
        case 'n':
            return ArgKind::Pointer;
        case 'm':
            return ArgKind::None;
        default:
            return ArgKind::None;
    }
}

static std::string exact_or_fast_length_string(const FormatSpec& spec) {
    bool is_signed = is_signed_int_conv(spec.conv);
    int bytes = 0;
    if (spec.length == LengthMod::ExactW) {
        bytes = spec.w_bits / 8;
    } else {
        bytes = fast_int_bytes(is_signed, spec.w_bits);
    }

    switch (bytes) {
        case 1:
            return "hh";
        case 2:
            return "h";
        case 4:
            return "";
        case 8:
            return "ll";
        default:
            return "";
    }
}

static ParsedFormat parse_format_string(const std::string& fmt) {
    ParsedFormat parsed;
    parsed.arg_kinds.resize(1, ArgKind::None);  // 1-based indexing.

    int next_seq_position = 1;
    std::string pending_literal;

    auto reserve_position = [&](int position, ArgKind kind) {
        if (position <= 0 || kind == ArgKind::None) {
            return;
        }
        if (static_cast<size_t>(position) >= parsed.arg_kinds.size()) {
            parsed.arg_kinds.resize(position + 1, ArgKind::None);
        }
        if (parsed.arg_kinds[position] == ArgKind::None) {
            parsed.arg_kinds[position] = kind;
        }
    };

    auto flush_literal = [&]() {
        if (pending_literal.empty()) {
            return;
        }
        FormatItem item;
        item.is_literal = true;
        item.literal = pending_literal;
        parsed.items.push_back(std::move(item));
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

        FormatSpec spec;
        size_t start = i;
        ++i;
        if (i >= fmt.size()) {
            parsed.ok = false;
            parsed.error = EINVAL;
            return parsed;
        }

        size_t cursor = i;

        // Optional positional index.
        if (std::isdigit(static_cast<unsigned char>(fmt[cursor]))) {
            size_t number_start = cursor;
            while (cursor < fmt.size() && std::isdigit(static_cast<unsigned char>(fmt[cursor]))) {
                ++cursor;
            }
            if (cursor < fmt.size() && fmt[cursor] == '$') {
                spec.value_position = std::stoi(fmt.substr(number_start, cursor - number_start));
                ++cursor;
            } else {
                cursor = number_start;
            }
        }

        while (cursor < fmt.size() &&
               (fmt[cursor] == '-' || fmt[cursor] == '+' || fmt[cursor] == ' ' ||
                fmt[cursor] == '#' || fmt[cursor] == '0' || fmt[cursor] == '\'')) {
            spec.flags.push_back(fmt[cursor]);
            ++cursor;
        }

        // Width.
        if (cursor < fmt.size() && fmt[cursor] == '*') {
            spec.has_width = true;
            spec.width_from_arg = true;
            ++cursor;

            if (cursor < fmt.size() && std::isdigit(static_cast<unsigned char>(fmt[cursor]))) {
                size_t number_start = cursor;
                while (cursor < fmt.size() && std::isdigit(static_cast<unsigned char>(fmt[cursor]))) {
                    ++cursor;
                }
                if (cursor < fmt.size() && fmt[cursor] == '$') {
                    spec.width_position = std::stoi(fmt.substr(number_start, cursor - number_start));
                    ++cursor;
                } else {
                    cursor = number_start;
                }
            }
        } else if (cursor < fmt.size() && std::isdigit(static_cast<unsigned char>(fmt[cursor]))) {
            spec.has_width = true;
            unsigned long long width = 0;
            while (cursor < fmt.size() && std::isdigit(static_cast<unsigned char>(fmt[cursor]))) {
                width = width * 10 + static_cast<unsigned long long>(fmt[cursor] - '0');
                if (width > static_cast<unsigned long long>(INT_MAX)) {
                    parsed.ok = false;
                    parsed.error = ENOMEM;
                    return parsed;
                }
                ++cursor;
            }
            spec.width = static_cast<int>(width);
        }

        // Precision.
        if (cursor < fmt.size() && fmt[cursor] == '.') {
            ++cursor;
            spec.has_precision = true;

            if (cursor < fmt.size() && fmt[cursor] == '*') {
                spec.precision_from_arg = true;
                ++cursor;

                if (cursor < fmt.size() && std::isdigit(static_cast<unsigned char>(fmt[cursor]))) {
                    size_t number_start = cursor;
                    while (cursor < fmt.size() && std::isdigit(static_cast<unsigned char>(fmt[cursor]))) {
                        ++cursor;
                    }
                    if (cursor < fmt.size() && fmt[cursor] == '$') {
                        spec.precision_position = std::stoi(fmt.substr(number_start, cursor - number_start));
                        ++cursor;
                    } else {
                        cursor = number_start;
                    }
                }
            } else {
                unsigned long long precision = 0;
                while (cursor < fmt.size() && std::isdigit(static_cast<unsigned char>(fmt[cursor]))) {
                    precision = precision * 10 + static_cast<unsigned long long>(fmt[cursor] - '0');
                    if (precision > static_cast<unsigned long long>(INT_MAX)) {
                        parsed.ok = false;
                        parsed.error = ENOMEM;
                        return parsed;
                    }
                    ++cursor;
                }
                spec.precision = static_cast<int>(precision);
            }
        }

        // Length modifier / Android %w / %wf.
        if (cursor < fmt.size()) {
            if (fmt[cursor] == 'w') {
                ++cursor;
                spec.length = LengthMod::ExactW;
                if (cursor < fmt.size() && fmt[cursor] == 'f') {
                    spec.length = LengthMod::FastW;
                    ++cursor;
                }

                unsigned long long bits = 0;
                while (cursor < fmt.size() && std::isdigit(static_cast<unsigned char>(fmt[cursor]))) {
                    bits = bits * 10 + static_cast<unsigned long long>(fmt[cursor] - '0');
                    ++cursor;
                }
                if (bits != 8 && bits != 16 && bits != 32 && bits != 64) {
                    parsed.ok = false;
                    parsed.error = EINVAL;
                    return parsed;
                }
                spec.w_bits = static_cast<int>(bits);
            } else if (fmt[cursor] == 'h') {
                ++cursor;
                if (cursor < fmt.size() && fmt[cursor] == 'h') {
                    spec.length = LengthMod::HH;
                    ++cursor;
                } else {
                    spec.length = LengthMod::H;
                }
            } else if (fmt[cursor] == 'l') {
                ++cursor;
                if (cursor < fmt.size() && fmt[cursor] == 'l') {
                    spec.length = LengthMod::LL;
                    ++cursor;
                } else {
                    spec.length = LengthMod::L;
                }
            } else if (fmt[cursor] == 'L') {
                spec.length = LengthMod::BigL;
                ++cursor;
            } else if (fmt[cursor] == 'j') {
                spec.length = LengthMod::J;
                ++cursor;
            } else if (fmt[cursor] == 'z') {
                spec.length = LengthMod::Z;
                ++cursor;
            } else if (fmt[cursor] == 't') {
                spec.length = LengthMod::T;
                ++cursor;
            }
        }

        if (cursor >= fmt.size()) {
            parsed.ok = false;
            parsed.error = EINVAL;
            return parsed;
        }

        spec.conv = fmt[cursor];
        spec.original = fmt.substr(start, cursor - start + 1);

        if (spec.width_from_arg && spec.width_position == 0) {
            spec.width_position = next_seq_position++;
        }
        if (spec.precision_from_arg && spec.precision_position == 0) {
            spec.precision_position = next_seq_position++;
        }
        if (spec_takes_value_arg(spec) && spec.value_position == 0) {
            spec.value_position = next_seq_position++;
        }

        reserve_position(spec.width_position, ArgKind::Int);
        reserve_position(spec.precision_position, ArgKind::Int);
        reserve_position(spec.value_position, determine_arg_kind(spec));

        FormatItem item;
        item.is_literal = false;
        item.spec = spec;
        parsed.items.push_back(std::move(item));
        i = cursor;
    }

    flush_literal();
    return parsed;
}

struct RegisterArgSource {
    explicit RegisterArgSource(Emulator& emu_in, int first_gp_reg)
        : emu(emu_in), next_gp_reg(first_gp_reg), stack_addr(get_reg(emu_in, UC_ARM64_REG_SP)) {}

    uint64_t next_gp_raw(size_t size = 8, size_t align = 8) {
        if (next_gp_reg <= 7) {
            uint64_t value = get_reg(emu, UC_ARM64_REG_X0 + next_gp_reg);
            ++next_gp_reg;
            return value;
        }

        stack_addr = align_up_u64(stack_addr, align);
        uint64_t value = 0;
        emu.mem_read(stack_addr, &value, size);
        stack_addr += align_up_u64(size, 8);
        return value;
    }

    double next_fp64() {
        if (next_fp_reg <= 7) {
            double value = get_dreg(emu, next_fp_reg);
            ++next_fp_reg;
            return value;
        }

        stack_addr = align_up_u64(stack_addr, 8);
        double value = 0.0;
        emu.mem_read(stack_addr, &value, sizeof(value));
        stack_addr += 8;
        return value;
    }

    __float128 next_fp128() {
        __float128 value = 0;
        if (next_fp_reg <= 7) {
            uint8_t bytes[16] = {};
            get_qreg(emu, UC_ARM64_REG_Q0 + next_fp_reg, bytes);
            ++next_fp_reg;
            std::memcpy(&value, bytes, 16);
            return value;
        }

        stack_addr = align_up_u64(stack_addr, 16);
        emu.mem_read(stack_addr, &value, 16);
        stack_addr += 16;
        return value;
    }

    Emulator& emu;
    int next_gp_reg = 0;
    int next_fp_reg = 0;
    uint64_t stack_addr = 0;
};

struct VaListArgSource {
    VaListArgSource(Emulator& emu_in, uint64_t va_list_addr) : emu(emu_in) {
        emu.mem_read(va_list_addr, &va, sizeof(va));
    }

    uint64_t next_gp_raw(size_t size = 8, size_t align = 8) {
        if (va.__gr_offs < 0) {
            uint64_t addr = va.__gr_top + static_cast<uint64_t>(va.__gr_offs);
            uint64_t value = 0;
            emu.mem_read(addr, &value, size);
            va.__gr_offs += 8;
            return value;
        }

        va.__stack = align_up_u64(va.__stack, align);
        uint64_t value = 0;
        emu.mem_read(va.__stack, &value, size);
        va.__stack += align_up_u64(size, 8);
        return value;
    }

    double next_fp64() {
        if (va.__vr_offs < 0) {
            uint64_t addr = va.__vr_top + static_cast<uint64_t>(va.__vr_offs);
            double value = 0.0;
            emu.mem_read(addr, &value, sizeof(value));
            va.__vr_offs += 16;
            return value;
        }

        va.__stack = align_up_u64(va.__stack, 8);
        double value = 0.0;
        emu.mem_read(va.__stack, &value, sizeof(value));
        va.__stack += 8;
        return value;
    }

    __float128 next_fp128() {
        __float128 value = 0;
        if (va.__vr_offs < 0) {
            uint64_t addr = va.__vr_top + static_cast<uint64_t>(va.__vr_offs);
            emu.mem_read(addr, &value, 16);
            va.__vr_offs += 16;
            return value;
        }

        va.__stack = align_up_u64(va.__stack, 16);
        emu.mem_read(va.__stack, &value, 16);
        va.__stack += 16;
        return value;
    }

    Emulator& emu;
    arm64_va_list va{};
};

template <typename Source>
static PrintArg read_arg(Source& source, ArgKind kind) {
    PrintArg arg;
    arg.kind = kind;

    switch (kind) {
        case ArgKind::Int:
            arg.s64 = static_cast<int32_t>(source.next_gp_raw());
            break;
        case ArgKind::UInt:
            arg.u64 = static_cast<uint32_t>(source.next_gp_raw());
            break;
        case ArgKind::Long:
            arg.s64 = static_cast<long>(source.next_gp_raw());
            break;
        case ArgKind::ULong:
            arg.u64 = static_cast<unsigned long>(source.next_gp_raw());
            break;
        case ArgKind::LongLong:
        case ArgKind::IntMax:
        case ArgKind::SSize:
        case ArgKind::PtrDiff:
            arg.s64 = static_cast<int64_t>(source.next_gp_raw());
            break;
        case ArgKind::ULongLong:
        case ArgKind::UIntMax:
        case ArgKind::Size:
        case ArgKind::Pointer:
        case ArgKind::CString:
        case ArgKind::WString:
            arg.u64 = source.next_gp_raw();
            break;
        case ArgKind::Double:
            arg.d = source.next_fp64();
            break;
        case ArgKind::Quad:
            arg.q = source.next_fp128();
            break;
        case ArgKind::None:
            break;
    }

    return arg;
}

template <typename Source>
static std::vector<PrintArg> materialize_args(Source& source, const std::vector<ArgKind>& arg_kinds) {
    std::vector<PrintArg> args(arg_kinds.size());
    for (size_t i = 1; i < arg_kinds.size(); ++i) {
        args[i] = read_arg(source, arg_kinds[i]);
    }
    return args;
}

static bool has_flag(const FormatSpec& spec, char flag) {
    return spec.flags.find(flag) != std::string::npos;
}

static int width_value_for_spec(const FormatSpec& spec, const std::vector<PrintArg>& args) {
    return spec.width_from_arg ? static_cast<int>(args[spec.width_position].s64) : spec.width;
}

static int precision_value_for_spec(const FormatSpec& spec, const std::vector<PrintArg>& args) {
    return spec.precision_from_arg ? static_cast<int>(args[spec.precision_position].s64) : spec.precision;
}

static std::string build_host_format(const FormatSpec& spec, char override_conv = '\0',
                                     std::string_view override_length = {}) {
    std::string fmt;
    fmt.push_back('%');
    fmt += spec.flags;

    if (spec.has_width) {
        if (spec.width_from_arg) {
            fmt.push_back('*');
        } else {
            fmt += std::to_string(spec.width);
        }
    }

    if (spec.has_precision) {
        fmt.push_back('.');
        if (spec.precision_from_arg) {
            fmt.push_back('*');
        } else {
            fmt += std::to_string(spec.precision);
        }
    }

    if (!override_length.empty()) {
        fmt.append(override_length);
    } else {
        switch (spec.length) {
            case LengthMod::HH:
                fmt += "hh";
                break;
            case LengthMod::H:
                fmt += 'h';
                break;
            case LengthMod::L:
                fmt += 'l';
                break;
            case LengthMod::LL:
                fmt += "ll";
                break;
            case LengthMod::BigL:
                fmt += 'L';
                break;
            case LengthMod::J:
                fmt += 'j';
                break;
            case LengthMod::Z:
                fmt += 'z';
                break;
            case LengthMod::T:
                fmt += 't';
                break;
            case LengthMod::ExactW:
            case LengthMod::FastW:
                fmt += exact_or_fast_length_string(spec);
                break;
            case LengthMod::None:
                break;
        }
    }

    char conv = override_conv == '\0' ? spec.conv : override_conv;
    if (conv == 'S') conv = 's';
    if (conv == 'C') conv = 'c';
    fmt.push_back(conv);
    return fmt;
}

template <typename... Args>
static HleFormatResult host_snprintf_result(const std::string& fmt, Args... args) {
    ScopedUtf8Locale locale_guard;
    int saved_errno = errno;
    int needed = std::snprintf(nullptr, 0, fmt.c_str(), args...);
    if (needed < 0) {
        return {.ok = false, .result = -1, .error = errno != 0 ? errno : EINVAL, .output = {}};
    }

    std::string output(static_cast<size_t>(needed), '\0');
    int written = std::snprintf(output.data(), output.size() + 1, fmt.c_str(), args...);
    if (written < 0) {
        return {.ok = false, .result = -1, .error = errno != 0 ? errno : EINVAL, .output = {}};
    }
    errno = saved_errno;
    return {.ok = true, .result = written, .error = 0, .output = std::move(output)};
}

template <typename... Args>
static HleFormatResult host_quadmath_result(const std::string& fmt, Args... args) {
    ScopedUtf8Locale locale_guard;
    int saved_errno = errno;
    int needed = quadmath_snprintf(nullptr, 0, fmt.c_str(), args...);
    if (needed < 0) {
        return {.ok = false, .result = -1, .error = errno != 0 ? errno : EINVAL, .output = {}};
    }

    std::string output(static_cast<size_t>(needed), '\0');
    int written = quadmath_snprintf(output.data(), output.size() + 1, fmt.c_str(), args...);
    if (written < 0) {
        return {.ok = false, .result = -1, .error = errno != 0 ? errno : EINVAL, .output = {}};
    }
    errno = saved_errno;
    return {.ok = true, .result = written, .error = 0, .output = std::move(output)};
}

template <typename Value>
static HleFormatResult host_format_value(const std::string& fmt, const FormatSpec& spec,
                                         const std::vector<PrintArg>& args, Value value) {
    if (spec.width_from_arg && spec.precision_from_arg) {
        return host_snprintf_result(fmt, width_value_for_spec(spec, args),
                                    precision_value_for_spec(spec, args), value);
    }
    if (spec.width_from_arg) {
        return host_snprintf_result(fmt, width_value_for_spec(spec, args), value);
    }
    if (spec.precision_from_arg) {
        return host_snprintf_result(fmt, precision_value_for_spec(spec, args), value);
    }
    return host_snprintf_result(fmt, value);
}

static HleFormatResult host_format_no_value(const std::string& fmt, const FormatSpec& spec,
                                            const std::vector<PrintArg>& args) {
    if (spec.width_from_arg && spec.precision_from_arg) {
        return host_snprintf_result(fmt, width_value_for_spec(spec, args),
                                    precision_value_for_spec(spec, args));
    }
    if (spec.width_from_arg) {
        return host_snprintf_result(fmt, width_value_for_spec(spec, args));
    }
    if (spec.precision_from_arg) {
        return host_snprintf_result(fmt, precision_value_for_spec(spec, args));
    }
    return host_snprintf_result(fmt);
}

static HleFormatResult host_format_quad(const std::string& fmt, const FormatSpec& spec,
                                        const std::vector<PrintArg>& args, __float128 value) {
    if (spec.width_from_arg && spec.precision_from_arg) {
        return host_quadmath_result(fmt, width_value_for_spec(spec, args),
                                    precision_value_for_spec(spec, args), value);
    }
    if (spec.width_from_arg) {
        return host_quadmath_result(fmt, width_value_for_spec(spec, args), value);
    }
    if (spec.precision_from_arg) {
        return host_quadmath_result(fmt, precision_value_for_spec(spec, args), value);
    }
    return host_quadmath_result(fmt, value);
}

static std::string apply_binary_width(const FormatSpec& spec, const std::vector<PrintArg>& args,
                                      std::string digits, bool uppercase, uint64_t value) {
    bool alternate = has_flag(spec, '#') && value != 0;
    bool left = has_flag(spec, '-');
    bool zero = has_flag(spec, '0');

    if (spec.width_from_arg) {
        int width = width_value_for_spec(spec, args);
        if (width < 0) {
            left = true;
        }
    }

    if (spec.has_precision) {
        int precision = precision_value_for_spec(spec, args);
        if (precision >= 0) {
            zero = false;
            if (precision == 0 && value == 0) {
                digits.clear();
            } else if (static_cast<int>(digits.size()) < precision) {
                digits.insert(digits.begin(), precision - static_cast<int>(digits.size()), '0');
            }
        }
    }

    std::string prefix;
    if (alternate) {
        prefix = uppercase ? "0B" : "0b";
    }

    int width = spec.has_width ? width_value_for_spec(spec, args) : 0;
    if (width < 0) {
        left = true;
        width = -width;
    }

    size_t total_len = prefix.size() + digits.size();
    if (!left && zero && width > static_cast<int>(total_len)) {
        digits.insert(digits.begin(), width - static_cast<int>(total_len), '0');
    }

    total_len = prefix.size() + digits.size();
    std::string result = prefix + digits;
    if (width > static_cast<int>(total_len)) {
        std::string padding(width - static_cast<int>(total_len), ' ');
        if (left) {
            result += padding;
        } else {
            result = padding + result;
        }
    }
    return result;
}

static HleFormatResult format_binary_spec(const FormatSpec& spec, const std::vector<PrintArg>& args,
                                          uint64_t value) {
    std::string digits;
    if (value == 0) {
        digits = "0";
    } else {
        uint64_t working = value;
        while (working != 0) {
            digits.push_back((working & 1) ? '1' : '0');
            working >>= 1;
        }
        std::reverse(digits.begin(), digits.end());
    }

    std::string result = apply_binary_width(spec, args, std::move(digits), spec.conv == 'B', value);
    return {.ok = true, .result = static_cast<int>(result.size()), .error = 0, .output = std::move(result)};
}

static HleFormatResult format_pointer_null_spec(const FormatSpec& spec, const std::vector<PrintArg>& args) {
    std::string fmt = build_host_format(spec, 's');
    return host_format_value(fmt, spec, args, "0x0");
}

static HleFormatResult format_string_spec(Emulator& emu, const FormatSpec& spec,
                                          const std::vector<PrintArg>& args) {
    const PrintArg& value = args[spec.value_position];

    if (spec.conv == 's' && spec.length != LengthMod::L) {
        std::string host_string = value.u64 != 0 ? read_c_string(emu, value.u64) : "(null)";
        std::string fmt = build_host_format(spec, 's');
        return host_format_value(fmt, spec, args, host_string.c_str());
    }

    std::wstring host_wstring = value.u64 != 0 ? read_wide_string(emu, value.u64) : std::wstring(L"(null)");
    std::string fmt = build_host_format(spec, 's', "l");
    return host_format_value(fmt, spec, args, host_wstring.c_str());
}

static HleFormatResult format_int_spec(const FormatSpec& spec, const std::vector<PrintArg>& args) {
    std::string fmt = build_host_format(spec);
    const PrintArg& value = args[spec.value_position];

    switch (value.kind) {
        case ArgKind::Int:
            return host_format_value(fmt, spec, args, static_cast<int>(value.s64));
        case ArgKind::UInt:
            return host_format_value(fmt, spec, args, static_cast<unsigned int>(value.u64));
        case ArgKind::Long:
            return host_format_value(fmt, spec, args, static_cast<long>(value.s64));
        case ArgKind::ULong:
            return host_format_value(fmt, spec, args, static_cast<unsigned long>(value.u64));
        case ArgKind::LongLong:
            return host_format_value(fmt, spec, args, static_cast<long long>(value.s64));
        case ArgKind::ULongLong:
            return host_format_value(fmt, spec, args, static_cast<unsigned long long>(value.u64));
        case ArgKind::IntMax:
            return host_format_value(fmt, spec, args, static_cast<intmax_t>(value.s64));
        case ArgKind::UIntMax:
            return host_format_value(fmt, spec, args, static_cast<uintmax_t>(value.u64));
        case ArgKind::SSize:
            return host_format_value(fmt, spec, args, static_cast<ssize_t>(value.s64));
        case ArgKind::Size:
            return host_format_value(fmt, spec, args, static_cast<size_t>(value.u64));
        case ArgKind::PtrDiff:
            return host_format_value(fmt, spec, args, static_cast<ptrdiff_t>(value.s64));
        default:
            return {.ok = false, .result = -1, .error = EINVAL, .output = {}};
    }
}

static HleFormatResult format_float_spec(const FormatSpec& spec, const std::vector<PrintArg>& args) {
    const PrintArg& value = args[spec.value_position];
    if (value.kind == ArgKind::Quad) {
        std::string fmt = build_host_format(spec, spec.conv, "Q");
        return host_format_quad(fmt, spec, args, value.q);
    }

    std::string fmt = build_host_format(spec);
    return host_format_value(fmt, spec, args, value.d);
}

static HleFormatResult format_pointer_spec(const FormatSpec& spec, const std::vector<PrintArg>& args) {
    const PrintArg& value = args[spec.value_position];
    if (value.u64 == 0) {
        return format_pointer_null_spec(spec, args);
    }
    std::string fmt = build_host_format(spec);
    return host_format_value(fmt, spec, args, reinterpret_cast<void*>(value.u64));
}

static HleFormatResult format_char_spec(const FormatSpec& spec, const std::vector<PrintArg>& args) {
    const PrintArg& value = args[spec.value_position];
    if (spec.conv == 'C' || spec.length == LengthMod::L) {
        std::string fmt = build_host_format(spec, 'c', "l");
        return host_format_value(fmt, spec, args, static_cast<wint_t>(static_cast<uint32_t>(value.s64)));
    }

    std::string fmt = build_host_format(spec, 'c');
    return host_format_value(fmt, spec, args, static_cast<int>(value.s64));
}

static HleFormatResult format_m_spec(const FormatSpec& spec, const std::vector<PrintArg>& args) {
    std::string fmt = build_host_format(spec);
    return host_format_no_value(fmt, spec, args);
}

static HleFormatResult format_directive(Emulator& emu, const FormatSpec& spec,
                                        const std::vector<PrintArg>& args) {
    if (spec.conv == 'n') {
        return {.ok = false, .result = -1, .error = EINVAL, .output = {}};
    }

    if (spec.conv == 'm') {
        return format_m_spec(spec, args);
    }
    if (spec.conv == 'p') {
        return format_pointer_spec(spec, args);
    }
    if (spec.conv == 's' || spec.conv == 'S') {
        return format_string_spec(emu, spec, args);
    }
    if (spec.conv == 'c' || spec.conv == 'C') {
        return format_char_spec(spec, args);
    }
    if (spec.conv == 'b' || spec.conv == 'B') {
        const PrintArg& value = args[spec.value_position];
        uint64_t binary_value = 0;
        switch (value.kind) {
            case ArgKind::Int:
            case ArgKind::Long:
            case ArgKind::LongLong:
            case ArgKind::IntMax:
            case ArgKind::SSize:
            case ArgKind::PtrDiff:
                binary_value = static_cast<uint64_t>(value.s64);
                break;
            default:
                binary_value = value.u64;
                break;
        }
        return format_binary_spec(spec, args, binary_value);
    }
    if (is_float_conv(spec.conv)) {
        return format_float_spec(spec, args);
    }
    if (is_signed_int_conv(spec.conv) || is_unsigned_int_conv(spec.conv)) {
        return format_int_spec(spec, args);
    }

    std::string fmt = build_host_format(spec);
    return host_format_no_value(fmt, spec, args);
}

template <typename Source>
static HleFormatResult format_with_source(Emulator& emu, uint64_t fmt_addr, bool wide_format,
                                          Source&& source) {
    std::string fmt = wide_format ? read_wide_string_utf8(emu, fmt_addr) : read_c_string(emu, fmt_addr);
    ParsedFormat parsed = parse_format_string(fmt);
    if (!parsed.ok) {
        return {.ok = false, .result = -1, .error = parsed.error, .output = {}};
    }

    std::vector<PrintArg> args = materialize_args(source, parsed.arg_kinds);

    std::string output;
    int guest_errno = hle_get_errno(emu);
    for (const FormatItem& item : parsed.items) {
        if (item.is_literal) {
            output += item.literal;
            continue;
        }

        errno = guest_errno;
        HleFormatResult piece = format_directive(emu, item.spec, args);
        if (!piece.ok) {
            return piece;
        }
        output += piece.output;
    }

    return {.ok = true, .result = static_cast<int>(output.size()), .error = 0, .output = std::move(output)};
}

}  // namespace

HleFormatResult hle_format_from_regs(Emulator& emu, uint64_t fmt_addr, int first_arg_reg,
                                     bool wide_format) {
    RegisterArgSource source(emu, first_arg_reg);
    return format_with_source(emu, fmt_addr, wide_format, source);
}

HleFormatResult hle_format_from_va_list(Emulator& emu, uint64_t fmt_addr, uint64_t va_list_addr,
                                        bool wide_format) {
    VaListArgSource source(emu, va_list_addr);
    return format_with_source(emu, fmt_addr, wide_format, source);
}

}  // namespace cross_shim
