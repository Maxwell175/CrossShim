/**
 * HLE I/O Functions
 * printf, fprintf, sprintf, snprintf, sscanf
 * fopen, fclose, fread, fwrite, fseek, ftell, fgets, fputs, puts
 * open, close, read, write, lseek
 */

#include "debug_log.h"
#include "hle_manager.h"
#include "cross_shim.h"
#include "memory_manager.h"
#include "emu_compat.h"
#include <cstring>
#include <cstdio>
#include <cstdarg>
#include <vector>
#include <unordered_map>
#include <iostream>

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

// File handle management (shared with hle_file.cpp)
extern std::unordered_map<int, FILE*> g_file_map;
extern int g_next_fd;

// ARM64 va_list structure
// See: https://developer.arm.com/documentation/ihi0055/latest/
struct arm64_va_list {
    uint64_t __stack;      // pointer to next stack argument
    uint64_t __gr_top;     // pointer to end of general register save area
    uint64_t __vr_top;     // pointer to end of vector register save area
    int32_t __gr_offs;     // offset from __gr_top to next general register arg
    int32_t __vr_offs;     // offset from __vr_top to next vector register arg
};

// Helper to format printf-style output using va_list from guest memory
static std::string do_vprintf_format(Emulator& emu, const std::string& fmt, uint64_t va_list_addr) {
    // Read the va_list structure from guest memory
    arm64_va_list va;
    emu.mem_read(va_list_addr, &va.__stack, sizeof(va.__stack));
    emu.mem_read(va_list_addr + 8, &va.__gr_top, sizeof(va.__gr_top));
    emu.mem_read(va_list_addr + 16, &va.__vr_top, sizeof(va.__vr_top));
    emu.mem_read(va_list_addr + 24, &va.__gr_offs, sizeof(va.__gr_offs));
    emu.mem_read(va_list_addr + 28, &va.__vr_offs, sizeof(va.__vr_offs));

    std::string result;
    char buf[256];

    auto get_next_int_arg = [&]() -> uint64_t {
        uint64_t val = 0;
        if (va.__gr_offs < 0) {
            // Read from register save area
            uint64_t addr = va.__gr_top + va.__gr_offs;
            emu.mem_read(addr, &val, sizeof(val));
            va.__gr_offs += 8;
        } else {
            // Read from stack
            emu.mem_read(va.__stack, &val, sizeof(val));
            va.__stack += 8;
        }
        return val;
    };

    auto get_next_fp_arg = [&]() -> double {
        double val = 0.0;
        if (va.__vr_offs < 0) {
            // Read from vector register save area
            uint64_t addr = va.__vr_top + va.__vr_offs;
            emu.mem_read(addr, &val, sizeof(val));
            va.__vr_offs += 16;  // SIMD registers are 16 bytes
        } else {
            // Read from stack
            emu.mem_read(va.__stack, &val, sizeof(val));
            va.__stack += 8;
        }
        return val;
    };

    for (size_t i = 0; i < fmt.length(); i++) {
        if (fmt[i] != '%') {
            result += fmt[i];
            continue;
        }

        size_t spec_start = i;
        i++;
        if (i >= fmt.length()) break;

        if (fmt[i] == '%') {
            result += '%';
            continue;
        }

        // Skip flags
        while (i < fmt.length() && (fmt[i] == '-' || fmt[i] == '+' ||
               fmt[i] == ' ' || fmt[i] == '#' || fmt[i] == '0')) i++;
        // Skip width
        while (i < fmt.length() && fmt[i] >= '0' && fmt[i] <= '9') i++;
        // Skip precision
        if (i < fmt.length() && fmt[i] == '.') {
            i++;
            while (i < fmt.length() && fmt[i] >= '0' && fmt[i] <= '9') i++;
        }
        // Skip length modifiers
        while (i < fmt.length() && (fmt[i] == 'h' || fmt[i] == 'l' ||
               fmt[i] == 'L' || fmt[i] == 'z' || fmt[i] == 'j' || fmt[i] == 't')) i++;

        if (i >= fmt.length()) break;
        char spec = fmt[i];
        std::string spec_str = fmt.substr(spec_start, i - spec_start + 1);

        switch (spec) {
            case 'd': case 'i': {
                uint64_t arg = get_next_int_arg();
                snprintf(buf, sizeof(buf), spec_str.c_str(), (int64_t)arg);
                result += buf;
                break;
            }
            case 'u': {
                uint64_t arg = get_next_int_arg();
                snprintf(buf, sizeof(buf), spec_str.c_str(), (uint64_t)arg);
                result += buf;
                break;
            }
            case 'x': case 'X': {
                uint64_t arg = get_next_int_arg();
                snprintf(buf, sizeof(buf), spec_str.c_str(), (uint64_t)arg);
                result += buf;
                break;
            }
            case 'p': {
                uint64_t arg = get_next_int_arg();
                snprintf(buf, sizeof(buf), "%p", (void*)arg);
                result += buf;
                break;
            }
            case 's': {
                uint64_t arg = get_next_int_arg();
                std::string s = arg ? read_string(emu, arg) : "(null)";
                result += s;
                break;
            }
            case 'c': {
                uint64_t arg = get_next_int_arg();
                result += (char)arg;
                break;
            }
            case 'f': case 'F': case 'e': case 'E': case 'g': case 'G': {
                double d = get_next_fp_arg();
                snprintf(buf, sizeof(buf), spec_str.c_str(), d);
                result += buf;
                break;
            }
            default:
                result += spec_str;
                break;
        }
    }

    return result;
}

// Helper to format printf-style output by delegating to host snprintf
// fmt_reg_start: which X register contains the format string (0 for printf, 1 for fprintf)
static std::string do_printf_format(Emulator& emu, int fmt_reg_start) {
    uint64_t fmt_addr = get_reg(emu, UC_ARM64_REG_X0 + fmt_reg_start);
    std::string fmt = read_string(emu, fmt_addr);

    // Args start after format string register
    int arg_reg = fmt_reg_start + 1;  // X1 for printf, X2 for fprintf
    int fp_reg = 0;  // D0-D7 for floating point args

    std::string result;
    char buf[256];

    for (size_t i = 0; i < fmt.length(); i++) {
        if (fmt[i] != '%') {
            result += fmt[i];
            continue;
        }

        // Parse format specifier
        size_t spec_start = i;
        i++;  // skip '%'

        if (i >= fmt.length()) break;

        // Handle %%
        if (fmt[i] == '%') {
            result += '%';
            continue;
        }

        // Skip flags: -, +, space, #, 0
        while (i < fmt.length() && (fmt[i] == '-' || fmt[i] == '+' ||
               fmt[i] == ' ' || fmt[i] == '#' || fmt[i] == '0')) i++;

        // Skip width
        while (i < fmt.length() && fmt[i] >= '0' && fmt[i] <= '9') i++;

        // Skip precision
        if (i < fmt.length() && fmt[i] == '.') {
            i++;
            while (i < fmt.length() && fmt[i] >= '0' && fmt[i] <= '9') i++;
        }

        // Skip length modifiers: h, hh, l, ll, L, z, j, t
        while (i < fmt.length() && (fmt[i] == 'h' || fmt[i] == 'l' ||
               fmt[i] == 'L' || fmt[i] == 'z' || fmt[i] == 'j' || fmt[i] == 't')) i++;

        if (i >= fmt.length()) break;

        char spec = fmt[i];
        std::string spec_str = fmt.substr(spec_start, i - spec_start + 1);

        switch (spec) {
            case 'd': case 'i': {
                uint64_t arg = 0;
                if (arg_reg <= 7) {
                    arg = get_reg(emu, UC_ARM64_REG_X0 + arg_reg);
                    arg_reg++;
                }
                snprintf(buf, sizeof(buf), spec_str.c_str(), (int64_t)arg);
                result += buf;
                break;
            }
            case 'u': {
                uint64_t arg = 0;
                if (arg_reg <= 7) {
                    arg = get_reg(emu, UC_ARM64_REG_X0 + arg_reg);
                    arg_reg++;
                }
                snprintf(buf, sizeof(buf), spec_str.c_str(), (uint64_t)arg);
                result += buf;
                break;
            }
            case 'x': case 'X': {
                uint64_t arg = 0;
                if (arg_reg <= 7) {
                    arg = get_reg(emu, UC_ARM64_REG_X0 + arg_reg);
                    arg_reg++;
                }
                snprintf(buf, sizeof(buf), spec_str.c_str(), (uint64_t)arg);
                result += buf;
                break;
            }
            case 'p': {
                uint64_t arg = 0;
                if (arg_reg <= 7) {
                    arg = get_reg(emu, UC_ARM64_REG_X0 + arg_reg);
                    arg_reg++;
                }
                snprintf(buf, sizeof(buf), "%p", (void*)arg);
                result += buf;
                break;
            }
            case 's': {
                uint64_t arg = 0;
                if (arg_reg <= 7) {
                    arg = get_reg(emu, UC_ARM64_REG_X0 + arg_reg);
                    arg_reg++;
                }
                std::string s = arg ? read_string(emu, arg) : "(null)";
                result += s;
                break;
            }
            case 'c': {
                uint64_t arg = 0;
                if (arg_reg <= 7) {
                    arg = get_reg(emu, UC_ARM64_REG_X0 + arg_reg);
                    arg_reg++;
                }
                result += (char)arg;
                break;
            }
            case 'f': case 'F': case 'e': case 'E': case 'g': case 'G': {
                // ARM64: floating point args are passed in D0-D7 (SIMD registers)
                double d = 0.0;
                if (fp_reg <= 7) {
                    // Use get_dreg which properly handles 128-bit SIMD registers
                    d = get_dreg(emu, fp_reg);
                    fp_reg++;
                }
                snprintf(buf, sizeof(buf), spec_str.c_str(), d);
                result += buf;
                break;
            }
            default:
                result += spec_str;
                break;
        }
    }

    return result;
}

void register_hle_io(HleManager& hle) {
    // ========================================================================
    // Console output
    // ========================================================================

    hle.register_function("printf", [](Emulator& emu) {
        std::string output = do_printf_format(emu, 0);
        std::cout << output;
        std::cout.flush();
        set_reg(emu, UC_ARM64_REG_X0, output.length());
    });

    hle.register_function("puts", [](Emulator& emu) {
        uint64_t s = get_reg(emu, UC_ARM64_REG_X0);
        std::string str = read_string(emu, s);
        std::cout << str << std::endl;
        set_reg(emu, UC_ARM64_REG_X0, 1);
    });

    hle.register_function("putchar", [](Emulator& emu) {
        int c = get_reg(emu, UC_ARM64_REG_X0) & 0xFF;
        std::cout << static_cast<char>(c);
        set_reg(emu, UC_ARM64_REG_X0, c);
    });

    hle.register_function("fputs", [](Emulator& emu) {
        uint64_t s = get_reg(emu, UC_ARM64_REG_X0);
        std::string str = read_string(emu, s);
        std::cout << str;
        set_reg(emu, UC_ARM64_REG_X0, 1);
    });

    hle.register_function("fputc", [](Emulator& emu) {
        int c = get_reg(emu, UC_ARM64_REG_X0) & 0xFF;
        std::cout << static_cast<char>(c);
        set_reg(emu, UC_ARM64_REG_X0, c);
    });

    // ========================================================================
    // String formatting
    // ========================================================================
    
    hle.register_function("sprintf", [](Emulator& emu) {
        uint64_t buf = get_reg(emu, UC_ARM64_REG_X0);
        // Format string is in X1, args start at X2
        // We need a custom formatter that starts at X1
        uint64_t fmt_addr = get_reg(emu, UC_ARM64_REG_X1);
        std::string fmt = read_string(emu, fmt_addr);

        // Parse format and build output
        int arg_reg = 2;  // Args start at X2
        std::string result;
        char tmp[256];

        for (size_t i = 0; i < fmt.length(); i++) {
            if (fmt[i] != '%') {
                result += fmt[i];
                continue;
            }

            size_t spec_start = i;
            i++;
            if (i >= fmt.length()) break;

            if (fmt[i] == '%') {
                result += '%';
                continue;
            }

            // Skip flags
            while (i < fmt.length() && (fmt[i] == '-' || fmt[i] == '+' ||
                   fmt[i] == ' ' || fmt[i] == '#' || fmt[i] == '0')) i++;
            // Skip width
            while (i < fmt.length() && fmt[i] >= '0' && fmt[i] <= '9') i++;
            // Skip precision
            if (i < fmt.length() && fmt[i] == '.') {
                i++;
                while (i < fmt.length() && fmt[i] >= '0' && fmt[i] <= '9') i++;
            }
            // Skip length modifiers
            while (i < fmt.length() && (fmt[i] == 'h' || fmt[i] == 'l' ||
                   fmt[i] == 'L' || fmt[i] == 'z' || fmt[i] == 'j' || fmt[i] == 't')) i++;

            if (i >= fmt.length()) break;

            char spec = fmt[i];
            std::string spec_str = fmt.substr(spec_start, i - spec_start + 1);

            uint64_t arg = 0;
            if (arg_reg <= 7) {
                arg = get_reg(emu, UC_ARM64_REG_X0 + arg_reg);
                arg_reg++;
            }

            switch (spec) {
                case 'd': case 'i':
                    snprintf(tmp, sizeof(tmp), spec_str.c_str(), (int64_t)arg);
                    result += tmp;
                    break;
                case 'u':
                    snprintf(tmp, sizeof(tmp), spec_str.c_str(), (uint64_t)arg);
                    result += tmp;
                    break;
                case 'x': case 'X':
                    snprintf(tmp, sizeof(tmp), spec_str.c_str(), (uint64_t)arg);
                    result += tmp;
                    break;
                case 'p':
                    snprintf(tmp, sizeof(tmp), "%p", (void*)arg);
                    result += tmp;
                    break;
                case 's': {
                    std::string s = arg ? read_string(emu, arg) : "(null)";
                    result += s;
                    break;
                }
                case 'c':
                    result += (char)arg;
                    break;
                case 'f': case 'F': case 'e': case 'E': case 'g': case 'G': {
                    double d;
                    memcpy(&d, &arg, sizeof(d));
                    snprintf(tmp, sizeof(tmp), spec_str.c_str(), d);
                    result += tmp;
                    break;
                }
                default:
                    result += spec_str;
                    break;
            }
        }

        emu.mem_write(buf, result.c_str(), result.length() + 1);
        set_reg(emu, UC_ARM64_REG_X0, result.length());
    });

    hle.register_function("snprintf", [](Emulator& emu) {
        uint64_t buf = get_reg(emu, UC_ARM64_REG_X0);
        size_t size = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t fmt_addr = get_reg(emu, UC_ARM64_REG_X2);
        std::string fmt = read_string(emu, fmt_addr);

        // Parse format and build output
        int arg_reg = 3;  // Args start at X3
        std::string result;
        char tmp[256];

        for (size_t i = 0; i < fmt.length(); i++) {
            if (fmt[i] != '%') {
                result += fmt[i];
                continue;
            }

            size_t spec_start = i;
            i++;
            if (i >= fmt.length()) break;

            if (fmt[i] == '%') {
                result += '%';
                continue;
            }

            // Skip flags
            while (i < fmt.length() && (fmt[i] == '-' || fmt[i] == '+' ||
                   fmt[i] == ' ' || fmt[i] == '#' || fmt[i] == '0')) i++;
            // Skip width
            while (i < fmt.length() && fmt[i] >= '0' && fmt[i] <= '9') i++;
            // Skip precision
            if (i < fmt.length() && fmt[i] == '.') {
                i++;
                while (i < fmt.length() && fmt[i] >= '0' && fmt[i] <= '9') i++;
            }
            // Skip length modifiers
            while (i < fmt.length() && (fmt[i] == 'h' || fmt[i] == 'l' ||
                   fmt[i] == 'L' || fmt[i] == 'z' || fmt[i] == 'j' || fmt[i] == 't')) i++;

            if (i >= fmt.length()) break;

            char spec = fmt[i];
            std::string spec_str = fmt.substr(spec_start, i - spec_start + 1);

            uint64_t arg = 0;
            if (arg_reg <= 7) {
                arg = get_reg(emu, UC_ARM64_REG_X0 + arg_reg);
                arg_reg++;
            }

            switch (spec) {
                case 'd': case 'i':
                    snprintf(tmp, sizeof(tmp), spec_str.c_str(), (int64_t)arg);
                    result += tmp;
                    break;
                case 'u':
                    snprintf(tmp, sizeof(tmp), spec_str.c_str(), (uint64_t)arg);
                    result += tmp;
                    break;
                case 'x': case 'X':
                    snprintf(tmp, sizeof(tmp), spec_str.c_str(), (uint64_t)arg);
                    result += tmp;
                    break;
                case 'p':
                    snprintf(tmp, sizeof(tmp), "%p", (void*)arg);
                    result += tmp;
                    break;
                case 's': {
                    std::string s = arg ? read_string(emu, arg) : "(null)";
                    result += s;
                    break;
                }
                case 'c':
                    result += (char)arg;
                    break;
                case 'f': case 'F': case 'e': case 'E': case 'g': case 'G': {
                    double d;
                    memcpy(&d, &arg, sizeof(d));
                    snprintf(tmp, sizeof(tmp), spec_str.c_str(), d);
                    result += tmp;
                    break;
                }
                default:
                    result += spec_str;
                    break;
            }
        }

        size_t len = std::min(result.length(), size > 0 ? size - 1 : 0);
        if (size > 0) {
            emu.mem_write(buf, result.c_str(), len);
            char null = 0;
            emu.mem_write(buf + len, &null, 1);
        }
        set_reg(emu, UC_ARM64_REG_X0, result.length());
    });

    hle.register_function("__vsnprintf_chk", [](Emulator& emu) {
        uint64_t buf = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t size = get_reg(emu, UC_ARM64_REG_X1);
        // Skip flag and real_size (X2, X3)
        uint64_t fmt_addr = get_reg(emu, UC_ARM64_REG_X4);
        uint64_t va_list_addr = get_reg(emu, UC_ARM64_REG_X5);
        std::string fmt = read_string(emu, fmt_addr);
        std::string result = do_vprintf_format(emu, fmt, va_list_addr);
        size_t len = std::min(result.length(), size > 0 ? (size_t)(size - 1) : 0);
        if (buf && size > 0) {
            emu.mem_write(buf, result.c_str(), len);
            char null = 0;
            emu.mem_write(buf + len, &null, 1);
        }
        set_reg(emu, UC_ARM64_REG_X0, result.length());
    });

    hle.register_function("sscanf", [](Emulator& emu) {
        uint64_t str_addr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t fmt_addr = get_reg(emu, UC_ARM64_REG_X1);
        std::string str = read_string(emu, str_addr);
        std::string fmt = read_string(emu, fmt_addr);

        int arg_reg = 2;  // Args start at X2
        int matched = 0;
        size_t str_pos = 0;

        for (size_t i = 0; i < fmt.length() && str_pos < str.length(); i++) {
            if (fmt[i] != '%') {
                // Match literal character
                if (isspace(fmt[i])) {
                    while (str_pos < str.length() && isspace(str[str_pos])) str_pos++;
                } else if (str_pos < str.length() && str[str_pos] == fmt[i]) {
                    str_pos++;
                } else {
                    break;  // Mismatch
                }
                continue;
            }

            i++;  // Skip '%'
            if (i >= fmt.length()) break;

            if (fmt[i] == '%') {
                if (str_pos < str.length() && str[str_pos] == '%') str_pos++;
                else break;
                continue;
            }

            // Skip width
            while (i < fmt.length() && fmt[i] >= '0' && fmt[i] <= '9') i++;

            // Handle scanset [...]
            bool is_scanset = false;
            bool scanset_negate = false;
            std::string scanset_chars;
            if (i < fmt.length() && fmt[i] == '[') {
                is_scanset = true;
                i++;
                if (i < fmt.length() && fmt[i] == '^') {
                    scanset_negate = true;
                    i++;
                }
                // Handle ] as first char (literal ])
                if (i < fmt.length() && fmt[i] == ']') {
                    scanset_chars += ']';
                    i++;
                }
                while (i < fmt.length() && fmt[i] != ']') {
                    // Handle ranges like a-z
                    if (i + 2 < fmt.length() && fmt[i + 1] == '-' && fmt[i + 2] != ']') {
                        char start = fmt[i];
                        char end = fmt[i + 2];
                        for (char c = start; c <= end; c++) {
                            scanset_chars += c;
                        }
                        i += 3;
                    } else {
                        scanset_chars += fmt[i];
                        i++;
                    }
                }
                // Skip past the closing ']'
                if (i < fmt.length() && fmt[i] == ']') {
                    i++;
                }
            }

            if (i > fmt.length()) break;

            // For scanset, spec is '[', otherwise it's the current character
            char spec = is_scanset ? '[' : (i < fmt.length() ? fmt[i] : 0);
            uint64_t arg_ptr = 0;
            if (arg_reg <= 7) {
                arg_ptr = get_reg(emu, UC_ARM64_REG_X0 + arg_reg);
                arg_reg++;
            }

            // Skip whitespace for most specifiers
            if (spec != 'c' && spec != '[') {
                while (str_pos < str.length() && isspace(str[str_pos])) str_pos++;
            }

            if (str_pos >= str.length()) break;

            switch (spec) {
                case 'd': case 'i': {
                    char* end;
                    long val = strtol(str.c_str() + str_pos, &end, 10);
                    if (end == str.c_str() + str_pos) break;  // No conversion
                    int32_t ival = (int32_t)val;
                    emu.mem_write(arg_ptr, &ival, sizeof(ival));
                    str_pos = end - str.c_str();
                    matched++;
                    break;
                }
                case 'u': {
                    char* end;
                    unsigned long val = strtoul(str.c_str() + str_pos, &end, 10);
                    if (end == str.c_str() + str_pos) break;
                    uint32_t uval = (uint32_t)val;
                    emu.mem_write(arg_ptr, &uval, sizeof(uval));
                    str_pos = end - str.c_str();
                    matched++;
                    break;
                }
                case 'x': case 'X': {
                    char* end;
                    unsigned long val = strtoul(str.c_str() + str_pos, &end, 16);
                    if (end == str.c_str() + str_pos) break;
                    uint32_t uval = (uint32_t)val;
                    emu.mem_write(arg_ptr, &uval, sizeof(uval));
                    str_pos = end - str.c_str();
                    matched++;
                    break;
                }
                case 'f': case 'e': case 'g': {
                    char* end;
                    float val = strtof(str.c_str() + str_pos, &end);
                    if (end == str.c_str() + str_pos) break;
                    emu.mem_write(arg_ptr, &val, sizeof(val));
                    str_pos = end - str.c_str();
                    matched++;
                    break;
                }
                case 'l': {
                    // Check for lf (double)
                    if (i + 1 < fmt.length() && fmt[i + 1] == 'f') {
                        i++;
                        char* end;
                        double val = strtod(str.c_str() + str_pos, &end);
                        if (end == str.c_str() + str_pos) break;
                        emu.mem_write(arg_ptr, &val, sizeof(val));
                        str_pos = end - str.c_str();
                        matched++;
                    }
                    break;
                }
                case 's': {
                    std::string word;
                    while (str_pos < str.length() && !isspace(str[str_pos])) {
                        word += str[str_pos++];
                    }
                    if (!word.empty()) {
                        emu.mem_write(arg_ptr, word.c_str(), word.length() + 1);
                        matched++;
                    }
                    break;
                }
                case 'c': {
                    char c = str[str_pos++];
                    emu.mem_write(arg_ptr, &c, 1);
                    matched++;
                    break;
                }
                case '[': {
                    // Scanset already parsed
                    std::string word;
                    while (str_pos < str.length()) {
                        bool in_set = scanset_chars.find(str[str_pos]) != std::string::npos;
                        // If negated, match chars NOT in set
                        if (scanset_negate) in_set = !in_set;
                        if (in_set) {
                            word += str[str_pos++];
                        } else {
                            break;
                        }
                    }
                    if (!word.empty()) {
                        emu.mem_write(arg_ptr, word.c_str(), word.length() + 1);
                        matched++;
                    }
                    break;
                }
                default:
                    break;
            }
        }

        set_reg(emu, UC_ARM64_REG_X0, matched);
    });

    hle.register_function("fprintf", [](Emulator& emu) {
        // X0 = FILE*, X1 = format, X2+ = args
        int fd = get_reg(emu, UC_ARM64_REG_X0);
        std::string output = do_printf_format(emu, 1);

        // Check for stdout/stderr (fd 1 or 2) or our file handles
        if (fd == 1) {
            std::cout << output;
            std::cout.flush();
        } else if (fd == 2) {
            EMU_LOG << output;
            std::cerr.flush();
        } else {
            auto it = g_file_map.find(fd);
            if (it != g_file_map.end()) {
                fputs(output.c_str(), it->second);
            }
        }
        set_reg(emu, UC_ARM64_REG_X0, output.length());
    });

    hle.register_function("perror", [](Emulator& emu) {
        uint64_t s = get_reg(emu, UC_ARM64_REG_X0);
        std::string str = s ? read_string(emu, s) : "";
        EMU_LOG << str << ": error" << std::endl;
    });

    hle.register_function("vprintf", [](Emulator& emu) {
        uint64_t fmt_addr = get_reg(emu, UC_ARM64_REG_X0);
        std::string fmt = read_string(emu, fmt_addr);
        std::cout << "[vprintf] " << fmt;
        set_reg(emu, UC_ARM64_REG_X0, fmt.length());
    });

    hle.register_function("vfprintf", [](Emulator& emu) {
        uint64_t fmt_addr = get_reg(emu, UC_ARM64_REG_X1);
        std::string fmt = read_string(emu, fmt_addr);
        std::cout << "[vfprintf] " << fmt;
        set_reg(emu, UC_ARM64_REG_X0, fmt.length());
    });

    hle.register_function("vsprintf", [](Emulator& emu) {
        uint64_t buf = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t fmt_addr = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t va_list_addr = get_reg(emu, UC_ARM64_REG_X2);
        std::string fmt = read_string(emu, fmt_addr);
        std::string result = do_vprintf_format(emu, fmt, va_list_addr);
        emu.mem_write(buf, result.c_str(), result.length() + 1);
        set_reg(emu, UC_ARM64_REG_X0, result.length());
    });

    // __vsprintf_chk - checked version of vsprintf
    hle.register_function("__vsprintf_chk", [](Emulator& emu) {
        uint64_t buf = get_reg(emu, UC_ARM64_REG_X0);
        // int flag = get_reg(emu, UC_ARM64_REG_X1);  // ignored
        size_t slen = get_reg(emu, UC_ARM64_REG_X2);  // buffer size limit
        uint64_t fmt_addr = get_reg(emu, UC_ARM64_REG_X3);
        uint64_t va_list_addr = get_reg(emu, UC_ARM64_REG_X4);
        std::string fmt = read_string(emu, fmt_addr);
        std::string result = do_vprintf_format(emu, fmt, va_list_addr);

        // Respect the buffer size limit if provided
        if (slen > 0 && result.length() >= slen) {
            EMU_LOG << "[HLE] __vsprintf_chk: WARNING: output truncated from "
                      << result.length() << " to " << (slen - 1) << " bytes" << std::endl;
            result = result.substr(0, slen - 1);
        }

        if (buf) {
            emu.mem_write(buf, result.c_str(), result.length() + 1);
        }
        set_reg(emu, UC_ARM64_REG_X0, result.length());
    });

    hle.register_function("vsnprintf", [](Emulator& emu) {
        uint64_t buf = get_reg(emu, UC_ARM64_REG_X0);
        size_t size = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t fmt_addr = get_reg(emu, UC_ARM64_REG_X2);
        uint64_t va_list_addr = get_reg(emu, UC_ARM64_REG_X3);
        std::string fmt = read_string(emu, fmt_addr);
        std::string result = do_vprintf_format(emu, fmt, va_list_addr);
        size_t len = std::min(result.length(), size > 0 ? size - 1 : 0);
        if (buf && size > 0) {
            emu.mem_write(buf, result.c_str(), len);
            char null = 0;
            emu.mem_write(buf + len, &null, 1);
        }
        set_reg(emu, UC_ARM64_REG_X0, result.length());
    });

    hle.register_function("vasprintf", [](Emulator& emu) {
        uint64_t strp = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t fmt_addr = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t va_list_addr = get_reg(emu, UC_ARM64_REG_X2);
        std::string fmt = read_string(emu, fmt_addr);
        std::string result = do_vprintf_format(emu, fmt, va_list_addr);

        uint64_t ptr = emu.memory().heap().allocate(result.length() + 1, 8);
        emu.mem_write(ptr, result.c_str(), result.length() + 1);
        emu.mem_write(strp, &ptr, sizeof(ptr));
        set_reg(emu, UC_ARM64_REG_X0, result.length());
    });

    hle.register_function("asprintf", [](Emulator& emu) {
        uint64_t strp = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t fmt_addr = get_reg(emu, UC_ARM64_REG_X1);
        std::string fmt = read_string(emu, fmt_addr);

        uint64_t ptr = emu.memory().heap().allocate(fmt.length() + 1, 8);
        emu.mem_write(ptr, fmt.c_str(), fmt.length() + 1);
        emu.mem_write(strp, &ptr, sizeof(ptr));
        set_reg(emu, UC_ARM64_REG_X0, fmt.length());
    });

    hle.register_function("dprintf", [](Emulator& emu) {
        // int fd = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t fmt_addr = get_reg(emu, UC_ARM64_REG_X1);
        std::string fmt = read_string(emu, fmt_addr);
        std::cout << "[dprintf] " << fmt;
        set_reg(emu, UC_ARM64_REG_X0, fmt.length());
    });

    hle.register_function("vdprintf", [](Emulator& emu) {
        uint64_t fmt_addr = get_reg(emu, UC_ARM64_REG_X1);
        std::string fmt = read_string(emu, fmt_addr);
        std::cout << "[vdprintf] " << fmt;
        set_reg(emu, UC_ARM64_REG_X0, fmt.length());
    });

    hle.register_function("getchar", [](Emulator& emu) {
        int c = getchar();
        set_reg(emu, UC_ARM64_REG_X0, c);
    });

    hle.register_function("getc_unlocked", [](Emulator& emu) {
        // Simplified: return EOF
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
    });

    hle.register_function("putc_unlocked", [](Emulator& emu) {
        int c = get_reg(emu, UC_ARM64_REG_X0);
        putchar(c);
        set_reg(emu, UC_ARM64_REG_X0, c);
    });

    hle.register_function("fflush_unlocked", [](Emulator& emu) {
        fflush(stdout);
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("__isoc99_sscanf", [](Emulator& emu) {
        // Same as sscanf - delegate to the same implementation
        uint64_t str_addr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t fmt_addr = get_reg(emu, UC_ARM64_REG_X1);
        std::string str = read_string(emu, str_addr);
        std::string fmt = read_string(emu, fmt_addr);

        int arg_reg = 2;
        int matched = 0;
        size_t str_pos = 0;

        for (size_t i = 0; i < fmt.length() && str_pos < str.length(); i++) {
            if (fmt[i] != '%') {
                if (isspace(fmt[i])) {
                    while (str_pos < str.length() && isspace(str[str_pos])) str_pos++;
                } else if (str_pos < str.length() && str[str_pos] == fmt[i]) {
                    str_pos++;
                } else {
                    break;
                }
                continue;
            }

            i++;
            if (i >= fmt.length()) break;

            if (fmt[i] == '%') {
                if (str_pos < str.length() && str[str_pos] == '%') str_pos++;
                else break;
                continue;
            }

            while (i < fmt.length() && fmt[i] >= '0' && fmt[i] <= '9') i++;

            bool is_scanset = false;
            std::string scanset_chars;
            if (i < fmt.length() && fmt[i] == '[') {
                is_scanset = true;
                i++;
                if (i < fmt.length() && fmt[i] == '^') i++;
                while (i < fmt.length() && fmt[i] != ']') {
                    scanset_chars += fmt[i];
                    i++;
                }
            }

            if (i >= fmt.length()) break;

            char spec = fmt[i];
            uint64_t arg_ptr = 0;
            if (arg_reg <= 7) {
                arg_ptr = get_reg(emu, UC_ARM64_REG_X0 + arg_reg);
                arg_reg++;
            }

            if (spec != 'c' && spec != '[') {
                while (str_pos < str.length() && isspace(str[str_pos])) str_pos++;
            }

            if (str_pos >= str.length()) break;

            switch (spec) {
                case 'd': case 'i': {
                    char* end;
                    long val = strtol(str.c_str() + str_pos, &end, 10);
                    if (end == str.c_str() + str_pos) break;
                    int32_t ival = (int32_t)val;
                    emu.mem_write(arg_ptr, &ival, sizeof(ival));
                    str_pos = end - str.c_str();
                    matched++;
                    break;
                }
                case 'x': case 'X': {
                    char* end;
                    unsigned long val = strtoul(str.c_str() + str_pos, &end, 16);
                    if (end == str.c_str() + str_pos) break;
                    uint32_t uval = (uint32_t)val;
                    emu.mem_write(arg_ptr, &uval, sizeof(uval));
                    str_pos = end - str.c_str();
                    matched++;
                    break;
                }
                case 'f': {
                    char* end;
                    float val = strtof(str.c_str() + str_pos, &end);
                    if (end == str.c_str() + str_pos) break;
                    emu.mem_write(arg_ptr, &val, sizeof(val));
                    str_pos = end - str.c_str();
                    matched++;
                    break;
                }
                case 's': {
                    std::string word;
                    while (str_pos < str.length() && !isspace(str[str_pos])) {
                        word += str[str_pos++];
                    }
                    if (!word.empty()) {
                        emu.mem_write(arg_ptr, word.c_str(), word.length() + 1);
                        matched++;
                    }
                    break;
                }
                case '[': {
                    std::string word;
                    while (str_pos < str.length()) {
                        bool in_set = scanset_chars.find(str[str_pos]) != std::string::npos;
                        if (in_set) {
                            word += str[str_pos++];
                        } else {
                            break;
                        }
                    }
                    if (!word.empty()) {
                        emu.mem_write(arg_ptr, word.c_str(), word.length() + 1);
                        matched++;
                    }
                    break;
                }
                default:
                    break;
            }
        }

        set_reg(emu, UC_ARM64_REG_X0, matched);
    });

    hle.register_function("__isoc99_fscanf", [](Emulator& emu) {
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("__isoc99_scanf", [](Emulator& emu) {
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("scanf", [](Emulator& emu) {
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("fscanf", [](Emulator& emu) {
        int fd = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t fmt_addr = get_reg(emu, UC_ARM64_REG_X1);

        FILE* file = nullptr;
        auto it = g_file_map.find(fd);
        if (it != g_file_map.end()) {
            file = it->second;
        }

        if (!file) {
            set_reg(emu, UC_ARM64_REG_X0, -1);
            return;
        }

        std::string fmt = read_string(emu, fmt_addr);

        // Read a line from the file to parse
        char line[4096];
        if (!fgets(line, sizeof(line), file)) {
            set_reg(emu, UC_ARM64_REG_X0, -1);
            return;
        }
        std::string str = line;

        int arg_reg = 2;  // Args start at X2
        int matched = 0;
        size_t str_pos = 0;

        for (size_t i = 0; i < fmt.length() && str_pos < str.length(); i++) {
            if (fmt[i] != '%') {
                if (isspace(fmt[i])) {
                    while (str_pos < str.length() && isspace(str[str_pos])) str_pos++;
                } else if (str_pos < str.length() && str[str_pos] == fmt[i]) {
                    str_pos++;
                } else {
                    break;
                }
                continue;
            }

            i++;
            if (i >= fmt.length()) break;

            if (fmt[i] == '%') {
                if (str_pos < str.length() && str[str_pos] == '%') str_pos++;
                else break;
                continue;
            }

            while (i < fmt.length() && fmt[i] >= '0' && fmt[i] <= '9') i++;

            if (i >= fmt.length()) break;

            char spec = fmt[i];
            uint64_t arg_ptr = 0;
            if (arg_reg <= 7) {
                arg_ptr = get_reg(emu, UC_ARM64_REG_X0 + arg_reg);
                arg_reg++;
            }

            if (spec != 'c') {
                while (str_pos < str.length() && isspace(str[str_pos])) str_pos++;
            }

            if (str_pos >= str.length()) break;

            switch (spec) {
                case 'd': case 'i': {
                    char* end;
                    long val = strtol(str.c_str() + str_pos, &end, 10);
                    if (end == str.c_str() + str_pos) break;
                    int32_t ival = (int32_t)val;
                    emu.mem_write(arg_ptr, &ival, sizeof(ival));
                    str_pos = end - str.c_str();
                    matched++;
                    break;
                }
                case 'f': case 'e': case 'g': {
                    char* end;
                    float val = strtof(str.c_str() + str_pos, &end);
                    if (end == str.c_str() + str_pos) break;
                    emu.mem_write(arg_ptr, &val, sizeof(val));
                    str_pos = end - str.c_str();
                    matched++;
                    break;
                }
                case 'l': {
                    if (i + 1 < fmt.length() && fmt[i + 1] == 'f') {
                        i++;
                        char* end;
                        double val = strtod(str.c_str() + str_pos, &end);
                        if (end == str.c_str() + str_pos) break;
                        emu.mem_write(arg_ptr, &val, sizeof(val));
                        str_pos = end - str.c_str();
                        matched++;
                    }
                    break;
                }
                case 's': {
                    std::string word;
                    while (str_pos < str.length() && !isspace(str[str_pos])) {
                        word += str[str_pos++];
                    }
                    if (!word.empty()) {
                        emu.mem_write(arg_ptr, word.c_str(), word.length() + 1);
                        matched++;
                    }
                    break;
                }
                case 'c': {
                    char c = str[str_pos++];
                    emu.mem_write(arg_ptr, &c, 1);
                    matched++;
                    break;
                }
                default:
                    break;
            }
        }

        set_reg(emu, UC_ARM64_REG_X0, matched);
    });

    hle.register_function("vsscanf", [](Emulator& emu) {
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("vfscanf", [](Emulator& emu) {
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("vscanf", [](Emulator& emu) {
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });
}

} // namespace cross_shim
