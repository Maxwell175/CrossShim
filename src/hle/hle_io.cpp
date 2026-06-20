/**
 * HLE I/O Functions
 * printf, fprintf, sprintf, snprintf, sscanf
 * fopen, fclose, fread, fwrite, fseek, ftell, fgets, fputs, puts
 * open, close, read, write, lseek
 */

#include "debug_log.h"
#include "hle_format.h"
#include "hle_manager.h"
#include "hle_scan.h"
#include "hle_stdio_state.h"
#include "cross_shim.h"
#include "memory_manager.h"
#include "emu_compat.h"
#include <cstring>
#include <cstdio>
#include <cstdarg>
#include <mutex>
#include <vector>
#include <unordered_map>
#include <iostream>
#include <termios.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <pty.h>

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
extern std::unordered_map<uint64_t, FILE*> g_file_map;
extern int g_next_fd;
// Guards the FILE*/fd table family (defined in hle_file.cpp). Any handler here that
// touches g_file_map must hold this, since file handlers run concurrently across guest
// threads with no other serialization.
extern std::recursive_mutex g_file_tables_mutex;

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
            case 'u': case 'o': {
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
            case 'f': case 'F': case 'e': case 'E': case 'g': case 'G': case 'a': case 'A': {
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
            case 'u': case 'o': {
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
            case 'f': case 'F': case 'e': case 'E': case 'g': case 'G': case 'a': case 'A': {
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
        uint64_t fmt_addr = get_reg(emu, UC_ARM64_REG_X0);
        HleFormatResult formatted = hle_format_from_regs(emu, fmt_addr, 1, false);
        if (!formatted.ok) {
            hle_set_errno(emu, formatted.error);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }
        std::cout << formatted.output;
        std::cout.flush();
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(formatted.result));
    });

    hle.register_function("puts", [](Emulator& emu) {
        uint64_t s = get_reg(emu, UC_ARM64_REG_X0);
        std::string str = read_string(emu, s);
        errno = 0;
        if (std::fputs(str.c_str(), stdout) == EOF || std::fputc('\n', stdout) == EOF) {
            hle_set_errno(emu, errno);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(EOF));
            return;
        }
        std::fflush(stdout);
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("putchar", [](Emulator& emu) {
        int c = get_reg(emu, UC_ARM64_REG_X0) & 0xFF;
        errno = 0;
        int result = std::fputc(c, stdout);
        if (result == EOF) {
            hle_set_errno(emu, errno);
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
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
        uint64_t fmt_addr = get_reg(emu, UC_ARM64_REG_X1);
        HleFormatResult formatted = hle_format_from_regs(emu, fmt_addr, 2, false);
        if (!formatted.ok) {
            hle_set_errno(emu, formatted.error);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }
        emu.mem_write(buf, formatted.output.c_str(), formatted.output.length() + 1);
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(formatted.result));
    });

    hle.register_function("snprintf", [](Emulator& emu) {
        uint64_t buf = get_reg(emu, UC_ARM64_REG_X0);
        size_t size = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t fmt_addr = get_reg(emu, UC_ARM64_REG_X2);
        HleFormatResult formatted = hle_format_from_regs(emu, fmt_addr, 3, false);
        if (!formatted.ok) {
            hle_set_errno(emu, formatted.error);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }
        size_t len = std::min(formatted.output.length(), size > 0 ? size - 1 : 0);
        if (size > 0) {
            emu.mem_write(buf, formatted.output.c_str(), len);
            char null = 0;
            emu.mem_write(buf + len, &null, 1);
        }
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(formatted.result));
    });

    hle.register_function("__vsnprintf_chk", [](Emulator& emu) {
        uint64_t buf = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t size = get_reg(emu, UC_ARM64_REG_X1);
        // Skip flag and real_size (X2, X3)
        uint64_t fmt_addr = get_reg(emu, UC_ARM64_REG_X4);
        uint64_t va_list_addr = get_reg(emu, UC_ARM64_REG_X5);
        HleFormatResult formatted = hle_format_from_va_list(emu, fmt_addr, va_list_addr, false);
        if (!formatted.ok) {
            hle_set_errno(emu, formatted.error);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }
        size_t len = std::min(formatted.output.length(), size > 0 ? (size_t)(size - 1) : 0);
        if (buf && size > 0) {
            emu.mem_write(buf, formatted.output.c_str(), len);
            char null = 0;
            emu.mem_write(buf + len, &null, 1);
        }
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(formatted.result));
    });

    hle.register_function("sscanf", [](Emulator& emu) {
        HleScanResult scanned = hle_scan_from_regs(
            emu,
            get_reg(emu, UC_ARM64_REG_X0),
            get_reg(emu, UC_ARM64_REG_X1),
            2,
            false);
        if (!scanned.ok) {
            hle_set_errno(emu, scanned.error);
        }
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(static_cast<int64_t>(scanned.result)));
    });

    hle.register_function("fprintf", [](Emulator& emu) {
        // X0 = FILE*, X1 = format, X2+ = args
        uint64_t stream = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t fmt_addr = get_reg(emu, UC_ARM64_REG_X1);
        HleFormatResult formatted = hle_format_from_regs(emu, fmt_addr, 2, false);
        if (!formatted.ok) {
            hle_set_errno(emu, formatted.error);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(EOF));
            return;
        }

        FILE* fp = hle_resolve_guest_file(emu, stream);
        if (fp == nullptr) {
            hle_set_errno(emu, EBADF);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(EOF));
            return;
        }

        errno = 0;
        if (std::fputs(formatted.output.c_str(), fp) == EOF) {
            hle_set_errno(emu, errno);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(EOF));
            return;
        }
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(formatted.result));
    });

    hle.register_function("perror", [](Emulator& emu) {
        uint64_t s = get_reg(emu, UC_ARM64_REG_X0);
        std::string str = s ? read_string(emu, s) : "";
        int err = hle_get_errno(emu);
        const char* message = std::strerror(err);
        if (str.empty()) {
            std::fprintf(stderr, "%s\n", message);
        } else {
            std::fprintf(stderr, "%s: %s\n", str.c_str(), message);
        }
        std::fflush(stderr);
    });

    hle.register_function("vprintf", [](Emulator& emu) {
        uint64_t fmt_addr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t va_list_addr = get_reg(emu, UC_ARM64_REG_X1);
        HleFormatResult formatted = hle_format_from_va_list(emu, fmt_addr, va_list_addr, false);
        if (!formatted.ok) {
            hle_set_errno(emu, formatted.error);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }
        std::cout << formatted.output;
        std::cout.flush();
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(formatted.result));
    });

    hle.register_function("vfprintf", [](Emulator& emu) {
        uint64_t stream = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t fmt_addr = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t va_list_addr = get_reg(emu, UC_ARM64_REG_X2);
        HleFormatResult formatted = hle_format_from_va_list(emu, fmt_addr, va_list_addr, false);
        if (!formatted.ok) {
            hle_set_errno(emu, formatted.error);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(EOF));
            return;
        }

        FILE* fp = hle_resolve_guest_file(emu, stream);
        if (fp == nullptr) {
            hle_set_errno(emu, EBADF);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(EOF));
            return;
        }

        errno = 0;
        if (std::fputs(formatted.output.c_str(), fp) == EOF) {
            hle_set_errno(emu, errno);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(EOF));
            return;
        }
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(formatted.result));
    });

    hle.register_function("vsprintf", [](Emulator& emu) {
        uint64_t buf = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t fmt_addr = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t va_list_addr = get_reg(emu, UC_ARM64_REG_X2);
        HleFormatResult formatted = hle_format_from_va_list(emu, fmt_addr, va_list_addr, false);
        if (!formatted.ok) {
            hle_set_errno(emu, formatted.error);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }
        emu.mem_write(buf, formatted.output.c_str(), formatted.output.length() + 1);
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(formatted.result));
    });

    // __vsprintf_chk - checked version of vsprintf
    hle.register_function("__vsprintf_chk", [](Emulator& emu) {
        uint64_t buf = get_reg(emu, UC_ARM64_REG_X0);
        // int flag = get_reg(emu, UC_ARM64_REG_X1);  // ignored
        size_t slen = get_reg(emu, UC_ARM64_REG_X2);  // buffer size limit
        uint64_t fmt_addr = get_reg(emu, UC_ARM64_REG_X3);
        uint64_t va_list_addr = get_reg(emu, UC_ARM64_REG_X4);
        HleFormatResult formatted = hle_format_from_va_list(emu, fmt_addr, va_list_addr, false);
        if (!formatted.ok) {
            hle_set_errno(emu, formatted.error);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        // Respect the buffer size limit if provided
        if (slen > 0 && formatted.output.length() >= slen) {
            EMU_LOG << "[HLE] __vsprintf_chk: WARNING: output truncated from "
                      << formatted.output.length() << " to " << (slen - 1) << " bytes" << std::endl;
            formatted.output = formatted.output.substr(0, slen - 1);
        }

        if (buf) {
            emu.mem_write(buf, formatted.output.c_str(), formatted.output.length() + 1);
        }
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(formatted.result));
    });

    hle.register_function("vsnprintf", [](Emulator& emu) {
        uint64_t buf = get_reg(emu, UC_ARM64_REG_X0);
        size_t size = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t fmt_addr = get_reg(emu, UC_ARM64_REG_X2);
        uint64_t va_list_addr = get_reg(emu, UC_ARM64_REG_X3);
        HleFormatResult formatted = hle_format_from_va_list(emu, fmt_addr, va_list_addr, false);
        if (!formatted.ok) {
            hle_set_errno(emu, formatted.error);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }
        size_t len = std::min(formatted.output.length(), size > 0 ? size - 1 : 0);
        if (buf && size > 0) {
            emu.mem_write(buf, formatted.output.c_str(), len);
            char null = 0;
            emu.mem_write(buf + len, &null, 1);
        }
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(formatted.result));
    });

    hle.register_function("vasprintf", [](Emulator& emu) {
        uint64_t strp = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t fmt_addr = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t va_list_addr = get_reg(emu, UC_ARM64_REG_X2);
        HleFormatResult formatted = hle_format_from_va_list(emu, fmt_addr, va_list_addr, false);
        if (!formatted.ok) {
            hle_set_errno(emu, formatted.error);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        uint64_t ptr = emu.memory().heap().allocate(formatted.output.length() + 1, 8);
        emu.mem_write(ptr, formatted.output.c_str(), formatted.output.length() + 1);
        emu.mem_write(strp, &ptr, sizeof(ptr));
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(formatted.result));
    });

    hle.register_function("asprintf", [](Emulator& emu) {
        uint64_t strp = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t fmt_addr = get_reg(emu, UC_ARM64_REG_X1);
        HleFormatResult formatted = hle_format_from_regs(emu, fmt_addr, 2, false);
        if (!formatted.ok) {
            hle_set_errno(emu, formatted.error);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }
        uint64_t ptr = emu.memory().heap().allocate(formatted.output.length() + 1, 8);
        emu.mem_write(ptr, formatted.output.c_str(), formatted.output.length() + 1);
        emu.mem_write(strp, &ptr, sizeof(ptr));
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(formatted.result));
    });

    hle.register_function("dprintf", [](Emulator& emu) {
        int fd = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t fmt_addr = get_reg(emu, UC_ARM64_REG_X1);
        HleFormatResult formatted = hle_format_from_regs(emu, fmt_addr, 2, false);
        if (!formatted.ok) {
            hle_set_errno(emu, formatted.error);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }
        errno = 0;
        ssize_t written = ::write(fd, formatted.output.data(), formatted.output.size());
        if (written == -1) {
            hle_set_errno(emu, errno);
        }
        set_reg(emu, UC_ARM64_REG_X0,
                static_cast<uint64_t>(static_cast<int64_t>(written)));
    });

    hle.register_function("vdprintf", [](Emulator& emu) {
        int fd = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t fmt_addr = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t va_list_addr = get_reg(emu, UC_ARM64_REG_X2);
        HleFormatResult formatted = hle_format_from_va_list(emu, fmt_addr, va_list_addr, false);
        if (!formatted.ok) {
            hle_set_errno(emu, formatted.error);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }
        errno = 0;
        ssize_t written = ::write(fd, formatted.output.data(), formatted.output.size());
        if (written == -1) {
            hle_set_errno(emu, errno);
        }
        set_reg(emu, UC_ARM64_REG_X0,
                static_cast<uint64_t>(static_cast<int64_t>(written)));
    });

    hle.register_function("getchar", [](Emulator& emu) {
        int c = std::getchar();
        set_reg(emu, UC_ARM64_REG_X0, c);
    });

    hle.register_function("fgetc_unlocked", [](Emulator& emu) {
        uint64_t stream = get_reg(emu, UC_ARM64_REG_X0);
        FILE* fp = hle_resolve_guest_file(emu, stream);
        if (fp == nullptr) {
            hle_set_errno(emu, EBADF);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(EOF));
            return;
        }
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(::fgetc(fp)));
    });

    hle.register_function("getc_unlocked", [](Emulator& emu) {
        uint64_t stream = get_reg(emu, UC_ARM64_REG_X0);
        FILE* fp = hle_resolve_guest_file(emu, stream);
        if (fp == nullptr) {
            hle_set_errno(emu, EBADF);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(EOF));
            return;
        }
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(::getc(fp)));
    });

    hle.register_function("fputc_unlocked", [](Emulator& emu) {
        int c = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t stream = get_reg(emu, UC_ARM64_REG_X1);
        FILE* fp = hle_resolve_guest_file(emu, stream);
        if (fp == nullptr) {
            hle_set_errno(emu, EBADF);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(EOF));
            return;
        }
        errno = 0;
        int result = ::fputc(c, fp);
        if (result == EOF) {
            hle_set_errno(emu, errno);
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("putc_unlocked", [](Emulator& emu) {
        int c = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t stream = get_reg(emu, UC_ARM64_REG_X1);
        FILE* fp = hle_resolve_guest_file(emu, stream);
        if (fp == nullptr) {
            hle_set_errno(emu, EBADF);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(EOF));
            return;
        }
        errno = 0;
        int result = ::putc(c, fp);
        if (result == EOF) {
            hle_set_errno(emu, errno);
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("fflush_unlocked", [](Emulator& emu) {
        uint64_t stream = get_reg(emu, UC_ARM64_REG_X0);
        errno = 0;
        int result = stream == 0 ? ::fflush(nullptr) : -1;
        if (stream != 0) {
            FILE* fp = hle_resolve_guest_file(emu, stream);
            if (fp == nullptr) {
                hle_set_errno(emu, EBADF);
                set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
                return;
            }
            result = ::fflush(fp);
        }
        if (result == EOF) {
            hle_set_errno(emu, errno);
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // clearerr_unlocked - clear error indicators (unlocked version)
    hle.register_function("clearerr_unlocked", [](Emulator& emu) {
        uint64_t stream = get_reg(emu, UC_ARM64_REG_X0);
        FILE* fp = hle_resolve_guest_file(emu, stream);
        if (fp != nullptr) {
            clearerr(fp);
        }
    });

    // feof_unlocked - test end-of-file indicator (unlocked version)
    hle.register_function("feof_unlocked", [](Emulator& emu) {
        uint64_t stream = get_reg(emu, UC_ARM64_REG_X0);
        FILE* fp = hle_resolve_guest_file(emu, stream);
        if (fp != nullptr) {
            int result = feof(fp);
            set_reg(emu, UC_ARM64_REG_X0, result);
        } else {
            hle_set_errno(emu, EBADF);
            set_reg(emu, UC_ARM64_REG_X0, 1);
        }
    });

    // ferror_unlocked - test error indicator (unlocked version)
    hle.register_function("ferror_unlocked", [](Emulator& emu) {
        uint64_t stream = get_reg(emu, UC_ARM64_REG_X0);
        FILE* fp = hle_resolve_guest_file(emu, stream);
        if (fp != nullptr) {
            int result = ferror(fp);
            set_reg(emu, UC_ARM64_REG_X0, result);
        } else {
            hle_set_errno(emu, EBADF);
            set_reg(emu, UC_ARM64_REG_X0, 1);
        }
    });

    // fileno_unlocked - get file descriptor (unlocked version)
    hle.register_function("fileno_unlocked", [](Emulator& emu) {
        uint64_t stream = get_reg(emu, UC_ARM64_REG_X0);
        int result = hle_resolve_guest_fileno(emu, stream);
        if (result != -1) {
            set_reg(emu, UC_ARM64_REG_X0, result);
        } else {
            hle_set_errno(emu, EBADF);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
        }
    });

    // fread_unlocked - read from stream (unlocked version)
    hle.register_function("fread_unlocked", [](Emulator& emu) {
        uint64_t buf_addr = get_reg(emu, UC_ARM64_REG_X0);
        size_t size = get_reg(emu, UC_ARM64_REG_X1);
        size_t nmemb = get_reg(emu, UC_ARM64_REG_X2);
        uint64_t stream = get_reg(emu, UC_ARM64_REG_X3);

        FILE* fp = hle_resolve_guest_file(emu, stream);
        if (fp != nullptr) {
            std::vector<char> buf(size * nmemb);
            if (std::feof(fp)) {
                ::clearerr(fp);
            }
            errno = 0;
            off_t before = ::ftello(fp);
            errno = 0;
            size_t result = fread(buf.data(), size, nmemb, fp);
            size_t bytes_read = result * size;
            off_t after = ::ftello(fp);
            if (before != static_cast<off_t>(-1) &&
                after != static_cast<off_t>(-1) &&
                after >= before) {
                bytes_read = static_cast<size_t>(after - before);
            }
            if (bytes_read > 0) {
                emu.mem_write(buf_addr, buf.data(), bytes_read);
            }
            if (result < nmemb && std::ferror(fp)) {
                hle_set_errno(emu, errno);
            }
            set_reg(emu, UC_ARM64_REG_X0, result);
        } else {
            hle_set_errno(emu, EBADF);
            set_reg(emu, UC_ARM64_REG_X0, 0);
        }
    });

    // fwrite_unlocked - write to stream (unlocked version)
    hle.register_function("fwrite_unlocked", [](Emulator& emu) {
        uint64_t buf_addr = get_reg(emu, UC_ARM64_REG_X0);
        size_t size = get_reg(emu, UC_ARM64_REG_X1);
        size_t nmemb = get_reg(emu, UC_ARM64_REG_X2);
        uint64_t stream = get_reg(emu, UC_ARM64_REG_X3);

        FILE* fp = hle_resolve_guest_file(emu, stream);
        if (fp != nullptr) {
            std::vector<char> buf(size * nmemb);
            emu.mem_read(buf_addr, buf.data(), size * nmemb);
            errno = 0;
            size_t result = fwrite(buf.data(), size, nmemb, fp);
            if (result < nmemb && std::ferror(fp)) {
                hle_set_errno(emu, errno);
            }
            set_reg(emu, UC_ARM64_REG_X0, result);
        } else {
            hle_set_errno(emu, EBADF);
            set_reg(emu, UC_ARM64_REG_X0, 0);
        }
    });

    // fgets_unlocked - read string from stream (unlocked version)
    hle.register_function("fgets_unlocked", [](Emulator& emu) {
        uint64_t buf_addr = get_reg(emu, UC_ARM64_REG_X0);
        int size = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t stream = get_reg(emu, UC_ARM64_REG_X2);

        FILE* fp = hle_resolve_guest_file(emu, stream);
        if (fp != nullptr) {
            std::vector<char> buf(size);
            errno = 0;
            char* result = fgets(buf.data(), size, fp);
            if (result) {
                emu.mem_write(buf_addr, buf.data(), strlen(buf.data()) + 1);
                set_reg(emu, UC_ARM64_REG_X0, buf_addr);
            } else {
                if (std::ferror(fp)) {
                    hle_set_errno(emu, errno);
                }
                set_reg(emu, UC_ARM64_REG_X0, 0);
            }
        } else {
            hle_set_errno(emu, EBADF);
            set_reg(emu, UC_ARM64_REG_X0, 0);
        }
    });

    // fputs_unlocked - write string to stream (unlocked version)
    hle.register_function("fputs_unlocked", [](Emulator& emu) {
        uint64_t s_addr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t stream = get_reg(emu, UC_ARM64_REG_X1);
        std::string str = read_string(emu, s_addr);

        FILE* fp = hle_resolve_guest_file(emu, stream);
        if (fp != nullptr) {
            errno = 0;
            int result = fputs(str.c_str(), fp);
            if (result == EOF) {
                hle_set_errno(emu, errno);
            }
            set_reg(emu, UC_ARM64_REG_X0, result);
        } else {
            hle_set_errno(emu, EBADF);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(EOF));
        }
    });

    // ctermid - get controlling terminal name
    hle.register_function("ctermid", [](Emulator& emu) {
        uint64_t buf_addr = get_reg(emu, UC_ARM64_REG_X0);

        // Return /dev/tty as the controlling terminal
        const char* tty_name = "/dev/tty";

        if (buf_addr) {
            emu.mem_write(buf_addr, tty_name, strlen(tty_name) + 1);
            set_reg(emu, UC_ARM64_REG_X0, buf_addr);
        } else {
            // Return static buffer
            static uint64_t static_ctermid_buf = 0;
            if (static_ctermid_buf == 0) {
                static_ctermid_buf = emu.memory().heap().allocate(16, 8);
                emu.mem_write(static_ctermid_buf, tty_name, strlen(tty_name) + 1);
            }
            set_reg(emu, UC_ARM64_REG_X0, static_ctermid_buf);
        }
    });

    // flockfile - lock file stream
    hle.register_function("flockfile", [](Emulator& emu) {
        // No-op for now since we're single-threaded in FILE operations
    });

    // funlockfile - unlock file stream
    hle.register_function("funlockfile", [](Emulator& emu) {
        // No-op for now
    });

    // ftrylockfile - try to lock file stream
    hle.register_function("ftrylockfile", [](Emulator& emu) {
        set_reg(emu, UC_ARM64_REG_X0, 0);  // Always succeeds
    });

    hle.register_function("__isoc99_sscanf", [](Emulator& emu) {
        HleScanResult scanned = hle_scan_from_regs(
            emu,
            get_reg(emu, UC_ARM64_REG_X0),
            get_reg(emu, UC_ARM64_REG_X1),
            2,
            false);
        if (!scanned.ok) {
            hle_set_errno(emu, scanned.error);
        }
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(static_cast<int64_t>(scanned.result)));
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
        std::lock_guard<std::recursive_mutex> _fl(g_file_tables_mutex);
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
                case 'o': {
                    char* end;
                    unsigned long val = strtoul(str.c_str() + str_pos, &end, 8);  // octal
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
        HleScanResult scanned = hle_scan_from_va_list(
            emu,
            get_reg(emu, UC_ARM64_REG_X0),
            get_reg(emu, UC_ARM64_REG_X1),
            get_reg(emu, UC_ARM64_REG_X2),
            false);
        if (!scanned.ok) {
            hle_set_errno(emu, scanned.error);
        }
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(static_cast<int64_t>(scanned.result)));
    });

    hle.register_function("vfscanf", [](Emulator& emu) {
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("vscanf", [](Emulator& emu) {
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    // ========================================================================
    // Terminal I/O (termios)
    // ========================================================================

    // tcgetattr - get terminal attributes
    hle.register_function("tcgetattr", [](Emulator& emu) {
        int fd = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t termios_ptr = get_reg(emu, UC_ARM64_REG_X1);

        struct termios host_termios;
        int result = ::tcgetattr(fd, &host_termios);

        if (result == 0 && termios_ptr) {
            // ARM64 bionic termios is 60 bytes:
            // tcflag_t c_iflag (4), c_oflag (4), c_cflag (4), c_lflag (4)
            // cc_t c_line (1), cc_t c_cc[NCCS=19] (19)
            // 4 bytes padding
            // speed_t c_ispeed (4), c_ospeed (4)
            // Total: 44 bytes (but may have padding)

            // Write host termios directly - layout should be compatible on LP64
            emu.mem_write(termios_ptr, &host_termios, sizeof(host_termios));
        }

        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // tcsetattr - set terminal attributes
    hle.register_function("tcsetattr", [](Emulator& emu) {
        int fd = get_reg(emu, UC_ARM64_REG_X0);
        int optional_actions = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t termios_ptr = get_reg(emu, UC_ARM64_REG_X2);

        struct termios host_termios;
        if (termios_ptr) {
            emu.mem_read(termios_ptr, &host_termios, sizeof(host_termios));
        }

        int result = ::tcsetattr(fd, optional_actions, &host_termios);
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // Bionic termios baud rate constants and masks
    // These differ from glibc where B1200=1200; in bionic B1200=9 (small index)
    constexpr uint32_t BIONIC_CBAUD = 0x100F;     // CBAUD mask (010017 octal)
    constexpr uint32_t BIONIC_CBAUDEX = 0x1000;   // Extended baud flag (010000 octal)
    constexpr size_t BIONIC_TERMIOS_CFLAG_OFFSET = 8;  // offset of c_cflag in bionic termios

    // cfgetispeed - get input baud rate
    // In bionic, speed is stored in c_cflag & CBAUD
    hle.register_function("cfgetispeed", [BIONIC_CBAUD](Emulator& emu) {
        uint64_t termios_ptr = get_reg(emu, UC_ARM64_REG_X0);

        if (termios_ptr) {
            uint32_t c_cflag;
            emu.mem_read(termios_ptr + BIONIC_TERMIOS_CFLAG_OFFSET, &c_cflag, sizeof(c_cflag));
            speed_t result = c_cflag & BIONIC_CBAUD;
            set_reg(emu, UC_ARM64_REG_X0, result);
        } else {
            set_reg(emu, UC_ARM64_REG_X0, 0);
        }
    });

    // cfgetospeed - get output baud rate
    // In bionic, speed is stored in c_cflag & CBAUD (same as input)
    hle.register_function("cfgetospeed", [BIONIC_CBAUD](Emulator& emu) {
        uint64_t termios_ptr = get_reg(emu, UC_ARM64_REG_X0);

        if (termios_ptr) {
            uint32_t c_cflag;
            emu.mem_read(termios_ptr + BIONIC_TERMIOS_CFLAG_OFFSET, &c_cflag, sizeof(c_cflag));
            speed_t result = c_cflag & BIONIC_CBAUD;
            set_reg(emu, UC_ARM64_REG_X0, result);
        } else {
            set_reg(emu, UC_ARM64_REG_X0, 0);
        }
    });

    // Helper to validate baud rate constants (B0, B50, B75, etc.)
    // Use bionic/Android values (small indices), not glibc values (actual baud rates)
    auto is_valid_baud_constant = [](uint32_t speed) -> bool {
        // Standard baud rates: 0-15 (B0 through B38400)
        if (speed <= 15) return true;
        // Extended baud rates: 4096-4111 (010000-010017 octal) and beyond
        // BOTHER=4096, B57600=4097, B115200=4098, etc.
        if (speed >= 4096 && speed <= 4111) return true;
        // More extended baud rates (B1000000 etc.)
        if (speed >= 4112 && speed <= 4127) return true;
        return false;
    };

    // cfsetispeed - set input baud rate
    // In bionic, input speed is stored in c_cflag along with output speed
    hle.register_function("cfsetispeed", [is_valid_baud_constant, BIONIC_CBAUD](Emulator& emu) {
        uint64_t termios_ptr = get_reg(emu, UC_ARM64_REG_X0);
        uint32_t speed = get_reg(emu, UC_ARM64_REG_X1);

        // Validate the baud rate constant
        if (!is_valid_baud_constant(speed)) {
            hle_set_errno(emu, EINVAL);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        if (termios_ptr) {
            // Read c_cflag, modify baud bits, write back
            uint32_t c_cflag;
            emu.mem_read(termios_ptr + BIONIC_TERMIOS_CFLAG_OFFSET, &c_cflag, sizeof(c_cflag));
            c_cflag = (c_cflag & ~BIONIC_CBAUD) | (speed & BIONIC_CBAUD);
            emu.mem_write(termios_ptr + BIONIC_TERMIOS_CFLAG_OFFSET, &c_cflag, sizeof(c_cflag));
            set_reg(emu, UC_ARM64_REG_X0, 0);  // Success
        } else {
            hle_set_errno(emu, EINVAL);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
        }
    });

    // cfsetospeed - set output baud rate
    // In bionic, output speed is stored in c_cflag (same as input speed)
    hle.register_function("cfsetospeed", [is_valid_baud_constant, BIONIC_CBAUD](Emulator& emu) {
        uint64_t termios_ptr = get_reg(emu, UC_ARM64_REG_X0);
        uint32_t speed = get_reg(emu, UC_ARM64_REG_X1);

        // Validate the baud rate constant
        if (!is_valid_baud_constant(speed)) {
            hle_set_errno(emu, EINVAL);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        if (termios_ptr) {
            // Read c_cflag, modify baud bits, write back
            uint32_t c_cflag;
            emu.mem_read(termios_ptr + BIONIC_TERMIOS_CFLAG_OFFSET, &c_cflag, sizeof(c_cflag));
            c_cflag = (c_cflag & ~BIONIC_CBAUD) | (speed & BIONIC_CBAUD);
            emu.mem_write(termios_ptr + BIONIC_TERMIOS_CFLAG_OFFSET, &c_cflag, sizeof(c_cflag));
            set_reg(emu, UC_ARM64_REG_X0, 0);  // Success
        } else {
            hle_set_errno(emu, EINVAL);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
        }
    });

    // cfsetspeed - set both baud rates
    hle.register_function("cfsetspeed", [is_valid_baud_constant, BIONIC_CBAUD](Emulator& emu) {
        uint64_t termios_ptr = get_reg(emu, UC_ARM64_REG_X0);
        uint32_t speed = get_reg(emu, UC_ARM64_REG_X1);

        // Validate the baud rate constant
        if (!is_valid_baud_constant(speed)) {
            hle_set_errno(emu, EINVAL);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        if (termios_ptr) {
            // Read c_cflag, modify baud bits, write back
            uint32_t c_cflag;
            emu.mem_read(termios_ptr + BIONIC_TERMIOS_CFLAG_OFFSET, &c_cflag, sizeof(c_cflag));
            c_cflag = (c_cflag & ~BIONIC_CBAUD) | (speed & BIONIC_CBAUD);
            emu.mem_write(termios_ptr + BIONIC_TERMIOS_CFLAG_OFFSET, &c_cflag, sizeof(c_cflag));
            set_reg(emu, UC_ARM64_REG_X0, 0);  // Success
        } else {
            hle_set_errno(emu, EINVAL);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
        }
    });

    // cfmakeraw - set terminal to raw mode
    hle.register_function("cfmakeraw", [](Emulator& emu) {
        uint64_t termios_ptr = get_reg(emu, UC_ARM64_REG_X0);

        struct termios host_termios;
        if (termios_ptr) {
            emu.mem_read(termios_ptr, &host_termios, sizeof(host_termios));
            ::cfmakeraw(&host_termios);
            emu.mem_write(termios_ptr, &host_termios, sizeof(host_termios));
        }
    });

    // tcdrain - wait for output to be transmitted
    hle.register_function("tcdrain", [](Emulator& emu) {
        int fd = get_reg(emu, UC_ARM64_REG_X0);
        int result = ::tcdrain(fd);
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // tcflush - flush terminal data
    hle.register_function("tcflush", [](Emulator& emu) {
        int fd = get_reg(emu, UC_ARM64_REG_X0);
        int queue_selector = get_reg(emu, UC_ARM64_REG_X1);
        int result = ::tcflush(fd, queue_selector);
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // tcflow - suspend/restart terminal output
    hle.register_function("tcflow", [](Emulator& emu) {
        int fd = get_reg(emu, UC_ARM64_REG_X0);
        int action = get_reg(emu, UC_ARM64_REG_X1);
        int result = ::tcflow(fd, action);
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // tcsendbreak - send break condition
    hle.register_function("tcsendbreak", [](Emulator& emu) {
        int fd = get_reg(emu, UC_ARM64_REG_X0);
        int duration = get_reg(emu, UC_ARM64_REG_X1);
        int result = ::tcsendbreak(fd, duration);
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // tcgetsid - get session ID
    hle.register_function("tcgetsid", [](Emulator& emu) {
        int fd = get_reg(emu, UC_ARM64_REG_X0);
        pid_t result = ::tcgetsid(fd);
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // isatty - test whether fd refers to a terminal
    hle.register_function("isatty", [](Emulator& emu) {
        int fd = get_reg(emu, UC_ARM64_REG_X0);
        int result = ::isatty(fd);
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // ttyname - return name of terminal
    hle.register_function("ttyname", [](Emulator& emu) {
        int fd = get_reg(emu, UC_ARM64_REG_X0);
        char* name = ::ttyname(fd);
        if (name) {
            uint64_t ptr = emu.memory().heap().allocate(strlen(name) + 1, 8);
            emu.mem_write(ptr, name, strlen(name) + 1);
            set_reg(emu, UC_ARM64_REG_X0, ptr);
        } else {
            set_reg(emu, UC_ARM64_REG_X0, 0);
        }
    });

    // ttyname_r - thread-safe version of ttyname
    hle.register_function("ttyname_r", [](Emulator& emu) {
        int fd = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t buf = get_reg(emu, UC_ARM64_REG_X1);
        size_t buflen = get_reg(emu, UC_ARM64_REG_X2);

        if (buf == 0 || buflen == 0) {
            hle_set_errno(emu, EINVAL);
            set_reg(emu, UC_ARM64_REG_X0, EINVAL);
            return;
        }

        std::vector<char> host_buf(buflen);
        int result = ::ttyname_r(fd, host_buf.data(), buflen);
        if (result == 0 && buf) {
            emu.mem_write(buf, host_buf.data(), strlen(host_buf.data()) + 1);
        } else if (result != 0) {
            hle_set_errno(emu, result);
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // ========================================================================
    // Terminal window size functions
    // ========================================================================

    // ARM64 winsize structure
    struct winsize_arm64 {
        uint16_t ws_row;
        uint16_t ws_col;
        uint16_t ws_xpixel;
        uint16_t ws_ypixel;
    };

    // tcgetwinsize - get terminal window size
    hle.register_function("tcgetwinsize", [](Emulator& emu) {
        int fd = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t ws_ptr = get_reg(emu, UC_ARM64_REG_X1);

        if (!ws_ptr) {
            hle_set_errno(emu, EINVAL);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        struct winsize ws;
        int result = ::ioctl(fd, TIOCGWINSZ, &ws);
        if (result == 0) {
            winsize_arm64 ws_arm;
            ws_arm.ws_row = ws.ws_row;
            ws_arm.ws_col = ws.ws_col;
            ws_arm.ws_xpixel = ws.ws_xpixel;
            ws_arm.ws_ypixel = ws.ws_ypixel;
            emu.mem_write(ws_ptr, &ws_arm, sizeof(ws_arm));
        } else {
            hle_set_errno(emu, errno);
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // tcsetwinsize - set terminal window size
    hle.register_function("tcsetwinsize", [](Emulator& emu) {
        int fd = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t ws_ptr = get_reg(emu, UC_ARM64_REG_X1);

        if (!ws_ptr) {
            hle_set_errno(emu, EINVAL);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        winsize_arm64 ws_arm;
        emu.mem_read(ws_ptr, &ws_arm, sizeof(ws_arm));

        struct winsize ws;
        ws.ws_row = ws_arm.ws_row;
        ws.ws_col = ws_arm.ws_col;
        ws.ws_xpixel = ws_arm.ws_xpixel;
        ws.ws_ypixel = ws_arm.ws_ypixel;

        int result = ::ioctl(fd, TIOCSWINSZ, &ws);
        if (result < 0) {
            hle_set_errno(emu, errno);
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // openpty - open a pseudo-terminal
    hle.register_function("openpty", [](Emulator& emu) {
        uint64_t amaster_ptr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t aslave_ptr = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t name_ptr = get_reg(emu, UC_ARM64_REG_X2);
        uint64_t termp_ptr = get_reg(emu, UC_ARM64_REG_X3);
        uint64_t winp_ptr = get_reg(emu, UC_ARM64_REG_X4);

        int amaster, aslave;
        char name[256] = {};
        struct termios termp = {};
        struct winsize winp = {};

        // Read optional termios
        if (termp_ptr) {
            emu.mem_read(termp_ptr, &termp, sizeof(termp));
        }

        // Read optional winsize
        if (winp_ptr) {
            winsize_arm64 winp_arm;
            emu.mem_read(winp_ptr, &winp_arm, sizeof(winp_arm));
            winp.ws_row = winp_arm.ws_row;
            winp.ws_col = winp_arm.ws_col;
            winp.ws_xpixel = winp_arm.ws_xpixel;
            winp.ws_ypixel = winp_arm.ws_ypixel;
        }

        int result = ::openpty(&amaster, &aslave,
                                name_ptr ? name : nullptr,
                                termp_ptr ? &termp : nullptr,
                                winp_ptr ? &winp : nullptr);

        if (result == 0) {
            if (amaster_ptr) {
                int32_t am = amaster;
                emu.mem_write(amaster_ptr, &am, 4);
            }
            if (aslave_ptr) {
                int32_t as = aslave;
                emu.mem_write(aslave_ptr, &as, 4);
            }
            if (name_ptr && name[0]) {
                emu.mem_write(name_ptr, name, strlen(name) + 1);
            }
        }

        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // forkpty - fork and open a pseudo-terminal
    hle.register_function("forkpty", [](Emulator& emu) {
        // forkpty is complex and involves forking - return error for now
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
    });

    // login_tty - prepare for login on a terminal
    hle.register_function("login_tty", [](Emulator& emu) {
        // Simplified: just return success
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });
}

} // namespace cross_shim
