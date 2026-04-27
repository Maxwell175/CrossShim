/**
 * HLE Locale and Multibyte Functions
 * Locale: setlocale, localeconv, nl_langinfo, newlocale, uselocale, freelocale, duplocale
 * Multibyte: btowc, wctob, mbstowcs, wcstombs, mbtowc, wctomb, wcrtomb, mbrtowc, mblen, mbrlen,
 *            mbsinit, mbsrtowcs, wcsrtombs, wcsnrtombs, mbsnrtowcs, __ctype_get_mb_cur_max
 * C11: mbrtoc16, c16rtomb, mbrtoc32, c32rtomb
 */

#include "debug_log.h"
#include "hle_manager.h"
#include "cross_shim.h"
#include "memory_manager.h"
#include "emu_compat.h"
#include <cstring>
#include <cstdlib>
#include <cctype>
#include <clocale>
#include <iconv.h>
#include <langinfo.h>
#include <vector>
#include <map>
#include <unordered_map>
#include <algorithm>
#include <cerrno>

namespace cross_shim {

// Constants
static constexpr int EILSEQ_VALUE = 84;  // Invalid or incomplete multibyte or wide character

static std::string read_string(Emulator& emu, uint64_t addr, size_t max_len = 4096) {
    std::string result;
    char c;
    for (size_t i = 0; i < max_len; i++) {
        if (!emu.mem_read(addr + i, &c, 1) || c == '\0') break;
        result += c;
    }
    return result;
}

// Fake locale handle
static uint64_t g_current_locale = 0x12345678;
static uint64_t g_c_locale = 0x87654321;

// Static lconv structure for localeconv
struct guest_lconv {
    uint64_t decimal_point;
    uint64_t thousands_sep;
    uint64_t grouping;
    uint64_t int_curr_symbol;
    uint64_t currency_symbol;
    uint64_t mon_decimal_point;
    uint64_t mon_thousands_sep;
    uint64_t mon_grouping;
    uint64_t positive_sign;
    uint64_t negative_sign;
    int8_t int_frac_digits;
    int8_t frac_digits;
    int8_t p_cs_precedes;
    int8_t p_sep_by_space;
    int8_t n_cs_precedes;
    int8_t n_sep_by_space;
    int8_t p_sign_posn;
    int8_t n_sign_posn;
    int8_t int_p_cs_precedes;
    int8_t int_p_sep_by_space;
    int8_t int_n_cs_precedes;
    int8_t int_n_sep_by_space;
    int8_t int_p_sign_posn;
    int8_t int_n_sign_posn;
};

struct IconvDescriptor {
    iconv_t host_cd;
    std::string tocode;
    std::string fromcode;
    bool ascii_question_translit;
};

static std::unordered_map<uint64_t, IconvDescriptor> g_iconv_descriptors;

static std::string canonicalize_iconv_base_name(const std::string& encoding) {
    std::string canonical;
    canonical.reserve(encoding.size());

    size_t i = 0;
    while (i < encoding.size()) {
        unsigned char ch = static_cast<unsigned char>(encoding[i]);
        if (std::isalpha(ch)) {
            canonical.push_back(static_cast<char>(std::tolower(ch)));
            ++i;
            continue;
        }

        if (std::isdigit(ch)) {
            size_t start = i;
            while (i < encoding.size() &&
                   std::isdigit(static_cast<unsigned char>(encoding[i]))) {
                ++i;
            }

            size_t first_nonzero = start;
            while (first_nonzero < i && encoding[first_nonzero] == '0') {
                ++first_nonzero;
            }

            if (first_nonzero == i) {
                canonical.push_back('0');
            } else {
                canonical.append(encoding, first_nonzero, i - first_nonzero);
            }
            continue;
        }

        ++i;
    }

    return canonical;
}

static std::string normalize_iconv_base_name(const std::string& encoding) {
    const std::string canonical = canonicalize_iconv_base_name(encoding);

    if (canonical == "ascii") {
        return "ASCII";
    }
    if (canonical == "utf8") {
        return "UTF-8";
    }
    if (canonical == "utf16") {
        return "UTF-16";
    }
    if (canonical == "utf16be") {
        return "UTF-16BE";
    }
    if (canonical == "utf16le") {
        return "UTF-16LE";
    }
    if (canonical == "utf32") {
        return "UTF-32";
    }
    if (canonical == "utf32be") {
        return "UTF-32BE";
    }
    if (canonical == "utf32le") {
        return "UTF-32LE";
    }
    if (canonical == "wchart") {
        return "WCHAR_T";
    }

    return encoding;
}

static std::string normalize_iconv_name(const std::string& encoding) {
    size_t suffix_pos = encoding.find("//");
    std::string base = encoding.substr(0, suffix_pos);
    std::string suffix = (suffix_pos == std::string::npos) ? "" : encoding.substr(suffix_pos);
    return normalize_iconv_base_name(base) + suffix;
}

static bool iconv_uses_question_mark_translit(const std::string& tocode) {
    size_t suffix_pos = tocode.find("//");
    std::string base = tocode.substr(0, suffix_pos);
    std::string suffix = (suffix_pos == std::string::npos) ? "" : tocode.substr(suffix_pos);

    std::string lowercase_suffix;
    lowercase_suffix.reserve(suffix.size());
    for (unsigned char ch : suffix) {
        lowercase_suffix.push_back(static_cast<char>(std::tolower(ch)));
    }

    return canonicalize_iconv_base_name(base) == "ascii" &&
           lowercase_suffix.find("translit") != std::string::npos;
}

static char* guest_addr_to_host_char_ptr(Emulator& emu, uint64_t guest_addr) {
    if (guest_addr == 0) {
        return nullptr;
    }
    return static_cast<char*>(emu.memory().get_host_ptr(guest_addr));
}

static uint64_t host_ptr_to_guest_addr(const void* host_ptr) {
    if (host_ptr == nullptr) {
        return 0;
    }
    return reinterpret_cast<uint64_t>(host_ptr);
}

enum class Utf8DecodeStatus {
    Ok,
    Incomplete,
    Invalid,
};

static Utf8DecodeStatus decode_utf8_codepoint(const unsigned char* input, size_t available,
                                              uint32_t& codepoint, size_t& consumed) {
    if (available == 0) {
        return Utf8DecodeStatus::Incomplete;
    }

    const unsigned char b0 = input[0];
    if (b0 < 0x80) {
        codepoint = b0;
        consumed = 1;
        return Utf8DecodeStatus::Ok;
    }

    if (b0 >= 0xC2 && b0 <= 0xDF) {
        if (available < 2) {
            return Utf8DecodeStatus::Incomplete;
        }
        const unsigned char b1 = input[1];
        if ((b1 & 0xC0) != 0x80) {
            return Utf8DecodeStatus::Invalid;
        }
        codepoint = ((b0 & 0x1F) << 6) | (b1 & 0x3F);
        consumed = 2;
        return Utf8DecodeStatus::Ok;
    }

    if (b0 >= 0xE0 && b0 <= 0xEF) {
        if (available < 3) {
            return Utf8DecodeStatus::Incomplete;
        }
        const unsigned char b1 = input[1];
        const unsigned char b2 = input[2];
        if ((b1 & 0xC0) != 0x80 || (b2 & 0xC0) != 0x80) {
            return Utf8DecodeStatus::Invalid;
        }
        if ((b0 == 0xE0 && b1 < 0xA0) || (b0 == 0xED && b1 >= 0xA0)) {
            return Utf8DecodeStatus::Invalid;
        }
        codepoint = ((b0 & 0x0F) << 12) | ((b1 & 0x3F) << 6) | (b2 & 0x3F);
        consumed = 3;
        return Utf8DecodeStatus::Ok;
    }

    if (b0 >= 0xF0 && b0 <= 0xF4) {
        if (available < 4) {
            return Utf8DecodeStatus::Incomplete;
        }
        const unsigned char b1 = input[1];
        const unsigned char b2 = input[2];
        const unsigned char b3 = input[3];
        if ((b1 & 0xC0) != 0x80 || (b2 & 0xC0) != 0x80 || (b3 & 0xC0) != 0x80) {
            return Utf8DecodeStatus::Invalid;
        }
        if ((b0 == 0xF0 && b1 < 0x90) || (b0 == 0xF4 && b1 >= 0x90)) {
            return Utf8DecodeStatus::Invalid;
        }
        codepoint = ((b0 & 0x07) << 18) | ((b1 & 0x3F) << 12) |
                    ((b2 & 0x3F) << 6) | (b3 & 0x3F);
        consumed = 4;
        return Utf8DecodeStatus::Ok;
    }

    return Utf8DecodeStatus::Invalid;
}

static size_t iconv_ascii_question_translit(char** inbuf, size_t* inbytesleft,
                                            char** outbuf, size_t* outbytesleft,
                                            int& out_errno) {
    if (inbuf == nullptr || *inbuf == nullptr) {
        out_errno = 0;
        return 0;
    }

    if (inbytesleft == nullptr || outbuf == nullptr || outbytesleft == nullptr) {
        out_errno = EFAULT;
        return static_cast<size_t>(-1);
    }

    auto* input = reinterpret_cast<unsigned char*>(*inbuf);
    size_t input_left = *inbytesleft;
    char* output = *outbuf;
    size_t output_left = *outbytesleft;
    size_t replacement_count = 0;

    while (input_left > 0) {
        uint32_t codepoint = 0;
        size_t consumed = 0;
        Utf8DecodeStatus status = decode_utf8_codepoint(input, input_left, codepoint, consumed);

        if (status == Utf8DecodeStatus::Incomplete) {
            out_errno = EINVAL;
            *inbuf = reinterpret_cast<char*>(input);
            *inbytesleft = input_left;
            *outbuf = output;
            *outbytesleft = output_left;
            return static_cast<size_t>(-1);
        }

        if (status == Utf8DecodeStatus::Invalid) {
            out_errno = EILSEQ;
            *inbuf = reinterpret_cast<char*>(input);
            *inbytesleft = input_left;
            *outbuf = output;
            *outbytesleft = output_left;
            return static_cast<size_t>(-1);
        }

        if (output_left == 0) {
            out_errno = E2BIG;
            *inbuf = reinterpret_cast<char*>(input);
            *inbytesleft = input_left;
            *outbuf = output;
            *outbytesleft = output_left;
            return static_cast<size_t>(-1);
        }

        if (codepoint <= 0x7F) {
            *output = static_cast<char>(codepoint);
        } else {
            *output = '?';
            ++replacement_count;
        }

        ++output;
        --output_left;
        input += consumed;
        input_left -= consumed;
    }

    *inbuf = reinterpret_cast<char*>(input);
    *inbytesleft = input_left;
    *outbuf = output;
    *outbytesleft = output_left;
    out_errno = 0;
    return replacement_count;
}

void register_hle_locale(HleManager& hle) {
    // ========================================================================
    // Locale functions
    // ========================================================================

    // Track current locale name
    static std::string g_current_locale_name = "C";
    static uint64_t g_locale_str_addr = 0;

    hle.register_function("setlocale", [](Emulator& emu) {
        int category = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t locale_ptr = get_reg(emu, UC_ARM64_REG_X1);
        (void)category;  // We support all categories the same way

        if (locale_ptr == 0) {
            // Query current locale - return current locale name
            if (g_locale_str_addr == 0 || g_current_locale_name.size() + 1 > 32) {
                g_locale_str_addr = emu.memory().heap().allocate(g_current_locale_name.size() + 1, 8);
            }
            emu.mem_write(g_locale_str_addr, g_current_locale_name.c_str(), g_current_locale_name.size() + 1);
            set_reg(emu, UC_ARM64_REG_X0, g_locale_str_addr);
            return;
        }

        // Read requested locale string
        std::string requested = read_string(emu, locale_ptr);

        // Support these locales:
        // - "C" - C locale
        // - "POSIX" - same as C
        // - "C.UTF-8" - C locale with UTF-8 encoding
        // - "" - use environment (we default to C.UTF-8)
        // - "en_US.UTF-8" and similar - accept UTF-8 locales
        bool valid = false;
        std::string result_name;

        if (requested == "C" || requested == "POSIX") {
            result_name = "C";
            valid = true;
        } else if (requested == "C.UTF-8" || requested == "C.utf8") {
            result_name = "C.UTF-8";
            valid = true;
        } else if (requested.empty()) {
            // Empty string means use environment - default to C.UTF-8
            result_name = "C.UTF-8";
            valid = true;
        } else if (requested.find("UTF-8") != std::string::npos ||
                   requested.find("utf8") != std::string::npos ||
                   requested.find("utf-8") != std::string::npos) {
            // Accept any UTF-8 locale but normalize to C.UTF-8
            result_name = "C.UTF-8";
            valid = true;
        }

        if (valid) {
            g_current_locale_name = result_name;
            // Allocate/reallocate string buffer if needed
            g_locale_str_addr = emu.memory().heap().allocate(result_name.size() + 1, 8);
            emu.mem_write(g_locale_str_addr, result_name.c_str(), result_name.size() + 1);
            set_reg(emu, UC_ARM64_REG_X0, g_locale_str_addr);
        } else {
            // Unsupported locale - return NULL
            set_reg(emu, UC_ARM64_REG_X0, 0);
        }
    });

    hle.register_function("localeconv", [](Emulator& emu) {
        static uint64_t lconv_addr = 0;
        static uint64_t dot_str = 0;
        static uint64_t empty_str = 0;

        if (lconv_addr == 0) {
            // Allocate strings
            dot_str = emu.memory().heap().allocate(2, 8);
            emu.mem_write(dot_str, ".", 2);

            empty_str = emu.memory().heap().allocate(1, 8);
            emu.mem_write(empty_str, "", 1);

            // Allocate and initialize lconv
            lconv_addr = emu.memory().heap().allocate(sizeof(guest_lconv), 8);

            guest_lconv lc = {};
            lc.decimal_point = dot_str;
            lc.thousands_sep = empty_str;
            lc.grouping = empty_str;
            lc.int_curr_symbol = empty_str;
            lc.currency_symbol = empty_str;
            lc.mon_decimal_point = empty_str;
            lc.mon_thousands_sep = empty_str;
            lc.mon_grouping = empty_str;
            lc.positive_sign = empty_str;
            lc.negative_sign = empty_str;
            lc.int_frac_digits = 127;
            lc.frac_digits = 127;
            lc.p_cs_precedes = 127;
            lc.p_sep_by_space = 127;
            lc.n_cs_precedes = 127;
            lc.n_sep_by_space = 127;
            lc.p_sign_posn = 127;
            lc.n_sign_posn = 127;
            lc.int_p_cs_precedes = 127;
            lc.int_p_sep_by_space = 127;
            lc.int_n_cs_precedes = 127;
            lc.int_n_sep_by_space = 127;
            lc.int_p_sign_posn = 127;
            lc.int_n_sign_posn = 127;

            emu.mem_write(lconv_addr, &lc, sizeof(lc));
        }

        set_reg(emu, UC_ARM64_REG_X0, lconv_addr);
    });

    // Static storage for nl_langinfo strings (bionic langinfo.h values)
    // CODESET=1, D_T_FMT=2, D_FMT=3, T_FMT=4, T_FMT_AMPM=5, AM_STR=6, PM_STR=7
    // DAY_1-7=8-14, ABDAY_1-7=15-21, MON_1-12=22-33, ABMON_1-12=34-45
    // ERA=46, ERA_D_FMT=47, ERA_D_T_FMT=48, ERA_T_FMT=49, ALT_DIGITS=50
    // RADIXCHAR=51, THOUSEP=52, YESEXPR=53, NOEXPR=54, CRNCYSTR=55
    static std::map<int, uint64_t> g_langinfo_strings;
    static bool g_langinfo_initialized = false;

    auto init_langinfo = [](Emulator& emu) {
        if (g_langinfo_initialized) return;

        auto alloc_str = [&emu](const char* s) -> uint64_t {
            size_t len = strlen(s) + 1;
            uint64_t addr = emu.memory().heap().allocate(len, 8);
            emu.mem_write(addr, s, len);
            return addr;
        };

        // Core strings for C.UTF-8 locale (bionic style)
        g_langinfo_strings[1] = alloc_str("UTF-8");          // CODESET
        g_langinfo_strings[2] = alloc_str("%F %T %z");       // D_T_FMT (bionic C locale uses ISO format)
        g_langinfo_strings[3] = alloc_str("%F");             // D_FMT
        g_langinfo_strings[4] = alloc_str("%T");             // T_FMT
        g_langinfo_strings[5] = alloc_str("%I:%M:%S %p");    // T_FMT_AMPM
        g_langinfo_strings[6] = alloc_str("AM");             // AM_STR
        g_langinfo_strings[7] = alloc_str("PM");             // PM_STR

        // Day names (DAY_1=Sunday through DAY_7=Saturday)
        g_langinfo_strings[8] = alloc_str("Sunday");
        g_langinfo_strings[9] = alloc_str("Monday");
        g_langinfo_strings[10] = alloc_str("Tuesday");
        g_langinfo_strings[11] = alloc_str("Wednesday");
        g_langinfo_strings[12] = alloc_str("Thursday");
        g_langinfo_strings[13] = alloc_str("Friday");
        g_langinfo_strings[14] = alloc_str("Saturday");

        // Abbreviated day names (ABDAY_1 through ABDAY_7)
        g_langinfo_strings[15] = alloc_str("Sun");
        g_langinfo_strings[16] = alloc_str("Mon");
        g_langinfo_strings[17] = alloc_str("Tue");
        g_langinfo_strings[18] = alloc_str("Wed");
        g_langinfo_strings[19] = alloc_str("Thu");
        g_langinfo_strings[20] = alloc_str("Fri");
        g_langinfo_strings[21] = alloc_str("Sat");

        // Month names (MON_1 through MON_12)
        g_langinfo_strings[22] = alloc_str("January");
        g_langinfo_strings[23] = alloc_str("February");
        g_langinfo_strings[24] = alloc_str("March");
        g_langinfo_strings[25] = alloc_str("April");
        g_langinfo_strings[26] = alloc_str("May");
        g_langinfo_strings[27] = alloc_str("June");
        g_langinfo_strings[28] = alloc_str("July");
        g_langinfo_strings[29] = alloc_str("August");
        g_langinfo_strings[30] = alloc_str("September");
        g_langinfo_strings[31] = alloc_str("October");
        g_langinfo_strings[32] = alloc_str("November");
        g_langinfo_strings[33] = alloc_str("December");

        // Abbreviated month names (ABMON_1 through ABMON_12)
        g_langinfo_strings[34] = alloc_str("Jan");
        g_langinfo_strings[35] = alloc_str("Feb");
        g_langinfo_strings[36] = alloc_str("Mar");
        g_langinfo_strings[37] = alloc_str("Apr");
        g_langinfo_strings[38] = alloc_str("May");
        g_langinfo_strings[39] = alloc_str("Jun");
        g_langinfo_strings[40] = alloc_str("Jul");
        g_langinfo_strings[41] = alloc_str("Aug");
        g_langinfo_strings[42] = alloc_str("Sep");
        g_langinfo_strings[43] = alloc_str("Oct");
        g_langinfo_strings[44] = alloc_str("Nov");
        g_langinfo_strings[45] = alloc_str("Dec");

        // ERA-related (not used in C locale)
        g_langinfo_strings[46] = alloc_str("");              // ERA
        g_langinfo_strings[47] = alloc_str("");              // ERA_D_FMT
        g_langinfo_strings[48] = alloc_str("");              // ERA_D_T_FMT
        g_langinfo_strings[49] = alloc_str("");              // ERA_T_FMT
        g_langinfo_strings[50] = alloc_str("");              // ALT_DIGITS

        // Numeric formatting
        g_langinfo_strings[51] = alloc_str(".");             // RADIXCHAR
        g_langinfo_strings[52] = alloc_str("");              // THOUSEP

        // Yes/No expressions
        g_langinfo_strings[53] = alloc_str("^[yY]");         // YESEXPR
        g_langinfo_strings[54] = alloc_str("^[nN]");         // NOEXPR

        // Currency (not defined in C locale)
        g_langinfo_strings[55] = alloc_str("");              // CRNCYSTR

        // Empty string for unknown items
        g_langinfo_strings[0] = alloc_str("");

        g_langinfo_initialized = true;
    };

    hle.register_function("nl_langinfo", [init_langinfo](Emulator& emu) {
        init_langinfo(emu);

        int item = get_reg(emu, UC_ARM64_REG_X0);

        auto it = g_langinfo_strings.find(item);
        if (it != g_langinfo_strings.end()) {
            set_reg(emu, UC_ARM64_REG_X0, it->second);
        } else {
            // Unknown item - return empty string
            set_reg(emu, UC_ARM64_REG_X0, g_langinfo_strings[0]);
        }
    });

    hle.register_function("nl_langinfo_l", [init_langinfo](Emulator& emu) {
        init_langinfo(emu);

        int item = get_reg(emu, UC_ARM64_REG_X0);
        // uint64_t locale = get_reg(emu, UC_ARM64_REG_X1);  // ignored - we only support C.UTF-8

        auto it = g_langinfo_strings.find(item);
        if (it != g_langinfo_strings.end()) {
            set_reg(emu, UC_ARM64_REG_X0, it->second);
        } else {
            set_reg(emu, UC_ARM64_REG_X0, g_langinfo_strings[0]);
        }
    });

    // ========================================================================
    // Extended locale functions
    // ========================================================================

    hle.register_function("newlocale", [](Emulator& emu) {
        // int category_mask = get_reg(emu, UC_ARM64_REG_X0);
        // uint64_t locale = get_reg(emu, UC_ARM64_REG_X1);
        // uint64_t base = get_reg(emu, UC_ARM64_REG_X2);

        // Return a fake locale handle
        set_reg(emu, UC_ARM64_REG_X0, g_current_locale);
    });

    hle.register_function("uselocale", [](Emulator& emu) {
        uint64_t newloc = get_reg(emu, UC_ARM64_REG_X0);

        uint64_t old = g_current_locale;

        if (newloc == 0) {
            // Query current
        } else if (newloc == static_cast<uint64_t>(-1)) {
            // LC_GLOBAL_LOCALE
            g_current_locale = g_c_locale;
        } else {
            g_current_locale = newloc;
        }

        set_reg(emu, UC_ARM64_REG_X0, old);
    });

    hle.register_function("freelocale", [](Emulator& emu) {
        // No-op for our fake locales
    });

    hle.register_function("duplocale", [](Emulator& emu) {
        // Return the same fake locale handle
        set_reg(emu, UC_ARM64_REG_X0, g_current_locale);
    });

    // ========================================================================
    // iconv
    // ========================================================================

    hle.register_function("iconv_open", [](Emulator& emu) {
        uint64_t tocode_addr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t fromcode_addr = get_reg(emu, UC_ARM64_REG_X1);

        if (tocode_addr == 0 || fromcode_addr == 0) {
            hle_set_errno(emu, EINVAL);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        std::string tocode = read_string(emu, tocode_addr);
        std::string fromcode = read_string(emu, fromcode_addr);

        errno = 0;
        iconv_t cd = ::iconv_open(tocode.c_str(), fromcode.c_str());
        int saved_errno = errno;

        if (cd == reinterpret_cast<iconv_t>(-1)) {
            std::string normalized_tocode = normalize_iconv_name(tocode);
            std::string normalized_fromcode = normalize_iconv_name(fromcode);

            if (normalized_tocode != tocode || normalized_fromcode != fromcode) {
                errno = 0;
                cd = ::iconv_open(normalized_tocode.c_str(), normalized_fromcode.c_str());
                saved_errno = errno;
            }
        }

        if (cd == reinterpret_cast<iconv_t>(-1)) {
            hle_set_errno(emu, saved_errno);
        } else {
            uint64_t handle = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(cd));
            g_iconv_descriptors[handle] = IconvDescriptor{
                cd,
                tocode,
                fromcode,
                iconv_uses_question_mark_translit(tocode),
            };
        }

        set_reg(emu, UC_ARM64_REG_X0,
                static_cast<uint64_t>(reinterpret_cast<uintptr_t>(cd)));
    });

    hle.register_function("iconv_close", [](Emulator& emu) {
        uint64_t handle = get_reg(emu, UC_ARM64_REG_X0);
        auto it = g_iconv_descriptors.find(handle);
        if (it == g_iconv_descriptors.end()) {
            hle_set_errno(emu, EBADF);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        iconv_t cd = it->second.host_cd;

        errno = 0;
        int result = ::iconv_close(cd);
        if (result == -1) {
            hle_set_errno(emu, errno);
        } else {
            g_iconv_descriptors.erase(it);
        }

        set_reg(emu, UC_ARM64_REG_X0,
                static_cast<uint64_t>(static_cast<int64_t>(result)));
    });

    hle.register_function("iconv", [](Emulator& emu) {
        uint64_t handle = get_reg(emu, UC_ARM64_REG_X0);
        auto it = g_iconv_descriptors.find(handle);
        if (it == g_iconv_descriptors.end()) {
            hle_set_errno(emu, EBADF);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        const IconvDescriptor& descriptor = it->second;
        iconv_t cd = descriptor.host_cd;
        uint64_t inbuf_ptr = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t inbytesleft_ptr = get_reg(emu, UC_ARM64_REG_X2);
        uint64_t outbuf_ptr = get_reg(emu, UC_ARM64_REG_X3);
        uint64_t outbytesleft_ptr = get_reg(emu, UC_ARM64_REG_X4);

        char* host_inbuf = nullptr;
        size_t host_inbytesleft = 0;
        char** host_inbuf_arg = nullptr;
        size_t* host_inbytesleft_arg = nullptr;

        if (inbuf_ptr != 0) {
            uint64_t guest_inbuf = 0;
            if (inbytesleft_ptr == 0 ||
                !emu.mem_read(inbuf_ptr, &guest_inbuf, sizeof(guest_inbuf)) ||
                !emu.mem_read(inbytesleft_ptr, &host_inbytesleft, sizeof(host_inbytesleft))) {
                hle_set_errno(emu, EFAULT);
                set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
                return;
            }

            if (guest_inbuf != 0) {
                host_inbuf = guest_addr_to_host_char_ptr(emu, guest_inbuf);
                if (host_inbuf == nullptr) {
                    hle_set_errno(emu, EFAULT);
                    set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
                    return;
                }
            }

            host_inbuf_arg = &host_inbuf;
            host_inbytesleft_arg = &host_inbytesleft;
        }

        char* host_outbuf = nullptr;
        size_t host_outbytesleft = 0;
        char** host_outbuf_arg = nullptr;
        size_t* host_outbytesleft_arg = nullptr;

        if (outbuf_ptr != 0) {
            uint64_t guest_outbuf = 0;
            if (outbytesleft_ptr == 0 ||
                !emu.mem_read(outbuf_ptr, &guest_outbuf, sizeof(guest_outbuf)) ||
                !emu.mem_read(outbytesleft_ptr, &host_outbytesleft, sizeof(host_outbytesleft))) {
                hle_set_errno(emu, EFAULT);
                set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
                return;
            }

            if (guest_outbuf != 0) {
                host_outbuf = guest_addr_to_host_char_ptr(emu, guest_outbuf);
                if (host_outbuf == nullptr) {
                    hle_set_errno(emu, EFAULT);
                    set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
                    return;
                }
            }

            host_outbuf_arg = &host_outbuf;
            host_outbytesleft_arg = &host_outbytesleft;
        }

        size_t result = 0;
        int saved_errno = 0;
        if (descriptor.ascii_question_translit &&
            canonicalize_iconv_base_name(descriptor.fromcode) == "utf8") {
            result = iconv_ascii_question_translit(host_inbuf_arg, host_inbytesleft_arg,
                                                  host_outbuf_arg, host_outbytesleft_arg,
                                                  saved_errno);
        } else {
            errno = 0;
            result = ::iconv(cd, host_inbuf_arg, host_inbytesleft_arg,
                             host_outbuf_arg, host_outbytesleft_arg);
            saved_errno = errno;
        }

        if (inbuf_ptr != 0) {
            uint64_t updated_inbuf = host_ptr_to_guest_addr(host_inbuf);
            emu.mem_write(inbuf_ptr, &updated_inbuf, sizeof(updated_inbuf));
            emu.mem_write(inbytesleft_ptr, &host_inbytesleft, sizeof(host_inbytesleft));
        }

        if (outbuf_ptr != 0) {
            uint64_t updated_outbuf = host_ptr_to_guest_addr(host_outbuf);
            emu.mem_write(outbuf_ptr, &updated_outbuf, sizeof(updated_outbuf));
            emu.mem_write(outbytesleft_ptr, &host_outbytesleft, sizeof(host_outbytesleft));
        }

        if (result == static_cast<size_t>(-1)) {
            hle_set_errno(emu, saved_errno);
        }

        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(result));
    });

    // ========================================================================
    // Multibyte/wide character conversion
    // ========================================================================

    hle.register_function("btowc", [](Emulator& emu) {
        int c = get_reg(emu, UC_ARM64_REG_X0);
        // For ASCII, just return the character
        if (c == EOF || c < 0 || c > 127) {
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));  // WEOF
        } else {
            set_reg(emu, UC_ARM64_REG_X0, c);
        }
    });

    hle.register_function("wctob", [](Emulator& emu) {
        uint32_t wc = get_reg(emu, UC_ARM64_REG_X0);
        if (wc > 127) {
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));  // EOF
        } else {
            set_reg(emu, UC_ARM64_REG_X0, wc);
        }
    });

    hle.register_function("mbstowcs", [](Emulator& emu) {
        uint64_t dest = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t src = get_reg(emu, UC_ARM64_REG_X1);
        size_t n = get_reg(emu, UC_ARM64_REG_X2);

        std::string str = read_string(emu, src);
        size_t converted = 0;

        for (size_t i = 0; i < str.length() && (dest == 0 || converted < n); i++) {
            if (dest != 0) {
                uint32_t wc = (unsigned char)str[i];
                emu.mem_write(dest + converted * 4, &wc, 4);
            }
            converted++;
        }

        // Null terminator
        if (dest != 0 && converted < n) {
            uint32_t null = 0;
            emu.mem_write(dest + converted * 4, &null, 4);
        }

        set_reg(emu, UC_ARM64_REG_X0, converted);
    });

    // Helper to get UTF-8 byte count for a code point
    auto wc_to_utf8_len = [](uint32_t wc) -> int {
        if (wc <= 0x7F) return 1;
        if (wc <= 0x7FF) return 2;
        if (wc <= 0xFFFF) return 3;
        if (wc <= 0x10FFFF) return 4;
        return -1;  // Invalid
    };

    // Helper to encode UTF-8
    auto wc_to_utf8 = [](uint32_t wc, uint8_t* buf) -> int {
        if (wc <= 0x7F) {
            buf[0] = wc;
            return 1;
        } else if (wc <= 0x7FF) {
            buf[0] = 0xC0 | (wc >> 6);
            buf[1] = 0x80 | (wc & 0x3F);
            return 2;
        } else if (wc <= 0xFFFF) {
            buf[0] = 0xE0 | (wc >> 12);
            buf[1] = 0x80 | ((wc >> 6) & 0x3F);
            buf[2] = 0x80 | (wc & 0x3F);
            return 3;
        } else if (wc <= 0x10FFFF) {
            buf[0] = 0xF0 | (wc >> 18);
            buf[1] = 0x80 | ((wc >> 12) & 0x3F);
            buf[2] = 0x80 | ((wc >> 6) & 0x3F);
            buf[3] = 0x80 | (wc & 0x3F);
            return 4;
        }
        return -1;  // Invalid
    };

    // mbstate_t layout (8 bytes):
    // Bytes 0-3: partial UTF-8 bytes (__seq)
    // Bytes 4-7: count of bytes consumed (__count)

    // Internal static state used when ps is NULL
    static uint8_t g_internal_mbstate[8] = {0};

    auto mbstate_is_initial = [](Emulator& emu, uint64_t ps) -> bool {
        if (ps == 0) {
            // Check internal state
            uint32_t count;
            memcpy(&count, g_internal_mbstate + 4, 4);
            return count == 0;
        }
        uint32_t count;
        emu.mem_read(ps + 4, &count, 4);
        return count == 0;
    };

    auto mbstate_reset = [](Emulator& emu, uint64_t ps) {
        if (ps == 0) {
            memset(g_internal_mbstate, 0, 8);
            return;
        }
        uint64_t zero = 0;
        emu.mem_write(ps, &zero, 8);
    };

    auto mbstate_get_partial = [](Emulator& emu, uint64_t ps, uint8_t* buf, uint32_t* count) {
        if (ps == 0) {
            memcpy(buf, g_internal_mbstate, 4);
            memcpy(count, g_internal_mbstate + 4, 4);
            return;
        }
        emu.mem_read(ps, buf, 4);
        emu.mem_read(ps + 4, count, 4);
    };

    auto mbstate_set_partial = [](Emulator& emu, uint64_t ps, const uint8_t* buf, uint32_t count) {
        if (ps == 0) {
            memcpy(g_internal_mbstate, buf, 4);
            memcpy(g_internal_mbstate + 4, &count, 4);
            return;
        }
        emu.mem_write(ps, buf, 4);
        emu.mem_write(ps + 4, &count, 4);
    };

    hle.register_function("wcstombs", [wc_to_utf8_len, wc_to_utf8](Emulator& emu) {
        uint64_t dest = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t src = get_reg(emu, UC_ARM64_REG_X1);
        size_t n = get_reg(emu, UC_ARM64_REG_X2);

        size_t byte_count = 0;
        size_t wc_idx = 0;

        while (true) {
            uint32_t wc;
            emu.mem_read(src + wc_idx * 4, &wc, 4);
            if (wc == 0) break;

            int char_len = wc_to_utf8_len(wc);
            if (char_len < 0) {
                // Invalid character - set EILSEQ and return -1
                int err = EILSEQ_VALUE;
                hle_set_errno(emu, err);
                set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
                return;
            }

            if (dest == 0) {
                // Counting mode - just count bytes
                byte_count += char_len;
            } else {
                // Check if there's room for this character
                if (byte_count + char_len > n) {
                    // Not enough space - stop without null terminator
                    break;
                }
                uint8_t buf[4];
                wc_to_utf8(wc, buf);
                emu.mem_write(dest + byte_count, buf, char_len);
                byte_count += char_len;
            }
            wc_idx++;
        }

        // Null terminator only if there's room (and dest is not NULL)
        if (dest != 0 && byte_count < n) {
            char null = 0;
            emu.mem_write(dest + byte_count, &null, 1);
        }

        set_reg(emu, UC_ARM64_REG_X0, byte_count);
    });

    hle.register_function("mbtowc", [](Emulator& emu) {
        uint64_t pwc = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t s = get_reg(emu, UC_ARM64_REG_X1);
        size_t n = get_reg(emu, UC_ARM64_REG_X2);

        if (s == 0) {
            set_reg(emu, UC_ARM64_REG_X0, 0);  // No state-dependent encoding
            return;
        }

        if (n == 0) {
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        uint8_t c;
        emu.mem_read(s, &c, 1);

        if (c == 0) {
            if (pwc) {
                uint32_t null = 0;
                emu.mem_write(pwc, &null, 4);
            }
            set_reg(emu, UC_ARM64_REG_X0, 0);
            return;
        }

        if (pwc) {
            uint32_t wc = c;
            emu.mem_write(pwc, &wc, 4);
        }
        set_reg(emu, UC_ARM64_REG_X0, 1);
    });

    hle.register_function("wctomb", [](Emulator& emu) {
        uint64_t s = get_reg(emu, UC_ARM64_REG_X0);
        uint32_t wc = get_reg(emu, UC_ARM64_REG_X1);

        if (s == 0) {
            set_reg(emu, UC_ARM64_REG_X0, 0);  // No state-dependent encoding
            return;
        }

        if (wc <= 127) {
            char c = wc;
            emu.mem_write(s, &c, 1);
            set_reg(emu, UC_ARM64_REG_X0, 1);
        } else {
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
        }
    });

    hle.register_function("wcrtomb", [mbstate_is_initial, mbstate_reset](Emulator& emu) {
        uint64_t s = get_reg(emu, UC_ARM64_REG_X0);
        uint32_t wc = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t ps = get_reg(emu, UC_ARM64_REG_X2);

        // If s is NULL, reset state and return 1
        if (s == 0) {
            mbstate_reset(emu, ps);
            set_reg(emu, UC_ARM64_REG_X0, 1);
            return;
        }

        // If wc is L'\0', write null byte, reset state, return 1
        // This takes priority over the non-initial state check
        if (wc == 0) {
            char c = 0;
            emu.mem_write(s, &c, 1);
            mbstate_reset(emu, ps);
            set_reg(emu, UC_ARM64_REG_X0, 1);
            return;
        }

        // If mbstate is non-initial, return error
        if (!mbstate_is_initial(emu, ps)) {
            int err = EILSEQ_VALUE;
            hle_set_errno(emu, err);
            mbstate_reset(emu, ps);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        if (wc <= 0x7F) {
            char c = wc;
            emu.mem_write(s, &c, 1);
            set_reg(emu, UC_ARM64_REG_X0, 1);
        } else if (wc <= 0x7FF) {
            char buf[2] = {
                static_cast<char>(0xC0 | (wc >> 6)),
                static_cast<char>(0x80 | (wc & 0x3F))
            };
            emu.mem_write(s, buf, 2);
            set_reg(emu, UC_ARM64_REG_X0, 2);
        } else if (wc <= 0xFFFF) {
            char buf[3] = {
                static_cast<char>(0xE0 | (wc >> 12)),
                static_cast<char>(0x80 | ((wc >> 6) & 0x3F)),
                static_cast<char>(0x80 | (wc & 0x3F))
            };
            emu.mem_write(s, buf, 3);
            set_reg(emu, UC_ARM64_REG_X0, 3);
        } else if (wc <= 0x10FFFF) {
            char buf[4] = {
                static_cast<char>(0xF0 | (wc >> 18)),
                static_cast<char>(0x80 | ((wc >> 12) & 0x3F)),
                static_cast<char>(0x80 | ((wc >> 6) & 0x3F)),
                static_cast<char>(0x80 | (wc & 0x3F))
            };
            emu.mem_write(s, buf, 4);
            set_reg(emu, UC_ARM64_REG_X0, 4);
        } else {
            // Invalid code point - set EILSEQ and return -1
            int err = EILSEQ_VALUE;
            hle_set_errno(emu, err);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
        }
    });

    hle.register_function("mbsinit", [mbstate_is_initial](Emulator& emu) {
        uint64_t ps = get_reg(emu, UC_ARM64_REG_X0);
        set_reg(emu, UC_ARM64_REG_X0, mbstate_is_initial(emu, ps) ? 1 : 0);
    });

    hle.register_function("mbrtowc", [mbstate_get_partial, mbstate_set_partial, mbstate_reset](Emulator& emu) {
        uint64_t pwc = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t s = get_reg(emu, UC_ARM64_REG_X1);
        size_t n = get_reg(emu, UC_ARM64_REG_X2);
        uint64_t ps = get_reg(emu, UC_ARM64_REG_X3);

        auto set_eilseq = [&emu, &ps, mbstate_reset]() {
            int err = EILSEQ_VALUE;
            hle_set_errno(emu, err);
            mbstate_reset(emu, ps);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
        };

        if (s == 0) {
            mbstate_reset(emu, ps);
            set_reg(emu, UC_ARM64_REG_X0, 0);
            return;
        }

        if (n == 0) {
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-2));
            return;
        }

        // Get any saved partial state
        uint8_t partial[4] = {0};
        uint32_t partial_count = 0;
        mbstate_get_partial(emu, ps, partial, &partial_count);

        // Combine partial with new input
        uint8_t bytes[8];
        size_t total_bytes = partial_count;
        for (size_t i = 0; i < partial_count && i < 4; i++) {
            bytes[i] = partial[i];
        }
        size_t new_bytes = std::min(n, (size_t)(4 - partial_count));
        emu.mem_read(s, bytes + partial_count, new_bytes);
        total_bytes += new_bytes;

        uint32_t wc;
        size_t expected_len;
        size_t consumed_new;  // How many new bytes consumed from s

        uint8_t lead = bytes[0];
        if ((lead & 0x80) == 0) {
            // ASCII - 1 byte
            expected_len = 1;
        } else if ((lead & 0xE0) == 0xC0) {
            // 2-byte sequence
            expected_len = 2;
        } else if ((lead & 0xF0) == 0xE0) {
            // 3-byte sequence
            expected_len = 3;
        } else if ((lead & 0xF8) == 0xF0) {
            // 4-byte sequence
            expected_len = 4;
        } else {
            // Invalid lead byte or continuation byte as lead
            set_eilseq();
            return;
        }

        // Check if we have enough bytes
        if (total_bytes < expected_len) {
            // Need more bytes - save state and return -2
            for (size_t i = partial_count; i < total_bytes && i < 4; i++) {
                partial[i] = bytes[i];
            }
            mbstate_set_partial(emu, ps, bytes, total_bytes);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-2));
            return;
        }

        // Now we have enough bytes - decode
        if (expected_len == 1) {
            wc = bytes[0];
            consumed_new = (partial_count >= 1) ? 0 : 1;
        } else if (expected_len == 2) {
            if ((bytes[1] & 0xC0) != 0x80) { set_eilseq(); return; }
            wc = ((bytes[0] & 0x1F) << 6) | (bytes[1] & 0x3F);
            if (wc < 0x80) { set_eilseq(); return; }  // Overlong
            consumed_new = (expected_len > partial_count) ? (expected_len - partial_count) : 0;
        } else if (expected_len == 3) {
            if ((bytes[1] & 0xC0) != 0x80 || (bytes[2] & 0xC0) != 0x80) { set_eilseq(); return; }
            wc = ((bytes[0] & 0x0F) << 12) | ((bytes[1] & 0x3F) << 6) | (bytes[2] & 0x3F);
            if (wc < 0x800) { set_eilseq(); return; }  // Overlong
            if (wc >= 0xD800 && wc <= 0xDFFF) { set_eilseq(); return; }  // Surrogates
            consumed_new = (expected_len > partial_count) ? (expected_len - partial_count) : 0;
        } else {  // expected_len == 4
            if ((bytes[1] & 0xC0) != 0x80 || (bytes[2] & 0xC0) != 0x80 || (bytes[3] & 0xC0) != 0x80) { set_eilseq(); return; }
            wc = ((bytes[0] & 0x07) << 18) | ((bytes[1] & 0x3F) << 12) |
                 ((bytes[2] & 0x3F) << 6) | (bytes[3] & 0x3F);
            if (wc < 0x10000) { set_eilseq(); return; }  // Overlong
            if (wc > 0x10FFFF) { set_eilseq(); return; }  // Out of range
            consumed_new = (expected_len > partial_count) ? (expected_len - partial_count) : 0;
        }

        // Success - reset state
        mbstate_reset(emu, ps);

        if (pwc) {
            emu.mem_write(pwc, &wc, 4);
        }
        set_reg(emu, UC_ARM64_REG_X0, wc == 0 ? 0 : consumed_new);
    });

    hle.register_function("mblen", [](Emulator& emu) {
        uint64_t s = get_reg(emu, UC_ARM64_REG_X0);
        size_t n = get_reg(emu, UC_ARM64_REG_X1);

        if (s == 0) {
            set_reg(emu, UC_ARM64_REG_X0, 0);
            return;
        }
        if (n == 0) {
            hle_set_errno(emu, EILSEQ);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        size_t available = std::min<size_t>(n, 4);
        unsigned char bytes[4] = {};
        emu.mem_read(s, bytes, available);
        if (bytes[0] == 0) {
            set_reg(emu, UC_ARM64_REG_X0, 0);
            return;
        }

        uint32_t codepoint = 0;
        size_t consumed = 0;
        Utf8DecodeStatus status = decode_utf8_codepoint(bytes, available, codepoint, consumed);
        if (status == Utf8DecodeStatus::Ok) {
            set_reg(emu, UC_ARM64_REG_X0, consumed);
        } else {
            hle_set_errno(emu, EILSEQ);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
        }
    });

    hle.register_function("mbrlen", [](Emulator& emu) {
        uint64_t s = get_reg(emu, UC_ARM64_REG_X0);
        size_t n = get_reg(emu, UC_ARM64_REG_X1);
        // uint64_t ps = get_reg(emu, UC_ARM64_REG_X2);

        if (s == 0 || n == 0) {
            set_reg(emu, UC_ARM64_REG_X0, n == 0 ? static_cast<uint64_t>(-2) : 0);
            return;
        }

        uint8_t c;
        emu.mem_read(s, &c, 1);
        set_reg(emu, UC_ARM64_REG_X0, c == 0 ? 0 : 1);
    });

    hle.register_function("mbsrtowcs", [mbstate_is_initial, mbstate_get_partial, mbstate_set_partial, mbstate_reset](Emulator& emu) {
        uint64_t dest = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t src_ptr = get_reg(emu, UC_ARM64_REG_X1);
        size_t len = get_reg(emu, UC_ARM64_REG_X2);
        uint64_t ps = get_reg(emu, UC_ARM64_REG_X3);

        uint64_t src = 0;
        emu.mem_read(src_ptr, &src, 8);
        const bool count_only = (dest == 0);

        // Get any saved partial state
        uint8_t partial[4] = {0};
        uint32_t partial_count = 0;
        mbstate_get_partial(emu, ps, partial, &partial_count);

        size_t wc_count = 0;
        size_t byte_pos = 0;

        while (count_only || wc_count < len) {
            unsigned char bytes[4] = {0};
            size_t available = partial_count;
            for (size_t i = 0; i < partial_count && i < 4; ++i) {
                bytes[i] = partial[i];
            }

            size_t newly_read = 0;
            while (available < 4) {
                unsigned char next = 0;
                emu.mem_read(src + byte_pos + newly_read, &next, 1);
                if (available == 0 && next == 0) {
                    if (!count_only && wc_count < len) {
                        uint32_t null_wc = 0;
                        emu.mem_write(dest + wc_count * 4, &null_wc, 4);
                        uint64_t null_ptr = 0;
                        emu.mem_write(src_ptr, &null_ptr, 8);
                    }
                    mbstate_reset(emu, ps);
                    set_reg(emu, UC_ARM64_REG_X0, wc_count);
                    return;
                }
                if (next == 0) {
                    break;
                }
                bytes[available++] = next;
                ++newly_read;
            }

            uint32_t wc = 0;
            size_t consumed = 0;
            Utf8DecodeStatus status = decode_utf8_codepoint(bytes, available, wc, consumed);
            if (status != Utf8DecodeStatus::Ok) {
                hle_set_errno(emu, EILSEQ_VALUE);
                if (!count_only) {
                    uint64_t error_src = src + byte_pos;
                    emu.mem_write(src_ptr, &error_src, 8);
                }
                mbstate_reset(emu, ps);
                set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
                return;
            }

            if (!count_only) {
                emu.mem_write(dest + wc_count * 4, &wc, 4);
            }
            ++wc_count;
            byte_pos += (consumed > partial_count) ? (consumed - partial_count) : 0;
            partial_count = 0;
        }

        if (!count_only) {
            uint64_t new_src = src + byte_pos;
            emu.mem_write(src_ptr, &new_src, 8);
        }
        mbstate_reset(emu, ps);
        set_reg(emu, UC_ARM64_REG_X0, wc_count);
    });

    hle.register_function("wcsrtombs", [wc_to_utf8_len, wc_to_utf8, mbstate_is_initial](Emulator& emu) {
        uint64_t dest = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t src_ptr = get_reg(emu, UC_ARM64_REG_X1);
        size_t n = get_reg(emu, UC_ARM64_REG_X2);
        uint64_t ps = get_reg(emu, UC_ARM64_REG_X3);

        // Check if mbstate_t is in non-initial state - this is an error for wcsrtombs
        if (!mbstate_is_initial(emu, ps)) {
            int err = EILSEQ_VALUE;
            hle_set_errno(emu, err);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        uint64_t src;
        emu.mem_read(src_ptr, &src, 8);
        uint64_t original_src = src;

        size_t byte_count = 0;

        if (dest == 0) {
            // Counting mode - count bytes for entire string, don't update src
            while (true) {
                uint32_t wc;
                emu.mem_read(src, &wc, 4);
                if (wc == 0) break;

                int char_len = wc_to_utf8_len(wc);
                if (char_len < 0) {
                    // Invalid character - set EILSEQ and return -1
                    // src pointer is NOT updated when dest is NULL
                    int err = EILSEQ_VALUE;
                    hle_set_errno(emu, err);
                    set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
                    return;
                }
                byte_count += char_len;
                src += 4;
            }
            // Don't update *src_ptr when dest is NULL
            set_reg(emu, UC_ARM64_REG_X0, byte_count);
            return;
        }

        // Conversion mode
        while (byte_count < n || n == 0) {
            uint32_t wc;
            emu.mem_read(src, &wc, 4);

            if (wc == 0) {
                // Null terminator - write it and set *src = NULL
                if (byte_count < n) {
                    char null = 0;
                    emu.mem_write(dest + byte_count, &null, 1);
                }
                uint64_t null_ptr = 0;
                emu.mem_write(src_ptr, &null_ptr, 8);
                set_reg(emu, UC_ARM64_REG_X0, byte_count);
                return;
            }

            int char_len = wc_to_utf8_len(wc);
            if (char_len < 0) {
                // Invalid character - set EILSEQ, update src to point to bad char
                int err = EILSEQ_VALUE;
                hle_set_errno(emu, err);
                emu.mem_write(src_ptr, &src, 8);
                set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
                return;
            }

            // Check if there's room
            if (byte_count + char_len > n) {
                // Not enough space - stop, update src to current position
                emu.mem_write(src_ptr, &src, 8);
                set_reg(emu, UC_ARM64_REG_X0, byte_count);
                return;
            }

            // Encode and write
            uint8_t buf[4];
            wc_to_utf8(wc, buf);
            emu.mem_write(dest + byte_count, buf, char_len);
            byte_count += char_len;
            src += 4;
        }

        // Reached n limit without finding null - update src
        emu.mem_write(src_ptr, &src, 8);
        set_reg(emu, UC_ARM64_REG_X0, byte_count);
    });

    hle.register_function("wcsnrtombs", [](Emulator& emu) {
        uint64_t dest = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t src_ptr = get_reg(emu, UC_ARM64_REG_X1);
        size_t nwc = get_reg(emu, UC_ARM64_REG_X2);
        size_t len = get_reg(emu, UC_ARM64_REG_X3);
        // uint64_t ps = get_reg(emu, UC_ARM64_REG_X4);

        uint64_t src;
        emu.mem_read(src_ptr, &src, 8);

        size_t converted = 0;
        size_t wc_read = 0;

        while (wc_read < nwc && (converted < len || dest == 0)) {
            uint32_t wc;
            emu.mem_read(src, &wc, 4);

            if (wc == 0) {
                if (dest != 0) {
                    char null = 0;
                    emu.mem_write(dest + converted, &null, 1);
                }
                break;
            }

            if (wc <= 127) {
                if (dest != 0 && converted < len) {
                    char c = wc;
                    emu.mem_write(dest + converted, &c, 1);
                    converted++;
                }
            }

            src += 4;
            wc_read++;
        }

        emu.mem_write(src_ptr, &src, 8);
        set_reg(emu, UC_ARM64_REG_X0, converted);
    });

    hle.register_function("mbsnrtowcs", [](Emulator& emu) {
        uint64_t dest = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t src_ptr = get_reg(emu, UC_ARM64_REG_X1);
        size_t nms = get_reg(emu, UC_ARM64_REG_X2);
        size_t len = get_reg(emu, UC_ARM64_REG_X3);
        // uint64_t ps = get_reg(emu, UC_ARM64_REG_X4);

        uint64_t src = 0;
        emu.mem_read(src_ptr, &src, 8);
        const bool count_only = (dest == 0);

        size_t converted = 0;
        size_t byte_pos = 0;

        while (byte_pos < nms && (count_only || converted < len)) {
            unsigned char first = 0;
            emu.mem_read(src + byte_pos, &first, 1);
            if (first == 0) {
                if (!count_only) {
                    uint32_t null_wc = 0;
                    emu.mem_write(dest + converted * 4, &null_wc, 4);
                    uint64_t null_ptr = 0;
                    emu.mem_write(src_ptr, &null_ptr, 8);
                }
                set_reg(emu, UC_ARM64_REG_X0, converted);
                return;
            }

            unsigned char bytes[4] = {0};
            size_t available = std::min<size_t>(4, nms - byte_pos);
            emu.mem_read(src + byte_pos, bytes, available);

            uint32_t wc = 0;
            size_t consumed = 0;
            Utf8DecodeStatus status = decode_utf8_codepoint(bytes, available, wc, consumed);
            if (status != Utf8DecodeStatus::Ok) {
                hle_set_errno(emu, EILSEQ_VALUE);
                if (!count_only) {
                    uint64_t error_src = src + byte_pos;
                    emu.mem_write(src_ptr, &error_src, 8);
                }
                set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
                return;
            }

            if (!count_only) {
                emu.mem_write(dest + converted * 4, &wc, 4);
            }
            ++converted;
            byte_pos += consumed;
        }

        if (!count_only) {
            uint64_t new_src = src + byte_pos;
            emu.mem_write(src_ptr, &new_src, 8);
        }
        set_reg(emu, UC_ARM64_REG_X0, converted);
    });

    hle.register_function("__ctype_get_mb_cur_max", [](Emulator& emu) {
        set_reg(emu, UC_ARM64_REG_X0, 4);  // UTF-8 max is 4 bytes
    });

    // ========================================================================
    // C11/C23 char16_t and char32_t conversion functions
    // ========================================================================

    // Static state for c16rtomb surrogate pair handling
    static uint16_t g_c16rtomb_high_surrogate = 0;

    // Static state for mbrtoc16 surrogate pair output
    // When we decode a 4-byte UTF-8, we output high surrogate first,
    // then on next call we return -3 and output low surrogate
    static uint16_t g_mbrtoc16_pending_low_surrogate = 0;

    // Internal mbstate storage for when ps is NULL
    static uint8_t g_mbrtoc16_internal_state[8] = {0};
    static uint8_t g_mbrtoc32_internal_state[8] = {0};
    static uint8_t g_c16rtomb_internal_state[8] = {0};
    static uint8_t g_c32rtomb_internal_state[8] = {0};

    // Helper to check if mbstate is initial (zero)
    auto uchar_mbstate_is_initial = [](Emulator& emu, uint64_t ps, uint8_t* internal_state) -> bool {
        if (ps == 0) {
            uint32_t count;
            memcpy(&count, internal_state + 4, 4);
            return count == 0;
        }
        uint32_t count;
        emu.mem_read(ps + 4, &count, 4);
        return count == 0;
    };

    auto uchar_mbstate_reset = [](Emulator& emu, uint64_t ps, uint8_t* internal_state) {
        if (ps == 0) {
            memset(internal_state, 0, 8);
            return;
        }
        uint64_t zero = 0;
        emu.mem_write(ps, &zero, 8);
    };

    auto uchar_mbstate_get_partial = [](Emulator& emu, uint64_t ps, uint8_t* internal_state, uint8_t* buf, uint32_t* count) {
        if (ps == 0) {
            memcpy(buf, internal_state, 4);
            memcpy(count, internal_state + 4, 4);
            return;
        }
        emu.mem_read(ps, buf, 4);
        emu.mem_read(ps + 4, count, 4);
    };

    auto uchar_mbstate_set_partial = [](Emulator& emu, uint64_t ps, uint8_t* internal_state, const uint8_t* buf, uint32_t count) {
        if (ps == 0) {
            memcpy(internal_state, buf, 4);
            memcpy(internal_state + 4, &count, 4);
            return;
        }
        emu.mem_write(ps, buf, 4);
        emu.mem_write(ps + 4, &count, 4);
    };

    hle.register_function("mbrtoc16", [uchar_mbstate_is_initial, uchar_mbstate_reset,
                                        uchar_mbstate_get_partial, uchar_mbstate_set_partial](Emulator& emu) {
        uint64_t pc16 = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t s = get_reg(emu, UC_ARM64_REG_X1);
        size_t n = get_reg(emu, UC_ARM64_REG_X2);
        uint64_t ps = get_reg(emu, UC_ARM64_REG_X3);

        // If there's a pending low surrogate from previous 4-byte decode, return it
        if (g_mbrtoc16_pending_low_surrogate != 0) {
            if (pc16) {
                emu.mem_write(pc16, &g_mbrtoc16_pending_low_surrogate, 2);
            }
            g_mbrtoc16_pending_low_surrogate = 0;
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-3));
            return;
        }

        if (s == 0) {
            uchar_mbstate_reset(emu, ps, g_mbrtoc16_internal_state);
            set_reg(emu, UC_ARM64_REG_X0, 0);
            return;
        }

        if (n == 0) {
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-2));
            return;
        }

        // Get any partial sequence from mbstate
        uint8_t partial[4] = {0};
        uint32_t partial_count = 0;
        uchar_mbstate_get_partial(emu, ps, g_mbrtoc16_internal_state, partial, &partial_count);

        // Combine partial with new input
        uint8_t bytes[8];
        size_t total_bytes = 0;
        if (partial_count > 0) {
            memcpy(bytes, partial, partial_count);
            total_bytes = partial_count;
        }
        size_t to_read = std::min(n, (size_t)(8 - total_bytes));
        emu.mem_read(s, bytes + total_bytes, to_read);
        total_bytes += to_read;

        // Determine expected length from first byte
        size_t expected_len;
        if ((bytes[0] & 0x80) == 0) {
            expected_len = 1;
        } else if ((bytes[0] & 0xE0) == 0xC0) {
            expected_len = 2;
        } else if ((bytes[0] & 0xF0) == 0xE0) {
            expected_len = 3;
        } else if ((bytes[0] & 0xF8) == 0xF0) {
            expected_len = 4;
        } else if ((bytes[0] & 0xFC) == 0xF8) {
            // 5-byte sequence (invalid in modern UTF-8, reject per bionic)
            int err = EILSEQ_VALUE;
            hle_set_errno(emu, err);
            uchar_mbstate_reset(emu, ps, g_mbrtoc16_internal_state);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        } else if ((bytes[0] & 0xFE) == 0xFC) {
            // 6-byte sequence (invalid)
            int err = EILSEQ_VALUE;
            hle_set_errno(emu, err);
            uchar_mbstate_reset(emu, ps, g_mbrtoc16_internal_state);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        } else {
            int err = EILSEQ_VALUE;
            hle_set_errno(emu, err);
            uchar_mbstate_reset(emu, ps, g_mbrtoc16_internal_state);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        // Check if we have enough bytes
        if (total_bytes < expected_len) {
            // Store partial sequence
            uchar_mbstate_set_partial(emu, ps, g_mbrtoc16_internal_state, bytes, total_bytes);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-2));
            return;
        }

        uint32_t codepoint;
        size_t len;

        if ((bytes[0] & 0x80) == 0) {
            codepoint = bytes[0];
            len = 1;
        } else if ((bytes[0] & 0xE0) == 0xC0) {
            if ((bytes[1] & 0xC0) != 0x80) {
                int err = EILSEQ_VALUE;
                hle_set_errno(emu, err);
                uchar_mbstate_reset(emu, ps, g_mbrtoc16_internal_state);
                set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
                return;
            }
            codepoint = ((bytes[0] & 0x1F) << 6) | (bytes[1] & 0x3F);
            // Check for overlong encoding
            if (codepoint < 0x80) {
                int err = EILSEQ_VALUE;
                hle_set_errno(emu, err);
                uchar_mbstate_reset(emu, ps, g_mbrtoc16_internal_state);
                set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
                return;
            }
            len = 2;
        } else if ((bytes[0] & 0xF0) == 0xE0) {
            if ((bytes[1] & 0xC0) != 0x80 || (bytes[2] & 0xC0) != 0x80) {
                int err = EILSEQ_VALUE;
                hle_set_errno(emu, err);
                uchar_mbstate_reset(emu, ps, g_mbrtoc16_internal_state);
                set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
                return;
            }
            codepoint = ((bytes[0] & 0x0F) << 12) | ((bytes[1] & 0x3F) << 6) | (bytes[2] & 0x3F);
            // Check for overlong encoding
            if (codepoint < 0x800) {
                int err = EILSEQ_VALUE;
                hle_set_errno(emu, err);
                uchar_mbstate_reset(emu, ps, g_mbrtoc16_internal_state);
                set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
                return;
            }
            len = 3;
        } else if ((bytes[0] & 0xF8) == 0xF0) {
            if ((bytes[1] & 0xC0) != 0x80 || (bytes[2] & 0xC0) != 0x80 || (bytes[3] & 0xC0) != 0x80) {
                int err = EILSEQ_VALUE;
                hle_set_errno(emu, err);
                uchar_mbstate_reset(emu, ps, g_mbrtoc16_internal_state);
                set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
                return;
            }
            codepoint = ((bytes[0] & 0x07) << 18) | ((bytes[1] & 0x3F) << 12) |
                        ((bytes[2] & 0x3F) << 6) | (bytes[3] & 0x3F);
            // Check for overlong encoding or out of range
            if (codepoint < 0x10000 || codepoint > 0x10FFFF) {
                int err = EILSEQ_VALUE;
                hle_set_errno(emu, err);
                uchar_mbstate_reset(emu, ps, g_mbrtoc16_internal_state);
                set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
                return;
            }
            len = 4;
        } else {
            int err = EILSEQ_VALUE;
            hle_set_errno(emu, err);
            uchar_mbstate_reset(emu, ps, g_mbrtoc16_internal_state);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        // Reset state since we consumed a complete character
        uchar_mbstate_reset(emu, ps, g_mbrtoc16_internal_state);

        // Calculate how many bytes we consumed from input (not from partial)
        size_t consumed_from_input = (len > partial_count) ? (len - partial_count) : 0;

        if (pc16) {
            if (codepoint <= 0xFFFF) {
                uint16_t c16 = codepoint;
                emu.mem_write(pc16, &c16, 2);
            } else {
                // Convert to surrogate pair
                uint32_t adjusted = codepoint - 0x10000;
                uint16_t high = 0xD800 + (adjusted >> 10);
                uint16_t low = 0xDC00 + (adjusted & 0x3FF);
                emu.mem_write(pc16, &high, 2);
                g_mbrtoc16_pending_low_surrogate = low;
            }
        } else if (codepoint > 0xFFFF) {
            // Even if pc16 is null, we need to set up for -3 return
            uint32_t adjusted = codepoint - 0x10000;
            uint16_t low = 0xDC00 + (adjusted & 0x3FF);
            g_mbrtoc16_pending_low_surrogate = low;
        }

        set_reg(emu, UC_ARM64_REG_X0, codepoint == 0 ? 0 : consumed_from_input);
    });

    hle.register_function("c16rtomb", [uchar_mbstate_is_initial, uchar_mbstate_reset](Emulator& emu) {
        uint64_t s = get_reg(emu, UC_ARM64_REG_X0);
        uint16_t c16 = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t ps = get_reg(emu, UC_ARM64_REG_X2);

        if (s == 0) {
            g_c16rtomb_high_surrogate = 0;
            uchar_mbstate_reset(emu, ps, g_c16rtomb_internal_state);
            set_reg(emu, UC_ARM64_REG_X0, 1);
            return;
        }

        if (c16 == 0) {
            g_c16rtomb_high_surrogate = 0;
            uchar_mbstate_reset(emu, ps, g_c16rtomb_internal_state);
            uint8_t null = 0;
            emu.mem_write(s, &null, 1);
            set_reg(emu, UC_ARM64_REG_X0, 1);
            return;
        }

        uint32_t codepoint;

        if (c16 >= 0xD800 && c16 <= 0xDBFF) {
            // High surrogate - error if we already have one pending
            if (g_c16rtomb_high_surrogate != 0) {
                g_c16rtomb_high_surrogate = 0;
                int err = EILSEQ_VALUE;
                hle_set_errno(emu, err);
                set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
                return;
            }
            // Save for next call
            g_c16rtomb_high_surrogate = c16;
            set_reg(emu, UC_ARM64_REG_X0, 0);
            return;
        } else if (c16 >= 0xDC00 && c16 <= 0xDFFF) {
            // Low surrogate - must have a high surrogate pending
            if (g_c16rtomb_high_surrogate == 0) {
                int err = EILSEQ_VALUE;
                hle_set_errno(emu, err);
                set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
                return;
            }
            uint32_t hi = g_c16rtomb_high_surrogate - 0xD800;
            uint32_t lo = c16 - 0xDC00;
            codepoint = (hi << 10) + lo + 0x10000;
            g_c16rtomb_high_surrogate = 0;
        } else {
            // Regular character - must not have a pending high surrogate
            if (g_c16rtomb_high_surrogate != 0) {
                g_c16rtomb_high_surrogate = 0;
                int err = EILSEQ_VALUE;
                hle_set_errno(emu, err);
                set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
                return;
            }
            codepoint = c16;
        }

        uint8_t buf[4];
        size_t len;

        if (codepoint <= 0x7F) {
            buf[0] = codepoint;
            len = 1;
        } else if (codepoint <= 0x7FF) {
            buf[0] = 0xC0 | (codepoint >> 6);
            buf[1] = 0x80 | (codepoint & 0x3F);
            len = 2;
        } else if (codepoint <= 0xFFFF) {
            buf[0] = 0xE0 | (codepoint >> 12);
            buf[1] = 0x80 | ((codepoint >> 6) & 0x3F);
            buf[2] = 0x80 | (codepoint & 0x3F);
            len = 3;
        } else {
            buf[0] = 0xF0 | (codepoint >> 18);
            buf[1] = 0x80 | ((codepoint >> 12) & 0x3F);
            buf[2] = 0x80 | ((codepoint >> 6) & 0x3F);
            buf[3] = 0x80 | (codepoint & 0x3F);
            len = 4;
        }

        emu.mem_write(s, buf, len);
        set_reg(emu, UC_ARM64_REG_X0, len);
    });

    hle.register_function("mbrtoc32", [uchar_mbstate_is_initial, uchar_mbstate_reset,
                                        uchar_mbstate_get_partial, uchar_mbstate_set_partial](Emulator& emu) {
        uint64_t pc32 = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t s = get_reg(emu, UC_ARM64_REG_X1);
        size_t n = get_reg(emu, UC_ARM64_REG_X2);
        uint64_t ps = get_reg(emu, UC_ARM64_REG_X3);

        if (s == 0) {
            uchar_mbstate_reset(emu, ps, g_mbrtoc32_internal_state);
            set_reg(emu, UC_ARM64_REG_X0, 0);
            return;
        }

        if (n == 0) {
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-2));
            return;
        }

        // Get any partial sequence from mbstate
        uint8_t partial[4] = {0};
        uint32_t partial_count = 0;
        uchar_mbstate_get_partial(emu, ps, g_mbrtoc32_internal_state, partial, &partial_count);

        // Combine partial with new input
        uint8_t bytes[8];
        size_t total_bytes = 0;
        if (partial_count > 0) {
            memcpy(bytes, partial, partial_count);
            total_bytes = partial_count;
        }
        size_t to_read = std::min(n, (size_t)(8 - total_bytes));
        emu.mem_read(s, bytes + total_bytes, to_read);
        total_bytes += to_read;

        // Determine expected length from first byte
        size_t expected_len;
        if ((bytes[0] & 0x80) == 0) {
            expected_len = 1;
        } else if ((bytes[0] & 0xE0) == 0xC0) {
            expected_len = 2;
        } else if ((bytes[0] & 0xF0) == 0xE0) {
            expected_len = 3;
        } else if ((bytes[0] & 0xF8) == 0xF0) {
            expected_len = 4;
        } else if ((bytes[0] & 0xFC) == 0xF8) {
            // 5-byte sequence (invalid in modern UTF-8)
            int err = EILSEQ_VALUE;
            hle_set_errno(emu, err);
            uchar_mbstate_reset(emu, ps, g_mbrtoc32_internal_state);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        } else if ((bytes[0] & 0xFE) == 0xFC) {
            // 6-byte sequence (invalid)
            int err = EILSEQ_VALUE;
            hle_set_errno(emu, err);
            uchar_mbstate_reset(emu, ps, g_mbrtoc32_internal_state);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        } else {
            int err = EILSEQ_VALUE;
            hle_set_errno(emu, err);
            uchar_mbstate_reset(emu, ps, g_mbrtoc32_internal_state);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        // Check if we have enough bytes
        if (total_bytes < expected_len) {
            // Store partial sequence
            uchar_mbstate_set_partial(emu, ps, g_mbrtoc32_internal_state, bytes, total_bytes);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-2));
            return;
        }

        uint32_t codepoint;
        size_t len;

        if ((bytes[0] & 0x80) == 0) {
            codepoint = bytes[0];
            len = 1;
        } else if ((bytes[0] & 0xE0) == 0xC0) {
            if ((bytes[1] & 0xC0) != 0x80) {
                int err = EILSEQ_VALUE;
                hle_set_errno(emu, err);
                uchar_mbstate_reset(emu, ps, g_mbrtoc32_internal_state);
                set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
                return;
            }
            codepoint = ((bytes[0] & 0x1F) << 6) | (bytes[1] & 0x3F);
            // Check for overlong encoding
            if (codepoint < 0x80) {
                int err = EILSEQ_VALUE;
                hle_set_errno(emu, err);
                uchar_mbstate_reset(emu, ps, g_mbrtoc32_internal_state);
                set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
                return;
            }
            len = 2;
        } else if ((bytes[0] & 0xF0) == 0xE0) {
            if ((bytes[1] & 0xC0) != 0x80 || (bytes[2] & 0xC0) != 0x80) {
                int err = EILSEQ_VALUE;
                hle_set_errno(emu, err);
                uchar_mbstate_reset(emu, ps, g_mbrtoc32_internal_state);
                set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
                return;
            }
            codepoint = ((bytes[0] & 0x0F) << 12) | ((bytes[1] & 0x3F) << 6) | (bytes[2] & 0x3F);
            // Check for overlong encoding
            if (codepoint < 0x800) {
                int err = EILSEQ_VALUE;
                hle_set_errno(emu, err);
                uchar_mbstate_reset(emu, ps, g_mbrtoc32_internal_state);
                set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
                return;
            }
            len = 3;
        } else if ((bytes[0] & 0xF8) == 0xF0) {
            if ((bytes[1] & 0xC0) != 0x80 || (bytes[2] & 0xC0) != 0x80 || (bytes[3] & 0xC0) != 0x80) {
                int err = EILSEQ_VALUE;
                hle_set_errno(emu, err);
                uchar_mbstate_reset(emu, ps, g_mbrtoc32_internal_state);
                set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
                return;
            }
            codepoint = ((bytes[0] & 0x07) << 18) | ((bytes[1] & 0x3F) << 12) |
                        ((bytes[2] & 0x3F) << 6) | (bytes[3] & 0x3F);
            // Check for overlong encoding or out of range
            if (codepoint < 0x10000 || codepoint > 0x10FFFF) {
                int err = EILSEQ_VALUE;
                hle_set_errno(emu, err);
                uchar_mbstate_reset(emu, ps, g_mbrtoc32_internal_state);
                set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
                return;
            }
            len = 4;
        } else {
            int err = EILSEQ_VALUE;
            hle_set_errno(emu, err);
            uchar_mbstate_reset(emu, ps, g_mbrtoc32_internal_state);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        // Reset state since we consumed a complete character
        uchar_mbstate_reset(emu, ps, g_mbrtoc32_internal_state);

        // Calculate how many bytes we consumed from input (not from partial)
        size_t consumed_from_input = (len > partial_count) ? (len - partial_count) : 0;

        if (pc32) {
            emu.mem_write(pc32, &codepoint, 4);
        }
        set_reg(emu, UC_ARM64_REG_X0, codepoint == 0 ? 0 : consumed_from_input);
    });

    hle.register_function("c32rtomb", [uchar_mbstate_is_initial, uchar_mbstate_reset](Emulator& emu) {
        uint64_t s = get_reg(emu, UC_ARM64_REG_X0);
        uint32_t c32 = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t ps = get_reg(emu, UC_ARM64_REG_X2);

        // If s is NULL, reset state and return 1
        if (s == 0) {
            uchar_mbstate_reset(emu, ps, g_c32rtomb_internal_state);
            set_reg(emu, UC_ARM64_REG_X0, 1);
            return;
        }

        // If c32 is L'\0', reset state, write null byte, return 1
        if (c32 == 0) {
            uchar_mbstate_reset(emu, ps, g_c32rtomb_internal_state);
            uint8_t null = 0;
            emu.mem_write(s, &null, 1);
            set_reg(emu, UC_ARM64_REG_X0, 1);
            return;
        }

        // If mbstate is non-initial (from a prior incomplete mbrtoc32), error
        if (!uchar_mbstate_is_initial(emu, ps, g_c32rtomb_internal_state)) {
            int err = EILSEQ_VALUE;
            hle_set_errno(emu, err);
            uchar_mbstate_reset(emu, ps, g_c32rtomb_internal_state);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        uint8_t buf[4];
        size_t len;

        if (c32 <= 0x7F) {
            buf[0] = c32;
            len = 1;
        } else if (c32 <= 0x7FF) {
            buf[0] = 0xC0 | (c32 >> 6);
            buf[1] = 0x80 | (c32 & 0x3F);
            len = 2;
        } else if (c32 <= 0xFFFF) {
            buf[0] = 0xE0 | (c32 >> 12);
            buf[1] = 0x80 | ((c32 >> 6) & 0x3F);
            buf[2] = 0x80 | (c32 & 0x3F);
            len = 3;
        } else if (c32 <= 0x10FFFF) {
            buf[0] = 0xF0 | (c32 >> 18);
            buf[1] = 0x80 | ((c32 >> 12) & 0x3F);
            buf[2] = 0x80 | ((c32 >> 6) & 0x3F);
            buf[3] = 0x80 | (c32 & 0x3F);
            len = 4;
        } else {
            int err = EILSEQ_VALUE;
            hle_set_errno(emu, err);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        emu.mem_write(s, buf, len);
        set_reg(emu, UC_ARM64_REG_X0, len);
    });
}

} // namespace cross_shim
