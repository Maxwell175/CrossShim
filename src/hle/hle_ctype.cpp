/**
 * HLE Character Classification Functions
 * Standard: isalpha, isdigit, isalnum, isspace, isupper, islower, isprint, ispunct, isxdigit, iscntrl, isgraph, isblank
 * Case conversion: toupper, tolower
 * Wide: iswalnum, iswalpha, iswblank, iswcntrl, iswdigit, iswgraph, iswlower, iswprint, iswpunct, iswspace, iswupper, iswxdigit
 * Wide classification: iswctype, wctype, towupper, towlower, towctrans, wctrans
 * Width: wcwidth, wcswidth
 * Locale variants: all *_l functions
 */

#include "debug_log.h"
#include "hle_manager.h"
#include "cross_shim.h"
#include "memory_manager.h"
#include "emu_compat.h"
#include <cctype>
#include <cwctype>
#include <locale.h>
#include <wctype.h>
#include <cerrno>
#include <mutex>

namespace cross_shim {

static constexpr int EINVAL_VALUE = 22;

namespace {

#ifndef LC_CTYPE_MASK
#define LC_CTYPE_MASK (1 << LC_CTYPE)
#endif

static locale_t host_utf8_locale() {
    static std::once_flag once;
    static locale_t locale = nullptr;

    std::call_once(once, [] {
        static constexpr const char* kLocaleNames[] = {
            "C.UTF-8",
            "C.utf8",
            "en_US.UTF-8",
        };

        for (const char* name : kLocaleNames) {
            locale = ::newlocale(LC_CTYPE_MASK, name, nullptr);
            if (locale != nullptr) {
                return;
            }
        }
    });

    return locale;
}

template <typename Fn>
static auto with_utf8_locale(Fn&& fn) -> decltype(fn()) {
    locale_t locale = host_utf8_locale();
    if (locale == nullptr) {
        return fn();
    }

    locale_t previous = ::uselocale(locale);
    auto result = fn();
    ::uselocale(previous);
    return result;
}

static wint_t guest_wint(uint64_t raw) {
    return static_cast<wint_t>(static_cast<uint32_t>(raw));
}

static int unicode_iswalnum(uint32_t wc) {
    locale_t locale = host_utf8_locale();
    return (locale ? ::iswalnum_l(static_cast<wint_t>(wc), locale) : ::iswalnum(static_cast<wint_t>(wc))) ? 1 : 0;
}

static int unicode_iswalpha(uint32_t wc) {
    locale_t locale = host_utf8_locale();
    return (locale ? ::iswalpha_l(static_cast<wint_t>(wc), locale) : ::iswalpha(static_cast<wint_t>(wc))) ? 1 : 0;
}

static int unicode_iswblank(uint32_t wc) {
    locale_t locale = host_utf8_locale();
    return (locale ? ::iswblank_l(static_cast<wint_t>(wc), locale) : ::iswblank(static_cast<wint_t>(wc))) ? 1 : 0;
}

static int unicode_iswcntrl(uint32_t wc) {
    locale_t locale = host_utf8_locale();
    return (locale ? ::iswcntrl_l(static_cast<wint_t>(wc), locale) : ::iswcntrl(static_cast<wint_t>(wc))) ? 1 : 0;
}

static int unicode_iswdigit(uint32_t wc) {
    locale_t locale = host_utf8_locale();
    return (locale ? ::iswdigit_l(static_cast<wint_t>(wc), locale) : ::iswdigit(static_cast<wint_t>(wc))) ? 1 : 0;
}

static int unicode_iswgraph(uint32_t wc) {
    locale_t locale = host_utf8_locale();
    return (locale ? ::iswgraph_l(static_cast<wint_t>(wc), locale) : ::iswgraph(static_cast<wint_t>(wc))) ? 1 : 0;
}

static int unicode_iswlower(uint32_t wc) {
    locale_t locale = host_utf8_locale();
    return (locale ? ::iswlower_l(static_cast<wint_t>(wc), locale) : ::iswlower(static_cast<wint_t>(wc))) ? 1 : 0;
}

static int unicode_iswprint(uint32_t wc) {
    locale_t locale = host_utf8_locale();
    return (locale ? ::iswprint_l(static_cast<wint_t>(wc), locale) : ::iswprint(static_cast<wint_t>(wc))) ? 1 : 0;
}

static int unicode_iswpunct(uint32_t wc) {
    locale_t locale = host_utf8_locale();
    return (locale ? ::iswpunct_l(static_cast<wint_t>(wc), locale) : ::iswpunct(static_cast<wint_t>(wc))) ? 1 : 0;
}

static int unicode_iswspace(uint32_t wc) {
    locale_t locale = host_utf8_locale();
    return (locale ? ::iswspace_l(static_cast<wint_t>(wc), locale) : ::iswspace(static_cast<wint_t>(wc))) ? 1 : 0;
}

static int unicode_iswupper(uint32_t wc) {
    locale_t locale = host_utf8_locale();
    return (locale ? ::iswupper_l(static_cast<wint_t>(wc), locale) : ::iswupper(static_cast<wint_t>(wc))) ? 1 : 0;
}

static int unicode_iswxdigit(uint32_t wc) {
    locale_t locale = host_utf8_locale();
    return (locale ? ::iswxdigit_l(static_cast<wint_t>(wc), locale) : ::iswxdigit(static_cast<wint_t>(wc))) ? 1 : 0;
}

static uint32_t unicode_towlower(uint32_t wc) {
    locale_t locale = host_utf8_locale();
    wint_t result = locale ? ::towlower_l(static_cast<wint_t>(wc), locale) : ::towlower(static_cast<wint_t>(wc));
    return static_cast<uint32_t>(result);
}

static uint32_t unicode_towupper(uint32_t wc) {
    locale_t locale = host_utf8_locale();
    wint_t result = locale ? ::towupper_l(static_cast<wint_t>(wc), locale) : ::towupper(static_cast<wint_t>(wc));
    return static_cast<uint32_t>(result);
}

static bool is_default_ignorable_width_zero(uint32_t wc) {
    return (wc >= 0xfff0 && wc <= 0xfff7) || (wc >= 0xe0000 && wc <= 0xe0fff);
}

static int unicode_wcwidth(uint32_t wc) {
    if (wc == 0) {
        return 0;
    }
    if (wc > 0x10ffff || (wc >= 0xd800 && wc <= 0xdfff)) {
        return -1;
    }
    if (is_default_ignorable_width_zero(wc)) {
        return 0;
    }

    return with_utf8_locale([&] {
        return ::wcwidth(static_cast<wchar_t>(wc));
    });
}

}  // namespace

void register_hle_ctype(HleManager& hle) {
    // ========================================================================
    // Standard character classification
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
        set_reg(emu, UC_ARM64_REG_X0, (c == ' ' || c == '\t') ? 1 : 0);
    });

    hle.register_function("isascii", [](Emulator& emu) {
        int c = get_reg(emu, UC_ARM64_REG_X0);
        set_reg(emu, UC_ARM64_REG_X0, (c >= 0 && c <= 127) ? 1 : 0);
    });

    // ========================================================================
    // Case conversion
    // ========================================================================

    hle.register_function("toupper", [](Emulator& emu) {
        int c = get_reg(emu, UC_ARM64_REG_X0);
        set_reg(emu, UC_ARM64_REG_X0, toupper(c));
    });

    hle.register_function("tolower", [](Emulator& emu) {
        int c = get_reg(emu, UC_ARM64_REG_X0);
        set_reg(emu, UC_ARM64_REG_X0, tolower(c));
    });

    hle.register_function("toascii", [](Emulator& emu) {
        int c = get_reg(emu, UC_ARM64_REG_X0);
        set_reg(emu, UC_ARM64_REG_X0, c & 0x7F);
    });

    // ========================================================================
    // Locale-aware character classification (*_l variants)
    // ========================================================================

    hle.register_function("isalpha_l", [](Emulator& emu) {
        int c = get_reg(emu, UC_ARM64_REG_X0);
        // locale ignored
        set_reg(emu, UC_ARM64_REG_X0, isalpha(c) ? 1 : 0);
    });

    hle.register_function("isdigit_l", [](Emulator& emu) {
        int c = get_reg(emu, UC_ARM64_REG_X0);
        set_reg(emu, UC_ARM64_REG_X0, isdigit(c) ? 1 : 0);
    });

    hle.register_function("isalnum_l", [](Emulator& emu) {
        int c = get_reg(emu, UC_ARM64_REG_X0);
        set_reg(emu, UC_ARM64_REG_X0, isalnum(c) ? 1 : 0);
    });

    hle.register_function("isspace_l", [](Emulator& emu) {
        int c = get_reg(emu, UC_ARM64_REG_X0);
        set_reg(emu, UC_ARM64_REG_X0, isspace(c) ? 1 : 0);
    });

    hle.register_function("isupper_l", [](Emulator& emu) {
        int c = get_reg(emu, UC_ARM64_REG_X0);
        set_reg(emu, UC_ARM64_REG_X0, isupper(c) ? 1 : 0);
    });

    hle.register_function("islower_l", [](Emulator& emu) {
        int c = get_reg(emu, UC_ARM64_REG_X0);
        set_reg(emu, UC_ARM64_REG_X0, islower(c) ? 1 : 0);
    });

    hle.register_function("isprint_l", [](Emulator& emu) {
        int c = get_reg(emu, UC_ARM64_REG_X0);
        set_reg(emu, UC_ARM64_REG_X0, isprint(c) ? 1 : 0);
    });

    hle.register_function("ispunct_l", [](Emulator& emu) {
        int c = get_reg(emu, UC_ARM64_REG_X0);
        set_reg(emu, UC_ARM64_REG_X0, ispunct(c) ? 1 : 0);
    });

    hle.register_function("isxdigit_l", [](Emulator& emu) {
        int c = get_reg(emu, UC_ARM64_REG_X0);
        set_reg(emu, UC_ARM64_REG_X0, isxdigit(c) ? 1 : 0);
    });

    hle.register_function("iscntrl_l", [](Emulator& emu) {
        int c = get_reg(emu, UC_ARM64_REG_X0);
        set_reg(emu, UC_ARM64_REG_X0, iscntrl(c) ? 1 : 0);
    });

    hle.register_function("isgraph_l", [](Emulator& emu) {
        int c = get_reg(emu, UC_ARM64_REG_X0);
        set_reg(emu, UC_ARM64_REG_X0, isgraph(c) ? 1 : 0);
    });

    hle.register_function("isblank_l", [](Emulator& emu) {
        int c = get_reg(emu, UC_ARM64_REG_X0);
        set_reg(emu, UC_ARM64_REG_X0, (c == ' ' || c == '\t') ? 1 : 0);
    });

    hle.register_function("toupper_l", [](Emulator& emu) {
        int c = get_reg(emu, UC_ARM64_REG_X0);
        set_reg(emu, UC_ARM64_REG_X0, toupper(c));
    });

    hle.register_function("tolower_l", [](Emulator& emu) {
        int c = get_reg(emu, UC_ARM64_REG_X0);
        set_reg(emu, UC_ARM64_REG_X0, tolower(c));
    });

    // ========================================================================
    // Wide character classification
    // ========================================================================

    hle.register_function("iswalnum", [](Emulator& emu) {
        uint32_t wc = get_reg(emu, UC_ARM64_REG_X0);
        set_reg(emu, UC_ARM64_REG_X0, unicode_iswalnum(wc));
    });

    hle.register_function("iswalpha", [](Emulator& emu) {
        uint32_t wc = get_reg(emu, UC_ARM64_REG_X0);
        set_reg(emu, UC_ARM64_REG_X0, unicode_iswalpha(wc));
    });

    hle.register_function("iswblank", [](Emulator& emu) {
        uint32_t wc = get_reg(emu, UC_ARM64_REG_X0);
        set_reg(emu, UC_ARM64_REG_X0, unicode_iswblank(wc));
    });

    hle.register_function("iswcntrl", [](Emulator& emu) {
        uint32_t wc = get_reg(emu, UC_ARM64_REG_X0);
        set_reg(emu, UC_ARM64_REG_X0, unicode_iswcntrl(wc));
    });

    hle.register_function("iswdigit", [](Emulator& emu) {
        uint32_t wc = get_reg(emu, UC_ARM64_REG_X0);
        set_reg(emu, UC_ARM64_REG_X0, unicode_iswdigit(wc));
    });

    hle.register_function("iswgraph", [](Emulator& emu) {
        uint32_t wc = get_reg(emu, UC_ARM64_REG_X0);
        set_reg(emu, UC_ARM64_REG_X0, unicode_iswgraph(wc));
    });

    hle.register_function("iswlower", [](Emulator& emu) {
        uint32_t wc = get_reg(emu, UC_ARM64_REG_X0);
        set_reg(emu, UC_ARM64_REG_X0, unicode_iswlower(wc));
    });

    hle.register_function("iswprint", [](Emulator& emu) {
        uint32_t wc = get_reg(emu, UC_ARM64_REG_X0);
        set_reg(emu, UC_ARM64_REG_X0, unicode_iswprint(wc));
    });

    hle.register_function("iswpunct", [](Emulator& emu) {
        uint32_t wc = get_reg(emu, UC_ARM64_REG_X0);
        set_reg(emu, UC_ARM64_REG_X0, unicode_iswpunct(wc));
    });

    hle.register_function("iswspace", [](Emulator& emu) {
        uint32_t wc = get_reg(emu, UC_ARM64_REG_X0);
        set_reg(emu, UC_ARM64_REG_X0, unicode_iswspace(wc));
    });

    hle.register_function("iswupper", [](Emulator& emu) {
        uint32_t wc = get_reg(emu, UC_ARM64_REG_X0);
        set_reg(emu, UC_ARM64_REG_X0, unicode_iswupper(wc));
    });

    hle.register_function("iswxdigit", [](Emulator& emu) {
        uint32_t wc = get_reg(emu, UC_ARM64_REG_X0);
        set_reg(emu, UC_ARM64_REG_X0, unicode_iswxdigit(wc));
    });

    // ========================================================================
    // Locale-aware wide character classification
    // ========================================================================

    hle.register_function("iswalnum_l", [](Emulator& emu) {
        uint32_t wc = get_reg(emu, UC_ARM64_REG_X0);
        set_reg(emu, UC_ARM64_REG_X0, unicode_iswalnum(wc));
    });

    hle.register_function("iswalpha_l", [](Emulator& emu) {
        uint32_t wc = get_reg(emu, UC_ARM64_REG_X0);
        set_reg(emu, UC_ARM64_REG_X0, unicode_iswalpha(wc));
    });

    hle.register_function("iswblank_l", [](Emulator& emu) {
        uint32_t wc = get_reg(emu, UC_ARM64_REG_X0);
        set_reg(emu, UC_ARM64_REG_X0, unicode_iswblank(wc));
    });

    hle.register_function("iswcntrl_l", [](Emulator& emu) {
        uint32_t wc = get_reg(emu, UC_ARM64_REG_X0);
        set_reg(emu, UC_ARM64_REG_X0, unicode_iswcntrl(wc));
    });

    hle.register_function("iswdigit_l", [](Emulator& emu) {
        uint32_t wc = get_reg(emu, UC_ARM64_REG_X0);
        set_reg(emu, UC_ARM64_REG_X0, unicode_iswdigit(wc));
    });

    hle.register_function("iswgraph_l", [](Emulator& emu) {
        uint32_t wc = get_reg(emu, UC_ARM64_REG_X0);
        set_reg(emu, UC_ARM64_REG_X0, unicode_iswgraph(wc));
    });

    hle.register_function("iswlower_l", [](Emulator& emu) {
        uint32_t wc = get_reg(emu, UC_ARM64_REG_X0);
        set_reg(emu, UC_ARM64_REG_X0, unicode_iswlower(wc));
    });

    hle.register_function("iswprint_l", [](Emulator& emu) {
        uint32_t wc = get_reg(emu, UC_ARM64_REG_X0);
        set_reg(emu, UC_ARM64_REG_X0, unicode_iswprint(wc));
    });

    hle.register_function("iswpunct_l", [](Emulator& emu) {
        uint32_t wc = get_reg(emu, UC_ARM64_REG_X0);
        set_reg(emu, UC_ARM64_REG_X0, unicode_iswpunct(wc));
    });

    hle.register_function("iswspace_l", [](Emulator& emu) {
        uint32_t wc = get_reg(emu, UC_ARM64_REG_X0);
        set_reg(emu, UC_ARM64_REG_X0, unicode_iswspace(wc));
    });

    hle.register_function("iswupper_l", [](Emulator& emu) {
        uint32_t wc = get_reg(emu, UC_ARM64_REG_X0);
        set_reg(emu, UC_ARM64_REG_X0, unicode_iswupper(wc));
    });

    hle.register_function("iswxdigit_l", [](Emulator& emu) {
        uint32_t wc = get_reg(emu, UC_ARM64_REG_X0);
        set_reg(emu, UC_ARM64_REG_X0, unicode_iswxdigit(wc));
    });

    // ========================================================================
    // Wide character case conversion
    // ========================================================================

    hle.register_function("towlower", [](Emulator& emu) {
        uint32_t wc = get_reg(emu, UC_ARM64_REG_X0);
        set_reg(emu, UC_ARM64_REG_X0, unicode_towlower(wc));
    });

    hle.register_function("towupper", [](Emulator& emu) {
        uint32_t wc = get_reg(emu, UC_ARM64_REG_X0);
        set_reg(emu, UC_ARM64_REG_X0, unicode_towupper(wc));
    });

    hle.register_function("towlower_l", [](Emulator& emu) {
        uint32_t wc = get_reg(emu, UC_ARM64_REG_X0);
        set_reg(emu, UC_ARM64_REG_X0, unicode_towlower(wc));
    });

    hle.register_function("towupper_l", [](Emulator& emu) {
        uint32_t wc = get_reg(emu, UC_ARM64_REG_X0);
        set_reg(emu, UC_ARM64_REG_X0, unicode_towupper(wc));
    });

    // ========================================================================
    // Wide character classification types
    // ========================================================================

    hle.register_function("iswctype", [](Emulator& emu) {
        wint_t wc = guest_wint(get_reg(emu, UC_ARM64_REG_X0));
        wctype_t desc = get_reg(emu, UC_ARM64_REG_X1);
        set_reg(emu, UC_ARM64_REG_X0, iswctype(wc, desc) ? 1 : 0);
    });

    hle.register_function("iswctype_l", [](Emulator& emu) {
        wint_t wc = guest_wint(get_reg(emu, UC_ARM64_REG_X0));
        wctype_t desc = get_reg(emu, UC_ARM64_REG_X1);
        set_reg(emu, UC_ARM64_REG_X0, iswctype(wc, desc) ? 1 : 0);
    });

    hle.register_function("wctype", [](Emulator& emu) {
        uint64_t name_ptr = get_reg(emu, UC_ARM64_REG_X0);
        char name[32] = {};
        for (size_t i = 0; i < 31; i++) {
            char c;
            emu.mem_read(name_ptr + i, &c, 1);
            if (c == 0) break;
            name[i] = c;
        }
        set_reg(emu, UC_ARM64_REG_X0, wctype(name));
    });

    hle.register_function("wctype_l", [](Emulator& emu) {
        uint64_t name_ptr = get_reg(emu, UC_ARM64_REG_X0);
        char name[32] = {};
        for (size_t i = 0; i < 31; i++) {
            char c;
            emu.mem_read(name_ptr + i, &c, 1);
            if (c == 0) break;
            name[i] = c;
        }
        set_reg(emu, UC_ARM64_REG_X0, wctype(name));
    });

    hle.register_function("towctrans", [](Emulator& emu) {
        wint_t wc = guest_wint(get_reg(emu, UC_ARM64_REG_X0));
        wctrans_t desc = reinterpret_cast<wctrans_t>(get_reg(emu, UC_ARM64_REG_X1));
        if (desc == 0) {
            // Invalid descriptor - set errno to EINVAL
            int err = EINVAL_VALUE;
            hle_set_errno(emu, err);
            set_reg(emu, UC_ARM64_REG_X0, wc);  // Return unchanged character
        } else {
            set_reg(emu, UC_ARM64_REG_X0, towctrans(wc, desc));
        }
    });

    hle.register_function("towctrans_l", [](Emulator& emu) {
        wint_t wc = guest_wint(get_reg(emu, UC_ARM64_REG_X0));
        wctrans_t desc = reinterpret_cast<wctrans_t>(get_reg(emu, UC_ARM64_REG_X1));
        if (desc == 0) {
            // Invalid descriptor - set errno to EINVAL
            int err = EINVAL_VALUE;
            hle_set_errno(emu, err);
            set_reg(emu, UC_ARM64_REG_X0, wc);  // Return unchanged character
        } else {
            set_reg(emu, UC_ARM64_REG_X0, towctrans(wc, desc));
        }
    });

    hle.register_function("wctrans", [](Emulator& emu) {
        uint64_t name_ptr = get_reg(emu, UC_ARM64_REG_X0);
        char name[32] = {};
        for (size_t i = 0; i < 31; i++) {
            char c;
            emu.mem_read(name_ptr + i, &c, 1);
            if (c == 0) break;
            name[i] = c;
        }
        wctrans_t result = wctrans(name);
        if (result == 0) {
            // Unknown property name - set errno to EINVAL
            int err = EINVAL_VALUE;
            hle_set_errno(emu, err);
        }
        set_reg(emu, UC_ARM64_REG_X0, reinterpret_cast<uint64_t>(result));
    });

    hle.register_function("wctrans_l", [](Emulator& emu) {
        uint64_t name_ptr = get_reg(emu, UC_ARM64_REG_X0);
        char name[32] = {};
        for (size_t i = 0; i < 31; i++) {
            char c;
            emu.mem_read(name_ptr + i, &c, 1);
            if (c == 0) break;
            name[i] = c;
        }
        wctrans_t result = wctrans(name);
        if (result == 0) {
            // Unknown property name - set errno to EINVAL
            int err = EINVAL_VALUE;
            hle_set_errno(emu, err);
        }
        set_reg(emu, UC_ARM64_REG_X0, reinterpret_cast<uint64_t>(result));
    });

    // ========================================================================
    // Character width functions
    // ========================================================================

    hle.register_function("wcwidth", [](Emulator& emu) {
        uint32_t wc = get_reg(emu, UC_ARM64_REG_X0);
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(static_cast<int64_t>(unicode_wcwidth(wc))));
    });

    hle.register_function("wcswidth", [](Emulator& emu) {
        uint64_t ws = get_reg(emu, UC_ARM64_REG_X0);
        size_t n = get_reg(emu, UC_ARM64_REG_X1);

        int width = 0;
        for (size_t i = 0; i < n; i++) {
            uint32_t wc;
            emu.mem_read(ws + i * 4, &wc, 4);
            if (wc == 0) break;

            int w = unicode_wcwidth(wc);
            if (w < 0) {
                set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(static_cast<int64_t>(-1)));
                return;
            }
            width += w;
        }
        set_reg(emu, UC_ARM64_REG_X0, width);
    });
}

} // namespace cross_shim
