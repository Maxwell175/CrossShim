/**
 * HLE Syslog Functions
 * openlog, syslog, closelog, vsyslog
 */

#include "hle_manager.h"
#include "cross_shim.h"
#include "memory_manager.h"
#include "emu_compat.h"
#include <cstring>
#include <cstdio>

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

// Syslog state
static std::string g_syslog_ident;
static int g_syslog_option = 0;
static int g_syslog_facility = 0;
static int g_syslog_mask = 0xFF;  // All priorities enabled by default

void register_hle_syslog(HleManager& hle) {
    hle.register_function("openlog", [](Emulator& emu) {
        uint64_t ident_addr = get_reg(emu, UC_ARM64_REG_X0);
        g_syslog_option = get_reg(emu, UC_ARM64_REG_X1);
        g_syslog_facility = get_reg(emu, UC_ARM64_REG_X2);
        
        if (ident_addr) {
            g_syslog_ident = read_string(emu, ident_addr);
        }
        // No return value
    });

    hle.register_function("syslog", [](Emulator& emu) {
        int priority = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t format_addr = get_reg(emu, UC_ARM64_REG_X1);

        // Check if this priority is enabled in the mask
        int pri_level = priority & 0x7;
        if (!(g_syslog_mask & (1 << pri_level))) {
            return;  // Priority is masked out
        }

        std::string format = read_string(emu, format_addr);

        // Just print to stderr for debugging
        const char* level = "INFO";
        switch (pri_level) {
            case 0: level = "EMERG"; break;
            case 1: level = "ALERT"; break;
            case 2: level = "CRIT"; break;
            case 3: level = "ERR"; break;
            case 4: level = "WARNING"; break;
            case 5: level = "NOTICE"; break;
            case 6: level = "INFO"; break;
            case 7: level = "DEBUG"; break;
        }

        fprintf(stderr, "[%s] %s: %s\n", level, g_syslog_ident.c_str(), format.c_str());
    });

    hle.register_function("vsyslog", [](Emulator& emu) {
        // Same as syslog for our purposes
        int priority = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t format_addr = get_reg(emu, UC_ARM64_REG_X1);
        
        std::string format = read_string(emu, format_addr);
        fprintf(stderr, "[SYSLOG] %s: %s\n", g_syslog_ident.c_str(), format.c_str());
    });

    hle.register_function("closelog", [](Emulator& emu) {
        g_syslog_ident.clear();
        g_syslog_option = 0;
        g_syslog_facility = 0;
    });

    hle.register_function("setlogmask", [](Emulator& emu) {
        int mask = get_reg(emu, UC_ARM64_REG_X0);
        int old_mask = g_syslog_mask;
        if (mask != 0) {
            g_syslog_mask = mask;
        }
        set_reg(emu, UC_ARM64_REG_X0, old_mask);
    });
}

} // namespace cross_shim

