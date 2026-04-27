#pragma once

#include <cstdint>
#include <string>

namespace cross_shim {

class Emulator;

struct HleFormatResult {
    bool ok = false;
    int result = -1;
    int error = 0;
    std::string output;
};

HleFormatResult hle_format_from_regs(Emulator& emu, uint64_t fmt_addr, int first_arg_reg,
                                     bool wide_format);
HleFormatResult hle_format_from_va_list(Emulator& emu, uint64_t fmt_addr, uint64_t va_list_addr,
                                        bool wide_format);

}  // namespace cross_shim
