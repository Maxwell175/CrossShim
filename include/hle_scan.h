#pragma once

#include <cstdint>

namespace cross_shim {

class Emulator;

struct HleScanResult {
    bool ok = false;
    int result = -1;
    int error = 0;
};

HleScanResult hle_scan_from_regs(Emulator& emu, uint64_t input_addr, uint64_t fmt_addr,
                                 int first_arg_reg, bool wide_strings);
HleScanResult hle_scan_from_va_list(Emulator& emu, uint64_t input_addr, uint64_t fmt_addr,
                                    uint64_t va_list_addr, bool wide_strings);

}  // namespace cross_shim
