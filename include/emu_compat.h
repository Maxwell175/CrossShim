/**
 * Emulator Compatibility Layer
 *
 * This header provides compatibility macros and register access functions
 * for the QEMU-based ARM64 emulator.
 */

#ifndef EMU_COMPAT_H
#define EMU_COMPAT_H

#include "cross_shim.h"
#include "qemu_api.h"
#include <cstring>
#include <cstdio>

namespace cross_shim {

// Get the current CPU for HLE handlers
CPUState* get_current_cpu(Emulator& emu);

// =============================================================================
// Register Access Helper Functions
// =============================================================================

// Read a 64-bit general-purpose register
inline uint64_t get_reg(Emulator& emu, int reg) {
    CPUState* cpu = get_current_cpu(emu);
    if (!cpu) return 0;
    return qemu::read_reg(cpu, reg);
}

// Write a 64-bit general-purpose register
inline void set_reg(Emulator& emu, int reg, uint64_t value) {
    CPUState* cpu = get_current_cpu(emu);
    if (!cpu) return;
    qemu::write_reg(cpu, reg, value);
}

// Read a double-precision floating-point register (D0-D31 = lower 64 bits of V0-V31)
// NOTE: QEMU's libafl_qemu_read_reg may read up to 256 bytes for FP registers
inline double get_dreg(Emulator& emu, int reg) {
    CPUState* cpu = get_current_cpu(emu);
    if (!cpu) return 0.0;
    // FP registers start at REG_V0 = 34
    int fp_reg = qemu::REG_V0 + reg;
    uint8_t buf[512] = {0};  // Large buffer to avoid stack overflow
    libafl_qemu_read_reg(cpu, fp_reg, buf);
    double val;
    memcpy(&val, buf, sizeof(val));
    return val;
}

// Write a double-precision floating-point register
// NOTE: QEMU's libafl_qemu_read_reg/write_reg writes 256 bytes (all FP regs)
// when accessing FPU coprocessor registers, so we use a larger buffer.
inline void set_dreg(Emulator& emu, int reg, double value) {
    CPUState* cpu = get_current_cpu(emu);
    if (!cpu) return;
    int fp_reg = qemu::REG_V0 + reg;
    // QEMU writes 256 bytes (32 FP regs × 8 bytes) for FPU register access
    uint8_t buf[512] = {0};
    libafl_qemu_read_reg(cpu, fp_reg, buf);
    memcpy(buf, &value, sizeof(value));  // Modify lower 64 bits of V[reg]
    libafl_qemu_write_reg(cpu, fp_reg, buf);
}

// Read a single-precision floating-point register (S0-S31 = lower 32 bits of V0-V31)
// NOTE: QEMU's libafl_qemu_read_reg may read up to 256 bytes for FP registers
inline float get_sreg(Emulator& emu, int reg) {
    CPUState* cpu = get_current_cpu(emu);
    if (!cpu) return 0.0f;
    int fp_reg = qemu::REG_V0 + reg;
    uint8_t buf[512] = {0};  // Large buffer to avoid stack overflow
    libafl_qemu_read_reg(cpu, fp_reg, buf);
    float val;
    memcpy(&val, buf, sizeof(val));
    return val;
}

// Write a single-precision floating-point register
// NOTE: QEMU's libafl_qemu_read_reg/write_reg may read/write up to 256 bytes
inline void set_sreg(Emulator& emu, int reg, float value) {
    CPUState* cpu = get_current_cpu(emu);
    if (!cpu) return;
    int fp_reg = qemu::REG_V0 + reg;
    uint8_t buf[512] = {0};  // Large buffer to avoid stack overflow
    libafl_qemu_read_reg(cpu, fp_reg, buf);  // Read full register
    memcpy(buf, &value, sizeof(value));      // Modify lower 32 bits
    libafl_qemu_write_reg(cpu, fp_reg, buf);
}

// =============================================================================
// ARM64 Register Constants
// =============================================================================

constexpr int UC_ARM64_REG_X0 = qemu::REG_X0;
constexpr int UC_ARM64_REG_X1 = qemu::REG_X1;
constexpr int UC_ARM64_REG_X2 = qemu::REG_X2;
constexpr int UC_ARM64_REG_X3 = qemu::REG_X3;
constexpr int UC_ARM64_REG_X4 = qemu::REG_X4;
constexpr int UC_ARM64_REG_X5 = qemu::REG_X5;
constexpr int UC_ARM64_REG_X6 = qemu::REG_X6;
constexpr int UC_ARM64_REG_X7 = qemu::REG_X7;
constexpr int UC_ARM64_REG_X8 = qemu::REG_X8;
constexpr int UC_ARM64_REG_X9 = qemu::REG_X9;
constexpr int UC_ARM64_REG_X10 = qemu::REG_X10;
constexpr int UC_ARM64_REG_X11 = qemu::REG_X11;
constexpr int UC_ARM64_REG_X12 = qemu::REG_X12;
constexpr int UC_ARM64_REG_X13 = qemu::REG_X13;
constexpr int UC_ARM64_REG_X14 = qemu::REG_X14;
constexpr int UC_ARM64_REG_X15 = qemu::REG_X15;
constexpr int UC_ARM64_REG_X16 = qemu::REG_X16;
constexpr int UC_ARM64_REG_X17 = qemu::REG_X17;
constexpr int UC_ARM64_REG_X18 = qemu::REG_X18;
constexpr int UC_ARM64_REG_X19 = qemu::REG_X19;
constexpr int UC_ARM64_REG_X20 = qemu::REG_X20;
constexpr int UC_ARM64_REG_X21 = qemu::REG_X21;
constexpr int UC_ARM64_REG_X22 = qemu::REG_X22;
constexpr int UC_ARM64_REG_X23 = qemu::REG_X23;
constexpr int UC_ARM64_REG_X24 = qemu::REG_X24;
constexpr int UC_ARM64_REG_X25 = qemu::REG_X25;
constexpr int UC_ARM64_REG_X26 = qemu::REG_X26;
constexpr int UC_ARM64_REG_X27 = qemu::REG_X27;
constexpr int UC_ARM64_REG_X28 = qemu::REG_X28;
constexpr int UC_ARM64_REG_X29 = qemu::REG_X29;
constexpr int UC_ARM64_REG_X30 = qemu::REG_X30;
constexpr int UC_ARM64_REG_SP = qemu::REG_SP;
constexpr int UC_ARM64_REG_PC = qemu::REG_PC;
constexpr int UC_ARM64_REG_LR = qemu::REG_LR;
constexpr int UC_ARM64_REG_FP = qemu::REG_FP;
constexpr int UC_ARM64_REG_NZCV = qemu::REG_CPSR;

// SIMD/FP double register aliases (D0-D7 = lower 64 bits of V0-V7)
// Note: These map to the FPU coprocessor registers starting at index 34
constexpr int UC_ARM64_REG_D0 = qemu::REG_V0;
constexpr int UC_ARM64_REG_D1 = qemu::REG_V1;
constexpr int UC_ARM64_REG_D2 = qemu::REG_V2;
constexpr int UC_ARM64_REG_D3 = qemu::REG_V3;
constexpr int UC_ARM64_REG_D4 = qemu::REG_V4;
constexpr int UC_ARM64_REG_D5 = qemu::REG_V5;
constexpr int UC_ARM64_REG_D6 = qemu::REG_V6;
constexpr int UC_ARM64_REG_D7 = qemu::REG_V7;

// SIMD/FP single register aliases (S0-S7 = lower 32 bits of V0-V7)
// Note: These map to the same FPU registers - S and D share the V registers
constexpr int UC_ARM64_REG_S0 = qemu::REG_V0;
constexpr int UC_ARM64_REG_S1 = qemu::REG_V1;
constexpr int UC_ARM64_REG_S2 = qemu::REG_V2;
constexpr int UC_ARM64_REG_S3 = qemu::REG_V3;
constexpr int UC_ARM64_REG_S4 = qemu::REG_V4;
constexpr int UC_ARM64_REG_S5 = qemu::REG_V5;
constexpr int UC_ARM64_REG_S6 = qemu::REG_V6;
constexpr int UC_ARM64_REG_S7 = qemu::REG_V7;

// TLS register (TPIDR_EL0) - matches LibAFL QEMU register numbering
constexpr int UC_ARM64_REG_TPIDR_EL0 = qemu::REG_TPIDR_EL0;

// NEON/SIMD Q registers (Q0-Q31 = 128-bit V0-V31)
// Note: These are mapped to the same indices as V registers
constexpr int UC_ARM64_REG_Q0 = qemu::REG_V0;
constexpr int UC_ARM64_REG_Q1 = qemu::REG_V1;
constexpr int UC_ARM64_REG_Q2 = qemu::REG_V2;
constexpr int UC_ARM64_REG_Q3 = qemu::REG_V3;
constexpr int UC_ARM64_REG_Q4 = qemu::REG_V4;
constexpr int UC_ARM64_REG_Q5 = qemu::REG_V5;
constexpr int UC_ARM64_REG_Q6 = qemu::REG_V6;
constexpr int UC_ARM64_REG_Q7 = qemu::REG_V7;
constexpr int UC_ARM64_REG_Q8 = qemu::REG_V8;
constexpr int UC_ARM64_REG_Q9 = qemu::REG_V9;
constexpr int UC_ARM64_REG_Q10 = qemu::REG_V10;
constexpr int UC_ARM64_REG_Q11 = qemu::REG_V11;
constexpr int UC_ARM64_REG_Q12 = qemu::REG_V12;
constexpr int UC_ARM64_REG_Q13 = qemu::REG_V13;
constexpr int UC_ARM64_REG_Q14 = qemu::REG_V14;
constexpr int UC_ARM64_REG_Q15 = qemu::REG_V15;
constexpr int UC_ARM64_REG_Q16 = qemu::REG_V16;
constexpr int UC_ARM64_REG_Q17 = qemu::REG_V17;
constexpr int UC_ARM64_REG_Q18 = qemu::REG_V18;
constexpr int UC_ARM64_REG_Q19 = qemu::REG_V19;
constexpr int UC_ARM64_REG_Q20 = qemu::REG_V20;
constexpr int UC_ARM64_REG_Q21 = qemu::REG_V21;
constexpr int UC_ARM64_REG_Q22 = qemu::REG_V22;
constexpr int UC_ARM64_REG_Q23 = qemu::REG_V23;
constexpr int UC_ARM64_REG_Q24 = qemu::REG_V24;
constexpr int UC_ARM64_REG_Q25 = qemu::REG_V25;
constexpr int UC_ARM64_REG_Q26 = qemu::REG_V26;
constexpr int UC_ARM64_REG_Q27 = qemu::REG_V27;
constexpr int UC_ARM64_REG_Q28 = qemu::REG_V28;
constexpr int UC_ARM64_REG_Q29 = qemu::REG_V29;
constexpr int UC_ARM64_REG_Q30 = qemu::REG_V30;
constexpr int UC_ARM64_REG_Q31 = qemu::REG_V31;

// Floating-point control/status registers (after V0-V31 in FPU coprocessor)
constexpr int UC_ARM64_REG_FPSR = qemu::REG_FPSR;
constexpr int UC_ARM64_REG_FPCR = qemu::REG_FPCR;

// =============================================================================
// Extended Register Access for 128-bit SIMD registers
// =============================================================================

// Read a 128-bit Q register
inline void get_qreg(Emulator& emu, int reg, uint8_t buf[16]) {
    CPUState* cpu = get_current_cpu(emu);
    if (!cpu) {
        memset(buf, 0, 16);
        return;
    }
    libafl_qemu_read_reg(cpu, reg, buf);
}

// Write a 128-bit Q register
inline void set_qreg(Emulator& emu, int reg, const uint8_t buf[16]) {
    CPUState* cpu = get_current_cpu(emu);
    if (!cpu) return;
    libafl_qemu_write_reg(cpu, reg, const_cast<uint8_t*>(buf));
}

// Read 128-bit Q register as __int128 (or two uint64_t)
inline void get_vreg(Emulator& emu, int reg, uint64_t val[2]) {
    CPUState* cpu = get_current_cpu(emu);
    if (!cpu) {
        val[0] = val[1] = 0;
        return;
    }
    libafl_qemu_read_reg(cpu, reg, reinterpret_cast<uint8_t*>(val));
}

// Write 128-bit Q register from two uint64_t
inline void set_vreg(Emulator& emu, int reg, const uint64_t val[2]) {
    CPUState* cpu = get_current_cpu(emu);
    if (!cpu) return;
    libafl_qemu_write_reg(cpu, reg, reinterpret_cast<uint8_t*>(const_cast<uint64_t*>(val)));
}

} // namespace cross_shim

#endif // EMU_COMPAT_H
