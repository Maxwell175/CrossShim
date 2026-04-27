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
// reg is a simple index 0-31, mapped to QEMU's V registers
inline double get_dreg(Emulator& emu, int reg) {
    CPUState* cpu = get_current_cpu(emu);
    if (!cpu) return 0.0;
    int fp_reg = qemu::REG_V0 + reg;
    std::array<uint8_t, qemu::MAX_REGISTER_BYTES> buf{};
    qemu::read_reg_bytes(cpu, fp_reg, buf.data(), buf.size());
    double val;
    memcpy(&val, buf.data(), sizeof(val));
    return val;
}

// Write a double-precision floating-point register
// reg is a simple index 0-31, mapped to QEMU's V registers
inline void set_dreg(Emulator& emu, int reg, double value) {
    CPUState* cpu = get_current_cpu(emu);
    if (!cpu) return;
    int fp_reg = qemu::REG_V0 + reg;
    std::array<uint8_t, qemu::MAX_REGISTER_BYTES> buf{};
    qemu::read_reg_bytes(cpu, fp_reg, buf.data(), buf.size());
    memcpy(buf.data(), &value, sizeof(value));  // Modify lower 64 bits of V[reg]
    qemu::write_reg_bytes(cpu, fp_reg, buf.data(), buf.size());
}

// Read a single-precision floating-point register (S0-S31 = lower 32 bits of V0-V31)
// reg is a simple index 0-31, mapped to QEMU's V registers
inline float get_sreg(Emulator& emu, int reg) {
    CPUState* cpu = get_current_cpu(emu);
    if (!cpu) return 0.0f;
    int fp_reg = qemu::REG_V0 + reg;
    std::array<uint8_t, qemu::MAX_REGISTER_BYTES> buf{};
    qemu::read_reg_bytes(cpu, fp_reg, buf.data(), buf.size());
    float val;
    memcpy(&val, buf.data(), sizeof(val));
    return val;
}

// Write a single-precision floating-point register
// reg is a simple index 0-31, mapped to QEMU's V registers
inline void set_sreg(Emulator& emu, int reg, float value) {
    CPUState* cpu = get_current_cpu(emu);
    if (!cpu) return;
    int fp_reg = qemu::REG_V0 + reg;
    std::array<uint8_t, qemu::MAX_REGISTER_BYTES> buf{};
    qemu::read_reg_bytes(cpu, fp_reg, buf.data(), buf.size());  // Read full register
    memcpy(buf.data(), &value, sizeof(value));                  // Modify lower 32 bits
    qemu::write_reg_bytes(cpu, fp_reg, buf.data(), buf.size());
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

// SIMD/FP double register indices for use with get_dreg/set_dreg
// These are indices 0-7, the functions add REG_V0 base internally
constexpr int UC_ARM64_REG_D0 = 0;
constexpr int UC_ARM64_REG_D1 = 1;
constexpr int UC_ARM64_REG_D2 = 2;
constexpr int UC_ARM64_REG_D3 = 3;
constexpr int UC_ARM64_REG_D4 = 4;
constexpr int UC_ARM64_REG_D5 = 5;
constexpr int UC_ARM64_REG_D6 = 6;
constexpr int UC_ARM64_REG_D7 = 7;

// SIMD/FP single register indices for use with get_sreg/set_sreg
// These are indices 0-7, the functions add REG_V0 base internally
constexpr int UC_ARM64_REG_S0 = 0;
constexpr int UC_ARM64_REG_S1 = 1;
constexpr int UC_ARM64_REG_S2 = 2;
constexpr int UC_ARM64_REG_S3 = 3;
constexpr int UC_ARM64_REG_S4 = 4;
constexpr int UC_ARM64_REG_S5 = 5;
constexpr int UC_ARM64_REG_S6 = 6;
constexpr int UC_ARM64_REG_S7 = 7;

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
    qemu::read_reg_bytes(cpu, reg, buf, 16);
}

// Write a 128-bit Q register
inline void set_qreg(Emulator& emu, int reg, const uint8_t buf[16]) {
    CPUState* cpu = get_current_cpu(emu);
    if (!cpu) return;
    qemu::write_reg_bytes(cpu, reg, buf, 16);
}

// Read 128-bit Q register as __int128 (or two uint64_t)
inline void get_vreg(Emulator& emu, int reg, uint64_t val[2]) {
    CPUState* cpu = get_current_cpu(emu);
    if (!cpu) {
        val[0] = val[1] = 0;
        return;
    }
    qemu::read_reg_bytes(cpu, reg, reinterpret_cast<uint8_t*>(val), sizeof(uint64_t) * 2);
}

// Write 128-bit Q register from two uint64_t
inline void set_vreg(Emulator& emu, int reg, const uint64_t val[2]) {
    CPUState* cpu = get_current_cpu(emu);
    if (!cpu) return;
    qemu::write_reg_bytes(cpu, reg, val, sizeof(uint64_t) * 2);
}

// =============================================================================
// Long Double (128-bit IEEE 754 binary128) Register Access
// =============================================================================

// Read a long double from Q register (128-bit IEEE 754 binary128)
// On ARM64, long double is passed in Q registers (full 128-bit V registers)
// Note: x86-64 host doesn't natively support 128-bit long double, so we use
// software conversion via the __float128 type if available, or approximate with double
inline long double get_ldreg(Emulator& emu, int reg) {
    CPUState* cpu = get_current_cpu(emu);
    if (!cpu) return 0.0L;

    int fp_reg = qemu::REG_V0 + reg;
    std::array<uint8_t, qemu::MAX_REGISTER_BYTES> buf{};
    qemu::read_reg_bytes(cpu, fp_reg, buf.data(), buf.size());

    // ARM64 uses IEEE 754 binary128 (quad precision) for long double
    // On x86-64, we need to convert from binary128 to host long double
    // Since glibc on x86-64 typically uses 80-bit extended precision for long double,
    // we do a best-effort conversion using __float128 if available
#if defined(__GNUC__) && (defined(__x86_64__) || defined(__aarch64__))
    // Use __float128 which maps to IEEE 754 binary128
    __float128 quad_val;
    memcpy(&quad_val, buf.data(), 16);
    return static_cast<long double>(quad_val);
#else
    // Fallback: just read as double from the lower 64 bits
    // This loses precision but is better than nothing
    double d;
    memcpy(&d, buf.data(), sizeof(d));
    return static_cast<long double>(d);
#endif
}

// Write a long double to Q register (128-bit IEEE 754 binary128)
inline void set_ldreg(Emulator& emu, int reg, long double value) {
    CPUState* cpu = get_current_cpu(emu);
    if (!cpu) return;

    int fp_reg = qemu::REG_V0 + reg;
    std::array<uint8_t, qemu::MAX_REGISTER_BYTES> buf{};

    // First read the existing register content
    qemu::read_reg_bytes(cpu, fp_reg, buf.data(), buf.size());

#if defined(__GNUC__) && (defined(__x86_64__) || defined(__aarch64__))
    // Convert to __float128 which maps to IEEE 754 binary128
    __float128 quad_val = static_cast<__float128>(value);
    memcpy(buf.data(), &quad_val, 16);
#else
    // Fallback: write as double to lower 64 bits
    double d = static_cast<double>(value);
    memcpy(buf.data(), &d, sizeof(d));
#endif

    qemu::write_reg_bytes(cpu, fp_reg, buf.data(), buf.size());
}

// Write a long double to guest memory in ARM64 binary128 format
inline void write_ld_to_guest(Emulator& emu, uint64_t addr, long double value) {
#if defined(__GNUC__) && (defined(__x86_64__) || defined(__aarch64__))
    // Convert to __float128 which maps to IEEE 754 binary128
    __float128 quad_val = static_cast<__float128>(value);
    emu.mem_write(addr, &quad_val, 16);
#else
    // Fallback: write as double to lower 64 bits
    uint8_t buf[16] = {0};
    double d = static_cast<double>(value);
    memcpy(buf, &d, sizeof(d));
    emu.mem_write(addr, buf, 16);
#endif
}

// =============================================================================
// FPCR/FPSR Register Access for Floating-Point Environment
// =============================================================================

// Read FPCR (Floating-Point Control Register)
// Bits 22-23: Rounding mode (RMode)
//   00 = Round to Nearest (even)
//   01 = Round toward Plus Infinity
//   10 = Round toward Minus Infinity
//   11 = Round toward Zero
inline uint32_t get_fpcr(Emulator& emu) {
    CPUState* cpu = get_current_cpu(emu);
    if (!cpu) return 0;
    std::array<uint8_t, qemu::MAX_REGISTER_BYTES> buf{};
    qemu::read_reg_bytes(cpu, qemu::REG_FPCR, buf.data(), buf.size());
    uint32_t val;
    memcpy(&val, buf.data(), sizeof(val));
    return val;
}

// Write FPCR
inline void set_fpcr(Emulator& emu, uint32_t value) {
    CPUState* cpu = get_current_cpu(emu);
    if (!cpu) return;
    std::array<uint8_t, qemu::MAX_REGISTER_BYTES> buf{};
    memcpy(buf.data(), &value, sizeof(value));
    qemu::write_reg_bytes(cpu, qemu::REG_FPCR, buf.data(), buf.size());
}

// Read FPSR (Floating-Point Status Register)
// Lower bits contain exception flags:
//   Bit 0: IOC (Invalid Operation Cumulative)
//   Bit 1: DZC (Division by Zero Cumulative)
//   Bit 2: OFC (Overflow Cumulative)
//   Bit 3: UFC (Underflow Cumulative)
//   Bit 4: IXC (Inexact Cumulative)
//   Bit 7: IDC (Input Denormal Cumulative)
inline uint32_t get_fpsr(Emulator& emu) {
    CPUState* cpu = get_current_cpu(emu);
    if (!cpu) return 0;
    std::array<uint8_t, qemu::MAX_REGISTER_BYTES> buf{};
    qemu::read_reg_bytes(cpu, qemu::REG_FPSR, buf.data(), buf.size());
    uint32_t val;
    memcpy(&val, buf.data(), sizeof(val));
    return val;
}

// Write FPSR
inline void set_fpsr(Emulator& emu, uint32_t value) {
    CPUState* cpu = get_current_cpu(emu);
    if (!cpu) return;
    std::array<uint8_t, qemu::MAX_REGISTER_BYTES> buf{};
    memcpy(buf.data(), &value, sizeof(value));
    qemu::write_reg_bytes(cpu, qemu::REG_FPSR, buf.data(), buf.size());
}

// ARM64 rounding mode constants (bits 22-23 of FPCR)
constexpr uint32_t ARM64_FPCR_RMODE_SHIFT = 22;
constexpr uint32_t ARM64_FPCR_RMODE_MASK = 0x3 << ARM64_FPCR_RMODE_SHIFT;
constexpr uint32_t ARM64_RMODE_RN = 0;  // Round to Nearest (even)
constexpr uint32_t ARM64_RMODE_RP = 1;  // Round toward Plus Infinity
constexpr uint32_t ARM64_RMODE_RM = 2;  // Round toward Minus Infinity
constexpr uint32_t ARM64_RMODE_RZ = 3;  // Round toward Zero

// FPSR exception flag bits
constexpr uint32_t ARM64_FPSR_IOC = 1 << 0;  // Invalid Operation
constexpr uint32_t ARM64_FPSR_DZC = 1 << 1;  // Division by Zero
constexpr uint32_t ARM64_FPSR_OFC = 1 << 2;  // Overflow
constexpr uint32_t ARM64_FPSR_UFC = 1 << 3;  // Underflow
constexpr uint32_t ARM64_FPSR_IXC = 1 << 4;  // Inexact
constexpr uint32_t ARM64_FPSR_IDC = 1 << 7;  // Input Denormal

} // namespace cross_shim

#endif // EMU_COMPAT_H
