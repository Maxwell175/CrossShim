/**
 * HLE Math Functions (libm)
 * sin, cos, tan, asin, acos, atan, atan2
 * sinh, cosh, tanh, asinh, acosh, atanh
 * exp, exp2, log, log2, log10, pow, sqrt, cbrt
 * floor, ceil, round, trunc, fabs, fmod, remainder
 * Single precision (f suffix) variants
 */

#include "hle_manager.h"
#include "cross_shim.h"
#include "memory_manager.h"
#include "emu_compat.h"
#include <cmath>
#include <climits>

namespace cross_shim {

// get_dreg, set_dreg, get_sreg, set_sreg are provided by emu_compat.h

void register_hle_math(HleManager& hle) {
    // ========================================================================
    // Trigonometric (double)
    // ========================================================================
    
    hle.register_function("sin", [](Emulator& emu) {
        set_dreg(emu, 0, sin(get_dreg(emu, 0)));
    });
    hle.register_function("cos", [](Emulator& emu) {
        set_dreg(emu, 0, cos(get_dreg(emu, 0)));
    });
    hle.register_function("tan", [](Emulator& emu) {
        set_dreg(emu, 0, tan(get_dreg(emu, 0)));
    });
    hle.register_function("asin", [](Emulator& emu) {
        set_dreg(emu, 0, asin(get_dreg(emu, 0)));
    });
    hle.register_function("acos", [](Emulator& emu) {
        set_dreg(emu, 0, acos(get_dreg(emu, 0)));
    });
    hle.register_function("atan", [](Emulator& emu) {
        set_dreg(emu, 0, atan(get_dreg(emu, 0)));
    });
    hle.register_function("atan2", [](Emulator& emu) {
        double y = get_dreg(emu, 0);
        double x = get_dreg(emu, 1);
        set_dreg(emu, 0, atan2(y, x));
    });

    // ========================================================================
    // Hyperbolic (double)
    // ========================================================================
    
    hle.register_function("sinh", [](Emulator& emu) {
        set_dreg(emu, 0, sinh(get_dreg(emu, 0)));
    });
    hle.register_function("cosh", [](Emulator& emu) {
        set_dreg(emu, 0, cosh(get_dreg(emu, 0)));
    });
    hle.register_function("tanh", [](Emulator& emu) {
        set_dreg(emu, 0, tanh(get_dreg(emu, 0)));
    });
    hle.register_function("asinh", [](Emulator& emu) {
        set_dreg(emu, 0, asinh(get_dreg(emu, 0)));
    });
    hle.register_function("acosh", [](Emulator& emu) {
        set_dreg(emu, 0, acosh(get_dreg(emu, 0)));
    });
    hle.register_function("atanh", [](Emulator& emu) {
        set_dreg(emu, 0, atanh(get_dreg(emu, 0)));
    });

    // ========================================================================
    // Exponential and logarithmic (double)
    // ========================================================================
    
    hle.register_function("exp", [](Emulator& emu) {
        set_dreg(emu, 0, exp(get_dreg(emu, 0)));
    });
    hle.register_function("exp2", [](Emulator& emu) {
        set_dreg(emu, 0, exp2(get_dreg(emu, 0)));
    });
    hle.register_function("expm1", [](Emulator& emu) {
        set_dreg(emu, 0, expm1(get_dreg(emu, 0)));
    });
    hle.register_function("log", [](Emulator& emu) {
        set_dreg(emu, 0, log(get_dreg(emu, 0)));
    });
    hle.register_function("log2", [](Emulator& emu) {
        set_dreg(emu, 0, log2(get_dreg(emu, 0)));
    });
    hle.register_function("log10", [](Emulator& emu) {
        set_dreg(emu, 0, log10(get_dreg(emu, 0)));
    });
    hle.register_function("log1p", [](Emulator& emu) {
        set_dreg(emu, 0, log1p(get_dreg(emu, 0)));
    });

    // ========================================================================
    // Power functions (double)
    // ========================================================================
    
    hle.register_function("pow", [](Emulator& emu) {
        double x = get_dreg(emu, 0);
        double y = get_dreg(emu, 1);
        set_dreg(emu, 0, pow(x, y));
    });
    hle.register_function("sqrt", [](Emulator& emu) {
        set_dreg(emu, 0, sqrt(get_dreg(emu, 0)));
    });
    hle.register_function("cbrt", [](Emulator& emu) {
        set_dreg(emu, 0, cbrt(get_dreg(emu, 0)));
    });
    hle.register_function("hypot", [](Emulator& emu) {
        double x = get_dreg(emu, 0);
        double y = get_dreg(emu, 1);
        set_dreg(emu, 0, hypot(x, y));
    });

    // ========================================================================
    // Rounding and remainder (double)
    // ========================================================================

    hle.register_function("floor", [](Emulator& emu) {
        set_dreg(emu, 0, floor(get_dreg(emu, 0)));
    });
    hle.register_function("ceil", [](Emulator& emu) {
        set_dreg(emu, 0, ceil(get_dreg(emu, 0)));
    });
    hle.register_function("round", [](Emulator& emu) {
        set_dreg(emu, 0, round(get_dreg(emu, 0)));
    });
    hle.register_function("trunc", [](Emulator& emu) {
        set_dreg(emu, 0, trunc(get_dreg(emu, 0)));
    });
    hle.register_function("fabs", [](Emulator& emu) {
        set_dreg(emu, 0, fabs(get_dreg(emu, 0)));
    });
    hle.register_function("fmod", [](Emulator& emu) {
        double x = get_dreg(emu, 0);
        double y = get_dreg(emu, 1);
        set_dreg(emu, 0, fmod(x, y));
    });
    hle.register_function("remainder", [](Emulator& emu) {
        double x = get_dreg(emu, 0);
        double y = get_dreg(emu, 1);
        set_dreg(emu, 0, remainder(x, y));
    });
    hle.register_function("fmin", [](Emulator& emu) {
        double x = get_dreg(emu, 0);
        double y = get_dreg(emu, 1);
        set_dreg(emu, 0, fmin(x, y));
    });
    hle.register_function("fmax", [](Emulator& emu) {
        double x = get_dreg(emu, 0);
        double y = get_dreg(emu, 1);
        set_dreg(emu, 0, fmax(x, y));
    });
    hle.register_function("copysign", [](Emulator& emu) {
        double x = get_dreg(emu, 0);
        double y = get_dreg(emu, 1);
        set_dreg(emu, 0, copysign(x, y));
    });

    // ========================================================================
    // Single precision (float) variants
    // ========================================================================

    hle.register_function("sinf", [](Emulator& emu) {
        set_sreg(emu, UC_ARM64_REG_S0, sinf(get_sreg(emu, UC_ARM64_REG_S0)));
    });
    hle.register_function("cosf", [](Emulator& emu) {
        set_sreg(emu, UC_ARM64_REG_S0, cosf(get_sreg(emu, UC_ARM64_REG_S0)));
    });
    hle.register_function("tanf", [](Emulator& emu) {
        set_sreg(emu, UC_ARM64_REG_S0, tanf(get_sreg(emu, UC_ARM64_REG_S0)));
    });
    hle.register_function("sqrtf", [](Emulator& emu) {
        set_sreg(emu, UC_ARM64_REG_S0, sqrtf(get_sreg(emu, UC_ARM64_REG_S0)));
    });
    hle.register_function("expf", [](Emulator& emu) {
        set_sreg(emu, UC_ARM64_REG_S0, expf(get_sreg(emu, UC_ARM64_REG_S0)));
    });
    hle.register_function("logf", [](Emulator& emu) {
        set_sreg(emu, UC_ARM64_REG_S0, logf(get_sreg(emu, UC_ARM64_REG_S0)));
    });
    hle.register_function("log10f", [](Emulator& emu) {
        set_sreg(emu, UC_ARM64_REG_S0, log10f(get_sreg(emu, UC_ARM64_REG_S0)));
    });
    hle.register_function("powf", [](Emulator& emu) {
        float x = get_sreg(emu, UC_ARM64_REG_S0);
        float y = get_sreg(emu, UC_ARM64_REG_S1);
        set_sreg(emu, UC_ARM64_REG_S0, powf(x, y));
    });
    hle.register_function("floorf", [](Emulator& emu) {
        set_sreg(emu, UC_ARM64_REG_S0, floorf(get_sreg(emu, UC_ARM64_REG_S0)));
    });
    hle.register_function("ceilf", [](Emulator& emu) {
        set_sreg(emu, UC_ARM64_REG_S0, ceilf(get_sreg(emu, UC_ARM64_REG_S0)));
    });
    hle.register_function("roundf", [](Emulator& emu) {
        set_sreg(emu, UC_ARM64_REG_S0, roundf(get_sreg(emu, UC_ARM64_REG_S0)));
    });
    hle.register_function("fabsf", [](Emulator& emu) {
        set_sreg(emu, UC_ARM64_REG_S0, fabsf(get_sreg(emu, UC_ARM64_REG_S0)));
    });
    hle.register_function("fmodf", [](Emulator& emu) {
        float x = get_sreg(emu, UC_ARM64_REG_S0);
        float y = get_sreg(emu, UC_ARM64_REG_S1);
        set_sreg(emu, UC_ARM64_REG_S0, fmodf(x, y));
    });

    // ========================================================================
    // Classification
    // ========================================================================

    hle.register_function("isnan", [](Emulator& emu) {
        uint64_t val = get_reg(emu, UC_ARM64_REG_X0);
        set_dreg(emu, UC_ARM64_REG_X0, std::isnan(*(double*)&val) ? 1 : 0);
    });

    hle.register_function("isinf", [](Emulator& emu) {
        uint64_t val = get_reg(emu, UC_ARM64_REG_X0);
        set_dreg(emu, UC_ARM64_REG_X0, std::isinf(*(double*)&val) ? 1 : 0);
    });

    hle.register_function("isfinite", [](Emulator& emu) {
        uint64_t val = get_reg(emu, UC_ARM64_REG_X0);
        set_dreg(emu, UC_ARM64_REG_X0, std::isfinite(*(double*)&val) ? 1 : 0);
    });

    // ========================================================================
    // Misc
    // ========================================================================

    hle.register_function("ldexp", [](Emulator& emu) {
        double x = get_dreg(emu, 0);
        uint64_t exp = get_reg(emu, UC_ARM64_REG_X0);
        set_dreg(emu, 0, ldexp(x, (int)exp));
    });

    hle.register_function("frexp", [](Emulator& emu) {
        double x = get_dreg(emu, 0);
        uint64_t exp_ptr = get_reg(emu, UC_ARM64_REG_X0);  // int* exp
        int exp;
        double result = frexp(x, &exp);
        set_dreg(emu, 0, result);
        if (exp_ptr) {
            int32_t exp32 = exp;
            emu.mem_write(exp_ptr, &exp32, sizeof(exp32));
        }
    });

    hle.register_function("modf", [](Emulator& emu) {
        double x = get_dreg(emu, 0);
        uint64_t ipart_ptr = get_reg(emu, UC_ARM64_REG_X0);  // double* iptr
        double ipart;
        double result = modf(x, &ipart);
        set_dreg(emu, 0, result);
        if (ipart_ptr) {
            emu.mem_write(ipart_ptr, &ipart, sizeof(ipart));
        }
    });

    hle.register_function("modff", [](Emulator& emu) {
        float x = get_sreg(emu, UC_ARM64_REG_S0);
        uint64_t ipart_ptr = get_reg(emu, UC_ARM64_REG_X0);  // float* iptr
        float ipart;
        float result = modff(x, &ipart);
        set_sreg(emu, UC_ARM64_REG_S0, result);
        if (ipart_ptr) {
            emu.mem_write(ipart_ptr, &ipart, sizeof(ipart));
        }
    });

    hle.register_function("ldexpf", [](Emulator& emu) {
        float x = get_sreg(emu, UC_ARM64_REG_S0);
        uint64_t exp = get_reg(emu, UC_ARM64_REG_X0);
        set_sreg(emu, UC_ARM64_REG_S0, ldexpf(x, (int)exp));
    });

    hle.register_function("frexpf", [](Emulator& emu) {
        float x = get_sreg(emu, UC_ARM64_REG_S0);
        uint64_t exp_ptr = get_reg(emu, UC_ARM64_REG_X0);  // int* exp
        int exp;
        float result = frexpf(x, &exp);
        set_sreg(emu, UC_ARM64_REG_S0, result);
        if (exp_ptr) {
            int32_t exp32 = exp;
            emu.mem_write(exp_ptr, &exp32, sizeof(exp32));
        }
    });

    hle.register_function("scalbn", [](Emulator& emu) {
        double x = get_dreg(emu, 0);
        uint64_t n = get_reg(emu, UC_ARM64_REG_X0);
        set_dreg(emu, 0, scalbn(x, (int)n));
    });

    hle.register_function("scalbnf", [](Emulator& emu) {
        float x = get_sreg(emu, UC_ARM64_REG_S0);
        uint64_t n = get_reg(emu, UC_ARM64_REG_X0);
        set_sreg(emu, UC_ARM64_REG_S0, scalbnf(x, (int)n));
    });

    hle.register_function("scalbln", [](Emulator& emu) {
        double x = get_dreg(emu, 0);
        uint64_t n = get_reg(emu, UC_ARM64_REG_X0);
        set_dreg(emu, 0, scalbln(x, (long)n));
    });

    // Bionic uses FP_ILOGB0 = -INT_MAX, FP_ILOGBNAN = INT_MAX (different from glibc)
    hle.register_function("ilogb", [](Emulator& emu) {
        double x = get_dreg(emu, 0);
        int result;
        if (std::isnan(x)) result = INT_MAX;           // FP_ILOGBNAN
        else if (x == 0.0) result = -INT_MAX;          // FP_ILOGB0
        else if (std::isinf(x)) result = INT_MAX;      // ilogb(inf) = INT_MAX
        else result = ilogb(x);
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(static_cast<int64_t>(result)));
    });

    hle.register_function("ilogbf", [](Emulator& emu) {
        float x = get_sreg(emu, UC_ARM64_REG_S0);
        int result;
        if (std::isnan(x)) result = INT_MAX;           // FP_ILOGBNAN
        else if (x == 0.0f) result = -INT_MAX;         // FP_ILOGB0
        else if (std::isinf(x)) result = INT_MAX;      // ilogbf(inf) = INT_MAX
        else result = ilogbf(x);
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(static_cast<int64_t>(result)));
    });

    hle.register_function("logb", [](Emulator& emu) {
        set_dreg(emu, 0, logb(get_dreg(emu, 0)));
    });

    hle.register_function("logbf", [](Emulator& emu) {
        set_sreg(emu, UC_ARM64_REG_S0, logbf(get_sreg(emu, UC_ARM64_REG_S0)));
    });

    hle.register_function("nextafter", [](Emulator& emu) {
        double x = get_dreg(emu, 0);
        double y = get_dreg(emu, 1);
        set_dreg(emu, 0, nextafter(x, y));
    });

    hle.register_function("nextafterf", [](Emulator& emu) {
        float x = get_sreg(emu, UC_ARM64_REG_S0);
        float y = get_sreg(emu, UC_ARM64_REG_S1);
        set_sreg(emu, UC_ARM64_REG_S0, nextafterf(x, y));
    });

    hle.register_function("fdim", [](Emulator& emu) {
        double x = get_dreg(emu, 0);
        double y = get_dreg(emu, 1);
        set_dreg(emu, 0, fdim(x, y));
    });

    hle.register_function("fdimf", [](Emulator& emu) {
        float x = get_sreg(emu, UC_ARM64_REG_S0);
        float y = get_sreg(emu, UC_ARM64_REG_S1);
        set_sreg(emu, UC_ARM64_REG_S0, fdimf(x, y));
    });

    hle.register_function("fma", [](Emulator& emu) {
        double x = get_dreg(emu, 0);
        double y = get_dreg(emu, 1);
        double z = get_dreg(emu, 2);
        set_dreg(emu, 0, fma(x, y, z));
    });

    hle.register_function("fmaf", [](Emulator& emu) {
        float x = get_sreg(emu, UC_ARM64_REG_S0);
        float y = get_sreg(emu, UC_ARM64_REG_S1);
        float z = get_sreg(emu, UC_ARM64_REG_S2);
        set_sreg(emu, UC_ARM64_REG_S0, fmaf(x, y, z));
    });

    hle.register_function("nan", [](Emulator& emu) {
        set_dreg(emu, 0, nan(""));
    });

    hle.register_function("nanf", [](Emulator& emu) {
        set_sreg(emu, UC_ARM64_REG_S0, nanf(""));
    });

    hle.register_function("erf", [](Emulator& emu) {
        set_dreg(emu, 0, erf(get_dreg(emu, 0)));
    });

    hle.register_function("erff", [](Emulator& emu) {
        set_sreg(emu, UC_ARM64_REG_S0, erff(get_sreg(emu, UC_ARM64_REG_S0)));
    });

    hle.register_function("erfc", [](Emulator& emu) {
        set_dreg(emu, 0, erfc(get_dreg(emu, 0)));
    });

    hle.register_function("erfcf", [](Emulator& emu) {
        set_sreg(emu, UC_ARM64_REG_S0, erfcf(get_sreg(emu, UC_ARM64_REG_S0)));
    });

    hle.register_function("lgamma", [](Emulator& emu) {
        set_dreg(emu, 0, lgamma(get_dreg(emu, 0)));
    });

    hle.register_function("lgammaf", [](Emulator& emu) {
        set_sreg(emu, UC_ARM64_REG_S0, lgammaf(get_sreg(emu, UC_ARM64_REG_S0)));
    });

    hle.register_function("tgamma", [](Emulator& emu) {
        set_dreg(emu, 0, tgamma(get_dreg(emu, 0)));
    });

    hle.register_function("tgammaf", [](Emulator& emu) {
        set_sreg(emu, UC_ARM64_REG_S0, tgammaf(get_sreg(emu, UC_ARM64_REG_S0)));
    });

    hle.register_function("j0", [](Emulator& emu) {
        set_dreg(emu, 0, j0(get_dreg(emu, 0)));
    });

    hle.register_function("j1", [](Emulator& emu) {
        set_dreg(emu, 0, j1(get_dreg(emu, 0)));
    });

    hle.register_function("y0", [](Emulator& emu) {
        set_dreg(emu, 0, y0(get_dreg(emu, 0)));
    });

    hle.register_function("y1", [](Emulator& emu) {
        set_dreg(emu, 0, y1(get_dreg(emu, 0)));
    });

    // ========================================================================
    // Floating-point environment (fenv.h)
    // ========================================================================

    // ARM64 bionic fenv rounding mode constants (small integers 0-3)
    // FE_TONEAREST  = 0  (RN)
    // FE_UPWARD     = 1  (RP)
    // FE_DOWNWARD   = 2  (RM)
    // FE_TOWARDZERO = 3  (RZ)
    // These values are stored in FPCR bits 22-23 after shifting

    // fesetround - Set the rounding mode
    // int fesetround(int round)
    hle.register_function("fesetround", [](Emulator& emu) {
        uint32_t round = get_reg(emu, UC_ARM64_REG_X0);

        // Validate rounding mode (must be 0, 1, 2, or 3)
        if (round > 3) {
            set_reg(emu, UC_ARM64_REG_X0, -1);  // Invalid rounding mode
            return;
        }

        // Write to FPCR (rounding mode in bits 22-23)
        uint32_t fpcr = get_fpcr(emu);
        fpcr = (fpcr & ~ARM64_FPCR_RMODE_MASK) | (round << ARM64_FPCR_RMODE_SHIFT);
        set_fpcr(emu, fpcr);
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    // fegetround - Get the current rounding mode
    // int fegetround(void)
    hle.register_function("fegetround", [](Emulator& emu) {
        uint32_t fpcr = get_fpcr(emu);
        uint32_t rmode = (fpcr & ARM64_FPCR_RMODE_MASK) >> ARM64_FPCR_RMODE_SHIFT;
        set_reg(emu, UC_ARM64_REG_X0, rmode);
    });

    // ARM64 bionic exception flags (same as FPSR bits)
    // FE_INVALID   = 0x01 (IOC)
    // FE_DIVBYZERO = 0x02 (DZC)
    // FE_OVERFLOW  = 0x04 (OFC)
    // FE_UNDERFLOW = 0x08 (UFC)
    // FE_INEXACT   = 0x10 (IXC)
    // FE_DENORMAL  = 0x80 (IDC) - ARM64 extension

    // feclearexcept - Clear floating-point exception flags
    // int feclearexcept(int excepts)
    hle.register_function("feclearexcept", [](Emulator& emu) {
        uint32_t excepts = get_reg(emu, UC_ARM64_REG_X0);
        uint32_t fpsr = get_fpsr(emu);
        // Clear the requested exception flags
        fpsr &= ~(excepts & 0x9F);  // Mask valid exception bits
        set_fpsr(emu, fpsr);
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    // feraiseexcept - Raise floating-point exception flags
    // int feraiseexcept(int excepts)
    hle.register_function("feraiseexcept", [](Emulator& emu) {
        uint32_t excepts = get_reg(emu, UC_ARM64_REG_X0);
        uint32_t fpsr = get_fpsr(emu);
        // Set the requested exception flags
        fpsr |= (excepts & 0x9F);  // Mask valid exception bits
        set_fpsr(emu, fpsr);
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    // fetestexcept - Test floating-point exception flags
    // int fetestexcept(int excepts)
    hle.register_function("fetestexcept", [](Emulator& emu) {
        uint32_t excepts = get_reg(emu, UC_ARM64_REG_X0);
        uint32_t fpsr = get_fpsr(emu);
        // Return the intersection of requested and set flags
        set_reg(emu, UC_ARM64_REG_X0, fpsr & excepts & 0x9F);
    });

    // fegetexceptflag - Get floating-point exception flag state
    // int fegetexceptflag(fexcept_t *flagp, int excepts)
    hle.register_function("fegetexceptflag", [](Emulator& emu) {
        uint64_t flagp = get_reg(emu, UC_ARM64_REG_X0);
        uint32_t excepts = get_reg(emu, UC_ARM64_REG_X1);
        if (flagp != 0) {
            uint32_t fpsr = get_fpsr(emu);
            uint32_t flags = fpsr & excepts & 0x9F;
            emu.mem_write(flagp, &flags, sizeof(flags));
        }
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    // fesetexceptflag - Set floating-point exception flag state
    // int fesetexceptflag(const fexcept_t *flagp, int excepts)
    hle.register_function("fesetexceptflag", [](Emulator& emu) {
        uint64_t flagp = get_reg(emu, UC_ARM64_REG_X0);
        uint32_t excepts = get_reg(emu, UC_ARM64_REG_X1);
        if (flagp != 0) {
            uint32_t flags = 0;
            emu.mem_read(flagp, &flags, sizeof(flags));
            uint32_t fpsr = get_fpsr(emu);
            // Clear then set the requested flags
            fpsr = (fpsr & ~(excepts & 0x9F)) | (flags & excepts & 0x9F);
            set_fpsr(emu, fpsr);
        }
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    // fegetenv - Get floating-point environment
    // int fegetenv(fenv_t *envp)
    // On ARM64, fenv_t is { uint32_t __control, __status; } = FPCR, FPSR
    hle.register_function("fegetenv", [](Emulator& emu) {
        uint64_t envp = get_reg(emu, UC_ARM64_REG_X0);
        if (envp != 0) {
            uint32_t fpcr = get_fpcr(emu);
            uint32_t fpsr = get_fpsr(emu);
            emu.mem_write(envp, &fpcr, sizeof(fpcr));
            emu.mem_write(envp + 4, &fpsr, sizeof(fpsr));
        }
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    // fesetenv - Set floating-point environment
    // int fesetenv(const fenv_t *envp)
    hle.register_function("fesetenv", [](Emulator& emu) {
        uint64_t envp = get_reg(emu, UC_ARM64_REG_X0);
        if (envp == (uint64_t)-1) {
            // FE_DFL_ENV: reset to default
            set_fpcr(emu, 0);
            set_fpsr(emu, 0);
        } else if (envp != 0) {
            uint32_t fpcr = 0, fpsr = 0;
            emu.mem_read(envp, &fpcr, sizeof(fpcr));
            emu.mem_read(envp + 4, &fpsr, sizeof(fpsr));
            set_fpcr(emu, fpcr);
            set_fpsr(emu, fpsr);
        }
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    // feholdexcept - Save environment and clear exception flags
    // int feholdexcept(fenv_t *envp)
    hle.register_function("feholdexcept", [](Emulator& emu) {
        uint64_t envp = get_reg(emu, UC_ARM64_REG_X0);
        if (envp != 0) {
            // Save current environment
            uint32_t fpcr = get_fpcr(emu);
            uint32_t fpsr = get_fpsr(emu);
            emu.mem_write(envp, &fpcr, sizeof(fpcr));
            emu.mem_write(envp + 4, &fpsr, sizeof(fpsr));
        }
        // Clear exception flags
        set_fpsr(emu, 0);
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    // feupdateenv - Restore environment and raise saved exceptions
    // int feupdateenv(const fenv_t *envp)
    hle.register_function("feupdateenv", [](Emulator& emu) {
        uint64_t envp = get_reg(emu, UC_ARM64_REG_X0);
        // Save current exception flags
        uint32_t current_fpsr = get_fpsr(emu);

        if (envp == (uint64_t)-1) {
            // FE_DFL_ENV: reset to default
            set_fpcr(emu, 0);
            set_fpsr(emu, current_fpsr & 0x9F);  // Keep raised exceptions
        } else if (envp != 0) {
            uint32_t fpcr = 0, fpsr = 0;
            emu.mem_read(envp, &fpcr, sizeof(fpcr));
            emu.mem_read(envp + 4, &fpsr, sizeof(fpsr));
            set_fpcr(emu, fpcr);
            // Merge current exceptions with restored ones
            set_fpsr(emu, fpsr | (current_fpsr & 0x9F));
        }
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    // fedisableexcept - Disable floating-point exception traps (Linux-specific)
    // int fedisableexcept(int excepts)
    // On ARM64, exception trapping is not supported the same way as x86.
    // Return 0 (no exceptions were enabled) since we don't support trapping.
    hle.register_function("fedisableexcept", [](Emulator& emu) {
        // Return 0 - no exceptions were previously enabled
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    // feenableexcept - Enable floating-point exception traps (Linux-specific)
    // int feenableexcept(int excepts)
    // On ARM64, exception trapping is not supported. Return -1 to indicate failure.
    hle.register_function("feenableexcept", [](Emulator& emu) {
        // Return -1 - cannot enable exception trapping on ARM64
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
    });

    // fegetexcept - Get enabled floating-point exception traps (Linux-specific)
    // int fegetexcept(void)
    // On ARM64, return 0 since no exceptions can be enabled for trapping.
    hle.register_function("fegetexcept", [](Emulator& emu) {
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    // __fe_dfl_env - Default floating-point environment pointer
    hle.register_function("__fe_dfl_env", [](Emulator& emu) {
        // Return pointer to default environment (we use 0 to indicate default)
        static uint64_t dfl_env = 0;
        if (dfl_env == 0) {
            dfl_env = emu.memory().heap().allocate(16, 8);
            uint64_t zero = 0;
            emu.mem_write(dfl_env, &zero, 8);
        }
        set_reg(emu, UC_ARM64_REG_X0, dfl_env);
    });

    // ========================================================================
    // Additional single precision (float) variants
    // ========================================================================

    hle.register_function("asinf", [](Emulator& emu) {
        set_sreg(emu, UC_ARM64_REG_S0, asinf(get_sreg(emu, UC_ARM64_REG_S0)));
    });
    hle.register_function("acosf", [](Emulator& emu) {
        set_sreg(emu, UC_ARM64_REG_S0, acosf(get_sreg(emu, UC_ARM64_REG_S0)));
    });
    hle.register_function("atanf", [](Emulator& emu) {
        set_sreg(emu, UC_ARM64_REG_S0, atanf(get_sreg(emu, UC_ARM64_REG_S0)));
    });
    hle.register_function("atan2f", [](Emulator& emu) {
        float y = get_sreg(emu, UC_ARM64_REG_S0);
        float x = get_sreg(emu, UC_ARM64_REG_S1);
        set_sreg(emu, UC_ARM64_REG_S0, atan2f(y, x));
    });
    hle.register_function("sinhf", [](Emulator& emu) {
        set_sreg(emu, UC_ARM64_REG_S0, sinhf(get_sreg(emu, UC_ARM64_REG_S0)));
    });
    hle.register_function("coshf", [](Emulator& emu) {
        set_sreg(emu, UC_ARM64_REG_S0, coshf(get_sreg(emu, UC_ARM64_REG_S0)));
    });
    hle.register_function("tanhf", [](Emulator& emu) {
        set_sreg(emu, UC_ARM64_REG_S0, tanhf(get_sreg(emu, UC_ARM64_REG_S0)));
    });
    hle.register_function("asinhf", [](Emulator& emu) {
        set_sreg(emu, UC_ARM64_REG_S0, asinhf(get_sreg(emu, UC_ARM64_REG_S0)));
    });
    hle.register_function("acoshf", [](Emulator& emu) {
        set_sreg(emu, UC_ARM64_REG_S0, acoshf(get_sreg(emu, UC_ARM64_REG_S0)));
    });
    hle.register_function("atanhf", [](Emulator& emu) {
        set_sreg(emu, UC_ARM64_REG_S0, atanhf(get_sreg(emu, UC_ARM64_REG_S0)));
    });
    hle.register_function("exp2f", [](Emulator& emu) {
        set_sreg(emu, UC_ARM64_REG_S0, exp2f(get_sreg(emu, UC_ARM64_REG_S0)));
    });
    hle.register_function("expm1f", [](Emulator& emu) {
        set_sreg(emu, UC_ARM64_REG_S0, expm1f(get_sreg(emu, UC_ARM64_REG_S0)));
    });
    hle.register_function("log2f", [](Emulator& emu) {
        set_sreg(emu, UC_ARM64_REG_S0, log2f(get_sreg(emu, UC_ARM64_REG_S0)));
    });
    hle.register_function("log1pf", [](Emulator& emu) {
        set_sreg(emu, UC_ARM64_REG_S0, log1pf(get_sreg(emu, UC_ARM64_REG_S0)));
    });
    hle.register_function("cbrtf", [](Emulator& emu) {
        set_sreg(emu, UC_ARM64_REG_S0, cbrtf(get_sreg(emu, UC_ARM64_REG_S0)));
    });
    hle.register_function("hypotf", [](Emulator& emu) {
        float x = get_sreg(emu, UC_ARM64_REG_S0);
        float y = get_sreg(emu, UC_ARM64_REG_S1);
        set_sreg(emu, UC_ARM64_REG_S0, hypotf(x, y));
    });
    hle.register_function("copysignf", [](Emulator& emu) {
        float x = get_sreg(emu, UC_ARM64_REG_S0);
        float y = get_sreg(emu, UC_ARM64_REG_S1);
        set_sreg(emu, UC_ARM64_REG_S0, copysignf(x, y));
    });
    hle.register_function("fminf", [](Emulator& emu) {
        float x = get_sreg(emu, UC_ARM64_REG_S0);
        float y = get_sreg(emu, UC_ARM64_REG_S1);
        set_sreg(emu, UC_ARM64_REG_S0, fminf(x, y));
    });
    hle.register_function("fmaxf", [](Emulator& emu) {
        float x = get_sreg(emu, UC_ARM64_REG_S0);
        float y = get_sreg(emu, UC_ARM64_REG_S1);
        set_sreg(emu, UC_ARM64_REG_S0, fmaxf(x, y));
    });
    hle.register_function("truncf", [](Emulator& emu) {
        set_sreg(emu, UC_ARM64_REG_S0, truncf(get_sreg(emu, UC_ARM64_REG_S0)));
    });
    hle.register_function("remainderf", [](Emulator& emu) {
        float x = get_sreg(emu, UC_ARM64_REG_S0);
        float y = get_sreg(emu, UC_ARM64_REG_S1);
        set_sreg(emu, UC_ARM64_REG_S0, remainderf(x, y));
    });
    hle.register_function("nearbyintf", [](Emulator& emu) {
        set_sreg(emu, UC_ARM64_REG_S0, nearbyintf(get_sreg(emu, UC_ARM64_REG_S0)));
    });
    hle.register_function("rintf", [](Emulator& emu) {
        set_sreg(emu, UC_ARM64_REG_S0, rintf(get_sreg(emu, UC_ARM64_REG_S0)));
    });
    hle.register_function("lrintf", [](Emulator& emu) {
        set_reg(emu, UC_ARM64_REG_X0, lrintf(get_sreg(emu, UC_ARM64_REG_S0)));
    });
    hle.register_function("llrintf", [](Emulator& emu) {
        set_reg(emu, UC_ARM64_REG_X0, llrintf(get_sreg(emu, UC_ARM64_REG_S0)));
    });
    hle.register_function("lroundf", [](Emulator& emu) {
        set_reg(emu, UC_ARM64_REG_X0, lroundf(get_sreg(emu, UC_ARM64_REG_S0)));
    });
    hle.register_function("llroundf", [](Emulator& emu) {
        set_reg(emu, UC_ARM64_REG_X0, llroundf(get_sreg(emu, UC_ARM64_REG_S0)));
    });
    hle.register_function("j0f", [](Emulator& emu) {
        set_sreg(emu, UC_ARM64_REG_S0, j0f(get_sreg(emu, UC_ARM64_REG_S0)));
    });
    hle.register_function("j1f", [](Emulator& emu) {
        set_sreg(emu, UC_ARM64_REG_S0, j1f(get_sreg(emu, UC_ARM64_REG_S0)));
    });
    hle.register_function("jnf", [](Emulator& emu) {
        int n = get_reg(emu, UC_ARM64_REG_X0);
        float x = get_sreg(emu, UC_ARM64_REG_S0);
        set_sreg(emu, UC_ARM64_REG_S0, jnf(n, x));
    });
    hle.register_function("y0f", [](Emulator& emu) {
        set_sreg(emu, UC_ARM64_REG_S0, y0f(get_sreg(emu, UC_ARM64_REG_S0)));
    });
    hle.register_function("y1f", [](Emulator& emu) {
        set_sreg(emu, UC_ARM64_REG_S0, y1f(get_sreg(emu, UC_ARM64_REG_S0)));
    });
    hle.register_function("ynf", [](Emulator& emu) {
        int n = get_reg(emu, UC_ARM64_REG_X0);
        float x = get_sreg(emu, UC_ARM64_REG_S0);
        set_sreg(emu, UC_ARM64_REG_S0, ynf(n, x));
    });
    hle.register_function("gammaf_r", [](Emulator& emu) {
        float x = get_sreg(emu, UC_ARM64_REG_S0);
        uint64_t signp = get_reg(emu, UC_ARM64_REG_X0);
        int sign;
        float result = lgammaf_r(x, &sign);
        if (signp) {
            emu.mem_write(signp, &sign, sizeof(sign));
        }
        set_sreg(emu, UC_ARM64_REG_S0, result);
    });
    hle.register_function("lgammaf_r", [](Emulator& emu) {
        float x = get_sreg(emu, UC_ARM64_REG_S0);
        uint64_t signp = get_reg(emu, UC_ARM64_REG_X0);
        int sign;
        float result = lgammaf_r(x, &sign);
        if (signp) {
            emu.mem_write(signp, &sign, sizeof(sign));
        }
        set_sreg(emu, UC_ARM64_REG_S0, result);
    });
    hle.register_function("scalblnf", [](Emulator& emu) {
        float x = get_sreg(emu, UC_ARM64_REG_S0);
        long n = get_reg(emu, UC_ARM64_REG_X0);
        set_sreg(emu, UC_ARM64_REG_S0, scalblnf(x, n));
    });
    hle.register_function("remquof", [](Emulator& emu) {
        float x = get_sreg(emu, UC_ARM64_REG_S0);
        float y = get_sreg(emu, UC_ARM64_REG_S1);
        uint64_t quo_ptr = get_reg(emu, UC_ARM64_REG_X0);
        int quo;
        float result = remquof(x, y, &quo);
        if (quo_ptr) {
            emu.mem_write(quo_ptr, &quo, sizeof(quo));
        }
        set_sreg(emu, UC_ARM64_REG_S0, result);
    });

    // ========================================================================
    // Double precision functions with integer results
    // ========================================================================

    hle.register_function("nearbyint", [](Emulator& emu) {
        set_dreg(emu, 0, nearbyint(get_dreg(emu, 0)));
    });
    hle.register_function("rint", [](Emulator& emu) {
        set_dreg(emu, 0, rint(get_dreg(emu, 0)));
    });
    hle.register_function("lrint", [](Emulator& emu) {
        set_reg(emu, UC_ARM64_REG_X0, lrint(get_dreg(emu, 0)));
    });
    hle.register_function("llrint", [](Emulator& emu) {
        set_reg(emu, UC_ARM64_REG_X0, llrint(get_dreg(emu, 0)));
    });
    hle.register_function("lround", [](Emulator& emu) {
        set_reg(emu, UC_ARM64_REG_X0, lround(get_dreg(emu, 0)));
    });
    hle.register_function("llround", [](Emulator& emu) {
        set_reg(emu, UC_ARM64_REG_X0, llround(get_dreg(emu, 0)));
    });
    hle.register_function("jn", [](Emulator& emu) {
        int n = get_reg(emu, UC_ARM64_REG_X0);
        double x = get_dreg(emu, 0);
        set_dreg(emu, 0, jn(n, x));
    });
    hle.register_function("yn", [](Emulator& emu) {
        int n = get_reg(emu, UC_ARM64_REG_X0);
        double x = get_dreg(emu, 0);
        set_dreg(emu, 0, yn(n, x));
    });
    hle.register_function("gamma_r", [](Emulator& emu) {
        double x = get_dreg(emu, 0);
        uint64_t signp = get_reg(emu, UC_ARM64_REG_X0);
        int sign;
        double result = lgamma_r(x, &sign);
        if (signp) {
            emu.mem_write(signp, &sign, sizeof(sign));
        }
        set_dreg(emu, 0, result);
    });
    hle.register_function("lgamma_r", [](Emulator& emu) {
        double x = get_dreg(emu, 0);
        uint64_t signp = get_reg(emu, UC_ARM64_REG_X0);
        int sign;
        double result = lgamma_r(x, &sign);
        if (signp) {
            emu.mem_write(signp, &sign, sizeof(sign));
        }
        set_dreg(emu, 0, result);
    });
    hle.register_function("remquo", [](Emulator& emu) {
        double x = get_dreg(emu, 0);
        double y = get_dreg(emu, 1);
        uint64_t quo_ptr = get_reg(emu, UC_ARM64_REG_X0);
        int quo;
        double result = remquo(x, y, &quo);
        if (quo_ptr) {
            emu.mem_write(quo_ptr, &quo, sizeof(quo));
        }
        set_dreg(emu, 0, result);
    });

    // Legacy BSD-style functions
    hle.register_function("drem", [](Emulator& emu) {
        double x = get_dreg(emu, 0);
        double y = get_dreg(emu, 1);
        set_dreg(emu, 0, remainder(x, y));  // drem is just an alias
    });
    hle.register_function("dremf", [](Emulator& emu) {
        float x = get_sreg(emu, UC_ARM64_REG_S0);
        float y = get_sreg(emu, UC_ARM64_REG_S1);
        set_sreg(emu, UC_ARM64_REG_S0, remainderf(x, y));
    });
    hle.register_function("scalb", [](Emulator& emu) {
        double x = get_dreg(emu, 0);
        double n = get_dreg(emu, 1);
        set_dreg(emu, 0, scalbn(x, (int)n));
    });
    hle.register_function("scalbf", [](Emulator& emu) {
        float x = get_sreg(emu, UC_ARM64_REG_S0);
        float n = get_sreg(emu, UC_ARM64_REG_S1);
        set_sreg(emu, UC_ARM64_REG_S0, scalbnf(x, (int)n));
    });
    hle.register_function("finite", [](Emulator& emu) {
        double x = get_dreg(emu, 0);
        set_reg(emu, UC_ARM64_REG_X0, std::isfinite(x) ? 1 : 0);
    });
    hle.register_function("finitef", [](Emulator& emu) {
        float x = get_sreg(emu, UC_ARM64_REG_S0);
        set_reg(emu, UC_ARM64_REG_X0, std::isfinite(x) ? 1 : 0);
    });
    hle.register_function("significand", [](Emulator& emu) {
        double x = get_dreg(emu, 0);
        set_dreg(emu, 0, scalbn(x, -ilogb(x)));
    });
    hle.register_function("significandf", [](Emulator& emu) {
        float x = get_sreg(emu, UC_ARM64_REG_S0);
        set_sreg(emu, UC_ARM64_REG_S0, scalbnf(x, -ilogbf(x)));
    });

    // sincos - Compute sin and cos simultaneously
    hle.register_function("sincos", [](Emulator& emu) {
        double x = get_dreg(emu, 0);
        uint64_t sinp = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t cosp = get_reg(emu, UC_ARM64_REG_X1);
        double s = sin(x);
        double c = cos(x);
        if (sinp) emu.mem_write(sinp, &s, sizeof(s));
        if (cosp) emu.mem_write(cosp, &c, sizeof(c));
    });
    hle.register_function("sincosf", [](Emulator& emu) {
        float x = get_sreg(emu, UC_ARM64_REG_S0);
        uint64_t sinp = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t cosp = get_reg(emu, UC_ARM64_REG_X1);
        float s = sinf(x);
        float c = cosf(x);
        if (sinp) emu.mem_write(sinp, &s, sizeof(s));
        if (cosp) emu.mem_write(cosp, &c, sizeof(c));
    });

    // ========================================================================
    // Long double functions (128-bit IEEE 754 binary128 on ARM64)
    // ARM64 uses Q registers (full 128-bit V registers) for long double
    // ========================================================================

    hle.register_function("sinl", [](Emulator& emu) {
        set_ldreg(emu, 0, sinl(get_ldreg(emu, 0)));
    });
    hle.register_function("cosl", [](Emulator& emu) {
        set_ldreg(emu, 0, cosl(get_ldreg(emu, 0)));
    });
    hle.register_function("tanl", [](Emulator& emu) {
        set_ldreg(emu, 0, tanl(get_ldreg(emu, 0)));
    });
    hle.register_function("asinl", [](Emulator& emu) {
        set_ldreg(emu, 0, asinl(get_ldreg(emu, 0)));
    });
    hle.register_function("acosl", [](Emulator& emu) {
        set_ldreg(emu, 0, acosl(get_ldreg(emu, 0)));
    });
    hle.register_function("atanl", [](Emulator& emu) {
        set_ldreg(emu, 0, atanl(get_ldreg(emu, 0)));
    });
    hle.register_function("atan2l", [](Emulator& emu) {
        long double y = get_ldreg(emu, 0);
        long double x = get_ldreg(emu, 1);
        set_ldreg(emu, 0, atan2l(y, x));
    });
    hle.register_function("sinhl", [](Emulator& emu) {
        set_ldreg(emu, 0, sinhl(get_ldreg(emu, 0)));
    });
    hle.register_function("coshl", [](Emulator& emu) {
        set_ldreg(emu, 0, coshl(get_ldreg(emu, 0)));
    });
    hle.register_function("tanhl", [](Emulator& emu) {
        set_ldreg(emu, 0, tanhl(get_ldreg(emu, 0)));
    });
    hle.register_function("asinhl", [](Emulator& emu) {
        set_ldreg(emu, 0, asinhl(get_ldreg(emu, 0)));
    });
    hle.register_function("acoshl", [](Emulator& emu) {
        set_ldreg(emu, 0, acoshl(get_ldreg(emu, 0)));
    });
    hle.register_function("atanhl", [](Emulator& emu) {
        set_ldreg(emu, 0, atanhl(get_ldreg(emu, 0)));
    });
    hle.register_function("expl", [](Emulator& emu) {
        set_ldreg(emu, 0, expl(get_ldreg(emu, 0)));
    });
    hle.register_function("exp2l", [](Emulator& emu) {
        set_ldreg(emu, 0, exp2l(get_ldreg(emu, 0)));
    });
    hle.register_function("expm1l", [](Emulator& emu) {
        set_ldreg(emu, 0, expm1l(get_ldreg(emu, 0)));
    });
    hle.register_function("logl", [](Emulator& emu) {
        set_ldreg(emu, 0, logl(get_ldreg(emu, 0)));
    });
    hle.register_function("log2l", [](Emulator& emu) {
        set_ldreg(emu, 0, log2l(get_ldreg(emu, 0)));
    });
    hle.register_function("log10l", [](Emulator& emu) {
        set_ldreg(emu, 0, log10l(get_ldreg(emu, 0)));
    });
    hle.register_function("log1pl", [](Emulator& emu) {
        set_ldreg(emu, 0, log1pl(get_ldreg(emu, 0)));
    });
    hle.register_function("powl", [](Emulator& emu) {
        long double x = get_ldreg(emu, 0);
        long double y = get_ldreg(emu, 1);
        set_ldreg(emu, 0, powl(x, y));
    });
    hle.register_function("sqrtl", [](Emulator& emu) {
        set_ldreg(emu, 0, sqrtl(get_ldreg(emu, 0)));
    });
    hle.register_function("cbrtl", [](Emulator& emu) {
        set_ldreg(emu, 0, cbrtl(get_ldreg(emu, 0)));
    });
    hle.register_function("hypotl", [](Emulator& emu) {
        long double x = get_ldreg(emu, 0);
        long double y = get_ldreg(emu, 1);
        set_ldreg(emu, 0, hypotl(x, y));
    });
    hle.register_function("floorl", [](Emulator& emu) {
        set_ldreg(emu, 0, floorl(get_ldreg(emu, 0)));
    });
    hle.register_function("ceill", [](Emulator& emu) {
        set_ldreg(emu, 0, ceill(get_ldreg(emu, 0)));
    });
    hle.register_function("roundl", [](Emulator& emu) {
        set_ldreg(emu, 0, roundl(get_ldreg(emu, 0)));
    });
    hle.register_function("truncl", [](Emulator& emu) {
        set_ldreg(emu, 0, truncl(get_ldreg(emu, 0)));
    });
    hle.register_function("fabsl", [](Emulator& emu) {
        set_ldreg(emu, 0, fabsl(get_ldreg(emu, 0)));
    });
    hle.register_function("fmodl", [](Emulator& emu) {
        long double x = get_ldreg(emu, 0);
        long double y = get_ldreg(emu, 1);
        set_ldreg(emu, 0, fmodl(x, y));
    });
    hle.register_function("remainderl", [](Emulator& emu) {
        long double x = get_ldreg(emu, 0);
        long double y = get_ldreg(emu, 1);
        set_ldreg(emu, 0, remainderl(x, y));
    });
    hle.register_function("fminl", [](Emulator& emu) {
        long double x = get_ldreg(emu, 0);
        long double y = get_ldreg(emu, 1);
        set_ldreg(emu, 0, fminl(x, y));
    });
    hle.register_function("fmaxl", [](Emulator& emu) {
        long double x = get_ldreg(emu, 0);
        long double y = get_ldreg(emu, 1);
        set_ldreg(emu, 0, fmaxl(x, y));
    });
    hle.register_function("copysignl", [](Emulator& emu) {
        long double x = get_ldreg(emu, 0);
        long double y = get_ldreg(emu, 1);
        set_ldreg(emu, 0, copysignl(x, y));
    });
    hle.register_function("ldexpl", [](Emulator& emu) {
        long double x = get_ldreg(emu, 0);
        int exp = get_reg(emu, UC_ARM64_REG_X0);
        set_ldreg(emu, 0, ldexpl(x, exp));
    });
    hle.register_function("frexpl", [](Emulator& emu) {
        long double x = get_ldreg(emu, 0);
        uint64_t exp_ptr = get_reg(emu, UC_ARM64_REG_X0);
        int exp;
        long double result = frexpl(x, &exp);
        if (exp_ptr) {
            emu.mem_write(exp_ptr, &exp, sizeof(exp));
        }
        set_ldreg(emu, 0, result);
    });
    hle.register_function("modfl", [](Emulator& emu) {
        long double x = get_ldreg(emu, 0);
        uint64_t iptr = get_reg(emu, UC_ARM64_REG_X0);
        long double ipart;
        long double result = modfl(x, &ipart);
        if (iptr) {
            // Write 128-bit long double to guest memory in binary128 format
            write_ld_to_guest(emu, iptr, ipart);
        }
        set_ldreg(emu, 0, result);
    });
    hle.register_function("scalbnl", [](Emulator& emu) {
        long double x = get_ldreg(emu, 0);
        int n = get_reg(emu, UC_ARM64_REG_X0);
        set_ldreg(emu, 0, scalbnl(x, n));
    });
    hle.register_function("scalblnl", [](Emulator& emu) {
        long double x = get_ldreg(emu, 0);
        long n = get_reg(emu, UC_ARM64_REG_X0);
        set_ldreg(emu, 0, scalblnl(x, n));
    });
    hle.register_function("ilogbl", [](Emulator& emu) {
        long double x = get_ldreg(emu, 0);
        int result;
        if (std::isnan(x)) result = INT_MAX;           // FP_ILOGBNAN
        else if (x == 0.0L) result = -INT_MAX;         // FP_ILOGB0
        else if (std::isinf(x)) result = INT_MAX;      // ilogbl(inf) = INT_MAX
        else result = ilogbl(x);
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(static_cast<int64_t>(result)));
    });
    hle.register_function("logbl", [](Emulator& emu) {
        set_ldreg(emu, 0, logbl(get_ldreg(emu, 0)));
    });
    hle.register_function("nextafterl", [](Emulator& emu) {
        long double x = get_ldreg(emu, 0);
        long double y = get_ldreg(emu, 1);
        set_ldreg(emu, 0, nextafterl(x, y));
    });
    hle.register_function("nexttoward", [](Emulator& emu) {
        double x = get_dreg(emu, 0);
        long double y = get_ldreg(emu, 1);  // long double arg
        set_dreg(emu, 0, nexttoward(x, y));
    });
    hle.register_function("nexttowardf", [](Emulator& emu) {
        float x = get_sreg(emu, UC_ARM64_REG_S0);
        long double y = get_ldreg(emu, 0);
        set_sreg(emu, UC_ARM64_REG_S0, nexttowardf(x, y));
    });
    hle.register_function("nexttowardl", [](Emulator& emu) {
        long double x = get_ldreg(emu, 0);
        long double y = get_ldreg(emu, 1);
        set_ldreg(emu, 0, nexttowardl(x, y));
    });
    hle.register_function("nearbyintl", [](Emulator& emu) {
        set_ldreg(emu, 0, nearbyintl(get_ldreg(emu, 0)));
    });
    hle.register_function("rintl", [](Emulator& emu) {
        set_ldreg(emu, 0, rintl(get_ldreg(emu, 0)));
    });
    hle.register_function("lrintl", [](Emulator& emu) {
        set_reg(emu, UC_ARM64_REG_X0, lrintl(get_ldreg(emu, 0)));
    });
    hle.register_function("llrintl", [](Emulator& emu) {
        set_reg(emu, UC_ARM64_REG_X0, llrintl(get_ldreg(emu, 0)));
    });
    hle.register_function("lroundl", [](Emulator& emu) {
        set_reg(emu, UC_ARM64_REG_X0, lroundl(get_ldreg(emu, 0)));
    });
    hle.register_function("llroundl", [](Emulator& emu) {
        set_reg(emu, UC_ARM64_REG_X0, llroundl(get_ldreg(emu, 0)));
    });
    hle.register_function("remquol", [](Emulator& emu) {
        long double x = get_ldreg(emu, 0);
        long double y = get_ldreg(emu, 1);
        uint64_t quo_ptr = get_reg(emu, UC_ARM64_REG_X0);
        int quo;
        long double result = remquol(x, y, &quo);
        if (quo_ptr) {
            emu.mem_write(quo_ptr, &quo, sizeof(quo));
        }
        set_ldreg(emu, 0, result);
    });
    hle.register_function("fmal", [](Emulator& emu) {
        long double x = get_ldreg(emu, 0);
        long double y = get_ldreg(emu, 1);
        long double z = get_ldreg(emu, 2);
        set_ldreg(emu, 0, fmal(x, y, z));
    });
    hle.register_function("erfl", [](Emulator& emu) {
        set_ldreg(emu, 0, erfl(get_ldreg(emu, 0)));
    });
    hle.register_function("erfcl", [](Emulator& emu) {
        set_ldreg(emu, 0, erfcl(get_ldreg(emu, 0)));
    });
    hle.register_function("lgammal", [](Emulator& emu) {
        set_ldreg(emu, 0, lgammal(get_ldreg(emu, 0)));
    });
    hle.register_function("lgammal_r", [](Emulator& emu) {
        long double x = get_ldreg(emu, 0);
        uint64_t signp = get_reg(emu, UC_ARM64_REG_X0);
        int sign;
        long double result = lgammal_r(x, &sign);
        if (signp) {
            emu.mem_write(signp, &sign, sizeof(sign));
        }
        set_ldreg(emu, 0, result);
    });
    hle.register_function("tgammal", [](Emulator& emu) {
        set_ldreg(emu, 0, tgammal(get_ldreg(emu, 0)));
    });
    hle.register_function("nanl", [](Emulator& emu) {
        set_ldreg(emu, 0, nanl(""));
    });
    hle.register_function("sincosl", [](Emulator& emu) {
        long double x = get_ldreg(emu, 0);
        uint64_t sinp = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t cosp = get_reg(emu, UC_ARM64_REG_X1);
        long double s = sinl(x);
        long double c = cosl(x);
        if (sinp) write_ld_to_guest(emu, sinp, s);  // Write 128-bit binary128 format
        if (cosp) write_ld_to_guest(emu, cosp, c);
    });

    // ========================================================================
    // FP classification functions
    // ========================================================================

    // Bionic FP classification constants (different from glibc!)
    // FP_INFINITE = 0x01, FP_NAN = 0x02, FP_NORMAL = 0x04, FP_SUBNORMAL = 0x08, FP_ZERO = 0x10
    hle.register_function("__fpclassify", [](Emulator& emu) {
        double x = get_dreg(emu, 0);
        int result;
        if (std::isnan(x)) result = 0x02;       // FP_NAN
        else if (std::isinf(x)) result = 0x01;  // FP_INFINITE
        else if (x == 0.0) result = 0x10;       // FP_ZERO
        else if (!std::isnormal(x)) result = 0x08; // FP_SUBNORMAL
        else result = 0x04;                     // FP_NORMAL
        set_reg(emu, UC_ARM64_REG_X0, result);
    });
    hle.register_function("__fpclassifyf", [](Emulator& emu) {
        float x = get_sreg(emu, UC_ARM64_REG_S0);
        int result;
        if (std::isnan(x)) result = 0x02;       // FP_NAN
        else if (std::isinf(x)) result = 0x01;  // FP_INFINITE
        else if (x == 0.0f) result = 0x10;      // FP_ZERO
        else if (!std::isnormal(x)) result = 0x08; // FP_SUBNORMAL
        else result = 0x04;                     // FP_NORMAL
        set_reg(emu, UC_ARM64_REG_X0, result);
    });
    hle.register_function("__fpclassifyl", [](Emulator& emu) {
        long double x = get_ldreg(emu, 0);
        int result;
        if (std::isnan(x)) result = 0x02;       // FP_NAN
        else if (std::isinf(x)) result = 0x01;  // FP_INFINITE
        else if (x == 0.0L) result = 0x10;      // FP_ZERO
        else if (!std::isnormal(x)) result = 0x08; // FP_SUBNORMAL
        else result = 0x04;                     // FP_NORMAL
        set_reg(emu, UC_ARM64_REG_X0, result);
    });
    hle.register_function("__signbit", [](Emulator& emu) {
        double x = get_dreg(emu, 0);
        set_reg(emu, UC_ARM64_REG_X0, std::signbit(x) ? 1 : 0);
    });
    hle.register_function("__signbitf", [](Emulator& emu) {
        float x = get_sreg(emu, UC_ARM64_REG_S0);
        set_reg(emu, UC_ARM64_REG_X0, std::signbit(x) ? 1 : 0);
    });
    hle.register_function("__signbitl", [](Emulator& emu) {
        long double x = get_ldreg(emu, 0);
        set_reg(emu, UC_ARM64_REG_X0, std::signbit(x) ? 1 : 0);
    });
    hle.register_function("__isnormal", [](Emulator& emu) {
        double x = get_dreg(emu, 0);
        set_reg(emu, UC_ARM64_REG_X0, std::isnormal(x) ? 1 : 0);
    });
    hle.register_function("__isnormalf", [](Emulator& emu) {
        float x = get_sreg(emu, UC_ARM64_REG_S0);
        set_reg(emu, UC_ARM64_REG_X0, std::isnormal(x) ? 1 : 0);
    });
    hle.register_function("isnormalf", [](Emulator& emu) {
        float x = get_sreg(emu, UC_ARM64_REG_S0);
        set_reg(emu, UC_ARM64_REG_X0, std::isnormal(x) ? 1 : 0);
    });
    hle.register_function("__isnormall", [](Emulator& emu) {
        long double x = get_ldreg(emu, 0);
        set_reg(emu, UC_ARM64_REG_X0, std::isnormal(x) ? 1 : 0);
    });
    hle.register_function("isnormall", [](Emulator& emu) {
        long double x = get_ldreg(emu, 0);
        set_reg(emu, UC_ARM64_REG_X0, std::isnormal(x) ? 1 : 0);
    });
}

} // namespace cross_shim
