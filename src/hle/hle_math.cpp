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
#include "emu_compat.h"
#include <cmath>

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
        int exp;
        double result = frexp(x, &exp);
        set_dreg(emu, 0, result);
    });

    hle.register_function("modf", [](Emulator& emu) {
        double x = get_dreg(emu, 0);
        double ipart;
        double result = modf(x, &ipart);
        set_dreg(emu, 0, result);
    });

    hle.register_function("modff", [](Emulator& emu) {
        float x = get_sreg(emu, UC_ARM64_REG_S0);
        float ipart;
        float result = modff(x, &ipart);
        set_sreg(emu, UC_ARM64_REG_S0, result);
    });

    hle.register_function("ldexpf", [](Emulator& emu) {
        float x = get_sreg(emu, UC_ARM64_REG_S0);
        uint64_t exp = get_reg(emu, UC_ARM64_REG_X0);
        set_sreg(emu, UC_ARM64_REG_S0, ldexpf(x, (int)exp));
    });

    hle.register_function("frexpf", [](Emulator& emu) {
        float x = get_sreg(emu, UC_ARM64_REG_S0);
        int exp;
        float result = frexpf(x, &exp);
        set_sreg(emu, UC_ARM64_REG_S0, result);
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

    hle.register_function("ilogb", [](Emulator& emu) {
        double x = get_dreg(emu, 0);
        uint64_t result = ilogb(x);
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("ilogbf", [](Emulator& emu) {
        float x = get_sreg(emu, UC_ARM64_REG_S0);
        uint64_t result = ilogbf(x);
        set_reg(emu, UC_ARM64_REG_X0, result);
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
}

} // namespace cross_shim
