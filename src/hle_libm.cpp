#include "hle_manager.h"
#include "cross_shim.h"
#include "emu_compat.h"
#include <cmath>

namespace cross_shim {

void register_libm_hle(HleManager& hle) {
    // Double precision math functions
    hle.register_function("sin", [](Emulator& emu) {
        double x = get_dreg(emu, 0);
        set_dreg(emu, 0, sin(x));
    });

    hle.register_function("cos", [](Emulator& emu) {
        double x = get_dreg(emu, 0);
        set_dreg(emu, 0, cos(x));
    });

    hle.register_function("tan", [](Emulator& emu) {
        double x = get_dreg(emu, 0);
        set_dreg(emu, 0, tan(x));
    });

    hle.register_function("sqrt", [](Emulator& emu) {
        double x = get_dreg(emu, 0);
        set_dreg(emu, 0, sqrt(x));
    });

    hle.register_function("pow", [](Emulator& emu) {
        double x = get_dreg(emu, 0);
        double y = get_dreg(emu, 1);
        set_dreg(emu, 0, pow(x, y));
    });

    hle.register_function("exp", [](Emulator& emu) {
        double x = get_dreg(emu, 0);
        set_dreg(emu, 0, exp(x));
    });

    hle.register_function("log", [](Emulator& emu) {
        double x = get_dreg(emu, 0);
        set_dreg(emu, 0, log(x));
    });

    hle.register_function("log10", [](Emulator& emu) {
        double x = get_dreg(emu, 0);
        set_dreg(emu, 0, log10(x));
    });

    hle.register_function("floor", [](Emulator& emu) {
        double x = get_dreg(emu, 0);
        set_dreg(emu, 0, floor(x));
    });

    hle.register_function("ceil", [](Emulator& emu) {
        double x = get_dreg(emu, 0);
        set_dreg(emu, 0, ceil(x));
    });

    hle.register_function("fabs", [](Emulator& emu) {
        double x = get_dreg(emu, 0);
        set_dreg(emu, 0, fabs(x));
    });

    hle.register_function("fmod", [](Emulator& emu) {
        double x = get_dreg(emu, 0);
        double y = get_dreg(emu, 1);
        set_dreg(emu, 0, fmod(x, y));
    });

    // Single precision math functions
    hle.register_function("sinf", [](Emulator& emu) {
        float x = get_sreg(emu, UC_ARM64_REG_S0);
        set_sreg(emu, UC_ARM64_REG_S0, sinf(x));
    });

    hle.register_function("cosf", [](Emulator& emu) {
        float x = get_sreg(emu, UC_ARM64_REG_S0);
        set_sreg(emu, UC_ARM64_REG_S0, cosf(x));
    });

    hle.register_function("sqrtf", [](Emulator& emu) {
        float x = get_sreg(emu, UC_ARM64_REG_S0);
        set_sreg(emu, UC_ARM64_REG_S0, sqrtf(x));
    });

    hle.register_function("powf", [](Emulator& emu) {
        float x = get_sreg(emu, UC_ARM64_REG_S0);
        float y = get_sreg(emu, UC_ARM64_REG_S1);
        set_sreg(emu, UC_ARM64_REG_S0, powf(x, y));
    });

    hle.register_function("floorf", [](Emulator& emu) {
        float x = get_sreg(emu, UC_ARM64_REG_S0);
        set_sreg(emu, UC_ARM64_REG_S0, floorf(x));
    });

    hle.register_function("ceilf", [](Emulator& emu) {
        float x = get_sreg(emu, UC_ARM64_REG_S0);
        set_sreg(emu, UC_ARM64_REG_S0, ceilf(x));
    });

    hle.register_function("fabsf", [](Emulator& emu) {
        float x = get_sreg(emu, UC_ARM64_REG_S0);
        set_sreg(emu, UC_ARM64_REG_S0, fabsf(x));
    });
}

// Register libdl HLE functions
void register_libdl_hle(HleManager& hle) {
    hle.register_function("dlopen", [](Emulator& emu) {
        // Return NULL - we don't support dynamic loading
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("dlsym", [](Emulator& emu) {
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("dlclose", [](Emulator& emu) {
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("dlerror", [](Emulator& emu) {
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });
}

// Register pthread HLE functions
void register_pthread_hle(HleManager& hle) {
    hle.register_function("pthread_mutex_init", [](Emulator& emu) {
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("pthread_mutex_lock", [](Emulator& emu) {
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("pthread_mutex_unlock", [](Emulator& emu) {
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("pthread_mutex_destroy", [](Emulator& emu) {
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("pthread_self", [](Emulator& emu) {
        set_reg(emu, UC_ARM64_REG_X0, 1);  // Fake thread ID
    });

    hle.register_function("pthread_once", [](Emulator& emu) {
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });
}

} // namespace cross_shim
