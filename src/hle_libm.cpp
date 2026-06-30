#include "hle_manager.h"
#include "cross_shim.h"
#include "emu_compat.h"
#include "memory_manager.h"
#include <cmath>
#include <string>

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

// Read a NUL-terminated guest C-string (for dlopen/dlsym path and name args).
static std::string read_guest_cstr(Emulator& emu, uint64_t addr, size_t max_len = 4096) {
    std::string s;
    if (addr == 0) return s;
    s.reserve(64);
    for (size_t i = 0; i < max_len; i++) {
        char c = 0;
        if (!emu.mem_read(addr + i, &c, 1) || c == 0) break;
        s.push_back(c);
    }
    return s;
}

// Register libdl HLE functions: a real, generic dynamic loader backed by the
// emulator's ELF loader (dl_open/dl_sym/dl_close/dl_addr in emulator.cpp).
void register_libdl_hle(HleManager& hle) {
    // void* dlopen(const char* filename, int flag)
    hle.register_function("dlopen", [](Emulator& emu) {
        uint64_t path_ptr = get_reg(emu, UC_ARM64_REG_X0);
        int flags = static_cast<int>(get_reg(emu, UC_ARM64_REG_X1));
        if (path_ptr == 0) {
            // dlopen(NULL) -> a handle to the "global" scope; use RTLD_DEFAULT (0).
            set_reg(emu, UC_ARM64_REG_X0, 0);
            return;
        }
        std::string path = read_guest_cstr(emu, path_ptr);
        uint64_t handle = emu.dl_open(path, flags);
        set_reg(emu, UC_ARM64_REG_X0, handle);
    });

    // void* dlsym(void* handle, const char* symbol)
    hle.register_function("dlsym", [](Emulator& emu) {
        uint64_t handle = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t name_ptr = get_reg(emu, UC_ARM64_REG_X1);
        std::string name = read_guest_cstr(emu, name_ptr);
        uint64_t addr = emu.dl_sym(handle, name);
        set_reg(emu, UC_ARM64_REG_X0, addr);
    });

    // int dlclose(void* handle)
    hle.register_function("dlclose", [](Emulator& emu) {
        uint64_t handle = get_reg(emu, UC_ARM64_REG_X0);
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(emu.dl_close(handle)));
    });

    // char* dlerror(void) - returns a guest-resident string (cleared on read), or NULL.
    hle.register_function("dlerror", [](Emulator& emu) {
        std::string err = emu.dl_take_error();
        if (err.empty()) {
            set_reg(emu, UC_ARM64_REG_X0, 0);
            return;
        }
        // Reusable per-thread guest scratch buffer (matches tl_dl_error's thread-local
        // semantics and the convention used by other reusable-buffer HLE handlers).
        static thread_local uint64_t err_buf = 0;
        static thread_local size_t err_buf_sz = 0;
        size_t need = err.size() + 1;
        if (err_buf == 0 || need > err_buf_sz) {
            err_buf_sz = need < 512 ? 512 : need;
            err_buf = emu.memory().allocate_guest_memory(err_buf_sz, 8);
        }
        if (err_buf != 0) {
            emu.mem_write(err_buf, err.c_str(), need);
        }
        set_reg(emu, UC_ARM64_REG_X0, err_buf);
    });

    // int dladdr(const void* addr, Dl_info* info)
    hle.register_function("dladdr", [](Emulator& emu) {
        uint64_t addr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t info_ptr = get_reg(emu, UC_ARM64_REG_X1);
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(emu.dl_addr(addr, info_ptr)));
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
