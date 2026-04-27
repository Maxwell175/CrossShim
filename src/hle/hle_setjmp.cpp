/**
 * HLE Non-local Jump Functions (setjmp/longjmp)
 *
 * We keep the guest-visible storage inside the bionic arm64 jmp_buf footprint
 * (32 words / 256 bytes), but the exact layout is CrossShim-owned because the
 * guest test coverage only relies on behavior, not the raw storage contents in
 * the non-death-test path.
 */

#include "debug_log.h"
#include "hle_manager.h"
#include "hle_signal_state.h"
#include "cross_shim.h"
#include "memory_manager.h"
#include "emu_compat.h"
#include <cstddef>
#include <cstdint>

namespace cross_shim {

namespace {

constexpr size_t JMPBUF_X19_OFFSET = 0;
constexpr size_t JMPBUF_FP_OFFSET = 10;
constexpr size_t JMPBUF_LR_OFFSET = 11;
constexpr size_t JMPBUF_SP_OFFSET = 12;
constexpr size_t JMPBUF_D8_OFFSET = 13;
constexpr size_t JMPBUF_FLAGS_OFFSET = 21;
constexpr size_t JMPBUF_SIGMASK_OFFSET = 22;
constexpr uint64_t JMPBUF_FLAG_SAVE_SIGMASK = 1ULL << 0;

constexpr uint64_t word_offset(size_t word_index) {
    return static_cast<uint64_t>(word_index * sizeof(uint64_t));
}

void save_jmp_context(Emulator& emu, uint64_t env, bool save_signal_mask) {
    if (env == 0) {
        return;
    }

    for (int i = 0; i < 10; ++i) {
        uint64_t value = get_reg(emu, UC_ARM64_REG_X19 + i);
        emu.mem_write(env + word_offset(JMPBUF_X19_OFFSET + i), &value, sizeof(value));
    }

    uint64_t fp = get_reg(emu, UC_ARM64_REG_X29);
    uint64_t lr = get_reg(emu, UC_ARM64_REG_X30);
    uint64_t sp = get_reg(emu, UC_ARM64_REG_SP);
    emu.mem_write(env + word_offset(JMPBUF_FP_OFFSET), &fp, sizeof(fp));
    emu.mem_write(env + word_offset(JMPBUF_LR_OFFSET), &lr, sizeof(lr));
    emu.mem_write(env + word_offset(JMPBUF_SP_OFFSET), &sp, sizeof(sp));

    for (int i = 0; i < 8; ++i) {
        double value = get_dreg(emu, 8 + i);
        emu.mem_write(env + word_offset(JMPBUF_D8_OFFSET + i), &value, sizeof(value));
    }

    uint64_t flags = save_signal_mask ? JMPBUF_FLAG_SAVE_SIGMASK : 0;
    uint64_t signal_mask = save_signal_mask ? hle_signal_current_mask() : 0;
    emu.mem_write(env + word_offset(JMPBUF_FLAGS_OFFSET), &flags, sizeof(flags));
    emu.mem_write(env + word_offset(JMPBUF_SIGMASK_OFFSET), &signal_mask, sizeof(signal_mask));
}

void restore_jmp_context(Emulator& emu, uint64_t env, int value, bool restore_signal_mask) {
    if (env == 0) {
        return;
    }

    for (int i = 0; i < 10; ++i) {
        uint64_t reg_value = 0;
        emu.mem_read(env + word_offset(JMPBUF_X19_OFFSET + i), &reg_value, sizeof(reg_value));
        set_reg(emu, UC_ARM64_REG_X19 + i, reg_value);
    }

    uint64_t fp = 0;
    uint64_t lr = 0;
    uint64_t sp = 0;
    emu.mem_read(env + word_offset(JMPBUF_FP_OFFSET), &fp, sizeof(fp));
    emu.mem_read(env + word_offset(JMPBUF_LR_OFFSET), &lr, sizeof(lr));
    emu.mem_read(env + word_offset(JMPBUF_SP_OFFSET), &sp, sizeof(sp));
    set_reg(emu, UC_ARM64_REG_X29, fp);
    set_reg(emu, UC_ARM64_REG_X30, lr);
    set_reg(emu, UC_ARM64_REG_SP, sp);

    for (int i = 0; i < 8; ++i) {
        double fp_value = 0.0;
        emu.mem_read(env + word_offset(JMPBUF_D8_OFFSET + i), &fp_value, sizeof(fp_value));
        set_dreg(emu, 8 + i, fp_value);
    }

    uint64_t flags = 0;
    uint64_t signal_mask = 0;
    emu.mem_read(env + word_offset(JMPBUF_FLAGS_OFFSET), &flags, sizeof(flags));
    emu.mem_read(env + word_offset(JMPBUF_SIGMASK_OFFSET), &signal_mask, sizeof(signal_mask));
    if (restore_signal_mask && (flags & JMPBUF_FLAG_SAVE_SIGMASK) != 0) {
        hle_signal_set_mask(signal_mask);
    }

    set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(value));
    set_reg(emu, UC_ARM64_REG_PC, lr);
}

} // namespace

void register_hle_setjmp(HleManager& hle) {
    // setjmp - save calling environment
    hle.register_function("setjmp", [](Emulator& emu) {
        uint64_t env = get_reg(emu, UC_ARM64_REG_X0);
        save_jmp_context(emu, env, true);
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    // _setjmp - setjmp without signal mask save
    hle.register_function("_setjmp", [](Emulator& emu) {
        uint64_t env = get_reg(emu, UC_ARM64_REG_X0);
        save_jmp_context(emu, env, false);
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    // sigsetjmp - setjmp with optional signal mask save
    hle.register_function("sigsetjmp", [](Emulator& emu) {
        uint64_t env = get_reg(emu, UC_ARM64_REG_X0);
        bool save_signal_mask = get_reg(emu, UC_ARM64_REG_X1) != 0;
        save_jmp_context(emu, env, save_signal_mask);
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    // longjmp - restore saved environment
    hle.register_function("longjmp", [](Emulator& emu) {
        uint64_t env = get_reg(emu, UC_ARM64_REG_X0);
        int value = static_cast<int>(get_reg(emu, UC_ARM64_REG_X1));
        if (value == 0) {
            value = 1;
        }
        restore_jmp_context(emu, env, value, true);
    });

    // _longjmp - longjmp without signal mask restore
    hle.register_function("_longjmp", [](Emulator& emu) {
        uint64_t env = get_reg(emu, UC_ARM64_REG_X0);
        int value = static_cast<int>(get_reg(emu, UC_ARM64_REG_X1));
        if (value == 0) {
            value = 1;
        }
        restore_jmp_context(emu, env, value, false);
    });

    // siglongjmp - longjmp with signal mask restore
    hle.register_function("siglongjmp", [](Emulator& emu) {
        uint64_t env = get_reg(emu, UC_ARM64_REG_X0);
        int value = static_cast<int>(get_reg(emu, UC_ARM64_REG_X1));
        if (value == 0) {
            value = 1;
        }
        restore_jmp_context(emu, env, value, true);
    });
}

} // namespace cross_shim
