/**
 * HLE Memory Functions
 * malloc, calloc, realloc, free, mmap, mprotect, munmap, mlock, madvise
 */

#include "debug_log.h"
#include "hle_manager.h"
#include "cross_shim.h"
#include "hle_mmap_state.h"
#include "memory_manager.h"
#include "emu_compat.h"
#include "hle_brk_state.h"
#include <cstring>
#include <iostream>
#include <vector>
#include <sys/mman.h>
#include <limits>
#include <atomic>

namespace cross_shim {

// get_reg and set_reg are provided by emu_compat.h

static std::atomic<uint64_t> g_next_mmap_reservation_key{0xF000000000000000ULL};

static bool is_power_of_two(uint64_t value) {
    return value != 0 && (value & (value - 1)) == 0;
}

void register_hle_memory(HleManager& hle) {
    // ========================================================================
    // Basic allocation
    // ========================================================================
    
    hle.register_function("malloc", [](Emulator& emu) {
        uint64_t size = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t ptr = emu.memory().allocate_guest_memory(size, 16);
        // Log allocations for debugging - especially 0x2350 which is IKalayAVNew
        if (size == 0x2350 || ptr == 0) {
            EMU_LOG << "[HLE] malloc: size=0x" << std::hex << size << " ptr=0x" << ptr << std::dec << std::endl;
        }
        set_reg(emu, UC_ARM64_REG_X0, ptr);
    });

    hle.register_function("calloc", [](Emulator& emu) {
        uint64_t nmemb = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t size = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t total = nmemb * size;
        uint64_t ptr = emu.memory().allocate_guest_memory(total, 16);
        if (ptr) emu.memory().zero(ptr, total);
        set_reg(emu, UC_ARM64_REG_X0, ptr);
    });

    hle.register_function("realloc", [](Emulator& emu) {
        uint64_t old_ptr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t new_size = get_reg(emu, UC_ARM64_REG_X1);

        if (old_ptr == 0) {
            // realloc(NULL, size) is equivalent to malloc(size)
            uint64_t new_ptr = emu.memory().allocate_guest_memory(new_size, 16);
            set_reg(emu, UC_ARM64_REG_X0, new_ptr);
            return;
        }

        if (new_size == 0) {
            // realloc(ptr, 0) is equivalent to free(ptr)
            emu.memory().free_guest_memory(old_ptr);
            set_reg(emu, UC_ARM64_REG_X0, 0);
            return;
        }

        // Get old size
        uint64_t old_size = emu.memory().get_guest_allocation_size(old_ptr);
        if (old_size == 0) {
            // Invalid pointer
            set_reg(emu, UC_ARM64_REG_X0, 0);
            return;
        }

        if (new_size <= old_size) {
            // Shrinking - just return the same pointer
            set_reg(emu, UC_ARM64_REG_X0, old_ptr);
            return;
        }

        uint64_t new_ptr = emu.memory().realloc_guest_memory(old_ptr, new_size);
        set_reg(emu, UC_ARM64_REG_X0, new_ptr);
    });

    hle.register_function("free", [](Emulator& emu) {
        uint64_t ptr = get_reg(emu, UC_ARM64_REG_X0);
        if (ptr) emu.memory().free_guest_memory(ptr);
    });

    hle.register_function("posix_memalign", [](Emulator& emu) {
        uint64_t memptr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t alignment = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t size = get_reg(emu, UC_ARM64_REG_X2);
        constexpr uint64_t kGuestPointerSize = 8;

        if (memptr == 0 || alignment < kGuestPointerSize || !is_power_of_two(alignment) ||
            (alignment % kGuestPointerSize) != 0) {
            set_reg(emu, UC_ARM64_REG_X0, EINVAL);
            return;
        }
        if (size > static_cast<uint64_t>(std::numeric_limits<intptr_t>::max())) {
            set_reg(emu, UC_ARM64_REG_X0, ENOMEM);
            return;
        }

        uint64_t ptr = emu.memory().allocate_guest_memory(size, alignment);
        if (ptr) {
            emu.mem_write(memptr, &ptr, sizeof(ptr));
            set_reg(emu, UC_ARM64_REG_X0, 0);
        } else {
            set_reg(emu, UC_ARM64_REG_X0, ENOMEM);
        }
    });

    hle.register_function("aligned_alloc", [](Emulator& emu) {
        uint64_t alignment = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t size = get_reg(emu, UC_ARM64_REG_X1);

        if (!is_power_of_two(alignment) || size > static_cast<uint64_t>(std::numeric_limits<intptr_t>::max())) {
            hle_set_errno(emu, !is_power_of_two(alignment) ? EINVAL : ENOMEM);
            set_reg(emu, UC_ARM64_REG_X0, 0);
            return;
        }
        if (size % alignment != 0) {
            hle_set_errno(emu, EINVAL);
            set_reg(emu, UC_ARM64_REG_X0, 0);
            return;
        }

        uint64_t ptr = emu.memory().allocate_guest_memory(size, alignment);
        if (ptr == 0) {
            hle_set_errno(emu, ENOMEM);
        }
        set_reg(emu, UC_ARM64_REG_X0, ptr);
    });

    // ========================================================================
    // Memory mapping (simplified - uses heap)
    // ========================================================================
    
    hle.register_function("mmap", [](Emulator& emu) {
        uint64_t addr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t length = get_reg(emu, UC_ARM64_REG_X1);
        // int prot = get_reg(emu, UC_ARM64_REG_X2);
        // int flags = get_reg(emu, UC_ARM64_REG_X3);
        // int fd = get_reg(emu, UC_ARM64_REG_X4);
        // off_t offset = get_reg(emu, UC_ARM64_REG_X5);
        
        uint64_t reservation_key = g_next_mmap_reservation_key.fetch_add(0x1000);
        if (!hle_try_reserve_vmas(reservation_key, 1)) {
            hle_set_errno(emu, ENOMEM);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        // Simplified: just allocate from heap
        uint64_t ptr = emu.memory().allocate_guest_memory(length, 4096);
        if (ptr) {
            emu.memory().zero(ptr, length);
            hle_release_vmas(reservation_key);
            hle_try_reserve_vmas(ptr, 1);
        } else {
            hle_release_vmas(reservation_key);
            hle_set_errno(emu, ENOMEM);
        }
        set_reg(emu, UC_ARM64_REG_X0, ptr ? ptr : (uint64_t)-1);
    });

    hle.register_function("mmap64", [](Emulator& emu) {
        uint64_t length = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t reservation_key = g_next_mmap_reservation_key.fetch_add(0x1000);
        if (!hle_try_reserve_vmas(reservation_key, 1)) {
            hle_set_errno(emu, ENOMEM);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }
        uint64_t ptr = emu.memory().allocate_guest_memory(length, 4096);
        if (ptr) {
            emu.memory().zero(ptr, length);
            hle_release_vmas(reservation_key);
            hle_try_reserve_vmas(ptr, 1);
        } else {
            hle_release_vmas(reservation_key);
            hle_set_errno(emu, ENOMEM);
        }
        set_reg(emu, UC_ARM64_REG_X0, ptr ? ptr : (uint64_t)-1);
    });

    hle.register_function("munmap", [](Emulator& emu) {
        uint64_t addr = get_reg(emu, UC_ARM64_REG_X0);
        // uint64_t length = get_reg(emu, UC_ARM64_REG_X1);
        if (addr) emu.memory().free_guest_memory(addr);
        hle_release_vmas(addr);
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("mprotect", [](Emulator& emu) {
        // Simplified: always succeed
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("mlock", [](Emulator& emu) {
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("munlock", [](Emulator& emu) {
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("madvise", [](Emulator& emu) {
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    // ========================================================================
    // Program break (brk/sbrk) - simplified implementation
    // ========================================================================

    hle.register_function("brk", [](Emulator& emu) {
        uint64_t addr = get_reg(emu, UC_ARM64_REG_X0);
        guest_brk_initialize(emu.memory().heap().get_base());
        GuestBrkState& state = guest_brk_state();

        if (addr == 0 || addr > static_cast<uint64_t>(std::numeric_limits<intptr_t>::max())) {
            hle_set_errno(emu, ENOMEM);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        state.current_brk = addr;
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("sbrk", [](Emulator& emu) {
        int64_t increment = static_cast<int64_t>(get_reg(emu, UC_ARM64_REG_X0));
        guest_brk_initialize(emu.memory().heap().get_base());
        GuestBrkState& state = guest_brk_state();

        uint64_t old_brk = state.current_brk;
        if (increment == 0) {
            set_reg(emu, UC_ARM64_REG_X0, old_brk);
            return;
        }

        intptr_t new_brk = 0;
        if (__builtin_add_overflow(static_cast<intptr_t>(state.current_brk),
                                   static_cast<intptr_t>(increment), &new_brk) ||
            new_brk < 0) {
            hle_set_errno(emu, ENOMEM);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        state.current_brk = static_cast<uint64_t>(new_brk);
        set_reg(emu, UC_ARM64_REG_X0, old_brk);
    });
}

} // namespace cross_shim
