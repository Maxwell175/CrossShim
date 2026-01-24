/**
 * HLE Memory Functions
 * malloc, calloc, realloc, free, mmap, mprotect, munmap, mlock, madvise
 */

#include "debug_log.h"
#include "hle_manager.h"
#include "cross_shim.h"
#include "memory_manager.h"
#include "emu_compat.h"
#include <cstring>
#include <iostream>
#include <vector>
#include <sys/mman.h>

namespace cross_shim {

// get_reg and set_reg are provided by emu_compat.h

void register_hle_memory(HleManager& hle) {
    // ========================================================================
    // Basic allocation
    // ========================================================================
    
    hle.register_function("malloc", [](Emulator& emu) {
        uint64_t size = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t ptr = emu.memory().heap().allocate(size, 16);
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
        uint64_t ptr = emu.memory().heap().allocate(total, 16);
        if (ptr) emu.memory().zero(ptr, total);
        set_reg(emu, UC_ARM64_REG_X0, ptr);
    });

    hle.register_function("realloc", [](Emulator& emu) {
        uint64_t old_ptr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t new_size = get_reg(emu, UC_ARM64_REG_X1);

        if (old_ptr == 0) {
            // realloc(NULL, size) is equivalent to malloc(size)
            uint64_t new_ptr = emu.memory().heap().allocate(new_size, 16);
            set_reg(emu, UC_ARM64_REG_X0, new_ptr);
            return;
        }

        if (new_size == 0) {
            // realloc(ptr, 0) is equivalent to free(ptr)
            emu.memory().heap().free(old_ptr);
            set_reg(emu, UC_ARM64_REG_X0, 0);
            return;
        }

        // Get old size
        uint64_t old_size = emu.memory().heap().get_allocation_size(old_ptr);
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

        // Allocate new block
        uint64_t new_ptr = emu.memory().heap().allocate(new_size, 16);
        if (new_ptr == 0) {
            set_reg(emu, UC_ARM64_REG_X0, 0);
            return;
        }

        // Copy old data to new block
        std::vector<uint8_t> data(old_size);
        emu.mem_read(old_ptr, data.data(), old_size);
        emu.mem_write(new_ptr, data.data(), old_size);

        // Free old block
        emu.memory().heap().free(old_ptr);

        set_reg(emu, UC_ARM64_REG_X0, new_ptr);
    });

    hle.register_function("free", [](Emulator& emu) {
        uint64_t ptr = get_reg(emu, UC_ARM64_REG_X0);
        if (ptr) emu.memory().heap().free(ptr);
    });

    hle.register_function("posix_memalign", [](Emulator& emu) {
        uint64_t memptr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t alignment = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t size = get_reg(emu, UC_ARM64_REG_X2);
        uint64_t ptr = emu.memory().heap().allocate(size, alignment);
        if (ptr) {
            emu.mem_write(memptr, &ptr, sizeof(ptr));
            set_reg(emu, UC_ARM64_REG_X0, 0);
        } else {
            set_reg(emu, UC_ARM64_REG_X0, 12); // ENOMEM
        }
    });

    hle.register_function("aligned_alloc", [](Emulator& emu) {
        uint64_t alignment = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t size = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t ptr = emu.memory().heap().allocate(size, alignment);
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
        
        // Simplified: just allocate from heap
        uint64_t ptr = emu.memory().heap().allocate(length, 4096);
        if (ptr) {
            emu.memory().zero(ptr, length);
        }
        set_reg(emu, UC_ARM64_REG_X0, ptr ? ptr : (uint64_t)-1);
    });

    hle.register_function("mmap64", [](Emulator& emu) {
        uint64_t length = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t ptr = emu.memory().heap().allocate(length, 4096);
        if (ptr) emu.memory().zero(ptr, length);
        set_reg(emu, UC_ARM64_REG_X0, ptr ? ptr : (uint64_t)-1);
    });

    hle.register_function("munmap", [](Emulator& emu) {
        uint64_t addr = get_reg(emu, UC_ARM64_REG_X0);
        // uint64_t length = get_reg(emu, UC_ARM64_REG_X1);
        if (addr) emu.memory().heap().free(addr);
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

    // Static brk tracking
    static uint64_t current_brk = 0;

    hle.register_function("brk", [](Emulator& emu) {
        uint64_t addr = get_reg(emu, UC_ARM64_REG_X0);
        if (current_brk == 0) {
            current_brk = emu.memory().heap().get_base();
        }
        if (addr != 0) {
            current_brk = addr;
        }
        set_reg(emu, UC_ARM64_REG_X0, current_brk);
    });

    hle.register_function("sbrk", [](Emulator& emu) {
        int64_t increment = static_cast<int64_t>(get_reg(emu, UC_ARM64_REG_X0));
        if (current_brk == 0) {
            current_brk = emu.memory().heap().get_base();
        }
        uint64_t old_brk = current_brk;
        if (increment != 0) {
            current_brk += increment;
        }
        set_reg(emu, UC_ARM64_REG_X0, old_brk);
    });
}

} // namespace cross_shim
