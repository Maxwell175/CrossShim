#include "hle_manager.h"
#include "cross_shim.h"
#include "memory_manager.h"
#include "thread_manager.h"
#include "emu_compat.h"
#include <cstring>
#include <cstdlib>
#include <iostream>

namespace cross_shim {

void register_libc_hle(HleManager& hle) {
    // Memory allocation
    hle.register_function("malloc", [](Emulator& emu) {
        uint64_t size = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t ptr = emu.memory().allocate_guest_memory(size, 16);
        if (ptr) emu.memory().zero(ptr, size);
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
        uint64_t new_ptr = emu.memory().realloc_guest_memory(old_ptr, new_size);
        set_reg(emu, UC_ARM64_REG_X0, new_ptr);
    });

    hle.register_function("free", [](Emulator& emu) {
        uint64_t ptr = get_reg(emu, UC_ARM64_REG_X0);
        if (ptr) emu.memory().free_guest_memory(ptr);
    });

    // String functions
    hle.register_function("strlen", [](Emulator& emu) {
        uint64_t s = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t len = 0;
        char c;
        while (emu.mem_read(s + len, &c, 1) && c != '\0') len++;
        set_reg(emu, UC_ARM64_REG_X0, len);
    });

    hle.register_function("memcpy", [](Emulator& emu) {
        uint64_t dest = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t src = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t n = get_reg(emu, UC_ARM64_REG_X2);
        std::vector<uint8_t> buf(n);
        emu.mem_read(src, buf.data(), n);
        emu.mem_write(dest, buf.data(), n);
        set_reg(emu, UC_ARM64_REG_X0, dest);
    });

    hle.register_function("memmove", [](Emulator& emu) {
        uint64_t dest = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t src = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t n = get_reg(emu, UC_ARM64_REG_X2);
        std::vector<uint8_t> buf(n);
        emu.mem_read(src, buf.data(), n);
        emu.mem_write(dest, buf.data(), n);
        set_reg(emu, UC_ARM64_REG_X0, dest);
    });

    hle.register_function("memset", [](Emulator& emu) {
        uint64_t s = get_reg(emu, UC_ARM64_REG_X0);
        int c = get_reg(emu, UC_ARM64_REG_X1) & 0xFF;
        uint64_t n = get_reg(emu, UC_ARM64_REG_X2);
        std::vector<uint8_t> buf(n, c);
        emu.mem_write(s, buf.data(), n);
        set_reg(emu, UC_ARM64_REG_X0, s);
    });

    hle.register_function("memcmp", [](Emulator& emu) {
        uint64_t s1 = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t s2 = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t n = get_reg(emu, UC_ARM64_REG_X2);
        std::vector<uint8_t> buf1(n), buf2(n);
        emu.mem_read(s1, buf1.data(), n);
        emu.mem_read(s2, buf2.data(), n);
        int result = memcmp(buf1.data(), buf2.data(), n);
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("strcmp", [](Emulator& emu) {
        uint64_t s1 = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t s2 = get_reg(emu, UC_ARM64_REG_X1);
        std::string str1, str2;
        char c;
        while (emu.mem_read(s1++, &c, 1) && c) str1 += c;
        while (emu.mem_read(s2++, &c, 1) && c) str2 += c;
        set_reg(emu, UC_ARM64_REG_X0, strcmp(str1.c_str(), str2.c_str()));
    });

    hle.register_function("strncmp", [](Emulator& emu) {
        uint64_t s1 = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t s2 = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t n = get_reg(emu, UC_ARM64_REG_X2);
        std::vector<char> buf1(n+1, 0), buf2(n+1, 0);
        for (uint64_t i = 0; i < n; i++) {
            emu.mem_read(s1 + i, &buf1[i], 1);
            emu.mem_read(s2 + i, &buf2[i], 1);
            if (!buf1[i] || !buf2[i]) break;
        }
        set_reg(emu, UC_ARM64_REG_X0, strncmp(buf1.data(), buf2.data(), n));
    });

    hle.register_function("strcpy", [](Emulator& emu) {
        uint64_t dest = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t src = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t i = 0;
        char c;
        do {
            emu.mem_read(src + i, &c, 1);
            emu.mem_write(dest + i, &c, 1);
            i++;
        } while (c);
        set_reg(emu, UC_ARM64_REG_X0, dest);
    });

    // I/O stubs
    hle.register_function("printf", [](Emulator& emu) {
        set_reg(emu, UC_ARM64_REG_X0, 0);  // Return 0 (simplified)
    });

    hle.register_function("puts", [](Emulator& emu) {
        uint64_t s = get_reg(emu, UC_ARM64_REG_X0);
        std::string str;
        char c;
        while (emu.mem_read(s++, &c, 1) && c) str += c;
        std::cout << str << std::endl;
        set_reg(emu, UC_ARM64_REG_X0, 1);
    });

    // Error handling - __errno is implemented in hle_misc.cpp
    // Using consistent address TLS_BASE + 0x100 = 0xC0000100

    hle.register_function("abort", [](Emulator& emu) {
        emu.stop();
    });
}

} // namespace cross_shim
