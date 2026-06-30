/**
 * HLE Memory Operations
 * memcpy, memset, memcmp, memmove, memchr, memrchr
 */

#include "hle_manager.h"
#include "cross_shim.h"
#include "memory_manager.h"
#include "emu_compat.h"
#include "debug_log.h"
#include <cstring>
#include <vector>
#include <iostream>

namespace cross_shim {

// get_reg and set_reg are provided by emu_compat.h

void register_hle_mem_ops(HleManager& hle) {
    // memcpy - uses direct host memory when both src and dest are in host memory
    hle.register_function("memcpy", [](Emulator& emu) {
        uint64_t dest = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t src = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t n = get_reg(emu, UC_ARM64_REG_X2);
        if (n > 0) {
            // Try direct host memory access (fastest path)
            void* dest_host = emu.memory().get_host_ptr(dest);
            void* src_host = emu.memory().get_host_ptr(src);
            if (dest_host && src_host) {
                memcpy(dest_host, src_host, n);
            } else {
                std::vector<uint8_t> buf(n);
                emu.mem_read(src, buf.data(), n);
                emu.mem_write(dest, buf.data(), n);
            }
        }
        set_reg(emu, UC_ARM64_REG_X0, dest);
    });

    hle.register_function("__memcpy_chk", [](Emulator& emu) {
        uint64_t dest = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t src = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t n = get_reg(emu, UC_ARM64_REG_X2);
        if (n > 0) {
            void* dest_host = emu.memory().get_host_ptr(dest);
            void* src_host = emu.memory().get_host_ptr(src);
            if (dest_host && src_host) {
                memcpy(dest_host, src_host, n);
            } else {
                std::vector<uint8_t> buf(n);
                emu.mem_read(src, buf.data(), n);
                emu.mem_write(dest, buf.data(), n);
            }
        }
        set_reg(emu, UC_ARM64_REG_X0, dest);
    });

    // memmove - uses direct host memory when both src and dest are in host memory
    hle.register_function("memmove", [](Emulator& emu) {
        uint64_t dest = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t src = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t n = get_reg(emu, UC_ARM64_REG_X2);
        constexpr uint64_t MAX_MEMMOVE_SIZE = 256 * 1024 * 1024;
        if (n > 0 && n <= MAX_MEMMOVE_SIZE) {
            void* dest_host = emu.memory().get_host_ptr(dest);
            void* src_host = emu.memory().get_host_ptr(src);
            if (dest_host && src_host) {
                memmove(dest_host, src_host, n);
            } else {
                std::vector<uint8_t> buf(n);
                emu.mem_read(src, buf.data(), n);
                emu.mem_write(dest, buf.data(), n);
            }
        } else if (n > MAX_MEMMOVE_SIZE) {
            EMU_LOG << "[HLE] memmove: size " << n << " exceeds max, ignoring" << std::endl;
        }
        set_reg(emu, UC_ARM64_REG_X0, dest);
    });

    // memset - uses direct host memory when possible
    hle.register_function("memset", [](Emulator& emu) {
        uint64_t s = get_reg(emu, UC_ARM64_REG_X0);
        int c = get_reg(emu, UC_ARM64_REG_X1) & 0xFF;
        uint64_t n = get_reg(emu, UC_ARM64_REG_X2);

        constexpr uint64_t MAX_MEMSET_SIZE = 256 * 1024 * 1024;
        if (n > 0 && n <= MAX_MEMSET_SIZE) {
            void* host_ptr = emu.memory().get_host_ptr(s);
            if (host_ptr) {
                memset(host_ptr, c, n);
            } else {
                std::vector<uint8_t> buf(n, static_cast<uint8_t>(c));
                emu.mem_write(s, buf.data(), n);
            }
        } else if (n > MAX_MEMSET_SIZE) {
            EMU_LOG << "[HLE] memset: size " << n << " exceeds max, ignoring" << std::endl;
        }
        set_reg(emu, UC_ARM64_REG_X0, s);
    });

    // memcmp - uses direct host memory when both operands are in host memory
    hle.register_function("memcmp", [](Emulator& emu) {
        uint64_t s1 = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t s2 = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t n = get_reg(emu, UC_ARM64_REG_X2);
        int result = 0;
        constexpr uint64_t MAX_MEMCMP_SIZE = 256 * 1024 * 1024;
        if (n > 0 && n <= MAX_MEMCMP_SIZE) {
            void* s1_host = emu.memory().get_host_ptr(s1);
            void* s2_host = emu.memory().get_host_ptr(s2);
            if (s1_host && s2_host) {
                result = memcmp(s1_host, s2_host, n);
            } else {
                std::vector<uint8_t> buf1(n), buf2(n);
                emu.mem_read(s1, buf1.data(), n);
                emu.mem_read(s2, buf2.data(), n);
                result = memcmp(buf1.data(), buf2.data(), n);
            }
        } else if (n > MAX_MEMCMP_SIZE) {
            EMU_LOG << "[HLE] memcmp: size " << n << " exceeds max, returning 0" << std::endl;
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // memccpy - copy bytes from src to dst, stopping after the first occurrence of c.
    // Returns a pointer to the byte in dst just past c, or NULL if c not found in n bytes.
    hle.register_function("memccpy", [](Emulator& emu) {
        uint64_t dst = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t src = get_reg(emu, UC_ARM64_REG_X1);
        uint8_t c = static_cast<uint8_t>(get_reg(emu, UC_ARM64_REG_X2) & 0xFF);
        size_t n = get_reg(emu, UC_ARM64_REG_X3);
        std::vector<uint8_t> buf(n);
        if (n) emu.mem_read(src, buf.data(), n);
        uint64_t ret = 0;
        size_t copy_len = n;
        for (size_t i = 0; i < n; i++) {
            if (buf[i] == c) { copy_len = i + 1; ret = dst + copy_len; break; }
        }
        if (copy_len) emu.mem_write(dst, buf.data(), copy_len);
        set_reg(emu, UC_ARM64_REG_X0, ret);
    });

    // memchr - uses direct host memory when possible, falls back to batched reads
    hle.register_function("memchr", [](Emulator& emu) {
        uint64_t s = get_reg(emu, UC_ARM64_REG_X0);
        int c = get_reg(emu, UC_ARM64_REG_X1) & 0xFF;
        uint64_t n = get_reg(emu, UC_ARM64_REG_X2);
        uint64_t result = 0;

        // Try direct host memory access first (fastest path)
        void* host_ptr = emu.memory().get_host_ptr(s);
        if (host_ptr) {
            void* found = memchr(host_ptr, c, n);
            if (found) {
                result = s + (static_cast<uint8_t*>(found) - static_cast<uint8_t*>(host_ptr));
            }
            set_reg(emu, UC_ARM64_REG_X0, result);
            return;
        }

        // Fall back to batched reads
        constexpr uint64_t CHUNK_SIZE = 256;
        uint8_t chunk[CHUNK_SIZE];

        uint64_t offset = 0;
        while (offset < n) {
            uint64_t to_read = std::min(CHUNK_SIZE, n - offset);
            if (!emu.mem_read(s + offset, chunk, to_read)) break;

            void* found = memchr(chunk, c, to_read);
            if (found) {
                result = s + offset + (static_cast<uint8_t*>(found) - chunk);
                break;
            }
            offset += to_read;
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // memrchr - uses direct host memory when possible, falls back to batched reads
    hle.register_function("memrchr", [](Emulator& emu) {
        uint64_t s = get_reg(emu, UC_ARM64_REG_X0);
        int c = get_reg(emu, UC_ARM64_REG_X1) & 0xFF;
        uint64_t n = get_reg(emu, UC_ARM64_REG_X2);
        uint64_t result = 0;

        // Try direct host memory access first (fastest path)
        void* host_ptr = emu.memory().get_host_ptr(s);
        if (host_ptr) {
            // memrchr scans from end
            void* found = memrchr(host_ptr, c, n);
            if (found) {
                result = s + (static_cast<uint8_t*>(found) - static_cast<uint8_t*>(host_ptr));
            }
            set_reg(emu, UC_ARM64_REG_X0, result);
            return;
        }

        // Fall back to batched reads (scan backwards in chunks)
        constexpr uint64_t CHUNK_SIZE = 256;
        uint8_t chunk[CHUNK_SIZE];

        uint64_t remaining = n;
        while (remaining > 0) {
            uint64_t to_read = std::min(CHUNK_SIZE, remaining);
            uint64_t chunk_start = s + remaining - to_read;
            if (!emu.mem_read(chunk_start, chunk, to_read)) break;

            // Scan backwards through the chunk
            for (uint64_t i = to_read; i > 0; i--) {
                if (chunk[i - 1] == c) {
                    result = chunk_start + i - 1;
                    goto done;
                }
            }
            remaining -= to_read;
        }
done:
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("bzero", [](Emulator& emu) {
        uint64_t s = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t n = get_reg(emu, UC_ARM64_REG_X1);
        if (n > 0) {
            emu.memory().zero(s, n);
        }
    });

    hle.register_function("bcopy", [](Emulator& emu) {
        uint64_t src = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t dest = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t n = get_reg(emu, UC_ARM64_REG_X2);
        if (n > 0) {
            std::vector<uint8_t> buf(n);
            emu.mem_read(src, buf.data(), n);
            emu.mem_write(dest, buf.data(), n);
        }
    });
}

} // namespace cross_shim

