/**
 * HLE Process Control Functions
 * fork, exec, waitpid, kill, pipe, dup2, signal, sigaction
 * socketpair, syscall
 */

#include "debug_log.h"
#include "hle_manager.h"
#include "cross_shim.h"
#include "memory_manager.h"
#include "emu_compat.h"
#include <cstring>
#include <iostream>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <fcntl.h>

namespace cross_shim {

// get_reg and set_reg are provided by emu_compat.h

static std::string read_string(Emulator& emu, uint64_t addr, size_t max_len = 4096) {
    std::string result;
    char c;
    for (size_t i = 0; i < max_len; i++) {
        if (!emu.mem_read(addr + i, &c, 1) || c == '\0') break;
        result += c;
    }
    return result;
}

void register_hle_process(HleManager& hle) {
    // ========================================================================
    // Process creation (not supported in emulation)
    // ========================================================================
    
    hle.register_function("fork", [](Emulator& emu) {
        // Return -1 (error) - we don't support forking
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
    });

    hle.register_function("vfork", [](Emulator& emu) {
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
    });

    hle.register_function("execl", [](Emulator& emu) {
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
    });

    hle.register_function("execle", [](Emulator& emu) {
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
    });

    hle.register_function("execlp", [](Emulator& emu) {
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
    });

    hle.register_function("execv", [](Emulator& emu) {
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
    });

    hle.register_function("execve", [](Emulator& emu) {
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
    });

    hle.register_function("execvp", [](Emulator& emu) {
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
    });

    // ========================================================================
    // Process waiting
    // ========================================================================

    hle.register_function("waitpid", [](Emulator& emu) {
        // Return -1 (no child processes)
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
    });

    hle.register_function("wait", [](Emulator& emu) {
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
    });

    hle.register_function("wait3", [](Emulator& emu) {
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
    });

    hle.register_function("wait4", [](Emulator& emu) {
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
    });

    // ========================================================================
    // Signals
    // ========================================================================

    hle.register_function("kill", [](Emulator& emu) {
        // Pretend success
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("raise", [](Emulator& emu) {
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("signal", [](Emulator& emu) {
        // Return SIG_DFL (0)
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("sigaction", [](Emulator& emu) {
        // Pretend success
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("sigprocmask", [](Emulator& emu) {
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    // sigset_t on ARM64 Android is 8 bytes (64 bits for 64 signals)
    // It's defined as: typedef struct { unsigned long sig[1]; } sigset_t;
    // Each signal is represented by a bit: bit (signum-1)
    constexpr size_t SIGSET_SIZE = 8;  // sizeof(unsigned long) on ARM64
    constexpr int MAX_SIGNAL = 64;     // _KERNEL__NSIG

    hle.register_function("sigemptyset", [](Emulator& emu) {
        uint64_t set_addr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t zeros = 0;
        emu.mem_write(set_addr, &zeros, sizeof(zeros));
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("sigfillset", [](Emulator& emu) {
        uint64_t set_addr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t ones = ~0ULL;
        emu.mem_write(set_addr, &ones, sizeof(ones));
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("sigaddset", [](Emulator& emu) {
        uint64_t set_addr = get_reg(emu, UC_ARM64_REG_X0);
        int signum = get_reg(emu, UC_ARM64_REG_X1);
        if (signum < 1 || signum > MAX_SIGNAL) {
            set_reg(emu, UC_ARM64_REG_X0, -1);
            return;
        }
        uint64_t set_val;
        emu.mem_read(set_addr, &set_val, sizeof(set_val));
        set_val |= (1ULL << (signum - 1));
        emu.mem_write(set_addr, &set_val, sizeof(set_val));
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("sigdelset", [](Emulator& emu) {
        uint64_t set_addr = get_reg(emu, UC_ARM64_REG_X0);
        int signum = get_reg(emu, UC_ARM64_REG_X1);
        if (signum < 1 || signum > MAX_SIGNAL) {
            set_reg(emu, UC_ARM64_REG_X0, -1);
            return;
        }
        uint64_t set_val;
        emu.mem_read(set_addr, &set_val, sizeof(set_val));
        set_val &= ~(1ULL << (signum - 1));
        emu.mem_write(set_addr, &set_val, sizeof(set_val));
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("sigismember", [](Emulator& emu) {
        uint64_t set_addr = get_reg(emu, UC_ARM64_REG_X0);
        int signum = get_reg(emu, UC_ARM64_REG_X1);
        if (signum < 1 || signum > MAX_SIGNAL) {
            set_reg(emu, UC_ARM64_REG_X0, -1);
            return;
        }
        uint64_t set_val;
        emu.mem_read(set_addr, &set_val, sizeof(set_val));
        int result = (set_val >> (signum - 1)) & 1;
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // ========================================================================
    // Pipes and file descriptor operations
    // ========================================================================

    hle.register_function("pipe", [](Emulator& emu) {
        uint64_t pipefd_addr = get_reg(emu, UC_ARM64_REG_X0);
        int pipefd[2];
        int result = pipe(pipefd);
        if (result == 0 && pipefd_addr) {
            emu.mem_write(pipefd_addr, pipefd, sizeof(pipefd));
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("pipe2", [](Emulator& emu) {
        uint64_t pipefd_addr = get_reg(emu, UC_ARM64_REG_X0);
        int flags = get_reg(emu, UC_ARM64_REG_X1);
        int pipefd[2];
        int result = pipe2(pipefd, flags);
        if (result == 0 && pipefd_addr) {
            emu.mem_write(pipefd_addr, pipefd, sizeof(pipefd));
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("dup", [](Emulator& emu) {
        int oldfd = get_reg(emu, UC_ARM64_REG_X0);
        int result = dup(oldfd);
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("dup2", [](Emulator& emu) {
        int oldfd = get_reg(emu, UC_ARM64_REG_X0);
        int newfd = get_reg(emu, UC_ARM64_REG_X1);
        int result = dup2(oldfd, newfd);
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("dup3", [](Emulator& emu) {
        int oldfd = get_reg(emu, UC_ARM64_REG_X0);
        int newfd = get_reg(emu, UC_ARM64_REG_X1);
        int flags = get_reg(emu, UC_ARM64_REG_X2);
        int result = dup3(oldfd, newfd, flags);
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // ========================================================================
    // Socket pairs
    // ========================================================================

    hle.register_function("socketpair", [](Emulator& emu) {
        int domain = get_reg(emu, UC_ARM64_REG_X0);
        int type = get_reg(emu, UC_ARM64_REG_X1);
        int protocol = get_reg(emu, UC_ARM64_REG_X2);
        uint64_t sv_addr = get_reg(emu, UC_ARM64_REG_X3);

        int sv[2];
        int result = socketpair(domain, type, protocol, sv);
        if (result == 0 && sv_addr) {
            emu.mem_write(sv_addr, sv, sizeof(sv));
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // ========================================================================
    // System call interface
    // ========================================================================

    hle.register_function("syscall", [](Emulator& emu) {
        // Return -1 (not supported)
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
    });

    hle.register_function("__system_property_get", [](Emulator& emu) {
        uint64_t name_addr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t value_addr = get_reg(emu, UC_ARM64_REG_X1);
        std::string name = read_string(emu, name_addr);

        if (emu.is_debug()) {
            EMU_LOG << "[HLE] __system_property_get: name=" << name << std::endl;
        }

        // Provide values for common Android properties
        std::string value;
        if (name == "ro.arch") {
            value = "aarch64";
        } else if (name == "ro.product.cpu.abi") {
            value = "arm64-v8a";
        } else if (name == "ro.build.version.sdk") {
            value = "30";
        } else if (name == "net.dns1") {
            value = "8.8.8.8";
        } else if (name == "net.dns2") {
            value = "8.8.4.4";
        }

        if (!value.empty() && value_addr != 0) {
            emu.mem_write(value_addr, value.c_str(), value.length() + 1);
            set_reg(emu, UC_ARM64_REG_X0, value.length());
        } else {
            // Return 0 (property not found)
            set_reg(emu, UC_ARM64_REG_X0, 0);
        }
    });

    hle.register_function("__system_property_find", [](Emulator& emu) {
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("__system_property_read", [](Emulator& emu) {
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });
}

} // namespace cross_shim

