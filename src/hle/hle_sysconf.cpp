/**
 * HLE System Configuration and Resource Functions
 * System info: uname, gethostname, sethostname, getdomainname, setdomainname
 * System config: getpagesize, getloadavg, pathconf, fpathconf
 * Resource limits: getrlimit, getrlimit64, setrlimit, setrlimit64, prlimit64
 * Capabilities: capget, capset
 * File system: statfs, statfs64, fstatfs, fstatfs64
 */

#include "debug_log.h"
#include "hle_manager.h"
#include "cross_shim.h"
#include "memory_manager.h"
#include "emu_compat.h"
#include <sys/utsname.h>
#include <sys/resource.h>
#include <sys/sysinfo.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <sys/statfs.h>
#include <unistd.h>
#include <cstring>
#include <algorithm>
#include <cerrno>

namespace cross_shim {

static std::string read_string(Emulator& emu, uint64_t addr, size_t max_len = 4096) {
    std::string result;
    char c;
    for (size_t i = 0; i < max_len; i++) {
        if (!emu.mem_read(addr + i, &c, 1) || c == '\0') break;
        result += c;
    }
    return result;
}

enum class GuestPathconfKind {
    kBlockSize,
    kUnsupported,
    kUnknown,
};

static GuestPathconfKind resolve_guest_pathconf_name(int name) {
    switch (name) {
        case 8:   // _PC_ALLOC_SIZE_MIN
        case 11:  // _PC_REC_MIN_XFER_SIZE
        case 12:  // _PC_REC_XFER_ALIGN
            return GuestPathconfKind::kBlockSize;

        case 9:   // _PC_REC_INCR_XFER_SIZE
        case 10:  // _PC_REC_MAX_XFER_SIZE
        case 13:  // _PC_SYMLINK_MAX
        case 17:  // _PC_ASYNC_IO
        case 18:  // _PC_PRIO_IO
        case 19:  // _PC_SYNC_IO
            return GuestPathconfKind::kUnsupported;

        default:
            return GuestPathconfKind::kUnknown;
    }
}

static long normalize_guest_block_size(long block_size) {
    long value = block_size > 0 ? block_size : 4096;
    long power_of_two = 1;
    while (power_of_two < value && power_of_two < (1L << 30)) {
        power_of_two <<= 1;
    }
    return power_of_two;
}

static long guest_pathconf_from_path(const std::string& path, int& guest_errno) {
    struct stat st {};
    errno = 0;
    if (::stat(path.c_str(), &st) != 0) {
        guest_errno = errno;
        return -1;
    }

    guest_errno = 0;
    return normalize_guest_block_size(st.st_blksize);
}

static long guest_pathconf_from_fd(int fd, int& guest_errno) {
    struct stat st {};
    errno = 0;
    if (::fstat(fd, &st) != 0) {
        guest_errno = errno;
        return -1;
    }

    guest_errno = 0;
    return normalize_guest_block_size(st.st_blksize);
}

// ARM64 Android utsname structure (65 bytes per field, 6 fields)
struct utsname_arm64 {
    char sysname[65];
    char nodename[65];
    char release[65];
    char version[65];
    char machine[65];
    char domainname[65];
};

// ARM64 rlimit structure
struct rlimit_arm64 {
    uint64_t rlim_cur;
    uint64_t rlim_max;
};

// Linux capability structures
struct cap_user_header_arm64 {
    uint32_t version;
    int32_t pid;
};

struct cap_user_data_arm64 {
    uint32_t effective;
    uint32_t permitted;
    uint32_t inheritable;
};

struct sysinfo_arm64 {
    int64_t uptime;
    uint64_t loads[3];
    uint64_t totalram;
    uint64_t freeram;
    uint64_t sharedram;
    uint64_t bufferram;
    uint64_t totalswap;
    uint64_t freeswap;
    uint16_t procs;
    uint16_t pad;
    uint64_t totalhigh;
    uint64_t freehigh;
    uint32_t mem_unit;
    char _f[20 - 2 * sizeof(uint64_t) - sizeof(uint32_t)];
};

void register_hle_sysconf(HleManager& hle) {
    // ========================================================================
    // System information
    // ========================================================================

    hle.register_function("uname", [](Emulator& emu) {
        uint64_t buf_ptr = get_reg(emu, UC_ARM64_REG_X0);
        if (!buf_ptr) {
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        struct utsname host_uname;
        int result = ::uname(&host_uname);

        if (result == 0) {
            utsname_arm64 arm_uname = {};
            strncpy(arm_uname.sysname, "Linux", 64);
            strncpy(arm_uname.nodename, host_uname.nodename, 64);
            strncpy(arm_uname.release, "4.19.0", 64);  // Android kernel version
            strncpy(arm_uname.version, "#1 SMP", 64);
            strncpy(arm_uname.machine, "aarch64", 64);
            strncpy(arm_uname.domainname, "(none)", 64);
            emu.mem_write(buf_ptr, &arm_uname, sizeof(arm_uname));
        }

        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("gethostname", [](Emulator& emu) {
        uint64_t name_ptr = get_reg(emu, UC_ARM64_REG_X0);
        size_t len = get_reg(emu, UC_ARM64_REG_X1);

        if (!name_ptr || len == 0) {
            hle_set_errno(emu, EINVAL);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        char hostname[256];
        errno = 0;
        int result = ::gethostname(hostname, sizeof(hostname));
        if (result != 0) {
            hle_set_errno(emu, errno);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        size_t host_len = std::strlen(hostname);
        if (len <= host_len) {
            hle_set_errno(emu, ENAMETOOLONG);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        emu.mem_write(name_ptr, hostname, host_len + 1);
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("sethostname", [](Emulator& emu) {
        hle_set_errno(emu, EPERM);
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
    });

    hle.register_function("getdomainname", [](Emulator& emu) {
        uint64_t name_ptr = get_reg(emu, UC_ARM64_REG_X0);
        size_t len = get_reg(emu, UC_ARM64_REG_X1);

        if (!name_ptr || len == 0) {
            hle_set_errno(emu, EINVAL);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        const char* domain = "(none)";
        size_t domain_len = strlen(domain);

        if (len <= domain_len) {
            hle_set_errno(emu, EINVAL);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        emu.mem_write(name_ptr, domain, domain_len + 1);
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("setdomainname", [](Emulator& emu) {
        hle_set_errno(emu, EPERM);
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
    });

    // ========================================================================
    // System configuration
    // ========================================================================

    hle.register_function("getpagesize", [](Emulator& emu) {
        set_reg(emu, UC_ARM64_REG_X0, 4096);
    });

    hle.register_function("getloadavg", [](Emulator& emu) {
        uint64_t loadavg_ptr = get_reg(emu, UC_ARM64_REG_X0);
        int nelem = get_reg(emu, UC_ARM64_REG_X1);

        if (nelem == 0) {
            set_reg(emu, UC_ARM64_REG_X0, 0);
            return;
        }
        if (!loadavg_ptr || nelem < 0) {
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        double loadavg[3];
        int result = ::getloadavg(loadavg, std::min(nelem, 3));
        if (result > 0) {
            for (int i = 0; i < result; i++) {
                emu.mem_write(loadavg_ptr + i * 8, &loadavg[i], 8);
            }
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("sysinfo", [](Emulator& emu) {
        uint64_t info_ptr = get_reg(emu, UC_ARM64_REG_X0);
        if (!info_ptr) {
            hle_set_errno(emu, EFAULT);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        struct sysinfo host_info {};
        errno = 0;
        int result = ::sysinfo(&host_info);
        if (result == 0) {
            sysinfo_arm64 guest_info {};
            guest_info.uptime = host_info.uptime;
            std::copy(std::begin(host_info.loads), std::end(host_info.loads), guest_info.loads);
            guest_info.totalram = host_info.totalram;
            guest_info.freeram = host_info.freeram;
            guest_info.sharedram = host_info.sharedram;
            guest_info.bufferram = host_info.bufferram;
            guest_info.totalswap = host_info.totalswap;
            guest_info.freeswap = host_info.freeswap;
            guest_info.procs = host_info.procs;
            guest_info.pad = 0;
            guest_info.totalhigh = host_info.totalhigh;
            guest_info.freehigh = host_info.freehigh;
            guest_info.mem_unit = host_info.mem_unit;
            emu.mem_write(info_ptr, &guest_info, sizeof(guest_info));
        } else {
            hle_set_errno(emu, errno);
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("get_nprocs", [](Emulator& emu) {
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(::get_nprocs()));
    });

    hle.register_function("get_nprocs_conf", [](Emulator& emu) {
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(::get_nprocs_conf()));
    });

    hle.register_function("get_phys_pages", [](Emulator& emu) {
        long pages = ::sysconf(_SC_PHYS_PAGES);
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(pages));
    });

    hle.register_function("get_avphys_pages", [](Emulator& emu) {
        long pages = ::sysconf(_SC_AVPHYS_PAGES);
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(pages));
    });

    hle.register_function("pathconf", [](Emulator& emu) {
        uint64_t path_ptr = get_reg(emu, UC_ARM64_REG_X0);
        int name = get_reg(emu, UC_ARM64_REG_X1);

        if (!path_ptr) {
            hle_set_errno(emu, EFAULT);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        std::string path = read_string(emu, path_ptr);
        int guest_errno = 0;
        long result = -1;
        switch (resolve_guest_pathconf_name(name)) {
            case GuestPathconfKind::kBlockSize:
                result = guest_pathconf_from_path(path, guest_errno);
                break;
            case GuestPathconfKind::kUnsupported:
                result = -1;
                guest_errno = 0;
                break;
            case GuestPathconfKind::kUnknown:
                result = -1;
                guest_errno = EINVAL;
                break;
        }

        if (result == -1 && guest_errno != 0) {
            hle_set_errno(emu, guest_errno);
        }
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(result));
    });

    hle.register_function("fpathconf", [](Emulator& emu) {
        int fd = get_reg(emu, UC_ARM64_REG_X0);
        int name = get_reg(emu, UC_ARM64_REG_X1);

        int guest_errno = 0;
        long result = -1;
        switch (resolve_guest_pathconf_name(name)) {
            case GuestPathconfKind::kBlockSize:
                result = guest_pathconf_from_fd(fd, guest_errno);
                break;
            case GuestPathconfKind::kUnsupported:
                result = -1;
                guest_errno = 0;
                break;
            case GuestPathconfKind::kUnknown:
                result = -1;
                guest_errno = EINVAL;
                break;
        }

        if (result == -1 && guest_errno != 0) {
            hle_set_errno(emu, guest_errno);
        }
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(result));
    });

    // ========================================================================
    // Resource limits
    // ========================================================================

    hle.register_function("getrlimit", [](Emulator& emu) {
        int resource = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t rlim_ptr = get_reg(emu, UC_ARM64_REG_X1);

        if (!rlim_ptr) {
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        struct rlimit rl;
        int result = ::getrlimit(resource, &rl);
        if (result == 0) {
            rlimit_arm64 rl_arm;
            rl_arm.rlim_cur = rl.rlim_cur;
            rl_arm.rlim_max = rl.rlim_max;
            emu.mem_write(rlim_ptr, &rl_arm, sizeof(rl_arm));
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("getrlimit64", [](Emulator& emu) {
        int resource = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t rlim_ptr = get_reg(emu, UC_ARM64_REG_X1);

        if (!rlim_ptr) {
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        struct rlimit rl;
        int result = ::getrlimit(resource, &rl);
        if (result == 0) {
            rlimit_arm64 rl_arm;
            rl_arm.rlim_cur = rl.rlim_cur;
            rl_arm.rlim_max = rl.rlim_max;
            emu.mem_write(rlim_ptr, &rl_arm, sizeof(rl_arm));
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("setrlimit", [](Emulator& emu) {
        int resource = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t rlim_ptr = get_reg(emu, UC_ARM64_REG_X1);

        if (!rlim_ptr) {
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        rlimit_arm64 rl_arm;
        emu.mem_read(rlim_ptr, &rl_arm, sizeof(rl_arm));

        struct rlimit rl;
        rl.rlim_cur = rl_arm.rlim_cur;
        rl.rlim_max = rl_arm.rlim_max;

        int result = ::setrlimit(resource, &rl);
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("setrlimit64", [](Emulator& emu) {
        int resource = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t rlim_ptr = get_reg(emu, UC_ARM64_REG_X1);

        if (!rlim_ptr) {
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        rlimit_arm64 rl_arm;
        emu.mem_read(rlim_ptr, &rl_arm, sizeof(rl_arm));

        struct rlimit rl;
        rl.rlim_cur = rl_arm.rlim_cur;
        rl.rlim_max = rl_arm.rlim_max;

        int result = ::setrlimit(resource, &rl);
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("prlimit64", [](Emulator& emu) {
        pid_t pid = get_reg(emu, UC_ARM64_REG_X0);
        int resource = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t new_limit_ptr = get_reg(emu, UC_ARM64_REG_X2);
        uint64_t old_limit_ptr = get_reg(emu, UC_ARM64_REG_X3);

        struct rlimit new_limit, old_limit;
        struct rlimit* new_ptr = nullptr;
        struct rlimit* old_ptr = nullptr;

        if (new_limit_ptr) {
            rlimit_arm64 rl_arm;
            emu.mem_read(new_limit_ptr, &rl_arm, sizeof(rl_arm));
            new_limit.rlim_cur = rl_arm.rlim_cur;
            new_limit.rlim_max = rl_arm.rlim_max;
            new_ptr = &new_limit;
        }
        if (old_limit_ptr) {
            old_ptr = &old_limit;
        }

        int result = ::prlimit(pid, static_cast<__rlimit_resource>(resource), new_ptr, old_ptr);

        if (result == 0 && old_limit_ptr) {
            rlimit_arm64 rl_arm;
            rl_arm.rlim_cur = old_limit.rlim_cur;
            rl_arm.rlim_max = old_limit.rlim_max;
            emu.mem_write(old_limit_ptr, &rl_arm, sizeof(rl_arm));
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // ========================================================================
    // Linux capabilities
    // ========================================================================

    hle.register_function("capget", [](Emulator& emu) {
        uint64_t header_ptr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t data_ptr = get_reg(emu, UC_ARM64_REG_X1);

        if (!header_ptr) {
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        cap_user_header_arm64 header;
        emu.mem_read(header_ptr, &header, sizeof(header));

        if (!data_ptr) {
            // Set version to latest
            header.version = 0x20080522;  // _LINUX_CAPABILITY_VERSION_3
            emu.mem_write(header_ptr, &header, sizeof(header));
            set_reg(emu, UC_ARM64_REG_X0, 0);
            return;
        }

        // Return empty capabilities
        cap_user_data_arm64 data[2] = {{0, 0, 0}, {0, 0, 0}};
        emu.mem_write(data_ptr, data, sizeof(data));
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    hle.register_function("capset", [](Emulator& emu) {
        // Normally requires CAP_SETPCAP, just pretend success
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    // ========================================================================
    // File system statistics
    // ========================================================================

    hle.register_function("statfs", [](Emulator& emu) {
        uint64_t path_ptr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t buf_ptr = get_reg(emu, UC_ARM64_REG_X1);

        if (!path_ptr || !buf_ptr) {
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        std::string path = read_string(emu, path_ptr);
        struct statfs buf;
        int result = ::statfs(path.c_str(), &buf);
        if (result == 0) {
            emu.mem_write(buf_ptr, &buf, sizeof(buf));
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("statfs64", [](Emulator& emu) {
        uint64_t path_ptr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t buf_ptr = get_reg(emu, UC_ARM64_REG_X1);

        if (!path_ptr || !buf_ptr) {
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        std::string path = read_string(emu, path_ptr);
        struct statfs64 buf;
        int result = ::statfs64(path.c_str(), &buf);
        if (result == 0) {
            emu.mem_write(buf_ptr, &buf, sizeof(buf));
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("fstatfs", [](Emulator& emu) {
        int fd = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t buf_ptr = get_reg(emu, UC_ARM64_REG_X1);

        if (!buf_ptr) {
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        struct statfs buf;
        int result = ::fstatfs(fd, &buf);
        if (result == 0) {
            emu.mem_write(buf_ptr, &buf, sizeof(buf));
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("fstatfs64", [](Emulator& emu) {
        int fd = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t buf_ptr = get_reg(emu, UC_ARM64_REG_X1);

        if (!buf_ptr) {
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        struct statfs64 buf;
        int result = ::fstatfs64(fd, &buf);
        if (result == 0) {
            emu.mem_write(buf_ptr, &buf, sizeof(buf));
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });
}

} // namespace cross_shim
