/**
 * HLE Directory Operations
 * opendir, readdir, closedir, rewinddir, seekdir, telldir
 * mkdir, rmdir, chdir, getcwd, unlink, chmod, fchmod
 */

#include "hle_manager.h"
#include "cross_shim.h"
#include "memory_manager.h"
#include "bionic_types.h"
#include "emu_compat.h"
#include <cstring>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include <unordered_map>
#include <cerrno>

using namespace cross_shim::bionic;

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

// Directory handle management
static std::unordered_map<uint64_t, DIR*> g_dir_handles;
static uint64_t g_next_dir_handle = 0x2000;

void register_hle_dir(HleManager& hle) {
    // ========================================================================
    // Directory traversal
    // ========================================================================
    
    hle.register_function("opendir", [](Emulator& emu) {
        uint64_t name_addr = get_reg(emu, UC_ARM64_REG_X0);
        std::string name = read_string(emu, name_addr);
        
        DIR* dir = opendir(name.c_str());
        if (dir) {
            uint64_t handle = g_next_dir_handle++;
            g_dir_handles[handle] = dir;
            set_reg(emu, UC_ARM64_REG_X0, handle);
        } else {
            set_reg(emu, UC_ARM64_REG_X0, 0);
        }
    });

    hle.register_function("fdopendir", [](Emulator& emu) {
        int fd = get_reg(emu, UC_ARM64_REG_X0);
        DIR* dir = fdopendir(fd);
        if (dir) {
            uint64_t handle = g_next_dir_handle++;
            g_dir_handles[handle] = dir;
            set_reg(emu, UC_ARM64_REG_X0, handle);
        } else {
            set_reg(emu, UC_ARM64_REG_X0, 0);
        }
    });

    hle.register_function("closedir", [](Emulator& emu) {
        uint64_t handle = get_reg(emu, UC_ARM64_REG_X0);
        auto it = g_dir_handles.find(handle);
        if (it != g_dir_handles.end()) {
            closedir(it->second);
            g_dir_handles.erase(it);
            set_reg(emu, UC_ARM64_REG_X0, 0);
        } else {
            set_reg(emu, UC_ARM64_REG_X0, -1);
        }
    });

    hle.register_function("readdir", [](Emulator& emu) {
        uint64_t handle = get_reg(emu, UC_ARM64_REG_X0);
        auto it = g_dir_handles.find(handle);
        if (it != g_dir_handles.end()) {
            struct dirent* entry = readdir(it->second);
            if (entry) {
                // Convert host dirent to ARM64 bionic format and allocate
                dirent_arm64 entry_arm;
                host_to_arm64_dirent(*entry, entry_arm);
                uint64_t ptr = emu.memory().heap().allocate(sizeof(dirent_arm64), 8);
                emu.mem_write(ptr, &entry_arm, sizeof(entry_arm));
                set_reg(emu, UC_ARM64_REG_X0, ptr);
            } else {
                set_reg(emu, UC_ARM64_REG_X0, 0);
            }
        } else {
            set_reg(emu, UC_ARM64_REG_X0, 0);
        }
    });

    hle.register_function("readdir_r", [](Emulator& emu) {
        uint64_t handle = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t entry_addr = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t result_addr = get_reg(emu, UC_ARM64_REG_X2);

        auto it = g_dir_handles.find(handle);
        if (it != g_dir_handles.end()) {
            struct dirent* entry = readdir(it->second);
            if (entry) {
                // Convert host dirent to ARM64 bionic format
                dirent_arm64 entry_arm;
                host_to_arm64_dirent(*entry, entry_arm);
                emu.mem_write(entry_addr, &entry_arm, sizeof(entry_arm));
                emu.mem_write(result_addr, &entry_addr, sizeof(entry_addr));
                set_reg(emu, UC_ARM64_REG_X0, 0);
            } else {
                uint64_t null_ptr = 0;
                emu.mem_write(result_addr, &null_ptr, sizeof(null_ptr));
                set_reg(emu, UC_ARM64_REG_X0, 0);
            }
        } else {
            set_reg(emu, UC_ARM64_REG_X0, -1);
        }
    });

    hle.register_function("rewinddir", [](Emulator& emu) {
        uint64_t handle = get_reg(emu, UC_ARM64_REG_X0);
        auto it = g_dir_handles.find(handle);
        if (it != g_dir_handles.end()) {
            rewinddir(it->second);
        }
    });

    hle.register_function("seekdir", [](Emulator& emu) {
        uint64_t handle = get_reg(emu, UC_ARM64_REG_X0);
        long loc = get_reg(emu, UC_ARM64_REG_X1);
        auto it = g_dir_handles.find(handle);
        if (it != g_dir_handles.end()) {
            seekdir(it->second, loc);
        }
    });

    hle.register_function("telldir", [](Emulator& emu) {
        uint64_t handle = get_reg(emu, UC_ARM64_REG_X0);
        auto it = g_dir_handles.find(handle);
        if (it != g_dir_handles.end()) {
            set_reg(emu, UC_ARM64_REG_X0, telldir(it->second));
        } else {
            set_reg(emu, UC_ARM64_REG_X0, -1);
        }
    });

    // ========================================================================
    // Directory/file manipulation
    // ========================================================================

    hle.register_function("mkdir", [](Emulator& emu) {
        uint64_t path_addr = get_reg(emu, UC_ARM64_REG_X0);
        mode_t mode = get_reg(emu, UC_ARM64_REG_X1);
        std::string path = read_string(emu, path_addr);
        int result = mkdir(path.c_str(), mode);
        if (result < 0) {
            hle_set_errno(errno);
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("rmdir", [](Emulator& emu) {
        uint64_t path_addr = get_reg(emu, UC_ARM64_REG_X0);
        std::string path = read_string(emu, path_addr);
        int result = rmdir(path.c_str());
        if (result < 0) {
            hle_set_errno(errno);
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("chdir", [](Emulator& emu) {
        uint64_t path_addr = get_reg(emu, UC_ARM64_REG_X0);
        std::string path = read_string(emu, path_addr);
        int result = chdir(path.c_str());
        if (result < 0) {
            hle_set_errno(errno);
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("fchdir", [](Emulator& emu) {
        int fd = get_reg(emu, UC_ARM64_REG_X0);
        int result = fchdir(fd);
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("getcwd", [](Emulator& emu) {
        uint64_t buf_addr = get_reg(emu, UC_ARM64_REG_X0);
        size_t size = get_reg(emu, UC_ARM64_REG_X1);

        if (buf_addr && size > 0) {
            char* cwd = getcwd(nullptr, 0);
            if (cwd) {
                size_t len = strlen(cwd);
                if (len < size) {
                    emu.mem_write(buf_addr, cwd, len + 1);
                    set_reg(emu, UC_ARM64_REG_X0, buf_addr);
                } else {
                    set_reg(emu, UC_ARM64_REG_X0, 0);
                }
                free(cwd);
            } else {
                set_reg(emu, UC_ARM64_REG_X0, 0);
            }
        } else {
            set_reg(emu, UC_ARM64_REG_X0, 0);
        }
    });

    hle.register_function("unlink", [](Emulator& emu) {
        uint64_t path_addr = get_reg(emu, UC_ARM64_REG_X0);
        std::string path = read_string(emu, path_addr);
        int result = unlink(path.c_str());
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("chmod", [](Emulator& emu) {
        uint64_t path_addr = get_reg(emu, UC_ARM64_REG_X0);
        mode_t mode = get_reg(emu, UC_ARM64_REG_X1);
        std::string path = read_string(emu, path_addr);
        int result = chmod(path.c_str(), mode);
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("fchmod", [](Emulator& emu) {
        int fd = get_reg(emu, UC_ARM64_REG_X0);
        mode_t mode = get_reg(emu, UC_ARM64_REG_X1);
        int result = fchmod(fd, mode);
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("chown", [](Emulator& emu) {
        uint64_t path_addr = get_reg(emu, UC_ARM64_REG_X0);
        uid_t owner = get_reg(emu, UC_ARM64_REG_X1);
        gid_t group = get_reg(emu, UC_ARM64_REG_X2);
        std::string path = read_string(emu, path_addr);
        int result = chown(path.c_str(), owner, group);
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("fchown", [](Emulator& emu) {
        int fd = get_reg(emu, UC_ARM64_REG_X0);
        uid_t owner = get_reg(emu, UC_ARM64_REG_X1);
        gid_t group = get_reg(emu, UC_ARM64_REG_X2);
        int result = fchown(fd, owner, group);
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("link", [](Emulator& emu) {
        uint64_t oldpath_addr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t newpath_addr = get_reg(emu, UC_ARM64_REG_X1);
        std::string oldpath = read_string(emu, oldpath_addr);
        std::string newpath = read_string(emu, newpath_addr);
        int result = link(oldpath.c_str(), newpath.c_str());
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("symlink", [](Emulator& emu) {
        uint64_t target_addr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t linkpath_addr = get_reg(emu, UC_ARM64_REG_X1);
        std::string target = read_string(emu, target_addr);
        std::string linkpath = read_string(emu, linkpath_addr);
        int result = symlink(target.c_str(), linkpath.c_str());
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("readlink", [](Emulator& emu) {
        uint64_t path_addr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t buf_addr = get_reg(emu, UC_ARM64_REG_X1);
        size_t bufsiz = get_reg(emu, UC_ARM64_REG_X2);

        std::string path = read_string(emu, path_addr);
        std::vector<char> buf(bufsiz);
        ssize_t result = readlink(path.c_str(), buf.data(), bufsiz);
        if (result > 0) {
            emu.mem_write(buf_addr, buf.data(), result);
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("realpath", [](Emulator& emu) {
        uint64_t path_addr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t resolved_addr = get_reg(emu, UC_ARM64_REG_X1);

        std::string path = read_string(emu, path_addr);
        char* resolved = realpath(path.c_str(), nullptr);

        if (resolved) {
            if (resolved_addr) {
                emu.mem_write(resolved_addr, resolved, strlen(resolved) + 1);
                set_reg(emu, UC_ARM64_REG_X0, resolved_addr);
            } else {
                uint64_t ptr = emu.memory().heap().allocate(strlen(resolved) + 1, 8);
                emu.mem_write(ptr, resolved, strlen(resolved) + 1);
                set_reg(emu, UC_ARM64_REG_X0, ptr);
            }
            free(resolved);
        } else {
            set_reg(emu, UC_ARM64_REG_X0, 0);
        }
    });

    hle.register_function("basename", [](Emulator& emu) {
        uint64_t path_addr = get_reg(emu, UC_ARM64_REG_X0);
        std::string path = read_string(emu, path_addr);

        // Find last /
        size_t pos = path.rfind('/');
        std::string base = (pos == std::string::npos) ? path : path.substr(pos + 1);
        if (base.empty()) base = "/";

        uint64_t ptr = emu.memory().heap().allocate(base.length() + 1, 8);
        emu.mem_write(ptr, base.c_str(), base.length() + 1);
        set_reg(emu, UC_ARM64_REG_X0, ptr);
    });

    hle.register_function("dirname", [](Emulator& emu) {
        uint64_t path_addr = get_reg(emu, UC_ARM64_REG_X0);
        std::string path = read_string(emu, path_addr);

        size_t pos = path.rfind('/');
        std::string dir = (pos == std::string::npos) ? "." : path.substr(0, pos);
        if (dir.empty()) dir = "/";

        uint64_t ptr = emu.memory().heap().allocate(dir.length() + 1, 8);
        emu.mem_write(ptr, dir.c_str(), dir.length() + 1);
        set_reg(emu, UC_ARM64_REG_X0, ptr);
    });
}

} // namespace cross_shim
