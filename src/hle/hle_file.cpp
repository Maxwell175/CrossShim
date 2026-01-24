/**
 * HLE File Functions
 *
 * NOTE: With QEMU MTTCG (real parallel threads), all I/O operations use
 * direct blocking calls. Guest threads run on real host threads, so blocking
 * in the HLE handler blocks only that specific host thread.
 */

#include "debug_log.h"
#include "hle_manager.h"
#include "cross_shim.h"
#include "bionic_types.h"
#include "emu_compat.h"
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <iostream>
#include <vector>
#include <unordered_map>

namespace cross_shim {

using namespace bionic;

// File descriptor mapping for emulated files (shared with hle_io.cpp)
std::unordered_map<int, FILE*> g_file_map;
int g_next_fd = 100;

// get_reg and set_reg are provided by emu_compat.h

static std::string read_string(Emulator& emu, uint64_t addr) {
    std::string result;
    char c;
    while (emu.mem_read(addr++, &c, 1) && c != '\0') {
        result += c;
    }
    return result;
}

void register_hle_file(HleManager& hle) {
    // open
    hle.register_function("open", [](Emulator& emu) {
        uint64_t path_addr = get_reg(emu, UC_ARM64_REG_X0);
        int flags = get_reg(emu, UC_ARM64_REG_X1);
        int mode = get_reg(emu, UC_ARM64_REG_X2);

        std::string path = read_string(emu, path_addr);

        if (emu.is_debug()) {
            EMU_LOG << "[HLE] open(\"" << path << "\", flags=0x" << std::hex << flags << ", mode=0" << std::oct << mode << std::dec << ")" << std::endl;
        }

        // Allow /dev/urandom and /dev/random for cryptographic operations
        if (path == "/dev/urandom" || path == "/dev/random") {
            int fd = ::open(path.c_str(), flags, mode);
            if (emu.is_debug()) {
                EMU_LOG << "[HLE] open: allowing " << path << ", fd=" << fd << std::endl;
            }
            set_reg(emu, UC_ARM64_REG_X0, fd);
            return;
        }

        // Map Android paths to host paths
        if (path.find("/dev/") == 0 || path.find("/proc/") == 0 || path.find("/sys/") == 0) {
            // Return error for other device files
            if (emu.is_debug()) {
                EMU_LOG << "[HLE] open: returning -1 for device/proc/sys path" << std::endl;
            }
            set_reg(emu, UC_ARM64_REG_X0, (uint64_t)-1);
            return;
        }

        int fd = ::open(path.c_str(), flags, mode);
        if (emu.is_debug()) {
            EMU_LOG << "[HLE] open: result fd=" << fd << std::endl;
        }
        set_reg(emu, UC_ARM64_REG_X0, fd);
    });
    
    // close
    hle.register_function("close", [](Emulator& emu) {
        int fd = (int)get_reg(emu, UC_ARM64_REG_X0);
        int result = ::close(fd);
        if (emu.is_debug()) {
            EMU_LOG << "[HLE] close: fd=" << fd << " result=" << result << std::endl;
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });
    
    // read
    hle.register_function("read", [](Emulator& emu) {
        int fd = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t buf_addr = get_reg(emu, UC_ARM64_REG_X1);
        size_t count = get_reg(emu, UC_ARM64_REG_X2);

        if (emu.is_debug()) {
            EMU_LOG << "[HLE] read: fd=" << fd << " count=" << count << std::endl;
        }

        std::vector<char> buf(count);

        // Direct blocking read - with MTTCG, this blocks only this host thread
        ssize_t result = ::read(fd, buf.data(), count);

        if (emu.is_debug()) {
            EMU_LOG << "[HLE] read: result=" << result << std::endl;
        }

        if (result > 0) {
            emu.mem_write(buf_addr, buf.data(), result);
        }

        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // write
    hle.register_function("write", [](Emulator& emu) {
        int fd = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t buf_addr = get_reg(emu, UC_ARM64_REG_X1);
        size_t count = get_reg(emu, UC_ARM64_REG_X2);

        if (emu.is_debug()) {
            EMU_LOG << "[HLE] write: fd=" << fd << " count=" << count << std::endl;
        }

        std::vector<char> buf(count);
        emu.mem_read(buf_addr, buf.data(), count);

        // Direct blocking write - with MTTCG, this blocks only this host thread
        ssize_t result = ::write(fd, buf.data(), count);

        if (emu.is_debug()) {
            EMU_LOG << "[HLE] write: result=" << result << std::endl;
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });
    
    // lseek
    hle.register_function("lseek", [](Emulator& emu) {
        int fd = get_reg(emu, UC_ARM64_REG_X0);
        off_t offset = get_reg(emu, UC_ARM64_REG_X1);
        int whence = get_reg(emu, UC_ARM64_REG_X2);
        
        off_t result = ::lseek(fd, offset, whence);
        set_reg(emu, UC_ARM64_REG_X0, result);
    });
    
    // fopen
    hle.register_function("fopen", [](Emulator& emu) {
        uint64_t path_addr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t mode_addr = get_reg(emu, UC_ARM64_REG_X1);

        std::string path = read_string(emu, path_addr);
        std::string mode = read_string(emu, mode_addr);

        if (emu.is_debug()) {
            EMU_LOG << "[HLE] fopen: path=" << path << " mode=" << mode << std::endl;
        }

        FILE* fp = fopen(path.c_str(), mode.c_str());
        if (fp) {
            int fd = g_next_fd++;
            g_file_map[fd] = fp;
            if (emu.is_debug()) {
                EMU_LOG << "[HLE] fopen: success, fd=" << fd << std::endl;
            }
            set_reg(emu, UC_ARM64_REG_X0, fd);
        } else {
            if (emu.is_debug()) {
                EMU_LOG << "[HLE] fopen: failed, errno=" << errno << std::endl;
            }
            set_reg(emu, UC_ARM64_REG_X0, 0);
        }
    });
    
    // fclose
    hle.register_function("fclose", [](Emulator& emu) {
        int fd = get_reg(emu, UC_ARM64_REG_X0);
        auto it = g_file_map.find(fd);
        if (it != g_file_map.end()) {
            int result = fclose(it->second);
            g_file_map.erase(it);
            set_reg(emu, UC_ARM64_REG_X0, result);
        } else {
            set_reg(emu, UC_ARM64_REG_X0, -1);
        }
    });
    
    // fread
    hle.register_function("fread", [](Emulator& emu) {
        uint64_t buf_addr = get_reg(emu, UC_ARM64_REG_X0);
        size_t size = get_reg(emu, UC_ARM64_REG_X1);
        size_t count = get_reg(emu, UC_ARM64_REG_X2);
        int fd = get_reg(emu, UC_ARM64_REG_X3);
        
        auto it = g_file_map.find(fd);
        if (it != g_file_map.end()) {
            std::vector<char> buf(size * count);
            size_t result = fread(buf.data(), size, count, it->second);
            if (result > 0) {
                emu.mem_write(buf_addr, buf.data(), result * size);
            }
            set_reg(emu, UC_ARM64_REG_X0, result);
        } else {
            set_reg(emu, UC_ARM64_REG_X0, 0);
        }
    });

    // fgets
    hle.register_function("fgets", [](Emulator& emu) {
        uint64_t buf_addr = get_reg(emu, UC_ARM64_REG_X0);
        int size = get_reg(emu, UC_ARM64_REG_X1);
        int fd = get_reg(emu, UC_ARM64_REG_X2);

        auto it = g_file_map.find(fd);
        if (it != g_file_map.end()) {
            std::vector<char> buf(size);
            char* result = fgets(buf.data(), size, it->second);
            if (result) {
                emu.mem_write(buf_addr, buf.data(), strlen(buf.data()) + 1);
                set_reg(emu, UC_ARM64_REG_X0, buf_addr);
            } else {
                set_reg(emu, UC_ARM64_REG_X0, 0);
            }
        } else {
            set_reg(emu, UC_ARM64_REG_X0, 0);
        }
    });

    // setbuf
    hle.register_function("setbuf", [](Emulator& emu) {
        // int fd = get_reg(emu, UC_ARM64_REG_X0);
        // uint64_t buf = get_reg(emu, UC_ARM64_REG_X1);
        // Just ignore - buffering is handled by host
    });

    // setvbuf
    hle.register_function("setvbuf", [](Emulator& emu) {
        // int fd = get_reg(emu, UC_ARM64_REG_X0);
        // uint64_t buf = get_reg(emu, UC_ARM64_REG_X1);
        // int mode = get_reg(emu, UC_ARM64_REG_X2);
        // size_t size = get_reg(emu, UC_ARM64_REG_X3);
        // Just ignore - buffering is handled by host
        set_reg(emu, UC_ARM64_REG_X0, 0);
    });

    // remove
    hle.register_function("remove", [](Emulator& emu) {
        uint64_t path_addr = get_reg(emu, UC_ARM64_REG_X0);
        std::string path = read_string(emu, path_addr);
        int result = ::remove(path.c_str());
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // fwrite
    hle.register_function("fwrite", [](Emulator& emu) {
        uint64_t buf_addr = get_reg(emu, UC_ARM64_REG_X0);
        size_t size = get_reg(emu, UC_ARM64_REG_X1);
        size_t count = get_reg(emu, UC_ARM64_REG_X2);
        int fd = get_reg(emu, UC_ARM64_REG_X3);
        
        auto it = g_file_map.find(fd);
        if (it != g_file_map.end()) {
            std::vector<char> buf(size * count);
            emu.mem_read(buf_addr, buf.data(), size * count);
            size_t result = fwrite(buf.data(), size, count, it->second);
            set_reg(emu, UC_ARM64_REG_X0, result);
        } else {
            set_reg(emu, UC_ARM64_REG_X0, 0);
        }
    });
    
    // fseek
    hle.register_function("fseek", [](Emulator& emu) {
        int fd = get_reg(emu, UC_ARM64_REG_X0);
        long offset = get_reg(emu, UC_ARM64_REG_X1);
        int whence = get_reg(emu, UC_ARM64_REG_X2);
        
        auto it = g_file_map.find(fd);
        if (it != g_file_map.end()) {
            int result = fseek(it->second, offset, whence);
            set_reg(emu, UC_ARM64_REG_X0, result);
        } else {
            set_reg(emu, UC_ARM64_REG_X0, -1);
        }
    });
    
    // ftell
    hle.register_function("ftell", [](Emulator& emu) {
        int fd = get_reg(emu, UC_ARM64_REG_X0);
        
        auto it = g_file_map.find(fd);
        if (it != g_file_map.end()) {
            long result = ftell(it->second);
            set_reg(emu, UC_ARM64_REG_X0, result);
        } else {
            set_reg(emu, UC_ARM64_REG_X0, -1);
        }
    });
    
    // fflush
    hle.register_function("fflush", [](Emulator& emu) {
        int fd = get_reg(emu, UC_ARM64_REG_X0);
        
        if (fd == 0) {
            // NULL - flush all streams
            int result = fflush(nullptr);
            set_reg(emu, UC_ARM64_REG_X0, result);
        } else {
            auto it = g_file_map.find(fd);
            if (it != g_file_map.end()) {
                int result = fflush(it->second);
                set_reg(emu, UC_ARM64_REG_X0, result);
            } else {
                set_reg(emu, UC_ARM64_REG_X0, -1);
            }
        }
    });
    
    // stat - uses ARM64 bionic stat structure (128 bytes)
    hle.register_function("stat", [](Emulator& emu) {
        uint64_t path_addr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t buf_addr = get_reg(emu, UC_ARM64_REG_X1);

        std::string path = read_string(emu, path_addr);
        if (emu.is_debug()) {
            EMU_LOG << "[HLE] stat(\"" << path << "\")" << std::endl;
        }
        struct stat st;
        int result = ::stat(path.c_str(), &st);
        if (emu.is_debug()) {
            EMU_LOG << "[HLE] stat: result=" << result << std::endl;
        }

        if (result == 0 && buf_addr) {
            // Convert host stat to ARM64 bionic format
            stat_arm64 st_arm;
            host_to_arm64_stat(st, st_arm);
            emu.mem_write(buf_addr, &st_arm, sizeof(st_arm));
        }

        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // fstat - get file status from file descriptor
    hle.register_function("fstat", [](Emulator& emu) {
        int fd = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t buf_addr = get_reg(emu, UC_ARM64_REG_X1);

        struct stat st;
        int result = ::fstat(fd, &st);

        if (result == 0 && buf_addr) {
            // Convert host stat to ARM64 bionic format
            stat_arm64 st_arm;
            host_to_arm64_stat(st, st_arm);
            emu.mem_write(buf_addr, &st_arm, sizeof(st_arm));
        }

        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // lstat - get file status (doesn't follow symlinks)
    hle.register_function("lstat", [](Emulator& emu) {
        uint64_t path_addr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t buf_addr = get_reg(emu, UC_ARM64_REG_X1);

        std::string path = read_string(emu, path_addr);
        struct stat st;
        int result = ::lstat(path.c_str(), &st);

        if (result == 0 && buf_addr) {
            // Convert host stat to ARM64 bionic format
            stat_arm64 st_arm;
            host_to_arm64_stat(st, st_arm);
            emu.mem_write(buf_addr, &st_arm, sizeof(st_arm));
        }

        set_reg(emu, UC_ARM64_REG_X0, result);
    });
    
    // fcntl
    hle.register_function("fcntl", [](Emulator& emu) {
        int fd = get_reg(emu, UC_ARM64_REG_X0);
        int cmd = get_reg(emu, UC_ARM64_REG_X1);
        int arg = get_reg(emu, UC_ARM64_REG_X2);
        int result = fcntl(fd, cmd, arg);
        set_reg(emu, UC_ARM64_REG_X0, result);
    });
    
    // ioctl - with proper network interface support
    hle.register_function("ioctl", [](Emulator& emu) {
        int fd = get_reg(emu, UC_ARM64_REG_X0);
        unsigned long request = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t arg_ptr = get_reg(emu, UC_ARM64_REG_X2);

        if (emu.is_debug()) {
            EMU_LOG << "[HLE] ioctl: fd=" << fd << " request=0x" << std::hex << request << std::dec << std::endl;
        }

        // ARM64 ioctl request codes for network interfaces (same as x86_64 on Linux)
        constexpr unsigned long ARM64_SIOCGIFCONF    = 0x8912;
        constexpr unsigned long ARM64_SIOCGIFFLAGS   = 0x8913;
        constexpr unsigned long ARM64_SIOCGIFADDR    = 0x8915;
        constexpr unsigned long ARM64_SIOCGIFNETMASK = 0x891b;
        constexpr unsigned long ARM64_SIOCGIFBRDADDR = 0x8919;
        constexpr unsigned long ARM64_SIOCGIFHWADDR  = 0x8927;
        constexpr unsigned long ARM64_SIOCGIFINDEX   = 0x8933;

        // Handle network interface ioctls by passing through to host
        switch (request) {
            case ARM64_SIOCGIFCONF: {
                // Get interface configuration list
                int32_t ifc_len = 0;
                uint64_t guest_ifc_buf = 0;
                emu.mem_read(arg_ptr, &ifc_len, sizeof(ifc_len));
                emu.mem_read(arg_ptr + 8, &guest_ifc_buf, sizeof(guest_ifc_buf));

                // Allocate host buffer for interface list
                std::vector<char> host_buf(ifc_len);
                struct ifconf ifc;
                ifc.ifc_len = ifc_len;
                ifc.ifc_buf = host_buf.data();

                int result = ::ioctl(fd, SIOCGIFCONF, &ifc);

                if (result == 0) {
                    // Copy results back to emulated memory
                    if (guest_ifc_buf != 0 && ifc.ifc_len > 0) {
                        emu.mem_write(guest_ifc_buf, host_buf.data(), ifc.ifc_len);
                    }
                    // Update ifc_len with actual length
                    emu.mem_write(arg_ptr, &ifc.ifc_len, sizeof(ifc.ifc_len));
                }
                set_reg(emu, UC_ARM64_REG_X0, result);
                return;
            }

            case ARM64_SIOCGIFFLAGS:
            case ARM64_SIOCGIFADDR:
            case ARM64_SIOCGIFNETMASK:
            case ARM64_SIOCGIFBRDADDR:
            case ARM64_SIOCGIFHWADDR:
            case ARM64_SIOCGIFINDEX: {
                // These all use struct ifreq (40 bytes on ARM64)
                char ifreq_buf[40];
                emu.mem_read(arg_ptr, ifreq_buf, sizeof(ifreq_buf));

                // Map ARM64 request to host request
                unsigned long host_request;
                switch (request) {
                    case ARM64_SIOCGIFFLAGS:   host_request = SIOCGIFFLAGS; break;
                    case ARM64_SIOCGIFADDR:    host_request = SIOCGIFADDR; break;
                    case ARM64_SIOCGIFNETMASK: host_request = SIOCGIFNETMASK; break;
                    case ARM64_SIOCGIFBRDADDR: host_request = SIOCGIFBRDADDR; break;
                    case ARM64_SIOCGIFHWADDR:  host_request = SIOCGIFHWADDR; break;
                    case ARM64_SIOCGIFINDEX:   host_request = SIOCGIFINDEX; break;
                    default: host_request = request; break;
                }

                int result = ::ioctl(fd, host_request, ifreq_buf);

                if (emu.is_debug()) {
                    EMU_LOG << "[HLE] ioctl: iface=" << ifreq_buf << " result=" << result << std::endl;
                }

                if (result == 0) {
                    // Copy result back
                    emu.mem_write(arg_ptr, ifreq_buf, sizeof(ifreq_buf));
                }
                set_reg(emu, UC_ARM64_REG_X0, result);
                return;
            }

            default:
                // Unknown ioctl - return error
                set_reg(emu, UC_ARM64_REG_X0, -1);
                return;
        }
    });
    
    // fdopen
    hle.register_function("fdopen", [](Emulator& emu) {
        int fd = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t mode_addr = get_reg(emu, UC_ARM64_REG_X1);
        std::string mode = read_string(emu, mode_addr);
        
        FILE* fp = fdopen(fd, mode.c_str());
        if (fp) {
            int new_fd = g_next_fd++;
            g_file_map[new_fd] = fp;
            set_reg(emu, UC_ARM64_REG_X0, new_fd);
        } else {
            set_reg(emu, UC_ARM64_REG_X0, 0);
        }
    });
    
    // access
    hle.register_function("access", [](Emulator& emu) {
        uint64_t path_addr = get_reg(emu, UC_ARM64_REG_X0);
        int mode = get_reg(emu, UC_ARM64_REG_X1);
        
        std::string path = read_string(emu, path_addr);
        int result = ::access(path.c_str(), mode);
        set_reg(emu, UC_ARM64_REG_X0, result);
    });
    
    // unlink
    hle.register_function("unlink", [](Emulator& emu) {
        uint64_t path_addr = get_reg(emu, UC_ARM64_REG_X0);
        std::string path = read_string(emu, path_addr);
        int result = ::unlink(path.c_str());
        set_reg(emu, UC_ARM64_REG_X0, result);
    });
    
    // rename
    hle.register_function("rename", [](Emulator& emu) {
        uint64_t old_path_addr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t new_path_addr = get_reg(emu, UC_ARM64_REG_X1);
        
        std::string old_path = read_string(emu, old_path_addr);
        std::string new_path = read_string(emu, new_path_addr);
        
        int result = ::rename(old_path.c_str(), new_path.c_str());
        set_reg(emu, UC_ARM64_REG_X0, result);
    });
    
    // mkdir
    hle.register_function("mkdir", [](Emulator& emu) {
        uint64_t path_addr = get_reg(emu, UC_ARM64_REG_X0);
        int mode = get_reg(emu, UC_ARM64_REG_X1);
        
        std::string path = read_string(emu, path_addr);
        int result = ::mkdir(path.c_str(), mode);
        set_reg(emu, UC_ARM64_REG_X0, result);
    });
    
    // rmdir
    hle.register_function("rmdir", [](Emulator& emu) {
        uint64_t path_addr = get_reg(emu, UC_ARM64_REG_X0);
        std::string path = read_string(emu, path_addr);
        int result = ::rmdir(path.c_str());
        set_reg(emu, UC_ARM64_REG_X0, result);
    });
    
    // dup
    hle.register_function("dup", [](Emulator& emu) {
        int fd = get_reg(emu, UC_ARM64_REG_X0);
        int result = ::dup(fd);
        set_reg(emu, UC_ARM64_REG_X0, result);
    });
    
    // dup2
    hle.register_function("dup2", [](Emulator& emu) {
        int oldfd = get_reg(emu, UC_ARM64_REG_X0);
        int newfd = get_reg(emu, UC_ARM64_REG_X1);
        int result = ::dup2(oldfd, newfd);
        set_reg(emu, UC_ARM64_REG_X0, result);
    });
    
    // pipe
    hle.register_function("pipe", [](Emulator& emu) {
        uint64_t pipefd_addr = get_reg(emu, UC_ARM64_REG_X0);
        int pipefd[2];
        int result = ::pipe(pipefd);
        if (result == 0) {
            emu.mem_write(pipefd_addr, pipefd, sizeof(pipefd));
            if (emu.is_debug()) {
                EMU_LOG << "[HLE] pipe: read_fd=" << pipefd[0] << " write_fd=" << pipefd[1] << std::endl;
            }
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });
    
    // fileno - return the fd for a FILE*
    hle.register_function("fileno", [](Emulator& emu) {
        int fd = get_reg(emu, UC_ARM64_REG_X0);
        auto it = g_file_map.find(fd);
        if (it != g_file_map.end()) {
            int result = fileno(it->second);
            set_reg(emu, UC_ARM64_REG_X0, result);
        } else {
            set_reg(emu, UC_ARM64_REG_X0, -1);
        }
    });
    
    // feof
    hle.register_function("feof", [](Emulator& emu) {
        int fd = get_reg(emu, UC_ARM64_REG_X0);
        auto it = g_file_map.find(fd);
        if (it != g_file_map.end()) {
            int result = feof(it->second);
            set_reg(emu, UC_ARM64_REG_X0, result);
        } else {
            set_reg(emu, UC_ARM64_REG_X0, 1);  // Return EOF
        }
    });
    
    // ferror
    hle.register_function("ferror", [](Emulator& emu) {
        int fd = get_reg(emu, UC_ARM64_REG_X0);
        auto it = g_file_map.find(fd);
        if (it != g_file_map.end()) {
            int result = ferror(it->second);
            set_reg(emu, UC_ARM64_REG_X0, result);
        } else {
            set_reg(emu, UC_ARM64_REG_X0, 1);  // Return error
        }
    });
    
    // clearerr
    hle.register_function("clearerr", [](Emulator& emu) {
        int fd = get_reg(emu, UC_ARM64_REG_X0);
        auto it = g_file_map.find(fd);
        if (it != g_file_map.end()) {
            clearerr(it->second);
        }
    });

    // rewind
    hle.register_function("rewind", [](Emulator& emu) {
        int fd = get_reg(emu, UC_ARM64_REG_X0);
        auto it = g_file_map.find(fd);
        if (it != g_file_map.end()) {
            rewind(it->second);
        }
    });

    // fgetc
    hle.register_function("fgetc", [](Emulator& emu) {
        int fd = get_reg(emu, UC_ARM64_REG_X0);
        auto it = g_file_map.find(fd);
        if (it != g_file_map.end()) {
            int c = fgetc(it->second);
            set_reg(emu, UC_ARM64_REG_X0, c);
        } else {
            set_reg(emu, UC_ARM64_REG_X0, (uint64_t)-1);  // EOF
        }
    });

    // getc (same as fgetc)
    hle.register_function("getc", [](Emulator& emu) {
        int fd = get_reg(emu, UC_ARM64_REG_X0);
        auto it = g_file_map.find(fd);
        if (it != g_file_map.end()) {
            int c = fgetc(it->second);
            set_reg(emu, UC_ARM64_REG_X0, c);
        } else {
            set_reg(emu, UC_ARM64_REG_X0, (uint64_t)-1);  // EOF
        }
    });

    // ungetc
    hle.register_function("ungetc", [](Emulator& emu) {
        int c = get_reg(emu, UC_ARM64_REG_X0);
        int fd = get_reg(emu, UC_ARM64_REG_X1);
        auto it = g_file_map.find(fd);
        if (it != g_file_map.end()) {
            int result = ungetc(c, it->second);
            set_reg(emu, UC_ARM64_REG_X0, result);
        } else {
            set_reg(emu, UC_ARM64_REG_X0, (uint64_t)-1);  // EOF
        }
    });

    // fputc
    hle.register_function("fputc", [](Emulator& emu) {
        int c = get_reg(emu, UC_ARM64_REG_X0);
        int fd = get_reg(emu, UC_ARM64_REG_X1);
        auto it = g_file_map.find(fd);
        if (it != g_file_map.end()) {
            int result = fputc(c, it->second);
            set_reg(emu, UC_ARM64_REG_X0, result);
        } else {
            set_reg(emu, UC_ARM64_REG_X0, (uint64_t)-1);  // EOF
        }
    });

    // putc (same as fputc)
    hle.register_function("putc", [](Emulator& emu) {
        int c = get_reg(emu, UC_ARM64_REG_X0);
        int fd = get_reg(emu, UC_ARM64_REG_X1);
        auto it = g_file_map.find(fd);
        if (it != g_file_map.end()) {
            int result = fputc(c, it->second);
            set_reg(emu, UC_ARM64_REG_X0, result);
        } else {
            set_reg(emu, UC_ARM64_REG_X0, (uint64_t)-1);  // EOF
        }
    });

    // fputs (for files, not just stdout)
    hle.register_function("fputs", [](Emulator& emu) {
        uint64_t s_addr = get_reg(emu, UC_ARM64_REG_X0);
        int fd = get_reg(emu, UC_ARM64_REG_X1);
        std::string str = read_string(emu, s_addr);

        auto it = g_file_map.find(fd);
        if (it != g_file_map.end()) {
            int result = fputs(str.c_str(), it->second);
            set_reg(emu, UC_ARM64_REG_X0, result);
        } else {
            // Fallback to stdout
            std::cout << str;
            set_reg(emu, UC_ARM64_REG_X0, 1);
        }
    });
}

} // namespace cross_shim
