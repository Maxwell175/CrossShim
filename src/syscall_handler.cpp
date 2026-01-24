#include "debug_log.h"
#include "syscall_handler.h"
#include "cross_shim.h"
#include "memory_manager.h"
#include "thread_manager.h"
#include "emu_compat.h"
#include <cstring>
#include <ctime>
#include <random>
#include <iostream>
#include <unistd.h>
#include <sys/socket.h>
#include <cerrno>

namespace cross_shim {

SyscallHandler::SyscallHandler(Emulator& emu, MemoryManager& memory)
    : emu_(emu), memory_(memory), next_fd_(3), current_brk_(HEAP_BASE), logging_enabled_(false) {
    // Pre-open stdin, stdout, stderr
    open_fds_[0] = {0, "/dev/stdin", {}, 0, true};
    open_fds_[1] = {1, "/dev/stdout", {}, 0, true};
    open_fds_[2] = {2, "/dev/stderr", {}, 0, true};
}

void SyscallHandler::add_virtual_file(const std::string& path, const std::vector<uint8_t>& data) {
    virtual_files_[path] = data;
}

void SyscallHandler::add_virtual_file(const std::string& path, const std::string& content) {
    virtual_files_[path] = std::vector<uint8_t>(content.begin(), content.end());
}

std::string SyscallHandler::read_string(uint64_t address, size_t max_len) {
    std::string result;
    char c;
    for (size_t i = 0; i < max_len; i++) {
        if (!memory_.read(address + i, &c, 1) || c == '\0') break;
        result += c;
    }
    return result;
}

int SyscallHandler::allocate_fd() {
    return next_fd_++;
}

void SyscallHandler::handle(uint64_t syscall_num) {
    // Get syscall arguments from registers X0-X5
    uint64_t args[6];
    args[0] = get_reg(emu_, UC_ARM64_REG_X0);
    args[1] = get_reg(emu_, UC_ARM64_REG_X1);
    args[2] = get_reg(emu_, UC_ARM64_REG_X2);
    args[3] = get_reg(emu_, UC_ARM64_REG_X3);
    args[4] = get_reg(emu_, UC_ARM64_REG_X4);
    args[5] = get_reg(emu_, UC_ARM64_REG_X5);

    // Always log syscalls for debugging
    EMU_LOG << "[SYSCALL] handle(" << syscall_num << ") args: "
              << std::hex << args[0] << ", " << args[1] << ", " << args[2]
              << std::dec << std::endl;

    int64_t result = -1;  // Default: error

    switch (syscall_num) {
        case SYS_READ:
            result = sys_read(args[0], args[1], args[2]);
            break;
        case SYS_WRITE:
            result = sys_write(args[0], args[1], args[2]);
            break;
        case SYS_OPENAT:
            result = sys_openat(args[0], args[1], args[2], args[3]);
            break;
        case SYS_CLOSE:
            result = sys_close(args[0]);
            break;
        case SYS_LSEEK:
            result = sys_lseek(args[0], args[1], args[2]);
            break;
        case SYS_MMAP:
            result = sys_mmap(args[0], args[1], args[2], args[3], args[4], args[5]);
            break;
        case SYS_MPROTECT:
            result = sys_mprotect(args[0], args[1], args[2]);
            break;
        case SYS_MUNMAP:
            result = sys_munmap(args[0], args[1]);
            break;
        case SYS_BRK:
            result = sys_brk(args[0]);
            break;
        case SYS_FSTAT:
            result = sys_fstat(args[0], args[1]);
            break;
        case SYS_IOCTL:
            result = sys_ioctl(args[0], args[1], args[2]);
            break;
        case SYS_WRITEV:
            result = sys_writev(args[0], args[1], args[2]);
            break;
        case SYS_EXIT:
        case SYS_EXIT_GROUP:
            result = sys_exit(args[0]);
            break;
        case SYS_FUTEX:
            result = sys_futex(args[0], args[1], args[2], args[3], args[4], args[5]);
            break;
        case SYS_CLOCK_GETTIME:
            result = sys_clock_gettime(args[0], args[1]);
            break;
        case SYS_GETTIMEOFDAY:
            result = sys_gettimeofday(args[0], args[1]);
            break;
        case SYS_GETPID:
        case SYS_GETTID:
            result = 1000;  // Fake PID/TID
            break;
        case SYS_GETUID:
        case SYS_GETEUID:
            result = 1000;  // Fake UID
            break;
        case SYS_GETGID:
        case SYS_GETEGID:
            result = 1000;  // Fake GID
            break;
        case SYS_GETRANDOM:
            result = sys_getrandom(args[0], args[1], args[2]);
            break;
        case SYS_PRCTL:
            result = sys_prctl(args[0], args[1], args[2], args[3], args[4]);
            break;
        case SYS_MADVISE:
            result = sys_madvise(args[0], args[1], args[2]);
            break;
        case SYS_RT_SIGACTION:
            result = sys_rt_sigaction(args[0], args[1], args[2], args[3]);
            break;
        case SYS_RT_SIGPROCMASK:
            result = sys_rt_sigprocmask(args[0], args[1], args[2], args[3]);
            break;
        case SYS_SCHED_YIELD:
            result = 0;  // Just return success
            break;
        case SYS_PIPE2:
            result = sys_pipe2(args[0], args[1]);
            break;
        case SYS_SOCKET:
            result = sys_socket(args[0], args[1], args[2]);
            break;
        case SYS_CONNECT:
            result = sys_connect(args[0], args[1], args[2]);
            break;
        case SYS_BIND:
            result = sys_bind(args[0], args[1], args[2]);
            break;
        case SYS_LISTEN:
            result = sys_listen(args[0], args[1]);
            break;
        case SYS_ACCEPT:
            result = sys_accept(args[0], args[1], args[2]);
            break;
        case SYS_GETSOCKNAME:
            result = sys_getsockname(args[0], args[1], args[2]);
            break;
        case SYS_GETPEERNAME:
            result = sys_getpeername(args[0], args[1], args[2]);
            break;
        case SYS_SENDTO:
            result = sys_sendto(args[0], args[1], args[2], args[3], args[4], args[5]);
            break;
        case SYS_RECVFROM:
            result = sys_recvfrom(args[0], args[1], args[2], args[3], args[4], args[5]);
            break;
        case SYS_SETSOCKOPT:
            result = sys_setsockopt(args[0], args[1], args[2], args[3], args[4]);
            break;
        case SYS_GETSOCKOPT:
            result = sys_getsockopt(args[0], args[1], args[2], args[3], args[4]);
            break;
        default:
            EMU_LOG << "[SYSCALL] Unhandled syscall: " << syscall_num << std::endl;
            result = -38;  // ENOSYS
            break;
    }

    // Set return value in X0
    set_reg(emu_, UC_ARM64_REG_X0, static_cast<uint64_t>(result));
}

int64_t SyscallHandler::sys_read(int fd, uint64_t buf, size_t count) {
    auto it = open_fds_.find(fd);
    if (it == open_fds_.end()) return -9;  // EBADF

    VirtualFd& vfd = it->second;
    if (vfd.data.empty()) return 0;

    size_t available = vfd.data.size() - vfd.position;
    size_t to_read = std::min(count, available);

    if (to_read > 0) {
        memory_.write(buf, vfd.data.data() + vfd.position, to_read);
        vfd.position += to_read;
    }

    return to_read;
}

int64_t SyscallHandler::sys_write(int fd, uint64_t buf, size_t count) {
    if (logging_enabled_) {
        EMU_LOG << "[SYSCALL] write(fd=" << fd << ", buf=0x" << std::hex << buf
                  << ", count=" << std::dec << count << ")" << std::endl;
    }
    if (fd == 1 || fd == 2) {
        std::vector<uint8_t> data(count);
        memory_.read(buf, data.data(), count);
        if (fd == 1) {
            std::cout.write(reinterpret_cast<char*>(data.data()), count);
            std::cout.flush();
        } else {
            std::cerr.write(reinterpret_cast<char*>(data.data()), count);
            std::cerr.flush();
        }
        return count;
    }
    return -9;  // EBADF
}

int64_t SyscallHandler::sys_openat(int dirfd, uint64_t pathname, int flags, int mode) {
    std::string path = read_string(pathname);
    auto it = virtual_files_.find(path);
    if (it != virtual_files_.end()) {
        int fd = allocate_fd();
        open_fds_[fd] = {fd, path, it->second, 0, true};
        return fd;
    }
    return -2;  // ENOENT
}

int64_t SyscallHandler::sys_close(int fd) {
    auto it = open_fds_.find(fd);
    if (it == open_fds_.end()) return -9;
    open_fds_.erase(it);
    return 0;
}

int64_t SyscallHandler::sys_lseek(int fd, int64_t offset, int whence) {
    auto it = open_fds_.find(fd);
    if (it == open_fds_.end()) return -9;
    VirtualFd& vfd = it->second;
    size_t new_pos;
    switch (whence) {
        case 0: new_pos = offset; break;
        case 1: new_pos = vfd.position + offset; break;
        case 2: new_pos = vfd.data.size() + offset; break;
        default: return -22;
    }
    vfd.position = new_pos;
    return new_pos;
}

int64_t SyscallHandler::sys_mmap(uint64_t addr, size_t len, int prot, int flags, int fd, int64_t off) {
    uint64_t result = memory_.heap().allocate(len, PAGE_SIZE);
    if (result == 0) return -12;
    memory_.zero(result, len);
    return result;
}

int64_t SyscallHandler::sys_mprotect(uint64_t addr, size_t len, int prot) { return 0; }
int64_t SyscallHandler::sys_munmap(uint64_t addr, size_t len) { memory_.heap().free(addr); return 0; }

int64_t SyscallHandler::sys_brk(uint64_t addr) {
    if (addr == 0) return current_brk_;
    if (addr > current_brk_) current_brk_ = addr;
    return current_brk_;
}

int64_t SyscallHandler::sys_fstat(int fd, uint64_t statbuf) {
    // Zero the stat buffer first
    memory_.zero(statbuf, 128);

    // For stdin/stdout/stderr, return character device info
    if (fd >= 0 && fd <= 2) {
        // ARM64 Android struct stat layout:
        // st_dev: offset 0, size 8
        // st_ino: offset 8, size 8
        // st_mode: offset 16, size 4
        // st_nlink: offset 20, size 4
        // st_uid: offset 24, size 4
        // st_gid: offset 28, size 4
        // st_rdev: offset 32, size 8
        // st_size: offset 48, size 8
        // st_blksize: offset 56, size 8
        // st_blocks: offset 64, size 8
        // st_atime: offset 72, size 8
        // st_mtime: offset 88, size 8
        // st_ctime: offset 104, size 8

        uint32_t mode = 0020666;  // S_IFCHR | 0666 (character device, rw for all)
        uint32_t nlink = 1;
        uint64_t rdev = 0x0500;  // /dev/tty major=5, minor=0
        uint64_t blksize = 1024;

        memory_.write(statbuf + 16, &mode, 4);
        memory_.write(statbuf + 20, &nlink, 4);
        memory_.write(statbuf + 32, &rdev, 8);
        memory_.write(statbuf + 56, &blksize, 8);
        return 0;
    }

    // For other file descriptors, check if they're open
    auto it = open_fds_.find(fd);
    if (it == open_fds_.end()) {
        return -9;  // EBADF
    }

    // Return regular file info
    uint32_t mode = 0100644;  // S_IFREG | 0644 (regular file)
    uint32_t nlink = 1;
    uint64_t size = it->second.data.size();
    uint64_t blksize = 4096;

    memory_.write(statbuf + 16, &mode, 4);
    memory_.write(statbuf + 20, &nlink, 4);
    memory_.write(statbuf + 48, &size, 8);
    memory_.write(statbuf + 56, &blksize, 8);
    return 0;
}
int64_t SyscallHandler::sys_exit(int status) {
    if (logging_enabled_) {
        EMU_LOG << "[SYSCALL] exit(" << status << ")" << std::endl;
    }
    emu_.stop();
    return 0;
}
int64_t SyscallHandler::sys_futex(uint64_t uaddr, int op, uint32_t val,
                                   uint64_t timeout, uint64_t uaddr2, uint32_t val3) {
    // Extract the command (mask out private and clock flags)
    int cmd = op & FUTEX_CMD_MASK;

    if (logging_enabled_) {
        EMU_LOG << "[SYSCALL] futex(uaddr=0x" << std::hex << uaddr
                  << ", op=" << std::dec << cmd << ", val=" << val << ")" << std::endl;
    }

    switch (cmd) {
        case FUTEX_WAIT:
            return futex_wait(uaddr, val, FUTEX_BITSET_MATCH_ANY, timeout);

        case FUTEX_WAKE:
            return futex_wake(uaddr, val, FUTEX_BITSET_MATCH_ANY);

        case FUTEX_WAIT_BITSET:
            return futex_wait(uaddr, val, val3, timeout);

        case FUTEX_WAKE_BITSET:
            return futex_wake(uaddr, val, val3);

        case FUTEX_REQUEUE:
        case FUTEX_CMP_REQUEUE:
            // Requeue operations: wake up to val threads on uaddr,
            // then move remaining waiters to uaddr2
            {
                int woken = futex_wake(uaddr, val, FUTEX_BITSET_MATCH_ANY);
                // For simplicity, we don't implement the requeue part
                // since it's rarely needed in practice
                (void)uaddr2;
                (void)val3;
                return woken;
            }

        case FUTEX_WAKE_OP:
            // Wake op: wake val threads on uaddr, optionally modify memory at uaddr2,
            // then conditionally wake val3 threads on uaddr2
            {
                int woken = futex_wake(uaddr, val, FUTEX_BITSET_MATCH_ANY);
                // Simplified: just wake on both addresses
                woken += futex_wake(uaddr2, val3, FUTEX_BITSET_MATCH_ANY);
                return woken;
            }

        default:
            // Unsupported operation - return success for compatibility
            if (logging_enabled_) {
                EMU_LOG << "[SYSCALL] futex: unsupported op " << cmd << std::endl;
            }
            return 0;
    }
}

int SyscallHandler::futex_wait(uint64_t uaddr, uint32_t expected, uint32_t bitset, uint64_t timeout) {
    (void)timeout;  // TODO: implement timeout support

    // Read current value at uaddr
    uint32_t current_val = 0;
    memory_.read(uaddr, &current_val, sizeof(current_val));

    // If value doesn't match expected, return EAGAIN
    if (current_val != expected) {
        return -EAGAIN;
    }

    // In cooperative threading mode, we need to block this thread
    // and switch to another thread
    ThreadManager& threads = emu_.threads();
    uint64_t thread_id = threads.get_current_thread_id();

    // If threading is not enabled or only one thread, just return success
    // (simulating immediate wakeup)
    if (!threads.is_threading_enabled() || threads.get_thread_count() <= 1) {
        return 0;
    }

    // Add this thread to the futex wait queue
    {
        std::lock_guard<std::mutex> lock(futex_mutex_);
        FutexWaiter waiter;
        waiter.thread_id = thread_id;
        waiter.bitset = bitset;
        waiter.return_addr = 0;  // Will be set by context switch
        futex_waiters_[uaddr].push_back(waiter);
    }

    // Mark thread as blocked on futex and trigger context switch
    // The thread will be unblocked when futex_wake is called
    threads.block_on_futex(uaddr);

    // When we return here, we've been woken up
    return 0;
}

int SyscallHandler::futex_wake(uint64_t uaddr, uint32_t count, uint32_t bitset) {
    std::lock_guard<std::mutex> lock(futex_mutex_);

    auto it = futex_waiters_.find(uaddr);
    if (it == futex_waiters_.end() || it->second.empty()) {
        return 0;  // No waiters
    }

    int woken = 0;
    auto& waiters = it->second;

    for (auto waiter_it = waiters.begin(); waiter_it != waiters.end() && (uint32_t)woken < count; ) {
        // Check if bitsets match
        if ((waiter_it->bitset & bitset) != 0) {
            // Wake this thread
            uint64_t thread_id = waiter_it->thread_id;
            waiter_it = waiters.erase(waiter_it);

            // Unblock the thread
            emu_.threads().unblock_from_futex(thread_id);
            woken++;
        } else {
            ++waiter_it;
        }
    }

    // Clean up empty wait queue
    if (waiters.empty()) {
        futex_waiters_.erase(it);
    }

    return woken;
}

int64_t SyscallHandler::sys_clock_gettime(int clk_id, uint64_t tp) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    memory_.write(tp, &ts.tv_sec, 8);
    memory_.write(tp + 8, &ts.tv_nsec, 8);
    return 0;
}

int64_t SyscallHandler::sys_gettimeofday(uint64_t tv, uint64_t tz) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    int64_t sec = ts.tv_sec;
    int64_t usec = ts.tv_nsec / 1000;
    memory_.write(tv, &sec, 8);
    memory_.write(tv + 8, &usec, 8);
    return 0;
}

int64_t SyscallHandler::sys_getrandom(uint64_t buf, size_t buflen, unsigned int flags) {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::vector<uint8_t> data(buflen);
    for (size_t i = 0; i < buflen; i += 8) {
        uint64_t val = gen();
        size_t to_copy = std::min(buflen - i, size_t(8));
        memcpy(data.data() + i, &val, to_copy);
    }
    memory_.write(buf, data.data(), buflen);
    return buflen;
}

int64_t SyscallHandler::sys_prctl(int option, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5) { return 0; }
int64_t SyscallHandler::sys_madvise(uint64_t addr, size_t len, int advice) { return 0; }
int64_t SyscallHandler::sys_rt_sigaction(int sig, uint64_t act, uint64_t oact, size_t sigsetsize) { return 0; }
int64_t SyscallHandler::sys_rt_sigprocmask(int how, uint64_t set, uint64_t oset, size_t sigsetsize) { return 0; }

int64_t SyscallHandler::sys_ioctl(int fd, uint64_t request, uint64_t arg) {
    // TIOCGWINSZ (0x5413) - get window size
    if (request == 0x5413) {
        // Return a reasonable terminal size
        // struct winsize { unsigned short ws_row, ws_col, ws_xpixel, ws_ypixel; }
        uint16_t winsize[4] = {24, 80, 0, 0};  // 24 rows, 80 columns
        memory_.write(arg, winsize, 8);
        return 0;
    }
    // TCGETS (0x5401) - get terminal attributes
    if (request == 0x5401) {
        // Return zeroed termios structure (indicates raw mode)
        memory_.zero(arg, 60);  // sizeof(struct termios) on ARM64
        return 0;
    }
    // For stdin/stdout/stderr, return success for most ioctls
    if (fd >= 0 && fd <= 2) {
        return 0;
    }
    return -25;  // ENOTTY
}

int64_t SyscallHandler::sys_writev(int fd, uint64_t iov, int iovcnt) {
    // struct iovec { void *iov_base; size_t iov_len; }
    // On ARM64, each iovec is 16 bytes (8 + 8)
    int64_t total = 0;

    for (int i = 0; i < iovcnt; i++) {
        uint64_t base, len;
        memory_.read(iov + i * 16, &base, 8);
        memory_.read(iov + i * 16 + 8, &len, 8);

        if (len > 0) {
            int64_t written = sys_write(fd, base, len);
            if (written < 0) return written;
            total += written;
        }
    }
    return total;
}

int64_t SyscallHandler::sys_pipe2(uint64_t pipefd, int flags) {
    // Create a real pipe using host syscall
    int fds[2];
    int result = ::pipe(fds);
    if (result < 0) {
        return -errno;
    }

    // Store the file descriptors in emulated memory
    int32_t fd0 = fds[0];
    int32_t fd1 = fds[1];
    memory_.write(pipefd, &fd0, 4);
    memory_.write(pipefd + 4, &fd1, 4);

    EMU_LOG << "[SYSCALL] pipe2: created pipe [" << fd0 << ", " << fd1 << "]" << std::endl;
    return 0;
}

int64_t SyscallHandler::sys_socket(int domain, int type, int protocol) {
    // Create a real socket using host syscall
    int sockfd = ::socket(domain, type, protocol);
    if (sockfd < 0) {
        EMU_LOG << "[SYSCALL] socket failed: " << strerror(errno) << std::endl;
        return -errno;
    }
    EMU_LOG << "[SYSCALL] socket: created socket " << sockfd << " (domain=" << domain << ", type=" << type << ")" << std::endl;
    return sockfd;
}

int64_t SyscallHandler::sys_connect(int sockfd, uint64_t addr, uint32_t addrlen) {
    // Read the sockaddr structure from emulated memory
    std::vector<uint8_t> sockaddr_buf(addrlen);
    memory_.read(addr, sockaddr_buf.data(), addrlen);

    // Call host connect
    int result = ::connect(sockfd, (struct sockaddr*)sockaddr_buf.data(), addrlen);
    if (result < 0) {
        EMU_LOG << "[SYSCALL] connect failed: " << strerror(errno) << std::endl;
        return -errno;
    }
    EMU_LOG << "[SYSCALL] connect: connected socket " << sockfd << std::endl;
    return 0;
}

int64_t SyscallHandler::sys_bind(int sockfd, uint64_t addr, uint32_t addrlen) {
    std::vector<uint8_t> sockaddr_buf(addrlen);
    memory_.read(addr, sockaddr_buf.data(), addrlen);

    int result = ::bind(sockfd, (struct sockaddr*)sockaddr_buf.data(), addrlen);
    if (result < 0) {
        return -errno;
    }
    return 0;
}

int64_t SyscallHandler::sys_listen(int sockfd, int backlog) {
    int result = ::listen(sockfd, backlog);
    if (result < 0) {
        return -errno;
    }
    return 0;
}

int64_t SyscallHandler::sys_accept(int sockfd, uint64_t addr, uint64_t addrlen) {
    socklen_t len = 0;
    if (addrlen != 0) {
        uint32_t len32;
        memory_.read(addrlen, &len32, 4);
        len = len32;
    }

    std::vector<uint8_t> sockaddr_buf(len);
    int result = ::accept(sockfd, (struct sockaddr*)sockaddr_buf.data(), &len);
    if (result < 0) {
        return -errno;
    }

    if (addr != 0 && len > 0) {
        memory_.write(addr, sockaddr_buf.data(), len);
    }
    if (addrlen != 0) {
        uint32_t len32 = len;
        memory_.write(addrlen, &len32, 4);
    }

    return result;
}

int64_t SyscallHandler::sys_getsockname(int sockfd, uint64_t addr, uint64_t addrlen) {
    socklen_t len;
    uint32_t len32;
    memory_.read(addrlen, &len32, 4);
    len = len32;

    std::vector<uint8_t> sockaddr_buf(len);
    int result = ::getsockname(sockfd, (struct sockaddr*)sockaddr_buf.data(), &len);
    if (result < 0) {
        return -errno;
    }

    memory_.write(addr, sockaddr_buf.data(), len);
    len32 = len;
    memory_.write(addrlen, &len32, 4);

    return 0;
}

int64_t SyscallHandler::sys_getpeername(int sockfd, uint64_t addr, uint64_t addrlen) {
    socklen_t len;
    uint32_t len32;
    memory_.read(addrlen, &len32, 4);
    len = len32;

    std::vector<uint8_t> sockaddr_buf(len);
    int result = ::getpeername(sockfd, (struct sockaddr*)sockaddr_buf.data(), &len);
    if (result < 0) {
        return -errno;
    }

    memory_.write(addr, sockaddr_buf.data(), len);
    len32 = len;
    memory_.write(addrlen, &len32, 4);

    return 0;
}

int64_t SyscallHandler::sys_sendto(int sockfd, uint64_t buf, size_t len, int flags, uint64_t dest_addr, uint32_t addrlen) {
    std::vector<uint8_t> data(len);
    memory_.read(buf, data.data(), len);

    struct sockaddr* addr_ptr = nullptr;
    std::vector<uint8_t> sockaddr_buf;
    if (dest_addr != 0) {
        sockaddr_buf.resize(addrlen);
        memory_.read(dest_addr, sockaddr_buf.data(), addrlen);
        addr_ptr = (struct sockaddr*)sockaddr_buf.data();
    }

    ssize_t result = ::sendto(sockfd, data.data(), len, flags, addr_ptr, addrlen);
    if (result < 0) {
        return -errno;
    }
    return result;
}

int64_t SyscallHandler::sys_recvfrom(int sockfd, uint64_t buf, size_t len, int flags, uint64_t src_addr, uint64_t addrlen) {
    std::vector<uint8_t> data(len);

    socklen_t addr_len = 0;
    struct sockaddr* addr_ptr = nullptr;
    std::vector<uint8_t> sockaddr_buf;
    if (src_addr != 0 && addrlen != 0) {
        uint32_t len32;
        memory_.read(addrlen, &len32, 4);
        addr_len = len32;
        sockaddr_buf.resize(addr_len);
        addr_ptr = (struct sockaddr*)sockaddr_buf.data();
    }

    ssize_t result = ::recvfrom(sockfd, data.data(), len, flags, addr_ptr, &addr_len);
    if (result < 0) {
        return -errno;
    }

    memory_.write(buf, data.data(), result);

    if (src_addr != 0 && addr_len > 0) {
        memory_.write(src_addr, sockaddr_buf.data(), addr_len);
    }
    if (addrlen != 0) {
        uint32_t len32 = addr_len;
        memory_.write(addrlen, &len32, 4);
    }

    return result;
}

int64_t SyscallHandler::sys_setsockopt(int sockfd, int level, int optname, uint64_t optval, uint32_t optlen) {
    std::vector<uint8_t> optval_buf(optlen);
    memory_.read(optval, optval_buf.data(), optlen);

    int result = ::setsockopt(sockfd, level, optname, optval_buf.data(), optlen);
    if (result < 0) {
        return -errno;
    }
    return 0;
}

int64_t SyscallHandler::sys_getsockopt(int sockfd, int level, int optname, uint64_t optval, uint64_t optlen) {
    socklen_t len;
    uint32_t len32;
    memory_.read(optlen, &len32, 4);
    len = len32;

    std::vector<uint8_t> optval_buf(len);
    int result = ::getsockopt(sockfd, level, optname, optval_buf.data(), &len);
    if (result < 0) {
        return -errno;
    }

    memory_.write(optval, optval_buf.data(), len);
    len32 = len;
    memory_.write(optlen, &len32, 4);

    return 0;
}

} // namespace cross_shim
