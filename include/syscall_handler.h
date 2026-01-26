#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <functional>
#include <vector>
#include <list>
#include <mutex>

namespace cross_shim {

// Futex operation codes
constexpr int FUTEX_WAIT = 0;
constexpr int FUTEX_WAKE = 1;
constexpr int FUTEX_FD = 2;
constexpr int FUTEX_REQUEUE = 3;
constexpr int FUTEX_CMP_REQUEUE = 4;
constexpr int FUTEX_WAKE_OP = 5;
constexpr int FUTEX_LOCK_PI = 6;
constexpr int FUTEX_UNLOCK_PI = 7;
constexpr int FUTEX_TRYLOCK_PI = 8;
constexpr int FUTEX_WAIT_BITSET = 9;
constexpr int FUTEX_WAKE_BITSET = 10;
constexpr int FUTEX_WAIT_REQUEUE_PI = 11;
constexpr int FUTEX_CMP_REQUEUE_PI = 12;

// Futex flags
constexpr int FUTEX_PRIVATE_FLAG = 128;
constexpr int FUTEX_CLOCK_REALTIME = 256;
constexpr int FUTEX_CMD_MASK = ~(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME);

// Special bitset value meaning "match all"
constexpr uint32_t FUTEX_BITSET_MATCH_ANY = 0xFFFFFFFF;

// Futex waiter entry
struct FutexWaiter {
    uint64_t thread_id;
    uint32_t bitset;
    uint64_t return_addr;  // Where to return when woken
};

class Emulator;
class MemoryManager;

// ARM64 syscall numbers (Linux/Android)
enum Arm64Syscall {
    SYS_READ            = 63,
    SYS_WRITE           = 64,
    SYS_OPENAT          = 56,
    SYS_CLOSE           = 57,
    SYS_LSEEK           = 62,
    SYS_MMAP            = 222,
    SYS_MPROTECT        = 226,
    SYS_MUNMAP          = 215,
    SYS_BRK             = 214,
    SYS_IOCTL           = 29,
    SYS_WRITEV          = 66,
    SYS_READV           = 65,
    SYS_FSTAT           = 80,
    SYS_EXIT            = 93,
    SYS_EXIT_GROUP      = 94,
    SYS_FUTEX           = 98,
    SYS_CLOCK_GETTIME   = 113,
    SYS_GETTIMEOFDAY    = 169,
    SYS_GETPID          = 172,
    SYS_GETTID          = 178,
    SYS_GETUID          = 174,
    SYS_GETGID          = 176,
    SYS_GETEUID         = 175,
    SYS_GETEGID         = 177,
    SYS_GETRANDOM       = 278,
    SYS_PRCTL           = 167,
    SYS_MADVISE         = 233,
    SYS_RT_SIGACTION    = 134,
    SYS_RT_SIGPROCMASK  = 135,
    SYS_SCHED_YIELD     = 124,
    SYS_PIPE2           = 59,
    SYS_SOCKET          = 198,
    SYS_CONNECT         = 203,
    SYS_BIND            = 200,
    SYS_LISTEN          = 201,
    SYS_ACCEPT          = 202,
    SYS_GETSOCKNAME     = 204,
    SYS_GETPEERNAME     = 205,
    SYS_SENDTO          = 206,
    SYS_RECVFROM        = 207,
    SYS_SETSOCKOPT      = 208,
    SYS_GETSOCKOPT      = 209,
    SYS_EXECVE          = 221,
    SYS_EXECVEAT        = 281,
};

// Virtual file descriptor
struct VirtualFd {
    int fd;
    std::string path;
    std::vector<uint8_t> data;
    size_t position;
    bool is_open;
};

// Syscall handler
class SyscallHandler {
public:
    SyscallHandler(Emulator& emu, MemoryManager& memory);
    ~SyscallHandler() = default;
    
    // Handle a syscall (called from interrupt hook)
    void handle(uint64_t syscall_num);
    
    // Virtual file system
    void add_virtual_file(const std::string& path, const std::vector<uint8_t>& data);
    void add_virtual_file(const std::string& path, const std::string& content);
    
    // Enable/disable logging
    void set_logging(bool enabled) { logging_enabled_ = enabled; }

private:
    // Syscall implementations
    int64_t sys_read(int fd, uint64_t buf, size_t count);
    int64_t sys_write(int fd, uint64_t buf, size_t count);
    int64_t sys_openat(int dirfd, uint64_t pathname, int flags, int mode);
    int64_t sys_close(int fd);
    int64_t sys_lseek(int fd, int64_t offset, int whence);
    int64_t sys_mmap(uint64_t addr, size_t len, int prot, int flags, int fd, int64_t off);
    int64_t sys_mprotect(uint64_t addr, size_t len, int prot);
    int64_t sys_munmap(uint64_t addr, size_t len);
    int64_t sys_brk(uint64_t addr);
    int64_t sys_fstat(int fd, uint64_t statbuf);
    int64_t sys_exit(int status);
    int64_t sys_futex(uint64_t uaddr, int op, uint32_t val, uint64_t timeout, uint64_t uaddr2, uint32_t val3);
    int64_t sys_clock_gettime(int clk_id, uint64_t tp);
    int64_t sys_gettimeofday(uint64_t tv, uint64_t tz);
    int64_t sys_getrandom(uint64_t buf, size_t buflen, unsigned int flags);
    int64_t sys_prctl(int option, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5);
    int64_t sys_madvise(uint64_t addr, size_t len, int advice);
    int64_t sys_rt_sigaction(int sig, uint64_t act, uint64_t oact, size_t sigsetsize);
    int64_t sys_rt_sigprocmask(int how, uint64_t set, uint64_t oset, size_t sigsetsize);
    int64_t sys_ioctl(int fd, uint64_t request, uint64_t arg);
    int64_t sys_writev(int fd, uint64_t iov, int iovcnt);
    int64_t sys_pipe2(uint64_t pipefd, int flags);
    int64_t sys_socket(int domain, int type, int protocol);
    int64_t sys_connect(int sockfd, uint64_t addr, uint32_t addrlen);
    int64_t sys_bind(int sockfd, uint64_t addr, uint32_t addrlen);
    int64_t sys_listen(int sockfd, int backlog);
    int64_t sys_accept(int sockfd, uint64_t addr, uint64_t addrlen);
    int64_t sys_getsockname(int sockfd, uint64_t addr, uint64_t addrlen);
    int64_t sys_getpeername(int sockfd, uint64_t addr, uint64_t addrlen);
    int64_t sys_sendto(int sockfd, uint64_t buf, size_t len, int flags, uint64_t dest_addr, uint32_t addrlen);
    int64_t sys_recvfrom(int sockfd, uint64_t buf, size_t len, int flags, uint64_t src_addr, uint64_t addrlen);
    int64_t sys_setsockopt(int sockfd, int level, int optname, uint64_t optval, uint32_t optlen);
    int64_t sys_getsockopt(int sockfd, int level, int optname, uint64_t optval, uint64_t optlen);
    int64_t sys_execve(uint64_t pathname, uint64_t argv, uint64_t envp);
    int64_t sys_execveat(int dirfd, uint64_t pathname, uint64_t argv, uint64_t envp, int flags);

    // Helper functions
    std::string read_string(uint64_t address, size_t max_len = 4096);
    int allocate_fd();

    // Exec helpers
    bool is_arm64_elf(const std::string& path);
    std::vector<std::string> read_string_array(uint64_t array_addr);
    std::string get_cross_shim_path();
    
    // Futex helper functions
    int futex_wait(uint64_t uaddr, uint32_t val, uint32_t bitset, uint64_t timeout);
    int futex_wake(uint64_t uaddr, uint32_t count, uint32_t bitset);

    Emulator& emu_;
    MemoryManager& memory_;

    std::unordered_map<std::string, std::vector<uint8_t>> virtual_files_;
    std::unordered_map<int, VirtualFd> open_fds_;
    int next_fd_;
    uint64_t current_brk_;
    bool logging_enabled_;

    // Futex wait queues: address -> list of waiting threads
    std::unordered_map<uint64_t, std::list<FutexWaiter>> futex_waiters_;
    std::mutex futex_mutex_;
};

} // namespace cross_shim

