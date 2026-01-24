/**
 * ARM64 Bionic libc structure definitions and conversion functions
 * 
 * This header defines the exact memory layout of ARM64 Android (bionic) libc
 * structures and provides conversion functions to/from host (x86_64 glibc) structures.
 * 
 * These structures are used by HLE functions to properly marshal data between
 * emulated ARM64 code and host system calls.
 */

#pragma once

#include <cstdint>
#include <cstring>
#include <ctime>
#include <dirent.h>
#include <poll.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <sys/time.h>

namespace cross_shim {
namespace bionic {

// ============================================================================
// ARM64 Bionic timespec (16 bytes)
// Same layout as x86_64 glibc on LP64 systems
// ============================================================================
struct timespec_arm64 {
    int64_t tv_sec;   // time_t is 64-bit on ARM64
    int64_t tv_nsec;  // long is 64-bit on ARM64
};
static_assert(sizeof(timespec_arm64) == 16, "timespec_arm64 must be 16 bytes");

inline void arm64_to_host_timespec(const timespec_arm64& arm64, struct timespec& host) {
    host.tv_sec = arm64.tv_sec;
    host.tv_nsec = arm64.tv_nsec;
}

inline void host_to_arm64_timespec(const struct timespec& host, timespec_arm64& arm64) {
    arm64.tv_sec = host.tv_sec;
    arm64.tv_nsec = host.tv_nsec;
}

// ============================================================================
// ARM64 Bionic timeval (16 bytes)
// Same layout as x86_64 glibc on LP64 systems
// ============================================================================
struct timeval_arm64 {
    int64_t tv_sec;   // time_t is 64-bit on ARM64
    int64_t tv_usec;  // suseconds_t is 64-bit on ARM64
};
static_assert(sizeof(timeval_arm64) == 16, "timeval_arm64 must be 16 bytes");

inline void arm64_to_host_timeval(const timeval_arm64& arm64, struct timeval& host) {
    host.tv_sec = arm64.tv_sec;
    host.tv_usec = arm64.tv_usec;
}

inline void host_to_arm64_timeval(const struct timeval& host, timeval_arm64& arm64) {
    arm64.tv_sec = host.tv_sec;
    arm64.tv_usec = host.tv_usec;
}

// ============================================================================
// ARM64 Bionic struct tm (56 bytes)
// Layout from bionic time.h:
//   int tm_sec, tm_min, tm_hour, tm_mday, tm_mon, tm_year, tm_wday, tm_yday, tm_isdst (36 bytes)
//   4 bytes padding
//   long tm_gmtoff (8 bytes)
//   const char* tm_zone (8 bytes)
// ============================================================================
struct tm_arm64 {
    int32_t tm_sec;
    int32_t tm_min;
    int32_t tm_hour;
    int32_t tm_mday;
    int32_t tm_mon;
    int32_t tm_year;
    int32_t tm_wday;
    int32_t tm_yday;
    int32_t tm_isdst;
    int32_t _padding;   // Padding before 8-byte aligned tm_gmtoff
    int64_t tm_gmtoff;
    uint64_t tm_zone;   // Pointer (guest address)
};
static_assert(sizeof(tm_arm64) == 56, "tm_arm64 must be 56 bytes");
static_assert(offsetof(tm_arm64, tm_gmtoff) == 40, "tm_gmtoff must be at offset 40");
static_assert(offsetof(tm_arm64, tm_zone) == 48, "tm_zone must be at offset 48");

inline void host_to_arm64_tm(const struct tm& host, tm_arm64& arm64, uint64_t zone_ptr = 0) {
    arm64.tm_sec = host.tm_sec;
    arm64.tm_min = host.tm_min;
    arm64.tm_hour = host.tm_hour;
    arm64.tm_mday = host.tm_mday;
    arm64.tm_mon = host.tm_mon;
    arm64.tm_year = host.tm_year;
    arm64.tm_wday = host.tm_wday;
    arm64.tm_yday = host.tm_yday;
    arm64.tm_isdst = host.tm_isdst;
    arm64._padding = 0;
    arm64.tm_gmtoff = host.tm_gmtoff;
    arm64.tm_zone = zone_ptr;  // Caller must provide guest pointer
}

inline void arm64_to_host_tm(const tm_arm64& arm64, struct tm& host) {
    host.tm_sec = arm64.tm_sec;
    host.tm_min = arm64.tm_min;
    host.tm_hour = arm64.tm_hour;
    host.tm_mday = arm64.tm_mday;
    host.tm_mon = arm64.tm_mon;
    host.tm_year = arm64.tm_year;
    host.tm_wday = arm64.tm_wday;
    host.tm_yday = arm64.tm_yday;
    host.tm_isdst = arm64.tm_isdst;
    host.tm_gmtoff = arm64.tm_gmtoff;
    host.tm_zone = nullptr;  // Cannot convert guest pointer to host
}

// ============================================================================
// ARM64 Bionic dirent (280 bytes on LP64)
// Layout from bionic dirent.h:
//   ino_t d_ino (8 bytes)
//   off64_t d_off (8 bytes)
//   unsigned short d_reclen (2 bytes)
//   unsigned char d_type (1 byte)
//   char d_name[256] (256 bytes)
//   + 5 bytes padding to align to 8 bytes = 280 bytes total
// ============================================================================
struct dirent_arm64 {
    uint64_t d_ino;
    int64_t d_off;
    uint16_t d_reclen;
    uint8_t d_type;
    char d_name[256];
    uint8_t _padding[5];  // Align to 8 bytes
};
static_assert(sizeof(dirent_arm64) == 280, "dirent_arm64 must be 280 bytes");
static_assert(offsetof(dirent_arm64, d_off) == 8, "d_off must be at offset 8");
static_assert(offsetof(dirent_arm64, d_reclen) == 16, "d_reclen must be at offset 16");
static_assert(offsetof(dirent_arm64, d_type) == 18, "d_type must be at offset 18");
static_assert(offsetof(dirent_arm64, d_name) == 19, "d_name must be at offset 19");

inline void host_to_arm64_dirent(const struct dirent& host, dirent_arm64& arm64) {
    arm64.d_ino = host.d_ino;
    arm64.d_off = host.d_off;
    arm64.d_reclen = sizeof(dirent_arm64);  // Use ARM64 size
    arm64.d_type = host.d_type;
    std::memset(arm64.d_name, 0, sizeof(arm64.d_name));
    std::strncpy(arm64.d_name, host.d_name, sizeof(arm64.d_name) - 1);
    std::memset(arm64._padding, 0, sizeof(arm64._padding));
}

// ============================================================================
// ARM64 Bionic pollfd (8 bytes)
// Same layout as x86_64 glibc
// ============================================================================
struct pollfd_arm64 {
    int32_t fd;
    int16_t events;
    int16_t revents;
};
static_assert(sizeof(pollfd_arm64) == 8, "pollfd_arm64 must be 8 bytes");

inline void arm64_to_host_pollfd(const pollfd_arm64& arm64, struct pollfd& host) {
    host.fd = arm64.fd;
    host.events = arm64.events;
    host.revents = arm64.revents;
}

inline void host_to_arm64_pollfd(const struct pollfd& host, pollfd_arm64& arm64) {
    arm64.fd = host.fd;
    arm64.events = host.events;
    arm64.revents = host.revents;
}

// ============================================================================
// ARM64 Bionic epoll_event (16 bytes)
// On x86_64 glibc, epoll_event is packed (12 bytes)
// On ARM64 bionic, it uses natural alignment (16 bytes)
// ============================================================================
struct epoll_event_arm64 {
    uint32_t events;
    uint32_t _padding;  // ARM64 adds 4 bytes padding before the 8-byte data union
    union {
        void* ptr;
        int fd;
        uint32_t u32;
        uint64_t u64;
    } data;
};
static_assert(sizeof(epoll_event_arm64) == 16, "epoll_event_arm64 must be 16 bytes");
static_assert(offsetof(epoll_event_arm64, data) == 8, "data must be at offset 8");

inline void arm64_to_host_epoll_event(const epoll_event_arm64& arm64, struct epoll_event& host) {
    host.events = arm64.events;
    host.data.u64 = arm64.data.u64;
}

inline void host_to_arm64_epoll_event(const struct epoll_event& host, epoll_event_arm64& arm64) {
    arm64.events = host.events;
    arm64._padding = 0;
    arm64.data.u64 = host.data.u64;
}

// ============================================================================
// ARM64 Bionic stat (128 bytes)
// Layout from bionic sys/stat.h for __aarch64__:
//   dev_t st_dev (8), ino_t st_ino (8), mode_t st_mode (4), nlink_t st_nlink (4)
//   uid_t st_uid (4), gid_t st_gid (4), dev_t st_rdev (8), unsigned long __pad1 (8)
//   off_t st_size (8), int st_blksize (4), int __pad2 (4), long st_blocks (8)
//   struct timespec st_atim (16), st_mtim (16), st_ctim (16)
//   unsigned int __unused4 (4), __unused5 (4)
// ============================================================================
struct stat_arm64 {
    uint64_t st_dev;      // 0
    uint64_t st_ino;      // 8
    uint32_t st_mode;     // 16
    uint32_t st_nlink;    // 20
    uint32_t st_uid;      // 24
    uint32_t st_gid;      // 28
    uint64_t st_rdev;     // 32
    uint64_t __pad1;      // 40
    int64_t st_size;      // 48
    int32_t st_blksize;   // 56
    int32_t __pad2;       // 60
    int64_t st_blocks;    // 64
    timespec_arm64 st_atim;  // 72
    timespec_arm64 st_mtim;  // 88
    timespec_arm64 st_ctim;  // 104
    uint32_t __unused4;   // 120
    uint32_t __unused5;   // 124
};
static_assert(sizeof(stat_arm64) == 128, "stat_arm64 must be 128 bytes");
static_assert(offsetof(stat_arm64, st_size) == 48, "st_size must be at offset 48");
static_assert(offsetof(stat_arm64, st_atim) == 72, "st_atim must be at offset 72");

inline void host_to_arm64_stat(const struct stat& host, stat_arm64& arm64) {
    arm64.st_dev = host.st_dev;
    arm64.st_ino = host.st_ino;
    arm64.st_mode = host.st_mode;
    arm64.st_nlink = host.st_nlink;
    arm64.st_uid = host.st_uid;
    arm64.st_gid = host.st_gid;
    arm64.st_rdev = host.st_rdev;
    arm64.__pad1 = 0;
    arm64.st_size = host.st_size;
    arm64.st_blksize = host.st_blksize;
    arm64.__pad2 = 0;
    arm64.st_blocks = host.st_blocks;
    arm64.st_atim.tv_sec = host.st_atim.tv_sec;
    arm64.st_atim.tv_nsec = host.st_atim.tv_nsec;
    arm64.st_mtim.tv_sec = host.st_mtim.tv_sec;
    arm64.st_mtim.tv_nsec = host.st_mtim.tv_nsec;
    arm64.st_ctim.tv_sec = host.st_ctim.tv_sec;
    arm64.st_ctim.tv_nsec = host.st_ctim.tv_nsec;
    arm64.__unused4 = 0;
    arm64.__unused5 = 0;
}

// ============================================================================
// ARM64 Bionic addrinfo (48 bytes)
// Layout from bionic netdb.h - NOTE: different from glibc!
// Bionic has ai_canonname BEFORE ai_addr, glibc has ai_addr BEFORE ai_canonname
// ============================================================================
struct addrinfo_arm64 {
    int32_t ai_flags;
    int32_t ai_family;
    int32_t ai_socktype;
    int32_t ai_protocol;
    uint32_t ai_addrlen;
    uint32_t _padding;
    uint64_t ai_canonname;  // Guest pointer
    uint64_t ai_addr;       // Guest pointer
    uint64_t ai_next;       // Guest pointer
};
static_assert(sizeof(addrinfo_arm64) == 48, "addrinfo_arm64 must be 48 bytes");
static_assert(offsetof(addrinfo_arm64, ai_canonname) == 24, "ai_canonname must be at offset 24");
static_assert(offsetof(addrinfo_arm64, ai_addr) == 32, "ai_addr must be at offset 32");

} // namespace bionic
} // namespace cross_shim
