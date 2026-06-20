/**
 * HLE Directory Operations
 * opendir, readdir, closedir, rewinddir, seekdir, telldir
 * mkdir, rmdir, chdir, getcwd, unlink, chmod, fchmod
 */

#include "hle_manager.h"
#include "hle_path_translation.h"
#include "cross_shim.h"
#include "memory_manager.h"
#include "bionic_types.h"
#include "emu_compat.h"
#include <cstring>
#include <mutex>
#include <dirent.h>
#include <fts.h>
#include <ftw.h>
#include <fcntl.h>
#include <glob.h>
#include <memory>
#include <unistd.h>
#include <sys/stat.h>
#include <unordered_map>
#include <cerrno>
#include <algorithm>
#include <vector>

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

static bool is_deleted_proc_fd_path(const std::string& original_path, const std::string& resolved_path) {
    constexpr const char* kDeletedSuffix = " (deleted)";
    constexpr size_t kDeletedSuffixLen = 10;

    if (resolved_path.size() < kDeletedSuffixLen ||
        resolved_path.compare(resolved_path.size() - kDeletedSuffixLen, kDeletedSuffixLen,
                              kDeletedSuffix) != 0) {
        return false;
    }

    if (original_path.rfind("/proc/", 0) != 0) {
        return false;
    }

    const size_t fd_component = original_path.find("/fd/");
    return fd_component != std::string::npos && fd_component > 6;
}

static std::string guest_path_to_host(const std::string& path) {
    return translate_guest_host_path(path);
}

static std::string host_path_to_guest(const std::string& path) {
    return translate_host_guest_path(path);
}

// Directory handle management
static std::unordered_map<uint64_t, DIR*> g_dir_handles;
static uint64_t g_next_dir_handle = 0x2000;
static constexpr size_t MAX_GETCWD_ALLOCATION = 0x4000000;
static std::unordered_map<uint64_t, std::vector<uint64_t>> g_glob_guest_allocations;
struct FtsSession {
    std::vector<std::unique_ptr<char[]>> roots;
};
static std::unordered_map<FTS*, FtsSession> g_fts_sessions;

// Recursive lock guarding the directory tables above (g_dir_handles, g_next_dir_handle,
// g_glob_guest_allocations, g_fts_sessions). HLE handlers run concurrently on MTTCG guest
// threads with no global serialization, so concurrent opendir/readdir/closedir/glob/fts
// across camera sessions would corrupt these maps. Recursive because scandir comparators
// and ftw/nftw/glob callbacks re-enter dir handlers (via call_function_safe) on the same
// thread. (The per-walk ftw/glob contexts are thread_local and need no locking.)
static std::recursive_mutex g_dir_tables_mutex;

struct ftw_arm64 {
    int32_t base;
    int32_t level;
};
static_assert(sizeof(ftw_arm64) == 8, "ftw_arm64 must be 8 bytes");

constexpr int FTW_GUEST_F = 0;
constexpr int FTW_GUEST_D = 1;
constexpr int FTW_GUEST_DNR = 2;
constexpr int FTW_GUEST_DP = 3;
constexpr int FTW_GUEST_NS = 4;
constexpr int FTW_GUEST_SL = 5;
constexpr int FTW_GUEST_SLN = 6;

constexpr int FTW_GUEST_PHYS = 0x01;
constexpr int FTW_GUEST_MOUNT = 0x02;
constexpr int FTW_GUEST_DEPTH = 0x04;
constexpr int FTW_GUEST_CHDIR = 0x08;

struct glob_arm64 {
    uint64_t gl_pathc;
    uint64_t gl_matchc;
    uint64_t gl_offs;
    int32_t gl_flags;
    uint32_t _padding;
    uint64_t gl_pathv;
    uint64_t gl_errfunc;
    uint64_t gl_closedir;
    uint64_t gl_readdir;
    uint64_t gl_opendir;
    uint64_t gl_lstat;
    uint64_t gl_stat;
};
static_assert(sizeof(glob_arm64) == 88, "glob_arm64 must be 88 bytes");

constexpr int GLOB_GUEST_APPEND = 0x0001;
constexpr int GLOB_GUEST_DOOFFS = 0x0002;
constexpr int GLOB_GUEST_ERR = 0x0004;
constexpr int GLOB_GUEST_MARK = 0x0008;
constexpr int GLOB_GUEST_NOCHECK = 0x0010;
constexpr int GLOB_GUEST_NOSORT = 0x0020;
constexpr int GLOB_GUEST_ALTDIRFUNC = 0x0040;
constexpr int GLOB_GUEST_BRACE = 0x0080;
constexpr int GLOB_GUEST_MAGCHAR = 0x0100;
constexpr int GLOB_GUEST_NOMAGIC = 0x0200;
constexpr int GLOB_GUEST_QUOTE = 0x0400;
constexpr int GLOB_GUEST_TILDE = 0x0800;
constexpr int GLOB_GUEST_LIMIT = 0x1000;
constexpr int GLOB_GUEST_NOESCAPE = 0x2000;

constexpr int GLOB_GUEST_NOSPACE = -1;
constexpr int GLOB_GUEST_ABORTED = -2;
constexpr int GLOB_GUEST_NOMATCH = -3;

constexpr int FTS_GUEST_COMFOLLOW = 0x0001;
constexpr int FTS_GUEST_LOGICAL = 0x0002;
constexpr int FTS_GUEST_NOCHDIR = 0x0004;
constexpr int FTS_GUEST_NOSTAT = 0x0008;
constexpr int FTS_GUEST_PHYSICAL = 0x0010;
constexpr int FTS_GUEST_SEEDOT = 0x0020;
constexpr int FTS_GUEST_XDEV = 0x0040;

constexpr int FTS_GUEST_AGAIN = 1;
constexpr int FTS_GUEST_FOLLOW = 2;
constexpr int FTS_GUEST_NOINSTR = 3;
constexpr int FTS_GUEST_SKIP = 4;

static int host_ftw_flag_to_guest(int host_flag) {
    switch (host_flag) {
        case FTW_F:
            return FTW_GUEST_F;
        case FTW_D:
            return FTW_GUEST_D;
        case FTW_DNR:
            return FTW_GUEST_DNR;
        case FTW_NS:
            return FTW_GUEST_NS;
#ifdef FTW_SL
        case FTW_SL:
            return FTW_GUEST_SL;
#endif
#ifdef FTW_DP
        case FTW_DP:
            return FTW_GUEST_DP;
#endif
#ifdef FTW_SLN
        case FTW_SLN:
            return FTW_GUEST_SLN;
#endif
        default:
            return host_flag;
    }
}

static int guest_nftw_flags_to_host(int guest_flags) {
    int host_flags = 0;
    if ((guest_flags & FTW_GUEST_PHYS) != 0) {
        host_flags |= FTW_PHYS;
    }
    if ((guest_flags & FTW_GUEST_MOUNT) != 0) {
        host_flags |= FTW_MOUNT;
    }
    if ((guest_flags & FTW_GUEST_DEPTH) != 0) {
        host_flags |= FTW_DEPTH;
    }
    if ((guest_flags & FTW_GUEST_CHDIR) != 0) {
        host_flags |= FTW_CHDIR;
    }
    return host_flags;
}

static int guest_glob_flags_to_host(int guest_flags) {
    int host_flags = 0;
    if ((guest_flags & GLOB_GUEST_APPEND) != 0) {
        host_flags |= GLOB_APPEND;
    }
    if ((guest_flags & GLOB_GUEST_DOOFFS) != 0) {
        host_flags |= GLOB_DOOFFS;
    }
    if ((guest_flags & GLOB_GUEST_ERR) != 0) {
        host_flags |= GLOB_ERR;
    }
    if ((guest_flags & GLOB_GUEST_MARK) != 0) {
        host_flags |= GLOB_MARK;
    }
    if ((guest_flags & GLOB_GUEST_NOCHECK) != 0) {
        host_flags |= GLOB_NOCHECK;
    }
    if ((guest_flags & GLOB_GUEST_NOSORT) != 0) {
        host_flags |= GLOB_NOSORT;
    }
#ifdef GLOB_ALTDIRFUNC
    if ((guest_flags & GLOB_GUEST_ALTDIRFUNC) != 0) {
        host_flags |= GLOB_ALTDIRFUNC;
    }
#endif
#ifdef GLOB_BRACE
    if ((guest_flags & GLOB_GUEST_BRACE) != 0) {
        host_flags |= GLOB_BRACE;
    }
#endif
#ifdef GLOB_NOMAGIC
    if ((guest_flags & GLOB_GUEST_NOMAGIC) != 0) {
        host_flags |= GLOB_NOMAGIC;
    }
#endif
#ifdef GLOB_TILDE
    if ((guest_flags & GLOB_GUEST_TILDE) != 0) {
        host_flags |= GLOB_TILDE;
    }
#endif
    if ((guest_flags & GLOB_GUEST_NOESCAPE) != 0) {
        host_flags |= GLOB_NOESCAPE;
    }
    return host_flags;
}

static int host_glob_flags_to_guest(int host_flags) {
    int guest_flags = 0;
    if ((host_flags & GLOB_APPEND) != 0) {
        guest_flags |= GLOB_GUEST_APPEND;
    }
    if ((host_flags & GLOB_DOOFFS) != 0) {
        guest_flags |= GLOB_GUEST_DOOFFS;
    }
    if ((host_flags & GLOB_ERR) != 0) {
        guest_flags |= GLOB_GUEST_ERR;
    }
    if ((host_flags & GLOB_MARK) != 0) {
        guest_flags |= GLOB_GUEST_MARK;
    }
    if ((host_flags & GLOB_NOCHECK) != 0) {
        guest_flags |= GLOB_GUEST_NOCHECK;
    }
    if ((host_flags & GLOB_NOSORT) != 0) {
        guest_flags |= GLOB_GUEST_NOSORT;
    }
#ifdef GLOB_ALTDIRFUNC
    if ((host_flags & GLOB_ALTDIRFUNC) != 0) {
        guest_flags |= GLOB_GUEST_ALTDIRFUNC;
    }
#endif
#ifdef GLOB_BRACE
    if ((host_flags & GLOB_BRACE) != 0) {
        guest_flags |= GLOB_GUEST_BRACE;
    }
#endif
#ifdef GLOB_MAGCHAR
    if ((host_flags & GLOB_MAGCHAR) != 0) {
        guest_flags |= GLOB_GUEST_MAGCHAR;
    }
#endif
#ifdef GLOB_NOMAGIC
    if ((host_flags & GLOB_NOMAGIC) != 0) {
        guest_flags |= GLOB_GUEST_NOMAGIC;
    }
#endif
#ifdef GLOB_TILDE
    if ((host_flags & GLOB_TILDE) != 0) {
        guest_flags |= GLOB_GUEST_TILDE;
    }
#endif
    if ((host_flags & GLOB_NOESCAPE) != 0) {
        guest_flags |= GLOB_GUEST_NOESCAPE;
    }
    return guest_flags;
}

static int host_glob_result_to_guest(int host_result) {
    switch (host_result) {
        case 0:
            return 0;
        case GLOB_NOSPACE:
            return GLOB_GUEST_NOSPACE;
        case GLOB_ABORTED:
            return GLOB_GUEST_ABORTED;
        case GLOB_NOMATCH:
            return GLOB_GUEST_NOMATCH;
        default:
            return (host_result > 0) ? -host_result : host_result;
    }
}

static int guest_fts_options_to_host(int guest_options) {
    int host_options = 0;

#ifdef FTS_COMFOLLOW
    if ((guest_options & FTS_GUEST_COMFOLLOW) != 0) {
        host_options |= FTS_COMFOLLOW;
    }
#endif
#ifdef FTS_LOGICAL
    if ((guest_options & FTS_GUEST_LOGICAL) != 0) {
        host_options |= FTS_LOGICAL;
    }
#endif
#ifdef FTS_NOCHDIR
    if ((guest_options & FTS_GUEST_NOCHDIR) != 0) {
        host_options |= FTS_NOCHDIR;
    }
#endif
#ifdef FTS_NOSTAT
    if ((guest_options & FTS_GUEST_NOSTAT) != 0) {
        host_options |= FTS_NOSTAT;
    }
#endif
#ifdef FTS_PHYSICAL
    if ((guest_options & FTS_GUEST_PHYSICAL) != 0) {
        host_options |= FTS_PHYSICAL;
    }
#endif
#ifdef FTS_SEEDOT
    if ((guest_options & FTS_GUEST_SEEDOT) != 0) {
        host_options |= FTS_SEEDOT;
    }
#endif
#ifdef FTS_XDEV
    if ((guest_options & FTS_GUEST_XDEV) != 0) {
        host_options |= FTS_XDEV;
    }
#endif

    return host_options;
}

static int guest_fts_instruction_to_host(int guest_instruction) {
    switch (guest_instruction) {
        case FTS_GUEST_AGAIN:
#ifdef FTS_AGAIN
            return FTS_AGAIN;
#else
            return guest_instruction;
#endif
        case FTS_GUEST_FOLLOW:
#ifdef FTS_FOLLOW
            return FTS_FOLLOW;
#else
            return guest_instruction;
#endif
        case FTS_GUEST_NOINSTR:
#ifdef FTS_NOINSTR
            return FTS_NOINSTR;
#else
            return guest_instruction;
#endif
        case FTS_GUEST_SKIP:
#ifdef FTS_SKIP
            return FTS_SKIP;
#else
            return guest_instruction;
#endif
        default:
            return -1;
    }
}

static char* duplicate_cstring(const std::string& value) {
    char* copy = static_cast<char*>(std::malloc(value.size() + 1));
    if (copy != nullptr) {
        std::memcpy(copy, value.c_str(), value.size() + 1);
    }
    return copy;
}

static std::string normalize_glob_directory_path(const std::string& guest_reference_path,
                                                 const char* path) {
    std::string normalized =
        translate_host_path_for_guest(guest_reference_path, (path != nullptr) ? path : "");
    if (!normalized.empty() && normalized.back() != '/') {
        normalized.push_back('/');
    }
    return normalized;
}

static bool guest_glob_pattern_has_magic(const std::string& pattern, int guest_flags) {
    bool escaped = false;
    bool noescape = (guest_flags & GLOB_GUEST_NOESCAPE) != 0;

    for (char ch : pattern) {
        if (!noescape && !escaped && ch == '\\') {
            escaped = true;
            continue;
        }
        if (!escaped && (ch == '*' || ch == '?' || ch == '[')) {
            return true;
        }
        if (!escaped && ch == '{' && (guest_flags & GLOB_GUEST_BRACE) != 0) {
            return true;
        }
        escaped = false;
    }

    return false;
}

static uint64_t write_guest_string(Emulator& emu, const std::string& value) {
    uint64_t addr = emu.memory().heap().allocate(value.size() + 1, 1);
    if (addr != 0) {
        emu.mem_write(addr, value.c_str(), value.size() + 1);
    }
    return addr;
}

static void arm64_to_host_stat(const stat_arm64& arm64, struct stat& host) {
    std::memset(&host, 0, sizeof(host));
    host.st_dev = arm64.st_dev;
    host.st_ino = arm64.st_ino;
    host.st_mode = arm64.st_mode;
    host.st_nlink = arm64.st_nlink;
    host.st_uid = arm64.st_uid;
    host.st_gid = arm64.st_gid;
    host.st_rdev = arm64.st_rdev;
    host.st_size = arm64.st_size;
    host.st_blksize = arm64.st_blksize;
    host.st_blocks = arm64.st_blocks;
    host.st_atim.tv_sec = arm64.st_atim.tv_sec;
    host.st_atim.tv_nsec = arm64.st_atim.tv_nsec;
    host.st_mtim.tv_sec = arm64.st_mtim.tv_sec;
    host.st_mtim.tv_nsec = arm64.st_mtim.tv_nsec;
    host.st_ctim.tv_sec = arm64.st_ctim.tv_sec;
    host.st_ctim.tv_nsec = arm64.st_ctim.tv_nsec;
}

static void arm64_to_host_dirent(const dirent_arm64& arm64, struct dirent& host) {
    std::memset(&host, 0, sizeof(host));
    host.d_ino = arm64.d_ino;
    host.d_off = arm64.d_off;
    host.d_reclen = sizeof(struct dirent);
    host.d_type = arm64.d_type;
    std::strncpy(host.d_name, arm64.d_name, sizeof(host.d_name) - 1);
    host.d_name[sizeof(host.d_name) - 1] = '\0';
}

struct FtwCallbackContext {
    Emulator* emu;
    uint64_t guest_callback;
    bool include_ftw;
    std::string guest_root_path;
};

static thread_local FtwCallbackContext* g_current_ftw_context = nullptr;

static int invoke_guest_ftw_callback(const char* fpath, const struct stat* sb, int tflag,
                                     const struct FTW* ftwbuf) {
    if (g_current_ftw_context == nullptr || g_current_ftw_context->emu == nullptr ||
        g_current_ftw_context->guest_callback == 0 || fpath == nullptr) {
        errno = EINVAL;
        return -1;
    }

    Emulator& emu = *g_current_ftw_context->emu;
    std::vector<uint64_t> guest_allocations;

    std::string guest_path =
        translate_host_path_for_guest(g_current_ftw_context->guest_root_path, fpath);
    uint64_t path_addr = write_guest_string(emu, guest_path);
    guest_allocations.push_back(path_addr);

    stat_arm64 stat_guest{};
    if (sb != nullptr) {
        host_to_arm64_stat(*sb, stat_guest);
    }
    uint64_t stat_addr = emu.memory().heap().allocate(sizeof(stat_guest), 8);
    guest_allocations.push_back(stat_addr);
    if (stat_addr != 0) {
        emu.mem_write(stat_addr, &stat_guest, sizeof(stat_guest));
    }

    int guest_tflag = host_ftw_flag_to_guest(tflag);

    std::vector<uint64_t> args = {
        path_addr,
        stat_addr,
        static_cast<uint64_t>(static_cast<int64_t>(guest_tflag)),
    };

    uint64_t ftw_addr = 0;
    if (g_current_ftw_context->include_ftw) {
        ftw_arm64 ftw_guest{};
        if (ftwbuf != nullptr) {
            int base_adjustment = static_cast<int>(guest_path.size()) - static_cast<int>(std::strlen(fpath));
            ftw_guest.base = ftwbuf->base + base_adjustment;
            ftw_guest.level = ftwbuf->level;
        }
        ftw_addr = emu.memory().heap().allocate(sizeof(ftw_guest), 8);
        guest_allocations.push_back(ftw_addr);
        if (ftw_addr != 0) {
            emu.mem_write(ftw_addr, &ftw_guest, sizeof(ftw_guest));
        }
        args.push_back(ftw_addr);
    }

    uint64_t result = emu.call_function_safe(g_current_ftw_context->guest_callback, args);

    for (uint64_t addr : guest_allocations) {
        if (addr != 0) {
            emu.memory().heap().free(addr);
        }
    }

    return static_cast<int32_t>(result);
}

static int host_ftw_callback_bridge(const char* fpath, const struct stat* sb, int tflag) {
    return invoke_guest_ftw_callback(fpath, sb, tflag, nullptr);
}

static int host_nftw_callback_bridge(const char* fpath, const struct stat* sb, int tflag,
                                     struct FTW* ftwbuf) {
    return invoke_guest_ftw_callback(fpath, sb, tflag, ftwbuf);
}

struct GlobDirHandle {
    uint64_t guest_handle;
};

struct GlobContext {
    Emulator* emu;
    glob_arm64 guest_glob;
    uint64_t errfunc_addr;
    std::string guest_pattern;
};

static thread_local GlobContext* g_current_glob_context = nullptr;
static thread_local struct dirent g_glob_dirent_storage;

static void free_guest_glob_allocations(Emulator& emu, uint64_t glob_addr) {
    auto it = g_glob_guest_allocations.find(glob_addr);
    if (it == g_glob_guest_allocations.end()) {
        return;
    }
    for (uint64_t addr : it->second) {
        if (addr != 0) {
            emu.memory().heap().free(addr);
        }
    }
    g_glob_guest_allocations.erase(it);
}

static int host_glob_errfunc_bridge(const char* failure_path, int failure_errno) {
    if (g_current_glob_context == nullptr || g_current_glob_context->emu == nullptr ||
        g_current_glob_context->errfunc_addr == 0) {
        return 0;
    }

    Emulator& emu = *g_current_glob_context->emu;
    std::string normalized_path =
        normalize_glob_directory_path(g_current_glob_context->guest_pattern, failure_path);
    uint64_t path_addr = write_guest_string(emu, normalized_path);
    uint64_t result = emu.call_function_safe(g_current_glob_context->errfunc_addr,
                                             {path_addr, static_cast<uint64_t>(failure_errno)});
    if (path_addr != 0) {
        emu.memory().heap().free(path_addr);
    }
    return static_cast<int32_t>(result);
}

static void host_glob_closedir_bridge(void* dirp) {
    std::unique_ptr<GlobDirHandle> handle(static_cast<GlobDirHandle*>(dirp));
    if (g_current_glob_context == nullptr || g_current_glob_context->emu == nullptr ||
        g_current_glob_context->guest_glob.gl_closedir == 0 || handle == nullptr) {
        return;
    }

    g_current_glob_context->emu->call_function_safe(
        g_current_glob_context->guest_glob.gl_closedir, {handle->guest_handle});
}

static struct dirent* host_glob_readdir_bridge(void* dirp) {
    GlobDirHandle* handle = static_cast<GlobDirHandle*>(dirp);
    if (g_current_glob_context == nullptr || g_current_glob_context->emu == nullptr ||
        g_current_glob_context->guest_glob.gl_readdir == 0 || handle == nullptr) {
        return nullptr;
    }

    Emulator& emu = *g_current_glob_context->emu;
    uint64_t guest_dirent_addr = emu.call_function_safe(
        g_current_glob_context->guest_glob.gl_readdir, {handle->guest_handle});
    if (guest_dirent_addr == 0) {
        return nullptr;
    }

    dirent_arm64 guest_dirent{};
    if (!emu.mem_read(guest_dirent_addr, &guest_dirent, sizeof(guest_dirent))) {
        return nullptr;
    }

    arm64_to_host_dirent(guest_dirent, g_glob_dirent_storage);
    return &g_glob_dirent_storage;
}

static void* host_glob_opendir_bridge(const char* path) {
    if (g_current_glob_context == nullptr || g_current_glob_context->emu == nullptr ||
        g_current_glob_context->guest_glob.gl_opendir == 0) {
        errno = EINVAL;
        return nullptr;
    }

    Emulator& emu = *g_current_glob_context->emu;
    std::string normalized_path =
        normalize_glob_directory_path(g_current_glob_context->guest_pattern, path);
    uint64_t path_addr = write_guest_string(emu, normalized_path);
    uint64_t guest_handle = emu.call_function_safe(
        g_current_glob_context->guest_glob.gl_opendir, {path_addr});
    if (path_addr != 0) {
        emu.memory().heap().free(path_addr);
    }

    if (guest_handle == 0) {
        errno = hle_get_errno(emu);
        return nullptr;
    }

    GlobDirHandle* handle = new GlobDirHandle{guest_handle};
    return handle;
}

static int invoke_guest_glob_stat_bridge(uint64_t callback_addr, const char* path, struct stat* st) {
    if (g_current_glob_context == nullptr || g_current_glob_context->emu == nullptr || callback_addr == 0) {
        errno = EINVAL;
        return -1;
    }

    Emulator& emu = *g_current_glob_context->emu;
    std::string guest_path = translate_host_path_for_guest(
        g_current_glob_context->guest_pattern, path != nullptr ? path : "");
    uint64_t path_addr = write_guest_string(emu, guest_path);
    uint64_t stat_addr = emu.memory().heap().allocate(sizeof(stat_arm64), 8);
    stat_arm64 guest_stat{};
    if (stat_addr != 0) {
        emu.mem_write(stat_addr, &guest_stat, sizeof(guest_stat));
    }

    uint64_t result = emu.call_function_safe(callback_addr, {path_addr, stat_addr});
    if (path_addr != 0) {
        emu.memory().heap().free(path_addr);
    }

    int rc = static_cast<int32_t>(result);
    if (rc == 0 && st != nullptr && stat_addr != 0) {
        if (emu.mem_read(stat_addr, &guest_stat, sizeof(guest_stat))) {
            arm64_to_host_stat(guest_stat, *st);
        } else {
            std::memset(st, 0, sizeof(*st));
        }
    } else if (rc != 0) {
        errno = hle_get_errno(emu);
    }

    if (stat_addr != 0) {
        emu.memory().heap().free(stat_addr);
    }
    return rc;
}

static int host_glob_lstat_bridge(const char* path, struct stat* st) {
    return invoke_guest_glob_stat_bridge(g_current_glob_context->guest_glob.gl_lstat, path, st);
}

static int host_glob_stat_bridge(const char* path, struct stat* st) {
    return invoke_guest_glob_stat_bridge(g_current_glob_context->guest_glob.gl_stat, path, st);
}

static bool build_host_glob_seed_from_guest(Emulator& emu, const glob_arm64& guest, glob_t& host) {
    std::memset(&host, 0, sizeof(host));
    host.gl_offs = guest.gl_offs;
    host.gl_flags = guest_glob_flags_to_host(guest.gl_flags);

    if (guest.gl_pathc == 0 || guest.gl_pathv == 0) {
        return true;
    }

    size_t slot_count = guest.gl_offs + guest.gl_pathc + 1;
    host.gl_pathv = static_cast<char**>(std::calloc(slot_count, sizeof(char*)));
    if (host.gl_pathv == nullptr) {
        return false;
    }

    host.gl_pathc = guest.gl_pathc;
    for (size_t i = 0; i < guest.gl_pathc; ++i) {
        uint64_t guest_path_addr = 0;
        emu.mem_read(guest.gl_pathv + (guest.gl_offs + i) * 8, &guest_path_addr, sizeof(guest_path_addr));
        std::string path = guest_path_to_host(read_string(emu, guest_path_addr));
        host.gl_pathv[guest.gl_offs + i] = duplicate_cstring(path);
        if (host.gl_pathv[guest.gl_offs + i] == nullptr) {
            return false;
        }
    }

    return true;
}

static size_t compute_guest_glob_match_count(const std::string& pattern, int flags,
                                             const glob_t& host_glob, size_t previous_pathc) {
    size_t added_count = (host_glob.gl_pathc >= previous_pathc) ? (host_glob.gl_pathc - previous_pathc) : 0;
    if ((flags & GLOB_NOCHECK) != 0 && added_count == 1 && host_glob.gl_pathv != nullptr) {
        const char* added_path = host_glob.gl_pathv[host_glob.gl_offs + previous_pathc];
        if (added_path != nullptr &&
            pattern == translate_host_path_for_guest(pattern, added_path)) {
            return 0;
        }
    }
    return added_count;
}

static void write_guest_glob_result(Emulator& emu, uint64_t guest_glob_addr,
                                    const glob_arm64& guest_input, const glob_t& host_glob,
                                    const std::string& guest_pattern, size_t match_count,
                                    uint64_t errfunc_addr,
                                    bool pattern_has_magic) {
    free_guest_glob_allocations(emu, guest_glob_addr);

    glob_arm64 guest_output = guest_input;
    guest_output.gl_pathc = host_glob.gl_pathc;
    guest_output.gl_matchc = match_count;
    guest_output.gl_offs = host_glob.gl_offs;
    guest_output.gl_flags =
        host_glob_flags_to_guest(host_glob.gl_flags) |
        (guest_input.gl_flags & (GLOB_GUEST_QUOTE | GLOB_GUEST_LIMIT));
    if (pattern_has_magic) {
        guest_output.gl_flags |= GLOB_GUEST_MAGCHAR;
    } else {
        guest_output.gl_flags &= ~GLOB_GUEST_MAGCHAR;
    }
    guest_output._padding = 0;
    guest_output.gl_errfunc = errfunc_addr;
    guest_output.gl_pathv = 0;

    std::vector<uint64_t> allocations;
    if (host_glob.gl_pathc != 0 || host_glob.gl_offs != 0) {
        size_t slot_count = host_glob.gl_offs + host_glob.gl_pathc + 1;
        uint64_t pathv_addr = emu.memory().heap().allocate(slot_count * 8, 8);
        allocations.push_back(pathv_addr);
        guest_output.gl_pathv = pathv_addr;

        uint64_t null_ptr = 0;
        for (size_t i = 0; i < host_glob.gl_offs; ++i) {
            emu.mem_write(pathv_addr + i * 8, &null_ptr, sizeof(null_ptr));
        }

        for (size_t i = 0; i < host_glob.gl_pathc; ++i) {
            const char* path = host_glob.gl_pathv[host_glob.gl_offs + i];
            std::string path_string =
                translate_host_path_for_guest(guest_pattern, (path != nullptr) ? path : "");
            uint64_t path_addr = write_guest_string(emu, path_string);
            allocations.push_back(path_addr);
            emu.mem_write(pathv_addr + (host_glob.gl_offs + i) * 8, &path_addr, sizeof(path_addr));
        }
        emu.mem_write(pathv_addr + (host_glob.gl_offs + host_glob.gl_pathc) * 8, &null_ptr, sizeof(null_ptr));
    }

    if (!allocations.empty()) {
        g_glob_guest_allocations[guest_glob_addr] = allocations;
    }

    emu.mem_write(guest_glob_addr, &guest_output, sizeof(guest_output));
}

void register_hle_dir(HleManager& hle) {
    // Every directory handler runs under g_dir_tables_mutex for its whole body so the
    // directory tables can't be corrupted by concurrent guest threads. Recursive, so
    // scandir/ftw/glob callbacks that re-enter dir handlers on the same thread are safe.
    auto reg_locked = [&hle](const char* name, auto fn) {
        hle.register_function(name, [fn](Emulator& emu) {
            std::lock_guard<std::recursive_mutex> _dl(g_dir_tables_mutex);
            fn(emu);
        });
    };

    // ========================================================================
    // Directory traversal
    // ========================================================================

    reg_locked("opendir", [](Emulator& emu) {
        uint64_t name_addr = get_reg(emu, UC_ARM64_REG_X0);
        std::string name = read_string(emu, name_addr);
        std::string host_name = guest_path_to_host(name);
        
        DIR* dir = opendir(host_name.c_str());
        if (dir) {
            uint64_t handle = g_next_dir_handle++;
            g_dir_handles[handle] = dir;
            set_reg(emu, UC_ARM64_REG_X0, handle);
        } else {
            hle_set_errno(emu, errno);
            set_reg(emu, UC_ARM64_REG_X0, 0);
        }
    });

    reg_locked("fdopendir", [](Emulator& emu) {
        int fd = get_reg(emu, UC_ARM64_REG_X0);
        DIR* dir = fdopendir(fd);
        if (dir) {
            uint64_t handle = g_next_dir_handle++;
            g_dir_handles[handle] = dir;
            set_reg(emu, UC_ARM64_REG_X0, handle);
        } else {
            hle_set_errno(emu, errno);
            set_reg(emu, UC_ARM64_REG_X0, 0);
        }
    });

    reg_locked("closedir", [](Emulator& emu) {
        uint64_t handle = get_reg(emu, UC_ARM64_REG_X0);
        auto it = g_dir_handles.find(handle);
        if (it != g_dir_handles.end()) {
            int result = closedir(it->second);
            g_dir_handles.erase(it);
            if (result == -1) {
                hle_set_errno(emu, errno);
            }
            set_reg(emu, UC_ARM64_REG_X0, result);
        } else {
            hle_set_errno(emu, EINVAL);
            set_reg(emu, UC_ARM64_REG_X0, -1);
        }
    });

    reg_locked("readdir", [](Emulator& emu) {
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

    reg_locked("readdir_r", [](Emulator& emu) {
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

    // readdir64 - same as readdir on 64-bit systems
    reg_locked("readdir64", [](Emulator& emu) {
        uint64_t handle = get_reg(emu, UC_ARM64_REG_X0);
        auto it = g_dir_handles.find(handle);
        if (it != g_dir_handles.end()) {
            struct dirent* entry = readdir(it->second);
            if (entry) {
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

    // readdir64_r - same as readdir_r on 64-bit systems
    reg_locked("readdir64_r", [](Emulator& emu) {
        uint64_t handle = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t entry_addr = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t result_addr = get_reg(emu, UC_ARM64_REG_X2);

        auto it = g_dir_handles.find(handle);
        if (it != g_dir_handles.end()) {
            struct dirent* entry = readdir(it->second);
            if (entry) {
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

    // scandirat - scandir relative to directory fd
    reg_locked("scandirat", [](Emulator& emu) {
        int dirfd = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t dirp_addr = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t namelist_ptr = get_reg(emu, UC_ARM64_REG_X2);
        uint64_t filter_func = get_reg(emu, UC_ARM64_REG_X3);
        uint64_t compar_func = get_reg(emu, UC_ARM64_REG_X4);

        std::string dirpath = read_string(emu, dirp_addr);
        std::string host_dirpath = guest_path_to_host(dirpath);
        int fd = ::openat(dirfd, host_dirpath.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (fd == -1) {
            hle_set_errno(emu, errno);
            set_reg(emu, UC_ARM64_REG_X0, -1);
            return;
        }
        DIR* dir = fdopendir(fd);
        if (!dir) {
            hle_set_errno(emu, errno);
            ::close(fd);
            set_reg(emu, UC_ARM64_REG_X0, -1);
            return;
        }

        std::vector<struct dirent*> entries;
        struct dirent* entry;
        while ((entry = readdir(dir)) != nullptr) {
            struct dirent* copy = (struct dirent*)malloc(sizeof(struct dirent));
            memcpy(copy, entry, sizeof(struct dirent));
            entries.push_back(copy);
        }
        closedir(dir);

        // Sort if compar provided
        if (compar_func) {
            std::sort(entries.begin(), entries.end(), [](struct dirent* a, struct dirent* b) {
                return strcoll(a->d_name, b->d_name) < 0;
            });
        }

        size_t count = entries.size();
        uint64_t list_ptr = emu.memory().heap().allocate((count + 1) * 8, 8);

        for (size_t i = 0; i < count; i++) {
            dirent_arm64 entry_arm;
            host_to_arm64_dirent(*entries[i], entry_arm);
            uint64_t entry_ptr = emu.memory().heap().allocate(sizeof(dirent_arm64), 8);
            emu.mem_write(entry_ptr, &entry_arm, sizeof(entry_arm));
            emu.mem_write(list_ptr + i * 8, &entry_ptr, 8);
            free(entries[i]);
        }

        uint64_t null_ptr = 0;
        emu.mem_write(list_ptr + count * 8, &null_ptr, 8);
        emu.mem_write(namelist_ptr, &list_ptr, 8);

        set_reg(emu, UC_ARM64_REG_X0, count);
    });

    // scandirat64 - same as scandirat on 64-bit systems
    reg_locked("scandirat64", [](Emulator& emu) {
        int dirfd = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t dirp_addr = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t namelist_ptr = get_reg(emu, UC_ARM64_REG_X2);
        uint64_t filter_func = get_reg(emu, UC_ARM64_REG_X3);
        uint64_t compar_func = get_reg(emu, UC_ARM64_REG_X4);

        std::string dirpath = read_string(emu, dirp_addr);
        std::string host_dirpath = guest_path_to_host(dirpath);

        int fd = ::openat(dirfd, host_dirpath.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (fd == -1) {
            hle_set_errno(emu, errno);
            set_reg(emu, UC_ARM64_REG_X0, -1);
            return;
        }
        DIR* dir = fdopendir(fd);
        if (!dir) {
            hle_set_errno(emu, errno);
            ::close(fd);
            set_reg(emu, UC_ARM64_REG_X0, -1);
            return;
        }

        std::vector<struct dirent*> entries;
        struct dirent* entry;
        while ((entry = readdir(dir)) != nullptr) {
            struct dirent* copy = (struct dirent*)malloc(sizeof(struct dirent));
            memcpy(copy, entry, sizeof(struct dirent));
            entries.push_back(copy);
        }
        closedir(dir);

        if (compar_func) {
            std::sort(entries.begin(), entries.end(), [](struct dirent* a, struct dirent* b) {
                return strcoll(a->d_name, b->d_name) < 0;
            });
        }

        size_t count = entries.size();
        uint64_t list_ptr = emu.memory().heap().allocate((count + 1) * 8, 8);

        for (size_t i = 0; i < count; i++) {
            dirent_arm64 entry_arm;
            host_to_arm64_dirent(*entries[i], entry_arm);
            uint64_t entry_ptr = emu.memory().heap().allocate(sizeof(dirent_arm64), 8);
            emu.mem_write(entry_ptr, &entry_arm, sizeof(entry_arm));
            emu.mem_write(list_ptr + i * 8, &entry_ptr, 8);
            free(entries[i]);
        }

        uint64_t null_ptr = 0;
        emu.mem_write(list_ptr + count * 8, &null_ptr, 8);
        emu.mem_write(namelist_ptr, &list_ptr, 8);

        set_reg(emu, UC_ARM64_REG_X0, count);
    });

    reg_locked("rewinddir", [](Emulator& emu) {
        uint64_t handle = get_reg(emu, UC_ARM64_REG_X0);
        auto it = g_dir_handles.find(handle);
        if (it != g_dir_handles.end()) {
            rewinddir(it->second);
        }
    });

    reg_locked("seekdir", [](Emulator& emu) {
        uint64_t handle = get_reg(emu, UC_ARM64_REG_X0);
        long loc = get_reg(emu, UC_ARM64_REG_X1);
        auto it = g_dir_handles.find(handle);
        if (it != g_dir_handles.end()) {
            seekdir(it->second, loc);
        }
    });

    reg_locked("telldir", [](Emulator& emu) {
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

    reg_locked("mkdir", [](Emulator& emu) {
        uint64_t path_addr = get_reg(emu, UC_ARM64_REG_X0);
        mode_t mode = get_reg(emu, UC_ARM64_REG_X1);
        std::string path = read_string(emu, path_addr);
        std::string host_path = guest_path_to_host(path);
        int result = mkdir(host_path.c_str(), mode);
        if (result < 0) {
            hle_set_errno(emu, errno);
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    reg_locked("rmdir", [](Emulator& emu) {
        uint64_t path_addr = get_reg(emu, UC_ARM64_REG_X0);
        std::string path = read_string(emu, path_addr);
        std::string host_path = guest_path_to_host(path);
        int result = rmdir(host_path.c_str());
        if (result < 0) {
            hle_set_errno(emu, errno);
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    reg_locked("chdir", [](Emulator& emu) {
        uint64_t path_addr = get_reg(emu, UC_ARM64_REG_X0);
        std::string path = read_string(emu, path_addr);
        std::string host_path = guest_path_to_host(path);
        int result = chdir(host_path.c_str());
        if (result < 0) {
            hle_set_errno(emu, errno);
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    reg_locked("fchdir", [](Emulator& emu) {
        int fd = get_reg(emu, UC_ARM64_REG_X0);
        int result = fchdir(fd);
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    reg_locked("getcwd", [](Emulator& emu) {
        uint64_t buf_addr = get_reg(emu, UC_ARM64_REG_X0);
        size_t size = get_reg(emu, UC_ARM64_REG_X1);

        char* cwd = ::getcwd(nullptr, 0);
        if (!cwd) {
            hle_set_errno(emu, errno);
            set_reg(emu, UC_ARM64_REG_X0, 0);
            return;
        }

        std::string guest_cwd = host_path_to_guest(cwd);
        free(cwd);

        size_t needed = guest_cwd.size() + 1;
        if (buf_addr == 0) {
            size_t alloc_size = (size == 0) ? needed : size;
            if (alloc_size < needed) {
                hle_set_errno(emu, ERANGE);
                set_reg(emu, UC_ARM64_REG_X0, 0);
                return;
            }
            if (alloc_size > MAX_GETCWD_ALLOCATION) {
                hle_set_errno(emu, ENOMEM);
                set_reg(emu, UC_ARM64_REG_X0, 0);
                return;
            }
            uint64_t guest_buf = emu.memory().heap().allocate(alloc_size, 8);
            if (guest_buf == 0) {
                hle_set_errno(emu, ENOMEM);
                set_reg(emu, UC_ARM64_REG_X0, 0);
                return;
            }
            emu.mem_write(guest_buf, guest_cwd.c_str(), needed);
            set_reg(emu, UC_ARM64_REG_X0, guest_buf);
        } else {
            if (size == 0) {
                hle_set_errno(emu, EINVAL);
                set_reg(emu, UC_ARM64_REG_X0, 0);
                return;
            }
            if (size < needed) {
                hle_set_errno(emu, ERANGE);
                set_reg(emu, UC_ARM64_REG_X0, 0);
                return;
            }
            emu.mem_write(buf_addr, guest_cwd.c_str(), needed);
            set_reg(emu, UC_ARM64_REG_X0, buf_addr);
        }
    });

    reg_locked("unlink", [](Emulator& emu) {
        uint64_t path_addr = get_reg(emu, UC_ARM64_REG_X0);
        std::string path = read_string(emu, path_addr);
        std::string host_path = guest_path_to_host(path);
        int result = unlink(host_path.c_str());
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    reg_locked("chmod", [](Emulator& emu) {
        uint64_t path_addr = get_reg(emu, UC_ARM64_REG_X0);
        mode_t mode = get_reg(emu, UC_ARM64_REG_X1);
        std::string path = read_string(emu, path_addr);
        std::string host_path = guest_path_to_host(path);
        int result = chmod(host_path.c_str(), mode);
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    reg_locked("fchmod", [](Emulator& emu) {
        int fd = get_reg(emu, UC_ARM64_REG_X0);
        mode_t mode = get_reg(emu, UC_ARM64_REG_X1);
        int result = fchmod(fd, mode);
        if (result == -1) {
            hle_set_errno(emu, errno);
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    reg_locked("chown", [](Emulator& emu) {
        uint64_t path_addr = get_reg(emu, UC_ARM64_REG_X0);
        uid_t owner = get_reg(emu, UC_ARM64_REG_X1);
        gid_t group = get_reg(emu, UC_ARM64_REG_X2);
        std::string path = read_string(emu, path_addr);
        std::string host_path = guest_path_to_host(path);
        int result = chown(host_path.c_str(), owner, group);
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    reg_locked("fchown", [](Emulator& emu) {
        int fd = get_reg(emu, UC_ARM64_REG_X0);
        uid_t owner = get_reg(emu, UC_ARM64_REG_X1);
        gid_t group = get_reg(emu, UC_ARM64_REG_X2);
        int result = fchown(fd, owner, group);
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    reg_locked("link", [](Emulator& emu) {
        uint64_t oldpath_addr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t newpath_addr = get_reg(emu, UC_ARM64_REG_X1);
        std::string oldpath = read_string(emu, oldpath_addr);
        std::string newpath = read_string(emu, newpath_addr);
        std::string old_host_path = guest_path_to_host(oldpath);
        std::string new_host_path = guest_path_to_host(newpath);
        int result = link(old_host_path.c_str(), new_host_path.c_str());
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    reg_locked("symlink", [](Emulator& emu) {
        uint64_t target_addr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t linkpath_addr = get_reg(emu, UC_ARM64_REG_X1);
        std::string target = read_string(emu, target_addr);
        std::string linkpath = read_string(emu, linkpath_addr);
        std::string host_target = guest_path_to_host(target);
        std::string host_linkpath = guest_path_to_host(linkpath);
        int result = symlink(host_target.c_str(), host_linkpath.c_str());
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    reg_locked("readlink", [](Emulator& emu) {
        uint64_t path_addr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t buf_addr = get_reg(emu, UC_ARM64_REG_X1);
        size_t bufsiz = get_reg(emu, UC_ARM64_REG_X2);

        std::string path = read_string(emu, path_addr);
        std::string host_path = guest_path_to_host(path);
        std::vector<char> buf(bufsiz);
        ssize_t result = readlink(host_path.c_str(), buf.data(), bufsiz);
        if (result > 0) {
            std::string guest_target = translate_host_path_for_guest(
                path, std::string(buf.data(), static_cast<size_t>(result)));
            ssize_t guest_result = static_cast<ssize_t>(std::min(guest_target.size(), bufsiz));
            emu.mem_write(buf_addr, guest_target.data(), guest_result);
            result = guest_result;
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    reg_locked("realpath", [](Emulator& emu) {
        uint64_t path_addr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t resolved_addr = get_reg(emu, UC_ARM64_REG_X1);

        if (path_addr == 0) {
            hle_set_errno(emu, EINVAL);
            set_reg(emu, UC_ARM64_REG_X0, 0);
            return;
        }

        std::string path = read_string(emu, path_addr);
        errno = 0;
        std::string host_path = guest_path_to_host(path);
        char* resolved = realpath(host_path.c_str(), nullptr);

        if (resolved) {
            std::string guest_resolved_path = translate_host_path_for_guest(path, resolved);
            if (is_deleted_proc_fd_path(path, guest_resolved_path)) {
                free(resolved);
                hle_set_errno(emu, ENOENT);
                set_reg(emu, UC_ARM64_REG_X0, 0);
                return;
            }

            if (resolved_addr) {
                emu.mem_write(resolved_addr, guest_resolved_path.c_str(), guest_resolved_path.size() + 1);
                set_reg(emu, UC_ARM64_REG_X0, resolved_addr);
            } else {
                uint64_t ptr = emu.memory().heap().allocate(guest_resolved_path.size() + 1, 8);
                emu.mem_write(ptr, guest_resolved_path.c_str(), guest_resolved_path.size() + 1);
                set_reg(emu, UC_ARM64_REG_X0, ptr);
            }
            free(resolved);
        } else {
            hle_set_errno(emu, errno);
            set_reg(emu, UC_ARM64_REG_X0, 0);
        }
    });

    // ========================================================================
    // Directory scanning
    // ========================================================================

    // alphasort - comparison function for scandir
    reg_locked("alphasort", [](Emulator& emu) {
        uint64_t a_ptr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t b_ptr = get_reg(emu, UC_ARM64_REG_X1);

        // Read pointers to dirent structures
        uint64_t a_dirent, b_dirent;
        emu.mem_read(a_ptr, &a_dirent, 8);
        emu.mem_read(b_ptr, &b_dirent, 8);

        // Read d_name from each dirent (offset 19 on ARM64 bionic)
        char name_a[256], name_b[256];
        emu.mem_read(a_dirent + 19, name_a, 256);
        emu.mem_read(b_dirent + 19, name_b, 256);
        name_a[255] = '\0';
        name_b[255] = '\0';

        int result = strcoll(name_a, name_b);
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // alphasort64 - same as alphasort on 64-bit systems
    reg_locked("alphasort64", [](Emulator& emu) {
        uint64_t a_ptr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t b_ptr = get_reg(emu, UC_ARM64_REG_X1);

        uint64_t a_dirent, b_dirent;
        emu.mem_read(a_ptr, &a_dirent, 8);
        emu.mem_read(b_ptr, &b_dirent, 8);

        char name_a[256], name_b[256];
        emu.mem_read(a_dirent + 19, name_a, 256);
        emu.mem_read(b_dirent + 19, name_b, 256);
        name_a[255] = '\0';
        name_b[255] = '\0';

        int result = strcoll(name_a, name_b);
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // scandir - scan a directory for matching entries
    reg_locked("scandir", [](Emulator& emu) {
        uint64_t dirp_addr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t namelist_ptr = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t filter_func = get_reg(emu, UC_ARM64_REG_X2);
        uint64_t compar_func = get_reg(emu, UC_ARM64_REG_X3);

        std::string dirpath = read_string(emu, dirp_addr);
        std::string host_dirpath = guest_path_to_host(dirpath);

        // Open the directory
        DIR* dir = opendir(host_dirpath.c_str());
        if (!dir) {
            hle_set_errno(emu, errno);
            set_reg(emu, UC_ARM64_REG_X0, -1);
            return;
        }

        // Collect all entries
        std::vector<struct dirent*> entries;
        struct dirent* entry;
        while ((entry = readdir(dir)) != nullptr) {
            // Allocate a copy
            struct dirent* copy = (struct dirent*)malloc(sizeof(struct dirent));
            memcpy(copy, entry, sizeof(struct dirent));
            entries.push_back(copy);
        }
        closedir(dir);

        // Filter entries if filter function provided
        if (filter_func) {
            std::vector<struct dirent*> filtered;
            for (struct dirent* e : entries) {
                // Convert to ARM64 format and call filter
                dirent_arm64 entry_arm;
                host_to_arm64_dirent(*e, entry_arm);
                uint64_t entry_ptr = emu.memory().heap().allocate(sizeof(dirent_arm64), 8);
                emu.mem_write(entry_ptr, &entry_arm, sizeof(entry_arm));

                uint64_t result = emu.call_function_safe(filter_func, {entry_ptr});

                emu.memory().heap().free(entry_ptr);

                if (result != 0) {
                    filtered.push_back(e);
                } else {
                    free(e);
                }
            }
            entries = filtered;
        }

        // Sort entries if compar function provided
        // Note: For simplicity, we use alphasort behavior
        if (compar_func) {
            std::sort(entries.begin(), entries.end(), [](struct dirent* a, struct dirent* b) {
                return strcoll(a->d_name, b->d_name) < 0;
            });
        }

        // Allocate and populate namelist
        size_t count = entries.size();
        uint64_t list_ptr = emu.memory().heap().allocate((count + 1) * 8, 8);  // Array of pointers

        for (size_t i = 0; i < count; i++) {
            dirent_arm64 entry_arm;
            host_to_arm64_dirent(*entries[i], entry_arm);
            uint64_t entry_ptr = emu.memory().heap().allocate(sizeof(dirent_arm64), 8);
            emu.mem_write(entry_ptr, &entry_arm, sizeof(entry_arm));
            emu.mem_write(list_ptr + i * 8, &entry_ptr, 8);
            free(entries[i]);
        }

        // Null terminate
        uint64_t null_ptr = 0;
        emu.mem_write(list_ptr + count * 8, &null_ptr, 8);

        // Write list pointer to output
        emu.mem_write(namelist_ptr, &list_ptr, 8);

        set_reg(emu, UC_ARM64_REG_X0, count);
    });

    // scandir64 - same as scandir on 64-bit systems
    reg_locked("scandir64", [](Emulator& emu) {
        // Forward to scandir implementation
        uint64_t dirp_addr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t namelist_ptr = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t filter_func = get_reg(emu, UC_ARM64_REG_X2);
        uint64_t compar_func = get_reg(emu, UC_ARM64_REG_X3);

        std::string dirpath = read_string(emu, dirp_addr);
        std::string host_dirpath = guest_path_to_host(dirpath);

        DIR* dir = opendir(host_dirpath.c_str());
        if (!dir) {
            hle_set_errno(emu, errno);
            set_reg(emu, UC_ARM64_REG_X0, -1);
            return;
        }

        std::vector<struct dirent*> entries;
        struct dirent* entry;
        while ((entry = readdir(dir)) != nullptr) {
            struct dirent* copy = (struct dirent*)malloc(sizeof(struct dirent));
            memcpy(copy, entry, sizeof(struct dirent));
            entries.push_back(copy);
        }
        closedir(dir);

        if (filter_func) {
            std::vector<struct dirent*> filtered;
            for (struct dirent* e : entries) {
                dirent_arm64 entry_arm;
                host_to_arm64_dirent(*e, entry_arm);
                uint64_t entry_ptr = emu.memory().heap().allocate(sizeof(dirent_arm64), 8);
                emu.mem_write(entry_ptr, &entry_arm, sizeof(entry_arm));

                uint64_t result = emu.call_function_safe(filter_func, {entry_ptr});
                emu.memory().heap().free(entry_ptr);

                if (result != 0) {
                    filtered.push_back(e);
                } else {
                    free(e);
                }
            }
            entries = filtered;
        }

        if (compar_func) {
            std::sort(entries.begin(), entries.end(), [](struct dirent* a, struct dirent* b) {
                return strcoll(a->d_name, b->d_name) < 0;
            });
        }

        size_t count = entries.size();
        uint64_t list_ptr = emu.memory().heap().allocate((count + 1) * 8, 8);

        for (size_t i = 0; i < count; i++) {
            dirent_arm64 entry_arm;
            host_to_arm64_dirent(*entries[i], entry_arm);
            uint64_t entry_ptr = emu.memory().heap().allocate(sizeof(dirent_arm64), 8);
            emu.mem_write(entry_ptr, &entry_arm, sizeof(entry_arm));
            emu.mem_write(list_ptr + i * 8, &entry_ptr, 8);
            free(entries[i]);
        }

        uint64_t null_ptr = 0;
        emu.mem_write(list_ptr + count * 8, &null_ptr, 8);
        emu.mem_write(namelist_ptr, &list_ptr, 8);

        set_reg(emu, UC_ARM64_REG_X0, count);
    });

    // ========================================================================
    // File tree walking
    // ========================================================================

    auto run_ftw = [](Emulator& emu, bool include_ftw_info) {
        uint64_t path_addr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t callback_addr = get_reg(emu, UC_ARM64_REG_X1);
        int max_fd_count = get_reg(emu, UC_ARM64_REG_X2);
        int guest_flags = include_ftw_info ? get_reg(emu, UC_ARM64_REG_X3) : 0;
        int host_flags = include_ftw_info ? guest_nftw_flags_to_host(guest_flags) : 0;

        if (path_addr == 0 || callback_addr == 0) {
            hle_set_errno(emu, EINVAL);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        std::string path = read_string(emu, path_addr);
        std::string host_path = guest_path_to_host(path);
        FtwCallbackContext context{&emu, callback_addr, include_ftw_info, path};
        FtwCallbackContext* previous = g_current_ftw_context;
        g_current_ftw_context = &context;

        int result = include_ftw_info
            ? ::nftw(host_path.c_str(), host_nftw_callback_bridge, max_fd_count, host_flags)
            : ::ftw(host_path.c_str(), host_ftw_callback_bridge, max_fd_count);

        g_current_ftw_context = previous;

        if (result == -1) {
            hle_set_errno(emu, errno);
        }
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(static_cast<int64_t>(result)));
    };

    reg_locked("ftw", [run_ftw](Emulator& emu) {
        run_ftw(emu, false);
    });

    reg_locked("ftw64", [run_ftw](Emulator& emu) {
        run_ftw(emu, false);
    });

    reg_locked("nftw", [run_ftw](Emulator& emu) {
        run_ftw(emu, true);
    });

    reg_locked("nftw64", [run_ftw](Emulator& emu) {
        run_ftw(emu, true);
    });

    // ========================================================================
    // Globbing
    // ========================================================================

    auto run_glob = [](Emulator& emu) {
        uint64_t pattern_addr = get_reg(emu, UC_ARM64_REG_X0);
        int guest_flags = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t errfunc_addr = get_reg(emu, UC_ARM64_REG_X2);
        uint64_t glob_addr = get_reg(emu, UC_ARM64_REG_X3);

        if (pattern_addr == 0 || glob_addr == 0) {
            set_reg(emu, UC_ARM64_REG_X0,
                    static_cast<uint64_t>(static_cast<int64_t>(GLOB_GUEST_ABORTED)));
            return;
        }

        std::string pattern = read_string(emu, pattern_addr);
        std::string host_pattern = guest_path_to_host(pattern);
        glob_arm64 guest_glob{};
        emu.mem_read(glob_addr, &guest_glob, sizeof(guest_glob));
        bool pattern_has_magic = guest_glob_pattern_has_magic(pattern, guest_flags);

        size_t previous_pathc =
            ((guest_flags & GLOB_GUEST_APPEND) != 0) ? guest_glob.gl_pathc : 0;
        int host_flags = guest_glob_flags_to_host(guest_flags);

        glob_t host_glob{};
        if ((guest_flags & GLOB_GUEST_APPEND) != 0 &&
            !build_host_glob_seed_from_guest(emu, guest_glob, host_glob)) {
            ::globfree(&host_glob);
            set_reg(emu, UC_ARM64_REG_X0,
                    static_cast<uint64_t>(static_cast<int64_t>(GLOB_GUEST_NOSPACE)));
            return;
        }

        host_glob.gl_offs = guest_glob.gl_offs;
        host_glob.gl_flags = guest_glob_flags_to_host(guest_glob.gl_flags);
        if ((guest_flags & GLOB_GUEST_ALTDIRFUNC) != 0) {
            host_glob.gl_closedir = host_glob_closedir_bridge;
            host_glob.gl_readdir = host_glob_readdir_bridge;
            host_glob.gl_opendir = host_glob_opendir_bridge;
            host_glob.gl_lstat = host_glob_lstat_bridge;
            host_glob.gl_stat = host_glob_stat_bridge;
        }

        GlobContext context{&emu, guest_glob, errfunc_addr, pattern};
        GlobContext* previous = g_current_glob_context;
        g_current_glob_context = &context;

        int host_result = ::glob(host_pattern.c_str(), host_flags,
                                 errfunc_addr != 0 ? host_glob_errfunc_bridge : nullptr,
                                 &host_glob);

        g_current_glob_context = previous;

        size_t match_count = (host_result == 0)
            ? compute_guest_glob_match_count(pattern, guest_flags, host_glob, previous_pathc)
            : 0;
        write_guest_glob_result(emu, glob_addr, guest_glob, host_glob, pattern, match_count,
                                errfunc_addr, pattern_has_magic);
        ::globfree(&host_glob);

        int guest_result = host_glob_result_to_guest(host_result);
        set_reg(emu, UC_ARM64_REG_X0,
                static_cast<uint64_t>(static_cast<int64_t>(guest_result)));
    };

    reg_locked("glob", [run_glob](Emulator& emu) {
        run_glob(emu);
    });

    reg_locked("glob64", [run_glob](Emulator& emu) {
        run_glob(emu);
    });

    auto run_globfree = [](Emulator& emu) {
        uint64_t glob_addr = get_reg(emu, UC_ARM64_REG_X0);
        if (glob_addr == 0) {
            return;
        }

        free_guest_glob_allocations(emu, glob_addr);

        glob_arm64 guest_glob{};
        if (emu.mem_read(glob_addr, &guest_glob, sizeof(guest_glob))) {
            guest_glob.gl_pathc = 0;
            guest_glob.gl_matchc = 0;
            guest_glob.gl_flags = 0;
            guest_glob.gl_pathv = 0;
            guest_glob.gl_errfunc = 0;
            emu.mem_write(glob_addr, &guest_glob, sizeof(guest_glob));
        }
    };

    reg_locked("globfree", [run_globfree](Emulator& emu) {
        run_globfree(emu);
    });

    reg_locked("globfree64", [run_globfree](Emulator& emu) {
        run_globfree(emu);
    });

    // ========================================================================
    // File tree walk
    // ========================================================================

    reg_locked("fts_open", [](Emulator& emu) {
        uint64_t pathv_addr = get_reg(emu, UC_ARM64_REG_X0);
        int guest_options = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t compar_addr = get_reg(emu, UC_ARM64_REG_X2);

        if (pathv_addr == 0) {
            hle_set_errno(emu, EINVAL);
            set_reg(emu, UC_ARM64_REG_X0, 0);
            return;
        }

        if (compar_addr != 0) {
            hle_set_errno(emu, ENOSYS);
            set_reg(emu, UC_ARM64_REG_X0, 0);
            return;
        }

        std::vector<std::string> guest_paths;
        guest_paths.reserve(4);
        for (size_t i = 0; i < 4096; ++i) {
            uint64_t guest_path_addr = 0;
            if (!emu.mem_read(pathv_addr + i * sizeof(uint64_t),
                              &guest_path_addr, sizeof(guest_path_addr))) {
                hle_set_errno(emu, EFAULT);
                set_reg(emu, UC_ARM64_REG_X0, 0);
                return;
            }
            if (guest_path_addr == 0) {
                break;
            }
            guest_paths.push_back(read_string(emu, guest_path_addr));
        }

        if (guest_paths.empty()) {
            hle_set_errno(emu, EINVAL);
            set_reg(emu, UC_ARM64_REG_X0, 0);
            return;
        }

        FtsSession session;
        std::vector<char*> host_pathv;
        host_pathv.reserve(guest_paths.size() + 1);

        for (const std::string& guest_path : guest_paths) {
            std::string translated_path = guest_path_to_host(guest_path);
            std::unique_ptr<char[]> host_path(new char[translated_path.size() + 1]);
            std::memcpy(host_path.get(), translated_path.c_str(), translated_path.size() + 1);
            host_pathv.push_back(host_path.get());
            session.roots.push_back(std::move(host_path));
        }
        host_pathv.push_back(nullptr);

        errno = 0;
        FTS* fts = ::fts_open(host_pathv.data(),
                              guest_fts_options_to_host(guest_options),
                              nullptr);
        if (fts == nullptr) {
            hle_set_errno(emu, errno);
            set_reg(emu, UC_ARM64_REG_X0, 0);
            return;
        }

        g_fts_sessions.emplace(fts, std::move(session));
        set_reg(emu, UC_ARM64_REG_X0,
                static_cast<uint64_t>(reinterpret_cast<uintptr_t>(fts)));
    });

    reg_locked("fts_read", [](Emulator& emu) {
        FTS* fts = reinterpret_cast<FTS*>(
            static_cast<uintptr_t>(get_reg(emu, UC_ARM64_REG_X0)));

        if (g_fts_sessions.find(fts) == g_fts_sessions.end()) {
            hle_set_errno(emu, EINVAL);
            set_reg(emu, UC_ARM64_REG_X0, 0);
            return;
        }

        errno = 0;
        FTSENT* entry = ::fts_read(fts);
        if (entry == nullptr && errno != 0) {
            hle_set_errno(emu, errno);
        }

        set_reg(emu, UC_ARM64_REG_X0,
                static_cast<uint64_t>(reinterpret_cast<uintptr_t>(entry)));
    });

    reg_locked("fts_set", [](Emulator& emu) {
        FTS* fts = reinterpret_cast<FTS*>(
            static_cast<uintptr_t>(get_reg(emu, UC_ARM64_REG_X0)));
        FTSENT* entry = reinterpret_cast<FTSENT*>(
            static_cast<uintptr_t>(get_reg(emu, UC_ARM64_REG_X1)));
        int guest_instruction = get_reg(emu, UC_ARM64_REG_X2);

        if (g_fts_sessions.find(fts) == g_fts_sessions.end()) {
            hle_set_errno(emu, EINVAL);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        int host_instruction = guest_fts_instruction_to_host(guest_instruction);
        if (host_instruction == -1) {
            hle_set_errno(emu, EINVAL);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        errno = 0;
        int result = ::fts_set(fts, entry, host_instruction);
        if (result != 0) {
            hle_set_errno(emu, errno);
        }

        set_reg(emu, UC_ARM64_REG_X0,
                static_cast<uint64_t>(static_cast<int64_t>(result)));
    });

    reg_locked("fts_close", [](Emulator& emu) {
        FTS* fts = reinterpret_cast<FTS*>(
            static_cast<uintptr_t>(get_reg(emu, UC_ARM64_REG_X0)));

        auto it = g_fts_sessions.find(fts);
        if (it == g_fts_sessions.end()) {
            hle_set_errno(emu, EINVAL);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        errno = 0;
        int result = ::fts_close(fts);
        int saved_errno = errno;
        g_fts_sessions.erase(it);

        if (result != 0) {
            hle_set_errno(emu, saved_errno);
        }

        set_reg(emu, UC_ARM64_REG_X0,
                static_cast<uint64_t>(static_cast<int64_t>(result)));
    });

    reg_locked("basename", [](Emulator& emu) {
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

    reg_locked("dirname", [](Emulator& emu) {
        uint64_t path_addr = get_reg(emu, UC_ARM64_REG_X0);
        std::string path = read_string(emu, path_addr);

        // Handle empty or null path
        if (path.empty()) {
            uint64_t ptr = emu.memory().heap().allocate(2, 8);
            emu.mem_write(ptr, ".", 2);
            set_reg(emu, UC_ARM64_REG_X0, ptr);
            return;
        }

        // Strip trailing slashes (POSIX requirement), but keep root "/"
        while (path.length() > 1 && path.back() == '/') {
            path.pop_back();
        }

        // Find last slash
        size_t pos = path.rfind('/');
        std::string dir;
        if (pos == std::string::npos) {
            // No slash - current directory
            dir = ".";
        } else if (pos == 0) {
            // Slash at start only - root directory
            dir = "/";
        } else {
            // Get directory part
            dir = path.substr(0, pos);
            // Strip trailing slashes from result too
            while (dir.length() > 1 && dir.back() == '/') {
                dir.pop_back();
            }
        }

        uint64_t ptr = emu.memory().heap().allocate(dir.length() + 1, 8);
        emu.mem_write(ptr, dir.c_str(), dir.length() + 1);
        set_reg(emu, UC_ARM64_REG_X0, ptr);
    });
}

} // namespace cross_shim
