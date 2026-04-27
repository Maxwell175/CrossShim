/**
 * HLE File Functions
 *
 * NOTE: With QEMU MTTCG (real parallel threads), all I/O operations use
 * direct blocking calls. Guest threads run on real host threads, so blocking
 * in the HLE handler blocks only that specific host thread.
 */

#include "debug_log.h"
#include "hle_manager.h"
#include "hle_path_translation.h"
#include "hle_sched_state.h"
#include "hle_stdio_state.h"
#include "cross_shim.h"
#include "memory_manager.h"
#include "bionic_types.h"
#include "emu_compat.h"
#include "thread_manager.h"
#include <algorithm>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/eventfd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <iostream>
#include <memory>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <sys/sysmacros.h>

namespace cross_shim {

using namespace bionic;

// File descriptor mapping for emulated files (shared with hle_io.cpp)
std::unordered_map<uint64_t, FILE*> g_file_map;
int g_next_fd = 100;
static std::unordered_set<uint64_t> g_popen_handles;
static std::unordered_map<uint64_t, pid_t> g_popen_pids;
static std::unordered_set<uint64_t> g_closed_builtin_streams;
static uint64_t g_next_popen_fd = 0x20000000;

struct FmemopenState {
    char* host_buf = nullptr;
    size_t size = 0;
    uint64_t guest_buf = 0;
    std::string mode;
    size_t current_size = 0;
    bool last_op_write = false;
    bool last_write_extended = false;
};

struct OpenMemstreamState {
    char* host_buf = nullptr;
    size_t host_size = 0;
    uint64_t guest_ptr_ptr = 0;
    uint64_t guest_size_ptr = 0;
    uint64_t guest_buf = 0;
    size_t guest_capacity = 0;
};

struct OpenWmemstreamState {
    char* host_buf = nullptr;
    size_t host_size = 0;
    uint64_t guest_ptr_ptr = 0;
    uint64_t guest_size_ptr = 0;
    uint64_t guest_buf = 0;
    size_t guest_capacity_chars = 0;
};

struct FunopenState {
    uint64_t cookie = 0;
    uint64_t read_fn = 0;
    uint64_t write_fn = 0;
    uint64_t seek_fn = 0;
    uint64_t close_fn = 0;
    bool is64 = false;
};

static std::unordered_map<uint64_t, FmemopenState> g_fmemopen_streams;
static std::unordered_map<uint64_t, std::unique_ptr<OpenMemstreamState>> g_open_memstreams;
static std::unordered_map<uint64_t, std::unique_ptr<OpenWmemstreamState>> g_open_wmemstreams;
static std::unordered_map<uint64_t, FunopenState> g_funopen_streams;

static constexpr uint64_t GUEST_FILE_SIZE = 0x98;
static constexpr uint64_t GUEST_FILE_FILENO_OFFSET = 0x70;

// get_reg and set_reg are provided by emu_compat.h

static std::string read_string(Emulator& emu, uint64_t addr) {
    std::string result;
    char c;
    while (emu.mem_read(addr++, &c, 1) && c != '\0') {
        result += c;
    }
    return result;
}

static std::string read_host_file(const char* path) {
    std::ifstream file(path, std::ios::in | std::ios::binary);
    if (!file) {
        return {};
    }
    return std::string(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
}

static std::string guest_path_to_host(const std::string& path) {
    return translate_guest_host_path(path);
}

static std::string host_path_to_guest_for_template(const std::string& original_guest_path,
                                                   const char* host_path) {
    return translate_host_path_for_guest(original_guest_path, host_path != nullptr ? host_path : "");
}

static void write_guest_template_result(Emulator& emu, uint64_t template_addr,
                                        const std::string& original_guest_path,
                                        const char* host_path) {
    std::string guest_result = host_path_to_guest_for_template(original_guest_path, host_path);
    const std::string& writeback =
        (guest_result.size() <= original_guest_path.size())
            ? guest_result
            : std::string(host_path != nullptr ? host_path : "");
    emu.mem_write(template_addr, writeback.c_str(), writeback.size() + 1);
}

static FILE* builtin_stream_for_fd(int fd) {
    switch (fd) {
        case STDIN_FILENO:
            return stdin;
        case STDOUT_FILENO:
            return stdout;
        case STDERR_FILENO:
            return stderr;
        default:
            return nullptr;
    }
}

static int builtin_fd_for_stream(Emulator& emu, uint64_t stream) {
    if (stream == 0) {
        return -1;
    }

    uint64_t sf_addr = emu.get_symbol("__sF");
    if (sf_addr != 0 &&
        stream >= sf_addr &&
        stream < sf_addr + (3 * GUEST_FILE_SIZE) &&
        ((stream - sf_addr) % GUEST_FILE_SIZE) == 0) {
        return static_cast<int>((stream - sf_addr) / GUEST_FILE_SIZE);
    }

    uint64_t stdin_addr = emu.get_symbol("stdin");
    uint64_t stdout_addr = emu.get_symbol("stdout");
    uint64_t stderr_addr = emu.get_symbol("stderr");
    if (stream == stdin_addr) return STDIN_FILENO;
    if (stream == stdout_addr) return STDOUT_FILENO;
    if (stream == stderr_addr) return STDERR_FILENO;

    int16_t guest_fd = -1;
    if (emu.mem_read(stream + GUEST_FILE_FILENO_OFFSET, &guest_fd, sizeof(guest_fd))) {
        if (guest_fd >= STDIN_FILENO && guest_fd <= STDERR_FILENO) {
            return guest_fd;
        }
    }

    return -1;
}

FILE* hle_resolve_guest_file(Emulator& emu, uint64_t stream) {
    if (stream == 0) {
        return nullptr;
    }

    auto it = g_file_map.find(stream);
    if (it != g_file_map.end()) {
        return it->second;
    }

    if (g_closed_builtin_streams.find(stream) != g_closed_builtin_streams.end()) {
        return nullptr;
    }

    int builtin_fd = builtin_fd_for_stream(emu, stream);
    return builtin_stream_for_fd(builtin_fd);
}

int hle_resolve_guest_fileno(Emulator& emu, uint64_t stream) {
    if (stream == 0) {
        return -1;
    }

    auto it = g_file_map.find(stream);
    if (it != g_file_map.end()) {
        return ::fileno(it->second);
    }

    if (g_closed_builtin_streams.find(stream) != g_closed_builtin_streams.end()) {
        return -1;
    }

    return builtin_fd_for_stream(emu, stream);
}

static void sync_fmemopen_stream(Emulator& emu, uint64_t stream) {
    auto it = g_fmemopen_streams.find(stream);
    if (it == g_fmemopen_streams.end()) {
        return;
    }

    FmemopenState& state = it->second;
    if (state.guest_buf == 0 || state.size == 0) {
        return;
    }

    emu.mem_write(state.guest_buf, state.host_buf, state.size);

    size_t nul_offset = static_cast<size_t>(-1);
    FILE* fp = hle_resolve_guest_file(emu, stream);
    off64_t current_pos = fp != nullptr ? ::ftello(fp) : static_cast<off64_t>(-1);
    bool is_update_mode = state.mode.find('+') != std::string::npos;
    bool is_write_only_mode = !state.mode.empty() && (state.mode[0] == 'w' || state.mode[0] == 'a') && !is_update_mode;

    if (is_write_only_mode) {
        size_t pos = current_pos >= 0 ? static_cast<size_t>(current_pos) : state.current_size;
        nul_offset = std::min(pos, state.size - 1);
    } else if (is_update_mode && state.last_op_write && state.last_write_extended) {
        size_t pos = current_pos >= 0 ? static_cast<size_t>(current_pos) : state.current_size;
        size_t end_pos = std::max(pos, state.current_size);
        nul_offset = std::min(end_pos, state.size - 1);
    }

    if (nul_offset != static_cast<size_t>(-1)) {
        char zero = '\0';
        emu.mem_write(state.guest_buf + nul_offset, &zero, 1);
    }
}

static size_t initial_fmemopen_size(const char* buffer, size_t size, const std::string& mode,
                                    bool has_guest_buffer) {
    if (mode.empty()) {
        return 0;
    }

    switch (mode[0]) {
        case 'r':
            return size;
        case 'w':
            return 0;
        case 'a':
            if (!has_guest_buffer || buffer == nullptr || size == 0) {
                return 0;
            }
            for (size_t i = 0; i < size; ++i) {
                if (buffer[i] == '\0') {
                    return i;
                }
            }
            return size;
        default:
            return 0;
    }
}

static void note_fmemopen_write(Emulator& emu, uint64_t stream) {
    auto it = g_fmemopen_streams.find(stream);
    if (it == g_fmemopen_streams.end()) {
        return;
    }

    FILE* fp = hle_resolve_guest_file(emu, stream);
    if (fp == nullptr) {
        return;
    }

    off64_t pos = ::ftello(fp);
    if (pos >= 0) {
        size_t end_pos = std::min(static_cast<size_t>(pos), it->second.size);
        it->second.last_write_extended = end_pos > it->second.current_size;
        if (end_pos > it->second.current_size) {
            it->second.current_size = end_pos;
        }
    } else {
        it->second.last_write_extended = false;
    }
    it->second.last_op_write = true;
}

static void note_fmemopen_nonwrite(uint64_t stream) {
    auto it = g_fmemopen_streams.find(stream);
    if (it == g_fmemopen_streams.end()) {
        return;
    }
    it->second.last_op_write = false;
    it->second.last_write_extended = false;
}

static bool fmemopen_write_only_limit(Emulator& emu, uint64_t stream, size_t requested_bytes,
                                      size_t& allowed_bytes) {
    auto it = g_fmemopen_streams.find(stream);
    if (it == g_fmemopen_streams.end()) {
        return false;
    }

    const FmemopenState& state = it->second;
    bool is_write_only_mode = !state.mode.empty() && state.mode[0] == 'w' &&
                              state.mode.find('+') == std::string::npos;
    if (!is_write_only_mode) {
        return false;
    }

    size_t data_limit = state.size > 0 ? state.size - 1 : 0;
    FILE* fp = hle_resolve_guest_file(emu, stream);
    off64_t pos = fp != nullptr ? ::ftello(fp) : static_cast<off64_t>(-1);
    size_t current_pos = pos >= 0 ? static_cast<size_t>(pos) : state.current_size;
    if (current_pos >= data_limit) {
        allowed_bytes = 0;
        return true;
    }

    allowed_bytes = std::min(requested_bytes, data_limit - current_pos);
    return true;
}

enum class Utf8DecodeStatus {
    Ok,
    Incomplete,
    Invalid,
};

static Utf8DecodeStatus decode_utf8_codepoint(const unsigned char* input, size_t available,
                                              uint32_t& codepoint, size_t& consumed) {
    if (available == 0) {
        return Utf8DecodeStatus::Incomplete;
    }

    const unsigned char b0 = input[0];
    if (b0 < 0x80) {
        codepoint = b0;
        consumed = 1;
        return Utf8DecodeStatus::Ok;
    }

    if (b0 >= 0xC2 && b0 <= 0xDF) {
        if (available < 2) {
            return Utf8DecodeStatus::Incomplete;
        }
        const unsigned char b1 = input[1];
        if ((b1 & 0xC0) != 0x80) {
            return Utf8DecodeStatus::Invalid;
        }
        codepoint = ((b0 & 0x1F) << 6) | (b1 & 0x3F);
        consumed = 2;
        return Utf8DecodeStatus::Ok;
    }

    if (b0 >= 0xE0 && b0 <= 0xEF) {
        if (available < 3) {
            return Utf8DecodeStatus::Incomplete;
        }
        const unsigned char b1 = input[1];
        const unsigned char b2 = input[2];
        if ((b1 & 0xC0) != 0x80 || (b2 & 0xC0) != 0x80) {
            return Utf8DecodeStatus::Invalid;
        }
        if ((b0 == 0xE0 && b1 < 0xA0) || (b0 == 0xED && b1 >= 0xA0)) {
            return Utf8DecodeStatus::Invalid;
        }
        codepoint = ((b0 & 0x0F) << 12) | ((b1 & 0x3F) << 6) | (b2 & 0x3F);
        consumed = 3;
        return Utf8DecodeStatus::Ok;
    }

    if (b0 >= 0xF0 && b0 <= 0xF4) {
        if (available < 4) {
            return Utf8DecodeStatus::Incomplete;
        }
        const unsigned char b1 = input[1];
        const unsigned char b2 = input[2];
        const unsigned char b3 = input[3];
        if ((b1 & 0xC0) != 0x80 || (b2 & 0xC0) != 0x80 || (b3 & 0xC0) != 0x80) {
            return Utf8DecodeStatus::Invalid;
        }
        if ((b0 == 0xF0 && b1 < 0x90) || (b0 == 0xF4 && b1 >= 0x90)) {
            return Utf8DecodeStatus::Invalid;
        }
        codepoint = ((b0 & 0x07) << 18) | ((b1 & 0x3F) << 12) |
                    ((b2 & 0x3F) << 6) | (b3 & 0x3F);
        consumed = 4;
        return Utf8DecodeStatus::Ok;
    }

    return Utf8DecodeStatus::Invalid;
}

static bool decode_utf8_string_to_guest_wchars(const char* input, size_t size,
                                               std::vector<uint32_t>& output) {
    output.clear();
    size_t offset = 0;
    while (offset < size) {
        uint32_t codepoint = 0;
        size_t consumed = 0;
        Utf8DecodeStatus status = decode_utf8_codepoint(
            reinterpret_cast<const unsigned char*>(input + offset), size - offset, codepoint, consumed);
        if (status != Utf8DecodeStatus::Ok || consumed == 0) {
            return false;
        }
        output.push_back(codepoint);
        offset += consumed;
    }
    return true;
}

static void sync_open_memstream(Emulator& emu, uint64_t stream) {
    auto it = g_open_memstreams.find(stream);
    if (it == g_open_memstreams.end()) {
        return;
    }

    OpenMemstreamState& state = *it->second;
    if (state.host_buf == nullptr) {
        if (state.guest_buf == 0) {
            state.guest_buf = emu.memory().heap().allocate(1, 8);
            state.guest_capacity = 1;
            if (state.guest_buf != 0) {
                char zero = '\0';
                emu.mem_write(state.guest_buf, &zero, 1);
            }
        }
    } else {
        size_t required = state.host_size + 1;
        if (state.guest_buf == 0 || state.guest_capacity < required) {
            state.guest_buf = emu.memory().heap().allocate(required, 8);
            state.guest_capacity = required;
        }
        if (state.guest_buf != 0) {
            emu.mem_write(state.guest_buf, state.host_buf, required);
        }
    }

    if (state.guest_ptr_ptr != 0) {
        emu.mem_write(state.guest_ptr_ptr, &state.guest_buf, sizeof(state.guest_buf));
    }
    if (state.guest_size_ptr != 0) {
        emu.mem_write(state.guest_size_ptr, &state.host_size, sizeof(state.host_size));
    }
}

static void sync_open_wmemstream(Emulator& emu, uint64_t stream) {
    auto it = g_open_wmemstreams.find(stream);
    if (it == g_open_wmemstreams.end()) {
        return;
    }

    OpenWmemstreamState& state = *it->second;
    std::vector<uint32_t> codepoints;

    if (state.host_buf != nullptr && state.host_size != 0) {
        if (!decode_utf8_string_to_guest_wchars(state.host_buf, state.host_size, codepoints)) {
            codepoints.clear();
            codepoints.reserve(state.host_size);
            for (size_t i = 0; i < state.host_size; ++i) {
                codepoints.push_back(static_cast<unsigned char>(state.host_buf[i]));
            }
        }
    }

    size_t required_chars = codepoints.size() + 1;
    size_t required_bytes = required_chars * sizeof(uint32_t);
    if (state.guest_buf == 0 || state.guest_capacity_chars < required_chars) {
        state.guest_buf = emu.memory().heap().allocate(required_bytes, 8);
        state.guest_capacity_chars = required_chars;
    }

    if (state.guest_buf != 0) {
        if (!codepoints.empty()) {
            emu.mem_write(state.guest_buf, codepoints.data(), codepoints.size() * sizeof(uint32_t));
        }
        uint32_t zero = 0;
        emu.mem_write(state.guest_buf + codepoints.size() * sizeof(uint32_t), &zero, sizeof(zero));
    }

    if (state.guest_ptr_ptr != 0) {
        emu.mem_write(state.guest_ptr_ptr, &state.guest_buf, sizeof(state.guest_buf));
    }
    if (state.guest_size_ptr != 0) {
        size_t guest_size = codepoints.size();
        emu.mem_write(state.guest_size_ptr, &guest_size, sizeof(guest_size));
    }
}

uint64_t hle_open_wmemstream(Emulator& emu, uint64_t ptr_ptr, uint64_t sizeloc_ptr, int& out_errno) {
    out_errno = 0;
    if (ptr_ptr == 0 || sizeloc_ptr == 0) {
        out_errno = EINVAL;
        return 0;
    }

    auto state = std::make_unique<OpenWmemstreamState>();
    state->guest_ptr_ptr = ptr_ptr;
    state->guest_size_ptr = sizeloc_ptr;
    FILE* fp = ::open_memstream(&state->host_buf, &state->host_size);
    if (fp == nullptr) {
        out_errno = errno;
        return 0;
    }

    uint64_t handle = g_next_fd++;
    g_file_map[handle] = fp;
    g_open_wmemstreams[handle] = std::move(state);

    uint64_t zero_ptr = 0;
    size_t zero_size = 0;
    emu.mem_write(ptr_ptr, &zero_ptr, sizeof(zero_ptr));
    emu.mem_write(sizeloc_ptr, &zero_size, sizeof(zero_size));
    return handle;
}

void hle_sync_stream_after_write(Emulator& emu, uint64_t stream) {
    note_fmemopen_write(emu, stream);
    sync_fmemopen_stream(emu, stream);
    sync_open_wmemstream(emu, stream);
}

void hle_sync_stream_after_flush(Emulator& emu, uint64_t stream) {
    sync_fmemopen_stream(emu, stream);
    sync_open_memstream(emu, stream);
    sync_open_wmemstream(emu, stream);
}

static int64_t call_funopen_seek(Emulator& emu, const FunopenState& state, int64_t offset,
                                 int whence, int& err) {
    if (state.seek_fn == 0) {
        err = ESPIPE;
        return -1;
    }

    uint64_t result = emu.call_function_safe(state.seek_fn, {
        state.cookie,
        static_cast<uint64_t>(offset),
        static_cast<uint64_t>(whence),
    });
    err = 0;
    return static_cast<int64_t>(result);
}

static FILE* create_guest_tmpfile(Emulator& emu) {
    const char* tmpdir = std::getenv("TMPDIR");
    if (tmpdir == nullptr || tmpdir[0] == '\0') {
        FILE* fp = ::tmpfile();
        if (fp == nullptr) {
            hle_set_errno(emu, errno);
        }
        return fp;
    }

    std::string templ = std::string(tmpdir) + "/cross_shim_tmpfileXXXXXX";
    std::vector<char> buffer(templ.begin(), templ.end());
    buffer.push_back('\0');

    int fd = ::mkstemp(buffer.data());
    if (fd == -1) {
        hle_set_errno(emu, errno);
        return nullptr;
    }

    ::unlink(buffer.data());
    FILE* fp = ::fdopen(fd, "w+");
    if (fp == nullptr) {
        int saved_errno = errno;
        ::close(fd);
        hle_set_errno(emu, saved_errno);
    }
    return fp;
}

static void replace_or_append_line(std::string& content, const std::string& prefix, const std::string& replacement) {
    size_t line_start = 0;
    while (line_start < content.size()) {
        size_t line_end = content.find('\n', line_start);
        if (line_end == std::string::npos) {
            line_end = content.size();
        }

        if (content.compare(line_start, prefix.size(), prefix) == 0) {
            content.replace(line_start, line_end - line_start, replacement);
            return;
        }

        if (line_end == content.size()) {
            break;
        }
        line_start = line_end + 1;
    }

    if (!content.empty() && content.back() != '\n') {
        content.push_back('\n');
    }
    content += replacement;
    content.push_back('\n');
}

static std::string synthesize_proc_self_status(Emulator& emu) {
    std::string content = read_host_file("/proc/self/status");
    if (content.empty()) {
        content = "Name:\tcross_shim\n";
    }

    size_t guest_threads = std::max<size_t>(1, emu.threads().get_thread_count());
    replace_or_append_line(content, "Threads:", "Threads:\t" + std::to_string(guest_threads));
    return content;
}

static bool parse_proc_tid_stat_path(const std::string& path, pid_t& tid) {
    static constexpr const char* kPrefix = "/proc/";
    static constexpr const char* kSuffix = "/stat";
    if (path.rfind(kPrefix, 0) != 0 || path.size() <= strlen(kPrefix) + strlen(kSuffix)) {
        return false;
    }
    if (path.compare(path.size() - strlen(kSuffix), strlen(kSuffix), kSuffix) != 0) {
        return false;
    }

    std::string tid_str = path.substr(strlen(kPrefix), path.size() - strlen(kPrefix) - strlen(kSuffix));
    if (tid_str.empty() || tid_str.find_first_not_of("0123456789") != std::string::npos) {
        return false;
    }

    tid = static_cast<pid_t>(std::strtol(tid_str.c_str(), nullptr, 10));
    return tid > 0;
}

static std::string synthesize_proc_tid_stat(const std::string& path, pid_t tid) {
    int priority = 0;
    if (!hle_sched_get_effective_priority(tid, priority)) {
        return {};
    }

    std::string content = read_host_file(path.c_str());
    if (content.empty()) {
        return {};
    }

    size_t comm_end = content.rfind(')');
    if (comm_end == std::string::npos || comm_end + 2 >= content.size()) {
        return {};
    }

    std::string prefix = content.substr(0, comm_end + 2);
    std::string remainder = content.substr(comm_end + 2);
    bool has_newline = !remainder.empty() && remainder.back() == '\n';
    if (has_newline) {
        remainder.pop_back();
    }

    std::vector<std::string> fields;
    size_t start = 0;
    while (start <= remainder.size()) {
        size_t end = remainder.find(' ', start);
        if (end == std::string::npos) {
            fields.push_back(remainder.substr(start));
            break;
        }
        fields.push_back(remainder.substr(start, end - start));
        start = end + 1;
    }

    // /proc/<tid>/stat field 18 is "priority". After stripping pid and comm, field 3
    // ("state") becomes index 0, so priority is index 15.
    if (fields.size() <= 15) {
        return {};
    }
    fields[15] = std::to_string(priority);

    std::string rebuilt = prefix;
    for (size_t i = 0; i < fields.size(); ++i) {
        if (i != 0) {
            rebuilt.push_back(' ');
        }
        rebuilt += fields[i];
    }
    if (has_newline) {
        rebuilt.push_back('\n');
    }
    return rebuilt;
}

static int create_read_pipe_from_string(const std::string& content) {
    int pipe_fds[2];
    if (::pipe(pipe_fds) != 0) {
        return -1;
    }

    size_t offset = 0;
    while (offset < content.size()) {
        ssize_t written = ::write(pipe_fds[1], content.data() + offset, content.size() - offset);
        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            ::close(pipe_fds[0]);
            ::close(pipe_fds[1]);
            return -1;
        }
        offset += static_cast<size_t>(written);
    }

    ::close(pipe_fds[1]);
    return pipe_fds[0];
}

static int translate_open_flags(int guest_flags) {
    constexpr int GUEST_O_ACCMODE = 00000003;
    constexpr int GUEST_O_CREAT = 00000100;
    constexpr int GUEST_O_EXCL = 00000200;
    constexpr int GUEST_O_NOCTTY = 00000400;
    constexpr int GUEST_O_TRUNC = 00001000;
    constexpr int GUEST_O_APPEND = 00002000;
    constexpr int GUEST_O_NONBLOCK = 00004000;
    constexpr int GUEST_O_DSYNC = 00010000;
    constexpr int GUEST_FASYNC = 00020000;
    constexpr int GUEST_O_DIRECTORY = 00040000;
    constexpr int GUEST_O_NOFOLLOW = 00100000;
    constexpr int GUEST_O_DIRECT = 00200000;
    constexpr int GUEST_O_LARGEFILE = 00400000;
    constexpr int GUEST_O_NOATIME = 01000000;
    constexpr int GUEST_O_CLOEXEC = 02000000;
    constexpr int GUEST___O_SYNC = 04000000;
    constexpr int GUEST_O_SYNC = GUEST___O_SYNC | GUEST_O_DSYNC;
    constexpr int GUEST_O_PATH = 010000000;
#ifdef O_TMPFILE
    constexpr int GUEST_O_TMPFILE = 020000000 | GUEST_O_DIRECTORY;
#endif

    int host_flags = guest_flags & GUEST_O_ACCMODE;

    if (guest_flags & GUEST_O_CREAT) host_flags |= O_CREAT;
    if (guest_flags & GUEST_O_EXCL) host_flags |= O_EXCL;
    if (guest_flags & GUEST_O_NOCTTY) host_flags |= O_NOCTTY;
    if (guest_flags & GUEST_O_TRUNC) host_flags |= O_TRUNC;
    if (guest_flags & GUEST_O_APPEND) host_flags |= O_APPEND;
    if (guest_flags & GUEST_O_NONBLOCK) host_flags |= O_NONBLOCK;
    if (guest_flags & GUEST_O_DSYNC) host_flags |= O_DSYNC;
#ifdef FASYNC
    if (guest_flags & GUEST_FASYNC) host_flags |= FASYNC;
#endif
#ifdef O_DIRECTORY
    if (guest_flags & GUEST_O_DIRECTORY) host_flags |= O_DIRECTORY;
#endif
#ifdef O_NOFOLLOW
    if (guest_flags & GUEST_O_NOFOLLOW) host_flags |= O_NOFOLLOW;
#endif
#ifdef O_DIRECT
    if (guest_flags & GUEST_O_DIRECT) host_flags |= O_DIRECT;
#endif
#ifdef O_LARGEFILE
    if (guest_flags & GUEST_O_LARGEFILE) host_flags |= O_LARGEFILE;
#endif
#ifdef O_NOATIME
    if (guest_flags & GUEST_O_NOATIME) host_flags |= O_NOATIME;
#endif
#ifdef O_CLOEXEC
    if (guest_flags & GUEST_O_CLOEXEC) host_flags |= O_CLOEXEC;
#endif
#ifdef O_SYNC
    if ((guest_flags & GUEST_O_SYNC) == GUEST_O_SYNC) host_flags |= O_SYNC;
#endif
#ifdef O_PATH
    if (guest_flags & GUEST_O_PATH) host_flags |= O_PATH;
#endif
#ifdef O_TMPFILE
    if ((guest_flags & GUEST_O_TMPFILE) == GUEST_O_TMPFILE) host_flags |= O_TMPFILE;
#endif

    return host_flags;
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

        if (path == "/proc/self/status") {
            int fd = create_read_pipe_from_string(synthesize_proc_self_status(emu));
            if (fd == -1) {
                hle_set_errno(emu, errno);
                set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
                return;
            }
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(fd));
            return;
        }

        pid_t proc_tid = 0;
        if (parse_proc_tid_stat_path(path, proc_tid)) {
            std::string content = synthesize_proc_tid_stat(path, proc_tid);
            if (!content.empty()) {
                int fd = create_read_pipe_from_string(content);
                if (fd == -1) {
                    hle_set_errno(emu, errno);
                    set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
                    return;
                }
                set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(fd));
                return;
            }
        }

        std::string host_path = translate_guest_host_path(path);
        int fd = ::open(host_path.c_str(), translate_open_flags(flags), mode);
        if (emu.is_debug()) {
            EMU_LOG << "[HLE] open: result fd=" << fd << std::endl;
        }
        if (fd == -1) {
            hle_set_errno(emu, errno);
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
        if (result == -1) {
            hle_set_errno(emu, errno);
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
        errno = 0;
        ssize_t result = ::read(fd, buf.data(), count);

        if (emu.is_debug()) {
            EMU_LOG << "[HLE] read: result=" << result << std::endl;
        }

        if (result > 0) {
            emu.mem_write(buf_addr, buf.data(), result);
        } else if (result < 0) {
            hle_set_errno(emu, errno);
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
        errno = 0;
        ssize_t result = ::write(fd, buf.data(), count);

        if (result < 0) {
            hle_set_errno(emu, errno);
        }
        if (emu.is_debug()) {
            EMU_LOG << "[HLE] write: result=" << result << std::endl;
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // eventfd
    hle.register_function("eventfd", [](Emulator& emu) {
        unsigned int initval = static_cast<unsigned int>(get_reg(emu, UC_ARM64_REG_X0));
        int flags = static_cast<int>(get_reg(emu, UC_ARM64_REG_X1));

        int fd = ::eventfd(initval, flags);
        if (fd == -1) {
            hle_set_errno(emu, errno);
        }
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(fd));
    });

    hle.register_function("eventfd_read", [](Emulator& emu) {
        int fd = static_cast<int>(get_reg(emu, UC_ARM64_REG_X0));
        uint64_t value_addr = get_reg(emu, UC_ARM64_REG_X1);

        eventfd_t value = 0;
        int result = ::eventfd_read(fd, &value);
        if (result == 0 && value_addr != 0) {
            emu.mem_write(value_addr, &value, sizeof(value));
        } else if (result == -1) {
            hle_set_errno(emu, errno);
        }
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(result));
    });

    hle.register_function("eventfd_write", [](Emulator& emu) {
        int fd = static_cast<int>(get_reg(emu, UC_ARM64_REG_X0));
        eventfd_t value = static_cast<eventfd_t>(get_reg(emu, UC_ARM64_REG_X1));

        int result = ::eventfd_write(fd, value);
        if (result == -1) {
            hle_set_errno(emu, errno);
        }
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(result));
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
        std::string host_path = guest_path_to_host(path);

        if (emu.is_debug()) {
            EMU_LOG << "[HLE] fopen: path=" << path << " mode=" << mode << std::endl;
        }

        FILE* fp = fopen(host_path.c_str(), mode.c_str());
        if (fp) {
            uint64_t fd = g_next_fd++;
            g_file_map[fd] = fp;
            if (emu.is_debug()) {
                EMU_LOG << "[HLE] fopen: success, fd=" << fd << std::endl;
            }
            set_reg(emu, UC_ARM64_REG_X0, fd);
        } else {
            if (emu.is_debug()) {
                EMU_LOG << "[HLE] fopen: failed, errno=" << errno << std::endl;
            }
            hle_set_errno(emu, errno);
            set_reg(emu, UC_ARM64_REG_X0, 0);
        }
    });
    
    // fclose
    hle.register_function("fclose", [](Emulator& emu) {
        uint64_t stream = get_reg(emu, UC_ARM64_REG_X0);
        auto it = g_file_map.find(stream);
        if (it != g_file_map.end()) {
            bool is_fmemopen = g_fmemopen_streams.find(stream) != g_fmemopen_streams.end();
            bool is_open_memstream = g_open_memstreams.find(stream) != g_open_memstreams.end();
            bool is_open_wmemstream = g_open_wmemstreams.find(stream) != g_open_wmemstreams.end();
            if (is_fmemopen || is_open_memstream || is_open_wmemstream) {
                ::fflush(it->second);
                hle_sync_stream_after_flush(emu, stream);
            }
            errno = 0;
            int result;
            auto pid_it = g_popen_pids.find(stream);
            if (pid_it != g_popen_pids.end()) {
                pid_t pid = pid_it->second;
                g_popen_pids.erase(pid_it);
                g_popen_handles.erase(stream);
                result = ::fclose(it->second);
                int status = 0;
                while (::waitpid(pid, &status, 0) == -1 && errno == EINTR) {
                }
                if (result != EOF) {
                    result = 0;
                }
            } else {
                result = g_popen_handles.erase(stream) != 0 ? ::pclose(it->second) : ::fclose(it->second);
            }

            if (is_open_memstream) {
                sync_open_memstream(emu, stream);
            }
            if (is_open_wmemstream) {
                sync_open_wmemstream(emu, stream);
            }

            auto fmem_it = g_fmemopen_streams.find(stream);
            if (fmem_it != g_fmemopen_streams.end()) {
                std::free(fmem_it->second.host_buf);
                g_fmemopen_streams.erase(fmem_it);
            }
            auto memstream_it = g_open_memstreams.find(stream);
            if (memstream_it != g_open_memstreams.end()) {
                if (memstream_it->second->host_buf != nullptr) {
                    std::free(memstream_it->second->host_buf);
                }
                g_open_memstreams.erase(memstream_it);
            }
            auto wmemstream_it = g_open_wmemstreams.find(stream);
            if (wmemstream_it != g_open_wmemstreams.end()) {
                if (wmemstream_it->second->host_buf != nullptr) {
                    std::free(wmemstream_it->second->host_buf);
                }
                g_open_wmemstreams.erase(wmemstream_it);
            }
            g_file_map.erase(it);
            if (result == EOF) {
                hle_set_errno(emu, errno);
            }
            set_reg(emu, UC_ARM64_REG_X0, result);
        } else {
            auto funopen_it = g_funopen_streams.find(stream);
            if (funopen_it != g_funopen_streams.end()) {
                int result = 0;
                if (funopen_it->second.close_fn != 0) {
                    result = static_cast<int>(emu.call_function_safe(funopen_it->second.close_fn,
                        {funopen_it->second.cookie}));
                }
                g_funopen_streams.erase(funopen_it);
                if (result == -1) {
                    hle_set_errno(emu, errno != 0 ? errno : EBADF);
                }
                set_reg(emu, UC_ARM64_REG_X0, result);
                return;
            }
            FILE* builtin_fp = hle_resolve_guest_file(emu, stream);
            if (builtin_fp != nullptr && builtin_fd_for_stream(emu, stream) != -1) {
                errno = 0;
                int result = ::fclose(builtin_fp);
                if (result == 0) {
                    g_closed_builtin_streams.insert(stream);
                } else {
                    hle_set_errno(emu, errno);
                }
                set_reg(emu, UC_ARM64_REG_X0, result);
            } else {
                hle_set_errno(emu, EBADF);
                set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(EOF));
            }
        }
    });
    
    // fread
    hle.register_function("fread", [](Emulator& emu) {
        uint64_t buf_addr = get_reg(emu, UC_ARM64_REG_X0);
        size_t size = get_reg(emu, UC_ARM64_REG_X1);
        size_t count = get_reg(emu, UC_ARM64_REG_X2);
        uint64_t stream = get_reg(emu, UC_ARM64_REG_X3);

        FILE* fp = hle_resolve_guest_file(emu, stream);
        if (fp != nullptr) {
            if (std::feof(fp)) {
                ::clearerr(fp);
            }
            errno = 0;
            off_t before = ::ftello(fp);
            errno = 0;
            size_t result = 0;
            void* host_ptr = emu.memory().get_host_ptr(buf_addr);
            if (host_ptr != nullptr) {
                result = ::fread(host_ptr, size, count, fp);
            } else {
                size_t bytes_requested = size * count;
                std::vector<char> buf(bytes_requested);
                result = ::fread(buf.data(), size, count, fp);
                size_t bytes_read = result * size;
                off_t after = ::ftello(fp);
                if (before != static_cast<off_t>(-1) &&
                    after != static_cast<off_t>(-1) &&
                    after >= before) {
                    bytes_read = static_cast<size_t>(after - before);
                }
                if (bytes_read > 0) {
                    emu.mem_write(buf_addr, buf.data(), bytes_read);
                }
                if (result < count && std::ferror(fp)) {
                    hle_set_errno(emu, errno);
                }
                set_reg(emu, UC_ARM64_REG_X0, result);
                return;
            }
            size_t bytes_read = result * size;
            off_t after = ::ftello(fp);
            if (before != static_cast<off_t>(-1) &&
                after != static_cast<off_t>(-1) &&
                after >= before) {
                bytes_read = static_cast<size_t>(after - before);
            }
            note_fmemopen_nonwrite(stream);
            if (result < count && std::ferror(fp)) {
                hle_set_errno(emu, errno);
            }
            set_reg(emu, UC_ARM64_REG_X0, result);
        } else {
            hle_set_errno(emu, EBADF);
            set_reg(emu, UC_ARM64_REG_X0, 0);
        }
    });

    // fgets
    hle.register_function("fgets", [](Emulator& emu) {
        uint64_t buf_addr = get_reg(emu, UC_ARM64_REG_X0);
        int size = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t stream = get_reg(emu, UC_ARM64_REG_X2);

        FILE* fp = hle_resolve_guest_file(emu, stream);
        if (fp != nullptr) {
            std::vector<char> buf(size);
            errno = 0;
            char* result = ::fgets(buf.data(), size, fp);
            if (result) {
                emu.mem_write(buf_addr, buf.data(), strlen(buf.data()) + 1);
                set_reg(emu, UC_ARM64_REG_X0, buf_addr);
            } else {
                if (std::ferror(fp)) {
                    hle_set_errno(emu, errno);
                }
                set_reg(emu, UC_ARM64_REG_X0, 0);
            }
        } else {
            hle_set_errno(emu, EBADF);
            set_reg(emu, UC_ARM64_REG_X0, 0);
        }
    });

    // setbuf
    hle.register_function("setbuf", [](Emulator& emu) {
        uint64_t stream = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t guest_buf = get_reg(emu, UC_ARM64_REG_X1);

        FILE* fp = hle_resolve_guest_file(emu, stream);
        if (fp == nullptr) {
            return;
        }

        if (guest_buf == 0) {
            ::setbuf(fp, nullptr);
        }
    });

    // setvbuf
    hle.register_function("setvbuf", [](Emulator& emu) {
        uint64_t stream = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t guest_buf = get_reg(emu, UC_ARM64_REG_X1);
        int mode = get_reg(emu, UC_ARM64_REG_X2);
        size_t size = get_reg(emu, UC_ARM64_REG_X3);

        FILE* fp = hle_resolve_guest_file(emu, stream);
        if (fp == nullptr) {
            hle_set_errno(emu, EBADF);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        errno = 0;
        int result = ::setvbuf(fp, nullptr, mode, size);
        if (result != 0) {
            hle_set_errno(emu, errno != 0 ? errno : EINVAL);
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // remove
    hle.register_function("remove", [](Emulator& emu) {
        uint64_t path_addr = get_reg(emu, UC_ARM64_REG_X0);
        std::string path = read_string(emu, path_addr);
        std::string host_path = guest_path_to_host(path);
        errno = 0;
        int result = ::remove(host_path.c_str());
        if (result == -1) {
            hle_set_errno(emu, errno);
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // fwrite
    hle.register_function("fwrite", [](Emulator& emu) {
        uint64_t buf_addr = get_reg(emu, UC_ARM64_REG_X0);
        size_t size = get_reg(emu, UC_ARM64_REG_X1);
        size_t count = get_reg(emu, UC_ARM64_REG_X2);
        uint64_t stream = get_reg(emu, UC_ARM64_REG_X3);

        FILE* fp = hle_resolve_guest_file(emu, stream);
        if (fp != nullptr) {
            if (size == 0 || count == 0) {
                set_reg(emu, UC_ARM64_REG_X0, 0);
                return;
            }

            size_t allowed_bytes = size * count;
            if (fmemopen_write_only_limit(emu, stream, size * count, allowed_bytes)) {
                count = allowed_bytes / size;
                if (count == 0) {
                    set_reg(emu, UC_ARM64_REG_X0, 0);
                    return;
                }
            }

            errno = 0;
            size_t result = 0;
            void* host_ptr = emu.memory().get_host_ptr(buf_addr);
            if (host_ptr != nullptr) {
                result = ::fwrite(host_ptr, size, count, fp);
            } else {
                size_t bytes = size * count;
                std::vector<char> buf(bytes);
                emu.mem_read(buf_addr, buf.data(), bytes);
                result = ::fwrite(buf.data(), size, count, fp);
            }
            if (result < count && std::ferror(fp)) {
                hle_set_errno(emu, errno);
            }
            if (result > 0) {
                hle_sync_stream_after_write(emu, stream);
            }
            set_reg(emu, UC_ARM64_REG_X0, result);
        } else {
            hle_set_errno(emu, EBADF);
            set_reg(emu, UC_ARM64_REG_X0, 0);
        }
    });
    
    // fseek
    hle.register_function("fseek", [](Emulator& emu) {
        uint64_t stream = get_reg(emu, UC_ARM64_REG_X0);
        long offset = get_reg(emu, UC_ARM64_REG_X1);
        int whence = get_reg(emu, UC_ARM64_REG_X2);

        auto funopen_it = g_funopen_streams.find(stream);
        if (funopen_it != g_funopen_streams.end()) {
            int err = 0;
            int64_t seek_result = call_funopen_seek(emu, funopen_it->second, offset, whence, err);
            if (seek_result == -1) {
                hle_set_errno(emu, err);
                set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            } else {
                set_reg(emu, UC_ARM64_REG_X0, 0);
            }
            return;
        }

        FILE* fp = hle_resolve_guest_file(emu, stream);
        if (fp != nullptr) {
            errno = 0;
            int result = ::fseek(fp, offset, whence);
            if (result == -1) {
                hle_set_errno(emu, errno);
            } else {
                note_fmemopen_nonwrite(stream);
            }
            set_reg(emu, UC_ARM64_REG_X0, result);
        } else {
            hle_set_errno(emu, EBADF);
            set_reg(emu, UC_ARM64_REG_X0, -1);
        }
    });
    
    // ftell
    hle.register_function("ftell", [](Emulator& emu) {
        uint64_t stream = get_reg(emu, UC_ARM64_REG_X0);

        auto funopen_it = g_funopen_streams.find(stream);
        if (funopen_it != g_funopen_streams.end()) {
            int err = 0;
            int64_t result = call_funopen_seek(emu, funopen_it->second, 0, SEEK_CUR, err);
            if (result == -1) {
                hle_set_errno(emu, err);
            }
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(result));
            return;
        }

        FILE* fp = hle_resolve_guest_file(emu, stream);
        if (fp != nullptr) {
            errno = 0;
            long result = ::ftell(fp);
            if (result == -1L) {
                hle_set_errno(emu, errno);
            }
            set_reg(emu, UC_ARM64_REG_X0, result);
        } else {
            hle_set_errno(emu, EBADF);
            set_reg(emu, UC_ARM64_REG_X0, -1);
        }
    });
    
    // fflush
    hle.register_function("fflush", [](Emulator& emu) {
        uint64_t stream = get_reg(emu, UC_ARM64_REG_X0);

        if (stream == 0) {
            // NULL - flush all streams
            errno = 0;
            int result = ::fflush(nullptr);
            if (result == EOF) {
                hle_set_errno(emu, errno);
            } else {
                for (const auto& entry : g_fmemopen_streams) {
                    sync_fmemopen_stream(emu, entry.first);
                }
                for (const auto& entry : g_open_memstreams) {
                    sync_open_memstream(emu, entry.first);
                }
            }
            set_reg(emu, UC_ARM64_REG_X0, result);
        } else {
            FILE* fp = hle_resolve_guest_file(emu, stream);
            if (fp != nullptr) {
                errno = 0;
                int result = ::fflush(fp);
                if (result == EOF) {
                    hle_set_errno(emu, errno);
                } else {
                    hle_sync_stream_after_flush(emu, stream);
                }
                set_reg(emu, UC_ARM64_REG_X0, result);
            } else {
                hle_set_errno(emu, EBADF);
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
        std::string host_path = guest_path_to_host(path);
        int result = ::stat(host_path.c_str(), &st);
        if (emu.is_debug()) {
            EMU_LOG << "[HLE] stat: result=" << result << std::endl;
        }

        if (result == 0 && buf_addr) {
            // Convert host stat to ARM64 bionic format
            stat_arm64 st_arm;
            host_to_arm64_stat(st, st_arm);
            emu.mem_write(buf_addr, &st_arm, sizeof(st_arm));
        } else if (result == -1) {
            hle_set_errno(emu, errno);
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
        } else if (result == -1) {
            hle_set_errno(emu, errno);
        }

        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // lstat - get file status (doesn't follow symlinks)
    hle.register_function("lstat", [](Emulator& emu) {
        uint64_t path_addr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t buf_addr = get_reg(emu, UC_ARM64_REG_X1);

        std::string path = read_string(emu, path_addr);
        struct stat st;
        std::string host_path = guest_path_to_host(path);
        int result = ::lstat(host_path.c_str(), &st);

        if (result == 0 && buf_addr) {
            // Convert host stat to ARM64 bionic format
            stat_arm64 st_arm;
            host_to_arm64_stat(st, st_arm);
            emu.mem_write(buf_addr, &st_arm, sizeof(st_arm));
        } else if (result == -1) {
            hle_set_errno(emu, errno);
        }

        set_reg(emu, UC_ARM64_REG_X0, result);
    });
    
    // fcntl
    hle.register_function("fcntl", [](Emulator& emu) {
        int fd = get_reg(emu, UC_ARM64_REG_X0);
        int cmd = get_reg(emu, UC_ARM64_REG_X1);
        int arg = get_reg(emu, UC_ARM64_REG_X2);
        errno = 0;
        int result = fcntl(fd, cmd, arg);
        if (result == -1) {
            hle_set_errno(emu, errno);
        } else if (cmd == F_GETFL) {
            constexpr int GUEST_O_LARGEFILE = 00400000;
            result |= GUEST_O_LARGEFILE;
        }
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
        constexpr unsigned long ARM64_SIOCGIFDSTADDR = 0x8917;
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
                } else {
                    hle_set_errno(emu, errno);
                }
                set_reg(emu, UC_ARM64_REG_X0, result);
                return;
            }

            case ARM64_SIOCGIFFLAGS:
            case ARM64_SIOCGIFADDR:
            case ARM64_SIOCGIFDSTADDR:
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
                    case ARM64_SIOCGIFDSTADDR: host_request = SIOCGIFDSTADDR; break;
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
                } else {
                    hle_set_errno(emu, errno);
                }
                set_reg(emu, UC_ARM64_REG_X0, result);
                return;
            }

            default:
                hle_set_errno(emu, ENOTTY);
                set_reg(emu, UC_ARM64_REG_X0, -1);
                return;
        }
    });
    
    // fdopen
    hle.register_function("fdopen", [](Emulator& emu) {
        int fd = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t mode_addr = get_reg(emu, UC_ARM64_REG_X1);
        std::string mode = read_string(emu, mode_addr);

        off_t initial_offset = -1;
        if (mode.find('a') != std::string::npos) {
            initial_offset = ::lseek(fd, 0, SEEK_CUR);
        }

        FILE* fp = fdopen(fd, mode.c_str());
        if (fp) {
            if (mode.find('e') != std::string::npos) {
                int flags = ::fcntl(fd, F_GETFD);
                if (flags != -1) {
                    ::fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
                }
            }
            if (initial_offset != static_cast<off_t>(-1)) {
                ::fseeko(fp, initial_offset, SEEK_SET);
            }
            uint64_t new_fd = g_next_fd++;
            g_file_map[new_fd] = fp;
            set_reg(emu, UC_ARM64_REG_X0, new_fd);
        } else {
            hle_set_errno(emu, errno);
            set_reg(emu, UC_ARM64_REG_X0, 0);
        }
    });
    
    // access
    hle.register_function("access", [](Emulator& emu) {
        uint64_t path_addr = get_reg(emu, UC_ARM64_REG_X0);
        int mode = get_reg(emu, UC_ARM64_REG_X1);
        
        std::string path = read_string(emu, path_addr);
        std::string host_path = guest_path_to_host(path);
        int result = ::access(host_path.c_str(), mode);
        if (result == -1) {
            hle_set_errno(emu, errno);
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });
    
    // unlink
    hle.register_function("unlink", [](Emulator& emu) {
        uint64_t path_addr = get_reg(emu, UC_ARM64_REG_X0);
        std::string path = read_string(emu, path_addr);
        std::string host_path = guest_path_to_host(path);
        int result = ::unlink(host_path.c_str());
        set_reg(emu, UC_ARM64_REG_X0, result);
    });
    
    // rename
    hle.register_function("rename", [](Emulator& emu) {
        uint64_t old_path_addr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t new_path_addr = get_reg(emu, UC_ARM64_REG_X1);
        
        std::string old_path = read_string(emu, old_path_addr);
        std::string new_path = read_string(emu, new_path_addr);
        std::string old_host_path = guest_path_to_host(old_path);
        std::string new_host_path = guest_path_to_host(new_path);
        
        int result = ::rename(old_host_path.c_str(), new_host_path.c_str());
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("renameat", [](Emulator& emu) {
        int old_dirfd = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t old_path_addr = get_reg(emu, UC_ARM64_REG_X1);
        int new_dirfd = get_reg(emu, UC_ARM64_REG_X2);
        uint64_t new_path_addr = get_reg(emu, UC_ARM64_REG_X3);

        std::string old_path = read_string(emu, old_path_addr);
        std::string new_path = read_string(emu, new_path_addr);
        std::string old_host_path = guest_path_to_host(old_path);
        std::string new_host_path = guest_path_to_host(new_path);

        errno = 0;
        int result = ::renameat(old_dirfd, old_host_path.c_str(), new_dirfd, new_host_path.c_str());
        if (result == -1) {
            hle_set_errno(emu, errno);
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("renameat2", [](Emulator& emu) {
        int old_dirfd = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t old_path_addr = get_reg(emu, UC_ARM64_REG_X1);
        int new_dirfd = get_reg(emu, UC_ARM64_REG_X2);
        uint64_t new_path_addr = get_reg(emu, UC_ARM64_REG_X3);
        unsigned int flags = get_reg(emu, UC_ARM64_REG_X4);

        std::string old_path = read_string(emu, old_path_addr);
        std::string new_path = read_string(emu, new_path_addr);
        std::string old_host_path = guest_path_to_host(old_path);
        std::string new_host_path = guest_path_to_host(new_path);

        errno = 0;
        int result = static_cast<int>(::syscall(SYS_renameat2, old_dirfd, old_host_path.c_str(),
                                                new_dirfd, new_host_path.c_str(), flags));
        if (result == -1) {
            hle_set_errno(emu, errno);
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });
    
    // mkdir
    hle.register_function("mkdir", [](Emulator& emu) {
        uint64_t path_addr = get_reg(emu, UC_ARM64_REG_X0);
        int mode = get_reg(emu, UC_ARM64_REG_X1);
        
        std::string path = read_string(emu, path_addr);
        std::string host_path = guest_path_to_host(path);
        int result = ::mkdir(host_path.c_str(), mode);
        set_reg(emu, UC_ARM64_REG_X0, result);
    });
    
    // rmdir
    hle.register_function("rmdir", [](Emulator& emu) {
        uint64_t path_addr = get_reg(emu, UC_ARM64_REG_X0);
        std::string path = read_string(emu, path_addr);
        std::string host_path = guest_path_to_host(path);
        int result = ::rmdir(host_path.c_str());
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
        errno = 0;
        int result = ::dup2(oldfd, newfd);
        if (result < 0) {
            hle_set_errno(emu, errno);
        }
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
        uint64_t stream = get_reg(emu, UC_ARM64_REG_X0);
        int result = hle_resolve_guest_fileno(emu, stream);
        if (result != -1) {
            set_reg(emu, UC_ARM64_REG_X0, result);
        } else {
            hle_set_errno(emu, EBADF);
            set_reg(emu, UC_ARM64_REG_X0, -1);
        }
    });
    
    // feof
    hle.register_function("feof", [](Emulator& emu) {
        uint64_t stream = get_reg(emu, UC_ARM64_REG_X0);
        FILE* fp = hle_resolve_guest_file(emu, stream);
        if (fp != nullptr) {
            int result = ::feof(fp);
            set_reg(emu, UC_ARM64_REG_X0, result);
        } else {
            hle_set_errno(emu, EBADF);
            set_reg(emu, UC_ARM64_REG_X0, 1);
        }
    });
    
    // ferror
    hle.register_function("ferror", [](Emulator& emu) {
        uint64_t stream = get_reg(emu, UC_ARM64_REG_X0);
        FILE* fp = hle_resolve_guest_file(emu, stream);
        if (fp != nullptr) {
            int result = ::ferror(fp);
            set_reg(emu, UC_ARM64_REG_X0, result);
        } else {
            hle_set_errno(emu, EBADF);
            set_reg(emu, UC_ARM64_REG_X0, 1);
        }
    });
    
    // clearerr
    hle.register_function("clearerr", [](Emulator& emu) {
        uint64_t stream = get_reg(emu, UC_ARM64_REG_X0);
        FILE* fp = hle_resolve_guest_file(emu, stream);
        if (fp != nullptr) {
            ::clearerr(fp);
        }
    });

    // rewind
    hle.register_function("rewind", [](Emulator& emu) {
        uint64_t stream = get_reg(emu, UC_ARM64_REG_X0);
        FILE* fp = hle_resolve_guest_file(emu, stream);
        if (fp != nullptr) {
            ::rewind(fp);
            note_fmemopen_nonwrite(stream);
        }
    });

    // fgetc
    hle.register_function("fgetc", [](Emulator& emu) {
        uint64_t stream = get_reg(emu, UC_ARM64_REG_X0);
        FILE* fp = hle_resolve_guest_file(emu, stream);
        if (fp != nullptr) {
            int c = ::fgetc(fp);
            note_fmemopen_nonwrite(stream);
            set_reg(emu, UC_ARM64_REG_X0, c);
        } else {
            hle_set_errno(emu, EBADF);
            set_reg(emu, UC_ARM64_REG_X0, (uint64_t)-1);  // EOF
        }
    });

    // getc (same as fgetc)
    hle.register_function("getc", [](Emulator& emu) {
        uint64_t stream = get_reg(emu, UC_ARM64_REG_X0);
        FILE* fp = hle_resolve_guest_file(emu, stream);
        if (fp != nullptr) {
            int c = ::getc(fp);
            note_fmemopen_nonwrite(stream);
            set_reg(emu, UC_ARM64_REG_X0, c);
        } else {
            hle_set_errno(emu, EBADF);
            set_reg(emu, UC_ARM64_REG_X0, (uint64_t)-1);  // EOF
        }
    });

    // ungetc
    hle.register_function("ungetc", [](Emulator& emu) {
        int c = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t stream = get_reg(emu, UC_ARM64_REG_X1);
        FILE* fp = hle_resolve_guest_file(emu, stream);
        if (fp != nullptr) {
            int result = ::ungetc(c, fp);
            note_fmemopen_nonwrite(stream);
            set_reg(emu, UC_ARM64_REG_X0, result);
        } else {
            hle_set_errno(emu, EBADF);
            set_reg(emu, UC_ARM64_REG_X0, (uint64_t)-1);  // EOF
        }
    });

    // fputc
    hle.register_function("fputc", [](Emulator& emu) {
        int c = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t stream = get_reg(emu, UC_ARM64_REG_X1);
        FILE* fp = hle_resolve_guest_file(emu, stream);
        if (fp != nullptr) {
            size_t allowed_bytes = 1;
            if (fmemopen_write_only_limit(emu, stream, 1, allowed_bytes) && allowed_bytes == 0) {
                set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(EOF));
                return;
            }
            errno = 0;
            int result = ::fputc(c, fp);
            if (result == EOF) {
                hle_set_errno(emu, errno);
            } else {
                hle_sync_stream_after_write(emu, stream);
            }
            set_reg(emu, UC_ARM64_REG_X0, result);
        } else {
            hle_set_errno(emu, EBADF);
            set_reg(emu, UC_ARM64_REG_X0, (uint64_t)-1);  // EOF
        }
    });

    // putc (same as fputc)
    hle.register_function("putc", [](Emulator& emu) {
        int c = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t stream = get_reg(emu, UC_ARM64_REG_X1);
        FILE* fp = hle_resolve_guest_file(emu, stream);
        if (fp != nullptr) {
            errno = 0;
            int result = ::putc(c, fp);
            if (result == EOF) {
                hle_set_errno(emu, errno);
            } else {
                hle_sync_stream_after_write(emu, stream);
            }
            set_reg(emu, UC_ARM64_REG_X0, result);
        } else {
            hle_set_errno(emu, EBADF);
            set_reg(emu, UC_ARM64_REG_X0, (uint64_t)-1);  // EOF
        }
    });

    // fputs (for files, not just stdout)
    hle.register_function("fputs", [](Emulator& emu) {
        uint64_t s_addr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t stream = get_reg(emu, UC_ARM64_REG_X1);
        std::string str = read_string(emu, s_addr);

        FILE* fp = hle_resolve_guest_file(emu, stream);
        if (fp != nullptr) {
            errno = 0;
            int result = ::fputs(str.c_str(), fp);
            if (result == EOF) {
                hle_set_errno(emu, errno);
            } else {
                hle_sync_stream_after_write(emu, stream);
            }
            set_reg(emu, UC_ARM64_REG_X0, result);
        } else {
            hle_set_errno(emu, EBADF);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(EOF));
        }
    });

    // ========================================================================
    // Large file support (64-bit offsets)
    // ========================================================================

    // open64 - same as open on 64-bit systems
    hle.register_function("open64", [](Emulator& emu) {
        uint64_t path_addr = get_reg(emu, UC_ARM64_REG_X0);
        int flags = get_reg(emu, UC_ARM64_REG_X1);
        int mode = get_reg(emu, UC_ARM64_REG_X2);

        std::string path = read_string(emu, path_addr);

        if (emu.is_debug()) {
            EMU_LOG << "[HLE] open64(\"" << path << "\", flags=0x" << std::hex << flags << ", mode=0" << std::oct << mode << std::dec << ")" << std::endl;
        }

        std::string host_path = translate_guest_host_path(path);
        int fd = ::open(host_path.c_str(), translate_open_flags(flags), mode);
        if (fd == -1) {
            hle_set_errno(emu, errno);
        }
        set_reg(emu, UC_ARM64_REG_X0, fd);
    });

    // fseeko - 64-bit offset fseek
    hle.register_function("fseeko", [](Emulator& emu) {
        uint64_t stream = get_reg(emu, UC_ARM64_REG_X0);
        int64_t offset = get_reg(emu, UC_ARM64_REG_X1);
        int whence = get_reg(emu, UC_ARM64_REG_X2);

        auto funopen_it = g_funopen_streams.find(stream);
        if (funopen_it != g_funopen_streams.end()) {
            int err = 0;
            int64_t seek_result = call_funopen_seek(emu, funopen_it->second, offset, whence, err);
            if (seek_result == -1) {
                hle_set_errno(emu, err);
                set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            } else {
                set_reg(emu, UC_ARM64_REG_X0, 0);
            }
            return;
        }

        FILE* fp = hle_resolve_guest_file(emu, stream);
        if (fp != nullptr) {
            errno = 0;
            int result = ::fseeko(fp, offset, whence);
            if (result == -1) {
                hle_set_errno(emu, errno);
            }
            set_reg(emu, UC_ARM64_REG_X0, result);
        } else {
            hle_set_errno(emu, EBADF);
            set_reg(emu, UC_ARM64_REG_X0, -1);
        }
    });

    // fseeko64 - same as fseeko on 64-bit systems
    hle.register_function("fseeko64", [](Emulator& emu) {
        uint64_t stream = get_reg(emu, UC_ARM64_REG_X0);
        int64_t offset = get_reg(emu, UC_ARM64_REG_X1);
        int whence = get_reg(emu, UC_ARM64_REG_X2);

        auto funopen_it = g_funopen_streams.find(stream);
        if (funopen_it != g_funopen_streams.end()) {
            int err = 0;
            int64_t seek_result = call_funopen_seek(emu, funopen_it->second, offset, whence, err);
            if (seek_result == -1) {
                hle_set_errno(emu, err);
                set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            } else {
                set_reg(emu, UC_ARM64_REG_X0, 0);
            }
            return;
        }

        FILE* fp = hle_resolve_guest_file(emu, stream);
        if (fp != nullptr) {
            errno = 0;
            int result = ::fseeko(fp, offset, whence);
            if (result == -1) {
                hle_set_errno(emu, errno);
            }
            set_reg(emu, UC_ARM64_REG_X0, result);
        } else {
            hle_set_errno(emu, EBADF);
            set_reg(emu, UC_ARM64_REG_X0, -1);
        }
    });

    // ftello - 64-bit offset ftell
    hle.register_function("ftello", [](Emulator& emu) {
        uint64_t stream = get_reg(emu, UC_ARM64_REG_X0);

        auto funopen_it = g_funopen_streams.find(stream);
        if (funopen_it != g_funopen_streams.end()) {
            int err = 0;
            int64_t result = call_funopen_seek(emu, funopen_it->second, 0, SEEK_CUR, err);
            if (result == -1) {
                hle_set_errno(emu, err);
            }
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(result));
            return;
        }

        FILE* fp = hle_resolve_guest_file(emu, stream);
        if (fp != nullptr) {
            errno = 0;
            off_t result = ::ftello(fp);
            if (result == static_cast<off_t>(-1)) {
                hle_set_errno(emu, errno);
            }
            set_reg(emu, UC_ARM64_REG_X0, result);
        } else {
            hle_set_errno(emu, EBADF);
            set_reg(emu, UC_ARM64_REG_X0, -1);
        }
    });

    // ftello64 - same as ftello on 64-bit systems
    hle.register_function("ftello64", [](Emulator& emu) {
        uint64_t stream = get_reg(emu, UC_ARM64_REG_X0);

        auto funopen_it = g_funopen_streams.find(stream);
        if (funopen_it != g_funopen_streams.end()) {
            int err = 0;
            int64_t result = call_funopen_seek(emu, funopen_it->second, 0, SEEK_CUR, err);
            if (result == -1) {
                hle_set_errno(emu, err);
            }
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(result));
            return;
        }

        FILE* fp = hle_resolve_guest_file(emu, stream);
        if (fp != nullptr) {
            errno = 0;
            off_t result = ::ftello(fp);
            if (result == static_cast<off_t>(-1)) {
                hle_set_errno(emu, errno);
            }
            set_reg(emu, UC_ARM64_REG_X0, result);
        } else {
            hle_set_errno(emu, EBADF);
            set_reg(emu, UC_ARM64_REG_X0, -1);
        }
    });

    // lseek64 - 64-bit lseek
    hle.register_function("lseek64", [](Emulator& emu) {
        int fd = get_reg(emu, UC_ARM64_REG_X0);
        int64_t offset = get_reg(emu, UC_ARM64_REG_X1);
        int whence = get_reg(emu, UC_ARM64_REG_X2);

        off_t result = ::lseek(fd, offset, whence);
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // tmpfile - create a temporary file
    hle.register_function("tmpfile", [](Emulator& emu) {
        FILE* fp = create_guest_tmpfile(emu);
        if (fp) {
            uint64_t fd = g_next_fd++;
            g_file_map[fd] = fp;
            if (emu.is_debug()) {
                EMU_LOG << "[HLE] tmpfile: success, fd=" << fd << std::endl;
            }
            set_reg(emu, UC_ARM64_REG_X0, fd);
        } else {
            if (emu.is_debug()) {
                EMU_LOG << "[HLE] tmpfile: failed, errno=" << errno << std::endl;
            }
            set_reg(emu, UC_ARM64_REG_X0, 0);
        }
    });

    // tmpfile64 - same as tmpfile on 64-bit systems
    hle.register_function("tmpfile64", [](Emulator& emu) {
        FILE* fp = create_guest_tmpfile(emu);
        if (fp) {
            uint64_t fd = g_next_fd++;
            g_file_map[fd] = fp;
            set_reg(emu, UC_ARM64_REG_X0, fd);
        } else {
            set_reg(emu, UC_ARM64_REG_X0, 0);
        }
    });

    // mkstemp - create a unique temporary file
    hle.register_function("mkstemp", [](Emulator& emu) {
        uint64_t template_addr = get_reg(emu, UC_ARM64_REG_X0);

        // Read the template
        std::string templ = read_string(emu, template_addr);
        std::string host_templ = guest_path_to_host(templ);
        std::vector<char> buf(host_templ.begin(), host_templ.end());
        buf.push_back('\0');

        int fd = ::mkstemp(buf.data());

        if (fd >= 0) {
            write_guest_template_result(emu, template_addr, templ, buf.data());
        }

        if (emu.is_debug()) {
            EMU_LOG << "[HLE] mkstemp: template=" << templ << " result=" << fd << std::endl;
        }

        set_reg(emu, UC_ARM64_REG_X0, fd);
    });

    // mkstemp64 - same as mkstemp on 64-bit systems
    hle.register_function("mkstemp64", [](Emulator& emu) {
        uint64_t template_addr = get_reg(emu, UC_ARM64_REG_X0);

        std::string templ = read_string(emu, template_addr);
        std::string host_templ = guest_path_to_host(templ);
        std::vector<char> buf(host_templ.begin(), host_templ.end());
        buf.push_back('\0');

        int fd = ::mkostemp(buf.data(), O_LARGEFILE);

        if (fd >= 0) {
            write_guest_template_result(emu, template_addr, templ, buf.data());
        }

        set_reg(emu, UC_ARM64_REG_X0, fd);
    });

    // mkostemp - mkstemp with flags
    hle.register_function("mkostemp", [](Emulator& emu) {
        uint64_t template_addr = get_reg(emu, UC_ARM64_REG_X0);
        int flags = get_reg(emu, UC_ARM64_REG_X1);

        std::string templ = read_string(emu, template_addr);
        std::string host_templ = guest_path_to_host(templ);
        std::vector<char> buf(host_templ.begin(), host_templ.end());
        buf.push_back('\0');

        int fd = ::mkostemp(buf.data(), flags);

        if (fd >= 0) {
            write_guest_template_result(emu, template_addr, templ, buf.data());
        }

        set_reg(emu, UC_ARM64_REG_X0, fd);
    });

    // mkostemp64 - same as mkostemp on 64-bit systems
    hle.register_function("mkostemp64", [](Emulator& emu) {
        uint64_t template_addr = get_reg(emu, UC_ARM64_REG_X0);
        int flags = get_reg(emu, UC_ARM64_REG_X1);

        std::string templ = read_string(emu, template_addr);
        std::string host_templ = guest_path_to_host(templ);
        std::vector<char> buf(host_templ.begin(), host_templ.end());
        buf.push_back('\0');

        int fd = ::mkostemp(buf.data(), flags | O_LARGEFILE);

        if (fd >= 0) {
            write_guest_template_result(emu, template_addr, templ, buf.data());
        }

        set_reg(emu, UC_ARM64_REG_X0, fd);
    });

    // mkdtemp - create a unique temporary directory
    hle.register_function("mkdtemp", [](Emulator& emu) {
        uint64_t template_addr = get_reg(emu, UC_ARM64_REG_X0);

        std::string templ = read_string(emu, template_addr);
        std::string host_templ = guest_path_to_host(templ);
        std::vector<char> buf(host_templ.begin(), host_templ.end());
        buf.push_back('\0');

        char* result = ::mkdtemp(buf.data());

        if (result) {
            write_guest_template_result(emu, template_addr, templ, buf.data());
            set_reg(emu, UC_ARM64_REG_X0, template_addr);
        } else {
            set_reg(emu, UC_ARM64_REG_X0, 0);
        }
    });

    // fdatasync - synchronize file data to disk
    hle.register_function("fdatasync", [](Emulator& emu) {
        int fd = get_reg(emu, UC_ARM64_REG_X0);
        errno = 0;
        int result = ::fdatasync(fd);
        if (result == -1) {
            hle_set_errno(emu, errno);
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // fsync - synchronize file data and metadata to disk
    hle.register_function("fsync", [](Emulator& emu) {
        int fd = get_reg(emu, UC_ARM64_REG_X0);
        errno = 0;
        int result = ::fsync(fd);
        if (result == -1) {
            hle_set_errno(emu, errno);
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // ftruncate - truncate a file to a specified length
    hle.register_function("ftruncate", [](Emulator& emu) {
        int fd = get_reg(emu, UC_ARM64_REG_X0);
        off_t length = get_reg(emu, UC_ARM64_REG_X1);
        errno = 0;
        int result = ::ftruncate(fd, length);
        if (result < 0) {
            hle_set_errno(emu, errno);
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // ftruncate64 - same as ftruncate on 64-bit systems
    hle.register_function("ftruncate64", [](Emulator& emu) {
        int fd = get_reg(emu, UC_ARM64_REG_X0);
        off_t length = get_reg(emu, UC_ARM64_REG_X1);
        errno = 0;
        int result = ::ftruncate(fd, length);
        if (result < 0) {
            hle_set_errno(emu, errno);
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // truncate - truncate a file to a specified length (by path)
    hle.register_function("truncate", [](Emulator& emu) {
        uint64_t path_addr = get_reg(emu, UC_ARM64_REG_X0);
        off_t length = get_reg(emu, UC_ARM64_REG_X1);
        std::string path = read_string(emu, path_addr);
        errno = 0;
        int result = ::truncate(path.c_str(), length);
        if (result < 0) {
            hle_set_errno(emu, errno);
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // truncate64 - same as truncate on 64-bit systems
    hle.register_function("truncate64", [](Emulator& emu) {
        uint64_t path_addr = get_reg(emu, UC_ARM64_REG_X0);
        off_t length = get_reg(emu, UC_ARM64_REG_X1);
        std::string path = read_string(emu, path_addr);
        errno = 0;
        int result = ::truncate(path.c_str(), length);
        if (result < 0) {
            hle_set_errno(emu, errno);
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // pread - read from file at offset
    hle.register_function("pread", [](Emulator& emu) {
        int fd = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t buf_addr = get_reg(emu, UC_ARM64_REG_X1);
        size_t count = get_reg(emu, UC_ARM64_REG_X2);
        off_t offset = get_reg(emu, UC_ARM64_REG_X3);

        std::vector<char> buf(count);
        ssize_t result = ::pread(fd, buf.data(), count, offset);

        if (result > 0) {
            emu.mem_write(buf_addr, buf.data(), result);
        }

        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // pread64 - same as pread on 64-bit systems
    hle.register_function("pread64", [](Emulator& emu) {
        int fd = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t buf_addr = get_reg(emu, UC_ARM64_REG_X1);
        size_t count = get_reg(emu, UC_ARM64_REG_X2);
        off_t offset = get_reg(emu, UC_ARM64_REG_X3);

        std::vector<char> buf(count);
        ssize_t result = ::pread(fd, buf.data(), count, offset);

        if (result > 0) {
            emu.mem_write(buf_addr, buf.data(), result);
        }

        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // pwrite - write to file at offset
    hle.register_function("pwrite", [](Emulator& emu) {
        int fd = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t buf_addr = get_reg(emu, UC_ARM64_REG_X1);
        size_t count = get_reg(emu, UC_ARM64_REG_X2);
        off_t offset = get_reg(emu, UC_ARM64_REG_X3);

        std::vector<char> buf(count);
        emu.mem_read(buf_addr, buf.data(), count);

        ssize_t result = ::pwrite(fd, buf.data(), count, offset);
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // pwrite64 - same as pwrite on 64-bit systems
    hle.register_function("pwrite64", [](Emulator& emu) {
        int fd = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t buf_addr = get_reg(emu, UC_ARM64_REG_X1);
        size_t count = get_reg(emu, UC_ARM64_REG_X2);
        off_t offset = get_reg(emu, UC_ARM64_REG_X3);

        std::vector<char> buf(count);
        emu.mem_read(buf_addr, buf.data(), count);

        ssize_t result = ::pwrite(fd, buf.data(), count, offset);
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // stat64 - same as stat on 64-bit systems
    hle.register_function("stat64", [](Emulator& emu) {
        uint64_t path_addr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t buf_addr = get_reg(emu, UC_ARM64_REG_X1);

        std::string path = read_string(emu, path_addr);
        std::string host_path = guest_path_to_host(path);
        struct stat st;
        int result = ::stat(host_path.c_str(), &st);

        if (result == 0 && buf_addr) {
            stat_arm64 st_arm;
            host_to_arm64_stat(st, st_arm);
            emu.mem_write(buf_addr, &st_arm, sizeof(st_arm));
        } else if (result == -1) {
            hle_set_errno(emu, errno);
        }

        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // fstat64 - same as fstat on 64-bit systems
    hle.register_function("fstat64", [](Emulator& emu) {
        int fd = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t buf_addr = get_reg(emu, UC_ARM64_REG_X1);

        struct stat st;
        int result = ::fstat(fd, &st);

        if (result == 0 && buf_addr) {
            stat_arm64 st_arm;
            host_to_arm64_stat(st, st_arm);
            emu.mem_write(buf_addr, &st_arm, sizeof(st_arm));
        } else if (result == -1) {
            hle_set_errno(emu, errno);
        }

        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // lstat64 - same as lstat on 64-bit systems
    hle.register_function("lstat64", [](Emulator& emu) {
        uint64_t path_addr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t buf_addr = get_reg(emu, UC_ARM64_REG_X1);

        std::string path = read_string(emu, path_addr);
        std::string host_path = guest_path_to_host(path);
        struct stat st;
        int result = ::lstat(host_path.c_str(), &st);

        if (result == 0 && buf_addr) {
            stat_arm64 st_arm;
            host_to_arm64_stat(st, st_arm);
            emu.mem_write(buf_addr, &st_arm, sizeof(st_arm));
        } else if (result == -1) {
            hle_set_errno(emu, errno);
        }

        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // ========================================================================
    // openat and creat variants
    // ========================================================================

    // openat - open file relative to directory fd
    hle.register_function("openat", [](Emulator& emu) {
        int dirfd = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t path_addr = get_reg(emu, UC_ARM64_REG_X1);
        int flags = get_reg(emu, UC_ARM64_REG_X2);
        mode_t mode = get_reg(emu, UC_ARM64_REG_X3);

        std::string path = read_string(emu, path_addr);

        int result = ::openat(dirfd, path.c_str(), translate_open_flags(flags), mode);
        if (result == -1) {
            hle_set_errno(emu, errno);
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // openat64 - same as openat on 64-bit systems
    hle.register_function("openat64", [](Emulator& emu) {
        int dirfd = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t path_addr = get_reg(emu, UC_ARM64_REG_X1);
        int flags = get_reg(emu, UC_ARM64_REG_X2);
        mode_t mode = get_reg(emu, UC_ARM64_REG_X3);

        std::string path = read_string(emu, path_addr);

        int result = ::openat(dirfd, path.c_str(), translate_open_flags(flags), mode);
        if (result == -1) {
            hle_set_errno(emu, errno);
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // creat - create a file
    hle.register_function("creat", [](Emulator& emu) {
        uint64_t path_addr = get_reg(emu, UC_ARM64_REG_X0);
        mode_t mode = get_reg(emu, UC_ARM64_REG_X1);

        std::string path = read_string(emu, path_addr);

        int result = ::creat(path.c_str(), mode);
        if (result == -1) {
            hle_set_errno(emu, errno);
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // creat64 - same as creat on 64-bit systems
    hle.register_function("creat64", [](Emulator& emu) {
        uint64_t path_addr = get_reg(emu, UC_ARM64_REG_X0);
        mode_t mode = get_reg(emu, UC_ARM64_REG_X1);

        std::string path = read_string(emu, path_addr);

        int result = ::creat(path.c_str(), mode);
        if (result == -1) {
            hle_set_errno(emu, errno);
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // ========================================================================
    // File allocation functions
    // ========================================================================

    // posix_fadvise - provide advice on file access patterns
    hle.register_function("posix_fadvise", [](Emulator& emu) {
        int fd = get_reg(emu, UC_ARM64_REG_X0);
        off_t offset = get_reg(emu, UC_ARM64_REG_X1);
        off_t len = get_reg(emu, UC_ARM64_REG_X2);
        int advice = get_reg(emu, UC_ARM64_REG_X3);

        int result = ::posix_fadvise(fd, offset, len, advice);
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // posix_fadvise64 - same as posix_fadvise on 64-bit systems
    hle.register_function("posix_fadvise64", [](Emulator& emu) {
        int fd = get_reg(emu, UC_ARM64_REG_X0);
        off_t offset = get_reg(emu, UC_ARM64_REG_X1);
        off_t len = get_reg(emu, UC_ARM64_REG_X2);
        int advice = get_reg(emu, UC_ARM64_REG_X3);

        int result = ::posix_fadvise(fd, offset, len, advice);
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // fallocate - manipulate file space
    hle.register_function("fallocate", [](Emulator& emu) {
        int fd = get_reg(emu, UC_ARM64_REG_X0);
        int mode = get_reg(emu, UC_ARM64_REG_X1);
        off_t offset = get_reg(emu, UC_ARM64_REG_X2);
        off_t len = get_reg(emu, UC_ARM64_REG_X3);

        int result = ::fallocate(fd, mode, offset, len);
        if (result == -1) {
            hle_set_errno(emu, errno);
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // fallocate64 - same as fallocate on 64-bit systems
    hle.register_function("fallocate64", [](Emulator& emu) {
        int fd = get_reg(emu, UC_ARM64_REG_X0);
        int mode = get_reg(emu, UC_ARM64_REG_X1);
        off_t offset = get_reg(emu, UC_ARM64_REG_X2);
        off_t len = get_reg(emu, UC_ARM64_REG_X3);

        int result = ::fallocate(fd, mode, offset, len);
        if (result == -1) {
            hle_set_errno(emu, errno);
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // posix_fallocate - allocate file space
    hle.register_function("posix_fallocate", [](Emulator& emu) {
        int fd = get_reg(emu, UC_ARM64_REG_X0);
        off_t offset = get_reg(emu, UC_ARM64_REG_X1);
        off_t len = get_reg(emu, UC_ARM64_REG_X2);

        int result = ::posix_fallocate(fd, offset, len);
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // posix_fallocate64 - same as posix_fallocate on 64-bit systems
    hle.register_function("posix_fallocate64", [](Emulator& emu) {
        int fd = get_reg(emu, UC_ARM64_REG_X0);
        off_t offset = get_reg(emu, UC_ARM64_REG_X1);
        off_t len = get_reg(emu, UC_ARM64_REG_X2);

        int result = ::posix_fallocate(fd, offset, len);
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // fstatat - stat relative to directory fd
    hle.register_function("fstatat", [](Emulator& emu) {
        int dirfd = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t path_addr = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t buf_addr = get_reg(emu, UC_ARM64_REG_X2);
        int flags = get_reg(emu, UC_ARM64_REG_X3);

        std::string path = read_string(emu, path_addr);
        std::string host_path = guest_path_to_host(path);
        struct stat st;
        int result = ::fstatat(dirfd, host_path.c_str(), &st, flags);

        if (result == 0 && buf_addr) {
            stat_arm64 st_arm;
            host_to_arm64_stat(st, st_arm);
            emu.mem_write(buf_addr, &st_arm, sizeof(st_arm));
        }

        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // fstatat64 - same as fstatat on 64-bit systems
    hle.register_function("fstatat64", [](Emulator& emu) {
        int dirfd = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t path_addr = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t buf_addr = get_reg(emu, UC_ARM64_REG_X2);
        int flags = get_reg(emu, UC_ARM64_REG_X3);

        std::string path = read_string(emu, path_addr);
        std::string host_path = guest_path_to_host(path);
        struct stat st;
        int result = ::fstatat(dirfd, host_path.c_str(), &st, flags);

        if (result == 0 && buf_addr) {
            stat_arm64 st_arm;
            host_to_arm64_stat(st, st_arm);
            emu.mem_write(buf_addr, &st_arm, sizeof(st_arm));
        }

        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // ========================================================================
    // statx - extended stat function
    // ========================================================================

    // statx ARM64 bionic structure
    struct statx_arm64 {
        uint32_t stx_mask;
        uint32_t stx_blksize;
        uint64_t stx_attributes;
        uint32_t stx_nlink;
        uint32_t stx_uid;
        uint32_t stx_gid;
        uint16_t stx_mode;
        uint16_t __spare0[1];
        uint64_t stx_ino;
        uint64_t stx_size;
        uint64_t stx_blocks;
        uint64_t stx_attributes_mask;
        struct {
            int64_t tv_sec;
            uint32_t tv_nsec;
            int32_t __reserved;
        } stx_atime, stx_btime, stx_ctime, stx_mtime;
        uint32_t stx_rdev_major;
        uint32_t stx_rdev_minor;
        uint32_t stx_dev_major;
        uint32_t stx_dev_minor;
        uint64_t stx_mnt_id;
        uint64_t __spare2;
        uint64_t __spare3[12];
    };

    hle.register_function("statx", [](Emulator& emu) {
        int dirfd = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t path_addr = get_reg(emu, UC_ARM64_REG_X1);
        int flags = get_reg(emu, UC_ARM64_REG_X2);
        unsigned int mask = get_reg(emu, UC_ARM64_REG_X3);
        uint64_t buf_addr = get_reg(emu, UC_ARM64_REG_X4);

        if (!path_addr || !buf_addr) {
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-EINVAL));
            return;
        }

        std::string path = read_string(emu, path_addr);
        std::string host_path = guest_path_to_host(path);

        // Fall back to fstatat since statx may not be available
        struct stat st;
        int result = ::fstatat(dirfd, host_path.c_str(), &st, flags & ~0x1000); // Remove AT_STATX_*

        if (result == 0) {
            statx_arm64 stx = {};
            stx.stx_mask = mask;
            stx.stx_blksize = st.st_blksize;
            stx.stx_nlink = st.st_nlink;
            stx.stx_uid = st.st_uid;
            stx.stx_gid = st.st_gid;
            stx.stx_mode = st.st_mode;
            stx.stx_ino = st.st_ino;
            stx.stx_size = st.st_size;
            stx.stx_blocks = st.st_blocks;
            stx.stx_atime.tv_sec = st.st_atim.tv_sec;
            stx.stx_atime.tv_nsec = st.st_atim.tv_nsec;
            stx.stx_mtime.tv_sec = st.st_mtim.tv_sec;
            stx.stx_mtime.tv_nsec = st.st_mtim.tv_nsec;
            stx.stx_ctime.tv_sec = st.st_ctim.tv_sec;
            stx.stx_ctime.tv_nsec = st.st_ctim.tv_nsec;
            stx.stx_rdev_major = major(st.st_rdev);
            stx.stx_rdev_minor = minor(st.st_rdev);
            stx.stx_dev_major = major(st.st_dev);
            stx.stx_dev_minor = minor(st.st_dev);

            emu.mem_write(buf_addr, &stx, sizeof(stx));
        }

        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // ========================================================================
    // popen/pclose - process I/O
    // ========================================================================

    hle.register_function("popen", [](Emulator& emu) {
        uint64_t command_addr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t type_addr = get_reg(emu, UC_ARM64_REG_X1);

        if (!command_addr || !type_addr) {
            set_reg(emu, UC_ARM64_REG_X0, 0);
            return;
        }

        std::string command = read_string(emu, command_addr);
        std::string type = read_string(emu, type_addr);

        bool bidirectional = type.find('+') != std::string::npos;
        bool cloexec = type.find('e') != std::string::npos;
        FILE* fp = nullptr;
        pid_t child_pid = -1;

        if (!bidirectional) {
            fp = ::popen(command.c_str(), type.c_str());
            if (fp == nullptr) {
                hle_set_errno(emu, errno);
                set_reg(emu, UC_ARM64_REG_X0, 0);
                return;
            }
        } else {
            int sv[2];
            if (::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
                hle_set_errno(emu, errno);
                set_reg(emu, UC_ARM64_REG_X0, 0);
                return;
            }

            child_pid = ::fork();
            if (child_pid == -1) {
                int saved_errno = errno;
                ::close(sv[0]);
                ::close(sv[1]);
                hle_set_errno(emu, saved_errno);
                set_reg(emu, UC_ARM64_REG_X0, 0);
                return;
            }

            if (child_pid == 0) {
                ::close(sv[0]);
                ::dup2(sv[1], STDIN_FILENO);
                ::dup2(sv[1], STDOUT_FILENO);
                if (sv[1] > STDERR_FILENO) {
                    ::close(sv[1]);
                }
                ::execl("/bin/sh", "sh", "-c", command.c_str(), static_cast<char*>(nullptr));
                ::_exit(127);
            }

            ::close(sv[1]);
            if (cloexec) {
                int flags = ::fcntl(sv[0], F_GETFD);
                if (flags != -1) {
                    ::fcntl(sv[0], F_SETFD, flags | FD_CLOEXEC);
                }
            }
            fp = ::fdopen(sv[0], "r+");
            if (fp == nullptr) {
                int saved_errno = errno;
                ::close(sv[0]);
                int status = 0;
                while (::waitpid(child_pid, &status, 0) == -1 && errno == EINTR) {
                }
                hle_set_errno(emu, saved_errno);
                set_reg(emu, UC_ARM64_REG_X0, 0);
                return;
            }
        }

        uint64_t fd = g_next_popen_fd++;
        g_file_map[fd] = fp;
        g_popen_handles.insert(fd);
        if (child_pid != -1) {
            g_popen_pids[fd] = child_pid;
        }
        if (cloexec) {
            int host_fd = ::fileno(fp);
            int flags = ::fcntl(host_fd, F_GETFD);
            if (flags != -1) {
                ::fcntl(host_fd, F_SETFD, flags | FD_CLOEXEC);
            }
        }
        set_reg(emu, UC_ARM64_REG_X0, fd);
    });

    hle.register_function("pclose", [](Emulator& emu) {
        uint64_t fp = get_reg(emu, UC_ARM64_REG_X0);

        auto it = g_file_map.find(fp);
        if (it != g_file_map.end() && g_popen_handles.erase(fp) != 0) {
            int result = 0;
            auto pid_it = g_popen_pids.find(fp);
            if (pid_it != g_popen_pids.end()) {
                pid_t pid = pid_it->second;
                g_popen_pids.erase(pid_it);
                int close_result = ::fclose(it->second);
                int status = 0;
                while (::waitpid(pid, &status, 0) == -1 && errno == EINTR) {
                }
                if (close_result == EOF) {
                    result = -1;
                } else {
                    result = status;
                }
            } else {
                result = ::pclose(it->second);
            }
            g_file_map.erase(it);
            if (result == -1) {
                hle_set_errno(emu, errno);
            }
            set_reg(emu, UC_ARM64_REG_X0, result);
        } else {
            hle_set_errno(emu, EBADF);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
        }
    });

    // ========================================================================
    // fgetpos/fsetpos - file position functions
    // ========================================================================

    hle.register_function("fgetpos", [](Emulator& emu) {
        uint64_t stream = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t pos_ptr = get_reg(emu, UC_ARM64_REG_X1);

        if (!pos_ptr) {
            hle_set_errno(emu, EINVAL);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        auto funopen_it = g_funopen_streams.find(stream);
        if (funopen_it != g_funopen_streams.end()) {
            int err = 0;
            int64_t pos = call_funopen_seek(emu, funopen_it->second, 0, SEEK_CUR, err);
            if (pos == -1) {
                hle_set_errno(emu, err);
                set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            } else {
                emu.mem_write(pos_ptr, &pos, sizeof(pos));
                set_reg(emu, UC_ARM64_REG_X0, 0);
            }
            return;
        }

        FILE* fp = hle_resolve_guest_file(emu, stream);
        if (fp == nullptr) {
            hle_set_errno(emu, EBADF);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        errno = 0;
        off64_t pos = ::ftello(fp);
        if (pos == static_cast<off64_t>(-1)) {
            hle_set_errno(emu, errno);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
        } else {
            emu.mem_write(pos_ptr, &pos, sizeof(pos));
            set_reg(emu, UC_ARM64_REG_X0, 0);
        }
    });

    hle.register_function("fsetpos", [](Emulator& emu) {
        uint64_t stream = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t pos_ptr = get_reg(emu, UC_ARM64_REG_X1);

        if (!pos_ptr) {
            hle_set_errno(emu, EINVAL);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        int64_t pos = 0;
        emu.mem_read(pos_ptr, &pos, sizeof(pos));

        auto funopen_it = g_funopen_streams.find(stream);
        if (funopen_it != g_funopen_streams.end()) {
            int err = 0;
            int64_t result = call_funopen_seek(emu, funopen_it->second, pos, SEEK_SET, err);
            if (result == -1) {
                hle_set_errno(emu, err);
                set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            } else {
                set_reg(emu, UC_ARM64_REG_X0, 0);
            }
            return;
        }

        FILE* fp = hle_resolve_guest_file(emu, stream);
        if (fp == nullptr) {
            hle_set_errno(emu, EBADF);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        errno = 0;
        int result = ::fseeko(fp, pos, SEEK_SET);
        if (result == -1) {
            hle_set_errno(emu, errno);
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // ========================================================================
    // fmemopen - open memory as stream
    // ========================================================================

    hle.register_function("fmemopen", [](Emulator& emu) {
        uint64_t buf_ptr = get_reg(emu, UC_ARM64_REG_X0);
        size_t size = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t mode_addr = get_reg(emu, UC_ARM64_REG_X2);

        if (!mode_addr) {
            set_reg(emu, UC_ARM64_REG_X0, 0);
            return;
        }

        std::string mode = read_string(emu, mode_addr);

        size_t alloc_size = std::max<size_t>(size, 1);
        char* host_buf = static_cast<char*>(std::malloc(alloc_size));
        if (host_buf == nullptr) {
            hle_set_errno(emu, ENOMEM);
            set_reg(emu, UC_ARM64_REG_X0, 0);
            return;
        }
        if (size != 0) {
            std::memset(host_buf, 0, size);
        }
        if (buf_ptr != 0 && size != 0) {
            std::vector<char> temp(size);
            emu.mem_read(buf_ptr, temp.data(), size);
            std::memcpy(host_buf, temp.data(), size);
        }

        FILE* fp = ::fmemopen(host_buf, size, mode.c_str());
        if (fp) {
            uint64_t fd = g_next_fd++;
            g_file_map[fd] = fp;
            g_fmemopen_streams[fd] = {
                host_buf,
                size,
                buf_ptr,
                mode,
                initial_fmemopen_size(host_buf, size, mode, buf_ptr != 0),
                false,
                false,
            };
            set_reg(emu, UC_ARM64_REG_X0, fd);
        } else {
            std::free(host_buf);
            hle_set_errno(emu, errno);
            set_reg(emu, UC_ARM64_REG_X0, 0);
        }
    });

    // ========================================================================
    // Splice functions
    // ========================================================================

    hle.register_function("splice", [](Emulator& emu) {
        int fd_in = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t off_in_ptr = get_reg(emu, UC_ARM64_REG_X1);
        int fd_out = get_reg(emu, UC_ARM64_REG_X2);
        uint64_t off_out_ptr = get_reg(emu, UC_ARM64_REG_X3);
        size_t len = get_reg(emu, UC_ARM64_REG_X4);
        unsigned int flags = get_reg(emu, UC_ARM64_REG_X5);

        loff_t off_in = 0, off_out = 0;
        if (off_in_ptr) emu.mem_read(off_in_ptr, &off_in, 8);
        if (off_out_ptr) emu.mem_read(off_out_ptr, &off_out, 8);

        ssize_t result = ::splice(fd_in, off_in_ptr ? &off_in : nullptr,
                                   fd_out, off_out_ptr ? &off_out : nullptr,
                                   len, flags);

        if (result >= 0) {
            if (off_in_ptr) emu.mem_write(off_in_ptr, &off_in, 8);
            if (off_out_ptr) emu.mem_write(off_out_ptr, &off_out, 8);
        } else {
            hle_set_errno(emu, errno);
        }

        set_reg(emu, UC_ARM64_REG_X0,
                static_cast<uint64_t>(static_cast<int64_t>(result)));
    });

    hle.register_function("vmsplice", [](Emulator& emu) {
        struct guest_iovec {
            uint64_t iov_base;
            uint64_t iov_len;
        };

        int fd = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t iov_addr = get_reg(emu, UC_ARM64_REG_X1);
        unsigned long nr_segs = get_reg(emu, UC_ARM64_REG_X2);
        unsigned int flags = get_reg(emu, UC_ARM64_REG_X3);

        if (nr_segs != 0 && iov_addr == 0) {
            hle_set_errno(emu, EFAULT);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        std::vector<guest_iovec> guest_iov(nr_segs);
        if (nr_segs != 0 &&
            !emu.mem_read(iov_addr, guest_iov.data(), nr_segs * sizeof(guest_iovec))) {
            hle_set_errno(emu, EFAULT);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        std::vector<struct iovec> host_iov(nr_segs);
        for (unsigned long i = 0; i < nr_segs; ++i) {
            host_iov[i].iov_len = guest_iov[i].iov_len;
            if (guest_iov[i].iov_base == 0) {
                host_iov[i].iov_base = nullptr;
                continue;
            }

            void* host_ptr = emu.memory().get_host_ptr(guest_iov[i].iov_base);
            if (host_ptr == nullptr && guest_iov[i].iov_len != 0) {
                hle_set_errno(emu, EFAULT);
                set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
                return;
            }
            host_iov[i].iov_base = host_ptr;
        }

        errno = 0;
        ssize_t result = ::vmsplice(fd, host_iov.data(), nr_segs, flags);
        if (result == -1) {
            hle_set_errno(emu, errno);
        }

        set_reg(emu, UC_ARM64_REG_X0,
                static_cast<uint64_t>(static_cast<int64_t>(result)));
    });

    hle.register_function("tee", [](Emulator& emu) {
        int fd_in = get_reg(emu, UC_ARM64_REG_X0);
        int fd_out = get_reg(emu, UC_ARM64_REG_X1);
        size_t len = get_reg(emu, UC_ARM64_REG_X2);
        unsigned int flags = get_reg(emu, UC_ARM64_REG_X3);

        ssize_t result = ::tee(fd_in, fd_out, len, flags);
        if (result == -1) {
            hle_set_errno(emu, errno);
        }
        set_reg(emu, UC_ARM64_REG_X0,
                static_cast<uint64_t>(static_cast<int64_t>(result)));
    });

    hle.register_function("readahead", [](Emulator& emu) {
        int fd = get_reg(emu, UC_ARM64_REG_X0);
        off64_t offset = get_reg(emu, UC_ARM64_REG_X1);
        size_t count = get_reg(emu, UC_ARM64_REG_X2);

        ssize_t result = ::readahead(fd, offset, count);
        if (result == -1) {
            hle_set_errno(emu, errno);
        }
        set_reg(emu, UC_ARM64_REG_X0,
                static_cast<uint64_t>(static_cast<int64_t>(result)));
    });

    hle.register_function("sync_file_range", [](Emulator& emu) {
        int fd = get_reg(emu, UC_ARM64_REG_X0);
        off64_t offset = get_reg(emu, UC_ARM64_REG_X1);
        off64_t nbytes = get_reg(emu, UC_ARM64_REG_X2);
        unsigned int flags = get_reg(emu, UC_ARM64_REG_X3);

        int result = ::sync_file_range(fd, offset, nbytes, flags);
        if (result == -1) {
            hle_set_errno(emu, errno);
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // ========================================================================
    // Additional stdio functions
    // ========================================================================

    // open_memstream - open a memory stream for writing
    hle.register_function("open_memstream", [](Emulator& emu) {
        uint64_t ptr_ptr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t sizeloc_ptr = get_reg(emu, UC_ARM64_REG_X1);

        if (!ptr_ptr || !sizeloc_ptr) {
            hle_set_errno(emu, EINVAL);
            set_reg(emu, UC_ARM64_REG_X0, 0);
            return;
        }

        auto state = std::make_unique<OpenMemstreamState>();
        state->guest_ptr_ptr = ptr_ptr;
        state->guest_size_ptr = sizeloc_ptr;
        FILE* fp = ::open_memstream(&state->host_buf, &state->host_size);

        if (fp) {
            uint64_t fd = g_next_fd++;
            g_file_map[fd] = fp;
            g_open_memstreams[fd] = std::move(state);
            uint64_t zero_ptr = 0;
            size_t zero_size = 0;
            emu.mem_write(ptr_ptr, &zero_ptr, sizeof(zero_ptr));
            emu.mem_write(sizeloc_ptr, &zero_size, sizeof(zero_size));
            set_reg(emu, UC_ARM64_REG_X0, fd);
        } else {
            hle_set_errno(emu, errno);
            set_reg(emu, UC_ARM64_REG_X0, 0);
        }
    });

    // freopen - reopen a file stream
    hle.register_function("freopen", [](Emulator& emu) {
        uint64_t path_addr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t mode_addr = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t stream = get_reg(emu, UC_ARM64_REG_X2);

        std::string mode = read_string(emu, mode_addr);

        FILE* fp = hle_resolve_guest_file(emu, stream);
        if (fp == nullptr) {
            hle_set_errno(emu, EBADF);
            set_reg(emu, UC_ARM64_REG_X0, 0);
            return;
        }

        FILE* new_fp;
        if (path_addr) {
            std::string path = read_string(emu, path_addr);
            std::string host_path = guest_path_to_host(path);
            new_fp = ::freopen(host_path.c_str(), mode.c_str(), fp);
        } else {
            new_fp = ::freopen(nullptr, mode.c_str(), fp);
        }

        if (new_fp) {
            g_file_map[stream] = new_fp;
            g_closed_builtin_streams.erase(stream);
            set_reg(emu, UC_ARM64_REG_X0, stream);
        } else {
            g_file_map.erase(stream);
            hle_set_errno(emu, errno);
            set_reg(emu, UC_ARM64_REG_X0, 0);
        }
    });

    // fopen64 - same as fopen on 64-bit systems
    hle.register_function("fopen64", [](Emulator& emu) {
        uint64_t path_addr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t mode_addr = get_reg(emu, UC_ARM64_REG_X1);

        std::string path = read_string(emu, path_addr);
        std::string mode = read_string(emu, mode_addr);
        std::string host_path = guest_path_to_host(path);

        FILE* fp = ::fopen(host_path.c_str(), mode.c_str());
        if (fp) {
            uint64_t fd = g_next_fd++;
            g_file_map[fd] = fp;
            set_reg(emu, UC_ARM64_REG_X0, fd);
        } else {
            hle_set_errno(emu, errno);
            set_reg(emu, UC_ARM64_REG_X0, 0);
        }
    });

    // freopen64 - same as freopen on 64-bit systems
    hle.register_function("freopen64", [](Emulator& emu) {
        uint64_t path_addr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t mode_addr = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t stream = get_reg(emu, UC_ARM64_REG_X2);

        std::string mode = read_string(emu, mode_addr);

        FILE* fp = hle_resolve_guest_file(emu, stream);
        if (fp == nullptr) {
            hle_set_errno(emu, EBADF);
            set_reg(emu, UC_ARM64_REG_X0, 0);
            return;
        }

        FILE* new_fp;
        if (path_addr) {
            std::string path = read_string(emu, path_addr);
            std::string host_path = guest_path_to_host(path);
            new_fp = ::freopen(host_path.c_str(), mode.c_str(), fp);
        } else {
            new_fp = ::freopen(nullptr, mode.c_str(), fp);
        }

        if (new_fp) {
            g_file_map[stream] = new_fp;
            g_closed_builtin_streams.erase(stream);
            set_reg(emu, UC_ARM64_REG_X0, stream);
        } else {
            g_file_map.erase(stream);
            hle_set_errno(emu, errno);
            set_reg(emu, UC_ARM64_REG_X0, 0);
        }
    });

    // funopen - open stream with custom callbacks (BSD extension)
    hle.register_function("funopen", [](Emulator& emu) {
        uint64_t cookie = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t read_fn = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t write_fn = get_reg(emu, UC_ARM64_REG_X2);
        uint64_t seek_fn = get_reg(emu, UC_ARM64_REG_X3);
        uint64_t close_fn = get_reg(emu, UC_ARM64_REG_X4);

        if (read_fn == 0 && write_fn == 0 && seek_fn == 0 && close_fn == 0) {
            hle_set_errno(emu, EINVAL);
            set_reg(emu, UC_ARM64_REG_X0, 0);
            return;
        }

        uint64_t handle = g_next_popen_fd++;
        g_funopen_streams[handle] = {cookie, read_fn, write_fn, seek_fn, close_fn, false};
        set_reg(emu, UC_ARM64_REG_X0, handle);
    });

    // funopen64 - same as funopen
    hle.register_function("funopen64", [](Emulator& emu) {
        uint64_t cookie = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t read_fn = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t write_fn = get_reg(emu, UC_ARM64_REG_X2);
        uint64_t seek_fn = get_reg(emu, UC_ARM64_REG_X3);
        uint64_t close_fn = get_reg(emu, UC_ARM64_REG_X4);

        if (read_fn == 0 && write_fn == 0 && seek_fn == 0 && close_fn == 0) {
            hle_set_errno(emu, EINVAL);
            set_reg(emu, UC_ARM64_REG_X0, 0);
            return;
        }

        uint64_t handle = g_next_popen_fd++;
        g_funopen_streams[handle] = {cookie, read_fn, write_fn, seek_fn, close_fn, true};
        set_reg(emu, UC_ARM64_REG_X0, handle);
    });

    // fgetpos64 - same as fgetpos on 64-bit systems
    hle.register_function("fgetpos64", [](Emulator& emu) {
        uint64_t stream = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t pos_ptr = get_reg(emu, UC_ARM64_REG_X1);

        if (!pos_ptr) {
            hle_set_errno(emu, EINVAL);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        auto funopen_it = g_funopen_streams.find(stream);
        if (funopen_it != g_funopen_streams.end()) {
            int err = 0;
            int64_t pos = call_funopen_seek(emu, funopen_it->second, 0, SEEK_CUR, err);
            if (pos == -1) {
                hle_set_errno(emu, err);
                set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            } else {
                emu.mem_write(pos_ptr, &pos, sizeof(pos));
                set_reg(emu, UC_ARM64_REG_X0, 0);
            }
            return;
        }

        FILE* fp = hle_resolve_guest_file(emu, stream);
        if (fp == nullptr) {
            hle_set_errno(emu, EBADF);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        errno = 0;
        off64_t pos = ::ftello(fp);
        if (pos == static_cast<off64_t>(-1)) {
            hle_set_errno(emu, errno);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
        } else {
            emu.mem_write(pos_ptr, &pos, sizeof(pos));
            set_reg(emu, UC_ARM64_REG_X0, 0);
        }
    });

    // fsetpos64 - same as fsetpos on 64-bit systems
    hle.register_function("fsetpos64", [](Emulator& emu) {
        uint64_t stream = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t pos_ptr = get_reg(emu, UC_ARM64_REG_X1);

        if (!pos_ptr) {
            hle_set_errno(emu, EINVAL);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        int64_t pos = 0;
        emu.mem_read(pos_ptr, &pos, sizeof(pos));

        auto funopen_it = g_funopen_streams.find(stream);
        if (funopen_it != g_funopen_streams.end()) {
            int err = 0;
            int64_t result = call_funopen_seek(emu, funopen_it->second, pos, SEEK_SET, err);
            if (result == -1) {
                hle_set_errno(emu, err);
                set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            } else {
                set_reg(emu, UC_ARM64_REG_X0, 0);
            }
            return;
        }

        FILE* fp = hle_resolve_guest_file(emu, stream);
        if (fp == nullptr) {
            hle_set_errno(emu, EBADF);
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        errno = 0;
        int result = ::fseeko(fp, pos, SEEK_SET);
        if (result == -1) {
            hle_set_errno(emu, errno);
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });
}

} // namespace cross_shim
