/**
 * HLE Network Functions
 * socket, connect, bind, listen, accept, send, recv, sendto, recvfrom
 * getaddrinfo, freeaddrinfo, getnameinfo, inet_ntop, inet_pton
 * getsockopt, setsockopt, shutdown, getpeername, getsockname
 *
 * NOTE: With QEMU MTTCG (real parallel threads), all I/O operations use
 * direct blocking calls. Guest threads run on real host threads, so blocking
 * in the HLE handler blocks only that specific host thread - exactly what
 * we want for proper thread semantics.
 */

#include "debug_log.h"
#include "hle_manager.h"
#include <iostream>
#include <iomanip>
#include <atomic>
#include "cross_shim.h"
#include "memory_manager.h"
#include "bionic_types.h"
#include "emu_compat.h"
#include <cstring>
#include <vector>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <poll.h>
#include <sys/select.h>
#include <sys/epoll.h>
#include <cerrno>

namespace cross_shim {

using namespace bionic;

// get_reg and set_reg are provided by emu_compat.h

// Trace logging for network I/O debugging
static std::atomic<int> g_recv_call_count{0};
static std::atomic<int> g_recvfrom_call_count{0};
static std::atomic<int> g_poll_call_count{0};
static std::atomic<int> g_epoll_call_count{0};
static constexpr bool TRACE_NETWORK_IO = false; // Disabled - not the cause of slow frame rate
static std::atomic<int> g_epoll_return_with_events{0}; // Count epoll returns with events

static std::string read_string(Emulator& emu, uint64_t addr, size_t max_len = 4096) {
    std::string result;
    char c;
    for (size_t i = 0; i < max_len; i++) {
        if (!emu.mem_read(addr + i, &c, 1) || c == '\0') break;
        result += c;
    }
    return result;
}

void register_hle_network(HleManager& hle) {
    // ========================================================================
    // Socket creation and connection
    // ========================================================================
    
    hle.register_function("socket", [](Emulator& emu) {
        int domain = get_reg(emu, UC_ARM64_REG_X0);
        int type = get_reg(emu, UC_ARM64_REG_X1);
        int protocol = get_reg(emu, UC_ARM64_REG_X2);
        int fd = socket(domain, type, protocol);
        if (emu.is_debug()) {
            EMU_LOG << "[HLE] socket: domain=" << domain << " type=" << type << " protocol=" << protocol << " fd=" << fd << std::endl;
        }
        set_reg(emu, UC_ARM64_REG_X0, fd);
    });

    hle.register_function("connect", [](Emulator& emu) {
        int sockfd = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t addr_ptr = get_reg(emu, UC_ARM64_REG_X1);
        socklen_t addrlen = get_reg(emu, UC_ARM64_REG_X2);

        std::vector<char> addr_buf(addrlen);
        emu.mem_read(addr_ptr, addr_buf.data(), addrlen);

        // Debug: print connection info
        if (emu.is_debug()) {
            struct sockaddr_in* sin = (struct sockaddr_in*)addr_buf.data();
            char ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof(ip));
            EMU_LOG << "[HLE] connect: fd=" << sockfd << " addr=" << ip << ":" << ntohs(sin->sin_port) << std::endl;
        }

        // Direct blocking connect - with MTTCG, this blocks only this host thread
        int result = ::connect(sockfd, (struct sockaddr*)addr_buf.data(), addrlen);
        if (emu.is_debug()) {
            EMU_LOG << "[HLE] connect result: " << result << " errno=" << errno << std::endl;
        }
        if (result < 0) {
            hle_set_errno(errno);
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("bind", [](Emulator& emu) {
        int sockfd = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t addr_ptr = get_reg(emu, UC_ARM64_REG_X1);
        socklen_t addrlen = get_reg(emu, UC_ARM64_REG_X2);

        std::vector<char> addr_buf(addrlen);
        emu.mem_read(addr_ptr, addr_buf.data(), addrlen);

        int result = bind(sockfd, (struct sockaddr*)addr_buf.data(), addrlen);
        if (emu.is_debug()) {
            struct sockaddr* sa = (struct sockaddr*)addr_buf.data();
            if (sa->sa_family == AF_INET) {
                struct sockaddr_in* sin = (struct sockaddr_in*)sa;
                char ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof(ip));
                EMU_LOG << "[HLE] bind: sockfd=" << sockfd << " addr=" << ip << ":" << ntohs(sin->sin_port) << " result=" << result << std::endl;
            } else if (sa->sa_family == AF_INET6) {
                struct sockaddr_in6* sin6 = (struct sockaddr_in6*)sa;
                char ip[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, &sin6->sin6_addr, ip, sizeof(ip));
                EMU_LOG << "[HLE] bind: sockfd=" << sockfd << " addr=[" << ip << "]:" << ntohs(sin6->sin6_port) << " result=" << result << std::endl;
            } else {
                EMU_LOG << "[HLE] bind: sockfd=" << sockfd << " family=" << sa->sa_family << " result=" << result << std::endl;
            }
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("listen", [](Emulator& emu) {
        int sockfd = get_reg(emu, UC_ARM64_REG_X0);
        int backlog = get_reg(emu, UC_ARM64_REG_X1);
        int result = listen(sockfd, backlog);
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("accept", [](Emulator& emu) {
        int sockfd = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t addr_ptr = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t addrlen_ptr = get_reg(emu, UC_ARM64_REG_X2);

        struct sockaddr_storage addr;
        socklen_t addrlen = sizeof(addr);

        // Direct blocking accept - with MTTCG, this blocks only this host thread
        int result = ::accept(sockfd, (struct sockaddr*)&addr, &addrlen);

        if (result >= 0) {
            if (addr_ptr) {
                emu.mem_write(addr_ptr, &addr, addrlen);
            }
            if (addrlen_ptr) {
                emu.mem_write(addrlen_ptr, &addrlen, sizeof(addrlen));
            }
        }

        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("shutdown", [](Emulator& emu) {
        int sockfd = get_reg(emu, UC_ARM64_REG_X0);
        int how = get_reg(emu, UC_ARM64_REG_X1);
        int result = shutdown(sockfd, how);
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // ========================================================================
    // Data transfer
    // ========================================================================
    
    hle.register_function("send", [](Emulator& emu) {
        int sockfd = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t buf_ptr = get_reg(emu, UC_ARM64_REG_X1);
        size_t len = get_reg(emu, UC_ARM64_REG_X2);
        int flags = get_reg(emu, UC_ARM64_REG_X3);

        if (emu.is_debug()) {
            EMU_LOG << "[HLE] send: sockfd=" << sockfd << " len=" << len << std::endl;
        }

        std::vector<char> buf(len);
        emu.mem_read(buf_ptr, buf.data(), len);

        // Direct blocking send - with MTTCG, this blocks only this host thread
        ssize_t result = ::send(sockfd, buf.data(), len, flags);

        if (emu.is_debug()) {
            EMU_LOG << "[HLE] send result: " << result << std::endl;
        }
        if (result < 0) {
            hle_set_errno(errno);
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("recv", [](Emulator& emu) {
        int sockfd = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t buf_ptr = get_reg(emu, UC_ARM64_REG_X1);
        size_t len = get_reg(emu, UC_ARM64_REG_X2);
        int flags = get_reg(emu, UC_ARM64_REG_X3);

        int call_num = ++g_recv_call_count;
        if (TRACE_NETWORK_IO && (call_num <= 10 || call_num % 100 == 0)) {
            EMU_LOG << "[HLE-TRACE] recv ENTER #" << call_num << " sockfd=" << sockfd
                    << " len=" << len << " flags=0x" << std::hex << flags << std::dec << std::endl;
        }

        std::vector<char> buf(len);

        // Direct blocking recv - with MTTCG, this blocks only this host thread
        ssize_t result = ::recv(sockfd, buf.data(), len, flags);

        if (result > 0) {
            emu.mem_write(buf_ptr, buf.data(), result);
        } else if (result < 0) {
            hle_set_errno(errno);
        }

        if (TRACE_NETWORK_IO && (call_num <= 10 || call_num % 100 == 0)) {
            EMU_LOG << "[HLE-TRACE] recv EXIT #" << call_num << " sockfd=" << sockfd
                    << " result=" << result << std::endl;
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("sendto", [](Emulator& emu) {
        int sockfd = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t buf_ptr = get_reg(emu, UC_ARM64_REG_X1);
        size_t len = get_reg(emu, UC_ARM64_REG_X2);
        int flags = get_reg(emu, UC_ARM64_REG_X3);
        uint64_t dest_addr = get_reg(emu, UC_ARM64_REG_X4);
        socklen_t addrlen = get_reg(emu, UC_ARM64_REG_X5);

        std::vector<char> data(len);
        emu.mem_read(buf_ptr, data.data(), len);

        // If addrlen is 0 but dest_addr is non-null, infer address length from family
        if (dest_addr && addrlen == 0) {
            uint16_t sa_family = 0;
            emu.mem_read(dest_addr, &sa_family, sizeof(sa_family));
            if (sa_family == AF_INET) {
                addrlen = sizeof(struct sockaddr_in);
            } else if (sa_family == AF_INET6) {
                addrlen = sizeof(struct sockaddr_in6);
            }
        }

        std::vector<char> addr_buf(addrlen > 0 ? addrlen : 1);
        if (dest_addr && addrlen > 0) emu.mem_read(dest_addr, addr_buf.data(), addrlen);

        // Direct blocking sendto - with MTTCG, this blocks only this host thread
        ssize_t result = ::sendto(sockfd, data.data(), len, flags,
                                  (dest_addr && addrlen > 0) ? (struct sockaddr*)addr_buf.data() : nullptr, addrlen);

        if (result < 0) {
            hle_set_errno(errno);
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("recvfrom", [](Emulator& emu) {
        int sockfd = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t buf_ptr = get_reg(emu, UC_ARM64_REG_X1);
        size_t len = get_reg(emu, UC_ARM64_REG_X2);
        int flags = get_reg(emu, UC_ARM64_REG_X3);
        uint64_t src_addr = get_reg(emu, UC_ARM64_REG_X4);
        uint64_t addrlen_ptr = get_reg(emu, UC_ARM64_REG_X5);

        int call_num = ++g_recvfrom_call_count;
        if (TRACE_NETWORK_IO && (call_num <= 10 || call_num % 100 == 0)) {
            EMU_LOG << "[HLE-TRACE] recvfrom ENTER #" << call_num << " sockfd=" << sockfd
                    << " len=" << len << " flags=0x" << std::hex << flags << std::dec << std::endl;
        }

        std::vector<char> data(len);
        struct sockaddr_storage addr;
        socklen_t addrlen = sizeof(addr);

        // Direct blocking recvfrom - with MTTCG, this blocks only this host thread
        ssize_t result = ::recvfrom(sockfd, data.data(), len, flags,
                                    src_addr ? (struct sockaddr*)&addr : nullptr, &addrlen);

        if (TRACE_NETWORK_IO && (call_num <= 10 || call_num % 100 == 0)) {
            EMU_LOG << "[HLE-TRACE] recvfrom EXIT #" << call_num << " sockfd=" << sockfd
                    << " result=" << result << std::endl;
        }

        if (result > 0) {
            emu.mem_write(buf_ptr, data.data(), result);
            if (src_addr) {
                emu.mem_write(src_addr, &addr, addrlen);
            }
            if (addrlen_ptr) emu.mem_write(addrlen_ptr, &addrlen, sizeof(addrlen));
        } else if (result < 0) {
            // Set errno for the emulated code
            hle_set_errno(errno);
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // ========================================================================
    // Socket options
    // ========================================================================

    hle.register_function("setsockopt", [](Emulator& emu) {
        int sockfd = get_reg(emu, UC_ARM64_REG_X0);
        int level = get_reg(emu, UC_ARM64_REG_X1);
        int optname = get_reg(emu, UC_ARM64_REG_X2);
        uint64_t optval = get_reg(emu, UC_ARM64_REG_X3);
        socklen_t optlen = get_reg(emu, UC_ARM64_REG_X4);

        std::vector<char> val(optlen);
        emu.mem_read(optval, val.data(), optlen);

        // Debug: print the value for IPV6_V6ONLY
        if (level == IPPROTO_IPV6 && optname == IPV6_V6ONLY && optlen >= 4) {
            int v6only = *(int*)val.data();
            EMU_LOG << "[HLE] setsockopt: IPV6_V6ONLY=" << v6only << std::endl;
        }

        int result = setsockopt(sockfd, level, optname, val.data(), optlen);
        if (emu.is_debug()) {
            EMU_LOG << "[HLE] setsockopt: sockfd=" << sockfd << " level=" << level
                      << " optname=" << optname << " optlen=" << optlen << " result=" << result << std::endl;
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("getsockopt", [](Emulator& emu) {
        int sockfd = get_reg(emu, UC_ARM64_REG_X0);
        int level = get_reg(emu, UC_ARM64_REG_X1);
        int optname = get_reg(emu, UC_ARM64_REG_X2);
        uint64_t optval = get_reg(emu, UC_ARM64_REG_X3);
        uint64_t optlen_ptr = get_reg(emu, UC_ARM64_REG_X4);

        socklen_t optlen;
        emu.mem_read(optlen_ptr, &optlen, sizeof(optlen));

        std::vector<char> val(optlen);
        int result = getsockopt(sockfd, level, optname, val.data(), &optlen);

        if (result == 0) {
            emu.mem_write(optval, val.data(), optlen);
            emu.mem_write(optlen_ptr, &optlen, sizeof(optlen));
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("getpeername", [](Emulator& emu) {
        int sockfd = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t addr_ptr = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t addrlen_ptr = get_reg(emu, UC_ARM64_REG_X2);

        struct sockaddr_storage addr;
        socklen_t addrlen = sizeof(addr);

        int result = getpeername(sockfd, (struct sockaddr*)&addr, &addrlen);
        if (result == 0) {
            emu.mem_write(addr_ptr, &addr, addrlen);
            emu.mem_write(addrlen_ptr, &addrlen, sizeof(addrlen));
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("getsockname", [](Emulator& emu) {
        int sockfd = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t addr_ptr = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t addrlen_ptr = get_reg(emu, UC_ARM64_REG_X2);

        struct sockaddr_storage addr;
        socklen_t addrlen = sizeof(addr);

        int result = getsockname(sockfd, (struct sockaddr*)&addr, &addrlen);
        if (result == 0) {
            emu.mem_write(addr_ptr, &addr, addrlen);
            emu.mem_write(addrlen_ptr, &addrlen, sizeof(addrlen));
            if (emu.is_debug()) {
                struct sockaddr* sa = (struct sockaddr*)&addr;
                if (sa->sa_family == AF_INET) {
                    struct sockaddr_in* sin = (struct sockaddr_in*)sa;
                    char ip[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof(ip));
                    EMU_LOG << "[HLE] getsockname: sockfd=" << sockfd << " addr=" << ip << ":" << ntohs(sin->sin_port) << std::endl;
                } else if (sa->sa_family == AF_INET6) {
                    struct sockaddr_in6* sin6 = (struct sockaddr_in6*)sa;
                    char ip[INET6_ADDRSTRLEN];
                    inet_ntop(AF_INET6, &sin6->sin6_addr, ip, sizeof(ip));
                    EMU_LOG << "[HLE] getsockname: sockfd=" << sockfd << " addr=[" << ip << "]:" << ntohs(sin6->sin6_port) << std::endl;
                }
            }
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // ========================================================================
    // DNS and address conversion
    // ========================================================================

    hle.register_function("inet_addr", [](Emulator& emu) {
        uint64_t cp = get_reg(emu, UC_ARM64_REG_X0);
        std::string addr = read_string(emu, cp);
        in_addr_t result = inet_addr(addr.c_str());
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("inet_ntop", [](Emulator& emu) {
        int af = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t src = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t dst = get_reg(emu, UC_ARM64_REG_X2);
        socklen_t size = get_reg(emu, UC_ARM64_REG_X3);

        char addr_buf[16];
        emu.mem_read(src, addr_buf, af == AF_INET ? 4 : 16);

        char result_buf[INET6_ADDRSTRLEN];
        const char* result = inet_ntop(af, addr_buf, result_buf, sizeof(result_buf));

        // Note: Don't print debug for inet_ntop - it's called very frequently and floods the log

        if (result) {
            emu.mem_write(dst, result_buf, strlen(result_buf) + 1);
            set_reg(emu, UC_ARM64_REG_X0, dst);
        } else {
            set_reg(emu, UC_ARM64_REG_X0, 0);
        }
    });

    hle.register_function("inet_pton", [](Emulator& emu) {
        int af = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t src = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t dst = get_reg(emu, UC_ARM64_REG_X2);

        std::string addr = read_string(emu, src);
        char result_buf[16];

        EMU_LOG << "[HLE] inet_pton: af=" << af << " addr=" << addr << std::endl;

        int result = inet_pton(af, addr.c_str(), result_buf);
        EMU_LOG << "[HLE] inet_pton result: " << result << std::endl;
        if (result == 1) {
            emu.mem_write(dst, result_buf, af == AF_INET ? 4 : 16);
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // ========================================================================
    // Polling
    // ========================================================================

    hle.register_function("poll", [](Emulator& emu) {
        uint64_t fds_ptr = get_reg(emu, UC_ARM64_REG_X0);
        nfds_t nfds = get_reg(emu, UC_ARM64_REG_X1);
        int timeout = get_reg(emu, UC_ARM64_REG_X2);

        int call_num = ++g_poll_call_count;
        if (TRACE_NETWORK_IO && (call_num <= 20 || call_num % 100 == 0)) {
            EMU_LOG << "[HLE-TRACE] poll ENTER #" << call_num << " nfds=" << nfds
                    << " timeout=" << timeout << "ms" << std::endl;
        }

        if (nfds == 0 || fds_ptr == 0) {
            set_reg(emu, UC_ARM64_REG_X0, 0);
            return;
        }

        // Read ARM64 bionic pollfd array and convert to host format
        std::vector<pollfd_arm64> fds_arm(nfds);
        std::vector<struct pollfd> fds(nfds);
        emu.mem_read(fds_ptr, fds_arm.data(), nfds * sizeof(pollfd_arm64));
        for (nfds_t i = 0; i < nfds; i++) {
            arm64_to_host_pollfd(fds_arm[i], fds[i]);
        }

        // Direct blocking poll - with MTTCG, this blocks only this host thread
        int result = ::poll(fds.data(), nfds, timeout);

        if (TRACE_NETWORK_IO && (call_num <= 20 || call_num % 100 == 0)) {
            EMU_LOG << "[HLE-TRACE] poll EXIT #" << call_num << " result=" << result << std::endl;
        }

        // Convert back to ARM64 format and write back the results
        if (result > 0) {
            for (nfds_t i = 0; i < nfds; i++) {
                host_to_arm64_pollfd(fds[i], fds_arm[i]);
            }
            emu.mem_write(fds_ptr, fds_arm.data(), nfds * sizeof(pollfd_arm64));
        }

        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // __FD_SET_chk - checked version of FD_SET macro
    hle.register_function("__FD_SET_chk", [](Emulator& emu) {
        int fd = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t fdset_ptr = get_reg(emu, UC_ARM64_REG_X1);
        // size_t fdset_size = get_reg(emu, UC_ARM64_REG_X2);  // ignored

        if (fd >= 0 && fd < FD_SETSIZE && fdset_ptr) {
            fd_set fds;
            emu.mem_read(fdset_ptr, &fds, sizeof(fd_set));
            FD_SET(fd, &fds);
            emu.mem_write(fdset_ptr, &fds, sizeof(fd_set));
        }
    });

    hle.register_function("select", [](Emulator& emu) {
        int nfds = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t readfds_ptr = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t writefds_ptr = get_reg(emu, UC_ARM64_REG_X2);
        uint64_t exceptfds_ptr = get_reg(emu, UC_ARM64_REG_X3);
        uint64_t timeout_ptr = get_reg(emu, UC_ARM64_REG_X4);

        fd_set readfds, writefds, exceptfds;
        struct timeval timeout;

        FD_ZERO(&readfds);
        FD_ZERO(&writefds);
        FD_ZERO(&exceptfds);

        if (readfds_ptr) emu.mem_read(readfds_ptr, &readfds, sizeof(fd_set));
        if (writefds_ptr) emu.mem_read(writefds_ptr, &writefds, sizeof(fd_set));
        if (exceptfds_ptr) emu.mem_read(exceptfds_ptr, &exceptfds, sizeof(fd_set));

        struct timeval* timeout_arg = nullptr;
        if (timeout_ptr) {
            // Read ARM64 bionic timeval and convert to host
            timeval_arm64 timeout_arm;
            emu.mem_read(timeout_ptr, &timeout_arm, sizeof(timeout_arm));
            arm64_to_host_timeval(timeout_arm, timeout);
            timeout_arg = &timeout;
        }

        // Direct blocking select - with MTTCG, this blocks only this host thread
        int result = ::select(nfds,
                              readfds_ptr ? &readfds : nullptr,
                              writefds_ptr ? &writefds : nullptr,
                              exceptfds_ptr ? &exceptfds : nullptr,
                              timeout_arg);

        // Write back the results
        if (result >= 0) {
            if (readfds_ptr) emu.mem_write(readfds_ptr, &readfds, sizeof(fd_set));
            if (writefds_ptr) emu.mem_write(writefds_ptr, &writefds, sizeof(fd_set));
            if (exceptfds_ptr) emu.mem_write(exceptfds_ptr, &exceptfds, sizeof(fd_set));
        }

        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("epoll_create", [](Emulator& emu) {
        int size = get_reg(emu, UC_ARM64_REG_X0);
        int result = epoll_create(size);
        EMU_LOG_VERBOSE << "[HLE] epoll_create(size=" << size << ") = " << result << std::endl;
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    static std::atomic<int> g_epoll_ctl_count{0};
    hle.register_function("epoll_ctl", [](Emulator& emu) {
        int epfd = get_reg(emu, UC_ARM64_REG_X0);
        int op = get_reg(emu, UC_ARM64_REG_X1);
        int fd = get_reg(emu, UC_ARM64_REG_X2);
        uint64_t event_ptr = get_reg(emu, UC_ARM64_REG_X3);

        struct epoll_event host_event = {};
        epoll_event_arm64 arm64_event;
        if (event_ptr && op != EPOLL_CTL_DEL) {
            // Read ARM64 format (16 bytes) from emulated memory
            emu.mem_read(event_ptr, &arm64_event, sizeof(epoll_event_arm64));
            // Convert to host format
            arm64_to_host_epoll_event(arm64_event, host_event);
        }

        int result = epoll_ctl(epfd, op, fd, (event_ptr && op != EPOLL_CTL_DEL) ? &host_event : nullptr);
        int call_num = ++g_epoll_ctl_count;
        if (TRACE_NETWORK_IO && (call_num <= 50 || call_num % 100 == 0)) {
            const char* op_str = (op == EPOLL_CTL_ADD) ? "ADD" : (op == EPOLL_CTL_DEL) ? "DEL" : (op == EPOLL_CTL_MOD) ? "MOD" : "???";
            EMU_LOG << "[HLE-TRACE] epoll_ctl #" << call_num << ": epfd=" << epfd << " op=" << op_str << " fd=" << fd
                      << " events=0x" << std::hex << host_event.events << std::dec
                      << " data.fd=" << host_event.data.fd << " result=" << result
                      << (result < 0 ? " errno=" + std::to_string(errno) : "") << std::endl;
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("epoll_wait", [](Emulator& emu) {
        int epfd = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t events_ptr = get_reg(emu, UC_ARM64_REG_X1);
        int maxevents = get_reg(emu, UC_ARM64_REG_X2);
        int timeout = get_reg(emu, UC_ARM64_REG_X3);

        int call_num = ++g_epoll_call_count;
        if (TRACE_NETWORK_IO && (call_num <= 50 || call_num % 100 == 0)) {
            EMU_LOG << "[HLE-TRACE] epoll_wait ENTER #" << call_num << " epfd=" << epfd
                    << " maxevents=" << maxevents << " timeout=" << timeout << "ms" << std::endl;
        }

        if (maxevents <= 0 || events_ptr == 0) {
            set_reg(emu, UC_ARM64_REG_X0, -1);
            return;
        }

        std::vector<struct epoll_event> host_events(maxevents);

        // Direct blocking epoll_wait - with MTTCG, this blocks only this host thread
        int result = ::epoll_wait(epfd, host_events.data(), maxevents, timeout);

        if (TRACE_NETWORK_IO && (call_num <= 50 || call_num % 100 == 0 || result > 0)) {
            EMU_LOG << "[HLE-TRACE] epoll_wait EXIT #" << call_num << " result=" << result;
            if (result > 0) {
                EMU_LOG << " events=[";
                for (int i = 0; i < result && i < 5; i++) {
                    EMU_LOG << (i > 0 ? "," : "") << "fd=" << host_events[i].data.fd
                            << ":0x" << std::hex << host_events[i].events << std::dec;
                }
                if (result > 5) EMU_LOG << "...+" << (result - 5);
                EMU_LOG << "]";
            }
            EMU_LOG << std::endl;
        }

        if (result > 0) {
            // Convert host events to ARM64 format (16 bytes each) before writing to emulated memory
            std::vector<epoll_event_arm64> arm64_events(result);
            for (int i = 0; i < result; i++) {
                host_to_arm64_epoll_event(host_events[i], arm64_events[i]);
                if (TRACE_NETWORK_IO && call_num <= 10) {
                    EMU_LOG << "[HLE-TRACE] epoll_wait #" << call_num << " writing ARM64 event[" << i
                            << "]: events=0x" << std::hex << arm64_events[i].events
                            << " data.fd=" << std::dec << arm64_events[i].data.fd
                            << " at addr=0x" << std::hex << (events_ptr + i * 16) << std::dec << std::endl;
                }
            }
            emu.mem_write(events_ptr, arm64_events.data(), result * sizeof(epoll_event_arm64));

            // Debug: verify written data by reading back
            if (TRACE_NETWORK_IO && call_num <= 10) {
                epoll_event_arm64 verify;
                emu.mem_read(events_ptr, &verify, sizeof(verify));
                EMU_LOG << "[HLE-TRACE] epoll_wait #" << call_num << " VERIFY readback: events=0x"
                        << std::hex << verify.events << " padding=0x" << verify._padding
                        << " data.fd=" << std::dec << verify.data.fd << std::endl;
            }
        }

        // Count epoll_wait calls that returned with events
        if (result > 0) {
            int events_count = ++g_epoll_return_with_events;
            int recv_count = g_recvfrom_call_count.load();
            // Log ratio every 100 epoll events
            if (events_count % 100 == 0) {
                EMU_LOG << "[STATS] epoll_events=" << events_count
                        << " recvfrom=" << recv_count
                        << " ratio=" << (recv_count > 0 ? (float)events_count/recv_count : 0)
                        << std::endl;
            }
        }

        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("epoll_create1", [](Emulator& emu) {
        int flags = get_reg(emu, UC_ARM64_REG_X0);
        int result = epoll_create1(flags);
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("epoll_pwait", [](Emulator& emu) {
        int epfd = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t events_ptr = get_reg(emu, UC_ARM64_REG_X1);
        int maxevents = get_reg(emu, UC_ARM64_REG_X2);
        int timeout = get_reg(emu, UC_ARM64_REG_X3);
        // uint64_t sigmask = get_reg(emu, UC_ARM64_REG_X4); // Ignored for now

        if (maxevents <= 0 || events_ptr == 0) {
            set_reg(emu, UC_ARM64_REG_X0, -1);
            return;
        }

        std::vector<struct epoll_event> host_events(maxevents);

        // Direct blocking epoll_wait (signal mask ignored) - with MTTCG, this blocks only this host thread
        int result = ::epoll_wait(epfd, host_events.data(), maxevents, timeout);

        if (result > 0) {
            // Convert host events to ARM64 format (16 bytes each) before writing to emulated memory
            std::vector<epoll_event_arm64> arm64_events(result);
            for (int i = 0; i < result; i++) {
                host_to_arm64_epoll_event(host_events[i], arm64_events[i]);
            }
            emu.mem_write(events_ptr, arm64_events.data(), result * sizeof(epoll_event_arm64));
        }

        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    // ========================================================================
    // More address resolution
    // ========================================================================

    hle.register_function("getaddrinfo", [](Emulator& emu) {
        uint64_t node_addr = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t service_addr = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t hints_addr = get_reg(emu, UC_ARM64_REG_X2);
        uint64_t res_addr = get_reg(emu, UC_ARM64_REG_X3);

        std::string node = node_addr ? read_string(emu, node_addr) : "";
        std::string service = service_addr ? read_string(emu, service_addr) : "";

        if (emu.is_debug()) {
            EMU_LOG << "[HLE] getaddrinfo: node=" << node << " service=" << service << std::endl;
        }

        // For hints, we need to be careful - the pointers inside are guest pointers
        // For simplicity, we'll create a host hints structure with just the flags
        struct addrinfo hints = {0};
        struct addrinfo* result = nullptr;

        if (hints_addr) {
            // Read the basic fields (flags, family, socktype, protocol)
            int32_t ai_flags, ai_family, ai_socktype, ai_protocol;
            emu.mem_read(hints_addr + 0, &ai_flags, sizeof(ai_flags));
            emu.mem_read(hints_addr + 4, &ai_family, sizeof(ai_family));
            emu.mem_read(hints_addr + 8, &ai_socktype, sizeof(ai_socktype));
            emu.mem_read(hints_addr + 12, &ai_protocol, sizeof(ai_protocol));
            hints.ai_flags = ai_flags;
            hints.ai_family = ai_family;
            hints.ai_socktype = ai_socktype;
            hints.ai_protocol = ai_protocol;
            // Ignore ai_addrlen, ai_addr, ai_canonname, ai_next for hints
        }

        int ret = getaddrinfo(node.empty() ? nullptr : node.c_str(),
                              service.empty() ? nullptr : service.c_str(),
                              hints_addr ? &hints : nullptr,
                              &result);

        if (emu.is_debug()) {
            EMU_LOG << "[HLE] getaddrinfo: ret=" << ret << std::endl;
            if (ret == 0 && result) {
                for (struct addrinfo* ai = result; ai != nullptr; ai = ai->ai_next) {
                    char addr_str[INET6_ADDRSTRLEN] = {0};
                    if (ai->ai_family == AF_INET) {
                        struct sockaddr_in* sin = (struct sockaddr_in*)ai->ai_addr;
                        inet_ntop(AF_INET, &sin->sin_addr, addr_str, sizeof(addr_str));
                        EMU_LOG << "[HLE] getaddrinfo result: family=AF_INET addr=" << addr_str << std::endl;
                    } else if (ai->ai_family == AF_INET6) {
                        struct sockaddr_in6* sin6 = (struct sockaddr_in6*)ai->ai_addr;
                        inet_ntop(AF_INET6, &sin6->sin6_addr, addr_str, sizeof(addr_str));
                        EMU_LOG << "[HLE] getaddrinfo result: family=AF_INET6 addr=" << addr_str << std::endl;
                    }
                }
            }
        }

        if (ret == 0 && result) {
            // Count the number of results and allocate memory for all of them
            std::vector<uint64_t> guest_ptrs;
            for (struct addrinfo* ai = result; ai != nullptr; ai = ai->ai_next) {
                // Allocate space for: addrinfo struct + sockaddr + canonname
                size_t total_size = sizeof(struct addrinfo);
                if (ai->ai_addr) total_size += ai->ai_addrlen;
                if (ai->ai_canonname) total_size += strlen(ai->ai_canonname) + 1;

                uint64_t ptr = emu.memory().heap().allocate(total_size, 8);
                guest_ptrs.push_back(ptr);
            }

            // Now copy each addrinfo, fixing up pointers
            size_t idx = 0;
            for (struct addrinfo* ai = result; ai != nullptr; ai = ai->ai_next, idx++) {
                uint64_t base = guest_ptrs[idx];
                uint64_t offset = sizeof(struct addrinfo);

                // Create a guest-compatible addrinfo structure
                // ARM64 Linux addrinfo layout (same as x86_64):
                // int ai_flags, ai_family, ai_socktype, ai_protocol (4 bytes each = 16 bytes)
                // socklen_t ai_addrlen (4 bytes + 4 padding = 8 bytes)
                // struct sockaddr* ai_addr (8 bytes)
                // char* ai_canonname (8 bytes)
                // struct addrinfo* ai_next (8 bytes)
                // Total: 48 bytes

                int32_t ai_flags = ai->ai_flags;
                int32_t ai_family = ai->ai_family;
                int32_t ai_socktype = ai->ai_socktype;
                int32_t ai_protocol = ai->ai_protocol;
                uint32_t ai_addrlen = ai->ai_addrlen;
                uint64_t ai_addr_ptr = 0;
                uint64_t ai_canonname_ptr = 0;
                uint64_t ai_next_ptr = (idx + 1 < guest_ptrs.size()) ? guest_ptrs[idx + 1] : 0;

                // Copy sockaddr if present
                if (ai->ai_addr && ai->ai_addrlen > 0) {
                    ai_addr_ptr = base + offset;
                    emu.mem_write(ai_addr_ptr, ai->ai_addr, ai->ai_addrlen);
                    offset += ai->ai_addrlen;
                }

                // Copy canonname if present
                if (ai->ai_canonname) {
                    ai_canonname_ptr = base + offset;
                    size_t len = strlen(ai->ai_canonname) + 1;
                    emu.mem_write(ai_canonname_ptr, ai->ai_canonname, len);
                    offset += len;
                }

                // Write the addrinfo structure (Android Bionic layout)
                // Note: Android Bionic has ai_canonname before ai_addr, unlike glibc
                // Android Bionic layout:
                //   int ai_flags (0), ai_family (4), ai_socktype (8), ai_protocol (12)
                //   socklen_t ai_addrlen (16), padding (20)
                //   char* ai_canonname (24)
                //   struct sockaddr* ai_addr (32)
                //   struct addrinfo* ai_next (40)
                emu.mem_write(base + 0, &ai_flags, 4);
                emu.mem_write(base + 4, &ai_family, 4);
                emu.mem_write(base + 8, &ai_socktype, 4);
                emu.mem_write(base + 12, &ai_protocol, 4);
                emu.mem_write(base + 16, &ai_addrlen, 4);
                uint32_t padding = 0;
                emu.mem_write(base + 20, &padding, 4);
                emu.mem_write(base + 24, &ai_canonname_ptr, 8);  // Android: canonname at 24
                emu.mem_write(base + 32, &ai_addr_ptr, 8);       // Android: addr at 32
                emu.mem_write(base + 40, &ai_next_ptr, 8);
            }

            // Write the first result pointer to res_addr
            emu.mem_write(res_addr, &guest_ptrs[0], sizeof(uint64_t));
            freeaddrinfo(result);
        } else {
            uint64_t null_ptr = 0;
            emu.mem_write(res_addr, &null_ptr, sizeof(null_ptr));
        }
        set_reg(emu, UC_ARM64_REG_X0, ret);
    });

    hle.register_function("freeaddrinfo", [](Emulator& emu) {
        uint64_t res_ptr = get_reg(emu, UC_ARM64_REG_X0);
        // Walk the linked list and free each node
        while (res_ptr) {
            uint64_t next_ptr = 0;
            emu.mem_read(res_ptr + 40, &next_ptr, sizeof(next_ptr));  // ai_next is at offset 40
            emu.memory().heap().free(res_ptr);
            res_ptr = next_ptr;
        }
    });

    hle.register_function("gai_strerror", [](Emulator& emu) {
        int errcode = get_reg(emu, UC_ARM64_REG_X0);
        const char* msg = gai_strerror(errcode);
        uint64_t ptr = emu.memory().heap().allocate(strlen(msg) + 1, 8);
        emu.mem_write(ptr, msg, strlen(msg) + 1);
        set_reg(emu, UC_ARM64_REG_X0, ptr);
    });

    // gethostbyname - legacy DNS resolution (deprecated but still used)
    hle.register_function("gethostbyname", [](Emulator& emu) {
        uint64_t name_addr = get_reg(emu, UC_ARM64_REG_X0);
        std::string name = read_string(emu, name_addr);

        if (emu.is_debug()) {
            EMU_LOG << "[HLE] gethostbyname(\"" << name << "\")" << std::endl;
        }

        struct hostent* he = gethostbyname(name.c_str());
        if (!he) {
            if (emu.is_debug()) {
                EMU_LOG << "[HLE] gethostbyname: failed, h_errno=" << h_errno << std::endl;
            }
            set_reg(emu, UC_ARM64_REG_X0, 0);
            return;
        }

        // Allocate memory for the hostent structure and its data
        // ARM64 hostent layout:
        // char* h_name (8 bytes)
        // char** h_aliases (8 bytes)
        // int h_addrtype (4 bytes)
        // int h_length (4 bytes)
        // char** h_addr_list (8 bytes)
        // Total: 32 bytes

        // Calculate total size needed
        size_t name_len = strlen(he->h_name) + 1;
        size_t total_size = 32 + name_len;

        // Count addresses
        int addr_count = 0;
        for (char** p = he->h_addr_list; *p; p++) addr_count++;

        // Space for address list pointers + null terminator
        total_size += (addr_count + 1) * 8;
        // Space for addresses
        total_size += addr_count * he->h_length;
        // Space for empty aliases list (just null pointer)
        total_size += 8;

        uint64_t base = emu.memory().heap().allocate(total_size, 8);
        uint64_t offset = 32;

        // Copy h_name
        uint64_t h_name_ptr = base + offset;
        emu.mem_write(h_name_ptr, he->h_name, name_len);
        offset += name_len;

        // Create empty aliases list
        uint64_t h_aliases_ptr = base + offset;
        uint64_t null_ptr = 0;
        emu.mem_write(h_aliases_ptr, &null_ptr, 8);
        offset += 8;

        // Create address list
        uint64_t h_addr_list_ptr = base + offset;
        offset += (addr_count + 1) * 8;

        // Copy addresses and build pointer list
        for (int i = 0; i < addr_count; i++) {
            uint64_t addr_ptr = base + offset;
            emu.mem_write(addr_ptr, he->h_addr_list[i], he->h_length);
            emu.mem_write(h_addr_list_ptr + i * 8, &addr_ptr, 8);
            offset += he->h_length;
        }
        // Null terminate the list
        emu.mem_write(h_addr_list_ptr + addr_count * 8, &null_ptr, 8);

        // Write hostent structure
        emu.mem_write(base + 0, &h_name_ptr, 8);
        emu.mem_write(base + 8, &h_aliases_ptr, 8);
        int32_t h_addrtype = he->h_addrtype;
        int32_t h_length = he->h_length;
        emu.mem_write(base + 16, &h_addrtype, 4);
        emu.mem_write(base + 20, &h_length, 4);
        emu.mem_write(base + 24, &h_addr_list_ptr, 8);

        if (emu.is_debug()) {
            EMU_LOG << "[HLE] gethostbyname: success, returning hostent at 0x"
                      << std::hex << base << std::dec << std::endl;
        }

        set_reg(emu, UC_ARM64_REG_X0, base);
    });

    hle.register_function("htons", [](Emulator& emu) {
        uint16_t hostshort = get_reg(emu, UC_ARM64_REG_X0);
        set_reg(emu, UC_ARM64_REG_X0, htons(hostshort));
    });

    hle.register_function("htonl", [](Emulator& emu) {
        uint32_t hostlong = get_reg(emu, UC_ARM64_REG_X0);
        set_reg(emu, UC_ARM64_REG_X0, htonl(hostlong));
    });

    hle.register_function("ntohs", [](Emulator& emu) {
        uint16_t netshort = get_reg(emu, UC_ARM64_REG_X0);
        set_reg(emu, UC_ARM64_REG_X0, ntohs(netshort));
    });

    hle.register_function("ntohl", [](Emulator& emu) {
        uint32_t netlong = get_reg(emu, UC_ARM64_REG_X0);
        set_reg(emu, UC_ARM64_REG_X0, ntohl(netlong));
    });

    hle.register_function("inet_aton", [](Emulator& emu) {
        uint64_t cp = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t inp = get_reg(emu, UC_ARM64_REG_X1);

        std::string addr = read_string(emu, cp);
        struct in_addr in;
        int result = inet_aton(addr.c_str(), &in);
        if (result && inp) {
            emu.mem_write(inp, &in, sizeof(in));
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });

    hle.register_function("inet_ntoa", [](Emulator& emu) {
        uint64_t in_addr_val = get_reg(emu, UC_ARM64_REG_X0);
        struct in_addr in;
        in.s_addr = in_addr_val;
        char* result = inet_ntoa(in);
        uint64_t ptr = emu.memory().heap().allocate(strlen(result) + 1, 8);
        emu.mem_write(ptr, result, strlen(result) + 1);
        set_reg(emu, UC_ARM64_REG_X0, ptr);
    });

    // ========================================================================
    // Socket control messages
    // ========================================================================

    // sendmsg - send a message on a socket
    hle.register_function("sendmsg", [](Emulator& emu) {
        int sockfd = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t msg_ptr = get_reg(emu, UC_ARM64_REG_X1);
        int flags = get_reg(emu, UC_ARM64_REG_X2);

        if (!msg_ptr) {
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        // Read msghdr structure from emulated memory
        // ARM64 Android msghdr layout:
        // void *msg_name (8 bytes)
        // socklen_t msg_namelen (4 bytes + 4 padding)
        // struct iovec *msg_iov (8 bytes)
        // size_t msg_iovlen (8 bytes)
        // void *msg_control (8 bytes)
        // size_t msg_controllen (8 bytes)
        // int msg_flags (4 bytes)
        uint8_t msghdr_buf[56];
        if (!emu.mem_read(msg_ptr, msghdr_buf, 56)) {
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        uint64_t msg_name_ptr = *reinterpret_cast<uint64_t*>(msghdr_buf + 0);
        uint32_t msg_namelen = *reinterpret_cast<uint32_t*>(msghdr_buf + 8);
        uint64_t msg_iov_ptr = *reinterpret_cast<uint64_t*>(msghdr_buf + 16);
        uint64_t msg_iovlen = *reinterpret_cast<uint64_t*>(msghdr_buf + 24);

        // Build host msghdr
        struct msghdr msg = {};
        std::vector<uint8_t> name_buf;
        if (msg_name_ptr && msg_namelen > 0) {
            name_buf.resize(msg_namelen);
            emu.mem_read(msg_name_ptr, name_buf.data(), msg_namelen);
            msg.msg_name = name_buf.data();
            msg.msg_namelen = msg_namelen;
        }

        // Read iovec array
        std::vector<struct iovec> iovecs(msg_iovlen);
        std::vector<std::vector<uint8_t>> iov_bufs(msg_iovlen);
        for (size_t i = 0; i < msg_iovlen; i++) {
            uint8_t iov_buf[16];  // iovec: void* iov_base (8), size_t iov_len (8)
            emu.mem_read(msg_iov_ptr + i * 16, iov_buf, 16);
            uint64_t iov_base = *reinterpret_cast<uint64_t*>(iov_buf);
            uint64_t iov_len = *reinterpret_cast<uint64_t*>(iov_buf + 8);

            iov_bufs[i].resize(iov_len);
            if (iov_base && iov_len > 0) {
                emu.mem_read(iov_base, iov_bufs[i].data(), iov_len);
            }
            iovecs[i].iov_base = iov_bufs[i].data();
            iovecs[i].iov_len = iov_len;
        }
        msg.msg_iov = iovecs.data();
        msg.msg_iovlen = msg_iovlen;

        ssize_t result = ::sendmsg(sockfd, &msg, flags);
        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(result));
    });

    // recvmsg - receive a message from a socket
    hle.register_function("recvmsg", [](Emulator& emu) {
        int sockfd = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t msg_ptr = get_reg(emu, UC_ARM64_REG_X1);
        int flags = get_reg(emu, UC_ARM64_REG_X2);

        if (!msg_ptr) {
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        // Read msghdr structure
        uint8_t msghdr_buf[56];
        if (!emu.mem_read(msg_ptr, msghdr_buf, 56)) {
            set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(-1));
            return;
        }

        uint64_t msg_name_ptr = *reinterpret_cast<uint64_t*>(msghdr_buf + 0);
        uint32_t msg_namelen = *reinterpret_cast<uint32_t*>(msghdr_buf + 8);
        uint64_t msg_iov_ptr = *reinterpret_cast<uint64_t*>(msghdr_buf + 16);
        uint64_t msg_iovlen = *reinterpret_cast<uint64_t*>(msghdr_buf + 24);

        // Build host msghdr
        struct msghdr msg = {};
        std::vector<uint8_t> name_buf(msg_namelen > 0 ? msg_namelen : 128);
        msg.msg_name = name_buf.data();
        msg.msg_namelen = name_buf.size();

        // Read iovec array and allocate buffers
        std::vector<struct iovec> iovecs(msg_iovlen);
        std::vector<std::vector<uint8_t>> iov_bufs(msg_iovlen);
        std::vector<uint64_t> iov_bases(msg_iovlen);
        for (size_t i = 0; i < msg_iovlen; i++) {
            uint8_t iov_buf[16];
            emu.mem_read(msg_iov_ptr + i * 16, iov_buf, 16);
            iov_bases[i] = *reinterpret_cast<uint64_t*>(iov_buf);
            uint64_t iov_len = *reinterpret_cast<uint64_t*>(iov_buf + 8);

            iov_bufs[i].resize(iov_len);
            iovecs[i].iov_base = iov_bufs[i].data();
            iovecs[i].iov_len = iov_len;
        }
        msg.msg_iov = iovecs.data();
        msg.msg_iovlen = msg_iovlen;

        ssize_t result = ::recvmsg(sockfd, &msg, flags);

        if (result >= 0) {
            // Write received data back to emulated memory
            for (size_t i = 0; i < msg_iovlen; i++) {
                if (iov_bases[i] && iovecs[i].iov_len > 0) {
                    emu.mem_write(iov_bases[i], iov_bufs[i].data(), iovecs[i].iov_len);
                }
            }
            // Write back msg_name if provided
            if (msg_name_ptr && msg.msg_namelen > 0) {
                emu.mem_write(msg_name_ptr, name_buf.data(), msg.msg_namelen);
                // Update msg_namelen in msghdr
                uint32_t namelen = msg.msg_namelen;
                emu.mem_write(msg_ptr + 8, &namelen, 4);
            }
            // Update msg_flags
            int32_t msg_flags = msg.msg_flags;
            emu.mem_write(msg_ptr + 48, &msg_flags, 4);
        }

        set_reg(emu, UC_ARM64_REG_X0, static_cast<uint64_t>(result));
    });

    hle.register_function("accept4", [](Emulator& emu) {
        int sockfd = get_reg(emu, UC_ARM64_REG_X0);
        uint64_t addr_ptr = get_reg(emu, UC_ARM64_REG_X1);
        uint64_t addrlen_ptr = get_reg(emu, UC_ARM64_REG_X2);
        // int flags = get_reg(emu, UC_ARM64_REG_X3);

        struct sockaddr_storage addr;
        socklen_t addrlen = sizeof(addr);

        int result = accept(sockfd, (struct sockaddr*)&addr, &addrlen);

        if (result >= 0 && addr_ptr) {
            emu.mem_write(addr_ptr, &addr, addrlen);
            if (addrlen_ptr) {
                emu.mem_write(addrlen_ptr, &addrlen, sizeof(addrlen));
            }
        }
        set_reg(emu, UC_ARM64_REG_X0, result);
    });
}

} // namespace cross_shim
