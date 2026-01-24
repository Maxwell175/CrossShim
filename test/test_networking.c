/**
 * Networking Test Suite for Android Emulator
 * Pure C using only libc - Tests socket operations, DNS, polling.
 * Designed to be compiled with Android NDK for ARM64 target.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <sys/select.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include <pthread.h>
#include <stddef.h>
#include <sys/time.h>

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST_ASSERT(cond, msg) do { \
    if (cond) { \
        tests_passed++; \
        printf("  [PASS] %s\n", msg); \
    } else { \
        tests_failed++; \
        printf("  [FAIL] %s (errno=%d: %s)\n", msg, errno, strerror(errno)); \
    } \
} while(0)

#define TEST_ASSERT_MSG(cond, name, ...) do { \
    if (cond) { \
        printf("  [PASS] %s\n", name); \
        tests_passed++; \
    } else { \
        printf("  [FAIL] %s: ", name); \
        printf(__VA_ARGS__); \
        printf("\n"); \
        tests_failed++; \
    } \
} while(0)

/* ========================================================================== */
/* Structure Layout Validation Tests                                          */
/* These tests verify that the ARM64 bionic libc structures have the expected */
/* sizes and field offsets. If these fail, the emulator's structure           */
/* conversion code may be incorrect.                                          */
/* ========================================================================== */
static void test_structure_layouts(void) {
    printf("\n=== Structure Layout Validation ===\n");

    /* struct pollfd - ARM64 bionic: 8 bytes */
    TEST_ASSERT_MSG(sizeof(struct pollfd) == 8,
        "sizeof(struct pollfd) == 8",
        "got %zu", sizeof(struct pollfd));
    TEST_ASSERT_MSG(offsetof(struct pollfd, fd) == 0,
        "offsetof(pollfd, fd) == 0",
        "got %zu", offsetof(struct pollfd, fd));
    TEST_ASSERT_MSG(offsetof(struct pollfd, events) == 4,
        "offsetof(pollfd, events) == 4",
        "got %zu", offsetof(struct pollfd, events));
    TEST_ASSERT_MSG(offsetof(struct pollfd, revents) == 6,
        "offsetof(pollfd, revents) == 6",
        "got %zu", offsetof(struct pollfd, revents));

    /* struct epoll_event - ARM64 bionic: 16 bytes (NOT packed like x86_64 glibc)
     * Layout: events (4), padding (4), data (8)
     */
    TEST_ASSERT_MSG(sizeof(struct epoll_event) == 16,
        "sizeof(struct epoll_event) == 16",
        "got %zu", sizeof(struct epoll_event));
    TEST_ASSERT_MSG(offsetof(struct epoll_event, events) == 0,
        "offsetof(epoll_event, events) == 0",
        "got %zu", offsetof(struct epoll_event, events));
    TEST_ASSERT_MSG(offsetof(struct epoll_event, data) == 8,
        "offsetof(epoll_event, data) == 8",
        "got %zu", offsetof(struct epoll_event, data));

    /* struct timeval - ARM64 bionic: 16 bytes */
    TEST_ASSERT_MSG(sizeof(struct timeval) == 16,
        "sizeof(struct timeval) == 16",
        "got %zu", sizeof(struct timeval));

    /* struct sockaddr_in - should be 16 bytes */
    TEST_ASSERT_MSG(sizeof(struct sockaddr_in) == 16,
        "sizeof(struct sockaddr_in) == 16",
        "got %zu", sizeof(struct sockaddr_in));

    /* struct sockaddr_in6 - should be 28 bytes */
    TEST_ASSERT_MSG(sizeof(struct sockaddr_in6) == 28,
        "sizeof(struct sockaddr_in6) == 28",
        "got %zu", sizeof(struct sockaddr_in6));

    /* struct addrinfo - ARM64 bionic: 48 bytes
     * Note: bionic has ai_canonname BEFORE ai_addr (different from glibc!)
     */
    TEST_ASSERT_MSG(sizeof(struct addrinfo) == 48,
        "sizeof(struct addrinfo) == 48",
        "got %zu", sizeof(struct addrinfo));
    TEST_ASSERT_MSG(offsetof(struct addrinfo, ai_flags) == 0,
        "offsetof(addrinfo, ai_flags) == 0",
        "got %zu", offsetof(struct addrinfo, ai_flags));
    TEST_ASSERT_MSG(offsetof(struct addrinfo, ai_family) == 4,
        "offsetof(addrinfo, ai_family) == 4",
        "got %zu", offsetof(struct addrinfo, ai_family));
    TEST_ASSERT_MSG(offsetof(struct addrinfo, ai_socktype) == 8,
        "offsetof(addrinfo, ai_socktype) == 8",
        "got %zu", offsetof(struct addrinfo, ai_socktype));
    TEST_ASSERT_MSG(offsetof(struct addrinfo, ai_protocol) == 12,
        "offsetof(addrinfo, ai_protocol) == 12",
        "got %zu", offsetof(struct addrinfo, ai_protocol));
    TEST_ASSERT_MSG(offsetof(struct addrinfo, ai_addrlen) == 16,
        "offsetof(addrinfo, ai_addrlen) == 16",
        "got %zu", offsetof(struct addrinfo, ai_addrlen));
    /* ai_canonname at offset 24 in bionic (before ai_addr) */
    TEST_ASSERT_MSG(offsetof(struct addrinfo, ai_canonname) == 24,
        "offsetof(addrinfo, ai_canonname) == 24",
        "got %zu", offsetof(struct addrinfo, ai_canonname));
    /* ai_addr at offset 32 in bionic (after ai_canonname) */
    TEST_ASSERT_MSG(offsetof(struct addrinfo, ai_addr) == 32,
        "offsetof(addrinfo, ai_addr) == 32",
        "got %zu", offsetof(struct addrinfo, ai_addr));
    TEST_ASSERT_MSG(offsetof(struct addrinfo, ai_next) == 40,
        "offsetof(addrinfo, ai_next) == 40",
        "got %zu", offsetof(struct addrinfo, ai_next));
}

/* ========================================================================== */
/* Structure Field Value Tests                                                */
/* These tests verify that structure fields are correctly read/written by     */
/* the emulator's HLE functions.                                              */
/* ========================================================================== */
static void test_structure_field_values(void) {
    int sock, epfd, ret;
    struct pollfd pfd;
    struct epoll_event ev, events[1];
    struct timeval tv;

    printf("\n=== Structure Field Value Tests ===\n");

    /* Test poll correctly updates revents field */
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock >= 0) {
        memset(&pfd, 0xAA, sizeof(pfd));  /* Fill with pattern */
        pfd.fd = sock;
        pfd.events = POLLOUT;
        pfd.revents = (short)0x7FFF;  /* Should be cleared/updated by poll */

        ret = poll(&pfd, 1, 0);
        TEST_ASSERT(ret >= 0, "poll for field test");
        /* revents should be updated (socket should be writable) */
        TEST_ASSERT(pfd.fd == sock, "poll preserves fd field");
        TEST_ASSERT(pfd.events == POLLOUT, "poll preserves events field");
        /* revents should have been modified from 0x7FFF */
        TEST_ASSERT(pfd.revents != (short)0x7FFF || ret == 0, "poll updates revents field");

        close(sock);
    }

    /* Test epoll correctly handles epoll_event structure */
    epfd = epoll_create(1);
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (epfd >= 0 && sock >= 0) {
        memset(&ev, 0, sizeof(ev));
        ev.events = EPOLLIN | EPOLLOUT;
        ev.data.fd = sock;
        ev.data.u64 = 0x123456789ABCDEF0ULL;  /* Test 64-bit data preservation */

        ret = epoll_ctl(epfd, EPOLL_CTL_ADD, sock, &ev);
        TEST_ASSERT(ret == 0, "epoll_ctl for field test");

        memset(events, 0xAA, sizeof(events));
        ret = epoll_wait(epfd, events, 1, 0);
        if (ret > 0) {
            /* Verify data.u64 is preserved correctly */
            TEST_ASSERT(events[0].data.u64 == 0x123456789ABCDEF0ULL,
                "epoll_wait preserves data.u64 field");
        }

        close(sock);
        close(epfd);
    }

    /* Test select correctly reads timeval structure */
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock >= 0) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(sock, &readfds);

        memset(&tv, 0xAA, sizeof(tv));  /* Fill with pattern */
        tv.tv_sec = 0;
        tv.tv_usec = 1000;  /* 1ms timeout */

        ret = select(sock + 1, &readfds, NULL, NULL, &tv);
        TEST_ASSERT(ret >= 0, "select for field test");
        /* tv may be modified by select to show remaining time */
        TEST_ASSERT(tv.tv_sec >= 0, "select tv_sec field valid after call");
        TEST_ASSERT(tv.tv_usec >= 0 && tv.tv_usec < 1000000, "select tv_usec field valid after call");

        close(sock);
    }
}

/* ========================================================================== */
/* Socket Creation Tests                                                      */
/* ========================================================================== */

static void test_socket_creation(void) {
    int tcp_sock, udp_sock, tcp6_sock, udp6_sock;
    
    printf("\n=== Socket Creation Tests ===\n");
    
    tcp_sock = socket(AF_INET, SOCK_STREAM, 0);
    TEST_ASSERT(tcp_sock >= 0, "Create TCP socket (AF_INET, SOCK_STREAM)");
    if (tcp_sock >= 0) close(tcp_sock);
    
    udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    TEST_ASSERT(udp_sock >= 0, "Create UDP socket (AF_INET, SOCK_DGRAM)");
    if (udp_sock >= 0) close(udp_sock);
    
    tcp6_sock = socket(AF_INET6, SOCK_STREAM, 0);
    TEST_ASSERT(tcp6_sock >= 0, "Create IPv6 TCP socket");
    if (tcp6_sock >= 0) close(tcp6_sock);
    
    udp6_sock = socket(AF_INET6, SOCK_DGRAM, 0);
    TEST_ASSERT(udp6_sock >= 0, "Create IPv6 UDP socket");
    if (udp6_sock >= 0) close(udp6_sock);
}

/* ========================================================================== */
/* Socket Options Tests                                                       */
/* ========================================================================== */

static void test_socket_options(void) {
    int sock, ret, reuse, got_reuse, keepalive, rcvbuf, sndbuf, nodelay;
    socklen_t len;
    
    printf("\n=== Socket Options Tests ===\n");
    
    sock = socket(AF_INET, SOCK_STREAM, 0);
    TEST_ASSERT(sock >= 0, "Create socket for options test");
    if (sock < 0) return;
    
    reuse = 1;
    ret = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    TEST_ASSERT(ret == 0, "Set SO_REUSEADDR");
    
    got_reuse = 0;
    len = sizeof(got_reuse);
    ret = getsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &got_reuse, &len);
    TEST_ASSERT(ret == 0 && got_reuse != 0, "Get SO_REUSEADDR");
    
    keepalive = 1;
    ret = setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(keepalive));
    TEST_ASSERT(ret == 0, "Set SO_KEEPALIVE");
    
    rcvbuf = 65536;
    ret = setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
    TEST_ASSERT(ret == 0, "Set SO_RCVBUF");
    
    sndbuf = 65536;
    ret = setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    TEST_ASSERT(ret == 0, "Set SO_SNDBUF");
    
    nodelay = 1;
    ret = setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));
    TEST_ASSERT(ret == 0, "Set TCP_NODELAY");
    
    close(sock);
}

/* ========================================================================== */
/* Bind and Listen Tests                                                      */
/* ========================================================================== */

static void test_bind_listen(void) {
    int sock, ret, reuse;
    struct sockaddr_in addr;
    socklen_t addr_len;
    
    printf("\n=== Bind and Listen Tests ===\n");
    
    sock = socket(AF_INET, SOCK_STREAM, 0);
    TEST_ASSERT(sock >= 0, "Create socket for bind test");
    if (sock < 0) return;
    
    reuse = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(0);
    
    ret = bind(sock, (struct sockaddr*)&addr, sizeof(addr));
    TEST_ASSERT(ret == 0, "Bind to loopback with ephemeral port");
    
    addr_len = sizeof(addr);
    ret = getsockname(sock, (struct sockaddr*)&addr, &addr_len);
    TEST_ASSERT(ret == 0, "Get socket name after bind");
    printf("    Bound to port: %d\n", ntohs(addr.sin_port));
    
    ret = listen(sock, 5);
    TEST_ASSERT(ret == 0, "Listen with backlog 5");
    
    close(sock);
}

/* ========================================================================== */
/* DNS Resolution Tests                                                       */
/* ========================================================================== */

static void test_dns_resolution(void) {
    struct in_addr ipv4_addr;
    struct in6_addr ipv6_addr;
    char ipv4_str[INET_ADDRSTRLEN];
    char ipv6_str[INET6_ADDRSTRLEN];
    const char *result;
    int ret;
    in_addr_t addr;
    struct addrinfo hints, *res;
    
    printf("\n=== DNS Resolution Tests ===\n");

    ret = inet_pton(AF_INET, "127.0.0.1", &ipv4_addr);
    TEST_ASSERT(ret == 1, "inet_pton IPv4 (127.0.0.1)");

    result = inet_ntop(AF_INET, &ipv4_addr, ipv4_str, sizeof(ipv4_str));
    TEST_ASSERT(result != NULL && strcmp(ipv4_str, "127.0.0.1") == 0, "inet_ntop IPv4");

    ret = inet_pton(AF_INET6, "::1", &ipv6_addr);
    TEST_ASSERT(ret == 1, "inet_pton IPv6 (::1)");

    result = inet_ntop(AF_INET6, &ipv6_addr, ipv6_str, sizeof(ipv6_str));
    TEST_ASSERT(result != NULL, "inet_ntop IPv6");

    addr = inet_addr("192.168.1.1");
    TEST_ASSERT(addr != INADDR_NONE, "inet_addr (192.168.1.1)");

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    ret = getaddrinfo("127.0.0.1", "8080", &hints, &res);
    TEST_ASSERT(ret == 0 && res != NULL, "getaddrinfo numeric (127.0.0.1:8080)");
    if (ret == 0) freeaddrinfo(res);
}

/* ========================================================================== */
/* Poll Tests                                                                 */
/* ========================================================================== */

static void test_poll(void) {
    int sock, ret;
    struct pollfd pfd;

    printf("\n=== Poll Tests ===\n");

    sock = socket(AF_INET, SOCK_STREAM, 0);
    TEST_ASSERT(sock >= 0, "Create socket for poll test");
    if (sock < 0) return;

    pfd.fd = sock;
    pfd.events = POLLOUT;
    pfd.revents = 0;

    ret = poll(&pfd, 1, 0);
    TEST_ASSERT(ret >= 0, "poll() with timeout 0");

    ret = poll(&pfd, 1, 10);
    TEST_ASSERT(ret >= 0, "poll() with timeout 10ms");

    close(sock);
}

/* ========================================================================== */
/* Select Tests                                                               */
/* ========================================================================== */

static void test_select(void) {
    int sock, ret;
    fd_set readfds, writefds;
    struct timeval tv;

    printf("\n=== Select Tests ===\n");

    sock = socket(AF_INET, SOCK_STREAM, 0);
    TEST_ASSERT(sock >= 0, "Create socket for select test");
    if (sock < 0) return;

    FD_ZERO(&readfds);
    FD_ZERO(&writefds);
    FD_SET(sock, &writefds);

    tv.tv_sec = 0;
    tv.tv_usec = 0;

    ret = select(sock + 1, &readfds, &writefds, NULL, &tv);
    TEST_ASSERT(ret >= 0, "select() with timeout 0");

    tv.tv_sec = 0;
    tv.tv_usec = 10000;

    FD_ZERO(&readfds);
    FD_SET(sock, &readfds);

    ret = select(sock + 1, &readfds, NULL, NULL, &tv);
    TEST_ASSERT(ret >= 0, "select() with timeout 10ms");

    close(sock);
}

/* ========================================================================== */
/* Epoll Tests                                                                */
/* ========================================================================== */

static void test_epoll(void) {
    int epfd, sock, ret;
    struct epoll_event ev, events[10];

    printf("\n=== Epoll Tests ===\n");

    epfd = epoll_create(10);
    TEST_ASSERT(epfd >= 0, "epoll_create()");
    if (epfd < 0) return;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    TEST_ASSERT(sock >= 0, "Create socket for epoll test");
    if (sock < 0) { close(epfd); return; }

    ev.events = EPOLLIN | EPOLLOUT;
    ev.data.fd = sock;

    ret = epoll_ctl(epfd, EPOLL_CTL_ADD, sock, &ev);
    TEST_ASSERT(ret == 0, "epoll_ctl EPOLL_CTL_ADD");

    ret = epoll_wait(epfd, events, 10, 0);
    TEST_ASSERT(ret >= 0, "epoll_wait with timeout 0");

    ret = epoll_wait(epfd, events, 10, 10);
    TEST_ASSERT(ret >= 0, "epoll_wait with timeout 10ms");

    ret = epoll_ctl(epfd, EPOLL_CTL_DEL, sock, NULL);
    TEST_ASSERT(ret == 0, "epoll_ctl EPOLL_CTL_DEL");

    close(sock);
    close(epfd);
}

/* ========================================================================== */
/* Non-blocking Socket Tests                                                  */
/* ========================================================================== */

static void test_nonblocking(void) {
    int sock, flags, ret;

    printf("\n=== Non-blocking Socket Tests ===\n");

    sock = socket(AF_INET, SOCK_STREAM, 0);
    TEST_ASSERT(sock >= 0, "Create socket for non-blocking test");
    if (sock < 0) return;

    flags = fcntl(sock, F_GETFL, 0);
    TEST_ASSERT(flags >= 0, "fcntl F_GETFL");

    ret = fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    TEST_ASSERT(ret == 0, "fcntl F_SETFL O_NONBLOCK");

    flags = fcntl(sock, F_GETFL, 0);
    TEST_ASSERT((flags & O_NONBLOCK) != 0, "Verify O_NONBLOCK is set");

    close(sock);
}

/* ========================================================================== */
/* UDP Send/Recv Tests                                                        */
/* ========================================================================== */

static void test_udp_sendrecv(void) {
    int sock1, sock2, ret;
    struct sockaddr_in addr1, addr2;
    socklen_t addr_len;
    char send_buf[] = "Hello UDP";
    char recv_buf[64];
    ssize_t n;

    printf("\n=== UDP Send/Recv Tests ===\n");

    sock1 = socket(AF_INET, SOCK_DGRAM, 0);
    TEST_ASSERT(sock1 >= 0, "Create UDP socket 1");
    if (sock1 < 0) return;

    sock2 = socket(AF_INET, SOCK_DGRAM, 0);
    TEST_ASSERT(sock2 >= 0, "Create UDP socket 2");
    if (sock2 < 0) { close(sock1); return; }

    memset(&addr1, 0, sizeof(addr1));
    addr1.sin_family = AF_INET;
    addr1.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr1.sin_port = htons(0);

    ret = bind(sock1, (struct sockaddr*)&addr1, sizeof(addr1));
    TEST_ASSERT(ret == 0, "Bind UDP socket 1");

    addr_len = sizeof(addr1);
    getsockname(sock1, (struct sockaddr*)&addr1, &addr_len);

    memset(&addr2, 0, sizeof(addr2));
    addr2.sin_family = AF_INET;
    addr2.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr2.sin_port = htons(0);

    ret = bind(sock2, (struct sockaddr*)&addr2, sizeof(addr2));
    TEST_ASSERT(ret == 0, "Bind UDP socket 2");

    n = sendto(sock2, send_buf, strlen(send_buf), 0,
               (struct sockaddr*)&addr1, sizeof(addr1));
    TEST_ASSERT(n == (ssize_t)strlen(send_buf), "sendto UDP");

    memset(recv_buf, 0, sizeof(recv_buf));
    addr_len = sizeof(addr2);
    n = recvfrom(sock1, recv_buf, sizeof(recv_buf), 0,
                 (struct sockaddr*)&addr2, &addr_len);
    TEST_ASSERT(n > 0 && strcmp(recv_buf, send_buf) == 0, "recvfrom UDP");

    close(sock1);
    close(sock2);
}

/* ========================================================================== */
/* TCP Loopback Test (connect to self)                                        */
/* ========================================================================== */

struct server_args {
    int listen_sock;
    int client_sock;
    int port;
};

static void *tcp_server_thread(void *arg) {
    struct server_args *sa = (struct server_args *)arg;
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    char buf[64];
    ssize_t n;

    sa->client_sock = accept(sa->listen_sock, (struct sockaddr*)&client_addr, &addr_len);
    if (sa->client_sock >= 0) {
        n = recv(sa->client_sock, buf, sizeof(buf), 0);
        if (n > 0) {
            send(sa->client_sock, buf, n, 0);
        }
        close(sa->client_sock);
    }
    return NULL;
}

static void test_tcp_loopback(void) {
    int listen_sock, client_sock, ret, reuse;
    struct sockaddr_in addr;
    socklen_t addr_len;
    pthread_t server_thread;
    struct server_args sa;
    char send_buf[] = "Hello TCP";
    char recv_buf[64];
    ssize_t n;

    printf("\n=== TCP Loopback Tests ===\n");

    listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    TEST_ASSERT(listen_sock >= 0, "Create listen socket");
    if (listen_sock < 0) return;

    reuse = 1;
    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(0);

    ret = bind(listen_sock, (struct sockaddr*)&addr, sizeof(addr));
    TEST_ASSERT(ret == 0, "Bind listen socket");
    if (ret != 0) { close(listen_sock); return; }

    addr_len = sizeof(addr);
    getsockname(listen_sock, (struct sockaddr*)&addr, &addr_len);

    ret = listen(listen_sock, 1);
    TEST_ASSERT(ret == 0, "Listen on socket");

    sa.listen_sock = listen_sock;
    sa.client_sock = -1;
    sa.port = ntohs(addr.sin_port);

    pthread_create(&server_thread, NULL, tcp_server_thread, &sa);

    client_sock = socket(AF_INET, SOCK_STREAM, 0);
    TEST_ASSERT(client_sock >= 0, "Create client socket");

    ret = connect(client_sock, (struct sockaddr*)&addr, sizeof(addr));
    TEST_ASSERT(ret == 0, "Connect to server");

    n = send(client_sock, send_buf, strlen(send_buf), 0);
    TEST_ASSERT(n == (ssize_t)strlen(send_buf), "Send data to server");

    memset(recv_buf, 0, sizeof(recv_buf));
    n = recv(client_sock, recv_buf, sizeof(recv_buf), 0);
    TEST_ASSERT(n > 0 && strcmp(recv_buf, send_buf) == 0, "Recv echo from server");

    close(client_sock);
    pthread_join(server_thread, NULL);
    close(listen_sock);
}

/* ========================================================================== */
/* TCP Multiple Messages Test                                                 */
/* ========================================================================== */

static void *tcp_multi_msg_server(void *arg) {
    struct server_args *sa = (struct server_args *)arg;
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    char buf[64];
    ssize_t n;
    int i;

    sa->client_sock = accept(sa->listen_sock, (struct sockaddr*)&client_addr, &addr_len);
    if (sa->client_sock >= 0) {
        // Echo 5 messages
        for (i = 0; i < 5; i++) {
            n = recv(sa->client_sock, buf, sizeof(buf), 0);
            if (n > 0) {
                send(sa->client_sock, buf, n, 0);
            }
        }
        close(sa->client_sock);
    }
    return NULL;
}

static void test_tcp_multi_messages(void) {
    int listen_sock, client_sock, ret, reuse;
    struct sockaddr_in addr;
    socklen_t addr_len;
    pthread_t server_thread;
    struct server_args sa;
    char send_buf[64];
    char recv_buf[64];
    ssize_t n;
    int i, all_ok = 1;

    printf("\n=== TCP Multiple Messages Test ===\n");

    listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    TEST_ASSERT(listen_sock >= 0, "Create listen socket");
    if (listen_sock < 0) return;

    reuse = 1;
    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(0);

    ret = bind(listen_sock, (struct sockaddr*)&addr, sizeof(addr));
    TEST_ASSERT(ret == 0, "Bind listen socket");
    if (ret != 0) { close(listen_sock); return; }

    addr_len = sizeof(addr);
    getsockname(listen_sock, (struct sockaddr*)&addr, &addr_len);

    ret = listen(listen_sock, 1);
    TEST_ASSERT(ret == 0, "Listen on socket");

    sa.listen_sock = listen_sock;
    sa.client_sock = -1;
    sa.port = ntohs(addr.sin_port);

    pthread_create(&server_thread, NULL, tcp_multi_msg_server, &sa);

    client_sock = socket(AF_INET, SOCK_STREAM, 0);
    TEST_ASSERT(client_sock >= 0, "Create client socket");

    ret = connect(client_sock, (struct sockaddr*)&addr, sizeof(addr));
    TEST_ASSERT(ret == 0, "Connect to server");

    // Send and receive 5 messages
    for (i = 0; i < 5; i++) {
        snprintf(send_buf, sizeof(send_buf), "Message %d", i);
        n = send(client_sock, send_buf, strlen(send_buf) + 1, 0);
        if (n != (ssize_t)(strlen(send_buf) + 1)) {
            all_ok = 0;
            break;
        }

        memset(recv_buf, 0, sizeof(recv_buf));
        n = recv(client_sock, recv_buf, sizeof(recv_buf), 0);
        if (n <= 0 || strcmp(recv_buf, send_buf) != 0) {
            all_ok = 0;
            break;
        }
    }
    TEST_ASSERT(all_ok, "Send/recv 5 messages");

    close(client_sock);
    pthread_join(server_thread, NULL);
    close(listen_sock);
}

/* ========================================================================== */
/* TCP Ping-Pong Test (Bidirectional)                                         */
/* ========================================================================== */

struct pingpong_args {
    int listen_sock;
    int client_sock;
    int rounds;
    int success;
};

static void *tcp_pingpong_server(void *arg) {
    struct pingpong_args *pa = (struct pingpong_args *)arg;
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    char buf[64];
    ssize_t n;
    int i;

    pa->success = 0;
    pa->client_sock = accept(pa->listen_sock, (struct sockaddr*)&client_addr, &addr_len);
    if (pa->client_sock < 0) return NULL;

    for (i = 0; i < pa->rounds; i++) {
        // Receive ping
        n = recv(pa->client_sock, buf, sizeof(buf), 0);
        if (n <= 0) break;

        // Send pong
        snprintf(buf, sizeof(buf), "pong%d", i);
        n = send(pa->client_sock, buf, strlen(buf) + 1, 0);
        if (n <= 0) break;
    }

    if (i == pa->rounds) pa->success = 1;
    close(pa->client_sock);
    return NULL;
}

static void test_tcp_pingpong(void) {
    int listen_sock, client_sock, ret, reuse;
    struct sockaddr_in addr;
    socklen_t addr_len;
    pthread_t server_thread;
    struct pingpong_args pa;
    char send_buf[64];
    char recv_buf[64];
    ssize_t n;
    int i, client_ok = 1;
    int rounds = 3;

    printf("\n=== TCP Ping-Pong Test ===\n");

    listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    TEST_ASSERT(listen_sock >= 0, "Create listen socket");
    if (listen_sock < 0) return;

    reuse = 1;
    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(0);

    ret = bind(listen_sock, (struct sockaddr*)&addr, sizeof(addr));
    TEST_ASSERT(ret == 0, "Bind listen socket");
    if (ret != 0) { close(listen_sock); return; }

    addr_len = sizeof(addr);
    getsockname(listen_sock, (struct sockaddr*)&addr, &addr_len);

    ret = listen(listen_sock, 1);
    TEST_ASSERT(ret == 0, "Listen on socket");

    pa.listen_sock = listen_sock;
    pa.client_sock = -1;
    pa.rounds = rounds;
    pa.success = 0;

    pthread_create(&server_thread, NULL, tcp_pingpong_server, &pa);

    client_sock = socket(AF_INET, SOCK_STREAM, 0);
    TEST_ASSERT(client_sock >= 0, "Create client socket");

    ret = connect(client_sock, (struct sockaddr*)&addr, sizeof(addr));
    TEST_ASSERT(ret == 0, "Connect to server");

    // Ping-pong rounds
    for (i = 0; i < rounds; i++) {
        // Send ping
        snprintf(send_buf, sizeof(send_buf), "ping%d", i);
        n = send(client_sock, send_buf, strlen(send_buf) + 1, 0);
        if (n <= 0) { client_ok = 0; break; }

        // Receive pong
        memset(recv_buf, 0, sizeof(recv_buf));
        n = recv(client_sock, recv_buf, sizeof(recv_buf), 0);
        snprintf(send_buf, sizeof(send_buf), "pong%d", i);
        if (n <= 0 || strcmp(recv_buf, send_buf) != 0) { client_ok = 0; break; }
    }

    close(client_sock);
    pthread_join(server_thread, NULL);
    close(listen_sock);

    TEST_ASSERT(client_ok && pa.success, "Ping-pong bidirectional communication");
}

/* ========================================================================== */
/* TCP Large Data Transfer Test                                               */
/* ========================================================================== */

#define LARGE_DATA_SIZE 4096

struct large_data_args {
    int listen_sock;
    int client_sock;
    int bytes_received;
};

static void *tcp_large_data_server(void *arg) {
    struct large_data_args *la = (struct large_data_args *)arg;
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    char buf[1024];
    ssize_t n;

    la->bytes_received = 0;
    la->client_sock = accept(la->listen_sock, (struct sockaddr*)&client_addr, &addr_len);
    if (la->client_sock < 0) return NULL;

    // Receive all data
    while ((n = recv(la->client_sock, buf, sizeof(buf), 0)) > 0) {
        la->bytes_received += n;
        // Echo back
        send(la->client_sock, buf, n, 0);
    }

    close(la->client_sock);
    return NULL;
}

static void test_tcp_large_data(void) {
    int listen_sock, client_sock, ret, reuse;
    struct sockaddr_in addr;
    socklen_t addr_len;
    pthread_t server_thread;
    struct large_data_args la;
    char *send_buf, *recv_buf;
    ssize_t n, total_sent = 0, total_recv = 0;
    int i;

    printf("\n=== TCP Large Data Transfer Test ===\n");

    send_buf = (char*)malloc(LARGE_DATA_SIZE);
    recv_buf = (char*)malloc(LARGE_DATA_SIZE);
    if (!send_buf || !recv_buf) {
        TEST_ASSERT(0, "Allocate buffers");
        free(send_buf);
        free(recv_buf);
        return;
    }

    // Fill with pattern
    for (i = 0; i < LARGE_DATA_SIZE; i++) {
        send_buf[i] = (char)(i & 0xFF);
    }

    listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    TEST_ASSERT(listen_sock >= 0, "Create listen socket");
    if (listen_sock < 0) { free(send_buf); free(recv_buf); return; }

    reuse = 1;
    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(0);

    ret = bind(listen_sock, (struct sockaddr*)&addr, sizeof(addr));
    TEST_ASSERT(ret == 0, "Bind listen socket");
    if (ret != 0) { close(listen_sock); free(send_buf); free(recv_buf); return; }

    addr_len = sizeof(addr);
    getsockname(listen_sock, (struct sockaddr*)&addr, &addr_len);

    ret = listen(listen_sock, 1);
    TEST_ASSERT(ret == 0, "Listen on socket");

    la.listen_sock = listen_sock;
    la.client_sock = -1;
    la.bytes_received = 0;

    pthread_create(&server_thread, NULL, tcp_large_data_server, &la);

    client_sock = socket(AF_INET, SOCK_STREAM, 0);
    TEST_ASSERT(client_sock >= 0, "Create client socket");

    ret = connect(client_sock, (struct sockaddr*)&addr, sizeof(addr));
    TEST_ASSERT(ret == 0, "Connect to server");

    // Send all data
    while (total_sent < LARGE_DATA_SIZE) {
        n = send(client_sock, send_buf + total_sent, LARGE_DATA_SIZE - total_sent, 0);
        if (n <= 0) break;
        total_sent += n;
    }
    TEST_ASSERT(total_sent == LARGE_DATA_SIZE, "Send large data");

    // Signal end of data by shutting down write side
    shutdown(client_sock, SHUT_WR);

    // Receive echoed data
    while (total_recv < LARGE_DATA_SIZE) {
        n = recv(client_sock, recv_buf + total_recv, LARGE_DATA_SIZE - total_recv, 0);
        if (n <= 0) break;
        total_recv += n;
    }
    TEST_ASSERT(total_recv == LARGE_DATA_SIZE, "Recv large data");

    // Verify data
    TEST_ASSERT(memcmp(send_buf, recv_buf, LARGE_DATA_SIZE) == 0, "Data integrity");

    close(client_sock);
    pthread_join(server_thread, NULL);
    close(listen_sock);

    free(send_buf);
    free(recv_buf);
}

/* ========================================================================== */
/* Main Entry Point                                                           */
/* ========================================================================== */

int run_networking_tests(void) {
    printf("\n");
    printf("========================================\n");
    printf("   NETWORKING TEST SUITE\n");
    printf("========================================\n");

    test_structure_layouts();
    test_structure_field_values();
    test_socket_creation();
    test_socket_options();
    test_bind_listen();
    test_dns_resolution();
    test_poll();
    test_select();
    test_epoll();
    test_nonblocking();
    test_udp_sendrecv();
    test_tcp_loopback();
    test_tcp_multi_messages();
    test_tcp_pingpong();
    test_tcp_large_data();

    printf("\n========================================\n");
    printf("   NETWORKING RESULTS: %d passed, %d failed\n", tests_passed, tests_failed);
    printf("========================================\n");

    return tests_failed;
}
