/*
 * Minimal shim for bionic signal utilities
 * Only provides utility classes that bionic tests expect but bionic doesn't export.
 * Signal functions themselves come from bionic libc.
 */

#pragma once

#include <signal.h>
#include <string.h>
#include <stdint.h>

// SignalMaskRestorer - RAII class to save/restore signal mask
class SignalMaskRestorer {
public:
    SignalMaskRestorer() {
        sigprocmask(SIG_SETMASK, nullptr, &old_mask_);
    }
    ~SignalMaskRestorer() {
        sigprocmask(SIG_SETMASK, &old_mask_, nullptr);
    }
private:
    sigset_t old_mask_;
};

// SignalSetAdd/SignalSetDel - bionic test utilities for raw uint64_t signal sets
static inline void SignalSetAdd(uint64_t* sigset, int signo) {
    *sigset |= (1ULL << (signo - 1));
}

static inline void SignalSetDel(uint64_t* sigset, int signo) {
    *sigset &= ~(1ULL << (signo - 1));
}

// ScopedSignalHandler - RAII class to set/restore signal handler
class ScopedSignalHandler {
public:
    // Default constructor (ignore signal)
    explicit ScopedSignalHandler(int sig) : sig_(sig) {
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = SIG_IGN;
        sigaction(sig, &sa, &old_action_);
    }

    // Basic handler (no flags)
    ScopedSignalHandler(int sig, void (*handler)(int)) : sig_(sig) {
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = handler;
        sigaction(sig, &sa, &old_action_);
    }

    // Handler with flags (e.g., SA_ONSTACK)
    ScopedSignalHandler(int sig, void (*handler)(int), int flags) : sig_(sig) {
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = handler;
        sa.sa_flags = flags;
        sigaction(sig, &sa, &old_action_);
    }

    // Sigaction handler (SA_SIGINFO)
    ScopedSignalHandler(int sig, void (*handler)(int, siginfo_t*, void*), int flags) : sig_(sig) {
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_sigaction = handler;
        sa.sa_flags = flags | SA_SIGINFO;
        sigaction(sig, &sa, &old_action_);
    }

    ~ScopedSignalHandler() {
        sigaction(sig_, &old_action_, nullptr);
    }
private:
    int sig_;
    struct sigaction old_action_;
};
