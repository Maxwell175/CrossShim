/*
 * Minimal shim for private/ScopedSignalHandler.h
 */

#pragma once

#include <signal.h>
#include <string.h>

// RAII class to save/restore signal handler
class ScopedSignalHandler {
public:
    ScopedSignalHandler(int sig, void (*handler)(int), int sa_flags = 0) : sig_(sig) {
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = handler;
        sa.sa_flags = sa_flags;
        sigaction(sig, &sa, &old_action_);
    }

    ScopedSignalHandler(int sig, void (*handler)(int, siginfo_t*, void*), int sa_flags = SA_SIGINFO)
        : sig_(sig) {
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_sigaction = handler;
        sa.sa_flags = sa_flags;
        sigaction(sig, &sa, &old_action_);
    }

    ~ScopedSignalHandler() {
        sigaction(sig_, &old_action_, nullptr);
    }

private:
    int sig_;
    struct sigaction old_action_;

    ScopedSignalHandler(const ScopedSignalHandler&) = delete;
    ScopedSignalHandler& operator=(const ScopedSignalHandler&) = delete;
};

// RAII class to save/restore signal mask
class ScopedSignalMask {
public:
    ScopedSignalMask() {
        sigprocmask(SIG_SETMASK, nullptr, &old_mask_);
    }
    ~ScopedSignalMask() {
        sigprocmask(SIG_SETMASK, &old_mask_, nullptr);
    }
private:
    sigset_t old_mask_;
};
