/*
 * Minimal shim for android-base/threads.h
 */

#pragma once

#include <unistd.h>
#include <sys/types.h>
#include <sys/syscall.h>

namespace android {
namespace base {

inline pid_t GetThreadId() {
#if defined(__linux__)
    return syscall(SYS_gettid);
#else
    return getpid();
#endif
}

}  // namespace base
}  // namespace android
