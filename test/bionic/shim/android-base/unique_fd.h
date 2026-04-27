/*
 * Minimal shim for android-base/unique_fd.h
 */

#pragma once

#include <unistd.h>

namespace android {
namespace base {

// RAII wrapper for file descriptors
class unique_fd {
public:
    unique_fd() : fd_(-1) {}
    explicit unique_fd(int fd) : fd_(fd) {}

    unique_fd(unique_fd&& other) noexcept : fd_(other.fd_) {
        other.fd_ = -1;
    }

    ~unique_fd() {
        reset();
    }

    unique_fd& operator=(unique_fd&& other) noexcept {
        reset(other.release());
        return *this;
    }

    void reset(int fd = -1) {
        if (fd_ >= 0) {
            close(fd_);
        }
        fd_ = fd;
    }

    int release() {
        int fd = fd_;
        fd_ = -1;
        return fd;
    }

    int get() const { return fd_; }
    operator int() const { return fd_; }

    bool operator==(int rhs) const { return fd_ == rhs; }
    bool operator!=(int rhs) const { return fd_ != rhs; }
    bool operator<(int rhs) const { return fd_ < rhs; }
    bool operator>=(int rhs) const { return fd_ >= rhs; }

    // Disallow copy
    unique_fd(const unique_fd&) = delete;
    unique_fd& operator=(const unique_fd&) = delete;

private:
    int fd_;
};

}  // namespace base
}  // namespace android

// Also provide in global namespace for compatibility
using android::base::unique_fd;
