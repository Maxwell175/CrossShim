/*
 * Minimal shim for android-base/file.h
 */

#pragma once

#include <string>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <sys/stat.h>
#include <android-base/unique_fd.h>

// TemporaryFile - RAII for temp files
class TemporaryFile {
public:
    TemporaryFile() {
        snprintf(path, sizeof(path), "/tmp/bionic_test_XXXXXX");
        fd = mkstemp(path);
    }

    ~TemporaryFile() {
        if (fd >= 0) {
            close(fd);
        }
        unlink(path);
    }

    // Disallow copy
    TemporaryFile(const TemporaryFile&) = delete;
    TemporaryFile& operator=(const TemporaryFile&) = delete;

    int fd = -1;
    char path[PATH_MAX] = {};
};

// TemporaryDir - RAII for temp directories
class TemporaryDir {
public:
    TemporaryDir() {
        snprintf(path, sizeof(path), "/tmp/bionic_test_dir_XXXXXX");
        if (mkdtemp(path) == nullptr) {
            path[0] = '\0';
        }
    }

    ~TemporaryDir() {
        if (path[0] != '\0') {
            rmdir(path);
        }
    }

    // Disallow copy
    TemporaryDir(const TemporaryDir&) = delete;
    TemporaryDir& operator=(const TemporaryDir&) = delete;

    char path[PATH_MAX] = {};
};

namespace android {
namespace base {

inline bool ReadFileToString(const std::string& path, std::string* content) {
    int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0) return false;

    content->clear();
    char buf[4096];
    ssize_t n;
    while ((n = read(fd, buf, sizeof(buf))) > 0) {
        content->append(buf, n);
    }
    close(fd);
    return n >= 0;
}

inline bool WriteStringToFile(const std::string& content, const std::string& path) {
    int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return false;

    size_t written = 0;
    while (written < content.size()) {
        ssize_t n = write(fd, content.data() + written, content.size() - written);
        if (n < 0) {
            close(fd);
            return false;
        }
        written += n;
    }
    close(fd);
    return true;
}

inline bool WriteStringToFd(const std::string& content, int fd) {
    size_t written = 0;
    while (written < content.size()) {
        ssize_t n = write(fd, content.data() + written, content.size() - written);
        if (n < 0) return false;
        written += n;
    }
    return true;
}

inline bool ReadFdToString(int fd, std::string* content) {
    content->clear();
    char buf[4096];
    ssize_t n;
    while ((n = read(fd, buf, sizeof(buf))) > 0) {
        content->append(buf, n);
    }
    return n >= 0;
}

}  // namespace base
}  // namespace android
