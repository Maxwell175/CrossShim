/*
 * Minimal shim for bionic TemporaryFile utilities
 */

#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <sys/stat.h>

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

    int fd = -1;
    char path[PATH_MAX] = {};
};

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
            // Simple rmdir - tests should clean up contents
            rmdir(path);
        }
    }

    char path[PATH_MAX] = {};
};
