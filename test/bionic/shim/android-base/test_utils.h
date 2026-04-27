/*
 * Minimal shim for android-base/test_utils.h
 */

#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <sys/stat.h>

#include <string>

// TemporaryFile and TemporaryDir are in android-base/file.h
#include <android-base/file.h>

class CapturedStdout {
public:
    CapturedStdout() {
        fflush(stdout);
        old_fd_ = dup(STDOUT_FILENO);
        temp_file_ = tmpfile();
        dup2(fileno(temp_file_), STDOUT_FILENO);
    }

    ~CapturedStdout() {
        Stop();
        if (temp_file_) fclose(temp_file_);
    }

    void Stop() {
        if (old_fd_ >= 0) {
            fflush(stdout);
            dup2(old_fd_, STDOUT_FILENO);
            close(old_fd_);
            old_fd_ = -1;
        }
    }

    std::string str() {
        Stop();
        if (!temp_file_) return "";

        fseek(temp_file_, 0, SEEK_END);
        long size = ftell(temp_file_);
        fseek(temp_file_, 0, SEEK_SET);

        std::string result(size, '\0');
        fread(&result[0], 1, size, temp_file_);
        return result;
    }

private:
    int old_fd_ = -1;
    FILE* temp_file_ = nullptr;
};

class CapturedStderr {
public:
    CapturedStderr() {
        fflush(stderr);
        old_fd_ = dup(STDERR_FILENO);
        temp_file_ = tmpfile();
        dup2(fileno(temp_file_), STDERR_FILENO);
    }

    ~CapturedStderr() {
        Stop();
        if (temp_file_) fclose(temp_file_);
    }

    void Stop() {
        if (old_fd_ >= 0) {
            fflush(stderr);
            dup2(old_fd_, STDERR_FILENO);
            close(old_fd_);
            old_fd_ = -1;
        }
    }

    std::string str() {
        Stop();
        if (!temp_file_) return "";

        fseek(temp_file_, 0, SEEK_END);
        long size = ftell(temp_file_);
        fseek(temp_file_, 0, SEEK_SET);

        std::string result(size, '\0');
        fread(&result[0], 1, size, temp_file_);
        return result;
    }

private:
    int old_fd_ = -1;
    FILE* temp_file_ = nullptr;
};
