/*
 * Minimal shim for android-base/stringprintf.h
 */

#pragma once

#include <string>
#include <cstdarg>
#include <cstdio>

namespace android {
namespace base {

inline std::string StringPrintf(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);

    char buf[1024];
    vsnprintf(buf, sizeof(buf), fmt, ap);

    va_end(ap);
    return std::string(buf);
}

inline void StringAppendF(std::string* dst, const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);

    char buf[1024];
    vsnprintf(buf, sizeof(buf), fmt, ap);

    va_end(ap);
    dst->append(buf);
}

}  // namespace base
}  // namespace android
