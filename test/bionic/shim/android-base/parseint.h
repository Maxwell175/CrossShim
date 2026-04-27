/*
 * Minimal shim for android-base/parseint.h
 */

#pragma once

#include <string>
#include <cstdlib>
#include <climits>
#include <cerrno>
#include <limits>
#include <type_traits>

namespace android {
namespace base {

template <typename T>
bool ParseInt(const char* s, T* out, T min = std::numeric_limits<T>::min(),
              T max = std::numeric_limits<T>::max()) {
    static_assert(std::is_integral<T>::value, "T must be integral");

    char* end;
    errno = 0;

    if constexpr (std::is_signed<T>::value) {
        long long result = strtoll(s, &end, 0);
        if (errno != 0 || s == end || *end != '\0') return false;
        if (result < min || result > max) return false;
        *out = static_cast<T>(result);
    } else {
        unsigned long long result = strtoull(s, &end, 0);
        if (errno != 0 || s == end || *end != '\0') return false;
        if (result > max) return false;
        *out = static_cast<T>(result);
    }
    return true;
}

template <typename T>
bool ParseInt(const std::string& s, T* out, T min = std::numeric_limits<T>::min(),
              T max = std::numeric_limits<T>::max()) {
    return ParseInt(s.c_str(), out, min, max);
}

template <typename T>
bool ParseUint(const char* s, T* out, T max = std::numeric_limits<T>::max()) {
    static_assert(std::is_unsigned<T>::value, "T must be unsigned");
    return ParseInt(s, out, static_cast<T>(0), max);
}

template <typename T>
bool ParseUint(const std::string& s, T* out, T max = std::numeric_limits<T>::max()) {
    return ParseUint(s.c_str(), out, max);
}

}  // namespace base
}  // namespace android
