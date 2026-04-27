/*
 * Minimal shim for android-base/strings.h
 */

#pragma once

#include <string>
#include <vector>
#include <sstream>
#include <algorithm>

namespace android {
namespace base {

inline std::vector<std::string> Split(const std::string& s, const std::string& delimiters) {
    std::vector<std::string> result;
    size_t start = 0;
    size_t end;

    while ((end = s.find_first_of(delimiters, start)) != std::string::npos) {
        if (end > start) {
            result.push_back(s.substr(start, end - start));
        }
        start = end + 1;
    }
    if (start < s.size()) {
        result.push_back(s.substr(start));
    }
    return result;
}

inline std::string Trim(const std::string& s) {
    size_t start = s.find_first_not_of(" \t\n\r");
    if (start == std::string::npos) return "";
    size_t end = s.find_last_not_of(" \t\n\r");
    return s.substr(start, end - start + 1);
}

inline std::string Join(const std::vector<std::string>& strings, const std::string& separator) {
    if (strings.empty()) return "";
    std::string result = strings[0];
    for (size_t i = 1; i < strings.size(); ++i) {
        result += separator + strings[i];
    }
    return result;
}

inline bool StartsWith(const std::string& s, const std::string& prefix) {
    return s.size() >= prefix.size() && s.compare(0, prefix.size(), prefix) == 0;
}

inline bool EndsWith(const std::string& s, const std::string& suffix) {
    return s.size() >= suffix.size() &&
           s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

inline bool EqualsIgnoreCase(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (tolower(a[i]) != tolower(b[i])) return false;
    }
    return true;
}

}  // namespace base
}  // namespace android
