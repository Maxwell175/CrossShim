#ifndef CROSS_SHIM_HLE_PATH_TRANSLATION_H
#define CROSS_SHIM_HLE_PATH_TRANSLATION_H

#include <array>
#include <string>
#include <unistd.h>

namespace cross_shim {

inline bool is_guest_tmp_path(const std::string& path) {
    return path == "/data/local/tmp" || path.rfind("/data/local/tmp/", 0) == 0;
}

inline std::string translate_guest_host_path(const std::string& guest_path) {
    constexpr const char* kGuestTmpPrefix = "/data/local/tmp";
    constexpr size_t kGuestTmpPrefixLen = 15;
    if (guest_path == kGuestTmpPrefix) {
        return "/tmp";
    }
    if (guest_path.rfind("/data/local/tmp/", 0) == 0) {
        return std::string("/tmp") + guest_path.substr(kGuestTmpPrefixLen);
    }

    constexpr const char* kGuestSystemBinPrefix = "/system/bin/";
    constexpr size_t kGuestSystemBinPrefixLen = 12;
    if (guest_path.rfind(kGuestSystemBinPrefix, 0) == 0) {
        const std::string leaf = guest_path.substr(kGuestSystemBinPrefixLen);
        for (const char* dir : {"/bin/", "/usr/bin/"}) {
            std::string candidate = std::string(dir) + leaf;
            if (::access(candidate.c_str(), X_OK) == 0) {
                return candidate;
            }
        }
    }

    return guest_path;
}

inline std::string translate_host_guest_path(const std::string& host_path) {
    constexpr const char* kHostTmpPrefix = "/tmp";
    constexpr size_t kHostTmpPrefixLen = 4;
    if (host_path == kHostTmpPrefix) {
        return "/data/local/tmp";
    }
    if (host_path.rfind("/tmp/", 0) == 0) {
        return std::string("/data/local/tmp") + host_path.substr(kHostTmpPrefixLen);
    }

    return host_path;
}

inline std::string translate_host_path_for_guest(const std::string& guest_path,
                                                 const std::string& host_path) {
    if (is_guest_tmp_path(guest_path)) {
        return translate_host_guest_path(host_path);
    }
    return host_path;
}

} // namespace cross_shim

#endif
