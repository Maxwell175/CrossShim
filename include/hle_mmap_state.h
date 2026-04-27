#pragma once

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <unordered_map>

namespace cross_shim {

// Keep a coarse guest VMA budget so mmap-heavy tests and pthread stack setup
// can fail in a bounded, Linux-like way instead of spinning through tens of
// thousands of emulator-only mappings.
inline constexpr size_t GUEST_VMA_LIMIT = 4096;

inline std::mutex g_guest_vma_mutex;
inline size_t g_guest_vma_count = 0;
inline std::unordered_map<uint64_t, size_t> g_guest_vma_reservations;

inline bool hle_try_reserve_vmas(uint64_t key, size_t count) {
    if (key == 0 || count == 0) {
        return true;
    }

    std::lock_guard<std::mutex> lock(g_guest_vma_mutex);
    if (g_guest_vma_count + count > GUEST_VMA_LIMIT) {
        return false;
    }
    g_guest_vma_count += count;
    g_guest_vma_reservations[key] += count;
    return true;
}

inline void hle_release_vmas(uint64_t key) {
    if (key == 0) {
        return;
    }

    std::lock_guard<std::mutex> lock(g_guest_vma_mutex);
    auto it = g_guest_vma_reservations.find(key);
    if (it == g_guest_vma_reservations.end()) {
        return;
    }

    if (g_guest_vma_count >= it->second) {
        g_guest_vma_count -= it->second;
    } else {
        g_guest_vma_count = 0;
    }
    g_guest_vma_reservations.erase(it);
}

}  // namespace cross_shim
