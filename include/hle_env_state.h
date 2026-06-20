#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <mutex>

namespace cross_shim {

extern std::unordered_map<std::string, std::string> g_env;
extern std::unordered_map<std::string, uint64_t> g_putenv_guest_strings;
// Guards g_env / g_putenv_guest_strings. The env handlers (getenv/setenv/unsetenv in
// hle_stdlib.cpp, putenv/clearenv in hle_process.cpp) run concurrently across guest
// threads; a getenv read racing a setenv rehash corrupts the map. No env handler
// re-enters guest code or blocks, so a plain mutex is deadlock-free here.
extern std::mutex g_env_mutex;

}  // namespace cross_shim
