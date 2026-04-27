#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>

namespace cross_shim {

extern std::unordered_map<std::string, std::string> g_env;
extern std::unordered_map<std::string, uint64_t> g_putenv_guest_strings;

}  // namespace cross_shim
