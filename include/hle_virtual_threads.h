#pragma once

#include <cstdint>

namespace cross_shim {

uint64_t hle_virtual_thread_current_override();
void hle_virtual_thread_set_current_override(uint64_t tid);
uint64_t hle_virtual_thread_allocate();
void hle_virtual_thread_set_alive(uint64_t tid, bool alive);
bool hle_virtual_thread_is_alive(uint64_t tid);
bool hle_virtual_thread_is_virtual(uint64_t tid);

} // namespace cross_shim
