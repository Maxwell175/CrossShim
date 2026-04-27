#pragma once

#include <cstddef>
#include <cstdint>

namespace cross_shim {

class Emulator;

int hle_signal_rt_sigprocmask(Emulator& emu, int how, uint64_t set_ptr, uint64_t oldset_ptr, size_t sigsetsize);
int hle_signal_rt_tgsigqueueinfo(Emulator& emu, int tgid, int tid, int sig, uint64_t info_ptr);
int hle_signal_queue(Emulator& emu, int signum, int si_code, int32_t sival_int, bool has_sigval);
uint64_t hle_signal_current_mask();
void hle_signal_set_mask(uint64_t mask);

} // namespace cross_shim
