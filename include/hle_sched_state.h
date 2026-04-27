#pragma once

#include <sys/types.h>
#include <cstdint>

namespace cross_shim {

class Emulator;

void hle_sched_note_thread_tid(pid_t tid);
void hle_sched_set_thread_nice(pid_t tid, int nice_value);
bool hle_sched_get_effective_priority(pid_t tid, int& priority);
bool hle_sched_get_nice(pid_t tid, int& nice_value);
void hle_sched_pi_boost_begin(pid_t tid);
void hle_sched_pi_boost_end(pid_t tid);
int hle_sem_init(Emulator& emu, uint64_t sem_ptr, int pshared, uint32_t value);
int hle_sem_destroy(Emulator& emu, uint64_t sem_ptr);
int hle_sem_wait(Emulator& emu, uint64_t sem_ptr);
int hle_sem_trywait(Emulator& emu, uint64_t sem_ptr);
int hle_sem_timedwait(Emulator& emu, uint64_t sem_ptr, int clockid, uint64_t abstime_ptr);
int hle_sem_post(Emulator& emu, uint64_t sem_ptr);
int hle_sem_getvalue(Emulator& emu, uint64_t sem_ptr, uint64_t value_ptr);

} // namespace cross_shim
