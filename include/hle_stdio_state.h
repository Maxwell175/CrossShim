#pragma once

#include <cstdint>
#include <cstdio>

namespace cross_shim {

class Emulator;

FILE* hle_resolve_guest_file(Emulator& emu, uint64_t stream);
int hle_resolve_guest_fileno(Emulator& emu, uint64_t stream);
void hle_sync_stream_after_write(Emulator& emu, uint64_t stream);
void hle_sync_stream_after_flush(Emulator& emu, uint64_t stream);
uint64_t hle_open_wmemstream(Emulator& emu, uint64_t ptr_ptr, uint64_t sizeloc_ptr, int& out_errno);

} // namespace cross_shim
