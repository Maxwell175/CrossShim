/**
 * HLE Crypto Functions - DISABLED
 *
 * OpenSSL HLE has been disabled. ARM64 OpenSSL code will run naturally
 * in the emulator.
 *
 * This file now contains an empty stub function to satisfy the linker.
 */

#include "debug_log.h"
#include "hle_manager.h"
#include "cross_shim.h"
#include <iostream>

namespace cross_shim {

void register_hle_crypto(HleManager& hle) {
    EMU_LOG << "[HLE] OpenSSL HLE disabled - ARM64 crypto code will run in emulator" << std::endl;
}

} // namespace cross_shim

