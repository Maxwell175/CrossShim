#pragma once

#include <cstdint>

namespace cross_shim {

struct GuestBrkState {
    uint64_t initial_brk = 0;
    uint64_t current_brk = 0;
};

inline GuestBrkState& guest_brk_state() {
    static GuestBrkState state;
    return state;
}

inline void guest_brk_initialize(uint64_t brk) {
    GuestBrkState& state = guest_brk_state();
    if (state.initial_brk == 0) {
        state.initial_brk = brk;
    }
    if (state.current_brk == 0) {
        state.current_brk = brk;
    }
}

}  // namespace cross_shim
