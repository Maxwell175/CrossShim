#pragma once

#include <cstdint>

namespace cross_shim {

class Emulator;
class MemoryManager;

// Android Bionic TLS slot offsets
// Based on bionic/libc/platform/bionic/tls.h
enum TlsSlot {
    TLS_SLOT_SELF           = 0,   // Pointer to self (pthread_internal_t)
    TLS_SLOT_THREAD_ID      = 1,   // Thread ID
    TLS_SLOT_ERRNO          = 2,   // errno location
    TLS_SLOT_OPENGL_API     = 3,   // OpenGL API
    TLS_SLOT_OPENGL         = 4,   // OpenGL context
    TLS_SLOT_STACK_GUARD    = 5,   // Stack canary (offset 0x28 = 40 bytes)
    TLS_SLOT_DTV            = 6,   // Dynamic Thread Vector
    TLS_SLOT_BIONIC_TLS     = 7,   // Bionic TLS pointer
    TLS_SLOT_COUNT          = 8,
};

// TLS manager for Android Bionic compatibility
class TlsManager {
public:
    TlsManager(Emulator& emu, MemoryManager& memory);
    ~TlsManager() = default;
    
    // Initialize TLS region
    bool initialize();
    
    // Get TLS base address
    uint64_t get_tls_base() const { return tls_base_; }
    
    // Get stack guard value
    uint64_t get_stack_guard() const { return stack_guard_; }
    
    // Set a TLS slot value
    bool set_slot(TlsSlot slot, uint64_t value);
    
    // Get a TLS slot value
    uint64_t get_slot(TlsSlot slot) const;
    
    // Get errno address
    uint64_t get_errno_address() const;
    
    // Set errno value
    void set_errno(int value);
    
    // Get errno value
    int get_errno() const;

private:
    Emulator& emu_;
    MemoryManager& memory_;
    
    uint64_t tls_base_;
    uint64_t stack_guard_;
    uint64_t errno_location_;
};

} // namespace cross_shim

