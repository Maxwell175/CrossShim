#include "tls_manager.h"
#include "cross_shim.h"
#include "memory_manager.h"
#include "emu_compat.h"
#include <random>
#include <iostream>

namespace cross_shim {

TlsManager::TlsManager(Emulator& emu, MemoryManager& memory)
    : emu_(emu), memory_(memory), tls_base_(0), stack_guard_(0), errno_location_(0) {}

bool TlsManager::initialize() {
    // TLS region is already mapped by SharedMemoryManager
    // The TCB (Thread Control Block) is at TLS_BASE
    // TPIDR_EL0 should point to TLS_BASE + 8, so that TPIDR_EL0 - 8 = TLS_BASE
    // This is the Android bionic convention
    tls_base_ = TLS_BASE;
    uint64_t tpidr_value = TLS_BASE + 8;

    // Use a fixed stack guard canary that matches the value used in thread_manager.cpp
    // This ensures consistency across all threads
    // IMPORTANT: This must match the value in ThreadManager::allocate_thread_tls()
    stack_guard_ = 0xDEADBEEFCAFEBABEULL;

    // Set up TLS slots (relative to tls_base_, not tpidr_value)
    // Slot 0: Self pointer (pthread_internal_t*)
    set_slot(TLS_SLOT_SELF, tls_base_);

    // Slot 1: Thread ID
    set_slot(TLS_SLOT_THREAD_ID, 1);

    // Slot 2: errno location
    errno_location_ = tls_base_ + 0x100;  // Offset for errno storage
    set_slot(TLS_SLOT_ERRNO, errno_location_);
    memory_.zero(errno_location_, 4);  // Initialize errno to 0

    // Slot 5: Stack guard (at offset 0x28 = 40 bytes from TLS base)
    // This is where __init_tcb_stack_guard stores the stack guard
    // Offset 48 (0x30) from TCB base
    set_slot(TLS_SLOT_STACK_GUARD, stack_guard_);

    // Also store the stack guard at offset 48 from tls_base_ (TCB offset)
    // This is where __init_tcb_stack_guard expects it
    memory_.write(tls_base_ + 48, &stack_guard_, sizeof(stack_guard_));

    // Set TPIDR_EL0 register to point to TLS base + 8
    // This way, TPIDR_EL0 - 8 = TLS_BASE (the TCB address)
    // Note: QEMU's TPIDR_EL0 register index may differ - use UC_ARM64_REG_TPIDR_EL0 for compatibility
    set_reg(emu_, UC_ARM64_REG_TPIDR_EL0, tpidr_value);

    // Also set X18 (platform register) to the same value
    // On Android, X18 is used as the TLS base register
    set_reg(emu_, UC_ARM64_REG_X18, tpidr_value);

    return true;
}

bool TlsManager::set_slot(TlsSlot slot, uint64_t value) {
    if (tls_base_ == 0) return false;
    
    uint64_t offset = static_cast<uint64_t>(slot) * 8;
    return memory_.write(tls_base_ + offset, &value, sizeof(value));
}

uint64_t TlsManager::get_slot(TlsSlot slot) const {
    if (tls_base_ == 0) return 0;
    
    uint64_t offset = static_cast<uint64_t>(slot) * 8;
    uint64_t value = 0;
    memory_.read(tls_base_ + offset, &value, sizeof(value));
    return value;
}

uint64_t TlsManager::get_errno_address() const {
    return errno_location_;
}

void TlsManager::set_errno(int value) {
    if (errno_location_ != 0) {
        memory_.write(errno_location_, &value, sizeof(value));
    }
}

int TlsManager::get_errno() const {
    if (errno_location_ == 0) return 0;
    
    int value = 0;
    memory_.read(errno_location_, &value, sizeof(value));
    return value;
}

} // namespace cross_shim

