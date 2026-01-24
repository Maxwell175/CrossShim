#pragma once

#include <cstdint>
#include <unordered_set>
#include <mutex>

namespace cross_shim {

class MemoryManager;

/**
 * Session tracer for debugging TUTK AV sessions
 * Monitors critical session offsets to understand FIFO routing
 */
class SessionTracer {
public:
    SessionTracer(MemoryManager& memory);

    // Register a session base address to trace
    void register_session(uint64_t session_base);

    // Check if we should trace this address (called on every memory write)
    bool should_trace_write(uint64_t address, uint64_t size);

    // Trace a memory write
    void trace_write(uint64_t address, const void* data, uint64_t size, uint64_t pc);

    // Trace a memory read
    void trace_read(uint64_t address, const void* data, uint64_t size, uint64_t pc);

    // Dump current session state
    void dump_session_state(uint64_t session_base);

private:
    MemoryManager& memory_;
    std::unordered_set<uint64_t> session_bases_;
    mutable std::mutex mutex_;

    // Critical offsets we're monitoring
    static const uint64_t OFFSET_NEW_PROTOCOL = 0x1f84;  // New protocol mode flag
    static const uint64_t OFFSET_FRAME_ROUTING = 0x1908; // Frame routing control
    static const uint64_t OFFSET_FIFO_2018 = 0x2018;     // Incoming packets FIFO
    static const uint64_t OFFSET_FIFO_2020 = 0x2020;     // Assembled frames storage FIFO
    static const uint64_t OFFSET_FIFO_2028 = 0x2028;     // Intermediate FIFO
    static const uint64_t OFFSET_FIFO_2038 = 0x2038;     // New protocol input FIFO
    static const uint64_t OFFSET_FIFO_2040 = 0x2040;     // New protocol output FIFO

    bool is_critical_offset(uint64_t session_base, uint64_t address);
    const char* get_offset_name(uint64_t offset);
};

} // namespace cross_shim
