#include "debug_log.h"
#include "session_tracer.h"
#include "memory_manager.h"
#include <iostream>
#include <iomanip>
#include <cstring>

namespace cross_shim {

SessionTracer::SessionTracer(MemoryManager& memory)
    : memory_(memory) {}

void SessionTracer::register_session(uint64_t session_base) {
    std::lock_guard<std::mutex> lock(mutex_);
    session_bases_.insert(session_base);
    EMU_LOG << "[SESSION_TRACE] Registered session at 0x" << std::hex << session_base << std::dec << std::endl;
}

bool SessionTracer::is_critical_offset(uint64_t session_base, uint64_t address) {
    uint64_t offset = address - session_base;
    return offset == OFFSET_NEW_PROTOCOL ||
           offset == OFFSET_FRAME_ROUTING ||
           offset == OFFSET_FIFO_2018 ||
           offset == OFFSET_FIFO_2020 ||
           offset == OFFSET_FIFO_2028 ||
           offset == OFFSET_FIFO_2038 ||
           offset == OFFSET_FIFO_2040;
}

const char* SessionTracer::get_offset_name(uint64_t offset) {
    switch (offset) {
        case OFFSET_NEW_PROTOCOL: return "NEW_PROTOCOL_FLAG(0x1f84)";
        case OFFSET_FRAME_ROUTING: return "FRAME_ROUTING_CTRL(0x1908)";
        case OFFSET_FIFO_2018: return "FIFO_INCOMING(0x2018)";
        case OFFSET_FIFO_2020: return "FIFO_STORAGE(0x2020)";
        case OFFSET_FIFO_2028: return "FIFO_INTERMEDIATE(0x2028)";
        case OFFSET_FIFO_2038: return "FIFO_NEW_IN(0x2038)";
        case OFFSET_FIFO_2040: return "FIFO_NEW_OUT(0x2040)";
        default: return "UNKNOWN";
    }
}

bool SessionTracer::should_trace_write(uint64_t address, uint64_t size) {
    std::lock_guard<std::mutex> lock(mutex_);

    for (uint64_t session_base : session_bases_) {
        // Check if this write touches any critical offset
        for (uint64_t i = 0; i < size; i++) {
            if (is_critical_offset(session_base, address + i)) {
                return true;
            }
        }
    }
    return false;
}

void SessionTracer::trace_write(uint64_t address, const void* data, uint64_t size, uint64_t pc) {
    std::lock_guard<std::mutex> lock(mutex_);

    for (uint64_t session_base : session_bases_) {
        uint64_t offset = address - session_base;

        if (is_critical_offset(session_base, address)) {
            EMU_LOG << "[SESSION_TRACE] WRITE to " << get_offset_name(offset)
                     << " at session+0x" << std::hex << offset
                     << " from PC=0x" << pc << std::dec << " size=" << size << " value=";

            // Print value based on size
            if (size == 1) {
                EMU_LOG << (int)*(uint8_t*)data;
            } else if (size == 4) {
                EMU_LOG << "0x" << std::hex << *(uint32_t*)data << std::dec;
            } else if (size == 8) {
                EMU_LOG << "0x" << std::hex << *(uint64_t*)data << std::dec;
            } else {
                EMU_LOG << "[" << size << " bytes]";
            }
            EMU_LOG << std::endl;
        }
    }
}

void SessionTracer::trace_read(uint64_t address, const void* data, uint64_t size, uint64_t pc) {
    std::lock_guard<std::mutex> lock(mutex_);

    for (uint64_t session_base : session_bases_) {
        uint64_t offset = address - session_base;

        if (is_critical_offset(session_base, address)) {
            EMU_LOG << "[SESSION_TRACE] READ from " << get_offset_name(offset)
                     << " at session+0x" << std::hex << offset
                     << " from PC=0x" << pc << std::dec << " size=" << size << " value=";

            // Print value based on size
            if (size == 1) {
                EMU_LOG << (int)*(uint8_t*)data;
            } else if (size == 4) {
                EMU_LOG << "0x" << std::hex << *(uint32_t*)data << std::dec;
            } else if (size == 8) {
                EMU_LOG << "0x" << std::hex << *(uint64_t*)data << std::dec;
            } else {
                EMU_LOG << "[" << size << " bytes]";
            }
            EMU_LOG << std::endl;
        }
    }
}

void SessionTracer::dump_session_state(uint64_t session_base) {
    std::lock_guard<std::mutex> lock(mutex_);

    EMU_LOG << "\n[SESSION_TRACE] ===== Session State Dump (base=0x" << std::hex << session_base << std::dec << ") =====" << std::endl;

    // Read and display critical offsets
    uint32_t new_protocol = 0;
    uint8_t frame_routing = 0;
    uint64_t fifo_2018 = 0, fifo_2020 = 0, fifo_2028 = 0, fifo_2038 = 0, fifo_2040 = 0;

    memory_.read(session_base + OFFSET_NEW_PROTOCOL, &new_protocol, sizeof(new_protocol));
    memory_.read(session_base + OFFSET_FRAME_ROUTING, &frame_routing, sizeof(frame_routing));
    memory_.read(session_base + OFFSET_FIFO_2018, &fifo_2018, sizeof(fifo_2018));
    memory_.read(session_base + OFFSET_FIFO_2020, &fifo_2020, sizeof(fifo_2020));
    memory_.read(session_base + OFFSET_FIFO_2028, &fifo_2028, sizeof(fifo_2028));
    memory_.read(session_base + OFFSET_FIFO_2038, &fifo_2038, sizeof(fifo_2038));
    memory_.read(session_base + OFFSET_FIFO_2040, &fifo_2040, sizeof(fifo_2040));

    EMU_LOG << "  NEW_PROTOCOL (0x1f84): " << new_protocol << std::endl;
    EMU_LOG << "  FRAME_ROUTING (0x1908): " << (int)frame_routing << std::endl;
    EMU_LOG << "  FIFO_INCOMING (0x2018): 0x" << std::hex << fifo_2018 << std::dec
              << (fifo_2018 ? " (allocated)" : " (NULL)") << std::endl;
    EMU_LOG << "  FIFO_STORAGE (0x2020): 0x" << std::hex << fifo_2020 << std::dec
              << (fifo_2020 ? " (allocated)" : " (NULL)") << std::endl;
    EMU_LOG << "  FIFO_INTERMEDIATE (0x2028): 0x" << std::hex << fifo_2028 << std::dec
              << (fifo_2028 ? " (allocated)" : " (NULL)") << std::endl;
    EMU_LOG << "  FIFO_NEW_IN (0x2038): 0x" << std::hex << fifo_2038 << std::dec
              << (fifo_2038 ? " (allocated)" : " (NULL)") << std::endl;
    EMU_LOG << "  FIFO_NEW_OUT (0x2040): 0x" << std::hex << fifo_2040 << std::dec
              << (fifo_2040 ? " (allocated)" : " (NULL)") << std::endl;

    EMU_LOG << "[SESSION_TRACE] ===============================================\n" << std::endl;
}

} // namespace cross_shim
