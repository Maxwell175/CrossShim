#include "debug_log.h"
#include "relocation_handler.h"
#include "memory_manager.h"
#include "elf_loader.h"
#include <cstring>
#include <iostream>

namespace cross_shim {

// Strip version suffix from symbol name (e.g., "strtod@LIBC" -> "strtod")
static std::string strip_version_suffix(const std::string& symbol_name) {
    size_t at_pos = symbol_name.find('@');
    if (at_pos != std::string::npos) {
        return symbol_name.substr(0, at_pos);
    }
    return symbol_name;
}

RelocationHandler::RelocationHandler(MemoryManager& memory)
    : memory_(memory), processed_count_(0), failed_count_(0) {}

bool RelocationHandler::process_relocations(
    ElfLoader& loader,
    uint64_t base_address,
    SymbolResolver resolver
) {
    auto relocations = loader.get_relocations();

    for (const auto& reloc : relocations) {
        bool success = process_relocation(
            base_address,
            reloc.offset,
            reloc.type,
            reloc.addend,
            reloc.symbol_name,
            reloc.symbol_value,
            resolver
        );

        if (success) {
            processed_count_++;
        } else {
            failed_count_++;
        }
    }

    return failed_count_ == 0;
}

bool RelocationHandler::process_relocation(
    uint64_t base_address,
    uint64_t offset,
    uint64_t type,
    uint64_t addend,
    const std::string& symbol_name,
    uint64_t symbol_value,
    SymbolResolver resolver
) {
    uint64_t address = base_address + offset;
    int64_t signed_addend = static_cast<int64_t>(addend);

    // LIEF returns type with architecture marker in upper bits, mask to get actual type
    uint32_t reloc_type = static_cast<uint32_t>(type & 0xFFFF);

    switch (reloc_type) {
        case R_AARCH64_NONE:
            return true;

        case R_AARCH64_RELATIVE:
            return apply_relative(address, base_address, signed_addend);

        case R_AARCH64_ABS64: {
            uint64_t value = symbol_value;
            if (value == 0 && !symbol_name.empty() && resolver) {
                // Try with original name first, then without version suffix
                value = resolver(symbol_name);
                if (value == 0) {
                    value = resolver(strip_version_suffix(symbol_name));
                }
            } else if (value != 0) {
                value += base_address;
            }
            if (value == 0 && !symbol_name.empty()) {
                unresolved_.push_back(symbol_name);
                return false;
            }
            return apply_abs64(address, value, signed_addend);
        }

        case R_AARCH64_GLOB_DAT: {
            uint64_t value = symbol_value;
            EMU_LOG << "[RELOC] GLOB_DAT for " << symbol_name << " at 0x" << std::hex << address
                      << " initial_value=0x" << symbol_value << std::dec << std::endl;
            if (value == 0 && !symbol_name.empty() && resolver) {
                // Try with original name first, then without version suffix
                value = resolver(symbol_name);
                if (value == 0) {
                    value = resolver(strip_version_suffix(symbol_name));
                }
                EMU_LOG << "[RELOC] GLOB_DAT resolved " << symbol_name << " to 0x"
                          << std::hex << value << std::dec << std::endl;
            } else if (value != 0) {
                value += base_address;
            }
            if (value == 0 && !symbol_name.empty()) {
                EMU_LOG << "[RELOC] WARNING: Unresolved GLOB_DAT symbol: " << symbol_name
                          << " at 0x" << std::hex << address << std::dec << std::endl;
                unresolved_.push_back(symbol_name);
            }
            return apply_glob_dat(address, value, signed_addend);
        }

        case R_AARCH64_JUMP_SLOT: {
            uint64_t value = symbol_value;
            if (value == 0 && !symbol_name.empty() && resolver) {
                // Try with original name first, then without version suffix
                value = resolver(symbol_name);
                if (value == 0) {
                    value = resolver(strip_version_suffix(symbol_name));
                }
            } else if (value != 0) {
                value += base_address;
            }
            if (value == 0 && !symbol_name.empty()) {
                EMU_LOG << "[RELOC] WARNING: Unresolved JUMP_SLOT symbol: " << symbol_name
                          << " at 0x" << std::hex << address << std::dec << std::endl;
                unresolved_.push_back(symbol_name);
            }
            return apply_jump_slot(address, value, signed_addend);
        }

        case R_AARCH64_IRELATIVE:
            return apply_relative(address, base_address, signed_addend);

        default:
            return true;
    }
}

bool RelocationHandler::apply_relative(uint64_t address, uint64_t base, int64_t addend) {
    // R_AARCH64_RELATIVE: S + A (where S = base address)
    // For RELR relocations, the addend is stored in-place at the address
    // (addend=0 is passed for RELR entries)
    if (addend == 0) {
        // Read the existing value at the address as the addend
        uint64_t existing = 0;
        if (!memory_.read(address, &existing, sizeof(existing))) {
            EMU_LOG << "[RELOC] ERROR: Failed to read existing value for RELATIVE at 0x"
                      << std::hex << address << std::dec << std::endl;
            return false;
        }
        addend = static_cast<int64_t>(existing);

        // Debug: log first few RELR relocations
        static int relr_log_count = 0;
        if (relr_log_count < 10) {
            EMU_LOG << "[RELOC] RELR at 0x" << std::hex << address
                      << ": existing=0x" << existing
                      << " + base=0x" << base
                      << " = 0x" << (base + addend) << std::dec << std::endl;
            relr_log_count++;
        }
    }
    uint64_t value = base + addend;
    return memory_.write(address, &value, sizeof(value));
}

bool RelocationHandler::apply_abs64(uint64_t address, uint64_t value, int64_t addend) {
    uint64_t result = value + addend;
    return memory_.write(address, &result, sizeof(result));
}

bool RelocationHandler::apply_glob_dat(uint64_t address, uint64_t value, int64_t addend) {
    uint64_t result = value + addend;
    return memory_.write(address, &result, sizeof(result));
}

bool RelocationHandler::apply_jump_slot(uint64_t address, uint64_t value, int64_t addend) {
    uint64_t result = value + addend;
    // Debug: log HLE region writes
    if (result >= 0x10000000 && result < 0x10100000) {
        EMU_LOG << "[GOT_WRITE] Writing HLE addr 0x" << std::hex << result
                  << " to GOT at 0x" << address << std::dec << std::endl;
    }
    return memory_.write(address, &result, sizeof(result));
}

} // namespace cross_shim
