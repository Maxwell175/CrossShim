#pragma once

#include <cstdint>
#include <string>
#include <functional>
#include <unordered_map>

namespace cross_shim {

class MemoryManager;
class ElfLoader;

// AArch64 relocation types
enum AArch64RelocType {
    R_AARCH64_NONE          = 0,
    R_AARCH64_ABS64         = 257,
    R_AARCH64_GLOB_DAT      = 1025,
    R_AARCH64_JUMP_SLOT     = 1026,
    R_AARCH64_RELATIVE      = 1027,
    R_AARCH64_TLS_DTPREL64  = 1028,
    R_AARCH64_TLS_DTPMOD64  = 1029,
    R_AARCH64_TLS_TPREL64   = 1030,
    R_AARCH64_TLSDESC       = 1031,
    R_AARCH64_IRELATIVE     = 1032,
};

// Symbol resolver callback type
using SymbolResolver = std::function<uint64_t(const std::string&)>;

// Relocation handler
class RelocationHandler {
public:
    RelocationHandler(MemoryManager& memory);
    ~RelocationHandler() = default;
    
    // Process all relocations for a loaded module
    bool process_relocations(
        ElfLoader& loader,
        uint64_t base_address,
        SymbolResolver resolver
    );
    
    // Process a single relocation
    bool process_relocation(
        uint64_t base_address,
        uint64_t offset,
        uint64_t type,
        uint64_t addend,
        const std::string& symbol_name,
        uint64_t symbol_value,
        SymbolResolver resolver
    );
    
    // Get statistics
    size_t get_processed_count() const { return processed_count_; }
    size_t get_failed_count() const { return failed_count_; }
    
    // Get unresolved symbols
    const std::vector<std::string>& get_unresolved() const { return unresolved_; }

private:
    bool apply_relative(uint64_t address, uint64_t base, int64_t addend);
    bool apply_abs64(uint64_t address, uint64_t value, int64_t addend);
    bool apply_glob_dat(uint64_t address, uint64_t value, int64_t addend);
    bool apply_jump_slot(uint64_t address, uint64_t value, int64_t addend);
    
    MemoryManager& memory_;
    size_t processed_count_;
    size_t failed_count_;
    std::vector<std::string> unresolved_;
};

} // namespace cross_shim

