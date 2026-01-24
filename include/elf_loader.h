#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <unordered_map>

namespace LIEF::ELF {
    class Binary;
}

namespace cross_shim {

class MemoryManager;
struct LoadedModule;

// ELF segment information
struct SegmentInfo {
    uint64_t file_offset;
    uint64_t file_size;
    uint64_t vaddr;
    uint64_t mem_size;
    uint32_t flags;
};

// ELF relocation information
struct RelocationInfo {
    uint64_t offset;
    uint64_t type;
    uint64_t addend;
    std::string symbol_name;
    uint64_t symbol_value;
};

// ELF symbol information
struct SymbolInfo {
    std::string name;
    uint64_t value;
    uint64_t size;
    uint8_t type;
    uint8_t bind;
    bool is_exported;
};

// ELF dynamic entry information
struct DynamicEntry {
    uint64_t tag;
    uint64_t value;
};

// ELF loader using LIEF
class ElfLoader {
public:
    ElfLoader();
    ~ElfLoader();
    
    // Parse ELF from file
    bool parse(const std::string& path);
    
    // Parse ELF from memory
    bool parse(const std::vector<uint8_t>& data);
    
    // Load into emulator memory at specified base address
    bool load(MemoryManager& memory, uint64_t base_address, LoadedModule& module);
    
    // Get required dependencies (DT_NEEDED)
    std::vector<std::string> get_dependencies() const;
    
    // Get exported symbols
    std::vector<SymbolInfo> get_exports() const;
    
    // Get imported symbols
    std::vector<SymbolInfo> get_imports() const;
    
    // Get relocations
    std::vector<RelocationInfo> get_relocations() const;
    
    // Get init/fini arrays
    std::vector<uint64_t> get_init_array() const;  // Deprecated - use get_init_array_info()
    std::vector<uint64_t> get_fini_array() const;

    // Get INIT_ARRAY address and size (returns {address, size})
    std::pair<uint64_t, uint64_t> get_init_array_info() const;

    // Get dynamic entries
    std::vector<DynamicEntry> get_dynamic_entries() const;
    
    // Get entry point (relative to base)
    uint64_t get_entry_point() const;
    
    // Get total memory size needed
    uint64_t get_memory_size() const;
    
    // Check if valid ELF
    bool is_valid() const { return binary_ != nullptr; }
    
    // Check architecture
    bool is_aarch64() const;

    // Check if this is an executable (ET_EXEC) vs shared library (ET_DYN)
    bool is_executable() const;

    // Get the minimum virtual address (base address for EXEC binaries)
    uint64_t get_min_vaddr() const;

private:
    std::unique_ptr<LIEF::ELF::Binary> binary_;
};

} // namespace cross_shim

