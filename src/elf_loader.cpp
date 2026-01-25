#include "elf_loader.h"
#include "memory_manager.h"
#include "cross_shim.h"
#include <LIEF/ELF.hpp>
#include <iostream>
#include <algorithm>

namespace cross_shim {

ElfLoader::ElfLoader() : binary_(nullptr) {}

ElfLoader::~ElfLoader() = default;

bool ElfLoader::parse(const std::string& path) {
    binary_ = LIEF::ELF::Parser::parse(path);
    return binary_ != nullptr;
}

bool ElfLoader::parse(const std::vector<uint8_t>& data) {
    binary_ = LIEF::ELF::Parser::parse(data);
    return binary_ != nullptr;
}

bool ElfLoader::is_aarch64() const {
    if (!binary_) return false;
    return binary_->header().machine_type() == LIEF::ELF::ARCH::AARCH64;
}

bool ElfLoader::is_executable() const {
    if (!binary_) return false;
    return binary_->header().file_type() == LIEF::ELF::Header::FILE_TYPE::EXEC;
}

uint64_t ElfLoader::get_min_vaddr() const {
    if (!binary_) return 0;

    uint64_t min_addr = UINT64_MAX;
    for (const auto& segment : binary_->segments()) {
        if (segment.type() != LIEF::ELF::Segment::TYPE::LOAD) continue;
        min_addr = std::min(min_addr, segment.virtual_address());
    }
    return min_addr == UINT64_MAX ? 0 : min_addr;
}

uint64_t ElfLoader::get_entry_point() const {
    if (!binary_) return 0;
    return binary_->entrypoint();
}

uint64_t ElfLoader::get_memory_size() const {
    if (!binary_) return 0;

    uint64_t min_addr = UINT64_MAX;
    uint64_t max_addr = 0;

    for (const auto& segment : binary_->segments()) {
        if (segment.type() != LIEF::ELF::Segment::TYPE::LOAD) continue;

        uint64_t start = segment.virtual_address();
        uint64_t end = start + segment.virtual_size();

        min_addr = std::min(min_addr, start);
        max_addr = std::max(max_addr, end);
    }

    if (min_addr == UINT64_MAX) return 0;
    return max_addr - min_addr;
}

std::vector<std::string> ElfLoader::get_dependencies() const {
    std::vector<std::string> deps;
    if (!binary_) return deps;

    for (const auto& entry : binary_->dynamic_entries()) {
        if (auto* needed = dynamic_cast<const LIEF::ELF::DynamicEntryLibrary*>(&entry)) {
            deps.push_back(needed->name());
        }
    }
    return deps;
}

std::vector<SymbolInfo> ElfLoader::get_exports() const {
    std::vector<SymbolInfo> exports;
    if (!binary_) return exports;

    for (const auto& sym : binary_->exported_symbols()) {
        if (sym.value() == 0) continue;

        SymbolInfo info;
        info.name = sym.name();
        info.value = sym.value();
        info.size = sym.size();
        info.type = static_cast<uint8_t>(sym.type());
        info.bind = static_cast<uint8_t>(sym.binding());
        info.is_exported = true;
        exports.push_back(info);
    }
    return exports;
}

std::vector<SymbolInfo> ElfLoader::get_imports() const {
    std::vector<SymbolInfo> imports;
    if (!binary_) return imports;

    for (const auto& sym : binary_->imported_symbols()) {
        SymbolInfo info;
        info.name = sym.name();
        info.value = sym.value();
        info.size = sym.size();
        info.type = static_cast<uint8_t>(sym.type());
        info.bind = static_cast<uint8_t>(sym.binding());
        info.is_exported = false;
        imports.push_back(info);
    }
    return imports;
}

std::vector<RelocationInfo> ElfLoader::get_relocations() const {
    std::vector<RelocationInfo> relocs;
    if (!binary_) return relocs;

    for (const auto& reloc : binary_->relocations()) {
        RelocationInfo info;
        info.offset = reloc.address();
        info.type = static_cast<uint64_t>(reloc.type());
        info.addend = reloc.addend();

        if (reloc.has_symbol()) {
            info.symbol_name = reloc.symbol()->name();
            info.symbol_value = reloc.symbol()->value();
        }

        relocs.push_back(info);
    }
    return relocs;
}

std::pair<uint64_t, uint64_t> ElfLoader::get_init_array_info() const {
    if (!binary_) return {0, 0};

    uint64_t init_array_addr = 0;
    uint64_t init_array_size = 0;

    // Find INIT_ARRAY and INIT_ARRAYSZ in dynamic entries
    for (const auto& entry : binary_->dynamic_entries()) {
        if (entry.tag() == LIEF::ELF::DynamicEntry::TAG::INIT_ARRAY) {
            init_array_addr = entry.value();
        } else if (entry.tag() == LIEF::ELF::DynamicEntry::TAG::INIT_ARRAYSZ) {
            init_array_size = entry.value();
        }
    }

    return {init_array_addr, init_array_size};
}

std::vector<uint64_t> ElfLoader::get_fini_array() const {
    std::vector<uint64_t> fini_funcs;
    if (!binary_) return fini_funcs;

    for (const auto& entry : binary_->dynamic_entries()) {
        if (auto* arr = dynamic_cast<const LIEF::ELF::DynamicEntryArray*>(&entry)) {
            if (arr->tag() == LIEF::ELF::DynamicEntry::TAG::FINI_ARRAY) {
                for (uint64_t addr : arr->array()) {
                    if (addr != 0 && addr != static_cast<uint64_t>(-1)) {
                        fini_funcs.push_back(addr);
                    }
                }
            }
        }
    }
    return fini_funcs;
}

std::vector<DynamicEntry> ElfLoader::get_dynamic_entries() const {
    std::vector<DynamicEntry> entries;
    if (!binary_) return entries;

    for (const auto& entry : binary_->dynamic_entries()) {
        DynamicEntry de;
        de.tag = static_cast<uint64_t>(entry.tag());
        de.value = entry.value();
        entries.push_back(de);
    }
    return entries;
}

bool ElfLoader::load(MemoryManager& memory, uint64_t base_address, LoadedModule& module) {
    if (!binary_) return false;

    // Find the minimum virtual address to calculate proper offsets
    uint64_t min_vaddr = UINT64_MAX;
    for (const auto& segment : binary_->segments()) {
        if (segment.type() != LIEF::ELF::Segment::TYPE::LOAD) continue;
        min_vaddr = std::min(min_vaddr, segment.virtual_address());
    }
    if (min_vaddr == UINT64_MAX) min_vaddr = 0;

    // Load each PT_LOAD segment
    for (const auto& segment : binary_->segments()) {
        if (segment.type() != LIEF::ELF::Segment::TYPE::LOAD) continue;

        uint64_t vaddr = segment.virtual_address() - min_vaddr + base_address;
        uint64_t memsz = segment.virtual_size();
        uint64_t filesz = segment.physical_size();

        // Calculate aligned addresses for mapping
        uint64_t aligned_addr = MemoryManager::align_down(vaddr, PAGE_SIZE);
        uint64_t offset_in_page = vaddr - aligned_addr;
        uint64_t aligned_size = MemoryManager::align_up(memsz + offset_in_page, PAGE_SIZE);

        // Convert permissions
        uint32_t perms = MEM_NONE;
        auto flags = segment.flags();
        if ((flags & LIEF::ELF::Segment::FLAGS::R) != LIEF::ELF::Segment::FLAGS::NONE) perms |= MEM_READ;
        if ((flags & LIEF::ELF::Segment::FLAGS::W) != LIEF::ELF::Segment::FLAGS::NONE) perms |= MEM_WRITE;
        if ((flags & LIEF::ELF::Segment::FLAGS::X) != LIEF::ELF::Segment::FLAGS::NONE) perms |= MEM_EXEC;

        // Unmap any existing region at this address (e.g., LowMemory region)
        // This allows loading binaries at addresses that were pre-mapped
        if (memory.is_mapped(aligned_addr)) {
            memory.unmap(aligned_addr, aligned_size);
        }

        // Map the memory region
        if (!memory.map(aligned_addr, aligned_size, perms)) {
            return false;
        }

        // Write segment content
        auto content = segment.content();
        if (!content.empty()) {
            if (!memory.write(vaddr, content.data(), std::min(filesz, (uint64_t)content.size()))) {
                return false;
            }
        }

        // Zero the BSS portion (memsz > filesz)
        if (memsz > filesz) {
            if (!memory.zero(vaddr + filesz, memsz - filesz)) {
                return false;
            }
        }
    }

    // Fill in module info
    module.base_address = base_address;
    module.size = get_memory_size();

    // Collect exports
    for (const auto& sym : get_exports()) {
        if (!sym.name.empty() && sym.value != 0) {
            module.exports[sym.name] = base_address + sym.value - min_vaddr;
        }
    }

    return true;
}

} // namespace cross_shim
