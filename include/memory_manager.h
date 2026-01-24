#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <mutex>
#include <sys/mman.h>

namespace cross_shim {

// Memory region permissions
enum MemPerm {
    MEM_NONE  = 0,
    MEM_READ  = 1,
    MEM_WRITE = 2,
    MEM_EXEC  = 4,
    MEM_ALL   = 7
};

// Memory region tracking
struct MemoryRegion {
    uint64_t address;
    uint64_t size;
    uint32_t perms;
    std::string name;
    void* host_ptr;  // Host memory pointer (for shared memory)
    bool is_shared;  // Whether this region uses shared memory
};

// Free block for heap allocator
struct FreeBlock {
    uint64_t address;
    uint64_t size;
};

// Heap allocator with dual-indexed free list for emulated memory
// Uses two maps for O(log n) allocation AND O(log n) coalescing:
// - free_blocks_: sorted by address for fast neighbor coalescing
// - free_blocks_by_size_: sorted by size for fast allocation lookup
class HeapAllocator {
public:
    HeapAllocator(uint64_t base, uint64_t size);

    uint64_t allocate(uint64_t size, uint64_t alignment = 16);
    void free(uint64_t address);
    uint64_t realloc(uint64_t address, uint64_t new_size);

    uint64_t get_base() const { return base_; }
    uint64_t get_size() const { return size_; }
    uint64_t get_used() const;
    uint64_t get_allocation_size(uint64_t address) const;
    size_t get_allocation_count() const { return allocations_.size(); }
    size_t get_free_block_count() const { return free_blocks_.size(); }

private:
    // Add a free block and coalesce with neighbors (O(log n))
    void add_free_block(uint64_t address, uint64_t size);
    // Remove a free block from both indices
    void remove_free_block(uint64_t address, uint64_t size);

    uint64_t base_;
    uint64_t size_;
    uint64_t high_water_mark_;  // Highest address ever allocated
    std::unordered_map<uint64_t, uint64_t> allocations_;  // address -> size
    std::map<uint64_t, uint64_t> free_blocks_;  // Sorted by address: address -> size
    std::multimap<uint64_t, uint64_t> free_blocks_by_size_;  // Sorted by size: size -> address
    mutable std::recursive_mutex mutex_;  // Thread safety for heap operations (recursive for realloc)
};

class SharedMemoryManager;

// Memory manager for QEMU
//
// Before QEMU is initialized, memory is stored in host memory.
// After set_qemu_ready() is called, we sync to QEMU's guest memory
// and use cpu_memory_rw_debug() for all subsequent access.
class MemoryManager {
public:
    explicit MemoryManager(void* unused);
    ~MemoryManager();

    // Mark QEMU as ready and sync host memory to guest memory
    // This must be called after libafl_qemu_init() but before any emulation
    void set_qemu_ready(uint64_t guest_base);

    // Map memory region (allocates new memory in QEMU guest space)
    bool map(uint64_t address, uint64_t size, uint32_t perms, const std::string& name = "");
    bool map_aligned(uint64_t address, uint64_t size, uint32_t perms, const std::string& name = "");

    // Map memory region with shared host memory (for multi-engine threading)
    bool map_shared(uint64_t address, uint64_t size, uint32_t perms,
                    void* host_ptr, const std::string& name = "");

    // Unmap memory region
    bool unmap(uint64_t address, uint64_t size);

    // Check if address is mapped
    bool is_mapped(uint64_t address) const;
    bool is_mapped(uint64_t address, uint64_t size) const;

    // Read/write memory (uses QEMU cpu_memory_rw_debug when ready)
    bool read(uint64_t address, void* buffer, uint64_t size) const;
    bool write(uint64_t address, const void* buffer, uint64_t size);

    // Zero memory
    bool zero(uint64_t address, uint64_t size);

    // Get heap allocator
    HeapAllocator& heap() { return heap_; }

    // Get all regions
    const std::vector<MemoryRegion>& regions() const { return regions_; }

    // Get host pointer for a guest address
    void* get_host_ptr(uint64_t guest_address) const;

    // Translate guest address to host address (using QEMU's guest_base)
    void* guest_to_host(uint64_t guest_address) const;

    // Map all regions into a new engine (for threading)
    bool map_into_engine(void* engine) const;

    // Check if QEMU is ready
    bool is_qemu_ready() const { return qemu_ready_; }

    // Utility functions
    static uint64_t align_down(uint64_t value, uint64_t alignment);
    static uint64_t align_up(uint64_t value, uint64_t alignment);

private:
    std::vector<MemoryRegion> regions_;
    HeapAllocator heap_;
    mutable std::recursive_mutex mutex_;
    bool qemu_ready_;
    uint64_t guest_base_;
};

} // namespace cross_shim
