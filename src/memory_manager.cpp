#include "debug_log.h"
#include "memory_manager.h"
#include "cross_shim.h"
#include "qemu_api.h"
#include <cstring>
#include <algorithm>
#include <iostream>
#include <sys/mman.h>
#include <atomic>

namespace cross_shim {

// Guest base is set via set_qemu_ready() after QEMU init

// HeapAllocator implementation with sorted free list (std::map)
// This provides O(log n) operations instead of O(n log n) sorting
HeapAllocator::HeapAllocator(uint64_t base, uint64_t size)
    : base_(base), size_(size), high_water_mark_(base) {}

uint64_t HeapAllocator::allocate(uint64_t alloc_size, uint64_t alignment) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (alloc_size == 0) {
        alloc_size = 1;  // Minimum allocation
    }

    // Use size-indexed lookup for O(log n) finding of suitable blocks
    uint64_t min_required = alloc_size;  // Start with minimum, will check alignment

    // Find blocks >= min_required size
    auto size_it = free_blocks_by_size_.lower_bound(min_required);

    while (size_it != free_blocks_by_size_.end()) {
        uint64_t block_size = size_it->first;
        uint64_t block_addr = size_it->second;

        uint64_t aligned = (block_addr + alignment - 1) & ~(alignment - 1);
        uint64_t padding = aligned - block_addr;

        if (block_size >= alloc_size + padding) {
            uint64_t result = aligned;

            // Remove the block from both indices
            remove_free_block(block_addr, block_size);

            // If there's leftover space at the beginning (due to alignment), add it back
            if (padding > 0) {
                add_free_block(block_addr, padding);
            }

            // If there's leftover space at the end, add it back
            uint64_t remaining = block_size - alloc_size - padding;
            if (remaining >= 16) {  // Only keep if >= 16 bytes
                add_free_block(result + alloc_size, remaining);
            }

            // Track allocation
            allocations_[result] = alloc_size;

            return result;
        }
        ++size_it;
    }

    // No suitable free block found, allocate from high water mark
    uint64_t aligned = (high_water_mark_ + alignment - 1) & ~(alignment - 1);

    // Check if we have enough space
    if (aligned + alloc_size > base_ + size_) {
        return 0;  // Out of memory
    }

    uint64_t result = aligned;
    high_water_mark_ = aligned + alloc_size;

    // Track allocation
    allocations_[result] = alloc_size;

    return result;
}

void HeapAllocator::free(uint64_t address) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (address == 0) return;

    auto it = allocations_.find(address);
    if (it != allocations_.end()) {
        uint64_t freed_size = it->second;
        allocations_.erase(it);

        // Add to free list with immediate coalescing
        add_free_block(address, freed_size);
    }
}

// Remove a free block from both indices
void HeapAllocator::remove_free_block(uint64_t address, uint64_t size) {
    // Remove from address index
    free_blocks_.erase(address);

    // Remove from size index - need to find the exact entry
    auto range = free_blocks_by_size_.equal_range(size);
    for (auto it = range.first; it != range.second; ++it) {
        if (it->second == address) {
            free_blocks_by_size_.erase(it);
            break;
        }
    }
}

// Add a free block and coalesce with adjacent neighbors (O(log n))
void HeapAllocator::add_free_block(uint64_t address, uint64_t size) {
    uint64_t new_addr = address;
    uint64_t new_size = size;

    // Find where this block would be inserted
    auto next = free_blocks_.lower_bound(address);

    // Check if we can merge with predecessor
    if (next != free_blocks_.begin()) {
        auto prev = std::prev(next);
        uint64_t prev_addr = prev->first;
        uint64_t prev_size = prev->second;
        uint64_t prev_end = prev_addr + prev_size;
        if (prev_end == address) {
            // Merge with predecessor - remove old entry from both indices
            remove_free_block(prev_addr, prev_size);
            new_addr = prev_addr;
            new_size = prev_size + size;
        }
    }

    // Check if we can merge with successor
    if (next != free_blocks_.end()) {
        uint64_t next_addr = next->first;
        uint64_t next_size = next->second;
        if (new_addr + new_size == next_addr) {
            // Merge with successor - remove old entry from both indices
            remove_free_block(next_addr, next_size);
            new_size += next_size;
        }
    }

    // Insert the (possibly merged) block into both indices
    free_blocks_[new_addr] = new_size;
    free_blocks_by_size_.insert({new_size, new_addr});
}

uint64_t HeapAllocator::realloc(uint64_t address, uint64_t new_size) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (address == 0) {
        return allocate(new_size);
    }

    if (new_size == 0) {
        free(address);
        return 0;
    }

    auto it = allocations_.find(address);
    if (it == allocations_.end()) {
        return 0;  // Invalid address
    }

    uint64_t old_size = it->second;
    if (new_size <= old_size) {
        // Shrinking - could return excess to free list but keep it simple
        return address;
    }

    // Allocate new block
    uint64_t new_addr = allocate(new_size);
    if (new_addr == 0) {
        return 0;
    }

    // Note: Caller must copy data from old to new address
    // Free old block
    free(address);

    return new_addr;
}

uint64_t HeapAllocator::get_used() const {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    uint64_t total = 0;
    for (const auto& alloc : allocations_) {
        total += alloc.second;
    }
    return total;
}

uint64_t HeapAllocator::get_allocation_size(uint64_t address) const {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    auto it = allocations_.find(address);
    if (it != allocations_.end()) {
        return it->second;
    }
    return 0;
}

// MemoryManager implementation
MemoryManager::MemoryManager(void* /* unused */)
    : heap_(HEAP_BASE, HEAP_SIZE), qemu_ready_(false), guest_base_(0) {}

MemoryManager::~MemoryManager() {
    // Clean up any host-allocated memory for non-shared regions
    for (auto& region : regions_) {
        if (region.host_ptr && !region.is_shared) {
            munmap(region.host_ptr, region.size);
        }
    }
}

void MemoryManager::set_qemu_ready(uint64_t base) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);

    guest_base_ = base;
    qemu_ready_ = true;

    EMU_LOG << "[MEM] QEMU ready with guest_base=0x" << std::hex << guest_base_ << std::dec << std::endl;

    // Now sync all existing host memory regions to QEMU guest memory
    // We use target_mmap to allocate in guest space, then copy data from host
    CPUState* cpu = libafl_qemu_get_cpu(0);
    if (!cpu) {
        EMU_LOG << "[MEM] WARNING: No CPU available for memory sync" << std::endl;
        return;
    }

    for (auto& region : regions_) {
        if (!region.host_ptr || region.size == 0) continue;

        // Convert our permissions to mmap permissions
        int prot = 0;
        if (region.perms & MEM_READ) prot |= PROT_READ;
        if (region.perms & MEM_WRITE) prot |= PROT_WRITE;
        if (region.perms & MEM_EXEC) prot |= PROT_EXEC;

        // Map this region in QEMU's guest space
        uint64_t mapped = target_mmap(region.address, region.size, prot,
                                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
        if (mapped == (uint64_t)-1 || mapped != region.address) {
            EMU_LOG << "[MEM] WARNING: Failed to map region " << region.name
                      << " at 0x" << std::hex << region.address
                      << " (got 0x" << mapped << ")" << std::dec << std::endl;
            // Continue anyway - we'll try to use the host memory directly
        } else {
            EMU_LOG << "[MEM] Mapped region " << region.name << " at guest 0x"
                      << std::hex << region.address << std::dec << std::endl;
        }

        // Copy data from host memory to guest memory
        int err = cpu_memory_rw_debug(cpu, region.address, region.host_ptr, region.size, 1);
        if (err != 0) {
            EMU_LOG << "[MEM] WARNING: Failed to copy region " << region.name
                      << " to guest memory (err=" << err << ")" << std::endl;
        }
    }
}

void* MemoryManager::guest_to_host(uint64_t guest_address) const {
    if (!qemu_ready_) return nullptr;
    return reinterpret_cast<void*>(guest_base_ + guest_address);
}

uint64_t MemoryManager::align_down(uint64_t value, uint64_t alignment) {
    return value & ~(alignment - 1);
}

uint64_t MemoryManager::align_up(uint64_t value, uint64_t alignment) {
    return (value + alignment - 1) & ~(alignment - 1);
}

bool MemoryManager::map(uint64_t address, uint64_t size, uint32_t perms, const std::string& name) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);

    // Allocate host memory for this region
    void* host_ptr = mmap(nullptr, size, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (host_ptr == MAP_FAILED) {
        EMU_LOG << "[MEM] Failed to allocate host memory for region 0x"
                  << std::hex << address << std::dec << std::endl;
        return false;
    }

    // Zero the memory
    memset(host_ptr, 0, size);

    MemoryRegion region;
    region.address = address;
    region.size = size;
    region.perms = perms;
    region.name = name;
    region.host_ptr = host_ptr;
    region.is_shared = false;  // We own this memory

    regions_.push_back(region);

    EMU_LOG << "[MEM] Mapped region " << name << " at 0x" << std::hex << address
              << " (host=" << host_ptr << ", size=0x" << size << ")" << std::dec << std::endl;

    // If QEMU is ready, also map in guest space
    if (qemu_ready_) {
        int prot = 0;
        if (perms & MEM_READ) prot |= PROT_READ;
        if (perms & MEM_WRITE) prot |= PROT_WRITE;
        if (perms & MEM_EXEC) prot |= PROT_EXEC;

        EMU_LOG << "[MEM] Calling target_mmap for guest 0x" << std::hex << address
                  << " size=0x" << size << std::dec << std::endl;

        uint64_t mapped = target_mmap(address, size, prot,
                                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
        if (mapped == (uint64_t)-1 || mapped != address) {
            EMU_LOG << "[MEM] WARNING: Failed to map region " << name
                      << " in QEMU at 0x" << std::hex << address
                      << " (got 0x" << mapped << ")" << std::dec << std::endl;
        } else {
            EMU_LOG << "[MEM] Mapped region " << name << " at guest 0x"
                      << std::hex << mapped << std::dec << std::endl;
        }
    }
    return true;
}

bool MemoryManager::map_shared(uint64_t address, uint64_t size, uint32_t perms,
                                void* host_ptr, const std::string& name) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);

    MemoryRegion region;
    region.address = address;
    region.size = size;
    region.perms = perms;
    region.name = name;
    region.host_ptr = host_ptr;
    region.is_shared = true;  // We don't own this memory

    regions_.push_back(region);

    EMU_LOG << "[MEM] Mapped shared region " << name << " at 0x" << std::hex << address
              << " (host=" << host_ptr << ", size=0x" << size << ")" << std::dec << std::endl;
    return true;
}

bool MemoryManager::map_aligned(uint64_t address, uint64_t size, uint32_t perms, const std::string& name) {
    uint64_t aligned_addr = align_down(address, PAGE_SIZE);
    uint64_t aligned_size = align_up(size + (address - aligned_addr), PAGE_SIZE);
    return map(aligned_addr, aligned_size, perms, name);
}

bool MemoryManager::unmap(uint64_t address, uint64_t size) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);

    // Find and remove from regions list, freeing host memory if we own it
    for (auto it = regions_.begin(); it != regions_.end(); ++it) {
        if (it->address == address && it->size == size) {
            if (it->host_ptr && !it->is_shared) {
                munmap(it->host_ptr, it->size);
            }
            regions_.erase(it);
            EMU_LOG << "[MEM] Unmapped region at 0x" << std::hex << address << std::dec << std::endl;
            return true;
        }
    }

    EMU_LOG << "[MEM] Unmap failed: region at 0x" << std::hex << address << " not found" << std::dec << std::endl;
    return false;
}

bool MemoryManager::is_mapped(uint64_t address) const {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    
    for (const auto& region : regions_) {
        if (address >= region.address && address < region.address + region.size) {
            return true;
        }
    }
    return false;
}

bool MemoryManager::is_mapped(uint64_t address, uint64_t size) const {
    return is_mapped(address) && is_mapped(address + size - 1);
}

bool MemoryManager::read(uint64_t address, void* buffer, uint64_t size) const {
    // CRITICAL: Memory barrier to ensure we see writes from other threads
    // In MTTCG mode, another thread may have written to this memory location.
    std::atomic_thread_fence(std::memory_order_acquire);

    // If QEMU is ready, use cpu_memory_rw_debug for guest memory access
    // This is already thread-safe, no mutex needed
    if (qemu_ready_) {
        CPUState* cpu = libafl_qemu_current_cpu();
        if (!cpu) cpu = libafl_qemu_get_cpu(0);
        if (cpu) {
            int err = cpu_memory_rw_debug(cpu, address, buffer, size, 0);
            if (err == 0) return true;
            // Fall through to try host memory
        }
    }

    // Pre-QEMU fallback: need lock since regions_ may be modified
    std::lock_guard<std::recursive_mutex> lock(mutex_);

    // Read directly from host memory (pre-QEMU or fallback)
    for (const auto& region : regions_) {
        if (address >= region.address &&
            address + size <= region.address + region.size &&
            region.host_ptr) {
            uint64_t offset = address - region.address;
            memcpy(buffer, static_cast<char*>(region.host_ptr) + offset, size);
            return true;
        }
    }

    // Memory not mapped
    EMU_LOG << "[MEM] Read failed: address 0x" << std::hex << address
              << " (size=0x" << size << ") not mapped" << std::dec << std::endl;
    return false;
}

bool MemoryManager::write(uint64_t address, const void* buffer, uint64_t size) {
    // If QEMU is ready, use cpu_memory_rw_debug for guest memory access
    // This is already thread-safe, no mutex needed
    if (qemu_ready_) {
        CPUState* cpu = libafl_qemu_current_cpu();
        if (!cpu) cpu = libafl_qemu_get_cpu(0);
        if (cpu) {
            int err = cpu_memory_rw_debug(cpu, address, const_cast<void*>(buffer), size, 1);
            if (err == 0) {
                // CRITICAL: Memory barrier to ensure writes are visible to other threads
                std::atomic_thread_fence(std::memory_order_release);
                return true;
            }
            // Fall through to try host memory
        }
    }

    // Pre-QEMU fallback: need lock since regions_ may be modified
    std::lock_guard<std::recursive_mutex> lock(mutex_);

    // Write directly to host memory (pre-QEMU or fallback)
    for (auto& region : regions_) {
        if (address >= region.address &&
            address + size <= region.address + region.size &&
            region.host_ptr) {
            uint64_t offset = address - region.address;
            memcpy(static_cast<char*>(region.host_ptr) + offset, buffer, size);
            return true;
        }
    }

    // Memory not mapped
    EMU_LOG << "[MEM] Write failed: address 0x" << std::hex << address
              << " (size=0x" << size << ") not mapped" << std::dec << std::endl;
    return false;
}

bool MemoryManager::zero(uint64_t address, uint64_t size) {
    std::vector<uint8_t> zeros(size, 0);
    return write(address, zeros.data(), size);
}

void* MemoryManager::get_host_ptr(uint64_t guest_address) const {
    // When QEMU is ready with guest_base=0, the guest address IS the host address
    // that QEMU's translated code uses. No lock needed - this is a simple calculation.
    if (qemu_ready_ && guest_base_ == 0) {
        // Fast path: return guest address as host address (since guest_base=0)
        // The address is valid if it's in QEMU's mapped range
        return reinterpret_cast<void*>(guest_address);
    }

    // Pre-QEMU fallback: need lock since regions_ may be modified
    std::lock_guard<std::recursive_mutex> lock(mutex_);

    // Pre-QEMU fallback: use our allocated host memory
    for (const auto& region : regions_) {
        if (guest_address >= region.address &&
            guest_address < region.address + region.size &&
            region.host_ptr) {
            uint64_t offset = guest_address - region.address;
            return static_cast<char*>(region.host_ptr) + offset;
        }
    }

    return nullptr;
}

bool MemoryManager::map_into_engine(void* /* unused */) const {
    // QEMU version: memory regions are already accessible via host pointers
    // QEMU usermode uses guest_base offset for address translation
    // This function is kept for API compatibility but is now a no-op
    std::lock_guard<std::recursive_mutex> lock(const_cast<std::recursive_mutex&>(mutex_));

    EMU_LOG << "[MEM] map_into_engine: " << regions_.size() << " regions available" << std::endl;
    for (const auto& region : regions_) {
        EMU_LOG << "[MEM]   " << region.name << ": 0x" << std::hex << region.address
                  << " - 0x" << (region.address + region.size) << " (host="
                  << region.host_ptr << ")" << std::dec << std::endl;
    }

    return true;
}

} // namespace cross_shim


