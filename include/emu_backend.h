/**
 * Emulator Backend Abstraction Layer
 *
 * Provides a common interface for emulation backends.
 * Currently uses LibAFL QEMU with MTTCG for real parallel threads.
 *
 * This abstraction allows the emulator core to be backend-agnostic.
 */

#ifndef EMU_BACKEND_H
#define EMU_BACKEND_H

#include <cstdint>
#include <functional>

namespace cross_shim {

// Forward declarations
class Emulator;

/**
 * CPU handle - opaque pointer to backend-specific CPU state
 */
using CpuHandle = void*;

/**
 * ARM64 register indices
 * These are backend-agnostic and map to the appropriate backend constants
 */
enum Arm64Reg {
    REG_X0 = 0, REG_X1, REG_X2, REG_X3, REG_X4, REG_X5, REG_X6, REG_X7,
    REG_X8, REG_X9, REG_X10, REG_X11, REG_X12, REG_X13, REG_X14, REG_X15,
    REG_X16, REG_X17, REG_X18, REG_X19, REG_X20, REG_X21, REG_X22, REG_X23,
    REG_X24, REG_X25, REG_X26, REG_X27, REG_X28, REG_X29, REG_X30,
    REG_SP = 31,
    REG_PC = 32,
    REG_NZCV = 33,
    REG_TPIDR_EL0 = 34,
    REG_LR = REG_X30,
    REG_FP = REG_X29,
};

/**
 * Hook callback types
 */
using SyscallHook = std::function<bool(CpuHandle cpu, int syscall_num, uint64_t* args)>;
using BlockHook = std::function<void(CpuHandle cpu, uint64_t pc, uint32_t size)>;
using ThreadHook = std::function<void(CpuHandle cpu, uint64_t tid)>;

/**
 * Emulator backend interface
 *
 * Abstract base class that defines the common operations for all backends.
 */
class EmuBackend {
public:
    virtual ~EmuBackend() = default;

    // =========================================================================
    // Initialization
    // =========================================================================

    /**
     * Initialize the backend
     * @return true on success
     */
    virtual bool initialize() = 0;

    /**
     * Shutdown the backend
     */
    virtual void shutdown() = 0;

    // =========================================================================
    // CPU Access
    // =========================================================================

    /**
     * Get the current CPU for the calling thread
     * @return CPU handle or nullptr if not in emulation context
     */
    virtual CpuHandle current_cpu() = 0;

    /**
     * Get CPU by index
     * @param index CPU index (0-based)
     * @return CPU handle or nullptr
     */
    virtual CpuHandle get_cpu(int index) = 0;

    /**
     * Get number of CPUs
     */
    virtual int num_cpus() = 0;

    // =========================================================================
    // Register Access
    // =========================================================================

    /**
     * Read a 64-bit register
     * @param cpu CPU handle (nullptr for current)
     * @param reg Register index
     * @return Register value
     */
    virtual uint64_t read_reg(CpuHandle cpu, int reg) = 0;

    /**
     * Write a 64-bit register
     * @param cpu CPU handle (nullptr for current)
     * @param reg Register index
     * @param value Value to write
     */
    virtual void write_reg(CpuHandle cpu, int reg, uint64_t value) = 0;

    // =========================================================================
    // Memory Access
    // =========================================================================

    /**
     * Map memory region
     * @param address Guest address (must be page-aligned)
     * @param size Size in bytes (must be page-aligned)
     * @param perms Permission flags (MEM_READ | MEM_WRITE | MEM_EXEC)
     * @return true on success
     */
    virtual bool mem_map(uint64_t address, uint64_t size, uint32_t perms) = 0;

    /**
     * Map memory with existing host pointer (zero-copy)
     * @param address Guest address
     * @param size Size in bytes
     * @param perms Permission flags
     * @param host_ptr Host memory to map
     * @return true on success
     */
    virtual bool mem_map_ptr(uint64_t address, uint64_t size, uint32_t perms, void* host_ptr) = 0;

    /**
     * Unmap memory region
     */
    virtual bool mem_unmap(uint64_t address, uint64_t size) = 0;

    /**
     * Read from guest memory
     * @param address Guest address
     * @param buffer Output buffer
     * @param size Number of bytes
     * @return true on success
     */
    virtual bool mem_read(uint64_t address, void* buffer, size_t size) = 0;

    /**
     * Write to guest memory
     * @param address Guest address
     * @param buffer Input buffer
     * @param size Number of bytes
     * @return true on success
     */
    virtual bool mem_write(uint64_t address, const void* buffer, size_t size) = 0;

    /**
     * Get host pointer for guest address (for direct access)
     * @param guest_addr Guest address
     * @return Host pointer or nullptr if not mapped
     */
    virtual void* get_host_ptr(uint64_t guest_addr) = 0;

    // =========================================================================
    // Execution Control
    // =========================================================================

    /**
     * Start/continue execution
     * @param address Start address
     * @param end_address Stop when reaching this address (0 = run forever)
     * @return true on normal exit
     */
    virtual bool run(uint64_t address, uint64_t end_address = 0) = 0;

    /**
     * Stop execution
     */
    virtual void stop() = 0;

    // =========================================================================
    // Hook Registration
    // =========================================================================

    /**
     * Add syscall hook (called before syscall)
     * @param hook Callback function, returns true to skip syscall
     */
    virtual void add_syscall_hook(SyscallHook hook) = 0;

    /**
     * Add block execution hook
     * @param hook Callback function
     * @param start Start address (0 = all)
     * @param end End address (0 = all)
     */
    virtual void add_block_hook(BlockHook hook, uint64_t start = 0, uint64_t end = 0) = 0;

    /**
     * Add thread creation hook
     * @param hook Callback function
     */
    virtual void add_thread_hook(ThreadHook hook) = 0;

    // =========================================================================
    // Utilities
    // =========================================================================

    /**
     * Flush JIT/translation cache
     */
    virtual void flush_jit() = 0;

    /**
     * Get backend name
     */
    virtual const char* name() const = 0;

    /**
     * Check if backend supports real threading (MTTCG)
     */
    virtual bool supports_mttcg() const = 0;
};

// Factory function to create the appropriate backend
std::unique_ptr<EmuBackend> create_backend();

} // namespace cross_shim

#endif // EMU_BACKEND_H
