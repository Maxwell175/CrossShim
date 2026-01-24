/**
 * LibAFL QEMU C/C++ Wrapper
 *
 * This header provides C-compatible functions to access LibAFL QEMU's
 * ARM64 usermode emulator from C++ code.
 *
 * Key features:
 * - Multi-threaded TCG (MTTCG): Each guest thread runs on a real host thread
 * - guest_base offset: Guest addresses are offset in host memory
 * - Native LSE atomics: No manual emulation needed
 * - Real OS threading: No cooperative scheduling required
 */

#ifndef QEMU_WRAPPER_H
#define QEMU_WRAPPER_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// =============================================================================
// Error Codes
// =============================================================================

typedef enum {
    QEMU_ERR_OK = 0,
    QEMU_ERR_NOT_INITIALIZED = -1,
    QEMU_ERR_INVALID_ARGUMENT = -2,
    QEMU_ERR_MEMORY_ERROR = -3,
    QEMU_ERR_CPU_NOT_FOUND = -4,
    QEMU_ERR_HOOK_ERROR = -5,
    QEMU_ERR_INIT_ERROR = -6,
} QemuError;

// =============================================================================
// ARM64 Register Definitions
// =============================================================================

/**
 * ARM64 register indices for the emulator.
 */
typedef enum {
    // General purpose registers
    QEMU_ARM64_REG_X0 = 0,
    QEMU_ARM64_REG_X1 = 1,
    QEMU_ARM64_REG_X2 = 2,
    QEMU_ARM64_REG_X3 = 3,
    QEMU_ARM64_REG_X4 = 4,
    QEMU_ARM64_REG_X5 = 5,
    QEMU_ARM64_REG_X6 = 6,
    QEMU_ARM64_REG_X7 = 7,
    QEMU_ARM64_REG_X8 = 8,
    QEMU_ARM64_REG_X9 = 9,
    QEMU_ARM64_REG_X10 = 10,
    QEMU_ARM64_REG_X11 = 11,
    QEMU_ARM64_REG_X12 = 12,
    QEMU_ARM64_REG_X13 = 13,
    QEMU_ARM64_REG_X14 = 14,
    QEMU_ARM64_REG_X15 = 15,
    QEMU_ARM64_REG_X16 = 16,
    QEMU_ARM64_REG_X17 = 17,
    QEMU_ARM64_REG_X18 = 18,
    QEMU_ARM64_REG_X19 = 19,
    QEMU_ARM64_REG_X20 = 20,
    QEMU_ARM64_REG_X21 = 21,
    QEMU_ARM64_REG_X22 = 22,
    QEMU_ARM64_REG_X23 = 23,
    QEMU_ARM64_REG_X24 = 24,
    QEMU_ARM64_REG_X25 = 25,
    QEMU_ARM64_REG_X26 = 26,
    QEMU_ARM64_REG_X27 = 27,
    QEMU_ARM64_REG_X28 = 28,
    QEMU_ARM64_REG_X29 = 29,  // Frame pointer (FP)
    QEMU_ARM64_REG_X30 = 30,  // Link register (LR)
    QEMU_ARM64_REG_SP = 31,   // Stack pointer
    QEMU_ARM64_REG_PC = 32,   // Program counter

    // Condition flags
    QEMU_ARM64_REG_NZCV = 33,

    // Thread-local storage
    QEMU_ARM64_REG_TPIDR_EL0 = 34,

    // SIMD/NEON registers (V0-V31, 128-bit each)
    QEMU_ARM64_REG_V0 = 64,
    QEMU_ARM64_REG_V1 = 65,
    QEMU_ARM64_REG_V2 = 66,
    QEMU_ARM64_REG_V3 = 67,
    QEMU_ARM64_REG_V4 = 68,
    QEMU_ARM64_REG_V5 = 69,
    QEMU_ARM64_REG_V6 = 70,
    QEMU_ARM64_REG_V7 = 71,
    QEMU_ARM64_REG_V8 = 72,
    QEMU_ARM64_REG_V9 = 73,
    QEMU_ARM64_REG_V10 = 74,
    QEMU_ARM64_REG_V11 = 75,
    QEMU_ARM64_REG_V12 = 76,
    QEMU_ARM64_REG_V13 = 77,
    QEMU_ARM64_REG_V14 = 78,
    QEMU_ARM64_REG_V15 = 79,
    QEMU_ARM64_REG_V16 = 80,
    QEMU_ARM64_REG_V17 = 81,
    QEMU_ARM64_REG_V18 = 82,
    QEMU_ARM64_REG_V19 = 83,
    QEMU_ARM64_REG_V20 = 84,
    QEMU_ARM64_REG_V21 = 85,
    QEMU_ARM64_REG_V22 = 86,
    QEMU_ARM64_REG_V23 = 87,
    QEMU_ARM64_REG_V24 = 88,
    QEMU_ARM64_REG_V25 = 89,
    QEMU_ARM64_REG_V26 = 90,
    QEMU_ARM64_REG_V27 = 91,
    QEMU_ARM64_REG_V28 = 92,
    QEMU_ARM64_REG_V29 = 93,
    QEMU_ARM64_REG_V30 = 94,
    QEMU_ARM64_REG_V31 = 95,

    // Floating point control/status
    QEMU_ARM64_REG_FPCR = 96,
    QEMU_ARM64_REG_FPSR = 97,

    // Aliases for convenience
    QEMU_ARM64_REG_LR = QEMU_ARM64_REG_X30,
    QEMU_ARM64_REG_FP = QEMU_ARM64_REG_X29,
} QemuArm64Reg;

// =============================================================================
// Memory Protection Flags
// =============================================================================

#define QEMU_PROT_NONE  0
#define QEMU_PROT_READ  1
#define QEMU_PROT_WRITE 2
#define QEMU_PROT_EXEC  4
#define QEMU_PROT_ALL   7

// =============================================================================
// Callback Types
// =============================================================================

/**
 * Syscall pre-hook callback
 * Called before syscall execution. Can modify args array to change parameters.
 *
 * @param cpu      CPU state pointer
 * @param syscall  Syscall number
 * @param args     Array of 8 syscall arguments (can be modified)
 */
typedef void (*QemuSyscallPreHook)(void* cpu, int syscall, uint64_t* args);

/**
 * Syscall post-hook callback
 * Called after syscall execution with the return value.
 *
 * @param cpu      CPU state pointer
 * @param syscall  Syscall number
 * @param ret      Syscall return value
 */
typedef void (*QemuSyscallPostHook)(void* cpu, int syscall, uint64_t ret);

/**
 * Thread creation hook callback
 * Called when a new thread is created via clone().
 *
 * @param cpu  CPU state pointer for the new thread
 * @param tid  Thread ID of the new thread
 */
typedef void (*QemuThreadHook)(void* cpu, uint64_t tid);

/**
 * Block execution hook callback
 * Called at the start of each translated basic block.
 *
 * @param cpu   CPU state pointer
 * @param pc    Program counter (start of block)
 * @param size  Size of the block in bytes
 */
typedef void (*QemuBlockHook)(void* cpu, uint64_t pc, uint32_t size);

// =============================================================================
// Initialization Functions
// =============================================================================

/**
 * Initialize LibAFL QEMU for ARM64 usermode emulation
 *
 * @param argc  Argument count (pass QEMU options like "-cpu max")
 * @param argv  Argument vector
 * @return      0 on success, negative error code on failure
 */
int qemu_init(int argc, const char** argv);

/**
 * Deinitialize LibAFL QEMU and free resources
 */
void qemu_deinit(void);

/**
 * Check if QEMU is initialized
 *
 * @return true if initialized, false otherwise
 */
bool qemu_is_initialized(void);

/**
 * Get the guest base address for memory translation
 *
 * In QEMU usermode, guest addresses are offset by guest_base:
 *   host_addr = guest_addr + guest_base
 *
 * @return Guest base address
 */
uint64_t qemu_get_guest_base(void);

// =============================================================================
// CPU Access Functions
// =============================================================================

/**
 * Get the current CPU for the calling thread
 *
 * In MTTCG mode, each host thread has its own vCPU.
 *
 * @return CPU pointer or NULL if not in emulation context
 */
void* qemu_current_cpu(void);

/**
 * Get CPU by index
 *
 * @param index  CPU index (0-based)
 * @return       CPU pointer or NULL if index is out of range
 */
void* qemu_get_cpu(int index);

/**
 * Get the number of CPUs
 *
 * @return Number of vCPUs
 */
int qemu_num_cpus(void);

// =============================================================================
// Register Access Functions
// =============================================================================

/**
 * Read a register value from a CPU
 *
 * @param cpu  CPU pointer from qemu_current_cpu() or qemu_get_cpu()
 * @param reg  Register index (QemuArm64Reg enum value)
 * @return     Register value (64-bit)
 */
uint64_t qemu_read_reg(void* cpu, int reg);

/**
 * Write a register value to a CPU
 *
 * @param cpu    CPU pointer
 * @param reg    Register index (QemuArm64Reg enum value)
 * @param value  Value to write
 */
void qemu_write_reg(void* cpu, int reg, uint64_t value);

/**
 * Read multiple registers at once (more efficient for context saves)
 *
 * @param cpu     CPU pointer
 * @param regs    Array of register indices
 * @param values  Output array for register values
 * @param count   Number of registers to read
 * @return        0 on success, negative error code on failure
 */
int qemu_read_regs(void* cpu, const int* regs, uint64_t* values, size_t count);

/**
 * Write multiple registers at once
 *
 * @param cpu     CPU pointer
 * @param regs    Array of register indices
 * @param values  Array of values to write
 * @param count   Number of registers to write
 * @return        0 on success, negative error code on failure
 */
int qemu_write_regs(void* cpu, const int* regs, const uint64_t* values, size_t count);

// =============================================================================
// Memory Access Functions
// =============================================================================

/**
 * Read memory from guest address space
 *
 * @param cpu         CPU pointer (for TLB lookups)
 * @param guest_addr  Guest virtual address
 * @param buf         Output buffer
 * @param len         Number of bytes to read
 * @return            0 on success, negative error code on failure
 */
int qemu_mem_read(void* cpu, uint64_t guest_addr, void* buf, size_t len);

/**
 * Write memory to guest address space
 *
 * @param cpu         CPU pointer
 * @param guest_addr  Guest virtual address
 * @param buf         Input buffer
 * @param len         Number of bytes to write
 * @return            0 on success, negative error code on failure
 */
int qemu_mem_write(void* cpu, uint64_t guest_addr, const void* buf, size_t len);

/**
 * Translate guest address to host pointer
 *
 * This is a fast path for direct memory access when you know
 * the address is valid. Use with caution.
 *
 * @param guest_addr  Guest virtual address
 * @return            Host pointer or NULL if not mapped
 */
void* qemu_guest_to_host(uint64_t guest_addr);

/**
 * Translate host pointer to guest address
 *
 * @param host_ptr  Host pointer within mapped guest memory
 * @return          Guest address
 */
uint64_t qemu_host_to_guest(const void* host_ptr);

// =============================================================================
// Memory Mapping Functions
// =============================================================================

/**
 * Map a memory region in guest address space
 *
 * @param guest_addr  Guest address (should be page-aligned)
 * @param size        Size in bytes (should be page-aligned)
 * @param prot        Protection flags (QEMU_PROT_*)
 * @return            0 on success, negative error code on failure
 */
int qemu_mem_map(uint64_t guest_addr, size_t size, int prot);

/**
 * Map an existing host buffer into guest address space (zero-copy)
 *
 * This is useful for sharing buffers between host and guest without
 * copying data.
 *
 * @param guest_addr  Guest address
 * @param size        Size in bytes
 * @param prot        Protection flags
 * @param host_ptr    Existing host buffer to map
 * @return            0 on success, negative error code on failure
 */
int qemu_mem_map_ptr(uint64_t guest_addr, size_t size, int prot, void* host_ptr);

/**
 * Unmap a memory region
 *
 * @param guest_addr  Guest address
 * @param size        Size in bytes
 * @return            0 on success, negative error code on failure
 */
int qemu_mem_unmap(uint64_t guest_addr, size_t size);

// =============================================================================
// Hook Registration Functions
// =============================================================================

/**
 * Register syscall hooks
 *
 * @param pre_hook   Called before syscall, can modify args or skip syscall
 * @param post_hook  Called after syscall with return value
 * @return           0 on success, negative error code on failure
 */
int qemu_add_syscall_hook(QemuSyscallPreHook pre_hook, QemuSyscallPostHook post_hook);

/**
 * Register thread creation hook
 *
 * @param hook  Called when a new thread is created via clone()
 * @return      0 on success, negative error code on failure
 */
int qemu_add_thread_hook(QemuThreadHook hook);

/**
 * Register block execution hook
 *
 * @param hook  Called at the start of each translated block
 * @return      0 on success, negative error code on failure
 */
int qemu_add_block_hook(QemuBlockHook hook);

// =============================================================================
// Execution Control Functions
// =============================================================================

/**
 * Start/continue execution on the current CPU
 *
 * @return 0 on normal exit, negative error code on failure
 */
int qemu_run(void);

/**
 * Stop execution (can be called from hooks)
 */
void qemu_stop(void);

/**
 * Set a breakpoint at an address
 *
 * @param addr  Address to set breakpoint
 * @return      0 on success, negative error code on failure
 */
int qemu_set_breakpoint(uint64_t addr);

/**
 * Remove a breakpoint
 *
 * @param addr  Address of breakpoint to remove
 * @return      0 on success, negative error code on failure
 */
int qemu_remove_breakpoint(uint64_t addr);

// =============================================================================
// Utility Functions
// =============================================================================

/**
 * Get the version string of the QEMU bridge
 *
 * @return Version string (do not free)
 */
const char* qemu_bridge_version(void);

/**
 * Get the QEMU version string
 *
 * @return Version string (do not free)
 */
const char* qemu_version(void);

/**
 * Get error message for error code
 *
 * @param err  Error code
 * @return     Error message (do not free)
 */
const char* qemu_strerror(int err);

// =============================================================================
// C++ Convenience Wrapper (optional)
// =============================================================================

#ifdef __cplusplus
} // extern "C"

#include <string>
#include <vector>
#include <functional>

namespace qemu {

/**
 * C++ RAII wrapper for QEMU initialization
 */
class QemuInstance {
public:
    QemuInstance(const std::vector<std::string>& args = {}) {
        std::vector<const char*> argv;
        argv.push_back("qemu-aarch64");
        for (const auto& arg : args) {
            argv.push_back(arg.c_str());
        }
        argv.push_back(nullptr);

        int result = qemu_init(static_cast<int>(argv.size() - 1), argv.data());
        if (result != 0) {
            throw std::runtime_error(std::string("QEMU init failed: ") + qemu_strerror(result));
        }
    }

    ~QemuInstance() {
        qemu_deinit();
    }

    // Non-copyable, non-movable
    QemuInstance(const QemuInstance&) = delete;
    QemuInstance& operator=(const QemuInstance&) = delete;
    QemuInstance(QemuInstance&&) = delete;
    QemuInstance& operator=(QemuInstance&&) = delete;

    uint64_t guest_base() const { return qemu_get_guest_base(); }
    bool is_initialized() const { return qemu_is_initialized(); }
};

/**
 * C++ CPU handle with convenient register access
 */
class Cpu {
public:
    explicit Cpu(void* handle) : handle_(handle) {}

    static Cpu current() { return Cpu(qemu_current_cpu()); }
    static Cpu get(int index) { return Cpu(qemu_get_cpu(index)); }

    void* handle() const { return handle_; }
    bool valid() const { return handle_ != nullptr; }

    uint64_t read_reg(int reg) const {
        return qemu_read_reg(handle_, reg);
    }

    void write_reg(int reg, uint64_t value) {
        qemu_write_reg(handle_, reg, value);
    }

    // Convenience accessors
    uint64_t x(int n) const { return read_reg(QEMU_ARM64_REG_X0 + n); }
    void set_x(int n, uint64_t v) { write_reg(QEMU_ARM64_REG_X0 + n, v); }

    uint64_t pc() const { return read_reg(QEMU_ARM64_REG_PC); }
    void set_pc(uint64_t v) { write_reg(QEMU_ARM64_REG_PC, v); }

    uint64_t sp() const { return read_reg(QEMU_ARM64_REG_SP); }
    void set_sp(uint64_t v) { write_reg(QEMU_ARM64_REG_SP, v); }

    uint64_t lr() const { return read_reg(QEMU_ARM64_REG_LR); }
    void set_lr(uint64_t v) { write_reg(QEMU_ARM64_REG_LR, v); }

private:
    void* handle_;
};

/**
 * Memory access helpers
 */
class Memory {
public:
    static bool read(uint64_t addr, void* buf, size_t len) {
        return qemu_mem_read(nullptr, addr, buf, len) == 0;
    }

    static bool write(uint64_t addr, const void* buf, size_t len) {
        return qemu_mem_write(nullptr, addr, buf, len) == 0;
    }

    template<typename T>
    static T read(uint64_t addr) {
        T value;
        read(addr, &value, sizeof(T));
        return value;
    }

    template<typename T>
    static void write(uint64_t addr, const T& value) {
        write(addr, &value, sizeof(T));
    }

    static void* to_host(uint64_t guest_addr) {
        return qemu_guest_to_host(guest_addr);
    }

    static uint64_t to_guest(const void* host_ptr) {
        return qemu_host_to_guest(host_ptr);
    }
};

} // namespace qemu

#endif // __cplusplus

#endif // QEMU_WRAPPER_H
