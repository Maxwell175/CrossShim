/**
 * qemu-libafl-bridge C API Header
 *
 * This header declares the actual C functions exposed by qemu-libafl-bridge
 * for direct integration with CrossShim. Uses QEMU with MTTCG
 * (multi-threaded TCG) for real parallel thread execution.
 *
 * Source: https://github.com/AFLplusplus/qemu-libafl-bridge
 *
 * Build Requirements:
 * 1. Clone qemu-libafl-bridge
 * 2. Configure with: ./configure --target-list=aarch64-linux-user --enable-libafl
 * 3. Build: make -j$(nproc)
 * 4. Link against the resulting library
 */

#ifndef QEMU_LIBAFL_BRIDGE_H
#define QEMU_LIBAFL_BRIDGE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// =============================================================================
// QEMU Types (forward declarations)
// =============================================================================

// Opaque CPU state pointer
typedef struct CPUState CPUState;

// Target-specific types (architecture-dependent sizes)
typedef uint64_t target_ulong;  // 64-bit for AArch64
typedef uint64_t hwaddr;        // Hardware/physical address
typedef uint64_t vaddr;         // Virtual address

// =============================================================================
// CPU Access Functions
// =============================================================================

/**
 * Get a CPU instance by index
 * @param cpu_index CPU index (0-based)
 * @return CPU state pointer or NULL
 */
CPUState* libafl_qemu_get_cpu(int cpu_index);

/**
 * Get the currently active CPU
 * @return Current CPU state pointer
 */
CPUState* libafl_qemu_current_cpu(void);

/**
 * Get the index of a CPU
 * @param cpu CPU state pointer
 * @return CPU index
 */
int libafl_qemu_cpu_index(CPUState* cpu);

/**
 * Get total CPU count
 * @return Number of CPUs
 */
int libafl_qemu_num_cpus(void);

/**
 * Get the CPU that triggered the last exit
 * @return CPU state pointer
 */
CPUState* libafl_last_exit_cpu(void);

// =============================================================================
// Register Access Functions
// =============================================================================

/**
 * Read a register value
 * @param cpu CPU state pointer
 * @param reg Register index
 * @param val Output buffer (size depends on register)
 * @return 0 on success, negative on error
 */
int libafl_qemu_read_reg(CPUState* cpu, int reg, uint8_t* val);

/**
 * Write a register value
 * @param cpu CPU state pointer
 * @param reg Register index
 * @param val Input buffer (size depends on register)
 * @return 0 on success, negative on error
 */
int libafl_qemu_write_reg(CPUState* cpu, int reg, uint8_t* val);

/**
 * Get number of registers for a CPU
 * @param cpu CPU state pointer
 * @return Number of registers
 */
int libafl_qemu_num_regs(CPUState* cpu);

// =============================================================================
// ARM64 Register Indices
// =============================================================================

/**
 * ARM64 register indices for use with libafl_qemu_read_reg/write_reg
 * These match QEMU's internal gdbstub register numbering for AArch64
 */
typedef enum {
    // General purpose registers (X0-X30)
    LIBAFL_ARM64_REG_X0 = 0,
    LIBAFL_ARM64_REG_X1 = 1,
    LIBAFL_ARM64_REG_X2 = 2,
    LIBAFL_ARM64_REG_X3 = 3,
    LIBAFL_ARM64_REG_X4 = 4,
    LIBAFL_ARM64_REG_X5 = 5,
    LIBAFL_ARM64_REG_X6 = 6,
    LIBAFL_ARM64_REG_X7 = 7,
    LIBAFL_ARM64_REG_X8 = 8,
    LIBAFL_ARM64_REG_X9 = 9,
    LIBAFL_ARM64_REG_X10 = 10,
    LIBAFL_ARM64_REG_X11 = 11,
    LIBAFL_ARM64_REG_X12 = 12,
    LIBAFL_ARM64_REG_X13 = 13,
    LIBAFL_ARM64_REG_X14 = 14,
    LIBAFL_ARM64_REG_X15 = 15,
    LIBAFL_ARM64_REG_X16 = 16,
    LIBAFL_ARM64_REG_X17 = 17,
    LIBAFL_ARM64_REG_X18 = 18,
    LIBAFL_ARM64_REG_X19 = 19,
    LIBAFL_ARM64_REG_X20 = 20,
    LIBAFL_ARM64_REG_X21 = 21,
    LIBAFL_ARM64_REG_X22 = 22,
    LIBAFL_ARM64_REG_X23 = 23,
    LIBAFL_ARM64_REG_X24 = 24,
    LIBAFL_ARM64_REG_X25 = 25,
    LIBAFL_ARM64_REG_X26 = 26,
    LIBAFL_ARM64_REG_X27 = 27,
    LIBAFL_ARM64_REG_X28 = 28,
    LIBAFL_ARM64_REG_X29 = 29,  // Frame pointer (FP)
    LIBAFL_ARM64_REG_X30 = 30,  // Link register (LR)
    LIBAFL_ARM64_REG_SP = 31,   // Stack pointer
    LIBAFL_ARM64_REG_PC = 32,   // Program counter

    // Condition flags (PSTATE)
    LIBAFL_ARM64_REG_CPSR = 33,

    // SIMD/FP registers (V0-V31, 128-bit each)
    // These are typically at index 34+ in gdbstub numbering
    LIBAFL_ARM64_REG_V0 = 34,
    // ... V1-V31 follow sequentially

    // Aliases
    LIBAFL_ARM64_REG_LR = LIBAFL_ARM64_REG_X30,
    LIBAFL_ARM64_REG_FP = LIBAFL_ARM64_REG_X29,
} LibaflArm64Reg;

// =============================================================================
// Memory Access Functions
// =============================================================================

/**
 * Map physical address to host pointer
 * @param cpu CPU state pointer
 * @param addr Physical address
 * @param is_write Whether this is for writing
 * @return Host pointer or NULL if unmapped
 */
uint8_t* libafl_paddr2host(CPUState* cpu, hwaddr addr, bool is_write);

/**
 * Get page from address
 * @param addr Virtual address
 * @return Page address
 */
target_ulong libafl_page_from_addr(target_ulong addr);

/**
 * Get current paging ID (for TLB context)
 * @param cpu CPU state pointer
 * @return Paging context ID
 */
hwaddr libafl_qemu_current_paging_id(CPUState* cpu);

/**
 * Standard QEMU memory read/write via CPU MMU
 * This is the primary function for guest memory access in usermode
 *
 * @param cpu CPU state pointer
 * @param addr Guest virtual address
 * @param buf Host buffer
 * @param len Number of bytes
 * @param is_write 0 for read, 1 for write
 * @return 0 on success, negative on error
 */
int cpu_memory_rw_debug(CPUState* cpu, target_ulong addr,
                        void* buf, size_t len, int is_write);

// =============================================================================
// Breakpoint Functions
// =============================================================================

/**
 * Set a breakpoint at address
 * @param pc Program counter address
 * @return 0 on success
 */
int libafl_qemu_set_breakpoint(target_ulong pc);

/**
 * Remove a breakpoint
 * @param pc Program counter address
 * @return 0 on success
 */
int libafl_qemu_remove_breakpoint(target_ulong pc);

/**
 * Trigger breakpoint handling
 * @param cpu CPU state pointer
 */
void libafl_qemu_trigger_breakpoint(CPUState* cpu);

/**
 * Continue execution from breakpoint
 * @param pc_next Next PC to execute
 */
void libafl_qemu_breakpoint_run(vaddr pc_next);

/**
 * Invalidate breakpoint in translation cache
 * @param cpu CPU state pointer
 * @param pc Address to invalidate
 */
void libafl_breakpoint_invalidate(CPUState* cpu, target_ulong pc);

// =============================================================================
// JIT Control
// =============================================================================

/**
 * Flush JIT translation cache
 * Call after modifying code or breakpoints
 */
void libafl_flush_jit(void);

// =============================================================================
// Exit Handling
// =============================================================================

/**
 * Exit reason structure
 */
struct libafl_exit_reason;

/**
 * Check if immediate exit is requested
 * @return true if should exit ASAP
 */
bool libafl_exit_asap(void);

/**
 * Synchronize CPU exit state
 */
void libafl_sync_exit_cpu(void);

/**
 * Get exit reason details
 * @return Pointer to exit reason structure
 */
struct libafl_exit_reason* libafl_get_exit_reason(void);

/**
 * Signal VM startup
 */
void libafl_exit_signal_vm_start(void);

/**
 * Request crash exit
 * @param cpu CPU state pointer
 */
void libafl_exit_request_crash(CPUState* cpu);

/**
 * Request timeout exit
 */
void libafl_exit_request_timeout(void);

// =============================================================================
// Usermode Emulation Functions
// =============================================================================

/**
 * Memory map information structure
 */
struct libafl_mapinfo {
    target_ulong start;
    target_ulong end;
    target_ulong offset;
    const char* path;
    int flags;
};

/**
 * Get first memory map entry
 * @return First map node (for iteration)
 */
void* libafl_maps_first(void);

/**
 * Get next memory map entry
 * @param node Current node
 * @param info Output map info
 * @return Next node or NULL
 */
void* libafl_maps_next(void* node, struct libafl_mapinfo* info);

/**
 * Get executable load address
 * @return Load address of main binary
 */
target_ulong libafl_load_addr(void);

/**
 * Get image info structure
 * @return Pointer to image info
 */
void* libafl_get_image_info(void);

/**
 * Get current break (heap end)
 * @return Current brk address
 */
target_ulong libafl_get_brk(void);

/**
 * Set break (heap end)
 * @param brk New brk address
 */
void libafl_set_brk(target_ulong brk);

/**
 * Get initial break value
 * @return Initial brk address
 */
target_ulong libafl_get_initial_brk(void);

/**
 * Initialize usermode emulation (internal)
 * @param argc Argument count
 * @param argv Argument vector
 * @param envp Environment vector
 */
void _libafl_qemu_user_init(int argc, char** argv, char** envp);

// =============================================================================
// Hook Registration (from libafl_qemu, not qemu-libafl-bridge directly)
// =============================================================================

/**
 * Hook callback types
 * These are typically registered through libafl_qemu's Rust API,
 * but can be accessed through the sys bindings
 */

// Pre-syscall hook: called before syscall execution
// Returns: true to skip the syscall, false to execute normally
typedef bool (*libafl_syscall_hook_t)(CPUState* cpu, int syscall_num,
                                       uint64_t arg1, uint64_t arg2,
                                       uint64_t arg3, uint64_t arg4,
                                       uint64_t arg5, uint64_t arg6,
                                       uint64_t arg7, uint64_t arg8);

// Block execution hook
typedef void (*libafl_block_hook_t)(CPUState* cpu, target_ulong pc);

// Edge hook (block transition)
typedef void (*libafl_edge_hook_t)(CPUState* cpu, target_ulong src, target_ulong dst);

// Instruction hook
typedef void (*libafl_insn_hook_t)(CPUState* cpu, target_ulong pc);

/**
 * Add a syscall hook (pre-execution)
 * @param hook Callback function
 * @return Hook ID or negative on error
 *
 * Note: Exact API depends on qemu-libafl-bridge version
 */
// size_t libafl_add_pre_syscall_hook(libafl_syscall_hook_t hook);

/**
 * Add a block execution hook
 * @param hook Callback function
 * @param start Start address (0 for all)
 * @param end End address (0 for all)
 * @return Hook ID or negative on error
 */
// size_t libafl_add_block_hook(libafl_block_hook_t hook, target_ulong start, target_ulong end);

// =============================================================================
// Signal Handling (Usermode)
// =============================================================================

/**
 * Native signal handler for usermode
 */
void libafl_qemu_native_signal_handler(int sig, void* info, void* puc);

/**
 * Get signal context
 * @return Signal context pointer
 */
void* libafl_qemu_signal_context(void);

/**
 * Set in-target signal context flag
 */
void libafl_set_in_target_signal_ctx(void);

/**
 * Set in-host signal context flag
 */
void libafl_set_in_host_signal_ctx(void);

/**
 * Handle crash in usermode
 */
void libafl_qemu_handle_crash(void);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // QEMU_LIBAFL_BRIDGE_H
