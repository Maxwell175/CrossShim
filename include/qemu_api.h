/**
 * QEMU API Wrapper
 *
 * This header provides a clean C++ interface to the LibAFL QEMU APIs.
 * It wraps the C APIs from qemu-libafl-bridge for use in CrossShim.
 */

#ifndef QEMU_API_H
#define QEMU_API_H

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <mutex>

#include <glib.h>

// Forward declarations from QEMU
struct CPUState;
struct CPUArchState;

extern "C" {

typedef struct {
    int gdb_reg;
    const char* name;
    const char* feature_name;
} GDBRegDesc;

GArray* gdb_get_register_list(CPUState* cpu);

// =============================================================================
// QEMU Initialization
// =============================================================================

/**
 * Initialize QEMU with command-line arguments
 * This is the main entry point for the library mode.
 * @param argc Argument count
 * @param argv Argument vector
 */
void libafl_qemu_init(int argc, char** argv);

/**
 * Initialize QEMU usermode (internal)
 * @param argc Argument count
 * @param argv Argument vector
 * @param envp Environment vector
 * @return 0 on success
 */
int _libafl_qemu_user_init(int argc, char** argv, char** envp);

/**
 * Run QEMU emulation
 * @return Exit code
 */
int libafl_qemu_run(void);

/**
 * Main entry point (weak symbol, can be overridden)
 */
int libafl_qemu_main(void);

// =============================================================================
// CPU Access
// =============================================================================

/**
 * Get CPU by index
 * @param cpu_index CPU index (0-based)
 * @return CPU state pointer or NULL
 */
CPUState* libafl_qemu_get_cpu(int cpu_index);

/**
 * Get current CPU
 * @return Current CPU state pointer
 */
CPUState* libafl_qemu_current_cpu(void);

/**
 * Set current CPU for this thread
 * In MTTCG mode, this must be called before libafl_qemu_run()
 * if running from a non-QEMU-managed thread
 * @param cpu CPU state pointer
 */
void libafl_qemu_set_current_cpu(CPUState* cpu);

/**
 * Register this thread with TCG runtime
 * Must be called by any non-main thread before running TCG code
 */
void tcg_register_thread(void);

/**
 * Get CPU index
 * @param cpu CPU state pointer
 * @return CPU index
 */
int libafl_qemu_cpu_index(CPUState* cpu);

/**
 * Get number of CPUs
 * @return CPU count
 */
int libafl_qemu_num_cpus(void);

/**
 * Get number of registers for a CPU
 * @param cpu CPU state pointer
 * @return Register count
 */
int libafl_qemu_num_regs(CPUState* cpu);

// =============================================================================
// Register Access
// =============================================================================

/**
 * Read a register value
 * @param cpu CPU state pointer
 * @param reg Register index
 * @param val Output buffer (8 bytes for 64-bit registers)
 * @return 0 on success, negative on error
 */
int libafl_qemu_read_reg(CPUState* cpu, int reg, uint8_t* val);

/**
 * Write a register value
 * @param cpu CPU state pointer
 * @param reg Register index
 * @param val Input buffer (8 bytes for 64-bit registers)
 * @return 0 on success, negative on error
 */
int libafl_qemu_write_reg(CPUState* cpu, int reg, uint8_t* val);

// =============================================================================
// Memory Access
// =============================================================================

/**
 * Read/write guest memory via CPU debug interface
 * @param cpu CPU state pointer
 * @param addr Guest virtual address
 * @param buf Host buffer
 * @param len Number of bytes
 * @param is_write 0 for read, 1 for write
 * @return 0 on success, negative on error
 */
int cpu_memory_rw_debug(CPUState* cpu, uint64_t addr, void* buf, size_t len, int is_write);

/**
 * Map memory in guest address space
 * @param addr Guest address (0 to let QEMU choose)
 * @param len Size in bytes
 * @param prot Protection flags (PROT_READ | PROT_WRITE | PROT_EXEC)
 * @param flags Mapping flags (MAP_ANONYMOUS | MAP_PRIVATE, etc.)
 * @param fd File descriptor (-1 for anonymous)
 * @param offset File offset
 * @return Mapped address or -1 on error
 */
uint64_t target_mmap(uint64_t addr, uint64_t len, int prot, int flags, int fd, uint64_t offset);

/**
 * Unmap guest memory
 * @param addr Guest address
 * @param len Size in bytes
 * @return 0 on success
 */
int target_munmap(uint64_t addr, uint64_t len);

// =============================================================================
// Syscall Hooks
// =============================================================================

/**
 * Syscall hook result
 */
enum libafl_syshook_ret_tag {
    LIBAFL_SYSHOOK_RUN,   // Execute syscall normally
    LIBAFL_SYSHOOK_SKIP,  // Skip syscall, use provided return value
};

struct libafl_syshook_ret {
    enum libafl_syshook_ret_tag tag;
    union {
        uint64_t syshook_skip_retval;
    };
};

/**
 * Pre-syscall hook callback type
 */
typedef struct libafl_syshook_ret (*libafl_pre_syscall_cb)(
    uint64_t data, int sys_num,
    uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3,
    uint64_t arg4, uint64_t arg5, uint64_t arg6, uint64_t arg7);

/**
 * Post-syscall hook callback type
 */
typedef uint64_t (*libafl_post_syscall_cb)(
    uint64_t data, uint64_t ret, int sys_num,
    uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3,
    uint64_t arg4, uint64_t arg5, uint64_t arg6, uint64_t arg7);

/**
 * Add pre-syscall hook
 * @param callback Hook function
 * @param data User data passed to callback
 * @return Hook ID
 */
size_t libafl_add_pre_syscall_hook(libafl_pre_syscall_cb callback, uint64_t data);

/**
 * Add post-syscall hook
 * @param callback Hook function
 * @param data User data passed to callback
 * @return Hook ID
 */
size_t libafl_add_post_syscall_hook(libafl_post_syscall_cb callback, uint64_t data);

/**
 * Remove pre-syscall hook
 * @param num Hook ID
 * @return 1 if removed, 0 if not found
 */
int libafl_qemu_remove_pre_syscall_hook(size_t num);

/**
 * Remove post-syscall hook
 * @param num Hook ID
 * @return 1 if removed, 0 if not found
 */
int libafl_qemu_remove_post_syscall_hook(size_t num);

// =============================================================================
// Thread Hooks
// =============================================================================

/**
 * New thread hook callback type
 * @param data User data
 * @param env CPU architecture state
 * @param tid Thread ID
 * @return true to allow thread, false to deny
 */
typedef bool (*libafl_new_thread_cb)(uint64_t data, CPUArchState* env, uint32_t tid);

/**
 * Add new thread hook
 * @param callback Hook function
 * @param data User data passed to callback
 * @return Hook ID
 */
size_t libafl_add_new_thread_hook(libafl_new_thread_cb callback, uint64_t data);

/**
 * Remove new thread hook
 * @param num Hook ID
 * @return 1 if removed, 0 if not found
 */
int libafl_qemu_remove_new_thread_hook(size_t num);

// =============================================================================
// Block Hooks (for tracing/debugging)
// =============================================================================

typedef uint64_t (*libafl_block_pre_gen_cb)(uint64_t data, uint64_t pc);
typedef void (*libafl_block_post_gen_cb)(uint64_t data, uint64_t pc, uint64_t block_length);
typedef void (*libafl_block_exec_cb)(uint64_t data, uint64_t id);

/**
 * Add block execution hook
 * @param pre_gen_cb Called before block generation
 * @param post_gen_cb Called after block generation
 * @param exec_cb Called on block execution
 * @param data User data
 * @return Hook ID
 */
size_t libafl_add_block_hook(libafl_block_pre_gen_cb pre_gen_cb,
                              libafl_block_post_gen_cb post_gen_cb,
                              libafl_block_exec_cb exec_cb,
                              uint64_t data);

/**
 * Remove block hook
 * @param num Hook ID
 * @param invalidate Whether to flush JIT
 * @return 1 if removed, 0 if not found
 */
int libafl_qemu_remove_block_hook(size_t num, int invalidate);

// =============================================================================
// JIT/Translation Cache
// =============================================================================

/**
 * Flush JIT translation cache
 */
void libafl_flush_jit(void);

// =============================================================================
// Instruction Hooks (for single-stepping/debugging)
// =============================================================================

/**
 * Callback type for instruction hooks
 */
typedef void (*libafl_instruction_cb)(uint64_t data, uint64_t pc);

/**
 * Add instruction hook at a specific address
 * @param pc Address to hook
 * @param callback Function to call when address is executed
 * @param data User data passed to callback
 * @param invalidate Whether to invalidate JIT cache
 * @return Hook ID
 */
size_t libafl_qemu_add_instruction_hooks(uint64_t pc,
                                         libafl_instruction_cb callback,
                                         uint64_t data, int invalidate);

/**
 * Remove instruction hook
 * @param num Hook ID
 * @param invalidate Whether to invalidate JIT cache
 * @return 1 if removed, 0 if not found
 */
int libafl_qemu_remove_instruction_hook(size_t num, int invalidate);

/**
 * Remove all instruction hooks at an address
 * @param addr Address
 * @param invalidate Whether to invalidate JIT cache
 * @return Number of hooks removed
 */
size_t libafl_qemu_remove_instruction_hooks_at(uint64_t addr, int invalidate);

// =============================================================================
// Usermode Helpers
// =============================================================================

/**
 * Get load address of main binary
 * @return Load address
 */
uint64_t libafl_load_addr(void);

/**
 * Get current break (heap end)
 * @return Current brk address
 */
uint64_t libafl_get_brk(void);

/**
 * Set break (heap end)
 * @param new_brk New brk address
 * @return Old brk address
 */
uint64_t libafl_set_brk(uint64_t new_brk);

/**
 * Get initial break value
 * @return Initial brk address
 */
uint64_t libafl_get_initial_brk(void);

/**
 * Set QEMU environment for current CPU
 * @param env CPU architecture state
 */
void libafl_set_qemu_env(CPUArchState* env);

/**
 * Resolve the CPUState that owns a given CPUArchState (CrossShim vCPU pool).
 */
CPUState* libafl_qemu_cpu_from_env(CPUArchState* env);

// =============================================================================
// Breakpoints
// =============================================================================

/**
 * Set a breakpoint at an address
 * @param addr Guest address
 * @return Breakpoint ID on success, or error value
 */
size_t libafl_qemu_set_breakpoint(uint64_t addr);

/**
 * Remove a breakpoint
 * @param addr Guest address
 * @return 1 if removed, 0 if not found
 */
int libafl_qemu_remove_breakpoint(uint64_t addr);

/**
 * Trigger a breakpoint-style exit from cpu_loop for the given CPU.
 * Uses only per-thread (__thread) exit state - no global breakpoint list and no
 * cross-CPU TB flush - so it is safe to call concurrently from multiple vCPU
 * worker threads (e.g. from the syscall hook to stop a C->guest call).
 * @param cpu CPU state that should exit its run loop
 */
void libafl_qemu_trigger_breakpoint(CPUState* cpu);

// =============================================================================
// Exit/Crash Handling
// =============================================================================

/**
 * Check if QEMU should exit ASAP
 * @return true if should exit
 */
bool libafl_exit_asap(void);

/**
 * Request crash exit
 * @param cpu CPU state
 */
void libafl_exit_request_crash(CPUState* cpu);

/**
 * Set return on crash behavior
 * @param return_on_crash true to return instead of crashing
 */
void libafl_set_return_on_crash(bool return_on_crash);

/**
 * Get return on crash setting
 * @return Current setting
 */
bool libafl_get_return_on_crash(void);

// =============================================================================
// Exit Reason (for debugging why QEMU stopped)
// =============================================================================

/**
 * Exit reason kinds - matches libafl/exit.h
 */
enum libafl_exit_reason_kind {
    LIBAFL_EXIT_INTERNAL = 0,
    LIBAFL_EXIT_BREAKPOINT = 1,
    LIBAFL_EXIT_CUSTOM_INSN = 2,
    LIBAFL_EXIT_CRASH = 3,
    LIBAFL_EXIT_TIMEOUT = 4,
};

/**
 * Exit reason structure - simplified version for our use
 * The real structure in libafl/exit.h has more fields, but we only need kind
 */
struct libafl_exit_reason {
    enum libafl_exit_reason_kind kind;
    CPUState* cpu;
    uint64_t next_pc;
    // Union fields omitted - we only need kind for debugging
};

/**
 * Get the last exit reason
 * @return Pointer to exit reason structure
 */
struct libafl_exit_reason* libafl_get_exit_reason(void);

} // extern "C"

// =============================================================================
// ARM64 Register Indices (for libafl_qemu_read_reg/write_reg)
// =============================================================================

namespace qemu {

constexpr size_t MAX_REGISTER_BYTES = 256;

// =============================================================================
// ARM64 GDB Register Numbering
// =============================================================================
// Core registers are stable at 0-33. Supplemental feature blocks are appended
// dynamically by QEMU at runtime, so non-core register ids are not universally
// stable across all CPU feature sets. We keep the common FPU numbering here and
// resolve TLS registers dynamically from QEMU's live register list.

enum Arm64Reg {
    // General purpose registers (X0-X30)
    REG_X0 = 0, REG_X1, REG_X2, REG_X3, REG_X4, REG_X5, REG_X6, REG_X7,
    REG_X8, REG_X9, REG_X10, REG_X11, REG_X12, REG_X13, REG_X14, REG_X15,
    REG_X16, REG_X17, REG_X18, REG_X19, REG_X20, REG_X21, REG_X22, REG_X23,
    REG_X24, REG_X25, REG_X26, REG_X27, REG_X28, REG_X29, REG_X30,
    REG_SP = 31,   // Stack pointer
    REG_PC = 32,   // Program counter
    REG_CPSR = 33, // Condition flags (PSTATE/NZCV)

    // SIMD/FP registers (V0-V31 are 128-bit each)
    // FPU coprocessor starts at index 34 after core registers
    REG_V0 = 34,
    REG_V1 = 35,
    REG_V2 = 36,
    REG_V3 = 37,
    REG_V4 = 38,
    REG_V5 = 39,
    REG_V6 = 40,
    REG_V7 = 41,
    REG_V8 = 42,
    REG_V9 = 43,
    REG_V10 = 44,
    REG_V11 = 45,
    REG_V12 = 46,
    REG_V13 = 47,
    REG_V14 = 48,
    REG_V15 = 49,
    REG_V16 = 50,
    REG_V17 = 51,
    REG_V18 = 52,
    REG_V19 = 53,
    REG_V20 = 54,
    REG_V21 = 55,
    REG_V22 = 56,
    REG_V23 = 57,
    REG_V24 = 58,
    REG_V25 = 59,
    REG_V26 = 60,
    REG_V27 = 61,
    REG_V28 = 62,
    REG_V29 = 63,
    REG_V30 = 64,
    REG_V31 = 65,

    // Floating-point control/status registers
    REG_FPSR = 66,
    REG_FPCR = 67,

    // TLS coprocessor (starts after FPU)
    REG_TPIDR_EL0 = 68,
    REG_TPIDR2_EL0 = 69,

    // Aliases
    REG_FP = REG_X29,  // Frame pointer
    REG_LR = REG_X30,  // Link register
};

namespace detail {

struct DynamicRegInfo {
    int gdb_reg = -1;
    size_t size = 0;
};

struct DynamicRegCache {
    bool initialized = false;
    DynamicRegInfo tpidr_el0{};
    DynamicRegInfo tpidr2_el0{};
    DynamicRegInfo fpsr{};
    DynamicRegInfo fpcr{};
    std::array<DynamicRegInfo, 32> vectors{};
};

inline DynamicRegCache& dynamic_reg_cache() {
    static DynamicRegCache cache{};
    return cache;
}

inline std::mutex& dynamic_reg_cache_mutex() {
    static std::mutex mutex;
    return mutex;
}

inline bool is_vector_reg(int reg) {
    return reg >= REG_V0 && reg <= REG_V31;
}

inline size_t fallback_reg_size(int reg) {
    if (is_vector_reg(reg)) {
        return 16;
    }
    if (reg == REG_FPSR || reg == REG_FPCR) {
        return 4;
    }
    return 8;
}

inline size_t probe_reg_size(CPUState* cpu, int gdb_reg, int fallback_reg) {
    if (!cpu || gdb_reg < 0) {
        return fallback_reg_size(fallback_reg);
    }

    std::array<uint8_t, MAX_REGISTER_BYTES> buf{};
    int len = libafl_qemu_read_reg(cpu, gdb_reg, buf.data());
    if (len <= 0) {
        return fallback_reg_size(fallback_reg);
    }
    return std::min(buf.size(), static_cast<size_t>(len));
}

inline bool parse_vector_reg_name(const char* name, int* index_out) {
    if (!name || !index_out) {
        return false;
    }

    char prefix = '\0';
    int index = -1;
    char trailing = '\0';
    int matched = std::sscanf(name, "%c%d%c", &prefix, &index, &trailing);
    if (matched != 2) {
        return false;
    }
    if (prefix != 'v' && prefix != 'z') {
        return false;
    }
    if (index < 0 || index >= 32) {
        return false;
    }

    *index_out = index;
    return true;
}

inline void initialize_dynamic_reg_cache(CPUState* cpu) {
    DynamicRegCache& cache = dynamic_reg_cache();
    if (cache.initialized || !cpu) {
        return;
    }

    std::lock_guard<std::mutex> lock(dynamic_reg_cache_mutex());
    if (cache.initialized) {
        return;
    }

    GArray* regs = gdb_get_register_list(cpu);
    if (!regs) {
        cache.initialized = true;
        return;
    }

    for (guint i = 0; i < regs->len; ++i) {
        GDBRegDesc desc = g_array_index(regs, GDBRegDesc, i);
        if (desc.name == nullptr) {
            continue;
        }

        int vector_index = -1;
        if (parse_vector_reg_name(desc.name, &vector_index)) {
            cache.vectors[vector_index].gdb_reg = desc.gdb_reg;
            cache.vectors[vector_index].size =
                probe_reg_size(cpu, desc.gdb_reg, REG_V0 + vector_index);
            continue;
        }

        if (std::strcmp(desc.name, "fpsr") == 0) {
            cache.fpsr.gdb_reg = desc.gdb_reg;
            cache.fpsr.size = probe_reg_size(cpu, desc.gdb_reg, REG_FPSR);
            continue;
        }

        if (std::strcmp(desc.name, "fpcr") == 0) {
            cache.fpcr.gdb_reg = desc.gdb_reg;
            cache.fpcr.size = probe_reg_size(cpu, desc.gdb_reg, REG_FPCR);
            continue;
        }

        if (std::strcmp(desc.name, "tpidr") == 0) {
            cache.tpidr_el0.gdb_reg = desc.gdb_reg;
            cache.tpidr_el0.size = probe_reg_size(cpu, desc.gdb_reg, REG_TPIDR_EL0);
            continue;
        }

        if (std::strcmp(desc.name, "tpidr2") == 0) {
            cache.tpidr2_el0.gdb_reg = desc.gdb_reg;
            cache.tpidr2_el0.size = probe_reg_size(cpu, desc.gdb_reg, REG_TPIDR2_EL0);
            continue;
        }
    }

    g_array_free(regs, TRUE);
    cache.initialized = true;
}

inline const DynamicRegInfo* get_dynamic_reg_info(CPUState* cpu, int reg) {
    initialize_dynamic_reg_cache(cpu);

    DynamicRegCache& cache = dynamic_reg_cache();
    if (reg == REG_TPIDR_EL0) {
        return &cache.tpidr_el0;
    }
    if (reg == REG_TPIDR2_EL0) {
        return &cache.tpidr2_el0;
    }
    if (reg == REG_FPSR) {
        return &cache.fpsr;
    }
    if (reg == REG_FPCR) {
        return &cache.fpcr;
    }
    if (is_vector_reg(reg)) {
        return &cache.vectors[reg - REG_V0];
    }
    return nullptr;
}

inline int resolve_reg(CPUState* cpu, int reg) {
    const DynamicRegInfo* info = get_dynamic_reg_info(cpu, reg);
    if (info && info->gdb_reg >= 0) {
        return info->gdb_reg;
    }
    return reg;
}

inline size_t reg_size(CPUState* cpu, int reg) {
    const DynamicRegInfo* info = get_dynamic_reg_info(cpu, reg);
    if (info && info->size > 0) {
        return std::min(info->size, MAX_REGISTER_BYTES);
    }
    return fallback_reg_size(reg);
}

} // namespace detail

// Helper functions for register access
inline int read_reg_bytes(CPUState* cpu, int reg, void* dst, size_t dst_size) {
    if (!cpu) {
        if (dst && dst_size > 0) {
            std::memset(dst, 0, dst_size);
        }
        return 0;
    }

    if (dst && dst_size > 0) {
        std::memset(dst, 0, dst_size);
    }

    std::array<uint8_t, MAX_REGISTER_BYTES> buf{};
    int resolved_reg = detail::resolve_reg(cpu, reg);
    int len = libafl_qemu_read_reg(cpu, resolved_reg, buf.data());
    if (len > 0 && dst && dst_size > 0) {
        std::memcpy(dst, buf.data(), std::min(dst_size, static_cast<size_t>(len)));
    }
    return len;
}

inline int write_reg_bytes(CPUState* cpu, int reg, const void* src, size_t src_size) {
    if (!cpu) {
        return 0;
    }

    std::array<uint8_t, MAX_REGISTER_BYTES> buf{};
    size_t copy_size = std::min({src_size, detail::reg_size(cpu, reg), buf.size()});
    if (src && copy_size > 0) {
        std::memcpy(buf.data(), src, copy_size);
    }

    int resolved_reg = detail::resolve_reg(cpu, reg);
    return libafl_qemu_write_reg(cpu, resolved_reg, buf.data());
}

inline uint64_t read_reg(CPUState* cpu, int reg) {
    uint64_t val = 0;
    read_reg_bytes(cpu, reg, &val, sizeof(val));
    return val;
}

inline void write_reg(CPUState* cpu, int reg, uint64_t val) {
    write_reg_bytes(cpu, reg, &val, sizeof(val));
}

// Memory access helpers
inline bool mem_read(CPUState* cpu, uint64_t addr, void* buf, size_t len) {
    return cpu_memory_rw_debug(cpu, addr, buf, len, 0) == 0;
}

inline bool mem_write(CPUState* cpu, uint64_t addr, const void* buf, size_t len) {
    return cpu_memory_rw_debug(cpu, addr, const_cast<void*>(buf), len, 1) == 0;
}

} // namespace qemu

#endif // QEMU_API_H
