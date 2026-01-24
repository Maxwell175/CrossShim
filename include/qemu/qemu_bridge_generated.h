#include <cstdarg>
#include <cstdint>
#include <cstdlib>
#include <ostream>
#include <new>

template<typename T = void>
struct Option;

/// Syscall hook callback type
/// Called before syscall execution
using SyscallPreHook = void(*)(void *cpu, int syscall_num, uint64_t *args);

/// Syscall post-hook callback type
/// Called after syscall execution with the return value
using SyscallPostHook = void(*)(void *cpu, int syscall_num, uint64_t ret);

/// Thread creation hook callback type
using ThreadHook = void(*)(void *cpu, uint64_t tid);

/// Block execution hook callback type
using BlockHook = void(*)(void *cpu, uint64_t pc, uint32_t size);

extern "C" {

/// Initialize LibAFL QEMU for ARM64 usermode emulation
///
/// # Arguments
/// * `argc` - Argument count (like main)
/// * `argv` - Argument vector (like main)
///
/// # Returns
/// * 0 on success, negative error code on failure
///
/// # Safety
/// This function must be called before any other QEMU functions.
/// The argv array must be valid C strings.
int qemu_init(int argc, const char *const *argv);

/// Deinitialize LibAFL QEMU and free resources
void qemu_deinit();

/// Check if QEMU is initialized
bool qemu_is_initialized();

/// Get the guest base address for memory translation
///
/// In QEMU usermode, guest addresses are offset by guest_base:
/// host_addr = guest_addr + guest_base
uint64_t qemu_get_guest_base();

/// Get the current CPU (for the calling thread)
///
/// In MTTCG mode, each host thread has its own vCPU.
/// Returns NULL if not in an emulation context.
void *qemu_current_cpu();

/// Get CPU by index
///
/// # Arguments
/// * `index` - CPU index (0-based)
///
/// # Returns
/// CPU pointer or NULL if index is out of range
void *qemu_get_cpu(int index);

/// Get the number of CPUs
int qemu_num_cpus();

/// Read a register value from a CPU
///
/// # Arguments
/// * `cpu` - CPU pointer from qemu_current_cpu() or qemu_get_cpu()
/// * `reg` - Register index (Arm64Reg enum value)
///
/// # Returns
/// Register value (64-bit)
uint64_t qemu_read_reg(void *cpu, int reg);

/// Write a register value to a CPU
///
/// # Arguments
/// * `cpu` - CPU pointer
/// * `reg` - Register index (Arm64Reg enum value)
/// * `value` - Value to write
void qemu_write_reg(void *cpu, int reg, uint64_t value);

/// Read multiple registers at once (more efficient for context saves)
///
/// # Arguments
/// * `cpu` - CPU pointer
/// * `regs` - Array of register indices
/// * `values` - Output array for register values
/// * `count` - Number of registers to read
///
/// # Returns
/// 0 on success, negative error code on failure
int qemu_read_regs(void *cpu, const int *regs, uint64_t *values, size_t count);

/// Write multiple registers at once
int qemu_write_regs(void *cpu, const int *regs, const uint64_t *values, size_t count);

/// Read memory from guest address space
///
/// # Arguments
/// * `cpu` - CPU pointer (for TLB lookups in system mode)
/// * `guest_addr` - Guest virtual address
/// * `buf` - Output buffer
/// * `len` - Number of bytes to read
///
/// # Returns
/// 0 on success, negative error code on failure
int qemu_mem_read(void *cpu, uint64_t guest_addr, void *buf, size_t len);

/// Write memory to guest address space
///
/// # Arguments
/// * `cpu` - CPU pointer
/// * `guest_addr` - Guest virtual address
/// * `buf` - Input buffer
/// * `len` - Number of bytes to write
///
/// # Returns
/// 0 on success, negative error code on failure
int qemu_mem_write(void *cpu, uint64_t guest_addr, const void *buf, size_t len);

/// Translate guest address to host pointer
///
/// # Arguments
/// * `guest_addr` - Guest virtual address
///
/// # Returns
/// Host pointer or NULL if address is not mapped
void *qemu_guest_to_host(uint64_t guest_addr);

/// Translate host pointer to guest address
///
/// # Arguments
/// * `host_ptr` - Host pointer
///
/// # Returns
/// Guest address
uint64_t qemu_host_to_guest(const void *host_ptr);

/// Map a memory region in guest address space
///
/// # Arguments
/// * `guest_addr` - Guest address (must be page-aligned)
/// * `size` - Size in bytes (must be page-aligned)
/// * `prot` - Protection flags (PROT_READ | PROT_WRITE | PROT_EXEC)
///
/// # Returns
/// 0 on success, negative error code on failure
int qemu_mem_map(uint64_t guest_addr, size_t size, int prot);

/// Map an existing host buffer into guest address space (zero-copy)
///
/// # Arguments
/// * `guest_addr` - Guest address
/// * `size` - Size in bytes
/// * `prot` - Protection flags
/// * `host_ptr` - Existing host buffer to map
///
/// # Returns
/// 0 on success, negative error code on failure
int qemu_mem_map_ptr(uint64_t guest_addr, size_t size, int prot, void *host_ptr);

/// Unmap a memory region
int qemu_mem_unmap(uint64_t guest_addr, size_t size);

/// Register syscall hooks
///
/// # Arguments
/// * `pre_hook` - Called before syscall, can modify args or skip syscall
/// * `post_hook` - Called after syscall with return value
///
/// # Returns
/// 0 on success, negative error code on failure
int qemu_add_syscall_hook(Option<SyscallPreHook> pre_hook, Option<SyscallPostHook> post_hook);

/// Register thread creation hook
///
/// # Arguments
/// * `hook` - Called when a new thread is created via clone()
int qemu_add_thread_hook(Option<ThreadHook> hook);

/// Register block execution hook
///
/// # Arguments
/// * `hook` - Called at the start of each translated block
int qemu_add_block_hook(Option<BlockHook> hook);

/// Start/continue execution on the current CPU
///
/// # Returns
/// 0 on normal exit, negative error code on failure
int qemu_run();

/// Stop execution (can be called from hooks)
void qemu_stop();

/// Set a breakpoint at an address
int qemu_set_breakpoint(uint64_t addr);

/// Remove a breakpoint
int qemu_remove_breakpoint(uint64_t addr);

/// Get the version string of the QEMU bridge
const char *qemu_bridge_version();

/// Get the QEMU version string
const char *qemu_version();

/// Get error message for error code
const char *qemu_strerror(int err);

}  // extern "C"
