//! LibAFL QEMU FFI Bridge for CrossShim
//!
//! Provides C-compatible FFI functions to access LibAFL QEMU's ARM64 usermode
//! emulator from C++ code. Uses QEMU with MTTCG (multi-threaded TCG) for
//! real parallel thread execution.
//!
//! NOTE: This is a scaffold implementation. The actual LibAFL QEMU integration
//! requires understanding the specific API version and will be completed
//! during Phase 3 (Emulator Core Rewrite).

#![allow(unused_variables)]
#![allow(non_camel_case_types)]

use libc::{c_char, c_int, c_void, size_t};
use once_cell::sync::OnceCell;
use parking_lot::RwLock;
use std::ffi::CStr;
use std::ptr;

// TODO: Add actual LibAFL QEMU imports once we determine the correct API
// The libafl_qemu crate has different module structure than expected.
// We'll need to investigate:
// - libafl_qemu::Qemu for the main emulator handle
// - libafl_qemu_sys for low-level CPU/memory access
//
// For now, this provides the FFI interface that C++ code will use.

/// ARM64 register indices for the emulator
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arm64Reg {
    X0 = 0,
    X1 = 1,
    X2 = 2,
    X3 = 3,
    X4 = 4,
    X5 = 5,
    X6 = 6,
    X7 = 7,
    X8 = 8,
    X9 = 9,
    X10 = 10,
    X11 = 11,
    X12 = 12,
    X13 = 13,
    X14 = 14,
    X15 = 15,
    X16 = 16,
    X17 = 17,
    X18 = 18,
    X19 = 19,
    X20 = 20,
    X21 = 21,
    X22 = 22,
    X23 = 23,
    X24 = 24,
    X25 = 25,
    X26 = 26,
    X27 = 27,
    X28 = 28,
    X29 = 29,  // Frame pointer
    X30 = 30,  // Link register (LR)
    SP = 31,   // Stack pointer
    PC = 32,   // Program counter
    // NZCV flags
    NZCV = 33,
    // Thread-local storage
    TPIDR_EL0 = 34,
    // SIMD/NEON registers (V0-V31, 128-bit each)
    V0 = 64,
    V1 = 65,
    // ... up to V31
    V31 = 95,
    // Floating point control/status
    FPCR = 96,
    FPSR = 97,
}

/// Error codes returned by QEMU bridge functions
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QemuError {
    Ok = 0,
    NotInitialized = -1,
    InvalidArgument = -2,
    MemoryError = -3,
    CpuNotFound = -4,
    HookError = -5,
    InitError = -6,
}

/// Global QEMU emulator instance
/// Using OnceCell for safe lazy initialization
static QEMU_INSTANCE: OnceCell<RwLock<QemuState>> = OnceCell::new();

/// QEMU state wrapper
struct QemuState {
    /// The QEMU emulator handle (opaque for now)
    initialized: bool,
    /// Guest base address for memory translation
    guest_base: u64,
    /// Syscall pre-hook callback
    syscall_pre_hook: Option<extern "C" fn(*mut c_void, c_int, *mut u64)>,
    /// Syscall post-hook callback
    syscall_post_hook: Option<extern "C" fn(*mut c_void, c_int, u64)>,
    /// Thread creation hook callback
    thread_hook: Option<extern "C" fn(*mut c_void, u64)>,
    /// Block execution hook callback
    block_hook: Option<extern "C" fn(*mut c_void, u64, u32)>,
}

impl Default for QemuState {
    fn default() -> Self {
        Self {
            initialized: false,
            guest_base: 0,
            syscall_pre_hook: None,
            syscall_post_hook: None,
            thread_hook: None,
            block_hook: None,
        }
    }
}

// =============================================================================
// Initialization Functions
// =============================================================================

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
#[no_mangle]
pub unsafe extern "C" fn qemu_init(argc: c_int, argv: *const *const c_char) -> c_int {
    // Validate arguments
    if argc < 1 || argv.is_null() {
        return QemuError::InvalidArgument as c_int;
    }

    // Convert C strings to Rust strings
    let mut args: Vec<String> = Vec::with_capacity(argc as usize);
    for i in 0..argc as isize {
        let arg_ptr = *argv.offset(i);
        if arg_ptr.is_null() {
            break;
        }
        match CStr::from_ptr(arg_ptr).to_str() {
            Ok(s) => args.push(s.to_string()),
            Err(_) => return QemuError::InvalidArgument as c_int,
        }
    }

    // Initialize QEMU state
    let state = QemuState {
        initialized: true,
        guest_base: 0x0, // Will be set by QEMU during actual init
        ..Default::default()
    };

    // Store in global state
    match QEMU_INSTANCE.set(RwLock::new(state)) {
        Ok(_) => {
            // TODO: Actually initialize LibAFL QEMU here
            // For now, this is a placeholder that sets up the structure
            // The real initialization will happen when we integrate with
            // the actual libafl_qemu crate
            eprintln!("[QEMU_BRIDGE] Initialized with args: {:?}", args);
            QemuError::Ok as c_int
        }
        Err(_) => {
            // Already initialized
            QemuError::InitError as c_int
        }
    }
}

/// Deinitialize LibAFL QEMU and free resources
#[no_mangle]
pub extern "C" fn qemu_deinit() {
    // OnceCell doesn't support resetting, so we just mark as not initialized
    if let Some(state) = QEMU_INSTANCE.get() {
        let mut guard = state.write();
        guard.initialized = false;
    }
}

/// Check if QEMU is initialized
#[no_mangle]
pub extern "C" fn qemu_is_initialized() -> bool {
    QEMU_INSTANCE
        .get()
        .map(|s| s.read().initialized)
        .unwrap_or(false)
}

/// Get the guest base address for memory translation
///
/// In QEMU usermode, guest addresses are offset by guest_base:
/// host_addr = guest_addr + guest_base
#[no_mangle]
pub extern "C" fn qemu_get_guest_base() -> u64 {
    QEMU_INSTANCE
        .get()
        .map(|s| s.read().guest_base)
        .unwrap_or(0)
}

// =============================================================================
// CPU Access Functions
// =============================================================================

/// Get the current CPU (for the calling thread)
///
/// In MTTCG mode, each host thread has its own vCPU.
/// Returns NULL if not in an emulation context.
#[no_mangle]
pub extern "C" fn qemu_current_cpu() -> *mut c_void {
    // TODO: Implement via libafl_qemu_sys::libafl_qemu_current_cpu()
    // For now, return a placeholder
    ptr::null_mut()
}

/// Get CPU by index
///
/// # Arguments
/// * `index` - CPU index (0-based)
///
/// # Returns
/// CPU pointer or NULL if index is out of range
#[no_mangle]
pub extern "C" fn qemu_get_cpu(index: c_int) -> *mut c_void {
    // TODO: Implement via libafl_qemu_sys
    ptr::null_mut()
}

/// Get the number of CPUs
#[no_mangle]
pub extern "C" fn qemu_num_cpus() -> c_int {
    // TODO: Implement via libafl_qemu_sys
    1
}

// =============================================================================
// Register Access Functions
// =============================================================================

/// Read a register value from a CPU
///
/// # Arguments
/// * `cpu` - CPU pointer from qemu_current_cpu() or qemu_get_cpu()
/// * `reg` - Register index (Arm64Reg enum value)
///
/// # Returns
/// Register value (64-bit)
#[no_mangle]
pub unsafe extern "C" fn qemu_read_reg(cpu: *mut c_void, reg: c_int) -> u64 {
    if cpu.is_null() {
        return 0;
    }

    // TODO: Implement via libafl_qemu_sys register access
    // The exact API depends on the QEMU version and bindings
    //
    // For ARM64, registers are typically accessed via:
    // - env->xregs[0-30] for X0-X30
    // - env->pc for PC
    // - env->sp_el[0] for SP
    // - env->pstate for NZCV
    // - env->cp15.tpidr_el[0] for TPIDR_EL0

    0
}

/// Write a register value to a CPU
///
/// # Arguments
/// * `cpu` - CPU pointer
/// * `reg` - Register index (Arm64Reg enum value)
/// * `value` - Value to write
#[no_mangle]
pub unsafe extern "C" fn qemu_write_reg(cpu: *mut c_void, reg: c_int, value: u64) {
    if cpu.is_null() {
        return;
    }

    // TODO: Implement via libafl_qemu_sys register access
}

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
#[no_mangle]
pub unsafe extern "C" fn qemu_read_regs(
    cpu: *mut c_void,
    regs: *const c_int,
    values: *mut u64,
    count: size_t,
) -> c_int {
    if cpu.is_null() || regs.is_null() || values.is_null() {
        return QemuError::InvalidArgument as c_int;
    }

    for i in 0..count {
        let reg = *regs.add(i);
        *values.add(i) = qemu_read_reg(cpu, reg);
    }

    QemuError::Ok as c_int
}

/// Write multiple registers at once
#[no_mangle]
pub unsafe extern "C" fn qemu_write_regs(
    cpu: *mut c_void,
    regs: *const c_int,
    values: *const u64,
    count: size_t,
) -> c_int {
    if cpu.is_null() || regs.is_null() || values.is_null() {
        return QemuError::InvalidArgument as c_int;
    }

    for i in 0..count {
        let reg = *regs.add(i);
        let value = *values.add(i);
        qemu_write_reg(cpu, reg, value);
    }

    QemuError::Ok as c_int
}

// =============================================================================
// Memory Access Functions
// =============================================================================

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
#[no_mangle]
pub unsafe extern "C" fn qemu_mem_read(
    cpu: *mut c_void,
    guest_addr: u64,
    buf: *mut c_void,
    len: size_t,
) -> c_int {
    if buf.is_null() || len == 0 {
        return QemuError::InvalidArgument as c_int;
    }

    // In usermode, we can directly translate guest->host via guest_base
    let guest_base = qemu_get_guest_base();
    let host_addr = (guest_addr + guest_base) as *const u8;

    // TODO: Add bounds checking against mapped regions
    std::ptr::copy_nonoverlapping(host_addr, buf as *mut u8, len);

    QemuError::Ok as c_int
}

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
#[no_mangle]
pub unsafe extern "C" fn qemu_mem_write(
    cpu: *mut c_void,
    guest_addr: u64,
    buf: *const c_void,
    len: size_t,
) -> c_int {
    if buf.is_null() || len == 0 {
        return QemuError::InvalidArgument as c_int;
    }

    let guest_base = qemu_get_guest_base();
    let host_addr = (guest_addr + guest_base) as *mut u8;

    // TODO: Add bounds checking and write protection
    std::ptr::copy_nonoverlapping(buf as *const u8, host_addr, len);

    QemuError::Ok as c_int
}

/// Translate guest address to host pointer
///
/// # Arguments
/// * `guest_addr` - Guest virtual address
///
/// # Returns
/// Host pointer or NULL if address is not mapped
#[no_mangle]
pub extern "C" fn qemu_guest_to_host(guest_addr: u64) -> *mut c_void {
    let guest_base = qemu_get_guest_base();
    (guest_addr + guest_base) as *mut c_void
}

/// Translate host pointer to guest address
///
/// # Arguments
/// * `host_ptr` - Host pointer
///
/// # Returns
/// Guest address
#[no_mangle]
pub extern "C" fn qemu_host_to_guest(host_ptr: *const c_void) -> u64 {
    let guest_base = qemu_get_guest_base();
    (host_ptr as u64).wrapping_sub(guest_base)
}

// =============================================================================
// Memory Mapping Functions
// =============================================================================

/// Map a memory region in guest address space
///
/// # Arguments
/// * `guest_addr` - Guest address (must be page-aligned)
/// * `size` - Size in bytes (must be page-aligned)
/// * `prot` - Protection flags (PROT_READ | PROT_WRITE | PROT_EXEC)
///
/// # Returns
/// 0 on success, negative error code on failure
#[no_mangle]
pub extern "C" fn qemu_mem_map(guest_addr: u64, size: size_t, prot: c_int) -> c_int {
    // TODO: Implement via QEMU's target_mmap()
    // This will allocate host memory and map it at the guest address
    QemuError::Ok as c_int
}

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
#[no_mangle]
pub unsafe extern "C" fn qemu_mem_map_ptr(
    guest_addr: u64,
    size: size_t,
    prot: c_int,
    host_ptr: *mut c_void,
) -> c_int {
    if host_ptr.is_null() || size == 0 {
        return QemuError::InvalidArgument as c_int;
    }

    // TODO: Implement via mmap with MAP_FIXED at (guest_addr + guest_base)
    // This requires careful handling of the address space
    QemuError::Ok as c_int
}

/// Unmap a memory region
#[no_mangle]
pub extern "C" fn qemu_mem_unmap(guest_addr: u64, size: size_t) -> c_int {
    // TODO: Implement via target_munmap()
    QemuError::Ok as c_int
}

// =============================================================================
// Hook Registration Functions
// =============================================================================

/// Syscall hook callback type
/// Called before syscall execution
pub type SyscallPreHook = extern "C" fn(cpu: *mut c_void, syscall_num: c_int, args: *mut u64);

/// Syscall post-hook callback type
/// Called after syscall execution with the return value
pub type SyscallPostHook = extern "C" fn(cpu: *mut c_void, syscall_num: c_int, ret: u64);

/// Register syscall hooks
///
/// # Arguments
/// * `pre_hook` - Called before syscall, can modify args or skip syscall
/// * `post_hook` - Called after syscall with return value
///
/// # Returns
/// 0 on success, negative error code on failure
#[no_mangle]
pub extern "C" fn qemu_add_syscall_hook(
    pre_hook: Option<SyscallPreHook>,
    post_hook: Option<SyscallPostHook>,
) -> c_int {
    if let Some(state) = QEMU_INSTANCE.get() {
        let mut guard = state.write();
        guard.syscall_pre_hook = pre_hook;
        guard.syscall_post_hook = post_hook;
        QemuError::Ok as c_int
    } else {
        QemuError::NotInitialized as c_int
    }
}

/// Thread creation hook callback type
pub type ThreadHook = extern "C" fn(cpu: *mut c_void, tid: u64);

/// Register thread creation hook
///
/// # Arguments
/// * `hook` - Called when a new thread is created via clone()
#[no_mangle]
pub extern "C" fn qemu_add_thread_hook(hook: Option<ThreadHook>) -> c_int {
    if let Some(state) = QEMU_INSTANCE.get() {
        let mut guard = state.write();
        guard.thread_hook = hook;
        QemuError::Ok as c_int
    } else {
        QemuError::NotInitialized as c_int
    }
}

/// Block execution hook callback type
pub type BlockHook = extern "C" fn(cpu: *mut c_void, pc: u64, size: u32);

/// Register block execution hook
///
/// # Arguments
/// * `hook` - Called at the start of each translated block
#[no_mangle]
pub extern "C" fn qemu_add_block_hook(hook: Option<BlockHook>) -> c_int {
    if let Some(state) = QEMU_INSTANCE.get() {
        let mut guard = state.write();
        guard.block_hook = hook;
        QemuError::Ok as c_int
    } else {
        QemuError::NotInitialized as c_int
    }
}

// =============================================================================
// Execution Control Functions
// =============================================================================

/// Start/continue execution on the current CPU
///
/// # Returns
/// 0 on normal exit, negative error code on failure
#[no_mangle]
pub extern "C" fn qemu_run() -> c_int {
    // TODO: Implement via QEMU's cpu_loop or emulator run
    QemuError::Ok as c_int
}

/// Stop execution (can be called from hooks)
#[no_mangle]
pub extern "C" fn qemu_stop() {
    // TODO: Implement via uc_emu_stop equivalent
}

/// Set a breakpoint at an address
#[no_mangle]
pub extern "C" fn qemu_set_breakpoint(addr: u64) -> c_int {
    // TODO: Implement via libafl_qemu_set_breakpoint
    QemuError::Ok as c_int
}

/// Remove a breakpoint
#[no_mangle]
pub extern "C" fn qemu_remove_breakpoint(addr: u64) -> c_int {
    // TODO: Implement
    QemuError::Ok as c_int
}

// =============================================================================
// Utility Functions
// =============================================================================

/// Get the version string of the QEMU bridge
#[no_mangle]
pub extern "C" fn qemu_bridge_version() -> *const c_char {
    static VERSION: &[u8] = b"libafl_qemu_bridge 1.0.0\0";
    VERSION.as_ptr() as *const c_char
}

/// Get the QEMU version string
#[no_mangle]
pub extern "C" fn qemu_version() -> *const c_char {
    static VERSION: &[u8] = b"LibAFL QEMU 0.15\0";
    VERSION.as_ptr() as *const c_char
}

// =============================================================================
// Error Handling
// =============================================================================

/// Get error message for error code
#[no_mangle]
pub extern "C" fn qemu_strerror(err: c_int) -> *const c_char {
    static MESSAGES: [&[u8]; 7] = [
        b"Success\0",
        b"Not initialized\0",
        b"Invalid argument\0",
        b"Memory error\0",
        b"CPU not found\0",
        b"Hook error\0",
        b"Initialization error\0",
    ];

    let idx = (-err) as usize;
    if idx < MESSAGES.len() {
        MESSAGES[idx].as_ptr() as *const c_char
    } else {
        b"Unknown error\0".as_ptr() as *const c_char
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init_deinit() {
        // Note: Can only run once due to OnceCell
        unsafe {
            let args = [b"qemu-aarch64\0".as_ptr() as *const c_char];
            let result = qemu_init(1, args.as_ptr());
            assert_eq!(result, 0);
            assert!(qemu_is_initialized());
            qemu_deinit();
        }
    }

    #[test]
    fn test_guest_host_translation() {
        // With guest_base = 0, addresses should pass through unchanged
        let guest = 0x40000000u64;
        let host = qemu_guest_to_host(guest);
        assert_eq!(host as u64, guest);

        let back = qemu_host_to_guest(host);
        assert_eq!(back, guest);
    }
}
