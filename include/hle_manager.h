#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <functional>
#include <sys/types.h>

namespace cross_shim {

class Emulator;
class MemoryManager;

// HLE function callback
using HleCallback = std::function<void(Emulator&)>;

// HLE (High-Level Emulation) manager for libc/libm functions
class HleManager {
public:
    HleManager(Emulator& emu, MemoryManager& memory);
    ~HleManager() = default;
    
    // Register all default HLE functions
    void register_defaults();
    
    // Register a custom HLE function
    void register_function(const std::string& name, HleCallback callback);

    // Register an HLE function at a specific address (for internal library functions)
    void register_function_at_address(uint64_t address, const std::string& name, HleCallback callback);

    // Register an address for an already-registered HLE function (by name)
    void register_address_for_function(uint64_t address, const std::string& name);

    // Get address of HLE stub for a function
    uint64_t get_stub_address(const std::string& name);
    
    // Check if a function has HLE implementation
    bool has_hle(const std::string& name) const;
    
    // Handle HLE call (called from code hook)
    bool handle(uint64_t address);

    // Handle HLE call with explicit CPU pointer (avoids race in MTTCG mode)
    bool handle_with_cpu(void* cpu, uint64_t address);

    // Handle HLE call for a specific engine (for thread support)
    bool handle_for_engine(void* uc, uint64_t address);
    
    // Get all registered function names
    std::vector<std::string> get_registered_functions() const;

private:
    // Allocate a stub in HLE memory region
    uint64_t allocate_stub(const std::string& name);

    // Write stub code (syscall-based for multi-thread support)
    void write_stub(uint64_t address, int syscall_num);
    
    Emulator& emu_;
    MemoryManager& memory_;
    
    std::unordered_map<std::string, HleCallback> callbacks_;
    std::unordered_map<std::string, uint64_t> stub_addresses_;
    std::unordered_map<uint64_t, std::string> address_to_name_;
    
    uint64_t next_stub_addr_;
};

// Register libc HLE functions (legacy)
void register_libc_hle(HleManager& hle);

// Register libm HLE functions (legacy)
void register_libm_hle(HleManager& hle);

// Register libdl HLE functions
void register_libdl_hle(HleManager& hle);

// Register pthread HLE functions (legacy)
void register_pthread_hle(HleManager& hle);

// ============================================================================
// New modular HLE registration functions
// ============================================================================

// Memory allocation functions (malloc, calloc, realloc, free, mmap, etc.)
void register_hle_memory(HleManager& hle);

// String manipulation functions (strlen, strcpy, strcmp, strcat, etc.)
void register_hle_string(HleManager& hle);

// Memory operations (memcpy, memset, memcmp, memmove, etc.)
void register_hle_mem_ops(HleManager& hle);

// Console I/O and formatting (printf, sprintf, snprintf, etc.)
void register_hle_io(HleManager& hle);

// File operations (fopen, fclose, fread, fwrite, open, close, etc.)
void register_hle_file(HleManager& hle);

// Time functions (time, gettimeofday, clock_gettime, sleep, etc.)
void register_hle_time(HleManager& hle);

// Network functions (socket, connect, bind, send, recv, etc.)
void register_hle_network(HleManager& hle);

// Pthread functions (mutex, cond, rwlock, thread operations)
void register_hle_pthread(HleManager& hle);

// Miscellaneous functions (remaining misc functions)
void register_hle_misc(HleManager& hle);

// Standard library functions (getenv, atoi, strtol, rand, qsort, etc.)
void register_hle_stdlib(HleManager& hle);

// Wide character functions (wcs*, wmem*, wctype)
void register_hle_wchar(HleManager& hle);

// Locale and multibyte functions (setlocale, mb*, newlocale, c16/c32)
void register_hle_locale(HleManager& hle);

// Character classification functions (is*, to*, wctype, wctrans)
void register_hle_ctype(HleManager& hle);

// Signal functions (sigset*, sigprocmask*, pthread_sigmask*, etc.)
void register_hle_signal(HleManager& hle);

// Search functions (lfind, lsearch, tfind, tsearch, hcreate, hsearch, etc.)
void register_hle_search(HleManager& hle);

// Scheduler and semaphore functions (sched_*, sem_*)
void register_hle_sched(HleManager& hle);

// Non-local jumps (setjmp, longjmp)
void register_hle_setjmp(HleManager& hle);

// System configuration and resources (uname, getrlimit, pathconf, etc.)
void register_hle_sysconf(HleManager& hle);

// Math functions (sin, cos, sqrt, pow, floor, ceil, etc.)
void register_hle_math(HleManager& hle);

// Process control functions (fork, exec, waitpid, kill, signal, etc.)
void register_hle_process(HleManager& hle);

// Directory operations (opendir, readdir, closedir, mkdir, etc.)
void register_hle_dir(HleManager& hle);

// Syslog functions (openlog, syslog, closelog)
void register_hle_syslog(HleManager& hle);

// User/group functions (getpwuid, getauxval, if_nametoindex, etc.)
void register_hle_user(HleManager& hle);

// OpenSSL crypto functions (EC key generation, ECDH, etc.)
void register_hle_crypto(HleManager& hle);

// ============================================================================
// Shared HLE state functions
// ============================================================================

// Set the emulated errno value (used by HLE functions that fail)
// Writes directly to the errno location in guest memory
void hle_set_errno(Emulator& emu, int value);

// Get the emulated errno value from guest memory
int hle_get_errno(Emulator& emu);

// Guest thread identity helpers. These return guest-visible tids rather than
// raw host-thread ids, so the emulated main thread still reports tid==pid.
uint64_t hle_get_current_pthread_id(Emulator& emu);
pid_t hle_get_current_visible_tid(Emulator& emu);
pid_t hle_lookup_pthread_tid(Emulator& emu, uint64_t pthread_id);

} // namespace cross_shim
