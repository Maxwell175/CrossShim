/**
 * CrossShim - ARM64 Android Library Emulator
 *
 * This library provides a complete solution for emulating Android ARM64 shared
 * libraries (.so files) on x86_64 Linux systems using LibAFL QEMU.
 *
 * It intercepts system calls and library functions through High-Level Emulation
 * (HLE), executing them natively on the host system.
 *
 * Features:
 * - Full QEMU JIT for fast ARM64 emulation
 * - Native LSE atomics support (no manual emulation needed)
 * - MTTCG support for true parallel thread execution
 * - Syscall hooks for complete HLE control
 *
 * Usage:
 *   cross_shim::Emulator emu;
 *   emu.load_library("/path/to/libfoo.so");
 *   uint64_t func_addr = emu.get_symbol("my_function");
 *   uint64_t result = emu.call_function(func_addr, {arg1, arg2});
 */

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <unordered_map>
#include <mutex>
#include <thread>
#include <condition_variable>
#include <queue>
#include <atomic>

namespace cross_shim {

// Memory region constants
constexpr uint64_t CODE_BASE       = 0x40000000ULL;
constexpr uint64_t CODE_SIZE       = 0x10000000ULL;  // 256MB for code
constexpr uint64_t HEAP_BASE       = 0x60000000ULL;
constexpr uint64_t HEAP_SIZE       = 0x10000000ULL;  // 256MB for heap
constexpr uint64_t STACK_BASE      = 0x80000000ULL;
constexpr uint64_t STACK_SIZE      = 0x00800000ULL;  // 8MB for stack
constexpr uint64_t HLE_BASE        = 0x10000000ULL;
constexpr uint64_t HLE_SIZE        = 0x00100000ULL;  // 1MB for HLE stubs
constexpr uint64_t TLS_BASE        = 0xC0000000ULL;
constexpr uint64_t TLS_SIZE        = 0x00010000ULL;  // 64KB for TLS
constexpr uint64_t TLS_PRE_SIZE    = 0x00001000ULL;  // 4KB before TLS_BASE for negative offsets
constexpr uint64_t GLOBAL_DATA_BASE = 0xB0000000ULL;
constexpr uint64_t GLOBAL_DATA_SIZE = 0x00010000ULL;  // 64KB for global data (_ctype_, etc.)

constexpr uint64_t PAGE_SIZE       = 0x1000ULL;
constexpr uint64_t PAGE_MASK       = ~(PAGE_SIZE - 1);

// Forward declarations
class Emulator;
class ElfLoader;
class MemoryManager;
class RelocationHandler;
class SyscallHandler;
class HleManager;
class TlsManager;
class ThreadManager;

} // namespace cross_shim

// QEMU types (global namespace)
struct CPUState;
struct CPUArchState;

namespace cross_shim {

// Loaded module information
struct LoadedModule {
    std::string name;
    std::string path;
    uint64_t base_address;
    uint64_t size;
    std::unordered_map<std::string, uint64_t> exports;
    std::unordered_map<std::string, uint64_t> local_symbols;  // .symtab fallback (e.g. local `main`)
    std::vector<uint8_t> data;
};

// HLE function callback type
using HleCallback = std::function<void(Emulator&)>;

// Symbol resolution callback
using SymbolResolver = std::function<uint64_t(const std::string&)>;

// Emulator configuration
struct EmulatorConfig {
    uint64_t stack_size = STACK_SIZE;
    uint64_t heap_size = HEAP_SIZE;
    bool enable_tracing = false;
    bool enable_syscall_logging = false;
    bool enable_threading = true;  // Enable real host threading
    bool enable_debug = false;     // Enable debug output
    bool enable_profile = false;   // Enable periodic profiling output
};

// Main emulator class
class Emulator {
public:
    Emulator();
    explicit Emulator(const EmulatorConfig& config);
    ~Emulator();

    // Non-copyable
    Emulator(const Emulator&) = delete;
    Emulator& operator=(const Emulator&) = delete;

    // Module loading
    bool load_library(const std::string& path);
    bool load_library(const std::string& name, const std::vector<uint8_t>& data);

    // Call pending init functions (should be called after all libraries are loaded)
    void call_init_functions();

    // Symbol resolution
    uint64_t get_symbol(const std::string& name) const;
    uint64_t get_symbol(const std::string& module, const std::string& name) const;
    

    // Function invocation
    uint64_t call_function(uint64_t address, const std::vector<uint64_t>& args = {});
    // Safe version that preserves LR (use from within HLE handlers that call emulated code)
    uint64_t call_function_safe(uint64_t address, const std::vector<uint64_t>& args = {});
    uint64_t call_function_safe_on_stack(uint64_t address, uint64_t stack_top,
                                         const std::vector<uint64_t>& args = {});
    // Direct call from current thread (must be same thread as QEMU init)
    uint64_t call_function_direct(uint64_t address, const std::vector<uint64_t>& args = {});
    // Check if the last call_function succeeded
    bool last_call_succeeded() const { return last_call_succeeded_; }
    
    // Register access
    uint64_t get_reg(int reg) const;
    void set_reg(int reg, uint64_t value);
    float get_sreg_value(int reg) const;
    
    // Memory access
    bool mem_read(uint64_t address, void* buffer, size_t size) const;
    bool mem_write(uint64_t address, const void* buffer, size_t size);
    std::vector<uint8_t> mem_read(uint64_t address, size_t size) const;
    
    // HLE registration
    void register_hle(const std::string& name, HleCallback callback);
    
    // Execution control
    bool start(uint64_t address, uint64_t end_address = 0);
    void stop();
    
    // Internal access (for HLE handlers)
    CPUState* get_cpu() const { return cpu_; }
    void set_cpu(CPUState* cpu) { cpu_ = cpu; }
    MemoryManager& memory() { return *memory_; }
    HleManager& hle() { return *hle_; }
    ThreadManager& threads() { return *threads_; }
    SyscallHandler& syscall() { return *syscall_; }
    const std::vector<LoadedModule>& modules() const { return modules_; }
    void set_debug(bool enabled);
    bool is_debug() const { return debug_enabled_; }
    void set_profile(bool enabled);
    bool is_profile() const { return profile_enabled_; }

    // Mutex for serializing HLE handler calls from multiple threads
    // CRITICAL: Must be used by syscall hook when calling HLE handlers
    std::recursive_mutex& call_mutex() { return call_mutex_; }

    // Get the base address of a loaded library by name
    uint64_t get_library_base(const std::string& name) const {
        for (const auto& mod : modules_) {
            if (mod.name == name) {
                return mod.base_address;
            }
        }
        return 0;
    }

    // Hook HLE functions at their actual addresses in loaded libraries
    // This is needed for functions that are defined internally in a library
    // (not imported through GOT/PLT) but have HLE implementations
    void hook_hle_functions_at_addresses();

    // Syscall handling (called from interrupt hook)
    void handle_syscall(uint64_t syscall_num);

private:
    void initialize();
    void initialize_global_data();
    void initialize_qemu_on_this_thread();
    void setup_hooks();
public:
    void add_mem_write_hook();
    void enable_trace(uint64_t start, uint64_t end);
    void disable_trace();
private:
    uint64_t allocate_hle_stub(const std::string& name);

    CPUState* cpu_;  // QEMU CPU state
    EmulatorConfig config_;
    bool qemu_initialized_ = false;
    std::mutex qemu_init_mutex_;
    std::condition_variable qemu_init_cv_;
    std::string first_binary_path_;  // Path to first loaded binary for QEMU init

    // QEMU hook IDs
    size_t syscall_hook_id_ = 0;
    size_t thread_hook_id_ = 0;

    std::unique_ptr<MemoryManager> memory_;
    std::unique_ptr<ElfLoader> loader_;
    std::unique_ptr<RelocationHandler> relocator_;
    std::unique_ptr<SyscallHandler> syscall_;
    std::unique_ptr<HleManager> hle_;
    std::unique_ptr<TlsManager> tls_;
    std::unique_ptr<ThreadManager> threads_;

    std::vector<LoadedModule> modules_;
    std::unordered_map<std::string, uint64_t> global_symbols_;
    std::unordered_map<uint64_t, HleCallback> hle_callbacks_;
    std::unordered_map<std::string, uint64_t> hle_stubs_;

    uint64_t next_hle_addr_;
    uint64_t next_load_addr_;
    uint64_t tls_init_addr_ = 0;  // Address of MSR TPIDR_EL0 instruction
    // NOTE: running_ is now thread-local to prevent race conditions
    // Each thread tracks its own execution state independently
    // The old shared bool caused races when child threads finished their
    // start() call and set running_=false, terminating the main thread's loop
    bool debug_enabled_ = false;
    bool profile_enabled_ = false;

    // Flag to indicate we need to restart after a context switch in HLE handler
    bool context_switch_restart_needed_ = false;

    // Flag to indicate if the last call_function succeeded
    bool last_call_succeeded_ = true;

    // Pending init functions to call after all libraries are loaded
    std::vector<uint64_t> pending_init_funcs_;

    // Flag to track if we're inside an HLE handler
    bool in_hle_handler_ = false;

    // The HLE handler address (for yield to use)
    uint64_t current_hle_address_ = 0;

    // Recursive mutex to protect concurrent access to the emulator
    // Multiple host threads calling into the emulator must be serialized
    // Recursive because emulated code may call back into the emulator
    mutable std::recursive_mutex call_mutex_;

    // Async emulator infrastructure
    struct FunctionRequest {
        uint64_t address;
        std::vector<uint64_t> args;
        uint64_t result;
        std::atomic<bool> completed{false};  // Use atomic for spin-wait
        bool is_safe_call;  // Whether this is a call_function_safe
        uint64_t safe_stack_top = 0;
        std::mutex mutex;
        std::condition_variable cv;

        // Profiling timestamps for latency spike analysis
        std::chrono::steady_clock::time_point t_submit;      // When request was created
        std::chrono::steady_clock::time_point t_queued;      // After queue push
        std::chrono::steady_clock::time_point t_dequeued;    // When emulator thread picked it up
        std::chrono::steady_clock::time_point t_exec_start;  // Before call_function_internal
        std::chrono::steady_clock::time_point t_exec_end;    // After call_function_internal
    };

    std::thread emulator_thread_;
    std::thread::id emulator_thread_id_;
    std::thread::id current_execution_thread_id_;  // Thread currently running QEMU
    std::atomic<bool> should_stop_{false};
    std::queue<std::shared_ptr<FunctionRequest>> request_queue_;
    std::mutex queue_mutex_;
    std::condition_variable request_cv_;

    // Per-worker mailboxes for sticky affinity routing. Each calling host thread is
    // pinned to ONE worker vCPU so a given caller's C->guest calls always execute on the
    // SAME guest thread/CPU. Bouncing them across CPUs corrupts guest libraries that keep
    // per-thread state (e.g. receive/reassembly buffers), causing deterministic stalls.
    // Index 0 = main emulator thread (bootstrap + spawn); 1..vcpu_worker_count_
    // = pool workers, which are the affinity targets. Sized once in the constructor.
    struct WorkerMailbox {
        std::queue<std::shared_ptr<FunctionRequest>> queue;
        std::mutex mtx;
        std::condition_variable cv;
    };
    std::vector<std::unique_ptr<WorkerMailbox>> worker_mailboxes_;
    std::atomic<int> next_affinity_worker_{0};   // round-robin cursor for new caller threads
    bool spawn_initiated_ = false;               // worker-0-only guard for lazy pool spawn
    int pick_affinity_worker();                  // sticky worker id for the calling thread

    // --- Parallel vCPU worker pool ---------------------------------------------
    // Additional worker host threads, each owning its own cloned guest vCPU, that
    // consume request_queue_ concurrently so C->guest calls execute in PARALLEL across
    // host cores instead of serializing on the single
    // emulator_thread_/CPU0. Worker vCPUs are minted via the guest clone() path and
    // their host threads are diverted into worker_vcpu_loop() by a libafl new-thread
    // hook (see vcpu_new_thread_hook_cb). usermode linux-user has no real BQL, so these
    // run truly in parallel.
    int vcpu_worker_count_ = 0;                 // extra workers beyond the main thread
    std::atomic<bool> workers_spawned_{false};
    std::vector<CPUState*> worker_cpus_;
    // Spawn coordination: each freshly-cloned worker host thread self-binds its OWN vCPU
    // (env_cpu(env)) from the new-thread hook and is identified by the clone-stub PC, so
    // concurrent guest thread creation can't mis-assign vCPUs.
    std::mutex worker_handshake_mutex_;
    std::condition_variable worker_handshake_cv_;
    bool spawning_workers_ = false;
    int vcpu_workers_claimed_ = 0;
    uint64_t vcpu_worker_clone_addr_ = 0;   // guest PC the worker clones resume at
    void spawn_vcpu_workers();
    void worker_vcpu_loop(int worker_id, CPUState* cpu);
    void run_request_loop();                    // shared request-processing loop
    bool on_vcpu_new_thread(::CPUArchState* env, uint32_t tid);
    static bool vcpu_new_thread_hook_cb(uint64_t data, ::CPUArchState* env, uint32_t tid);

    void emulator_thread_func();  // Background thread function
    // Exception firewall: catches any C++ exception escaping guest execution / HLE and
    // converts it to a failed call (-1) instead of letting it cross the P/Invoke boundary
    // or escape the worker thread (which would std::terminate the whole process and every
    // session). All call paths (worker thread, direct, safe) funnel through here.
    uint64_t call_function_internal(uint64_t address, const std::vector<uint64_t>& args, bool is_safe,
                                    uint64_t safe_stack_top = 0);
    uint64_t call_function_internal_impl(uint64_t address, const std::vector<uint64_t>& args, bool is_safe,
                                         uint64_t safe_stack_top = 0);
    void start_emulator_thread();  // Start background thread
    void stop_emulator_thread();   // Stop background thread

public:
    // Set/get context switch restart flag
    void set_context_switch_restart_needed(bool needed) { context_switch_restart_needed_ = needed; }
    bool is_context_switch_restart_needed() const { return context_switch_restart_needed_; }

    // Set/get HLE handler state
    void set_in_hle_handler(bool in_hle, uint64_t hle_addr = 0) {
        in_hle_handler_ = in_hle;
        current_hle_address_ = hle_addr;
    }
    bool is_in_hle_handler() const { return in_hle_handler_; }
    uint64_t get_current_hle_address() const { return current_hle_address_; }
};

// Get the current CPU for this thread
CPUState* get_current_cpu(Emulator& emu);

} // namespace cross_shim
