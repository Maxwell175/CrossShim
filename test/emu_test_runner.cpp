/**
 * Emulator Test Runner
 * 
 * Loads an ARM64 ELF binary and executes it through the emulator.
 * Used to validate HLE implementations for networking and threading.
 */

#include "cross_shim.h"
#include "memory_manager.h"
#include "syscall_handler.h"
#include "hle_manager.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>

using namespace cross_shim;

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <arm64_binary>" << std::endl;
        return 1;
    }

    const char* binary_path = argv[1];
    
    std::cout << "========================================" << std::endl;
    std::cout << "  Emulator Test Runner" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Loading: " << binary_path << std::endl;

    // Get binary size for display
    std::ifstream file(binary_path, std::ios::binary | std::ios::ate);
    if (!file) {
        std::cerr << "ERROR: Cannot open file: " << binary_path << std::endl;
        return 1;
    }
    std::streamsize size = file.tellg();
    file.close();

    std::cout << "Binary size: " << size << " bytes" << std::endl;

    // Create emulator
    EmulatorConfig config;
    config.enable_tracing = false;
    config.enable_syscall_logging = false;  // Disable syscall logging
    config.enable_threading = true;
    config.stack_size = 8 * 1024 * 1024;  // 8MB stack
    config.heap_size = 64 * 1024 * 1024;  // 64MB heap
    // Check EMU_DEBUG environment variable
    const char* debug_env = getenv("EMU_DEBUG");
    config.enable_debug = (debug_env && atoi(debug_env) != 0);

    std::cout << "Initializing emulator..." << std::endl;
    Emulator emu(config);

    // Enable syscall logging if configured
    if (config.enable_syscall_logging) {
        emu.syscall().set_logging(true);
    }

    // Debug output if enabled
    if (config.enable_debug) {
        std::cout << "[DEBUG] Debug mode enabled - instruction-level tracing active" << std::endl;
    }

    // Load the binary as a library (using path to trigger QEMU initialization)
    std::cout << "Loading binary into emulator..." << std::endl;
    if (!emu.load_library(binary_path)) {
        std::cerr << "ERROR: Failed to load binary into emulator" << std::endl;
        return 1;
    }

    // Call init functions
    std::cout << "Calling init functions..." << std::endl;
    emu.call_init_functions();

    // Find the main function
    uint64_t main_addr = emu.get_symbol("main");
    if (main_addr == 0) {
        std::cerr << "ERROR: Cannot find 'main' symbol in binary" << std::endl;
        
        // List available symbols
        std::cout << "Available symbols:" << std::endl;
        for (const auto& mod : emu.modules()) {
            std::cout << "  Module: " << mod.name << std::endl;
            for (const auto& exp : mod.exports) {
                std::cout << "    " << exp.first << " @ 0x" << std::hex << exp.second << std::dec << std::endl;
            }
        }
        return 1;
    }

    std::cout << "Found main at: 0x" << std::hex << main_addr << std::dec << std::endl;

    // Set up argc/argv - pass through command line arguments after the binary path
    HeapAllocator& heap = emu.memory().heap();

    // Calculate number of arguments to pass (argc-1 arguments after binary path)
    int emu_argc = argc - 1;  // argv[0] = binary name, then rest of args

    // Allocate array for argv pointers (emu_argc + 1 for NULL terminator)
    uint64_t argv_addr = heap.allocate((emu_argc + 1) * 8, 8);

    // Allocate and copy each argument string
    std::vector<uint64_t> arg_addrs;
    for (int i = 1; i < argc; i++) {
        size_t len = strlen(argv[i]) + 1;
        uint64_t arg_addr = heap.allocate(len, 8);
        emu.mem_write(arg_addr, argv[i], len);
        arg_addrs.push_back(arg_addr);
    }

    // Write argv pointers
    for (int i = 0; i < emu_argc; i++) {
        emu.mem_write(argv_addr + i * 8, &arg_addrs[i], 8);
    }
    // NULL terminator
    uint64_t null_ptr = 0;
    emu.mem_write(argv_addr + emu_argc * 8, &null_ptr, 8);

    // Print arguments being passed
    std::cout << "Arguments (" << emu_argc << "):" << std::endl;
    for (int i = 1; i < argc; i++) {
        std::cout << "  argv[" << (i-1) << "] = " << argv[i] << std::endl;
    }

    std::cout << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "  Calling main() directly..." << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << std::endl;

    // Set up registers for calling main(argc, argv)
    // Must call from main thread since that's where QEMU was initialized
    emu.set_reg(0, emu_argc);  // x0 = argc
    emu.set_reg(1, argv_addr); // x1 = argv

    // Call main directly (not through emulator thread)
    uint64_t result = emu.call_function_direct(main_addr);

    std::cout << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "  Execution complete" << std::endl;
    std::cout << "  Return value: " << static_cast<int64_t>(result) << std::endl;
    std::cout << "========================================" << std::endl;

    return static_cast<int>(result);
}

