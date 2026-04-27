/**
 * CrossShim Runner - Standalone ARM64 binary executor
 *
 * Usage: cross_shim <binary> [args...]
 *
 * Loads an ARM64 ELF binary and executes its main() function,
 * passing the remaining command-line arguments.
 */

#include "cross_shim.h"
#include "memory_manager.h"
#include <iostream>
#include <fstream>
#include <cstring>
#include <cstdlib>

using namespace cross_shim;

static void print_usage(const char* prog) {
    std::cerr << "Usage: " << prog << " <arm64_binary> [args...]" << std::endl;
    std::cerr << std::endl;
    std::cerr << "Environment variables:" << std::endl;
    std::cerr << "  EMU_DEBUG=1       Enable debug output" << std::endl;
    std::cerr << "  EMU_TRACE=1       Enable instruction tracing" << std::endl;
    std::cerr << "  EMU_HEAP_MB=N     Set heap size in MB (default: 64)" << std::endl;
    std::cerr << "  EMU_STACK_MB=N    Set stack size in MB (default: 8)" << std::endl;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    const char* binary_path = argv[1];

    // Check binary exists
    std::ifstream file(binary_path, std::ios::binary);
    if (!file) {
        std::cerr << "Error: Cannot open file: " << binary_path << std::endl;
        return 1;
    }
    file.close();

    // Configure emulator from environment
    EmulatorConfig config;
    config.enable_threading = true;

    if (const char* v = getenv("EMU_DEBUG")) {
        config.enable_debug = (atoi(v) != 0);
    }
    if (const char* v = getenv("EMU_TRACE")) {
        config.enable_tracing = (atoi(v) != 0);
    }
    if (const char* v = getenv("EMU_HEAP_MB")) {
        config.heap_size = static_cast<uint64_t>(atoi(v)) * 1024 * 1024;
    } else {
        config.heap_size = 64 * 1024 * 1024;  // 64MB default
    }
    if (const char* v = getenv("EMU_STACK_MB")) {
        config.stack_size = static_cast<uint64_t>(atoi(v)) * 1024 * 1024;
    } else {
        config.stack_size = 8 * 1024 * 1024;  // 8MB default
    }

    // Create emulator
    Emulator emu(config);

    // Load the binary
    if (!emu.load_library(binary_path)) {
        std::cerr << "Error: Failed to load binary: " << binary_path << std::endl;
        return 1;
    }

    // Call init functions
    emu.call_init_functions();

    // Find main function
    uint64_t main_addr = emu.get_symbol("main");
    if (main_addr == 0) {
        std::cerr << "Error: Cannot find 'main' symbol in binary" << std::endl;
        return 1;
    }

    // Set up argc/argv
    // argc-1 because we skip our own argv[0], but include the binary as argv[0] for the guest
    int emu_argc = argc - 1;
    HeapAllocator& heap = emu.memory().heap();

    // Allocate argv array (argc + 1 for NULL terminator)
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

    // Call main with argc and argv as arguments
    // IMPORTANT: Don't use set_reg() separately - pass args directly to call_function
    // because the call may be queued to a different thread/CPU
    uint64_t result = emu.call_function_direct(main_addr, {
        static_cast<uint64_t>(emu_argc),
        argv_addr
    });

    return static_cast<int>(result);
}
