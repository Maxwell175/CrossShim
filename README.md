# CrossShim

A high-performance ARM64 Android library emulator for x86_64 Linux systems.

## Overview

CrossShim enables running Android ARM64 shared libraries (`.so` files) on x86_64 Linux by emulating the ARM64 CPU using LibAFL QEMU. Instead of emulating every libc/libm call, it uses High-Level Emulation (HLE) to intercept and execute them natively on the host system, providing near-native performance for I/O-bound operations.

## Features

- **ARM64 Emulation**: Full ARM64/AArch64 CPU emulation via LibAFL QEMU with JIT compilation
- **MTTCG Threading**: Real parallel host threads via QEMU's Multi-Threaded TCG
- **Native LSE Atomics**: ARM64 Large System Extensions handled natively by QEMU
- **ELF Loading**: Parse and load Android ELF shared libraries using LIEF
- **460+ HLE Functions**: Native implementations of libc, libm, pthread, networking, and more
- **Memory Management**: Virtual memory with heap, stack, and TLS support
- **Comprehensive Testing**: 760+ tests covering all major functionality

## Project Structure

```
CrossShim/
├── include/                    # Public headers
│   └── cross_shim.h          # Main emulator API
├── src/                        # Implementation
│   ├── emulator.cpp           # Core emulator (LibAFL QEMU integration)
│   ├── elf_loader.cpp         # ELF binary loading
│   ├── memory_manager.cpp     # Memory allocation
│   ├── thread_manager.cpp     # Thread tracking (QEMU handles actual threading)
│   ├── hle_libc.cpp           # libc HLE registration
│   ├── hle_libm.cpp           # libm HLE registration
│   └── hle/                   # Modular HLE implementations
├── scripts/                    # Build scripts
│   └── build_qemu_libafl.sh   # Build LibAFL QEMU (run first!)
├── external/                   # External dependencies (QEMU install, etc.)
├── test/                       # Emulator validation tests
│   ├── run_emulator_tests.sh  # Test runner script
│   └── test_*.c               # ARM64 test sources
├── wrapper_generator/          # Python tool for generating wrappers
├── CMakeLists.txt
└── ARCHITECTURE.md            # Detailed architecture documentation
```

## Quick Start

### Prerequisites

- CMake 3.20+
- C++20 compiler (GCC 10+ or Clang 12+)
- LIEF library
- GLib 2.0 (for QEMU)
- Android NDK (for running tests)

### Building

```bash
# 1. Build LibAFL QEMU first (one-time setup)
cd scripts
./build_qemu_libafl.sh
cd ..

# 2. Build the emulator library
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=ON
make -j$(nproc)
```

### Basic Usage

```cpp
#include <cross_shim.h>

int main() {
    cross_shim::Emulator emu;

    // Load an Android ARM64 shared library
    emu.load_library("/path/to/libfoo.so");
    emu.call_init_functions();

    // Get a function address and call it
    uint64_t func = emu.get_symbol("my_function");
    uint64_t result = emu.call_function(func, {arg1, arg2, arg3});

    return 0;
}
```

### Running Tests

```bash
# Build test binaries (requires Android NDK)
cd test && ./build_ndk.sh

# Run emulator tests
./build/emu_test_runner test/ndk_build/test_emulator_arm64

# Run wrapper generator tests
cd wrapper_generator && ./run_tests.sh
```

## Architecture

### LibAFL QEMU Backend

CrossShim uses [LibAFL QEMU](https://github.com/AFLplusplus/qemu-libafl-bridge) for ARM64 emulation:

- **JIT Compilation**: Fast Tiny Code Generator (TCG) translates ARM64 to x86_64
- **MTTCG**: Multi-Threaded TCG enables real parallel host threads
- **Native Syscalls**: Most syscalls handled directly by QEMU's linux-user mode
- **HLE via Syscall Hooks**: Custom syscall numbers trigger HLE handlers

### Threading Model

Unlike cooperative threading, MTTCG provides real parallel execution:

- Guest `pthread_create()` → Linux `clone()` syscall → Real host thread
- No explicit context switching needed
- Threads run truly in parallel on multi-core systems
- LSE atomics handled natively (no manual emulation)

### Memory Layout

```
0x10000000 - HLE_BASE: HLE trampolines and stubs
0x40000000 - CODE_BASE: Loaded libraries
0x60000000 - HEAP_BASE: Dynamic heap
0x80000000 - STACK_BASE: Main thread stack
0x90000000 - CHILD_STACKS: Child thread stacks
0xB0000000 - GLOBAL_DATA_BASE: Global data (_ctype_, __sF, etc.)
0xC0000000 - TLS_BASE: Thread Local Storage
```

## Wrapper Generator

The `wrapper_generator/` directory contains a Python tool that:

1. **Extracts symbols** from Android ARM64 `.so` files using NDK tools
2. **Generates C++ wrapper code** that loads the library into the emulator
3. **Creates host-callable interfaces** for the emulated functions

See `wrapper_generator/README.md` for detailed usage.

## Documentation

- **[ARCHITECTURE.md](ARCHITECTURE.md)** - Detailed architecture documentation
- **[wrapper_generator/](wrapper_generator/)** - Wrapper generation tool

## Test Suite

The emulator includes comprehensive tests:

| Category | Tests | Description |
|----------|-------|-------------|
| Main Emulator | 752+ | String, memory, stdio, stdlib, math, networking, threading, etc. |
| Threading | 90+ | pthread operations, mutexes, condition variables, TLS |
| **Total** | **760+** | All tests passing |

## License

See LICENSE file for details.
