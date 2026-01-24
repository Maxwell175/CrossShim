# CrossShim - Architecture Documentation

This project provides a complete solution for emulating Android ARM64 shared libraries on x86_64 Linux systems using LibAFL QEMU.

## Overview

The system emulates Android ARM64 shared libraries (`.so` files) on x86_64 Linux. It intercepts system calls and library functions through High-Level Emulation (HLE), executing them natively on the host system.

### Architecture Layers

```
┌─────────────────────────────────────────────────────────────────┐
│                    Your Application                             │
│  (Uses generated wrappers or direct Emulator API)               │
├─────────────────────────────────────────────────────────────────┤
│                    Generated Wrapper Layer                      │
│  (C++ wrappers with embedded .so data, created by               │
│   wrapper_generator Python tool)                                │
├─────────────────────────────────────────────────────────────────┤
│                    CrossShim Core                           │
│  (libcross_shim.a - ELF loading, memory, HLE, threading)       │
├─────────────────────────────────────────────────────────────────┤
│                    LibAFL QEMU                                  │
│  (ARM64/AArch64 CPU emulation with JIT + MTTCG)                 │
└─────────────────────────────────────────────────────────────────┘
```

## Directory Structure

```
CrossShim/
├── include/                    # Header files
│   ├── cross_shim.h          # Main emulator interface
│   ├── elf_loader.h           # ELF binary parser
│   ├── memory_manager.h       # Virtual memory management
│   ├── relocation_handler.h   # ELF relocation processing
│   ├── syscall_handler.h      # ARM64 syscall emulation
│   ├── hle_manager.h          # High-Level Emulation registry
│   ├── tls_manager.h          # Thread Local Storage
│   └── thread_manager.h       # Thread tracking
│
├── src/                        # Source files
│   ├── emulator.cpp           # Main emulator with QEMU integration
│   ├── elf_loader.cpp         # LIEF-based ELF loader
│   ├── memory_manager.cpp     # Memory allocation with free list
│   ├── relocation_handler.cpp # Relocation processing
│   ├── syscall_handler.cpp    # Syscall handling (includes futex)
│   ├── hle_libc.cpp           # libc HLE registration
│   ├── hle_libm.cpp           # libm HLE registration
│   ├── thread_manager.cpp     # Thread tracking
│   ├── tls_manager.cpp        # TLS setup
│   └── hle/                   # Modular HLE implementations
│       ├── hle_memory.cpp     # malloc, calloc, realloc, free, mmap
│       ├── hle_string.cpp     # strlen, strcpy, strcmp, strcat, etc.
│       ├── hle_mem_ops.cpp    # memcpy, memset, memcmp, memmove
│       ├── hle_io.cpp         # printf, fprintf, sprintf, snprintf
│       ├── hle_file.cpp       # fopen, fclose, fread, fwrite, fseek
│       ├── hle_time.cpp       # time, gettimeofday, clock_gettime
│       ├── hle_network.cpp    # socket, connect, bind, send, recv
│       ├── hle_pthread.cpp    # pthread_mutex_*, pthread_cond_*
│       ├── hle_misc.cpp       # getenv, atoi, strtol, rand, exit
│       ├── hle_math.cpp       # sin, cos, tan, sqrt, pow, log, exp
│       ├── hle_process.cpp    # fork, exec, wait, getpid
│       ├── hle_dir.cpp        # opendir, readdir, closedir
│       ├── hle_syslog.cpp     # syslog, openlog, closelog
│       ├── hle_user.cpp       # getuid, getgid, getpwnam
│       └── hle_crypto.cpp     # Crypto stubs (OpenSSL runs emulated)
│
├── scripts/                    # Build scripts
│   └── build_qemu_libafl.sh   # Build LibAFL QEMU
│
├── external/                   # External dependencies
│   ├── qemu-libafl-bridge/    # QEMU source (cloned by build script)
│   └── qemu-install/          # QEMU build output
│
├── test/                       # Emulator validation tests
│   ├── run_emulator_tests.sh  # Test runner script
│   ├── emu_test_runner.cpp    # Test harness
│   └── test_*.c               # ARM64 test sources
│
├── wrapper_generator/          # Python wrapper generation tool
│   ├── android_wrapper_generator/
│   └── tests/
│
├── cmake/                      # CMake package config
├── CMakeLists.txt             # Build configuration
└── build/                      # Build output
    └── libcross_shim.a       # Core emulator static library
```

## Core Components

### 1. Emulator (`src/emulator.cpp`)

The main emulator class that orchestrates all components:

- **LibAFL QEMU**: ARM64 CPU emulation with JIT compilation
- **MTTCG**: Multi-Threaded TCG for real parallel host threads
- **Syscall Hooks**: Intercept syscalls for HLE handling
- **Memory Layout**:
  - `CODE_BASE`: 0x40000000 (256MB for loaded libraries)
  - `HEAP_BASE`: 0x60000000 (256MB for dynamic allocation)
  - `STACK_BASE`: 0x80000000 (8MB stack)
  - `HLE_BASE`: 0x10000000 (1MB for HLE trampolines)
  - `TLS_BASE`: 0xC0000000 (64KB for Thread Local Storage)
  - `GLOBAL_DATA_BASE`: 0xB0000000 (64KB for global data like `_ctype_` table)

### 2. ELF Loader (`src/elf_loader.cpp`)

Uses LIEF library to parse and load ELF binaries:

- Loads PT_LOAD segments into emulated memory
- Extracts symbol tables for function lookup
- Provides base address and entry point information

### 3. Memory Manager (`src/memory_manager.cpp`)

Virtual memory management with:

- Page-aligned allocation
- Free list for memory reuse
- Heap growth tracking
- Memory protection support

### 4. Relocation Handler (`src/relocation_handler.cpp`)

Processes ELF relocations:

- `R_AARCH64_RELATIVE`: Base address adjustment
- `R_AARCH64_GLOB_DAT`: Global data symbols
- `R_AARCH64_JUMP_SLOT`: PLT entries for function calls

### 5. HLE (High-Level Emulation)

Instead of emulating libc/libm, we intercept calls and execute native implementations:

- **460+ HLE functions** across 15 modules
- **Mechanism**: PLT/GOT entries point to HLE stubs containing `SVC #syscall_num`
- **Syscall Hook**: Intercepts custom syscall numbers and calls HLE handlers
- **ARM64 ABI**: X0-X7 for integer arguments, D0-D7 for floating point, X0 for return

### 6. Syscall Handler (`src/syscall_handler.cpp`)

Handles ARM64 syscalls including:

- **File operations**: open, close, read, write, lseek, fstat
- **Memory operations**: mmap, munmap, mprotect, brk
- **Process operations**: getpid, gettid, exit, exit_group
- **Thread operations**: clone, futex, set_tid_address
- **Time operations**: clock_gettime, gettimeofday

#### Futex Support

The futex syscall is implemented for proper thread synchronization:

| Operation | Description |
|-----------|-------------|
| FUTEX_WAIT | Block if futex value matches expected |
| FUTEX_WAKE | Wake up to N waiters |
| FUTEX_WAIT_PRIVATE | Private futex wait (same process) |
| FUTEX_WAKE_PRIVATE | Private futex wake |

## Memory Layout Diagram

```
0x00000000 ┌─────────────────────────┐
           │                         │
0x10000000 ├─────────────────────────┤ HLE_BASE
           │   HLE Trampolines (1MB) │
0x10100000 ├─────────────────────────┤
           │                         │
0x40000000 ├─────────────────────────┤ CODE_BASE
           │   Loaded Libraries      │
           │   (256MB)               │
0x50000000 ├─────────────────────────┤
           │                         │
0x60000000 ├─────────────────────────┤ HEAP_BASE
           │   Dynamic Heap (256MB)  │
0x70000000 ├─────────────────────────┤
           │                         │
0x80000000 ├─────────────────────────┤ STACK_BASE
           │   Main Thread Stack     │
           │   (8MB, grows downward) │
0x80800000 ├─────────────────────────┤
           │                         │
0x90000000 ├─────────────────────────┤ CHILD_STACKS
           │   Child Thread Stacks   │
           │   (1MB each)            │
0xA0000000 ├─────────────────────────┤
           │                         │
0xB0000000 ├─────────────────────────┤ GLOBAL_DATA_BASE
           │   Global Data (64KB)    │
           │   - _ctype_ table       │
           │   - __sF (FILE structs) │
           │   - __stack_chk_guard   │
0xB0010000 ├─────────────────────────┤
           │                         │
0xC0000000 ├─────────────────────────┤ TLS_BASE
           │   Main Thread TLS       │
           │   (64KB)                │
0xC0010000 ├─────────────────────────┤
           │                         │
0xD0000000 ├─────────────────────────┤ CHILD_TLS
           │   Child Thread TLS      │
           │   (64KB each)           │
           └─────────────────────────┘
```

## API Usage

### Basic Usage

```cpp
#include <cross_shim.h>

int main() {
    // Create emulator with default config
    cross_shim::Emulator emu;

    // Or with custom config
    cross_shim::EmulatorConfig config;
    config.stack_size = 16 * 1024 * 1024;  // 16MB stack
    config.enable_threading = true;
    cross_shim::Emulator emu2(config);

    // Load library
    emu.load_library("/path/to/libfoo.so");
    emu.call_init_functions();

    // Call a function
    uint64_t func = emu.get_symbol("my_function");
    uint64_t result = emu.call_function(func, {arg1, arg2});

    return 0;
}
```

### Loading from Memory

```cpp
// Load library from byte array (useful for embedded libraries)
std::vector<uint8_t> lib_data = read_file("libfoo.so");
emu.load_library("libfoo.so", lib_data);
```

### Registering Custom HLE Functions

```cpp
emu.register_hle("my_custom_function", [](cross_shim::Emulator& emu) {
    // Read arguments from QEMU registers
    uint64_t arg0 = emu.get_reg(QEMU_ARM64_REG_X0);
    uint64_t arg1 = emu.get_reg(QEMU_ARM64_REG_X1);

    // Do work...
    uint64_t result = arg0 + arg1;

    // Write return value
    emu.set_reg(QEMU_ARM64_REG_X0, result);
});
```

## Threading Architecture

### MTTCG (Multi-Threaded TCG)

CrossShim uses QEMU's MTTCG mode for true parallel thread execution:

- **Real Host Threads**: Each guest thread runs on a dedicated host thread
- **Native clone()**: Guest `pthread_create()` → Linux `clone()` → real host thread
- **No Context Switching**: Unlike cooperative threading, no explicit scheduling needed
- **True Parallelism**: Threads execute in parallel on multi-core systems

### How It Works

1. Guest code calls `pthread_create()`
2. HLE handler sets up new thread stack and TLS
3. QEMU's `clone()` syscall implementation creates a real host thread
4. New thread starts executing at the specified entry point
5. Both threads run truly in parallel

### LSE Atomics

ARM64 Large System Extensions (LSE) atomics are handled natively by QEMU:

- No manual atomic instruction emulation needed
- `__aarch64_ldadd4_acq_rel`, `__aarch64_cas4_acq_rel`, etc. just work
- Memory barriers (DMB, DSB, ISB) handled by QEMU

### Thread-Local Storage (TLS)

Each thread has its own TLS region:
- `TPIDR_EL0` register (ARM64 thread pointer) points to thread's TLS base
- Stack guard canary at offset 0x28 (value: 0xDEADBEEFCAFEBABE)
- Thread ID at offset 0x10
- errno location at offset 0x100

## Building LibAFL QEMU

The emulator requires LibAFL QEMU built as a shared library. The build script handles this:

```bash
cd scripts
./build_qemu_libafl.sh
```

This script:
1. Clones qemu-libafl-bridge from AFLplusplus
2. Applies .NET compatibility patches (for signal handling)
3. Configures QEMU for ARM64 linux-user mode
4. Builds QEMU as a shared library (`libqemu-aarch64.so`)
5. Installs to `external/qemu-install/`

### .NET Compatibility Patches

When running with .NET, QEMU's signal handler can crash because it dereferences `thread_cpu` which is NULL on .NET CLR threads. The build script applies patches to fix this:

- **linux-user/signal.c**: Returns early from `host_signal_handler()` if `thread_cpu` is NULL
- **accel/tcg/vcpu-state.h**: Returns NULL from `get_task_state()` if cpu pointer is NULL

## Wrapper Generator

The `wrapper_generator/` directory contains a Python tool that automates creating host-callable wrappers for Android libraries.

### Features

- **Symbol Extraction**: Uses Android NDK tools (`llvm-nm`, `llvm-readelf`) to extract exported symbols
- **Code Generation**: Generates C++ wrapper code using Jinja2 templates
- **Library Embedding**: Converts `.so` files to C byte arrays for embedding

### Usage

```bash
# Install the tool
cd wrapper_generator
pip install -e ".[dev]"

# Generate a wrapper
android-wrapper-generator \
    --library /path/to/libfoo.so \
    --output ./generated \
    --class-name FooWrapper
```

### Generated Output

```
generated/
├── foo_wrapper.h          # C++ header
├── foo_wrapper.cpp        # C++ implementation
├── libfoo.so.inc          # Embedded library data
└── CMakeLists.txt         # Build configuration
```

## Building

### Prerequisites

- CMake 3.20+
- C++20 compiler (GCC 10+ or Clang 12+)
- LIEF library
- GLib 2.0 (for QEMU)
- pkg-config

### Build Commands

```bash
# First build QEMU
cd scripts && ./build_qemu_libafl.sh && cd ..

# Then build the emulator
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=ON
make -j$(nproc)
```

### Build Outputs

| File | Type | Description |
|------|------|-------------|
| `libcross_shim.a` | Static | Core emulator library |
| `emu_test_runner` | Executable | Test harness |

## Test Suite

The emulator includes a comprehensive test suite with **760+ tests** across multiple categories:

| Test Suite | Tests | Description |
|------------|-------|-------------|
| String | 96 | strlen, strcpy, strcmp, strcat, strstr, strtok, etc. |
| Memory | 28 | malloc, calloc, realloc, free, mmap |
| STDIO | 53 | printf, sprintf, sscanf, fopen, fread, fwrite |
| STDLIB | 67 | atoi, strtol, qsort, bsearch, getenv |
| CTYPE | 70 | isalpha, isdigit, isspace, toupper, tolower |
| Time | 39 | time, gettimeofday, localtime, gmtime |
| Math | 139 | sin, cos, tan, sqrt, pow, log, exp, etc. |
| Networking | 70 | socket, connect, bind, send, recv, TCP loopback |
| Threading | 92 | pthread_create, pthread_join, mutex, condvar |
| Atomics | 24 | atomic_load, atomic_store, atomic_exchange |
| Directory | 41 | opendir, readdir, closedir, stat, mkdir |
| Wide Char | 23 | wcslen, wcscpy, wcscmp, wcscat |
| Pipe | 19 | pipe, dup, dup2, fcntl |
| Signal | 22 | sigemptyset, sigfillset, sigaddset, sigdelset |

### Running Tests

```bash
# Run emulator tests (requires Android NDK)
./test/run_emulator_tests.sh

# Run wrapper generator tests
cd wrapper_generator && ./run_tests.sh
```

## Debugging Tips

### Common Issues

1. **QEMU not found**: Run `scripts/build_qemu_libafl.sh` first

2. **Memory access errors**: Verify all memory regions are properly mapped

3. **Thread crashes**: Ensure TLS is properly initialized with TPIDR_EL0 and stack canary

4. **Relocation errors**: Mask LIEF relocation types with 0xFFFF to get the actual type

5. **Floating point in printf**: ARM64 passes floats in D0-D7 registers, not X registers

6. **sigset_t size**: On ARM64 Android, `sigset_t` is only 8 bytes, not 128 bytes

### Debug Output

Enable debug mode to see detailed output:

```cpp
emu.set_debug(true);
```

This enables:
- HLE function call tracing
- Memory access logging
- Thread creation/destruction logging
- Syscall tracing

### Thread-Safe Logging

All debug output uses the `EMU_LOG` macro from `debug_log.h` which provides mutex-protected logging to prevent output corruption from concurrent writes.
