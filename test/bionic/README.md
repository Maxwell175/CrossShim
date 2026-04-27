# Bionic Test Suite Integration

This directory contains infrastructure to build and run Android bionic libc tests
through the CrossShim emulator, providing upstream compliance validation.

## Structure

```
bionic/
  setup.sh              - Downloads bionic tests and googletest
  build.sh              - Builds tests with NDK for ARM64
  run.sh                - Runs tests through CrossShim
  shim/                 - Stub headers for Android-specific utilities
    utils.h             - Minimal test utilities
    gtest_globals.h     - Test globals
  tests/                - Downloaded bionic test sources (gitignored)
  googletest/           - Downloaded googletest (gitignored)
  build/                - Built test binaries (gitignored)
```

## Usage

```bash
# One-time setup (downloads sources)
./setup.sh

# Build all tests
./build.sh

# Run tests through CrossShim
./run.sh

# Run specific test
./run.sh string_test
```

## Approach

The bionic tests use Google Test (gtest) and some Android-specific utilities.
We provide minimal shim headers that stub out Android-specific functionality
while preserving the core test logic. This allows us to:

1. Use the actual bionic test source code
2. Compile with Android NDK for ARM64
3. Run through CrossShim emulator
4. Report compliance with upstream bionic

## Supported Tests

Currently buildable tests (minimal dependencies):
- ctype_test.cpp
- string_test.cpp (partial)
- stdlib_test.cpp (partial)
- math_test.cpp
- stdio_test.cpp (partial)
- time_test.cpp
- unistd_test.cpp (partial)

Tests requiring more complex stubs are work-in-progress.
