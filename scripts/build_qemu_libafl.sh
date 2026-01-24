#!/bin/bash
# Build qemu-libafl-bridge for ARM64 usermode emulation
#
# This script clones and builds the qemu-libafl-bridge project
# which provides the QEMU backend with LibAFL instrumentation hooks.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ANDROID_LIB_EMU_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="${ANDROID_LIB_EMU_DIR}/external/qemu-libafl-bridge"
INSTALL_DIR="${ANDROID_LIB_EMU_DIR}/external/qemu-install"

echo "=== Building qemu-libafl-bridge for ARM64 usermode ==="
echo "Build directory: ${BUILD_DIR}"
echo "Install directory: ${INSTALL_DIR}"

# Create directories
mkdir -p "$(dirname "${BUILD_DIR}")"
mkdir -p "${INSTALL_DIR}"

# Clone or update repository
if [ -d "${BUILD_DIR}" ]; then
    echo "=== Updating existing qemu-libafl-bridge ==="
    cd "${BUILD_DIR}"
    # Reset any previous patches before pulling
    git checkout -- .
    git fetch origin
    git checkout main
    git pull origin main
else
    echo "=== Cloning qemu-libafl-bridge ==="
    git clone --depth 1 https://github.com/AFLplusplus/qemu-libafl-bridge.git "${BUILD_DIR}"
    cd "${BUILD_DIR}"
fi

# Apply patches for .NET CLR thread compatibility
# These patches prevent SIGSEGV crashes when signals are delivered to non-QEMU threads
# (e.g., .NET garbage collection threads) by adding NULL checks for thread_cpu
echo "=== Applying .NET compatibility patches ==="

PATCHES_DIR="${SCRIPT_DIR}/patches"

# Patch 1: linux-user/signal.c - Add NULL check in host_signal_handler
# This prevents crashes when signals are delivered to .NET runtime threads
if grep -q "If thread_cpu is NULL, this is a non-QEMU thread" "${BUILD_DIR}/linux-user/signal.c"; then
    echo "Patch 1 (signal.c): Already applied"
else
    echo "Applying patch 1: signal.c - NULL check in host_signal_handler"
    patch -p1 -d "${BUILD_DIR}" < "${PATCHES_DIR}/0001-null-check-signal-handler.patch"
fi

# Patch 2: accel/tcg/vcpu-state.h - Add NULL guard in get_task_state
# This prevents NULL pointer dereference when get_task_state is called with NULL cpu
if grep -q "Guard against NULL cpu" "${BUILD_DIR}/accel/tcg/vcpu-state.h"; then
    echo "Patch 2 (vcpu-state.h): Already applied"
else
    echo "Applying patch 2: vcpu-state.h - NULL guard in get_task_state"
    patch -p1 -d "${BUILD_DIR}" < "${PATCHES_DIR}/0002-null-check-get-task-state.patch"
fi

echo "=== Patches applied successfully ==="

# Check for required dependencies
echo "=== Checking dependencies ==="
MISSING_DEPS=""
for cmd in ninja meson pkg-config; do
    if ! command -v $cmd &> /dev/null; then
        MISSING_DEPS="${MISSING_DEPS} ${cmd}"
    fi
done

if [ -n "${MISSING_DEPS}" ]; then
    echo "Missing dependencies:${MISSING_DEPS}"
    echo "Please install them with your package manager:"
    echo "  Arch: sudo pacman -S ninja meson pkgconf"
    echo "  Ubuntu: sudo apt install ninja-build meson pkg-config"
    exit 1
fi

# Check for glib2
if ! pkg-config --exists glib-2.0; then
    echo "Missing glib-2.0 development files"
    echo "  Arch: sudo pacman -S glib2"
    echo "  Ubuntu: sudo apt install libglib2.0-dev"
    exit 1
fi

# Configure QEMU for ARM64 usermode with LibAFL support
echo "=== Configuring QEMU ==="

# Clean previous build if it exists
if [ -d "build" ]; then
    echo "Cleaning previous build..."
    rm -rf build
fi
mkdir -p build
cd build

# qemu-libafl-bridge already has LibAFL hooks built-in
# Configure for ARM64 usermode as a SHARED library
# --as-shared-lib: Build as shared library with AS_LIB=1 defined (enables libafl_qemu_init)
../configure \
    --target-list=aarch64-linux-user \
    --prefix="${INSTALL_DIR}" \
    --without-default-features \
    --enable-tcg \
    --as-shared-lib

# Build
echo "=== Building QEMU ==="
make -j$(nproc)

# Install
echo "=== Installing QEMU ==="
make install

# Copy the shared library to install directory
echo "=== Copying shared library ==="
cd "${BUILD_DIR}/build"

# Find and copy the shared library
if [ -f libqemu-aarch64-linux-user.so ]; then
    cp libqemu-aarch64-linux-user.so "${INSTALL_DIR}/lib/"
    echo "Copied libqemu-aarch64-linux-user.so"
elif [ -f qemu-aarch64 ]; then
    # Sometimes it builds as an executable with exported symbols
    cp qemu-aarch64 "${INSTALL_DIR}/lib/libqemu-aarch64-linux-user.so"
    echo "Copied qemu-aarch64 as shared library"
fi

# Verify the library has the required symbols
echo "Verifying libafl_qemu_init is exported..."
SO_FILE="${INSTALL_DIR}/lib/libqemu-aarch64-linux-user.so"
if [ -f "$SO_FILE" ]; then
    if nm -D "$SO_FILE" 2>/dev/null | grep -q "T libafl_qemu_init"; then
        echo "SUCCESS: libafl_qemu_init found in library"
    else
        echo "WARNING: libafl_qemu_init not found - AS_LIB may not have been set"
    fi

    if nm -D "$SO_FILE" 2>/dev/null | grep -q "T _libafl_qemu_user_init"; then
        echo "SUCCESS: _libafl_qemu_user_init found in library"
    else
        echo "WARNING: _libafl_qemu_user_init not found"
    fi
fi

echo ""
echo "=== Build complete ==="
echo "Shared library: ${INSTALL_DIR}/lib/libqemu-aarch64-linux-user.so"
echo ""
echo "Include paths:"
echo "  ${INSTALL_DIR}/include/libafl/"
echo "  ${INSTALL_DIR}/include/qemu/"
echo ""
echo "Key APIs available:"
echo "  libafl_qemu_init() - Initialize QEMU"
echo "  libafl_qemu_current_cpu() - Get current CPU"
echo "  libafl_qemu_read_reg/write_reg() - Register access"
echo "  libafl_add_pre_syscall_hook() - Hook syscalls"
echo "  target_mmap/target_munmap() - Memory mapping"
