cmake_minimum_required(VERSION 3.20)
project(CrossShim VERSION 2.0.0 LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Enable position-independent code for all targets
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Find LIEF
find_package(LIEF REQUIRED)

# LibAFL QEMU backend
message(STATUS "Using LibAFL QEMU backend")

set(QEMU_INSTALL_DIR "${CMAKE_CURRENT_SOURCE_DIR}/external/qemu-install")

# Check if QEMU was built
if(NOT EXISTS "${QEMU_INSTALL_DIR}/lib/libqemu-aarch64.so")
    message(FATAL_ERROR "QEMU shared library not found. Run scripts/build_qemu_libafl.sh first.")
endif()

# QEMU shared library
set(QEMU_LIBRARY "${QEMU_INSTALL_DIR}/lib/libqemu-aarch64.so")

# QEMU include directories
set(QEMU_INCLUDE_DIRS
    "${QEMU_INSTALL_DIR}/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/external/qemu-libafl-bridge/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/external/qemu-libafl-bridge/build"
)

# Required system libraries for QEMU
find_package(PkgConfig REQUIRED)
pkg_check_modules(GLIB2 REQUIRED glib-2.0)

# Core emulator library sources
set(CROSS_SHIM_SOURCES
    src/emulator.cpp
    src/elf_loader.cpp
    src/memory_manager.cpp
    src/relocation_handler.cpp
    src/syscall_handler.cpp
    src/hle_libc.cpp
    src/hle_libm.cpp
    src/tls_manager.cpp
    src/thread_manager.cpp
    # NOTE: nonblocking_io.cpp removed - MTTCG uses direct blocking I/O
    # NOTE: atomic_handler.cpp removed - QEMU handles LSE atomics natively
    # NOTE: qemu_stubs.cpp moved to separate library for link order
    # Modular HLE implementations
    src/hle/hle_memory.cpp
    src/hle/hle_string.cpp
    src/hle/hle_mem_ops.cpp
    src/hle/hle_io.cpp
    src/hle/hle_file.cpp
    src/hle/hle_time.cpp
    src/hle/hle_network.cpp
    src/hle/hle_pthread.cpp
    src/hle/hle_misc.cpp
    src/hle/hle_math.cpp
    src/hle/hle_process.cpp
    src/hle/hle_dir.cpp
    src/hle/hle_syslog.cpp
    src/hle/hle_user.cpp
    src/hle/hle_crypto.cpp
)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Create static library
add_library(cross_shim STATIC ${CROSS_SHIM_SOURCES})

# Public include directories
target_include_directories(cross_shim PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

# QEMU backend includes and libraries
target_include_directories(cross_shim PRIVATE
    ${QEMU_INCLUDE_DIRS}
    ${GLIB2_INCLUDE_DIRS}
)

target_link_libraries(cross_shim PUBLIC
    LIEF::LIEF
    ${QEMU_LIBRARY}
    ${GLIB2_LIBRARIES}
    z
    rt
    m
    pthread
    OpenSSL::SSL
    OpenSSL::Crypto
)

# Set library properties
set_target_properties(cross_shim PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION 1
    PUBLIC_HEADER "include/cross_shim.h"
)

# Installation rules
include(GNUInstallDirs)

install(TARGETS cross_shim
    EXPORT CrossShimTargets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/cross_shim
)

# Install all headers
install(DIRECTORY include/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/cross_shim
    FILES_MATCHING PATTERN "*.h"
)

# Export targets
install(EXPORT CrossShimTargets
    FILE CrossShimTargets.cmake
    NAMESPACE CrossShim::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/CrossShim
)

# Create package config file
include(CMakePackageConfigHelpers)

configure_package_config_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/CrossShimConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/CrossShimConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/CrossShim
)

write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/CrossShimConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/CrossShimConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/CrossShimConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/CrossShim
)

# Standalone executable for running ARM64 binaries
add_executable(cross_shim_runner src/cross_shim_runner.cpp)
target_link_libraries(cross_shim_runner PRIVATE cross_shim)
set_target_properties(cross_shim_runner PROPERTIES
    OUTPUT_NAME cross_shim
    # Set RPATH so the executable can find libqemu-aarch64.so
    BUILD_RPATH "${QEMU_INSTALL_DIR}/lib"
    INSTALL_RPATH "${QEMU_INSTALL_DIR}/lib"
)

# Install the runner executable
install(TARGETS cross_shim_runner
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

# Option to enable CTest
option(BUILD_TESTS "Enable CTest integration" ON)

if(BUILD_TESTS)
    enable_testing()

    # Add a test that runs the emulator test suite
    # Note: This requires ARM64 test binaries to be built first via test/build_individual_tests.sh
    add_test(
        NAME emulator_tests
        COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/test/run_individual_tests.sh
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    )
endif()
