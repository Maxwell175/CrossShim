/*
 * Minimal shim for android-base/macros.h
 */

#pragma once

// Disallow copy and assign
#define DISALLOW_COPY_AND_ASSIGN(TypeName) \
    TypeName(const TypeName&) = delete;    \
    void operator=(const TypeName&) = delete

// Disallow implicit constructors
#define DISALLOW_IMPLICIT_CONSTRUCTORS(TypeName) \
    TypeName() = delete;                          \
    DISALLOW_COPY_AND_ASSIGN(TypeName)

// Array size
#ifndef arraysize
#define arraysize(array) (sizeof(array) / sizeof((array)[0]))
#endif

// Unused parameter
#define ATTRIBUTE_UNUSED __attribute__((__unused__))

// Printf format checking
#define ATTRIBUTE_PRINTF(format_idx, first_arg) \
    __attribute__((__format__(__printf__, format_idx, first_arg)))

// No return
#define ATTRIBUTE_NORETURN __attribute__((__noreturn__))

// Fallthrough for switch statements
#if __cplusplus >= 201703L
#define FALLTHROUGH_INTENDED [[fallthrough]]
#else
#define FALLTHROUGH_INTENDED [[clang::fallthrough]]
#endif

// Stringify macro
#define STRINGIFY(x) STRINGIFY_IMPL(x)
#define STRINGIFY_IMPL(x) #x

// Likely/unlikely branch hints
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
