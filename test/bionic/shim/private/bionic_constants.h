/*
 * Minimal shim for private/bionic_constants.h
 */

#pragma once

// Avoid redefining if already defined
#ifndef PTHREAD_STACK_MIN
#define PTHREAD_STACK_MIN 16384
#endif

// TLS constants
#define BIONIC_TLS_SLOTS 32

// Align
#define BIONIC_ALIGN(value, alignment) \
    (((value) + (alignment) - 1) & ~((alignment) - 1))

// Page size
#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

// Time constants
#ifndef NS_PER_S
#define NS_PER_S 1000000000LL
#endif

#ifndef US_PER_S
#define US_PER_S 1000000LL
#endif

#ifndef MS_PER_S
#define MS_PER_S 1000LL
#endif
