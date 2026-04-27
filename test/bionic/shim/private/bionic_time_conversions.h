/*
 * Shim for bionic internal time conversion macros/functions
 */

#pragma once

#include <time.h>
#include <stdint.h>

#define NS_PER_S 1000000000LL
#define US_PER_S 1000000LL
#define MS_PER_S 1000LL

// Convert timespec to nanoseconds
static inline int64_t timespec_to_ns(const struct timespec& ts) {
    return static_cast<int64_t>(ts.tv_sec) * NS_PER_S + ts.tv_nsec;
}

// Convert nanoseconds to timespec
static inline struct timespec ns_to_timespec(int64_t ns) {
    struct timespec ts;
    ts.tv_sec = ns / NS_PER_S;
    ts.tv_nsec = ns % NS_PER_S;
    return ts;
}

// Convert timeval to timespec
static inline struct timespec timeval_to_timespec(const struct timeval& tv) {
    struct timespec ts;
    ts.tv_sec = tv.tv_sec;
    ts.tv_nsec = tv.tv_usec * 1000;
    return ts;
}

// Convert timespec to timeval
static inline struct timeval timespec_to_timeval(const struct timespec& ts) {
    struct timeval tv;
    tv.tv_sec = ts.tv_sec;
    tv.tv_usec = ts.tv_nsec / 1000;
    return tv;
}

// Add time to timespec
static inline bool timespec_add_relative(struct timespec* ts, int64_t ns) {
    ts->tv_nsec += ns % NS_PER_S;
    ts->tv_sec += ns / NS_PER_S;
    if (ts->tv_nsec >= NS_PER_S) {
        ts->tv_nsec -= NS_PER_S;
        ts->tv_sec++;
    }
    return true;
}

// Convert timeval to microseconds
static inline int64_t to_us(const struct timeval& tv) {
    return static_cast<int64_t>(tv.tv_sec) * US_PER_S + tv.tv_usec;
}

// Convert timespec to nanoseconds (for pthread tests)
static inline int64_t to_ns(const struct timespec& ts) {
    return static_cast<int64_t>(ts.tv_sec) * NS_PER_S + ts.tv_nsec;
}

// Check if timespec from CLOCK_REALTIME has elapsed
static inline bool timespec_from_absolute_timespec(struct timespec& rel,
                                                    const struct timespec& abs,
                                                    clockid_t clock_id) {
    struct timespec now;
    clock_gettime(clock_id, &now);

    rel.tv_sec = abs.tv_sec - now.tv_sec;
    rel.tv_nsec = abs.tv_nsec - now.tv_nsec;

    if (rel.tv_nsec < 0) {
        rel.tv_nsec += NS_PER_S;
        rel.tv_sec--;
    }

    // Return false if the time has already passed
    return !(rel.tv_sec < 0 || (rel.tv_sec == 0 && rel.tv_nsec < 0));
}
