#ifndef DEBUG_LOG_H
#define DEBUG_LOG_H

/**
 * Thread-safe logging for CrossShim
 *
 * Use EMU_LOG instead of std::cerr for all debug output to prevent
 * stack smashing from concurrent writes across QEMU threads.
 *
 * EMU_VERBOSE_LOGGING values:
 *   0 - Disabled (NullStream, no output)
 *   1 - Enabled with mutex (original LogStream)
 *   2 - Enabled WITHOUT mutex (UnlockedLogStream - for testing)
 */

#include <iostream>
#include <mutex>
#include <sstream>

namespace emu {

// Global mutex for synchronized logging
inline std::mutex& get_log_mutex() {
    static std::mutex log_mutex;
    return log_mutex;
}

// Thread-safe log stream that flushes on destruction (mutex-protected)
class LogStream {
public:
    LogStream() : lock_(get_log_mutex()) {}

    ~LogStream() {
        std::cerr << buffer_.str() << std::flush;
    }

    template<typename T>
    LogStream& operator<<(const T& value) {
        buffer_ << value;
        return *this;
    }

    // Handle std::endl and other manipulators
    LogStream& operator<<(std::ostream& (*manip)(std::ostream&)) {
        buffer_ << manip;
        return *this;
    }

private:
    std::lock_guard<std::mutex> lock_;
    std::ostringstream buffer_;
};

// Mutex-free log stream - ONLY does I/O, no synchronization
// Use this to test if it's the mutex or the I/O providing sync
class UnlockedLogStream {
public:
    UnlockedLogStream() {}

    ~UnlockedLogStream() {
        // Write and flush WITHOUT holding any mutex
        std::cerr << buffer_.str() << std::flush;
    }

    template<typename T>
    UnlockedLogStream& operator<<(const T& value) {
        buffer_ << value;
        return *this;
    }

    UnlockedLogStream& operator<<(std::ostream& (*manip)(std::ostream&)) {
        buffer_ << manip;
        return *this;
    }

private:
    std::ostringstream buffer_;
};

// Delay-only stream - NO I/O, just sched_yield() delay
// Use this to test if ANY delay works, or if I/O is specifically needed
class DelayOnlyStream {
public:
    DelayOnlyStream() {}

    ~DelayOnlyStream() {
        // No I/O, just yield CPU
        sched_yield();
    }

    template<typename T>
    DelayOnlyStream& operator<<(const T&) { return *this; }

    DelayOnlyStream& operator<<(std::ostream& (*)(std::ostream&)) { return *this; }
};

// Null stream that discards output
class NullStream {
public:
    template<typename T> NullStream& operator<<(const T&) { return *this; }
    NullStream& operator<<(std::ostream& (*)(std::ostream&)) { return *this; }
};

} // namespace emu

// Master logging switch - set to 0 to disable ALL logging
#ifndef EMU_LOGGING_ENABLED
#define EMU_LOGGING_ENABLED 0  // Disabled by default for clean output
#endif

// Macro for thread-safe logging - use like std::cerr
#if EMU_LOGGING_ENABLED
#define EMU_LOG emu::LogStream()
#else
#define EMU_LOG emu::NullStream()
#endif

// Verbose logging - can be disabled for performance
// Define EMU_VERBOSE_LOGGING:
//   0 - Disabled (NullStream, no output, no delay)
//   1 - Enabled with mutex (original LogStream)
//   2 - Enabled WITHOUT mutex (UnlockedLogStream - I/O only)
//   3 - Delay-only (sched_yield, no I/O)
#ifndef EMU_VERBOSE_LOGGING
#define EMU_VERBOSE_LOGGING 0  // Mode 0: Disabled (no logging overhead, pure MTTCG)
#endif

#if EMU_VERBOSE_LOGGING == 1
// Original mutex-protected verbose logging
#define EMU_LOG_VERBOSE emu::LogStream()
#elif EMU_VERBOSE_LOGGING == 2
// Mutex-free verbose logging - tests if I/O alone provides sync
#define EMU_LOG_VERBOSE emu::UnlockedLogStream()
#elif EMU_VERBOSE_LOGGING == 3
// Delay-only - sched_yield() but no I/O
#define EMU_LOG_VERBOSE emu::DelayOnlyStream()
#else
// Disabled - null stream
#define EMU_LOG_VERBOSE emu::NullStream()
#endif

#endif // DEBUG_LOG_H
