#ifndef DEBUG_LOG_H
#define DEBUG_LOG_H

/**
 * Thread-safe logging for CrossShim
 *
 * Use EMU_LOG instead of std::cerr for all debug output to prevent
 * stack smashing from concurrent writes across QEMU threads.
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

// Null stream that discards output
class NullStream {
public:
    template<typename T> NullStream& operator<<(const T&) { return *this; }
    NullStream& operator<<(std::ostream& (*)(std::ostream&)) { return *this; }
};

} // namespace emu

// Master logging switch - set to 1 to enable logging
#ifndef EMU_LOGGING_ENABLED
#define EMU_LOGGING_ENABLED 0  // Disabled by default for clean output
#endif

// Macro for thread-safe logging - use like std::cerr
#if EMU_LOGGING_ENABLED
#define EMU_LOG emu::LogStream()
#else
#define EMU_LOG emu::NullStream()
#endif

// Verbose logging - for high-frequency debug output
#ifndef EMU_VERBOSE_LOGGING
#define EMU_VERBOSE_LOGGING 0
#endif

#if EMU_VERBOSE_LOGGING
#define EMU_LOG_VERBOSE emu::LogStream()
#else
#define EMU_LOG_VERBOSE emu::NullStream()
#endif

#endif // DEBUG_LOG_H
