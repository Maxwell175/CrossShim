#ifndef DEBUG_LOG_H
#define DEBUG_LOG_H

/**
 * Thread-safe logging for CrossShim
 *
 * Use EMU_LOG instead of std::cerr for all debug output to prevent
 * stack smashing from concurrent writes across QEMU threads.
 */

#include <atomic>
#include <iostream>
#include <mutex>
#include <sstream>

namespace emu {

// Global mutex for synchronized logging
inline std::mutex& get_log_mutex() {
    static std::mutex log_mutex;
    return log_mutex;
}

inline std::atomic<bool>& debug_logging_enabled() {
    static std::atomic<bool> enabled{false};
    return enabled;
}

inline std::atomic<bool>& profile_logging_enabled() {
    static std::atomic<bool> enabled{false};
    return enabled;
}

inline void set_debug_logging_enabled(bool enabled) {
    debug_logging_enabled().store(enabled, std::memory_order_relaxed);
}

inline bool is_debug_logging_enabled() {
    return debug_logging_enabled().load(std::memory_order_relaxed);
}

inline void set_profile_logging_enabled(bool enabled) {
    profile_logging_enabled().store(enabled, std::memory_order_relaxed);
}

inline bool is_profile_logging_enabled() {
    return profile_logging_enabled().load(std::memory_order_relaxed);
}

// Thread-safe log stream that flushes on destruction (mutex-protected)
class ConditionalLogStream {
public:
    explicit ConditionalLogStream(bool enabled) : enabled_(enabled) {
        if (enabled_) {
            lock_ = std::unique_lock<std::mutex>(get_log_mutex());
        }
    }

    ~ConditionalLogStream() {
        if (enabled_) {
            std::cerr << buffer_.str() << std::flush;
        }
    }

    template<typename T>
    ConditionalLogStream& operator<<(const T& value) {
        if (enabled_) {
            buffer_ << value;
        }
        return *this;
    }

    // Handle std::endl and other manipulators
    ConditionalLogStream& operator<<(std::ostream& (*manip)(std::ostream&)) {
        if (enabled_) {
            buffer_ << manip;
        }
        return *this;
    }

private:
    bool enabled_;
    std::unique_lock<std::mutex> lock_;
    std::ostringstream buffer_;
};

// Null stream that discards output
class NullStream {
public:
    template<typename T> NullStream& operator<<(const T&) { return *this; }
    NullStream& operator<<(std::ostream& (*)(std::ostream&)) { return *this; }
};

} // namespace emu

// Master logging switch - set to 0 to compile out all CrossShim logging support
#ifndef EMU_LOGGING_ENABLED
#define EMU_LOGGING_ENABLED 1
#endif

// Regular debug logging - controlled at runtime by emu::set_debug_logging_enabled().
#if EMU_LOGGING_ENABLED
#define EMU_LOG emu::ConditionalLogStream(emu::is_debug_logging_enabled())
#define EMU_ALWAYS_LOG emu::ConditionalLogStream(true)
#define EMU_PROFILE_LOG emu::ConditionalLogStream(emu::is_profile_logging_enabled())
#else
#define EMU_LOG emu::NullStream()
#define EMU_ALWAYS_LOG emu::NullStream()
#define EMU_PROFILE_LOG emu::NullStream()
#endif

// Verbose logging - for high-frequency debug output
#ifndef EMU_VERBOSE_LOGGING
#define EMU_VERBOSE_LOGGING 0  // Disabled
#endif

#if EMU_VERBOSE_LOGGING
#define EMU_LOG_VERBOSE emu::ConditionalLogStream(emu::is_debug_logging_enabled())
#else
#define EMU_LOG_VERBOSE emu::NullStream()
#endif

#endif // DEBUG_LOG_H
