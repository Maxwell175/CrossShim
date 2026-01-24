/**
 * QEMU Stub Implementations
 *
 * This file provides stub implementations for QEMU symbols that are normally
 * provided by the full QEMU runtime but are not available in library mode.
 * These are primarily logging, tracing, and utility functions that we don't
 * actually need for emulation.
 */

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cstdarg>
#include <cstdio>

extern "C" {

// CPU info structure - minimal implementation
unsigned int cpuinfo = 0;

// QEMU log level (disabled)
int qemu_loglevel = 0;

// QEMU icache linesize
unsigned long qemu_icache_linesize = 64;

// Trace event states (disabled)
uint16_t _TRACE_GDBSTUB_OP_EXITING_DSTATE = 0;
uint16_t _TRACE_RESETTABLE_PHASE_EXIT_EXEC_DSTATE = 0;
uint32_t trace_events_enabled_count = 0;

// Logging functions - no-op
int qemu_log_trylock(void) { return 0; }
void qemu_log_unlock(void) {}
void qemu_log(const char* fmt, ...) {
    (void)fmt;
}
int qemu_log_in_addr_range(uint64_t addr) {
    (void)addr;
    return 0;
}
bool message_with_timestamp = false;
int qemu_get_thread_id(void) { return 0; }

// pstrcpy - safe string copy
char* pstrcpy(char* dest, int size, const char* src) {
    if (size <= 0) return dest;
    strncpy(dest, src, size - 1);
    dest[size - 1] = '\0';
    return dest;
}

// Interval tree functions - no-op for now
struct interval_tree_node;
struct rb_root_cached;

struct interval_tree_node* interval_tree_iter_first(
    struct rb_root_cached* root,
    unsigned long start,
    unsigned long last) {
    (void)root; (void)start; (void)last;
    return nullptr;
}

struct interval_tree_node* interval_tree_iter_next(
    struct interval_tree_node* node,
    unsigned long start,
    unsigned long last) {
    (void)node; (void)start; (void)last;
    return nullptr;
}

void interval_tree_insert(
    struct interval_tree_node* node,
    struct rb_root_cached* root) {
    (void)node; (void)root;
}

void interval_tree_remove(
    struct interval_tree_node* node,
    struct rb_root_cached* root) {
    (void)node; (void)root;
}

// Socket utilities - minimal implementations
void qemu_set_cloexec(int fd) { (void)fd; }
int socket_set_nodelay(int fd) { (void)fd; return 0; }
int socket_set_fast_reuse(int fd) { (void)fd; return 0; }

// Thread utilities
void qemu_kill_thread(void* thread) { (void)thread; }

// Error handling
void error_setg_internal(void** errp, const char* src, int line,
                         const char* func, const char* fmt, ...) {
    (void)errp; (void)src; (void)line; (void)func; (void)fmt;
}

// QAPI
int qapi_bool_parse(const char* name, const char* value, int* result, void** errp) {
    (void)name; (void)errp;
    if (strcmp(value, "true") == 0 || strcmp(value, "1") == 0 ||
        strcmp(value, "on") == 0 || strcmp(value, "yes") == 0) {
        *result = 1;
        return 0;
    }
    if (strcmp(value, "false") == 0 || strcmp(value, "0") == 0 ||
        strcmp(value, "off") == 0 || strcmp(value, "no") == 0) {
        *result = 0;
        return 0;
    }
    return -1;
}

// Additional trace event states
uint16_t _TRACE_BREAKPOINT_SINGLESTEP_DSTATE = 0;

// More logging/output functions
void qemu_printf(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

void qemu_log_separate(void) {}

// Error handling
void* error_fatal = nullptr;

void error_report(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "QEMU Error: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
}

// Timer/clock functions
int use_rt_clock = 1;
int64_t clock_start = 0;

// Replay (disabled)
void replay_finish(void) {}

// CRC32C implementation
uint32_t crc32c(uint32_t crc, const uint8_t* data, unsigned int length) {
    // Simple CRC32C implementation for ARM helper
    // This is a placeholder - full implementation needed for correct behavior
    static const uint32_t crc32c_table[256] = {
        // CRC32C polynomial table would go here
        // For now, return a simple XOR-based checksum
    };
    (void)crc32c_table;
    while (length--) {
        crc ^= *data++;
    }
    return crc;
}

// Random number generation
void qemu_guest_getrandom_nofail(void* buf, size_t len) {
    uint8_t* p = (uint8_t*)buf;
    for (size_t i = 0; i < len; i++) {
        p[i] = (uint8_t)(rand() & 0xff);
    }
}

void qemu_guest_random_seed_main(void* seed, size_t len) {
    (void)seed; (void)len;
}

// Environment list functions
void* envlist_create(void) { return nullptr; }
void envlist_setenv(void* list, const char* name, const char* value) {
    (void)list; (void)name; (void)value;
}
char** envlist_to_environ(void* list, size_t* count) {
    (void)list;
    if (count) *count = 0;
    return nullptr;
}
void envlist_free(void* list) { (void)list; }

// Trace functions
void* qemu_trace_opts = nullptr;
void qemu_add_opts(void* opts) { (void)opts; }
void qemu_set_log_filename_flags(const char* file, int flags) {
    (void)file; (void)flags;
}
void trace_init_backends(void) {}
void trace_init_file(void) {}
void trace_opt_parse(const char* str) { (void)str; }
void qemu_set_dfilter_ranges(const char* str, void** errp) {
    (void)str; (void)errp;
}

// Path functions
char* init_paths(const char* prefix, const char* exec_path) {
    (void)prefix; (void)exec_path;
    return nullptr;
}

// Auxiliary vector
uint64_t qemu_getauxval(unsigned long type) {
    (void)type;
    return 0;
}

// Error handling
void* error_abort = nullptr;
void error_reportf_err(void* err, const char* fmt, ...) {
    (void)err; (void)fmt;
}

// Size formatting
char* size_to_str(uint64_t size) {
    (void)size;
    static char buf[32];
    snprintf(buf, sizeof(buf), "%lu", (unsigned long)size);
    return buf;
}

// Mutex
void qemu_mutex_init(void* mutex) { (void)mutex; }

// Crypto
int qcrypto_init(void** errp) {
    (void)errp;
    return 0;
}

// More trace event states
uint16_t _TRACE_USER_QUEUE_SIGNAL_DSTATE = 0;
uint16_t _TRACE_USER_HOST_SIGNAL_DSTATE = 0;
uint16_t _TRACE_SIGNAL_DO_SIGACTION_HOST_DSTATE = 0;
uint16_t _TRACE_SIGNAL_DO_SIGACTION_GUEST_DSTATE = 0;

// String parsing
int qemu_strtoui(const char* nptr, char** endptr, int base, unsigned int* result) {
    *result = strtoul(nptr, endptr, base);
    return 0;
}

int qemu_strtoul(const char* nptr, char** endptr, int base, unsigned long* result) {
    *result = strtoul(nptr, endptr, base);
    return 0;
}

int qemu_str_to_log_mask(const char* str) {
    (void)str;
    return 0;
}

void qemu_print_log_usage(FILE* f) {
    (void)f;
}

void warn_report(const char* fmt, ...) {
    (void)fmt;
}

void envlist_unsetenv(void* list, const char* name) {
    (void)list; (void)name;
}

// Mutex functions
void qemu_mutex_lock_func(void* mutex, const char* file, int line) {
    (void)mutex; (void)file; (void)line;
}

void qemu_mutex_unlock_impl(void* mutex, const char* file, int line) {
    (void)mutex; (void)file; (void)line;
}

// Initialization functions
void error_init(const char* progname) {
    (void)progname;
}

void module_call_init(int type) {
    (void)type;
}

} // extern "C"
