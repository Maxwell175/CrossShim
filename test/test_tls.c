/**
 * Test TLS access - verify TPIDR_EL0 is set up correctly
 */

#include <stdio.h>
#include <stdint.h>

/* Read TPIDR_EL0 directly */
static inline uint64_t read_tpidr(void) {
    uint64_t val;
    __asm__ __volatile__("mrs %0, tpidr_el0" : "=r"(val));
    return val;
}

/* Read stack guard from TLS */
static inline uint64_t read_stack_guard(void) {
    /* Stack guard is at TLS slot 5 (offset 40 from TLS base) */
    /* Or at offset 48 from TCB base */
    /* TPIDR_EL0 points to TLS_BASE + 8, so TLS_BASE = TPIDR_EL0 - 8 */
    uint64_t tpidr = read_tpidr();
    uint64_t tls_base = tpidr - 8;
    uint64_t *guard_ptr = (uint64_t *)(tls_base + 48);
    return *guard_ptr;
}

int main(void) {
    uint64_t tpidr = read_tpidr();
    uint64_t guard = read_stack_guard();

    printf("TLS Test\n");
    printf("TPIDR_EL0 = 0x%lx\n", tpidr);
    printf("Stack guard = 0x%lx\n", guard);

    if (tpidr == 0) {
        printf("FAIL: TPIDR_EL0 is zero!\n");
        return 1;
    }

    /* Expected guard value */
    if (guard == 0xDEADBEEFCAFEBABEULL) {
        printf("PASS: Stack guard is correct!\n");
        return 0;
    } else {
        printf("FAIL: Stack guard is wrong (expected 0xDEADBEEFCAFEBABE)\n");
        return 1;
    }
}
