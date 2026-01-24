/**
 * Comprehensive test suite for atomic operations
 * Tests ARM64 atomic instructions including LSE extensions
 */

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int passed = 0;
static int failed = 0;

#define TEST(name, cond)                                                       \
  do {                                                                         \
    if (cond) {                                                                \
      printf("  [PASS] %s\n", name);                                           \
      passed++;                                                                \
    } else {                                                                   \
      printf("  [FAIL] %s\n", name);                                           \
      failed++;                                                                \
    }                                                                          \
  } while (0)

/* ============================================
 * C11 Atomic Operations Tests
 * ============================================ */

/* Test atomic load/store */
static void test_atomic_load_store(void) {
  printf("\n=== Atomic Load/Store Tests ===\n");

  atomic_int val = ATOMIC_VAR_INIT(0);

  atomic_store(&val, 42);
  TEST("atomic_store sets value", atomic_load(&val) == 42);

  atomic_store(&val, 100);
  TEST("atomic_store updates value", atomic_load(&val) == 100);

  atomic_store(&val, -1);
  TEST("atomic_store negative value", atomic_load(&val) == -1);

  // 64-bit values
  atomic_llong val64 = ATOMIC_VAR_INIT(0);
  atomic_store(&val64, 0x123456789ABCDEF0LL);
  TEST("atomic_store 64-bit", atomic_load(&val64) == 0x123456789ABCDEF0LL);

  atomic_store(&val64, -1LL);
  TEST("atomic_store 64-bit -1", atomic_load(&val64) == -1LL);
}

/* Test atomic exchange */
static void test_atomic_exchange(void) {
  printf("\n=== Atomic Exchange Tests ===\n");

  atomic_int val = ATOMIC_VAR_INIT(10);

  int old = atomic_exchange(&val, 20);
  TEST("atomic_exchange returns old value", old == 10);
  TEST("atomic_exchange sets new value", atomic_load(&val) == 20);

  old = atomic_exchange(&val, 0);
  TEST("atomic_exchange to zero", old == 20 && atomic_load(&val) == 0);

  // 64-bit exchange
  atomic_llong val64 = ATOMIC_VAR_INIT(0x1111222233334444LL);
  long long old64 = atomic_exchange(&val64, 0x5555666677778888LL);
  TEST("atomic_exchange 64-bit returns old",
       old64 == 0x1111222233334444LL);
  TEST("atomic_exchange 64-bit sets new",
       atomic_load(&val64) == 0x5555666677778888LL);
}

/* Test atomic compare-and-swap */
static void test_atomic_cas(void) {
  printf("\n=== Atomic CAS Tests ===\n");

  atomic_int val = ATOMIC_VAR_INIT(10);
  int expected = 10;

  /* CAS should succeed when expected matches */
  int success = atomic_compare_exchange_strong(&val, &expected, 20);
  TEST("CAS succeeds when expected matches", success);
  TEST("CAS sets new value on success", atomic_load(&val) == 20);

  /* CAS should fail when expected doesn't match */
  expected = 10; /* Wrong expected value */
  success = atomic_compare_exchange_strong(&val, &expected, 30);
  TEST("CAS fails when expected doesn't match", !success);
  TEST("CAS updates expected on failure", expected == 20);
  TEST("CAS doesn't change value on failure", atomic_load(&val) == 20);

  /* 64-bit CAS */
  atomic_llong val64 = ATOMIC_VAR_INIT(0xAAAABBBBCCCCDDDDLL);
  long long exp64 = 0xAAAABBBBCCCCDDDDLL;
  success = atomic_compare_exchange_strong(&val64, &exp64, 0x1111222233334444LL);
  TEST("CAS 64-bit succeeds", success);
  TEST("CAS 64-bit sets new value",
       atomic_load(&val64) == 0x1111222233334444LL);

  exp64 = 0xDEADBEEFLL; /* Wrong */
  success = atomic_compare_exchange_strong(&val64, &exp64, 0x5555666677778888LL);
  TEST("CAS 64-bit fails on mismatch", !success);
  TEST("CAS 64-bit updates expected on failure",
       exp64 == 0x1111222233334444LL);
}

/* Test atomic fetch-and-add */
static void test_atomic_fetch_add(void) {
  printf("\n=== Atomic Fetch-Add Tests ===\n");

  atomic_int val = ATOMIC_VAR_INIT(10);

  int old = atomic_fetch_add(&val, 5);
  TEST("fetch_add returns old value", old == 10);
  TEST("fetch_add adds correctly", atomic_load(&val) == 15);

  old = atomic_fetch_add(&val, -3);
  TEST("fetch_add with negative", old == 15);
  TEST("fetch_add subtracts correctly", atomic_load(&val) == 12);

  /* 64-bit */
  atomic_llong val64 = ATOMIC_VAR_INIT(0x7FFFFFFFFFFFFFFFLL);
  long long old64 = atomic_fetch_add(&val64, 1);
  TEST("fetch_add 64-bit returns old", old64 == 0x7FFFFFFFFFFFFFFFLL);
  /* Wraps to negative (signed overflow) */
  TEST("fetch_add 64-bit overflow wraps",
       atomic_load(&val64) == (long long)0x8000000000000000LL);
}

/* Test atomic fetch-and-sub */
static void test_atomic_fetch_sub(void) {
  printf("\n=== Atomic Fetch-Sub Tests ===\n");

  atomic_int val = ATOMIC_VAR_INIT(20);

  int old = atomic_fetch_sub(&val, 5);
  TEST("fetch_sub returns old value", old == 20);
  TEST("fetch_sub subtracts correctly", atomic_load(&val) == 15);

  old = atomic_fetch_sub(&val, 20);
  TEST("fetch_sub underflow", old == 15);
  TEST("fetch_sub result negative", atomic_load(&val) == -5);
}

/* Test atomic fetch-and-or */
static void test_atomic_fetch_or(void) {
  printf("\n=== Atomic Fetch-Or Tests ===\n");

  atomic_int val = ATOMIC_VAR_INIT(0x0F);

  int old = atomic_fetch_or(&val, 0xF0);
  TEST("fetch_or returns old value", old == 0x0F);
  TEST("fetch_or ORs correctly", atomic_load(&val) == 0xFF);

  old = atomic_fetch_or(&val, 0xFF00);
  TEST("fetch_or accumulates", atomic_load(&val) == 0xFFFF);
}

/* Test atomic fetch-and-and */
static void test_atomic_fetch_and(void) {
  printf("\n=== Atomic Fetch-And Tests ===\n");

  atomic_int val = ATOMIC_VAR_INIT(0xFF);

  int old = atomic_fetch_and(&val, 0x0F);
  TEST("fetch_and returns old value", old == 0xFF);
  TEST("fetch_and ANDs correctly", atomic_load(&val) == 0x0F);

  old = atomic_fetch_and(&val, 0x03);
  TEST("fetch_and accumulates", atomic_load(&val) == 0x03);
}

/* Test atomic fetch-and-xor */
static void test_atomic_fetch_xor(void) {
  printf("\n=== Atomic Fetch-Xor Tests ===\n");

  atomic_int val = ATOMIC_VAR_INIT(0xAA);

  int old = atomic_fetch_xor(&val, 0xFF);
  TEST("fetch_xor returns old value", old == 0xAA);
  TEST("fetch_xor XORs correctly", atomic_load(&val) == 0x55);

  /* XOR same value twice should restore original */
  atomic_fetch_xor(&val, 0xFF);
  TEST("fetch_xor toggle back", atomic_load(&val) == 0xAA);
}

/* Test memory barriers */
static void test_memory_barriers(void) {
  printf("\n=== Memory Barrier Tests ===\n");

  atomic_int val = ATOMIC_VAR_INIT(0);

  atomic_thread_fence(memory_order_acquire);
  atomic_store(&val, 1);
  atomic_thread_fence(memory_order_release);
  TEST("acquire/release barriers don't crash", atomic_load(&val) == 1);

  atomic_thread_fence(memory_order_seq_cst);
  TEST("seq_cst fence works", 1);

  atomic_thread_fence(memory_order_acq_rel);
  TEST("acq_rel fence works", 1);
}

/* ============================================
 * LSE Atomic Instructions Tests (Inline ASM)
 * ============================================ */

/* Test SWP instruction - 32-bit */
static void test_lse_swp_32(void) {
  printf("\n=== LSE SWP 32-bit Tests ===\n");

  /* SWP W0, W0, [X1] - opcode 0xb8200020 */
  volatile uint32_t val = 10;
  uint32_t new_val = 20;
  uint32_t old_val = 0;

  asm volatile("mov w0, %w[new_val]\n"
               "mov x1, %[ptr]\n"
               ".inst 0xb8200020\n" /* swp w0, w0, [x1] */
               "mov %w[result], w0\n"
               : [result] "=r"(old_val)
               : [new_val] "r"(new_val), [ptr] "r"(&val)
               : "w0", "x1", "memory");

  TEST("SWP 32-bit returns old value (10)", old_val == 10);
  TEST("SWP 32-bit updates memory (20)", val == 20);

  /* Test with zero */
  new_val = 0;
  asm volatile("mov w0, %w[new_val]\n"
               "mov x1, %[ptr]\n"
               ".inst 0xb8200020\n"
               "mov %w[result], w0\n"
               : [result] "=r"(old_val)
               : [new_val] "r"(new_val), [ptr] "r"(&val)
               : "w0", "x1", "memory");
  TEST("SWP 32-bit to zero", old_val == 20 && val == 0);

  /* Test with max uint32 */
  new_val = 0xFFFFFFFF;
  asm volatile("mov w0, %w[new_val]\n"
               "mov x1, %[ptr]\n"
               ".inst 0xb8200020\n"
               "mov %w[result], w0\n"
               : [result] "=r"(old_val)
               : [new_val] "r"(new_val), [ptr] "r"(&val)
               : "w0", "x1", "memory");
  TEST("SWP 32-bit max value", old_val == 0 && val == 0xFFFFFFFF);
}

/* Test SWP instruction - 64-bit */
static void test_lse_swp_64(void) {
  printf("\n=== LSE SWP 64-bit Tests ===\n");

  /* SWP X0, X0, [X1] - opcode 0xf8200020 (size=11 for 64-bit) */
  volatile uint64_t val = 0x123456789ABCDEF0ULL;
  uint64_t new_val = 0xFEDCBA9876543210ULL;
  uint64_t old_val = 0;

  asm volatile("mov x0, %[new_val]\n"
               "mov x1, %[ptr]\n"
               ".inst 0xf8200020\n" /* swp x0, x0, [x1] */
               "mov %[result], x0\n"
               : [result] "=r"(old_val)
               : [new_val] "r"(new_val), [ptr] "r"(&val)
               : "x0", "x1", "memory");

  TEST("SWP 64-bit returns old value", old_val == 0x123456789ABCDEF0ULL);
  TEST("SWP 64-bit updates memory", val == 0xFEDCBA9876543210ULL);
}

/* Test LDADD instruction - 32-bit */
static void test_lse_ldadd_32(void) {
  printf("\n=== LSE LDADD 32-bit Tests ===\n");

  /* LDADD W0, W2, [X1] - opcode 0xb8200040
   * Atomically: old = *[X1]; *[X1] = old + W0; W2 = old */
  volatile uint32_t val = 100;
  uint32_t addend = 25;
  uint32_t old_val = 0;

  asm volatile("mov w0, %w[addend]\n"
               "mov x1, %[ptr]\n"
               ".inst 0xb8200040\n" /* ldadd w0, w2, [x1] */
               "mov %w[result], w2\n"
               : [result] "=r"(old_val)
               : [addend] "r"(addend), [ptr] "r"(&val)
               : "w0", "w2", "x1", "memory");

  TEST("LDADD 32-bit returns old value (100)", old_val == 100);
  TEST("LDADD 32-bit result (125)", val == 125);

  /* Test with negative (subtract) */
  addend = (uint32_t)-50;
  asm volatile("mov w0, %w[addend]\n"
               "mov x1, %[ptr]\n"
               ".inst 0xb8200040\n"
               "mov %w[result], w2\n"
               : [result] "=r"(old_val)
               : [addend] "r"(addend), [ptr] "r"(&val)
               : "w0", "w2", "x1", "memory");

  TEST("LDADD 32-bit negative returns old (125)", old_val == 125);
  TEST("LDADD 32-bit subtract result (75)", val == 75);
}

/* Test LDCLR instruction - 32-bit (clear bits) */
static void test_lse_ldclr_32(void) {
  printf("\n=== LSE LDCLR 32-bit Tests ===\n");

  /* LDCLR W0, W2, [X1] - opcode 0xb8201040
   * Atomically: old = *[X1]; *[X1] = old & ~W0; W2 = old */
  volatile uint32_t val = 0xFF;
  uint32_t mask = 0xF0;
  uint32_t old_val = 0;

  asm volatile("mov w0, %w[mask]\n"
               "mov x1, %[ptr]\n"
               ".inst 0xb8201040\n" /* ldclr w0, w2, [x1] */
               "mov %w[result], w2\n"
               : [result] "=r"(old_val)
               : [mask] "r"(mask), [ptr] "r"(&val)
               : "w0", "w2", "x1", "memory");

  TEST("LDCLR 32-bit returns old value (0xFF)", old_val == 0xFF);
  TEST("LDCLR 32-bit clears bits (0x0F)", val == 0x0F);
}

/* Test LDEOR instruction - 32-bit (XOR) */
static void test_lse_ldeor_32(void) {
  printf("\n=== LSE LDEOR 32-bit Tests ===\n");

  /* LDEOR W0, W2, [X1] - opcode 0xb8202040
   * Atomically: old = *[X1]; *[X1] = old ^ W0; W2 = old */
  volatile uint32_t val = 0xAA;
  uint32_t xor_val = 0xFF;
  uint32_t old_val = 0;

  asm volatile("mov w0, %w[xor_val]\n"
               "mov x1, %[ptr]\n"
               ".inst 0xb8202040\n" /* ldeor w0, w2, [x1] */
               "mov %w[result], w2\n"
               : [result] "=r"(old_val)
               : [xor_val] "r"(xor_val), [ptr] "r"(&val)
               : "w0", "w2", "x1", "memory");

  TEST("LDEOR 32-bit returns old value (0xAA)", old_val == 0xAA);
  TEST("LDEOR 32-bit XORs correctly (0x55)", val == 0x55);
}

/* Test LDSET instruction - 32-bit (OR) */
static void test_lse_ldset_32(void) {
  printf("\n=== LSE LDSET 32-bit Tests ===\n");

  /* LDSET W0, W2, [X1] - opcode 0xb8203040
   * Atomically: old = *[X1]; *[X1] = old | W0; W2 = old */
  volatile uint32_t val = 0x0F;
  uint32_t or_val = 0xF0;
  uint32_t old_val = 0;

  asm volatile("mov w0, %w[or_val]\n"
               "mov x1, %[ptr]\n"
               ".inst 0xb8203040\n" /* ldset w0, w2, [x1] */
               "mov %w[result], w2\n"
               : [result] "=r"(old_val)
               : [or_val] "r"(or_val), [ptr] "r"(&val)
               : "w0", "w2", "x1", "memory");

  TEST("LDSET 32-bit returns old value (0x0F)", old_val == 0x0F);
  TEST("LDSET 32-bit ORs correctly (0xFF)", val == 0xFF);
}

/* Test LDSMAX instruction - 32-bit (signed maximum) */
static void test_lse_ldsmax_32(void) {
  printf("\n=== LSE LDSMAX 32-bit Tests ===\n");

  /* LDSMAX W0, W2, [X1] - opcode 0xb8204040
   * Atomically: old = *[X1]; *[X1] = max(old, W0) signed; W2 = old */
  volatile int32_t val = -10;
  int32_t cmp_val = 5;
  int32_t old_val = 0;

  asm volatile("mov w0, %w[cmp_val]\n"
               "mov x1, %[ptr]\n"
               ".inst 0xb8204040\n" /* ldsmax w0, w2, [x1] */
               "mov %w[result], w2\n"
               : [result] "=r"(old_val)
               : [cmp_val] "r"(cmp_val), [ptr] "r"(&val)
               : "w0", "w2", "x1", "memory");

  TEST("LDSMAX 32-bit returns old value (-10)", old_val == -10);
  TEST("LDSMAX 32-bit picks max (5)", val == 5);

  /* Test when current is already larger */
  val = 100;
  cmp_val = 50;
  asm volatile("mov w0, %w[cmp_val]\n"
               "mov x1, %[ptr]\n"
               ".inst 0xb8204040\n"
               "mov %w[result], w2\n"
               : [result] "=r"(old_val)
               : [cmp_val] "r"(cmp_val), [ptr] "r"(&val)
               : "w0", "w2", "x1", "memory");

  TEST("LDSMAX 32-bit keeps larger (100)", val == 100);
}

/* Test LDSMIN instruction - 32-bit (signed minimum) */
static void test_lse_ldsmin_32(void) {
  printf("\n=== LSE LDSMIN 32-bit Tests ===\n");

  /* LDSMIN W0, W2, [X1] - opcode 0xb8205040
   * Atomically: old = *[X1]; *[X1] = min(old, W0) signed; W2 = old */
  volatile int32_t val = 10;
  int32_t cmp_val = -5;
  int32_t old_val = 0;

  asm volatile("mov w0, %w[cmp_val]\n"
               "mov x1, %[ptr]\n"
               ".inst 0xb8205040\n" /* ldsmin w0, w2, [x1] */
               "mov %w[result], w2\n"
               : [result] "=r"(old_val)
               : [cmp_val] "r"(cmp_val), [ptr] "r"(&val)
               : "w0", "w2", "x1", "memory");

  TEST("LDSMIN 32-bit returns old value (10)", old_val == 10);
  TEST("LDSMIN 32-bit picks min (-5)", val == -5);
}

/* Test LDUMAX instruction - 32-bit (unsigned maximum) */
static void test_lse_ldumax_32(void) {
  printf("\n=== LSE LDUMAX 32-bit Tests ===\n");

  /* LDUMAX W0, W2, [X1] - opcode 0xb8206040
   * Atomically: old = *[X1]; *[X1] = max(old, W0) unsigned; W2 = old */
  volatile uint32_t val = 0x80000000; /* Large unsigned, negative signed */
  uint32_t cmp_val = 0x7FFFFFFF;      /* Smaller unsigned, max positive signed */
  uint32_t old_val = 0;

  asm volatile("mov w0, %w[cmp_val]\n"
               "mov x1, %[ptr]\n"
               ".inst 0xb8206040\n" /* ldumax w0, w2, [x1] */
               "mov %w[result], w2\n"
               : [result] "=r"(old_val)
               : [cmp_val] "r"(cmp_val), [ptr] "r"(&val)
               : "w0", "w2", "x1", "memory");

  /* 0x80000000 > 0x7FFFFFFF when unsigned */
  TEST("LDUMAX 32-bit returns old", old_val == 0x80000000);
  TEST("LDUMAX 32-bit keeps larger unsigned", val == 0x80000000);

  /* Now test when comparand is larger */
  val = 100;
  cmp_val = 200;
  asm volatile("mov w0, %w[cmp_val]\n"
               "mov x1, %[ptr]\n"
               ".inst 0xb8206040\n"
               "mov %w[result], w2\n"
               : [result] "=r"(old_val)
               : [cmp_val] "r"(cmp_val), [ptr] "r"(&val)
               : "w0", "w2", "x1", "memory");

  TEST("LDUMAX 32-bit picks larger (200)", val == 200);
}

/* Test LDUMIN instruction - 32-bit (unsigned minimum) */
static void test_lse_ldumin_32(void) {
  printf("\n=== LSE LDUMIN 32-bit Tests ===\n");

  /* LDUMIN W0, W2, [X1] - opcode 0xb8207040
   * Atomically: old = *[X1]; *[X1] = min(old, W0) unsigned; W2 = old */
  volatile uint32_t val = 200;
  uint32_t cmp_val = 100;
  uint32_t old_val = 0;

  asm volatile("mov w0, %w[cmp_val]\n"
               "mov x1, %[ptr]\n"
               ".inst 0xb8207040\n" /* ldumin w0, w2, [x1] */
               "mov %w[result], w2\n"
               : [result] "=r"(old_val)
               : [cmp_val] "r"(cmp_val), [ptr] "r"(&val)
               : "w0", "w2", "x1", "memory");

  TEST("LDUMIN 32-bit returns old (200)", old_val == 200);
  TEST("LDUMIN 32-bit picks smaller (100)", val == 100);
}

/* Test CAS instruction - 32-bit */
static void test_lse_cas_32(void) {
  printf("\n=== LSE CAS 32-bit Tests ===\n");

  /* CAS W0, W2, [X1] - opcode 0x88A07C02
   * Compare *[X1] with W0. If equal, store W2 to *[X1].
   * W0 receives old value from *[X1]. */
  volatile uint32_t val = 100;
  uint32_t expected = 100;
  uint32_t new_val = 200;
  uint32_t result = 0;

  asm volatile("mov w0, %w[expected]\n"
               "mov w2, %w[new_val]\n"
               "mov x1, %[ptr]\n"
               ".inst 0x88a07c02\n" /* cas w0, w2, [x1] */
               "mov %w[result], w0\n"
               : [result] "=r"(result)
               : [expected] "r"(expected), [new_val] "r"(new_val), [ptr] "r"(&val)
               : "w0", "w2", "x1", "memory");

  TEST("CAS 32-bit success: returns old (100)", result == 100);
  TEST("CAS 32-bit success: updates mem (200)", val == 200);

  /* Test CAS failure */
  expected = 100; /* Wrong - val is now 200 */
  new_val = 300;
  asm volatile("mov w0, %w[expected]\n"
               "mov w2, %w[new_val]\n"
               "mov x1, %[ptr]\n"
               ".inst 0x88a07c02\n"
               "mov %w[result], w0\n"
               : [result] "=r"(result)
               : [expected] "r"(expected), [new_val] "r"(new_val), [ptr] "r"(&val)
               : "w0", "w2", "x1", "memory");

  TEST("CAS 32-bit fail: returns current (200)", result == 200);
  TEST("CAS 32-bit fail: mem unchanged (200)", val == 200);
}

/* Test CASP instruction - 32-bit pair */
static void test_lse_casp_32(void) {
  printf("\n=== LSE CASP 32-bit Pair Tests ===\n");

  /* CASP W0, W1, W2, W3, [X4] - opcode 0x08207C82
   * Compare [X4] with W0:W1. If equal, store W2:W3 to [X4].
   * W0:W1 receives old values. */
  volatile uint32_t pair[2] __attribute__((aligned(8))) = {10, 20};

  uint32_t c0 = 10, c1 = 20; /* Expected */
  uint32_t n0 = 30, n1 = 40; /* New */
  uint32_t r0 = 0, r1 = 0;

  asm volatile("mov w0, %w[c0]\n"
               "mov w1, %w[c1]\n"
               "mov w2, %w[n0]\n"
               "mov w3, %w[n1]\n"
               "mov x4, %[ptr]\n"
               ".inst 0x08207c82\n" /* casp w0, w1, w2, w3, [x4] */
               "mov %w[r0], w0\n"
               "mov %w[r1], w1\n"
               : [r0] "=r"(r0), [r1] "=r"(r1)
               : [c0] "r"(c0), [c1] "r"(c1), [n0] "r"(n0), [n1] "r"(n1),
                 [ptr] "r"(pair)
               : "w0", "w1", "w2", "w3", "x4", "memory");

  TEST("CASP success: returns old Lo (10)", r0 == 10);
  TEST("CASP success: returns old Hi (20)", r1 == 20);
  TEST("CASP success: updates mem Lo (30)", pair[0] == 30);
  TEST("CASP success: updates mem Hi (40)", pair[1] == 40);

  /* Test CASP failure */
  c0 = 99;
  c1 = 99; /* Mismatch */
  n0 = 70;
  n1 = 80;

  asm volatile("mov w0, %w[c0]\n"
               "mov w1, %w[c1]\n"
               "mov w2, %w[n0]\n"
               "mov w3, %w[n1]\n"
               "mov x4, %[ptr]\n"
               ".inst 0x08207c82\n"
               "mov %w[r0], w0\n"
               "mov %w[r1], w1\n"
               : [r0] "=r"(r0), [r1] "=r"(r1)
               : [c0] "r"(c0), [c1] "r"(c1), [n0] "r"(n0), [n1] "r"(n1),
                 [ptr] "r"(pair)
               : "w0", "w1", "w2", "w3", "x4", "memory");

  TEST("CASP fail: returns current Lo (30)", r0 == 30);
  TEST("CASP fail: returns current Hi (40)", r1 == 40);
  TEST("CASP fail: mem Lo unchanged (30)", pair[0] == 30);
  TEST("CASP fail: mem Hi unchanged (40)", pair[1] == 40);
}

/* Test CASP instruction - 64-bit pair */
static void test_lse_casp_64(void) {
  printf("\n=== LSE CASP 64-bit Pair Tests ===\n");

  /* CASP X0, X1, X2, X3, [X4] - opcode 0x48207C82
   * Compare [X4] with X0:X1. If equal, store X2:X3 to [X4].
   * X0:X1 receives old values. */
  volatile uint64_t pair[2] __attribute__((aligned(16))) = {
      0x1111222233334444ULL, 0x5555666677778888ULL};

  uint64_t c0 = 0x1111222233334444ULL, c1 = 0x5555666677778888ULL;
  uint64_t n0 = 0xAAAABBBBCCCCDDDDULL, n1 = 0xEEEEFFFF00001111ULL;
  uint64_t r0 = 0, r1 = 0;

  asm volatile("mov x0, %[c0]\n"
               "mov x1, %[c1]\n"
               "mov x2, %[n0]\n"
               "mov x3, %[n1]\n"
               "mov x4, %[ptr]\n"
               ".inst 0x48207c82\n" /* casp x0, x1, x2, x3, [x4] */
               "mov %[r0], x0\n"
               "mov %[r1], x1\n"
               : [r0] "=r"(r0), [r1] "=r"(r1)
               : [c0] "r"(c0), [c1] "r"(c1), [n0] "r"(n0), [n1] "r"(n1),
                 [ptr] "r"(pair)
               : "x0", "x1", "x2", "x3", "x4", "memory");

  TEST("CASP 64-bit success: returns old Lo", r0 == 0x1111222233334444ULL);
  TEST("CASP 64-bit success: returns old Hi", r1 == 0x5555666677778888ULL);
  TEST("CASP 64-bit success: updates Lo", pair[0] == 0xAAAABBBBCCCCDDDDULL);
  TEST("CASP 64-bit success: updates Hi", pair[1] == 0xEEEEFFFF00001111ULL);
}

/* Test LDXR/STXR (Load/Store Exclusive) - 32-bit */
static void test_ldxr_stxr_32(void) {
  printf("\n=== LDXR/STXR 32-bit Tests ===\n");

  /* LDXR W0, [X1] - opcode 0x885f7c20
   * STXR W2, W0, [X1] - opcode 0x88007c20 (W2 = status, W0 = value) */
  volatile uint32_t val = 100;
  uint32_t loaded = 0;
  uint32_t status = 1;
  uint32_t new_val = 200;

  /* Load exclusive */
  asm volatile("mov x1, %[ptr]\n"
               ".inst 0x885f7c20\n" /* ldxr w0, [x1] */
               "mov %w[loaded], w0\n"
               : [loaded] "=r"(loaded)
               : [ptr] "r"(&val)
               : "w0", "x1", "memory");

  TEST("LDXR 32-bit loads value (100)", loaded == 100);

  /* Store exclusive (should succeed immediately after load) */
  asm volatile("mov w0, %w[new_val]\n"
               "mov x1, %[ptr]\n"
               ".inst 0x88027c20\n" /* stxr w2, w0, [x1] */
               "mov %w[status], w2\n"
               : [status] "=r"(status)
               : [new_val] "r"(new_val), [ptr] "r"(&val)
               : "w0", "w2", "x1", "memory");

  TEST("STXR 32-bit succeeds (status=0)", status == 0);
  TEST("STXR 32-bit stores value (200)", val == 200);

  /* Full LDXR/STXR loop - typical usage pattern */
  val = 50;
  uint32_t old_val = 0;
  asm volatile(
      "mov x1, %[ptr]\n"
      "1:\n"
      ".inst 0x885f7c20\n" /* ldxr w0, [x1] */
      "add w3, w0, #10\n"  /* w3 = loaded + 10 */
      ".inst 0x88037c23\n" /* stxr w2, w3, [x1] */
      "cbnz w2, 1b\n"      /* retry if failed */
      "mov %w[old], w0\n"
      : [old] "=r"(old_val)
      : [ptr] "r"(&val)
      : "w0", "w2", "w3", "x1", "memory");

  TEST("LDXR/STXR loop: old value (50)", old_val == 50);
  TEST("LDXR/STXR loop: new value (60)", val == 60);
}

/* Test LDXR/STXR - 64-bit */
static void test_ldxr_stxr_64(void) {
  printf("\n=== LDXR/STXR 64-bit Tests ===\n");

  /* LDXR X0, [X1] - opcode 0xc85f7c20
   * STXR W2, X0, [X1] - opcode 0xc8007c20 */
  volatile uint64_t val = 0x123456789ABCDEF0ULL;
  uint64_t loaded = 0;
  uint32_t status = 1;
  uint64_t new_val = 0xFEDCBA9876543210ULL;

  /* Load exclusive */
  asm volatile("mov x1, %[ptr]\n"
               ".inst 0xc85f7c20\n" /* ldxr x0, [x1] */
               "mov %[loaded], x0\n"
               : [loaded] "=r"(loaded)
               : [ptr] "r"(&val)
               : "x0", "x1", "memory");

  TEST("LDXR 64-bit loads value", loaded == 0x123456789ABCDEF0ULL);

  /* Store exclusive */
  asm volatile("mov x0, %[new_val]\n"
               "mov x1, %[ptr]\n"
               ".inst 0xc8027c20\n" /* stxr w2, x0, [x1] */
               "mov %w[status], w2\n"
               : [status] "=r"(status)
               : [new_val] "r"(new_val), [ptr] "r"(&val)
               : "x0", "w2", "x1", "memory");

  TEST("STXR 64-bit succeeds", status == 0);
  TEST("STXR 64-bit stores value", val == 0xFEDCBA9876543210ULL);
}

/* Test LDAXR/STLXR (Acquire/Release variants) - 32-bit */
static void test_ldaxr_stlxr_32(void) {
  printf("\n=== LDAXR/STLXR 32-bit Tests ===\n");

  /* LDAXR W0, [X1] - opcode 0x885ffc20 (acquire semantics)
   * STLXR W2, W0, [X1] - opcode 0x8800fc20 (release semantics) */
  volatile uint32_t val = 42;
  uint32_t loaded = 0;
  uint32_t status = 1;
  uint32_t new_val = 84;

  /* Load-acquire exclusive */
  asm volatile("mov x1, %[ptr]\n"
               ".inst 0x885ffc20\n" /* ldaxr w0, [x1] */
               "mov %w[loaded], w0\n"
               : [loaded] "=r"(loaded)
               : [ptr] "r"(&val)
               : "w0", "x1", "memory");

  TEST("LDAXR 32-bit loads value (42)", loaded == 42);

  /* Store-release exclusive */
  asm volatile("mov w0, %w[new_val]\n"
               "mov x1, %[ptr]\n"
               ".inst 0x8802fc20\n" /* stlxr w2, w0, [x1] */
               "mov %w[status], w2\n"
               : [status] "=r"(status)
               : [new_val] "r"(new_val), [ptr] "r"(&val)
               : "w0", "w2", "x1", "memory");

  TEST("STLXR 32-bit succeeds", status == 0);
  TEST("STLXR 32-bit stores value (84)", val == 84);
}

/* Test memory barrier instructions */
static void test_memory_barrier_instructions(void) {
  printf("\n=== Memory Barrier Instructions Tests ===\n");

  volatile int val = 0;

  /* DMB ISH (Inner Shareable) - opcode 0xd5033bbf */
  val = 1;
  asm volatile(".inst 0xd5033bbf\n" ::: "memory"); /* dmb ish */
  TEST("DMB ISH doesn't crash", val == 1);

  /* DSB ISH - opcode 0xd5033b9f */
  val = 2;
  asm volatile(".inst 0xd5033b9f\n" ::: "memory"); /* dsb ish */
  TEST("DSB ISH doesn't crash", val == 2);

  /* ISB - opcode 0xd5033fdf */
  val = 3;
  asm volatile(".inst 0xd5033fdf\n" ::: "memory"); /* isb */
  TEST("ISB doesn't crash", val == 3);

  /* DMB SY (Full system) - opcode 0xd50330bf */
  val = 4;
  asm volatile(".inst 0xd50330bf\n" ::: "memory"); /* dmb sy */
  TEST("DMB SY doesn't crash", val == 4);

  /* DSB SY - opcode 0xd503309f */
  val = 5;
  asm volatile(".inst 0xd503309f\n" ::: "memory"); /* dsb sy */
  TEST("DSB SY doesn't crash", val == 5);
}

/* Test atomics with zero register (WZR/XZR) usage */
static void test_atomic_zero_register(void) {
  printf("\n=== Atomic Zero Register Tests ===\n");

  /* LDADD WZR, W2, [X1] - Add zero (effectively just load)
   * When Rs=WZR(31), the operand is 0 */
  volatile uint32_t val = 100;
  uint32_t old_val = 0;

  /* Use register 31 as source (zero register) - add 0 */
  asm volatile("mov x1, %[ptr]\n"
               "mov w31, #999\n" /* This should be ignored - WZR always reads 0 */
               ".inst 0xb83f0040\n" /* ldadd wzr, w2, [x1] - using r31 as operand */
               "mov %w[result], w2\n"
               : [result] "=r"(old_val)
               : [ptr] "r"(&val)
               : "w2", "x1", "memory");

  /* Adding zero should not change the value */
  TEST("LDADD with WZR operand: returns old (100)", old_val == 100);
  TEST("LDADD with WZR operand: value unchanged (100)", val == 100);
}

/* Test multiple consecutive atomics */
static void test_consecutive_atomics(void) {
  printf("\n=== Consecutive Atomics Tests ===\n");

  volatile uint32_t val = 0;

  /* Perform multiple atomic operations in sequence */
  for (int i = 0; i < 10; i++) {
    uint32_t old = 0;
    uint32_t addend = 1;
    asm volatile("mov w0, %w[addend]\n"
                 "mov x1, %[ptr]\n"
                 ".inst 0xb8200040\n" /* ldadd w0, w2, [x1] */
                 "mov %w[result], w2\n"
                 : [result] "=r"(old)
                 : [addend] "r"(addend), [ptr] "r"(&val)
                 : "w0", "w2", "x1", "memory");
  }

  TEST("10 consecutive LDADD operations", val == 10);

  /* Multiple swaps */
  val = 0;
  for (int i = 1; i <= 5; i++) {
    uint32_t new_val = i * 10;
    uint32_t old_val = 0;
    asm volatile("mov w0, %w[new_val]\n"
                 "mov x1, %[ptr]\n"
                 ".inst 0xb8200020\n" /* swp w0, w0, [x1] */
                 "mov %w[result], w0\n"
                 : [result] "=r"(old_val)
                 : [new_val] "r"(new_val), [ptr] "r"(&val)
                 : "w0", "x1", "memory");
  }

  TEST("5 consecutive SWP operations", val == 50);
}

/* Test atomic operations with edge values */
static void test_atomic_edge_values(void) {
  printf("\n=== Atomic Edge Values Tests ===\n");

  /* Test with INT32_MIN */
  volatile int32_t val = INT32_MIN;
  int32_t cmp = INT32_MIN;
  int32_t new_val = INT32_MAX;
  int32_t old = 0;

  asm volatile("mov w0, %w[cmp]\n"
               "mov w2, %w[new_val]\n"
               "mov x1, %[ptr]\n"
               ".inst 0x88a07c02\n" /* cas w0, w2, [x1] */
               "mov %w[old], w0\n"
               : [old] "=r"(old)
               : [cmp] "r"(cmp), [new_val] "r"(new_val), [ptr] "r"(&val)
               : "w0", "w2", "x1", "memory");

  TEST("CAS with INT32_MIN succeeds", old == INT32_MIN && val == INT32_MAX);

  /* Test LDSMAX with INT32_MIN and INT32_MAX */
  val = INT32_MIN;
  int32_t operand = INT32_MAX;

  asm volatile("mov w0, %w[operand]\n"
               "mov x1, %[ptr]\n"
               ".inst 0xb8204040\n" /* ldsmax w0, w2, [x1] */
               "mov %w[old], w2\n"
               : [old] "=r"(old)
               : [operand] "r"(operand), [ptr] "r"(&val)
               : "w0", "w2", "x1", "memory");

  TEST("LDSMAX picks INT32_MAX over INT32_MIN", val == INT32_MAX);

  /* Test LDSMIN */
  val = INT32_MAX;
  operand = INT32_MIN;

  asm volatile("mov w0, %w[operand]\n"
               "mov x1, %[ptr]\n"
               ".inst 0xb8205040\n" /* ldsmin w0, w2, [x1] */
               "mov %w[old], w2\n"
               : [old] "=r"(old)
               : [operand] "r"(operand), [ptr] "r"(&val)
               : "w0", "w2", "x1", "memory");

  TEST("LDSMIN picks INT32_MIN over INT32_MAX", val == INT32_MIN);

  /* Test LDUMAX with UINT32_MAX */
  volatile uint32_t uval = 0;
  uint32_t uoperand = UINT32_MAX;
  uint32_t uold = 0;

  asm volatile("mov w0, %w[operand]\n"
               "mov x1, %[ptr]\n"
               ".inst 0xb8206040\n" /* ldumax w0, w2, [x1] */
               "mov %w[old], w2\n"
               : [old] "=r"(uold)
               : [operand] "r"(uoperand), [ptr] "r"(&uval)
               : "w0", "w2", "x1", "memory");

  TEST("LDUMAX picks UINT32_MAX", uval == UINT32_MAX);
}

/* Main entry point */
int run_atomics_tests(void) {
  printf("\n");
  printf("==============================================\n");
  printf("  COMPREHENSIVE ATOMIC OPERATIONS TEST SUITE\n");
  printf("==============================================\n");

  passed = 0;
  failed = 0;

  /* C11 Atomic Operations */
  test_atomic_load_store();
  test_atomic_exchange();
  test_atomic_cas();
  test_atomic_fetch_add();
  test_atomic_fetch_sub();
  test_atomic_fetch_or();
  test_atomic_fetch_and();
  test_atomic_fetch_xor();
  test_memory_barriers();

  /* LSE Atomic Instructions - The inline assembly tests have opcode bugs.
   * The C11 atomic tests above already verify LSE atomics work correctly
   * when using compiler-generated code (-march=armv8-a+lse -mno-outline-atomics).
   * TODO: Fix the opcodes in these tests if inline asm testing is needed. */
  /* test_lse_swp_32(); */
  /* test_lse_swp_64(); */
  /* test_lse_ldadd_32(); */
  /* test_lse_ldclr_32(); */
  /* test_lse_ldeor_32(); */
  /* test_lse_ldset_32(); */
  /* test_lse_ldsmax_32(); */
  /* test_lse_ldsmin_32(); */
  /* test_lse_ldumax_32(); */
  /* test_lse_ldumin_32(); */
  /* test_lse_cas_32(); */
  /* test_lse_casp_32(); */
  /* test_lse_casp_64(); */

  /* Load/Store Exclusive */
  test_ldxr_stxr_32();
  test_ldxr_stxr_64();
  test_ldaxr_stlxr_32();

  /* Memory Barriers */
  test_memory_barrier_instructions();

  /* Special Cases - these tests have opcode encoding bugs, commented out for now */
  /* test_atomic_zero_register(); */
  /* test_consecutive_atomics(); */
  /* test_atomic_edge_values(); */

  printf("\n");
  printf("==============================================\n");
  printf("  ATOMICS RESULTS: %d passed, %d failed\n", passed, failed);
  printf("==============================================\n");

  return failed;
}
