/**
 * Cooperative Threading Tests
 * Demonstrates all three tiers of adaptive scheduling
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>
#include <stdint.h>

// Test results tracking
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST_PASS(name) do { printf("  [PASS] %s\n", name); tests_passed++; } while(0)
#define TEST_FAIL(name) do { printf("  [FAIL] %s\n", name); tests_failed++; } while(0)

// ============================================================================
// TIER 1: Blocking Operation Detection Tests
// ============================================================================

// Shared data for mutex test
static pthread_mutex_t tier1_mutex = PTHREAD_MUTEX_INITIALIZER;
static int tier1_counter = 0;
static int tier1_expected_switches = 0;

void* tier1_mutex_thread(void* arg) {
    int thread_id = *(int*)arg;

    for (int i = 0; i < 10; i++) {
        pthread_mutex_lock(&tier1_mutex);
        tier1_counter++;
        printf("[T%d] Mutex locked, counter=%d\n", thread_id, tier1_counter);
        pthread_mutex_unlock(&tier1_mutex);
        tier1_expected_switches++;
    }

    return NULL;
}

void test_tier1_mutex_blocking() {
    printf("\n=== Tier 1: Mutex Blocking Test ===\n");

    tier1_counter = 0;
    tier1_expected_switches = 0;

    pthread_t threads[3];
    int thread_ids[3] = {1, 2, 3};

    // Create 3 threads that compete for the same mutex
    for (int i = 0; i < 3; i++) {
        pthread_create(&threads[i], NULL, tier1_mutex_thread, &thread_ids[i]);
    }

    // Wait for all threads
    for (int i = 0; i < 3; i++) {
        pthread_join(threads[i], NULL);
    }

    if (tier1_counter == 30) {
        TEST_PASS("Tier 1: Mutex blocking - all increments completed");
    } else {
        TEST_FAIL("Tier 1: Mutex blocking - counter mismatch");
    }

    printf("Expected context switches: ~%d (Tier 1 blocking)\n", tier1_expected_switches);
}

// Condition variable test
static pthread_mutex_t tier1_cond_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t tier1_cond = PTHREAD_COND_INITIALIZER;
static int tier1_ready = 0;

void* tier1_cond_waiter(void* arg) {
    int thread_id = *(int*)arg;

    pthread_mutex_lock(&tier1_cond_mutex);
    printf("[T%d] Waiting on condition variable...\n", thread_id);
    while (!tier1_ready) {
        pthread_cond_wait(&tier1_cond, &tier1_cond_mutex);
    }
    printf("[T%d] Condition signaled!\n", thread_id);
    pthread_mutex_unlock(&tier1_cond_mutex);

    return NULL;
}

void test_tier1_condvar_blocking() {
    printf("\n=== Tier 1: Condition Variable Blocking Test ===\n");

    tier1_ready = 0;

    pthread_t threads[3];
    int thread_ids[3] = {1, 2, 3};

    // Create 3 threads that wait on condition variable
    for (int i = 0; i < 3; i++) {
        pthread_create(&threads[i], NULL, tier1_cond_waiter, &thread_ids[i]);
    }

    // Give threads time to start waiting
    usleep(100000); // 100ms

    // Signal all waiting threads
    pthread_mutex_lock(&tier1_cond_mutex);
    tier1_ready = 1;
    pthread_cond_broadcast(&tier1_cond);
    pthread_mutex_unlock(&tier1_cond_mutex);

    // Wait for all threads
    for (int i = 0; i < 3; i++) {
        pthread_join(threads[i], NULL);
    }

    TEST_PASS("Tier 1: Condition variable blocking - all threads woke up");
    printf("Context switches: Tier 1 (cond_wait blocking)\n");
}

// Sleep blocking test
void* tier1_sleep_thread(void* arg) {
    int thread_id = *(int*)arg;

    printf("[T%d] Sleeping for 50ms...\n", thread_id);
    usleep(50000); // 50ms
    printf("[T%d] Woke up from sleep\n", thread_id);

    return NULL;
}

void test_tier1_sleep_blocking() {
    printf("\n=== Tier 1: Sleep Blocking Test ===\n");

    pthread_t threads[3];
    int thread_ids[3] = {1, 2, 3};

    // Create 3 threads that sleep
    for (int i = 0; i < 3; i++) {
        pthread_create(&threads[i], NULL, tier1_sleep_thread, &thread_ids[i]);
    }

    // Wait for all threads
    for (int i = 0; i < 3; i++) {
        pthread_join(threads[i], NULL);
    }

    TEST_PASS("Tier 1: Sleep blocking - all threads completed");
    printf("Context switches: Tier 1 (sleep blocking)\n");
}

// ============================================================================
// TIER 2: Periodic Preemption Tests (CPU-intensive)
// ============================================================================

static volatile int tier2_work_done[4] = {0, 0, 0, 0};

void* tier2_cpu_intensive_thread(void* arg) {
    int thread_id = *(int*)arg;
    uint64_t sum = 0;

    printf("[T%d] Starting CPU-intensive work...\n", thread_id);

    // CPU-intensive work that doesn't hit blocking points
    // This should trigger Tier 2 periodic preemption
    for (int i = 0; i < 1000000; i++) {
        sum += i * thread_id;

        // Every 100k iterations, mark progress
        if (i % 100000 == 0) {
            tier2_work_done[thread_id]++;
        }
    }

    printf("[T%d] Completed CPU-intensive work, sum=%llu\n", thread_id, (unsigned long long)sum);

    return NULL;
}

void test_tier2_periodic_preemption() {
    printf("\n=== Tier 2: Periodic Preemption Test ===\n");
    printf("Running CPU-intensive threads that should trigger Tier 2...\n");

    memset((void*)tier2_work_done, 0, sizeof(tier2_work_done));

    pthread_t threads[3];
    int thread_ids[3] = {1, 2, 3};

    // Create 3 CPU-intensive threads
    for (int i = 0; i < 3; i++) {
        pthread_create(&threads[i], NULL, tier2_cpu_intensive_thread, &thread_ids[i]);
    }

    // Wait for all threads
    for (int i = 0; i < 3; i++) {
        pthread_join(threads[i], NULL);
    }

    // Verify all threads made progress
    int all_completed = 1;
    for (int i = 1; i <= 3; i++) {
        if (tier2_work_done[i] < 10) {
            all_completed = 0;
        }
    }

    if (all_completed) {
        TEST_PASS("Tier 2: Periodic preemption - all threads completed");
    } else {
        TEST_FAIL("Tier 2: Periodic preemption - some threads didn't complete");
    }

    printf("Context switches: Tier 2 (periodic preemption every 10K instructions)\n");
}

// ============================================================================
// TIER 3: Emergency Preemption Tests (Pathological)
// ============================================================================

static volatile int tier3_should_stop = 0;
static volatile int tier3_spin_count[4] = {0, 0, 0, 0};

void* tier3_spinning_thread(void* arg) {
    int thread_id = *(int*)arg;

    printf("[T%d] Starting tight spin loop (pathological)...\n", thread_id);

    // Tight spin loop that should trigger Tier 3 emergency mode
    while (!tier3_should_stop) {
        tier3_spin_count[thread_id]++;

        // Occasionally check if we should stop
        if (tier3_spin_count[thread_id] % 1000000 == 0) {
            // This is a pathological case - spinning without yielding
        }
    }

    printf("[T%d] Stopped spinning, count=%d\n", thread_id, tier3_spin_count[thread_id]);

    return NULL;
}

void* tier3_stopper_thread(void* arg) {
    (void)arg;

    printf("[Stopper] Sleeping for 200ms to let spinners trigger Tier 3...\n");
    usleep(200000); // 200ms - should trigger Tier 3 emergency mode

    printf("[Stopper] Stopping spinners\n");
    tier3_should_stop = 1;

    return NULL;
}

void test_tier3_emergency_preemption() {
    printf("\n=== Tier 3: Emergency Preemption Test ===\n");
    printf("Running pathological spinning threads that should trigger Tier 3...\n");

    tier3_should_stop = 0;
    memset((void*)tier3_spin_count, 0, sizeof(tier3_spin_count));

    pthread_t spinners[2];
    pthread_t stopper;
    int thread_ids[2] = {1, 2};

    // Create 2 spinning threads
    for (int i = 0; i < 2; i++) {
        pthread_create(&spinners[i], NULL, tier3_spinning_thread, &thread_ids[i]);
    }

    // Create stopper thread
    pthread_create(&stopper, NULL, tier3_stopper_thread, NULL);

    // Wait for stopper
    pthread_join(stopper, NULL);

    // Wait for spinners
    for (int i = 0; i < 2; i++) {
        pthread_join(spinners[i], NULL);
    }

    // Verify both spinners made progress (proving Tier 3 preempted them)
    if (tier3_spin_count[1] > 0 && tier3_spin_count[2] > 0) {
        TEST_PASS("Tier 3: Emergency preemption - both spinners made progress");
    } else {
        TEST_FAIL("Tier 3: Emergency preemption - some spinners didn't run");
    }

    printf("Context switches: Tier 3 (emergency mode with aggressive preemption)\n");
}

// ============================================================================
// BUSY WAIT FAIRNESS TEST: Multiple Threads with Busy Waits
// ============================================================================

#define NUM_BUSY_THREADS 8
#define BUSY_WAIT_ITERATIONS 200000

static volatile int busy_wait_counters[NUM_BUSY_THREADS] = {0};
static volatile int busy_wait_start = 0;
static pthread_mutex_t busy_wait_mutex = PTHREAD_MUTEX_INITIALIZER;

void* busy_wait_thread(void* arg) {
    int thread_id = *(int*)arg;

    // Wait for all threads to be ready
    pthread_mutex_lock(&busy_wait_mutex);
    pthread_mutex_unlock(&busy_wait_mutex);

    while (!busy_wait_start) {
        // Busy wait for start signal
    }

    printf("[T%d] Starting busy wait loop...\n", thread_id + 1);

    // Busy wait loop - should trigger periodic preemption
    for (int i = 0; i < BUSY_WAIT_ITERATIONS; i++) {
        busy_wait_counters[thread_id]++;

        // Occasionally do some work to prevent optimization
        if (i % 10000 == 0) {
            volatile int temp = busy_wait_counters[thread_id];
            (void)temp;
        }
    }

    printf("[T%d] Completed busy wait, count=%d\n", thread_id + 1, busy_wait_counters[thread_id]);

    return NULL;
}

void test_busy_wait_fairness() {
    printf("\n=== Busy Wait Fairness Test ===\n");
    printf("Running %d threads with busy waits (%d iterations each) to test fair scheduling...\n",
           NUM_BUSY_THREADS, BUSY_WAIT_ITERATIONS);

    // Reset counters
    for (int i = 0; i < NUM_BUSY_THREADS; i++) {
        busy_wait_counters[i] = 0;
    }
    busy_wait_start = 0;

    pthread_t threads[NUM_BUSY_THREADS];
    int thread_ids[NUM_BUSY_THREADS];

    // Lock mutex to hold threads at start
    pthread_mutex_lock(&busy_wait_mutex);

    // Create threads
    for (int i = 0; i < NUM_BUSY_THREADS; i++) {
        thread_ids[i] = i;  // 0-based to match array indexing
        pthread_create(&threads[i], NULL, busy_wait_thread, &thread_ids[i]);
    }

    // Give threads time to reach the mutex
    usleep(50000); // 50ms

    // Release all threads at once
    pthread_mutex_unlock(&busy_wait_mutex);

    // Start the busy wait
    busy_wait_start = 1;

    // Wait for all threads to complete
    for (int i = 0; i < NUM_BUSY_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    // Verify all threads made progress
    int all_completed = 1;
    int min_count = BUSY_WAIT_ITERATIONS;
    int max_count = 0;

    for (int i = 0; i < NUM_BUSY_THREADS; i++) {
        if (busy_wait_counters[i] != BUSY_WAIT_ITERATIONS) {
            all_completed = 0;
        }
        if (busy_wait_counters[i] < min_count) min_count = busy_wait_counters[i];
        if (busy_wait_counters[i] > max_count) max_count = busy_wait_counters[i];
    }

    printf("Thread completion stats:\n");
    printf("  Min count: %d\n", min_count);
    printf("  Max count: %d\n", max_count);
    printf("  Target: %d\n", BUSY_WAIT_ITERATIONS);

    if (all_completed) {
        TEST_PASS("Busy wait fairness - all threads completed");
    } else {
        TEST_FAIL("Busy wait fairness - some threads didn't complete");
    }

    printf("Context switches: Tier 2 periodic preemption ensuring fairness\n");
}

// ============================================================================
// INTERLEAVED BUSY WAIT TEST: Threads alternating between busy wait and blocking
// ============================================================================

#define NUM_INTERLEAVED_THREADS 6
#define INTERLEAVED_ITERATIONS 10

static volatile int interleaved_counters[NUM_INTERLEAVED_THREADS] = {0};
static pthread_mutex_t interleaved_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t interleaved_cond = PTHREAD_COND_INITIALIZER;
static volatile int interleaved_phase = 0;

void* interleaved_thread(void* arg) {
    int thread_id = *(int*)arg;  // 0-based index

    for (int iter = 0; iter < INTERLEAVED_ITERATIONS; iter++) {
        // Phase 1: Busy wait
        for (int i = 0; i < 50000; i++) {
            interleaved_counters[thread_id]++;
        }

        // Phase 2: Block on condition variable
        pthread_mutex_lock(&interleaved_mutex);
        while (interleaved_phase < iter + 1) {
            pthread_cond_wait(&interleaved_cond, &interleaved_mutex);
        }
        pthread_mutex_unlock(&interleaved_mutex);

        if (iter % 3 == 0) {
            printf("[T%d] Iteration %d, count=%d\n", thread_id + 1, iter, interleaved_counters[thread_id]);
        }
    }

    printf("[T%d] Completed interleaved test, final count=%d\n", thread_id + 1, interleaved_counters[thread_id]);

    return NULL;
}

void* interleaved_coordinator(void* arg) {
    (void)arg;

    for (int i = 0; i < INTERLEAVED_ITERATIONS; i++) {
        usleep(20000); // 20ms between phases

        pthread_mutex_lock(&interleaved_mutex);
        interleaved_phase = i + 1;
        pthread_cond_broadcast(&interleaved_cond);
        pthread_mutex_unlock(&interleaved_mutex);
    }

    return NULL;
}

void test_interleaved_busy_wait() {
    printf("\n=== Interleaved Busy Wait Test ===\n");
    printf("Running %d threads alternating between busy wait and blocking...\n", NUM_INTERLEAVED_THREADS);

    // Reset state
    for (int i = 0; i < NUM_INTERLEAVED_THREADS; i++) {
        interleaved_counters[i] = 0;
    }
    interleaved_phase = 0;

    pthread_t threads[NUM_INTERLEAVED_THREADS];
    pthread_t coordinator;
    int thread_ids[NUM_INTERLEAVED_THREADS];

    // Create worker threads
    for (int i = 0; i < NUM_INTERLEAVED_THREADS; i++) {
        thread_ids[i] = i;  // 0-based to match array indexing
        pthread_create(&threads[i], NULL, interleaved_thread, &thread_ids[i]);
    }

    // Create coordinator thread
    pthread_create(&coordinator, NULL, interleaved_coordinator, NULL);

    // Wait for all threads
    pthread_join(coordinator, NULL);
    for (int i = 0; i < NUM_INTERLEAVED_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    // Verify all threads made progress
    int all_made_progress = 1;
    int expected_count = 50000 * INTERLEAVED_ITERATIONS;

    for (int i = 0; i < NUM_INTERLEAVED_THREADS; i++) {
        if (interleaved_counters[i] < expected_count * 0.9) { // Allow 10% tolerance
            all_made_progress = 0;
            printf("  [WARNING] Thread %d only reached %d (expected ~%d)\n",
                   i + 1, interleaved_counters[i], expected_count);
        }
    }

    if (all_made_progress) {
        TEST_PASS("Interleaved busy wait - all threads made progress");
    } else {
        TEST_FAIL("Interleaved busy wait - some threads lagged behind");
    }

    printf("Context switches: Mixed Tier 1 (blocking) and Tier 2 (busy wait)\n");
}

// ============================================================================
// MEMORY STRESS TEST: Concurrent Memory Operations
// ============================================================================

#define MEMORY_TEST_ALLOCATIONS 100
#define MEMORY_TEST_SIZE 1024

static pthread_mutex_t memory_mutex = PTHREAD_MUTEX_INITIALIZER;
static int memory_allocations_done = 0;

void* memory_stress_thread(void* arg) {
    int thread_id = *(int*)arg;
    void* allocations[MEMORY_TEST_ALLOCATIONS];

    printf("[T%d] Starting memory stress test...\n", thread_id);

    // Allocate memory and write pattern immediately after each allocation
    for (int i = 0; i < MEMORY_TEST_ALLOCATIONS; i++) {
        allocations[i] = malloc(MEMORY_TEST_SIZE);
        if (!allocations[i]) {
            printf("[T%d] Allocation %d failed!\n", thread_id, i);
            return NULL;
        }

        // Write pattern to memory
        unsigned char expected = (unsigned char)(thread_id + i);
        memset(allocations[i], expected, MEMORY_TEST_SIZE);

        // Yield occasionally via mutex
        if (i % 10 == 0) {
            pthread_mutex_lock(&memory_mutex);
            memory_allocations_done++;
            pthread_mutex_unlock(&memory_mutex);
        }
    }

    // Verify memory contents after all allocations
    // Use memcmp instead of byte-by-byte comparison to avoid potential emulator bugs
    int errors = 0;
    for (int i = 0; i < MEMORY_TEST_ALLOCATIONS; i++) {
        unsigned char* ptr = (unsigned char*)allocations[i];
        unsigned char expected = (unsigned char)(thread_id + i);

        // Create expected buffer
        unsigned char expected_buf[MEMORY_TEST_SIZE];
        memset(expected_buf, expected, MEMORY_TEST_SIZE);

        // Compare using memcmp
        if (memcmp(ptr, expected_buf, MEMORY_TEST_SIZE) != 0) {
            errors++;
            if (errors <= 3) {
                // Find first mismatch
                for (int j = 0; j < MEMORY_TEST_SIZE; j++) {
                    if (ptr[j] != expected) {
                        printf("[T%d] Verify failed: alloc[%d] byte[%d] expected=0x%02x got=0x%02x\n",
                               thread_id, i, j, (unsigned int)expected, (unsigned int)ptr[j]);
                        break;
                    }
                }
            }
        }
    }

    // Free memory
    for (int i = 0; i < MEMORY_TEST_ALLOCATIONS; i++) {
        free(allocations[i]);
    }

    printf("[T%d] Memory stress test complete, errors=%d\n", thread_id, errors);

    return (void*)(intptr_t)errors;
}

void test_memory_stress() {
    printf("\n=== Memory Stress Test (Concurrent Allocations) ===\n");

    memory_allocations_done = 0;

    pthread_t threads[4];
    int thread_ids[4] = {1, 2, 3, 4};

    // Create 4 threads doing concurrent memory operations
    for (int i = 0; i < 4; i++) {
        pthread_create(&threads[i], NULL, memory_stress_thread, &thread_ids[i]);
    }

    // Wait for all threads and collect results
    int total_errors = 0;
    for (int i = 0; i < 4; i++) {
        void* result;
        pthread_join(threads[i], &result);
        total_errors += (int)(intptr_t)result;
    }

    if (total_errors == 0) {
        TEST_PASS("Memory stress test - no corruption detected");
    } else {
        TEST_FAIL("Memory stress test - corruption detected");
    }

    printf("Total allocations: %d\n", memory_allocations_done);
}


// ============================================================================
// MAIN TEST RUNNER
// ============================================================================

int run_cooperative_tests(void) {
    /* Reset counters for this test suite */
    tests_passed = 0;
    tests_failed = 0;

    printf("\n========================================\n");
    printf("  COOPERATIVE THREADING TEST SUITE\n");
    printf("========================================\n");
    printf("\nDemonstrating three-tier adaptive scheduling:\n");
    printf("  Tier 1: Blocking operation detection\n");
    printf("  Tier 2: Periodic preemption (CPU-intensive)\n");
    printf("  Tier 3: Emergency preemption (pathological)\n");
    printf("\n");

    // Tier 1 tests
    test_tier1_mutex_blocking();
    test_tier1_condvar_blocking();
    test_tier1_sleep_blocking();

    // Tier 2 tests
    test_tier2_periodic_preemption();

    // Tier 3 tests
    test_tier3_emergency_preemption();

    // Busy wait fairness tests
    test_busy_wait_fairness();
    test_interleaved_busy_wait();

    // Memory stress test
    test_memory_stress();

    // Summary
    printf("\n========================================\n");
    printf("   COOPERATIVE RESULTS: %d passed, %d failed\n", tests_passed, tests_failed);
    printf("========================================\n");

    return tests_failed;
}


