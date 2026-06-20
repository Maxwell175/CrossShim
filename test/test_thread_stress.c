/*
 * Thread arena recycling stress test.
 *
 * The emulator allocates each guest thread a 1MB stack from a fixed arena
 * (0x90000000..0xA0000000 = 256 slots). Without recycling exited threads'
 * stack/TLS regions, sustained thread creation exhausts the arena after ~256
 * creations and pthread_create starts returning EAGAIN. This reproduces the
 * "periodic crash / cameras can no longer reconnect" behavior under multi-camera
 * reconnect churn.
 *
 * This test creates FAR more than 256 threads over its lifetime while keeping
 * only a few alive at once. It must pass only if the arena is recycled.
 */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <unistd.h>

static atomic_int g_ran = 0;

static void *worker(void *arg) {
    long n = (long)arg;
    /* Touch the stack a little so a real frame is used. */
    volatile char buf[4096];
    for (int i = 0; i < (int)sizeof(buf); i += 64) buf[i] = (char)(n + i);
    atomic_fetch_add(&g_ran, 1);
    return (void *)(n + 1);
}

/* Phase 1: create+join sequentially, many more than the 256-slot arena. */
static int phase_sequential(int count) {
    for (long i = 0; i < count; i++) {
        pthread_t t;
        int ret = pthread_create(&t, NULL, worker, (void *)i);
        if (ret != 0) {
            printf("  [FAIL] sequential pthread_create #%ld returned %d (arena exhausted?)\n", i, ret);
            return 1;
        }
        void *rv = NULL;
        ret = pthread_join(t, &rv);
        if (ret != 0) {
            printf("  [FAIL] sequential pthread_join #%ld returned %d\n", i, ret);
            return 1;
        }
        if ((long)rv != i + 1) {
            printf("  [FAIL] sequential retval #%ld = %ld (expected %ld)\n", i, (long)rv, i + 1);
            return 1;
        }
    }
    printf("  [PASS] sequential create+join x%d (arena recycled across joins)\n", count);
    return 0;
}

/* Phase 2: batches of concurrent detached threads, repeated, to exercise the
 * detached-finalize recycle path. Each batch fully drains before the next. */
static int phase_detached_batches(int batches, int per_batch) {
    for (int b = 0; b < batches; b++) {
        atomic_store(&g_ran, 0);
        for (int i = 0; i < per_batch; i++) {
            pthread_t t;
            pthread_attr_t attr;
            pthread_attr_init(&attr);
            pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
            int ret = pthread_create(&t, &attr, worker, (void *)(long)i);
            pthread_attr_destroy(&attr);
            if (ret != 0) {
                printf("  [FAIL] detached batch %d create #%d returned %d (arena exhausted?)\n", b, i, ret);
                return 1;
            }
        }
        /* Wait for the batch to finish so its arena slots get recycled. */
        int waited = 0;
        while (atomic_load(&g_ran) < per_batch && waited < 5000) {
            usleep(1000);
            waited++;
        }
        if (atomic_load(&g_ran) < per_batch) {
            printf("  [FAIL] detached batch %d: only %d/%d ran\n", b, atomic_load(&g_ran), per_batch);
            return 1;
        }
    }
    printf("  [PASS] detached %d batches x%d (arena recycled across finalize)\n", batches, per_batch);
    return 0;
}

int main(void) {
    printf("=== Thread Arena Recycling Stress Test ===\n");
    int rc = 0;
    rc |= phase_sequential(400);          /* 400 > 256 slot arena */
    rc |= phase_detached_batches(6, 64);  /* 384 detached threads total, 64 alive/batch */
    if (rc == 0) {
        printf("ALL TESTS PASSED\n");
        return 0;
    }
    printf("TESTS FAILED\n");
    return 1;
}
