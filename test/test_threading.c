/**
 * Threading Test Suite for Android Emulator
 * Pure C using only libc - Tests pthread operations, mutexes, condvars, TLS.
 * Designed to be compiled with Android NDK for ARM64 target.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <time.h>
#include <stdatomic.h>

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST_ASSERT(cond, msg) do { \
    if (cond) { \
        tests_passed++; \
        printf("  [PASS] %s\n", msg); \
    } else { \
        tests_failed++; \
        printf("  [FAIL] %s (errno=%d: %s)\n", msg, errno, strerror(errno)); \
    } \
} while(0)

/* ========================================================================== */
/* Basic Thread Creation Tests                                                */
/* ========================================================================== */

static void *simple_thread_func(void *arg) {
    int *value = (int *)arg;
    *value = 42;
    return (void *)(long)(*value * 2);
}

static void test_thread_create_join(void) {
    pthread_t thread;
    int value = 0;
    void *retval;
    int ret;
    
    printf("\n=== Thread Create/Join Tests ===\n");
    
    ret = pthread_create(&thread, NULL, simple_thread_func, &value);
    TEST_ASSERT(ret == 0, "pthread_create");
    
    ret = pthread_join(thread, &retval);
    TEST_ASSERT(ret == 0, "pthread_join");
    TEST_ASSERT(value == 42, "Thread modified shared value");
    TEST_ASSERT((long)retval == 84, "Thread return value");
}

static void *detached_thread_func(void *arg) {
    atomic_int *flag = (atomic_int *)arg;
    /* Don't sleep - just set the flag immediately */
    atomic_store(flag, 1);
    return NULL;
}

static void test_thread_detach(void) {
    pthread_t thread;
    pthread_attr_t attr;
    atomic_int flag = 0;
    int ret;
    int wait_count;

    printf("\n=== Thread Detach Tests ===\n");

    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    ret = pthread_create(&thread, &attr, detached_thread_func, &flag);
    TEST_ASSERT(ret == 0, "pthread_create detached");

    pthread_attr_destroy(&attr);

    /* Wait for the flag to be set (with timeout) */
    wait_count = 0;
    while (atomic_load(&flag) != 1 && wait_count < 1000) {
        usleep(1000);  /* 1ms */
        wait_count++;
    }
    TEST_ASSERT(atomic_load(&flag) == 1, "Detached thread completed");
}

static void test_pthread_self(void) {
    pthread_t self;
    
    printf("\n=== pthread_self Tests ===\n");
    
    self = pthread_self();
    TEST_ASSERT(self != 0, "pthread_self returns non-zero");
    TEST_ASSERT(pthread_equal(self, pthread_self()), "pthread_equal with self");
}

/* ========================================================================== */
/* Mutex Tests                                                                */
/* ========================================================================== */

static pthread_mutex_t test_mutex = PTHREAD_MUTEX_INITIALIZER;
static int shared_counter = 0;

static void *mutex_thread_func(void *arg) {
    int i;
    (void)arg;
    for (i = 0; i < 1000; i++) {
        pthread_mutex_lock(&test_mutex);
        shared_counter++;
        pthread_mutex_unlock(&test_mutex);
    }
    return NULL;
}

static void test_mutex_basic(void) {
    pthread_mutex_t mutex;
    int ret;
    
    printf("\n=== Mutex Basic Tests ===\n");
    
    ret = pthread_mutex_init(&mutex, NULL);
    TEST_ASSERT(ret == 0, "pthread_mutex_init");
    
    ret = pthread_mutex_lock(&mutex);
    TEST_ASSERT(ret == 0, "pthread_mutex_lock");
    
    ret = pthread_mutex_unlock(&mutex);
    TEST_ASSERT(ret == 0, "pthread_mutex_unlock");
    
    ret = pthread_mutex_destroy(&mutex);
    TEST_ASSERT(ret == 0, "pthread_mutex_destroy");
}

static void test_mutex_trylock(void) {
    pthread_mutex_t mutex;
    int ret;
    
    printf("\n=== Mutex Trylock Tests ===\n");
    
    pthread_mutex_init(&mutex, NULL);
    
    ret = pthread_mutex_trylock(&mutex);
    TEST_ASSERT(ret == 0, "pthread_mutex_trylock (unlocked)");
    
    ret = pthread_mutex_trylock(&mutex);
    TEST_ASSERT(ret == EBUSY, "pthread_mutex_trylock (locked) returns EBUSY");
    
    pthread_mutex_unlock(&mutex);
    pthread_mutex_destroy(&mutex);
}

static void test_mutex_contention(void) {
    pthread_t threads[4];
    int i, ret;
    
    printf("\n=== Mutex Contention Tests ===\n");
    
    shared_counter = 0;
    
    for (i = 0; i < 4; i++) {
        ret = pthread_create(&threads[i], NULL, mutex_thread_func, NULL);
        TEST_ASSERT(ret == 0, "Create contention thread");
    }
    
    for (i = 0; i < 4; i++) {
        pthread_join(threads[i], NULL);
    }
    
    TEST_ASSERT(shared_counter == 4000, "Mutex protected counter (4 threads x 1000)");
}

static void test_recursive_mutex(void) {
    pthread_mutex_t mutex;
    pthread_mutexattr_t attr;
    int ret;

    printf("\n=== Recursive Mutex Tests ===\n");

    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);

    ret = pthread_mutex_init(&mutex, &attr);
    TEST_ASSERT(ret == 0, "Init recursive mutex");

    ret = pthread_mutex_lock(&mutex);
    TEST_ASSERT(ret == 0, "First lock");

    ret = pthread_mutex_lock(&mutex);
    TEST_ASSERT(ret == 0, "Second lock (recursive)");

    ret = pthread_mutex_unlock(&mutex);
    TEST_ASSERT(ret == 0, "First unlock");

    ret = pthread_mutex_unlock(&mutex);
    TEST_ASSERT(ret == 0, "Second unlock");

    pthread_mutexattr_destroy(&attr);
    pthread_mutex_destroy(&mutex);
}

/* ========================================================================== */
/* Condition Variable Tests                                                   */
/* ========================================================================== */

static pthread_mutex_t cond_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cond_var = PTHREAD_COND_INITIALIZER;
static int cond_flag = 0;

static void *cond_wait_thread(void *arg) {
    (void)arg;
    pthread_mutex_lock(&cond_mutex);
    while (cond_flag == 0) {
        pthread_cond_wait(&cond_var, &cond_mutex);
    }
    pthread_mutex_unlock(&cond_mutex);
    return NULL;
}

static void test_condvar_signal(void) {
    pthread_t thread;
    int ret;

    printf("\n=== Condition Variable Signal Tests ===\n");

    cond_flag = 0;

    ret = pthread_create(&thread, NULL, cond_wait_thread, NULL);
    TEST_ASSERT(ret == 0, "Create cond wait thread");

    usleep(10000);

    pthread_mutex_lock(&cond_mutex);
    cond_flag = 1;
    ret = pthread_cond_signal(&cond_var);
    TEST_ASSERT(ret == 0, "pthread_cond_signal");
    pthread_mutex_unlock(&cond_mutex);

    ret = pthread_join(thread, NULL);
    TEST_ASSERT(ret == 0, "Join cond wait thread");
}

static atomic_int broadcast_count = 0;

static void *cond_broadcast_thread(void *arg) {
    (void)arg;
    pthread_mutex_lock(&cond_mutex);
    while (cond_flag == 0) {
        pthread_cond_wait(&cond_var, &cond_mutex);
    }
    atomic_fetch_add(&broadcast_count, 1);
    pthread_mutex_unlock(&cond_mutex);
    return NULL;
}

static void test_condvar_broadcast(void) {
    pthread_t threads[4];
    int i, ret;

    printf("\n=== Condition Variable Broadcast Tests ===\n");

    cond_flag = 0;
    atomic_store(&broadcast_count, 0);

    for (i = 0; i < 4; i++) {
        ret = pthread_create(&threads[i], NULL, cond_broadcast_thread, NULL);
        TEST_ASSERT(ret == 0, "Create broadcast wait thread");
    }

    usleep(20000);

    pthread_mutex_lock(&cond_mutex);
    cond_flag = 1;
    ret = pthread_cond_broadcast(&cond_var);
    TEST_ASSERT(ret == 0, "pthread_cond_broadcast");
    pthread_mutex_unlock(&cond_mutex);

    for (i = 0; i < 4; i++) {
        pthread_join(threads[i], NULL);
    }

    TEST_ASSERT(atomic_load(&broadcast_count) == 4, "All 4 threads woke up");
}

static void test_condvar_timedwait(void) {
    pthread_cond_t cond;
    pthread_mutex_t mutex;
    struct timespec ts;
    int ret;

    printf("\n=== Condition Variable Timedwait Tests ===\n");

    pthread_cond_init(&cond, NULL);
    pthread_mutex_init(&mutex, NULL);

    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_nsec += 10000000;
    if (ts.tv_nsec >= 1000000000) {
        ts.tv_sec++;
        ts.tv_nsec -= 1000000000;
    }

    pthread_mutex_lock(&mutex);
    ret = pthread_cond_timedwait(&cond, &mutex, &ts);
    TEST_ASSERT(ret == ETIMEDOUT, "pthread_cond_timedwait timeout");
    pthread_mutex_unlock(&mutex);

    pthread_cond_destroy(&cond);
    pthread_mutex_destroy(&mutex);
}

/* ========================================================================== */
/* Read-Write Lock Tests                                                      */
/* ========================================================================== */

static pthread_rwlock_t rwlock = PTHREAD_RWLOCK_INITIALIZER;
static int rwlock_value = 0;

static void *rwlock_reader_thread(void *arg) {
    int i, val;
    (void)arg;
    for (i = 0; i < 100; i++) {
        pthread_rwlock_rdlock(&rwlock);
        val = rwlock_value;
        (void)val;
        pthread_rwlock_unlock(&rwlock);
    }
    return NULL;
}

static void *rwlock_writer_thread(void *arg) {
    int i;
    (void)arg;
    for (i = 0; i < 100; i++) {
        pthread_rwlock_wrlock(&rwlock);
        rwlock_value++;
        pthread_rwlock_unlock(&rwlock);
    }
    return NULL;
}

static void test_rwlock_basic(void) {
    pthread_rwlock_t rw;
    int ret;

    printf("\n=== Read-Write Lock Basic Tests ===\n");

    ret = pthread_rwlock_init(&rw, NULL);
    TEST_ASSERT(ret == 0, "pthread_rwlock_init");

    ret = pthread_rwlock_rdlock(&rw);
    TEST_ASSERT(ret == 0, "pthread_rwlock_rdlock");

    ret = pthread_rwlock_unlock(&rw);
    TEST_ASSERT(ret == 0, "pthread_rwlock_unlock (read)");

    ret = pthread_rwlock_wrlock(&rw);
    TEST_ASSERT(ret == 0, "pthread_rwlock_wrlock");

    ret = pthread_rwlock_unlock(&rw);
    TEST_ASSERT(ret == 0, "pthread_rwlock_unlock (write)");

    ret = pthread_rwlock_destroy(&rw);
    TEST_ASSERT(ret == 0, "pthread_rwlock_destroy");
}

static void test_rwlock_contention(void) {
    pthread_t readers[4], writers[2];
    int i, ret;

    printf("\n=== Read-Write Lock Contention Tests ===\n");

    rwlock_value = 0;

    for (i = 0; i < 4; i++) {
        ret = pthread_create(&readers[i], NULL, rwlock_reader_thread, NULL);
        TEST_ASSERT(ret == 0, "Create reader thread");
    }

    for (i = 0; i < 2; i++) {
        ret = pthread_create(&writers[i], NULL, rwlock_writer_thread, NULL);
        TEST_ASSERT(ret == 0, "Create writer thread");
    }

    for (i = 0; i < 4; i++) {
        pthread_join(readers[i], NULL);
    }
    for (i = 0; i < 2; i++) {
        pthread_join(writers[i], NULL);
    }

    TEST_ASSERT(rwlock_value == 200, "RWLock protected counter (2 writers x 100)");
}

/* ========================================================================== */
/* Thread-Local Storage Tests                                                 */
/* ========================================================================== */

static pthread_key_t tls_key;
static atomic_int tls_destructor_called = 0;

static void tls_destructor(void *value) {
    (void)value;
    atomic_fetch_add(&tls_destructor_called, 1);
}

static void *tls_thread_func(void *arg) {
    long thread_num = (long)arg;
    void *val;

    pthread_setspecific(tls_key, (void *)(thread_num * 100));

    usleep(1000);

    val = pthread_getspecific(tls_key);
    if ((long)val != thread_num * 100) {
        return (void *)1;
    }
    return (void *)0;
}

static void test_tls_basic(void) {
    pthread_key_t key;
    void *val;
    int ret;

    printf("\n=== Thread-Local Storage Basic Tests ===\n");

    ret = pthread_key_create(&key, NULL);
    TEST_ASSERT(ret == 0, "pthread_key_create");

    ret = pthread_setspecific(key, (void *)12345);
    TEST_ASSERT(ret == 0, "pthread_setspecific");

    val = pthread_getspecific(key);
    TEST_ASSERT((long)val == 12345, "pthread_getspecific");

    ret = pthread_key_delete(key);
    TEST_ASSERT(ret == 0, "pthread_key_delete");
}

static void test_tls_multithread(void) {
    pthread_t threads[4];
    void *retval;
    int i, ret, all_ok;

    printf("\n=== Thread-Local Storage Multi-thread Tests ===\n");

    ret = pthread_key_create(&tls_key, tls_destructor);
    TEST_ASSERT(ret == 0, "Create TLS key with destructor");

    atomic_store(&tls_destructor_called, 0);

    for (i = 0; i < 4; i++) {
        ret = pthread_create(&threads[i], NULL, tls_thread_func, (void *)(long)(i + 1));
        TEST_ASSERT(ret == 0, "Create TLS test thread");
    }

    all_ok = 1;
    for (i = 0; i < 4; i++) {
        pthread_join(threads[i], &retval);
        if ((long)retval != 0) all_ok = 0;
    }

    TEST_ASSERT(all_ok, "All threads got correct TLS values");

    pthread_key_delete(tls_key);
}

/* ========================================================================== */
/* Stress Tests                                                               */
/* ========================================================================== */

static atomic_int stress_counter = 0;

static void *stress_thread_func(void *arg) {
    int i;
    (void)arg;
    for (i = 0; i < 100; i++) {
        atomic_fetch_add(&stress_counter, 1);
        usleep(100);
    }
    return NULL;
}

static void test_many_threads(void) {
    pthread_t threads[16];
    int i, ret;

    printf("\n=== Many Threads Stress Test ===\n");

    atomic_store(&stress_counter, 0);

    for (i = 0; i < 16; i++) {
        ret = pthread_create(&threads[i], NULL, stress_thread_func, NULL);
        TEST_ASSERT(ret == 0, "Create stress thread");
    }

    for (i = 0; i < 16; i++) {
        pthread_join(threads[i], NULL);
    }

    int final_count = atomic_load(&stress_counter);
    if (final_count != 1600) {
        printf("    stress_counter = %d (expected 1600, lost %d)\n", final_count, 1600 - final_count);
    }
    TEST_ASSERT(final_count == 1600, "16 threads x 100 increments");
}

/* ========================================================================== */
/* pthread_rwlock_trylock tests (from stubs)                                  */
/* ========================================================================== */
static void test_rwlock_trylock(void) {
    pthread_rwlock_t rw;
    int ret;

    printf("\n=== pthread_rwlock_trylock Tests ===\n");

    ret = pthread_rwlock_init(&rw, NULL);
    TEST_ASSERT(ret == 0, "pthread_rwlock_init");

    /* tryrdlock should succeed on unlocked rwlock */
    ret = pthread_rwlock_tryrdlock(&rw);
    TEST_ASSERT(ret == 0, "pthread_rwlock_tryrdlock on unlocked");

    /* Another tryrdlock should also succeed (multiple readers allowed) */
    ret = pthread_rwlock_tryrdlock(&rw);
    TEST_ASSERT(ret == 0, "pthread_rwlock_tryrdlock second reader");

    /* Unlock both read locks */
    pthread_rwlock_unlock(&rw);
    pthread_rwlock_unlock(&rw);

    /* trywrlock should succeed on unlocked rwlock */
    ret = pthread_rwlock_trywrlock(&rw);
    TEST_ASSERT(ret == 0, "pthread_rwlock_trywrlock on unlocked");

    /* tryrdlock should fail when write-locked */
    ret = pthread_rwlock_tryrdlock(&rw);
    TEST_ASSERT(ret == EBUSY, "pthread_rwlock_tryrdlock fails when write-locked");

    /* trywrlock should fail when write-locked */
    ret = pthread_rwlock_trywrlock(&rw);
    TEST_ASSERT(ret == EBUSY, "pthread_rwlock_trywrlock fails when write-locked");

    pthread_rwlock_unlock(&rw);
    pthread_rwlock_destroy(&rw);
}

/* ========================================================================== */
/* pthread_barrier tests (from stubs)                                         */
/* ========================================================================== */
static pthread_barrier_t test_barrier;
static int barrier_counter = 0;
static pthread_mutex_t barrier_mutex = PTHREAD_MUTEX_INITIALIZER;

static void *barrier_thread_func(void *arg) {
    int ret;
    (void)arg;

    /* Increment counter before barrier */
    pthread_mutex_lock(&barrier_mutex);
    barrier_counter++;
    pthread_mutex_unlock(&barrier_mutex);

    /* Wait at barrier */
    ret = pthread_barrier_wait(&test_barrier);

    /* One thread gets PTHREAD_BARRIER_SERIAL_THREAD, others get 0 */
    if (ret != 0 && ret != PTHREAD_BARRIER_SERIAL_THREAD) {
        return (void *)1;  /* Error */
    }

    return (void *)0;
}

static void test_barrier_basic(void) {
    int ret;

    printf("\n=== pthread_barrier Basic Tests ===\n");

    /* Initialize barrier for 1 thread */
    ret = pthread_barrier_init(&test_barrier, NULL, 1);
    TEST_ASSERT(ret == 0, "pthread_barrier_init with count=1");

    /* Single thread should pass immediately */
    ret = pthread_barrier_wait(&test_barrier);
    TEST_ASSERT(ret == 0 || ret == PTHREAD_BARRIER_SERIAL_THREAD,
                "pthread_barrier_wait single thread");

    ret = pthread_barrier_destroy(&test_barrier);
    TEST_ASSERT(ret == 0, "pthread_barrier_destroy");

    /* Test invalid count */
    ret = pthread_barrier_init(&test_barrier, NULL, 0);
    TEST_ASSERT(ret == EINVAL, "pthread_barrier_init with count=0 returns EINVAL");
}

static void test_barrier_multithread(void) {
    pthread_t threads[4];
    int i, ret;
    void *retval;
    int all_ok = 1;

    printf("\n=== pthread_barrier Multi-thread Tests ===\n");

    barrier_counter = 0;

    /* Initialize barrier for 4 threads */
    ret = pthread_barrier_init(&test_barrier, NULL, 4);
    TEST_ASSERT(ret == 0, "pthread_barrier_init with count=4");

    /* Create 4 threads */
    for (i = 0; i < 4; i++) {
        ret = pthread_create(&threads[i], NULL, barrier_thread_func, (void *)(long)i);
        TEST_ASSERT(ret == 0, "pthread_create for barrier test");
    }

    /* Wait for all threads */
    for (i = 0; i < 4; i++) {
        ret = pthread_join(threads[i], &retval);
        if (ret != 0 || retval != (void *)0) {
            all_ok = 0;
        }
    }
    TEST_ASSERT(all_ok, "All barrier threads completed successfully");
    TEST_ASSERT(barrier_counter == 4, "All threads incremented counter before barrier");

    ret = pthread_barrier_destroy(&test_barrier);
    TEST_ASSERT(ret == 0, "pthread_barrier_destroy after use");
}

/* ========================================================================== */
/* Main Entry Point                                                           */
/* ========================================================================== */

int run_threading_tests(void) {
    printf("\n");
    printf("========================================\n");
    printf("   THREADING TEST SUITE\n");
    printf("========================================\n");

    test_thread_create_join();
    test_thread_detach();
    test_pthread_self();
    test_mutex_basic();
    test_mutex_trylock();
    test_mutex_contention();
    test_recursive_mutex();
    test_condvar_signal();
    test_condvar_broadcast();
    test_condvar_timedwait();
    test_rwlock_basic();
    test_rwlock_contention();
    test_rwlock_trylock();
    test_tls_basic();
    test_tls_multithread();
    test_barrier_basic();
    test_barrier_multithread();
    test_many_threads();

    printf("\n========================================\n");
    printf("   THREADING RESULTS: %d passed, %d failed\n", tests_passed, tests_failed);
    printf("========================================\n");

    return tests_failed;
}

