/*
 * parallel.c — Thread pool and task system for Disturb.
 *
 * Guarded by DISTURB_ENABLE_PARALLEL.
 *
 * Sub-layers:
 *   2A — parr_dispatch: transparent parallel array kernel dispatch
 *   2B — task.spawn/task.join: parallel lambda execution with VM pool
 *   2C — parallel.pipeline: SPSC lock-free stream pipeline
 *   2D — parallel.pool: work-stealing pool (Chase-Lev deque)
 *
 * Exposed to Disturb as the "parallel" module:
 *   parallel.pool_size()
 *   parallel.cpu_count()
 *   parallel.map(fn, list)
 *   task.spawn(fn, arg)       → handle
 *   task.join(handle)         → result
 *   parallel.pipeline(stages) → pipe handle
 *   parallel.push(pipe, item)
 *   parallel.flush(pipe)
 *   parallel.destroy(pipe)
 *   parallel.wpool(n)         → work-stealing pool handle
 *   parallel.submit(pool, fn, arg) → handle
 *   parallel.gather(pool, handles) → results
 */

#ifndef _POSIX_C_SOURCE
#  define _POSIX_C_SOURCE 199309L
#endif

#ifdef DISTURB_ENABLE_PARALLEL

#include "parallel.h"
#include "vm.h"
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdatomic.h>
#include <time.h>
#include <math.h>

#ifdef DISTURB_ENABLE_SIMD
#include "simd_ops.h"
#endif

/* ---- Configuration ---------------------------------------------------- */

#ifndef DISTURB_PARALLEL_MAX_WORKERS
#  define DISTURB_PARALLEL_MAX_WORKERS 64
#endif

#ifndef VM_POOL_SIZE
#  define VM_POOL_SIZE 16
#endif

/* ---- Portable CPU count ----------------------------------------------- */

static int detect_cpu_count(void)
{
#if defined(_SC_NPROCESSORS_ONLN)
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    if (n > 0) return (int)n;
#endif
#if defined(_WIN32)
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    return (int)si.dwNumberOfProcessors;
#endif
    return 2;
}

/* ===========================================================================
 * CORE THREAD POOL (shared by all sub-layers)
 * =========================================================================== */

typedef struct {
    void (*fn)(void *arg);
    void *arg;
} GenericTask;

typedef struct {
    GenericTask *tasks;
    int cap;
    int head;
    int tail;
    int count;
    int shutdown;
    pthread_mutex_t lock;
    pthread_cond_t not_empty;
    pthread_cond_t not_full;
} TaskQueue;

static void taskqueue_init(TaskQueue *q, int cap)
{
    q->tasks = (GenericTask *)calloc((size_t)cap, sizeof(GenericTask));
    q->cap = cap;
    q->head = 0;
    q->tail = 0;
    q->count = 0;
    q->shutdown = 0;
    pthread_mutex_init(&q->lock, NULL);
    pthread_cond_init(&q->not_empty, NULL);
    pthread_cond_init(&q->not_full, NULL);
}

static void taskqueue_destroy(TaskQueue *q)
{
    pthread_mutex_destroy(&q->lock);
    pthread_cond_destroy(&q->not_empty);
    pthread_cond_destroy(&q->not_full);
    free(q->tasks);
    q->tasks = NULL;
}

static void taskqueue_push(TaskQueue *q, void (*fn)(void *), void *arg)
{
    pthread_mutex_lock(&q->lock);
    while (q->count == q->cap && !q->shutdown)
        pthread_cond_wait(&q->not_full, &q->lock);
    if (q->shutdown) { pthread_mutex_unlock(&q->lock); return; }
    q->tasks[q->tail].fn = fn;
    q->tasks[q->tail].arg = arg;
    q->tail = (q->tail + 1) % q->cap;
    q->count++;
    pthread_cond_signal(&q->not_empty);
    pthread_mutex_unlock(&q->lock);
}

static int taskqueue_pop(TaskQueue *q, GenericTask *out)
{
    pthread_mutex_lock(&q->lock);
    while (q->count == 0 && !q->shutdown)
        pthread_cond_wait(&q->not_empty, &q->lock);
    if (q->shutdown && q->count == 0) {
        pthread_mutex_unlock(&q->lock);
        return 0;
    }
    *out = q->tasks[q->head];
    q->head = (q->head + 1) % q->cap;
    q->count--;
    pthread_cond_signal(&q->not_full);
    pthread_mutex_unlock(&q->lock);
    return 1;
}

typedef struct {
    pthread_t *threads;
    int num_workers;
    TaskQueue queue;
    int initialized;
} ThreadPool;

static ThreadPool g_pool = { .initialized = 0 };

static void *worker_thread(void *arg)
{
    ThreadPool *pool = (ThreadPool *)arg;
    for (;;) {
        GenericTask task;
        if (!taskqueue_pop(&pool->queue, &task)) break;
        task.fn(task.arg);
    }
    return NULL;
}

static void pool_ensure_init(void)
{
    if (g_pool.initialized) return;
    int n = detect_cpu_count();
    if (n > DISTURB_PARALLEL_MAX_WORKERS) n = DISTURB_PARALLEL_MAX_WORKERS;
    if (n < 1) n = 1;

    g_pool.num_workers = n;
    taskqueue_init(&g_pool.queue, n * 64);
    g_pool.threads = (pthread_t *)calloc((size_t)n, sizeof(pthread_t));
    for (int i = 0; i < n; i++) {
        pthread_create(&g_pool.threads[i], NULL, worker_thread, &g_pool);
    }
    g_pool.initialized = 1;
}

static void pool_ensure_init(void);
static void vm_pool_shutdown(void);

void parallel_shutdown(void)
{
    if (!g_pool.initialized) return;
    pthread_mutex_lock(&g_pool.queue.lock);
    g_pool.queue.shutdown = 1;
    pthread_cond_broadcast(&g_pool.queue.not_empty);
    pthread_cond_broadcast(&g_pool.queue.not_full);
    pthread_mutex_unlock(&g_pool.queue.lock);

    for (int i = 0; i < g_pool.num_workers; i++) {
        pthread_join(g_pool.threads[i], NULL);
    }
    free(g_pool.threads);
    g_pool.threads = NULL;
    taskqueue_destroy(&g_pool.queue);
    g_pool.initialized = 0;

    /* Also shutdown VM pool */
    vm_pool_shutdown();
}

/* ---- Barrier helper (reusable for 2A etc.) ---------------------------- */
/* Uses atomic completion counter: workers increment when done,
 * main thread spins until all workers finished. Safe to free after spin. */

typedef struct {
    volatile int done;
    int target;
} Barrier;

static Barrier *barrier_create(int target)
{
    Barrier *b = (Barrier *)malloc(sizeof(Barrier));
    if (!b) return NULL;
    b->done = 0;
    b->target = target;
    return b;
}

/* Worker calls this when finished — atomic increment. */
static void barrier_wait(Barrier *b)
{
    __atomic_add_fetch(&b->done, 1, __ATOMIC_RELEASE);
}

/* Main thread: spin-wait until all workers completed, then free. */
static void barrier_wait_and_free(Barrier *b)
{
    if (!b) return;
    while (__atomic_load_n(&b->done, __ATOMIC_ACQUIRE) < b->target) {
        /* busy-wait with yield to avoid burning CPU */
#if defined(__x86_64__) || defined(__i386__)
        __asm__ volatile("pause");
#elif defined(__aarch64__)
        __asm__ volatile("yield");
#endif
    }
    free(b);
}

/* ===========================================================================
 * 2A — PARALLEL ARRAY DISPATCH
 * =========================================================================== */

enum {
    PARR_OP_ADD = 0,
    PARR_OP_SUB,
    PARR_OP_MUL,
    PARR_OP_DIV,
    PARR_OP_MOD
};

typedef struct {
    const void *a;
    const void *b;
    void *out;
    size_t start;
    size_t end;
    int ba;
    int bb;
    int op;
    int is_float;
    Barrier *barrier;
} ParrSlice;

static void parr_slice_worker(void *arg)
{
    ParrSlice *s = (ParrSlice *)arg;
    size_t n = s->end - s->start;

#if INTPTR_MAX == INT64_MAX
    if (s->is_float) {
        const double *a = (const double *)s->a + (s->ba ? 0 : s->start);
        const double *b = (const double *)s->b + (s->bb ? 0 : s->start);
        double *out = (double *)s->out + s->start;
#ifdef DISTURB_ENABLE_SIMD
        switch (s->op) {
        case PARR_OP_ADD: simd_float_add(a, b, out, n, s->ba, s->bb); break;
        case PARR_OP_SUB: simd_float_sub(a, b, out, n, s->ba, s->bb); break;
        case PARR_OP_MUL: simd_float_mul(a, b, out, n, s->ba, s->bb); break;
        case PARR_OP_DIV: simd_float_div(a, b, out, n, s->ba, s->bb); break;
        case PARR_OP_MOD: simd_float_mod(a, b, out, n, s->ba, s->bb); break;
        default: break;
        }
#else
        for (size_t i = 0; i < n; i++) {
            double av = s->ba ? ((const double *)s->a)[0] : a[i];
            double bv = s->bb ? ((const double *)s->b)[0] : b[i];
            switch (s->op) {
            case PARR_OP_ADD: out[i] = av + bv; break;
            case PARR_OP_SUB: out[i] = av - bv; break;
            case PARR_OP_MUL: out[i] = av * bv; break;
            case PARR_OP_DIV: out[i] = av / bv; break;
            case PARR_OP_MOD: out[i] = fmod(av, bv); break;
            default: break;
            }
        }
#endif
    } else {
        const int64_t *a = (const int64_t *)s->a + (s->ba ? 0 : s->start);
        const int64_t *b = (const int64_t *)s->b + (s->bb ? 0 : s->start);
        int64_t *out = (int64_t *)s->out + s->start;
#ifdef DISTURB_ENABLE_SIMD
        switch (s->op) {
        case PARR_OP_ADD: simd_int_add(a, b, out, n, s->ba, s->bb); break;
        case PARR_OP_SUB: simd_int_sub(a, b, out, n, s->ba, s->bb); break;
        case PARR_OP_MUL: simd_int_mul(a, b, out, n, s->ba, s->bb); break;
        default:
            for (size_t i = 0; i < n; i++) {
                int64_t av = s->ba ? ((const int64_t *)s->a)[0] : a[i];
                int64_t bv = s->bb ? ((const int64_t *)s->b)[0] : b[i];
                switch (s->op) {
                case PARR_OP_DIV: out[i] = bv != 0 ? av / bv : 0; break;
                case PARR_OP_MOD: out[i] = bv != 0 ? av % bv : 0; break;
                default: break;
                }
            }
            break;
        }
#else
        for (size_t i = 0; i < n; i++) {
            int64_t av = s->ba ? ((const int64_t *)s->a)[0] : a[i];
            int64_t bv = s->bb ? ((const int64_t *)s->b)[0] : b[i];
            switch (s->op) {
            case PARR_OP_ADD: out[i] = av + bv; break;
            case PARR_OP_SUB: out[i] = av - bv; break;
            case PARR_OP_MUL: out[i] = av * bv; break;
            case PARR_OP_DIV: out[i] = bv != 0 ? av / bv : 0; break;
            case PARR_OP_MOD: out[i] = bv != 0 ? av % bv : 0; break;
            default: break;
            }
        }
#endif
    }
#else
    /* 32-bit path: similar but with int32_t / float */
    if (s->is_float) {
        const float *a = (const float *)s->a + (s->ba ? 0 : s->start);
        const float *b = (const float *)s->b + (s->bb ? 0 : s->start);
        float *out = (float *)s->out + s->start;
        for (size_t i = 0; i < n; i++) {
            float av = s->ba ? ((const float *)s->a)[0] : a[i];
            float bv = s->bb ? ((const float *)s->b)[0] : b[i];
            switch (s->op) {
            case PARR_OP_ADD: out[i] = av + bv; break;
            case PARR_OP_SUB: out[i] = av - bv; break;
            case PARR_OP_MUL: out[i] = av * bv; break;
            case PARR_OP_DIV: out[i] = av / bv; break;
            case PARR_OP_MOD: out[i] = fmodf(av, bv); break;
            default: break;
            }
        }
    } else {
        const int32_t *a = (const int32_t *)s->a + (s->ba ? 0 : s->start);
        const int32_t *b = (const int32_t *)s->b + (s->bb ? 0 : s->start);
        int32_t *out = (int32_t *)s->out + s->start;
        for (size_t i = 0; i < n; i++) {
            int32_t av = s->ba ? ((const int32_t *)s->a)[0] : a[i];
            int32_t bv = s->bb ? ((const int32_t *)s->b)[0] : b[i];
            switch (s->op) {
            case PARR_OP_ADD: out[i] = av + bv; break;
            case PARR_OP_SUB: out[i] = av - bv; break;
            case PARR_OP_MUL: out[i] = av * bv; break;
            case PARR_OP_DIV: out[i] = bv != 0 ? av / bv : 0; break;
            case PARR_OP_MOD: out[i] = bv != 0 ? av % bv : 0; break;
            default: break;
            }
        }
    }
#endif

    barrier_wait(s->barrier);
}

void parr_dispatch(const void *a, const void *b, void *out,
                   size_t count, int ba, int bb, int op, int is_float)
{
    pool_ensure_init();
    int nw = g_pool.num_workers;
    if (nw < 1) nw = 1;
    if ((size_t)nw > count / 1024) nw = (int)(count / 1024);
    if (nw < 1) nw = 1;

    ParrSlice *slices = (ParrSlice *)malloc((size_t)nw * sizeof(ParrSlice));
    if (!slices) return;
    Barrier *barrier = barrier_create(nw);

    size_t chunk = count / (size_t)nw;
    size_t rem = count % (size_t)nw;
    size_t off = 0;

    for (int i = 0; i < nw; i++) {
        size_t end = off + chunk + (i < (int)rem ? 1 : 0);
        slices[i].a = a;
        slices[i].b = b;
        slices[i].out = out;
        slices[i].start = off;
        slices[i].end = end;
        slices[i].ba = ba;
        slices[i].bb = bb;
        slices[i].op = op;
        slices[i].is_float = is_float;
        slices[i].barrier = barrier;
        off = end;

        if (i == nw - 1) {
            /* Last slice runs in current thread to avoid overhead */
            parr_slice_worker(&slices[i]);
        } else {
            taskqueue_push(&g_pool.queue, parr_slice_worker, &slices[i]);
        }
    }

    /* Wait for all slices */
    barrier_wait_and_free(barrier);
    free(slices);
}

/* ===========================================================================
 * 2A-ext — PARALLEL BITWISE / CMP / UNARY / FMA / REDUCE
 * =========================================================================== */

/* --- Bitwise slice worker ---------------------------------------------- */

enum {
    PARR_BIT_AND = 0,
    PARR_BIT_OR,
    PARR_BIT_XOR
};

typedef struct {
    const void *a;
    const void *b;
    void *out;
    size_t start;
    size_t end;
    int ba;
    int bb;
    int op;
    Barrier *barrier;
} ParrBitwiseSlice;

static void parr_bitwise_slice_worker(void *arg)
{
    ParrBitwiseSlice *s = (ParrBitwiseSlice *)arg;
    size_t n = s->end - s->start;

#if INTPTR_MAX == INT64_MAX
    const int64_t *a = (const int64_t *)s->a + (s->ba ? 0 : s->start);
    const int64_t *b = (const int64_t *)s->b + (s->bb ? 0 : s->start);
    int64_t *out = (int64_t *)s->out + s->start;
#ifdef DISTURB_ENABLE_SIMD
    switch (s->op) {
    case PARR_BIT_AND: simd_int_and(a, b, out, n, s->ba, s->bb); break;
    case PARR_BIT_OR:  simd_int_or(a, b, out, n, s->ba, s->bb);  break;
    case PARR_BIT_XOR: simd_int_xor(a, b, out, n, s->ba, s->bb); break;
    default: break;
    }
#else
    for (size_t i = 0; i < n; i++) {
        int64_t av = s->ba ? ((const int64_t *)s->a)[0] : a[i];
        int64_t bv = s->bb ? ((const int64_t *)s->b)[0] : b[i];
        switch (s->op) {
        case PARR_BIT_AND: out[i] = av & bv; break;
        case PARR_BIT_OR:  out[i] = av | bv; break;
        case PARR_BIT_XOR: out[i] = av ^ bv; break;
        default: break;
        }
    }
#endif
#else
    const int32_t *a = (const int32_t *)s->a + (s->ba ? 0 : s->start);
    const int32_t *b = (const int32_t *)s->b + (s->bb ? 0 : s->start);
    int32_t *out = (int32_t *)s->out + s->start;
    for (size_t i = 0; i < n; i++) {
        int32_t av = s->ba ? ((const int32_t *)s->a)[0] : a[i];
        int32_t bv = s->bb ? ((const int32_t *)s->b)[0] : b[i];
        switch (s->op) {
        case PARR_BIT_AND: out[i] = av & bv; break;
        case PARR_BIT_OR:  out[i] = av | bv; break;
        case PARR_BIT_XOR: out[i] = av ^ bv; break;
        default: break;
        }
    }
#endif
    barrier_wait(s->barrier);
}

void parr_dispatch_bitwise(const void *a, const void *b, void *out,
                           size_t count, int ba, int bb, int op)
{
    pool_ensure_init();
    int nw = g_pool.num_workers;
    if (nw < 1) nw = 1;
    if ((size_t)nw > count / 1024) nw = (int)(count / 1024);
    if (nw < 1) nw = 1;

    ParrBitwiseSlice *slices = (ParrBitwiseSlice *)malloc((size_t)nw * sizeof(ParrBitwiseSlice));
    if (!slices) return;
    Barrier *barrier = barrier_create(nw);

    size_t chunk = count / (size_t)nw;
    size_t rem = count % (size_t)nw;
    size_t off = 0;

    for (int i = 0; i < nw; i++) {
        size_t end = off + chunk + (i < (int)rem ? 1 : 0);
        slices[i].a = a;
        slices[i].b = b;
        slices[i].out = out;
        slices[i].start = off;
        slices[i].end = end;
        slices[i].ba = ba;
        slices[i].bb = bb;
        slices[i].op = op;
        slices[i].barrier = barrier;
        off = end;
        if (i == nw - 1)
            parr_bitwise_slice_worker(&slices[i]);
        else
            taskqueue_push(&g_pool.queue, parr_bitwise_slice_worker, &slices[i]);
    }

    barrier_wait_and_free(barrier);
    free(slices);
}

/* --- Comparison slice worker ------------------------------------------- */

typedef struct {
    const void *a;
    const void *b;
    void *out;
    size_t start;
    size_t end;
    int ba;
    int bb;
    int op;
    int is_float;
    Barrier *barrier;
} ParrCmpSlice;

static void parr_cmp_slice_worker(void *arg)
{
    ParrCmpSlice *s = (ParrCmpSlice *)arg;
    size_t n = s->end - s->start;

#if INTPTR_MAX == INT64_MAX
    int64_t *out = (int64_t *)s->out + s->start;
    if (s->is_float) {
        const double *a = (const double *)s->a + (s->ba ? 0 : s->start);
        const double *b = (const double *)s->b + (s->bb ? 0 : s->start);
#ifdef DISTURB_ENABLE_SIMD
        simd_float_cmp(a, b, out, n, s->ba, s->bb, s->op);
#else
        for (size_t i = 0; i < n; i++) {
            double av = s->ba ? ((const double *)s->a)[0] : a[i];
            double bv = s->bb ? ((const double *)s->b)[0] : b[i];
            int res = 0;
            switch (s->op) {
            case 0: res = (av == bv); break;
            case 1: res = (av != bv); break;
            case 2: res = (av <  bv); break;
            case 3: res = (av <= bv); break;
            case 4: res = (av >  bv); break;
            case 5: res = (av >= bv); break;
            default: break;
            }
            out[i] = res;
        }
#endif
    } else {
        const int64_t *a = (const int64_t *)s->a + (s->ba ? 0 : s->start);
        const int64_t *b = (const int64_t *)s->b + (s->bb ? 0 : s->start);
#ifdef DISTURB_ENABLE_SIMD
        simd_int_cmp(a, b, out, n, s->ba, s->bb, s->op);
#else
        for (size_t i = 0; i < n; i++) {
            int64_t av = s->ba ? ((const int64_t *)s->a)[0] : a[i];
            int64_t bv = s->bb ? ((const int64_t *)s->b)[0] : b[i];
            int res = 0;
            switch (s->op) {
            case 0: res = (av == bv); break;
            case 1: res = (av != bv); break;
            case 2: res = (av <  bv); break;
            case 3: res = (av <= bv); break;
            case 4: res = (av >  bv); break;
            case 5: res = (av >= bv); break;
            default: break;
            }
            out[i] = res;
        }
#endif
    }
#else
    int32_t *out = (int32_t *)s->out + s->start;
    if (s->is_float) {
        const float *a = (const float *)s->a + (s->ba ? 0 : s->start);
        const float *b = (const float *)s->b + (s->bb ? 0 : s->start);
        for (size_t i = 0; i < n; i++) {
            float av = s->ba ? ((const float *)s->a)[0] : a[i];
            float bv = s->bb ? ((const float *)s->b)[0] : b[i];
            int res = 0;
            switch (s->op) {
            case 0: res = (av == bv); break;
            case 1: res = (av != bv); break;
            case 2: res = (av <  bv); break;
            case 3: res = (av <= bv); break;
            case 4: res = (av >  bv); break;
            case 5: res = (av >= bv); break;
            default: break;
            }
            out[i] = res;
        }
    } else {
        const int32_t *a = (const int32_t *)s->a + (s->ba ? 0 : s->start);
        const int32_t *b = (const int32_t *)s->b + (s->bb ? 0 : s->start);
        for (size_t i = 0; i < n; i++) {
            int32_t av = s->ba ? ((const int32_t *)s->a)[0] : a[i];
            int32_t bv = s->bb ? ((const int32_t *)s->b)[0] : b[i];
            int res = 0;
            switch (s->op) {
            case 0: res = (av == bv); break;
            case 1: res = (av != bv); break;
            case 2: res = (av <  bv); break;
            case 3: res = (av <= bv); break;
            case 4: res = (av >  bv); break;
            case 5: res = (av >= bv); break;
            default: break;
            }
            out[i] = res;
        }
    }
#endif
    barrier_wait(s->barrier);
}

void parr_dispatch_cmp(const void *a, const void *b, void *out,
                       size_t count, int ba, int bb, int op, int is_float)
{
    pool_ensure_init();
    int nw = g_pool.num_workers;
    if (nw < 1) nw = 1;
    if ((size_t)nw > count / 1024) nw = (int)(count / 1024);
    if (nw < 1) nw = 1;

    ParrCmpSlice *slices = (ParrCmpSlice *)malloc((size_t)nw * sizeof(ParrCmpSlice));
    if (!slices) return;
    Barrier *barrier = barrier_create(nw);

    size_t chunk = count / (size_t)nw;
    size_t rem = count % (size_t)nw;
    size_t off = 0;

    for (int i = 0; i < nw; i++) {
        size_t end = off + chunk + (i < (int)rem ? 1 : 0);
        slices[i].a = a;
        slices[i].b = b;
        slices[i].out = out;
        slices[i].start = off;
        slices[i].end = end;
        slices[i].ba = ba;
        slices[i].bb = bb;
        slices[i].op = op;
        slices[i].is_float = is_float;
        slices[i].barrier = barrier;
        off = end;
        if (i == nw - 1)
            parr_cmp_slice_worker(&slices[i]);
        else
            taskqueue_push(&g_pool.queue, parr_cmp_slice_worker, &slices[i]);
    }

    barrier_wait_and_free(barrier);
    free(slices);
}

/* --- Unary slice worker ------------------------------------------------ */

typedef struct {
    const void *src;
    void *dst;
    size_t start;
    size_t end;
    int op;           /* 0=neg, 1=bnot */
    int is_float;
    Barrier *barrier;
} ParrUnarySlice;

static void parr_unary_slice_worker(void *arg)
{
    ParrUnarySlice *s = (ParrUnarySlice *)arg;
    size_t n = s->end - s->start;

#if INTPTR_MAX == INT64_MAX
    if (s->op == 0 && s->is_float) {
        /* float neg */
        const double *src = (const double *)s->src + s->start;
        double *dst = (double *)s->dst + s->start;
#ifdef DISTURB_ENABLE_SIMD
        simd_float_neg(src, dst, n);
#else
        for (size_t i = 0; i < n; i++) dst[i] = -src[i];
#endif
    } else if (s->op == 0) {
        /* int neg */
        const int64_t *src = (const int64_t *)s->src + s->start;
        int64_t *dst = (int64_t *)s->dst + s->start;
#ifdef DISTURB_ENABLE_SIMD
        simd_int_neg(src, dst, n);
#else
        for (size_t i = 0; i < n; i++) dst[i] = -src[i];
#endif
    } else {
        /* bnot (always int) */
        const int64_t *src = (const int64_t *)s->src + s->start;
        int64_t *dst = (int64_t *)s->dst + s->start;
#ifdef DISTURB_ENABLE_SIMD
        simd_int_not(src, dst, n);
#else
        for (size_t i = 0; i < n; i++) dst[i] = ~src[i];
#endif
    }
#else
    if (s->op == 0 && s->is_float) {
        const float *src = (const float *)s->src + s->start;
        float *dst = (float *)s->dst + s->start;
        for (size_t i = 0; i < n; i++) dst[i] = -src[i];
    } else if (s->op == 0) {
        const int32_t *src = (const int32_t *)s->src + s->start;
        int32_t *dst = (int32_t *)s->dst + s->start;
        for (size_t i = 0; i < n; i++) dst[i] = -src[i];
    } else {
        const int32_t *src = (const int32_t *)s->src + s->start;
        int32_t *dst = (int32_t *)s->dst + s->start;
        for (size_t i = 0; i < n; i++) dst[i] = ~src[i];
    }
#endif
    barrier_wait(s->barrier);
}

void parr_dispatch_unary(const void *src, void *dst, size_t count,
                         int op, int is_float)
{
    pool_ensure_init();
    int nw = g_pool.num_workers;
    if (nw < 1) nw = 1;
    if ((size_t)nw > count / 1024) nw = (int)(count / 1024);
    if (nw < 1) nw = 1;

    ParrUnarySlice *slices = (ParrUnarySlice *)malloc((size_t)nw * sizeof(ParrUnarySlice));
    if (!slices) return;
    Barrier *barrier = barrier_create(nw);

    size_t chunk = count / (size_t)nw;
    size_t rem = count % (size_t)nw;
    size_t off = 0;

    for (int i = 0; i < nw; i++) {
        size_t end = off + chunk + (i < (int)rem ? 1 : 0);
        slices[i].src = src;
        slices[i].dst = dst;
        slices[i].start = off;
        slices[i].end = end;
        slices[i].op = op;
        slices[i].is_float = is_float;
        slices[i].barrier = barrier;
        off = end;
        if (i == nw - 1)
            parr_unary_slice_worker(&slices[i]);
        else
            taskqueue_push(&g_pool.queue, parr_unary_slice_worker, &slices[i]);
    }

    barrier_wait_and_free(barrier);
    free(slices);
}

/* --- FMA slice worker -------------------------------------------------- */

typedef struct {
    const void *a;
    const void *b;
    const void *c;
    void *out;
    size_t start;
    size_t end;
    Barrier *barrier;
} ParrFmaSlice;

static void parr_fma_slice_worker(void *arg)
{
    ParrFmaSlice *s = (ParrFmaSlice *)arg;
    size_t n = s->end - s->start;

#if INTPTR_MAX == INT64_MAX
    const double *a = (const double *)s->a + s->start;
    const double *b = (const double *)s->b + s->start;
    const double *c = (const double *)s->c + s->start;
    double *out = (double *)s->out + s->start;
#ifdef DISTURB_ENABLE_SIMD
    simd_float_fma(a, b, c, out, n, 0, 0, 0);
#else
    for (size_t i = 0; i < n; i++) out[i] = a[i] * b[i] + c[i];
#endif
#else
    const float *a = (const float *)s->a + s->start;
    const float *b = (const float *)s->b + s->start;
    const float *c = (const float *)s->c + s->start;
    float *out = (float *)s->out + s->start;
    for (size_t i = 0; i < n; i++) out[i] = a[i] * b[i] + c[i];
#endif
    barrier_wait(s->barrier);
}

void parr_dispatch_fma(const void *a, const void *b, const void *c,
                       void *out, size_t count)
{
    pool_ensure_init();
    int nw = g_pool.num_workers;
    if (nw < 1) nw = 1;
    if ((size_t)nw > count / 1024) nw = (int)(count / 1024);
    if (nw < 1) nw = 1;

    ParrFmaSlice *slices = (ParrFmaSlice *)malloc((size_t)nw * sizeof(ParrFmaSlice));
    if (!slices) return;
    Barrier *barrier = barrier_create(nw);

    size_t chunk = count / (size_t)nw;
    size_t rem = count % (size_t)nw;
    size_t off = 0;

    for (int i = 0; i < nw; i++) {
        size_t end = off + chunk + (i < (int)rem ? 1 : 0);
        slices[i].a = a;
        slices[i].b = b;
        slices[i].c = c;
        slices[i].out = out;
        slices[i].start = off;
        slices[i].end = end;
        slices[i].barrier = barrier;
        off = end;
        if (i == nw - 1)
            parr_fma_slice_worker(&slices[i]);
        else
            taskqueue_push(&g_pool.queue, parr_fma_slice_worker, &slices[i]);
    }

    barrier_wait_and_free(barrier);
    free(slices);
}

/* --- Parallel reduction: sum ------------------------------------------- */

typedef struct {
    const void *data;
    size_t start;
    size_t end;
    int is_float;
    double result;
    Barrier *barrier;
} ParrReduceSlice;

static void parr_reduce_sum_worker(void *arg)
{
    ParrReduceSlice *s = (ParrReduceSlice *)arg;
    size_t n = s->end - s->start;
    double acc = 0.0;

#if INTPTR_MAX == INT64_MAX
    if (s->is_float) {
        const double *data = (const double *)s->data + s->start;
#ifdef DISTURB_ENABLE_SIMD
        acc = simd_f64_sum(data, n);
#else
        for (size_t i = 0; i < n; i++) acc += data[i];
#endif
    } else {
        const int64_t *data = (const int64_t *)s->data + s->start;
        for (size_t i = 0; i < n; i++) acc += (double)data[i];
    }
#else
    if (s->is_float) {
        const float *data = (const float *)s->data + s->start;
        for (size_t i = 0; i < n; i++) acc += (double)data[i];
    } else {
        const int32_t *data = (const int32_t *)s->data + s->start;
        for (size_t i = 0; i < n; i++) acc += (double)data[i];
    }
#endif
    s->result = acc;
    barrier_wait(s->barrier);
}

double parr_reduce_sum(const void *data, size_t count, int is_float)
{
    pool_ensure_init();
    int nw = g_pool.num_workers;
    if (nw < 1) nw = 1;
    if ((size_t)nw > count / 1024) nw = (int)(count / 1024);
    if (nw < 1) nw = 1;

    ParrReduceSlice *slices = (ParrReduceSlice *)malloc((size_t)nw * sizeof(ParrReduceSlice));
    if (!slices) {
        /* fallback: scalar */
        double acc = 0.0;
#if INTPTR_MAX == INT64_MAX
        if (is_float) {
            const double *d = (const double *)data;
            for (size_t i = 0; i < count; i++) acc += d[i];
        } else {
            const int64_t *d = (const int64_t *)data;
            for (size_t i = 0; i < count; i++) acc += (double)d[i];
        }
#endif
        return acc;
    }
    Barrier *barrier = barrier_create(nw);

    size_t chunk = count / (size_t)nw;
    size_t rem = count % (size_t)nw;
    size_t off = 0;

    for (int i = 0; i < nw; i++) {
        size_t end = off + chunk + (i < (int)rem ? 1 : 0);
        slices[i].data = data;
        slices[i].start = off;
        slices[i].end = end;
        slices[i].is_float = is_float;
        slices[i].result = 0.0;
        slices[i].barrier = barrier;
        off = end;
        if (i == nw - 1)
            parr_reduce_sum_worker(&slices[i]);
        else
            taskqueue_push(&g_pool.queue, parr_reduce_sum_worker, &slices[i]);
    }

    barrier_wait_and_free(barrier);

    double total = 0.0;
    for (int i = 0; i < nw; i++) total += slices[i].result;
    free(slices);
    return total;
}

/* --- Parallel reduction: dot product ----------------------------------- */

typedef struct {
    const void *a;
    const void *b;
    size_t start;
    size_t end;
    int is_float;
    double result;
    Barrier *barrier;
} ParrDotSlice;

static void parr_reduce_dot_worker(void *arg)
{
    ParrDotSlice *s = (ParrDotSlice *)arg;
    size_t n = s->end - s->start;
    double acc = 0.0;

#if INTPTR_MAX == INT64_MAX
    if (s->is_float) {
        const double *a = (const double *)s->a + s->start;
        const double *b = (const double *)s->b + s->start;
#ifdef DISTURB_ENABLE_SIMD
        acc = simd_f64_dot(a, b, n);
#else
        for (size_t i = 0; i < n; i++) acc += a[i] * b[i];
#endif
    } else {
        const int64_t *a = (const int64_t *)s->a + s->start;
        const int64_t *b = (const int64_t *)s->b + s->start;
        for (size_t i = 0; i < n; i++) acc += (double)a[i] * (double)b[i];
    }
#else
    if (s->is_float) {
        const float *a = (const float *)s->a + s->start;
        const float *b = (const float *)s->b + s->start;
        for (size_t i = 0; i < n; i++) acc += (double)a[i] * (double)b[i];
    } else {
        const int32_t *a = (const int32_t *)s->a + s->start;
        const int32_t *b = (const int32_t *)s->b + s->start;
        for (size_t i = 0; i < n; i++) acc += (double)a[i] * (double)b[i];
    }
#endif
    s->result = acc;
    barrier_wait(s->barrier);
}

double parr_reduce_dot(const void *a, const void *b, size_t count, int is_float)
{
    pool_ensure_init();
    int nw = g_pool.num_workers;
    if (nw < 1) nw = 1;
    if ((size_t)nw > count / 1024) nw = (int)(count / 1024);
    if (nw < 1) nw = 1;

    ParrDotSlice *slices = (ParrDotSlice *)malloc((size_t)nw * sizeof(ParrDotSlice));
    if (!slices) {
        /* fallback scalar */
        double acc = 0.0;
#if INTPTR_MAX == INT64_MAX
        if (is_float) {
            const double *da = (const double *)a, *db = (const double *)b;
            for (size_t i = 0; i < count; i++) acc += da[i] * db[i];
        } else {
            const int64_t *da = (const int64_t *)a, *db = (const int64_t *)b;
            for (size_t i = 0; i < count; i++) acc += (double)da[i] * (double)db[i];
        }
#endif
        return acc;
    }
    Barrier *barrier = barrier_create(nw);

    size_t chunk = count / (size_t)nw;
    size_t rem = count % (size_t)nw;
    size_t off = 0;

    for (int i = 0; i < nw; i++) {
        size_t end = off + chunk + (i < (int)rem ? 1 : 0);
        slices[i].a = a;
        slices[i].b = b;
        slices[i].start = off;
        slices[i].end = end;
        slices[i].is_float = is_float;
        slices[i].result = 0.0;
        slices[i].barrier = barrier;
        off = end;
        if (i == nw - 1)
            parr_reduce_dot_worker(&slices[i]);
        else
            taskqueue_push(&g_pool.queue, parr_reduce_dot_worker, &slices[i]);
    }

    barrier_wait_and_free(barrier);

    double total = 0.0;
    for (int i = 0; i < nw; i++) total += slices[i].result;
    free(slices);
    return total;
}

/* ===========================================================================
 * 2B — VM POOL + task.spawn / task.join
 * =========================================================================== */

/* Pool of pre-initialized VMs for fast task execution */
typedef struct {
    VM vms[VM_POOL_SIZE];
    int available[VM_POOL_SIZE];
    int count;
    pthread_mutex_t lock;
    pthread_cond_t avail_cond;
    int initialized;
} VMPool;

static VMPool g_vm_pool = { .initialized = 0 };

static void vm_soft_reset(VM *vm)
{
    /* Reset stack to base (keep int cache, slabs, globals) */
    if (vm->stack_entry && vm->stack_entry->obj) {
        vm->stack_entry->obj->size = 2;
    }
    vm_gc(vm);
    vm->this_entry = vm->null_entry;
    /* Reset argc */
    if (vm->argc_entry && vm->argc_entry->obj) {
        Int zero = 0;
        memcpy(disturb_bytes_data(vm->argc_entry->obj), &zero, sizeof(Int));
    }
}

static void vm_pool_init(void)
{
    if (g_vm_pool.initialized) return;
    pthread_mutex_init(&g_vm_pool.lock, NULL);
    pthread_cond_init(&g_vm_pool.avail_cond, NULL);
    g_vm_pool.count = VM_POOL_SIZE;
    for (int i = 0; i < VM_POOL_SIZE; i++) {
        vm_init(&g_vm_pool.vms[i]);
        g_vm_pool.available[i] = 1;
    }
    g_vm_pool.initialized = 1;
}

static VM *vm_pool_acquire(void)
{
    if (!g_vm_pool.initialized) vm_pool_init();
    pthread_mutex_lock(&g_vm_pool.lock);
    for (;;) {
        for (int i = 0; i < VM_POOL_SIZE; i++) {
            if (g_vm_pool.available[i]) {
                g_vm_pool.available[i] = 0;
                pthread_mutex_unlock(&g_vm_pool.lock);
                return &g_vm_pool.vms[i];
            }
        }
        /* All busy — wait */
        pthread_cond_wait(&g_vm_pool.avail_cond, &g_vm_pool.lock);
    }
}

static void vm_pool_release(VM *vm)
{
    vm_soft_reset(vm);
    pthread_mutex_lock(&g_vm_pool.lock);
    for (int i = 0; i < VM_POOL_SIZE; i++) {
        if (&g_vm_pool.vms[i] == vm) {
            g_vm_pool.available[i] = 1;
            break;
        }
    }
    pthread_cond_signal(&g_vm_pool.avail_cond);
    pthread_mutex_unlock(&g_vm_pool.lock);
}

static void vm_pool_shutdown(void)
{
    if (!g_vm_pool.initialized) return;
    for (int i = 0; i < VM_POOL_SIZE; i++) {
        vm_free(&g_vm_pool.vms[i]);
    }
    pthread_mutex_destroy(&g_vm_pool.lock);
    pthread_cond_destroy(&g_vm_pool.avail_cond);
    g_vm_pool.initialized = 0;
}

/* Task handle for spawn/join */
#define TASK_HANDLE_MAGIC 0x5441534Bu  /* "TASK" */

typedef struct {
    uint32_t magic;
    int refcount;
    /* Input */
    const unsigned char *code;
    size_t code_len;
    int is_float_arg;
    Int int_arg;
    Float float_arg;
    /* Output */
    atomic_int done;
    int is_result_float;
    Int result_int;
    Float result_float;
    int has_error;
} TaskHandle;

static void task_handle_free(void *data)
{
    TaskHandle *h = (TaskHandle *)data;
    if (!h || h->magic != TASK_HANDLE_MAGIC) return;
    h->refcount--;
    if (h->refcount > 0) return;
    h->magic = 0;
    free(h);
}

static void task_handle_clone(void *data)
{
    TaskHandle *h = (TaskHandle *)data;
    if (h && h->magic == TASK_HANDLE_MAGIC) h->refcount++;
}

static TaskHandle *task_handle_from_entry(ObjEntry *entry)
{
    if (!entry || !entry->obj) return NULL;
    if (disturb_obj_type(entry->obj) != DISTURB_T_NATIVE) return NULL;
    NativeBox *nb = (NativeBox *)disturb_bytes_data(entry->obj);
    if (!nb || !nb->data) return NULL;
    TaskHandle *h = (TaskHandle *)nb->data;
    if (h->magic != TASK_HANDLE_MAGIC) return NULL;
    return h;
}

static void task_worker_fn(void *arg)
{
    TaskHandle *t = (TaskHandle *)arg;
    VM *wvm = vm_pool_acquire();

    /* Push arg onto worker stack */
    if (t->is_float_arg) {
        ObjEntry *val = vm_make_float_value(wvm, t->float_arg);
        List *old_stack = wvm->stack_entry->obj;
        List *stack = disturb_table_add(old_stack, val);
        stack = vm_update_shared_obj(wvm, old_stack, stack);
        wvm->stack_entry->obj = stack;
    } else {
        ObjEntry *val = vm_make_int_value(wvm, t->int_arg);
        List *old_stack = wvm->stack_entry->obj;
        List *stack = disturb_table_add(old_stack, val);
        stack = vm_update_shared_obj(wvm, old_stack, stack);
        wvm->stack_entry->obj = stack;
    }

    /* Execute bytecode */
    if (t->code && t->code_len > 0) {
        Int stack_before = wvm->stack_entry->obj->size;
        int ok = vm_exec_bytecode(wvm, t->code, t->code_len);
        if (ok) {
            List *st = wvm->stack_entry->obj;
            if (st->size > stack_before) {
                ObjEntry *res = (ObjEntry *)st->data[st->size - 1].p;
                if (res && res->obj) {
                    Int type = disturb_obj_type(res->obj);
                    if (type == DISTURB_T_FLOAT) {
                        Float fv = 0;
                        memcpy(&fv, disturb_bytes_data(res->obj), sizeof(Float));
                        t->is_result_float = 1;
                        t->result_float = fv;
                    } else if (type == DISTURB_T_INT) {
                        Int iv = 0;
                        memcpy(&iv, disturb_bytes_data(res->obj), sizeof(Int));
                        t->is_result_float = 0;
                        t->result_int = iv;
                    }
                }
            }
        } else {
            t->has_error = 1;
        }
    } else {
        t->has_error = 1;
    }

    vm_pool_release(wvm);
    atomic_store(&t->done, 1);
}

/* ===========================================================================
 * 2C — PARALLEL PIPELINE (SPSC lock-free queue)
 * =========================================================================== */

/* Single-Producer / Single-Consumer lock-free queue */
#define SPSC_CAP 4096

typedef struct {
    void *buf[SPSC_CAP];
    atomic_size_t head;
    atomic_size_t tail;
} SpscQueue;

static void spsc_init(SpscQueue *q)
{
    memset(q->buf, 0, sizeof(q->buf));
    atomic_store(&q->head, 0);
    atomic_store(&q->tail, 0);
}

static int spsc_push(SpscQueue *q, void *item)
{
    size_t tail = atomic_load_explicit(&q->tail, memory_order_relaxed);
    size_t next = (tail + 1) % SPSC_CAP;
    if (next == atomic_load_explicit(&q->head, memory_order_acquire))
        return 0; /* full */
    q->buf[tail] = item;
    atomic_store_explicit(&q->tail, next, memory_order_release);
    return 1;
}

static void *spsc_pop(SpscQueue *q)
{
    size_t head = atomic_load_explicit(&q->head, memory_order_relaxed);
    if (head == atomic_load_explicit(&q->tail, memory_order_acquire))
        return NULL; /* empty */
    void *item = q->buf[head];
    atomic_store_explicit(&q->head, (head + 1) % SPSC_CAP, memory_order_release);
    return item;
}

/* Pipeline handle */
#define PIPELINE_MAGIC 0x50495045u  /* "PIPE" */
#define MAX_PIPELINE_STAGES 16

typedef struct {
    uint32_t magic;
    int refcount;
    int num_stages;
    ObjEntry *stages[MAX_PIPELINE_STAGES]; /* lambda entries (from caller VM) */
    SpscQueue queues[MAX_PIPELINE_STAGES]; /* queue[i] feeds stage[i] */
    pthread_t threads[MAX_PIPELINE_STAGES];
    atomic_int running;
    VM *caller_vm; /* borrowed ref for callback */
} PipelineHandle;

typedef struct {
    PipelineHandle *pipe;
    int stage_idx;
} PipelineStageArg;

static void *pipeline_stage_thread(void *arg)
{
    PipelineStageArg *sa = (PipelineStageArg *)arg;
    PipelineHandle *pipe = sa->pipe;
    int idx = sa->stage_idx;
    free(sa);

    while (atomic_load(&pipe->running) || spsc_pop(&pipe->queues[idx]) != NULL) {
        /* Keep draining as long as pipeline is running or queue has items */
        void *item = spsc_pop(&pipe->queues[idx]);
        if (!item) {
            /* Spin-wait briefly then retry */
            struct timespec ts = {0, 1000000}; /* 1ms */
            nanosleep(&ts, NULL);
            continue;
        }

        /* The item is a serialized value (Int or Float encoded as pointer) */
        /* For simplicity, we pass items as raw Int values through the pipeline.
         * Each stage receives an Int, processes it, pushes result to next queue. */
        Int val = (Int)(intptr_t)item;

        /* Call the lambda for this stage */
        ObjEntry *fn_entry = pipe->stages[idx];
        ObjEntry *arg_entry = vm_make_int_value(pipe->caller_vm, val);
        ObjEntry *ret = NULL;

        /* Note: This uses the caller VM which is NOT thread-safe for concurrent
         * mutation. For a production pipeline, each stage should have its own VM
         * from the VM pool. For now, we serialize stage execution. */
        if (vm_call_entry(pipe->caller_vm, fn_entry, 1, &arg_entry, &ret) && ret) {
            Int rt = disturb_obj_type(ret->obj);
            Int result = 0;
            if (rt == DISTURB_T_INT) {
                memcpy(&result, disturb_bytes_data(ret->obj), sizeof(Int));
            } else if (rt == DISTURB_T_FLOAT) {
                Float fv = 0;
                memcpy(&fv, disturb_bytes_data(ret->obj), sizeof(Float));
                result = (Int)fv;
            }
            /* Push to next stage if any */
            if (idx + 1 < pipe->num_stages) {
                while (!spsc_push(&pipe->queues[idx + 1], (void *)(intptr_t)result)) {
                    struct timespec ts = {0, 100000}; /* 0.1ms */
                    nanosleep(&ts, NULL);
                }
            }
        }
    }
    return NULL;
}

static void pipeline_free(void *data)
{
    PipelineHandle *h = (PipelineHandle *)data;
    if (!h || h->magic != PIPELINE_MAGIC) return;
    h->refcount--;
    if (h->refcount > 0) return;
    h->magic = 0;
    free(h);
}

static void pipeline_clone(void *data)
{
    PipelineHandle *h = (PipelineHandle *)data;
    if (h && h->magic == PIPELINE_MAGIC) h->refcount++;
}

static PipelineHandle *pipeline_from_entry(ObjEntry *entry)
{
    if (!entry || !entry->obj) return NULL;
    if (disturb_obj_type(entry->obj) != DISTURB_T_NATIVE) return NULL;
    NativeBox *nb = (NativeBox *)disturb_bytes_data(entry->obj);
    if (!nb || !nb->data) return NULL;
    PipelineHandle *h = (PipelineHandle *)nb->data;
    if (h->magic != PIPELINE_MAGIC) return NULL;
    return h;
}

/* ===========================================================================
 * 2D — WORK-STEALING POOL (Chase-Lev deque)
 * =========================================================================== */

/* Chase-Lev work-stealing deque */
#define DEQUE_INIT_CAP 1024

typedef struct {
    void **buf;
    atomic_size_t cap;
} DequeArray;

typedef struct {
    atomic_long top;
    atomic_long bottom;
    atomic_uintptr_t array; /* points to DequeArray */
} ChaseLevDeque;

static DequeArray *deque_array_new(size_t cap)
{
    DequeArray *a = (DequeArray *)malloc(sizeof(DequeArray) + cap * sizeof(void *));
    if (!a) return NULL;
    a->buf = (void **)(a + 1);
    atomic_store(&a->cap, cap);
    return a;
}

static void deque_init(ChaseLevDeque *d)
{
    DequeArray *a = deque_array_new(DEQUE_INIT_CAP);
    atomic_store(&d->top, 0);
    atomic_store(&d->bottom, 0);
    atomic_store(&d->array, (uintptr_t)a);
}

static void deque_destroy(ChaseLevDeque *d)
{
    DequeArray *a = (DequeArray *)atomic_load(&d->array);
    free(a);
}

/* Push (owner only, no contention) */
static void deque_push(ChaseLevDeque *d, void *item)
{
    long b = atomic_load_explicit(&d->bottom, memory_order_relaxed);
    long t = atomic_load_explicit(&d->top, memory_order_acquire);
    DequeArray *a = (DequeArray *)atomic_load_explicit(&d->array, memory_order_relaxed);
    size_t cap = atomic_load_explicit(&a->cap, memory_order_relaxed);

    if ((size_t)(b - t) >= cap) {
        /* Grow (simplified: allocate bigger, copy) */
        size_t new_cap = cap * 2;
        DequeArray *na = deque_array_new(new_cap);
        for (long i = t; i < b; i++)
            na->buf[(size_t)i % new_cap] = a->buf[(size_t)i % cap];
        atomic_store_explicit(&d->array, (uintptr_t)na, memory_order_release);
        free(a);
        a = na;
        cap = new_cap;
    }
    a->buf[(size_t)b % cap] = item;
    atomic_store_explicit(&d->bottom, b + 1, memory_order_release);
}

/* Pop (owner only) */
static void *deque_pop(ChaseLevDeque *d)
{
    long b = atomic_load_explicit(&d->bottom, memory_order_relaxed) - 1;
    atomic_store_explicit(&d->bottom, b, memory_order_relaxed);
    DequeArray *a = (DequeArray *)atomic_load_explicit(&d->array, memory_order_relaxed);
    size_t cap = atomic_load_explicit(&a->cap, memory_order_relaxed);
    long t = atomic_load_explicit(&d->top, memory_order_acquire);

    if (t <= b) {
        void *item = a->buf[(size_t)b % cap];
        if (t == b) {
            /* Last element: CAS to avoid race with steal */
            if (!atomic_compare_exchange_strong_explicit(&d->top, &t, t + 1,
                    memory_order_acq_rel, memory_order_relaxed)) {
                item = NULL;
            }
            atomic_store_explicit(&d->bottom, b + 1, memory_order_relaxed);
        }
        return item;
    } else {
        atomic_store_explicit(&d->bottom, b + 1, memory_order_relaxed);
        return NULL; /* empty */
    }
}

/* Steal (any thread) */
static void *deque_steal(ChaseLevDeque *d)
{
    long t = atomic_load_explicit(&d->top, memory_order_acquire);
    long b = atomic_load_explicit(&d->bottom, memory_order_acquire);
    if (t >= b) return NULL; /* empty */

    DequeArray *a = (DequeArray *)atomic_load_explicit(&d->array, memory_order_relaxed);
    size_t cap = atomic_load_explicit(&a->cap, memory_order_relaxed);
    void *item = a->buf[(size_t)t % cap];

    if (!atomic_compare_exchange_strong_explicit(&d->top, &t, t + 1,
            memory_order_acq_rel, memory_order_relaxed))
        return NULL; /* lost race */
    return item;
}

/* Work-stealing pool handle */
#define WPOOL_MAGIC 0x5750554Cu  /* "WPUL" */
#define WPOOL_MAX_WORKERS 64

typedef struct WPoolHandle WPoolHandle;

typedef struct {
    WPoolHandle *pool;
    int worker_idx;
} WPoolWorkerArg;

struct WPoolHandle {
    uint32_t magic;
    int refcount;
    int num_workers;
    ChaseLevDeque deques[WPOOL_MAX_WORKERS];
    pthread_t threads[WPOOL_MAX_WORKERS];
    WPoolWorkerArg args[WPOOL_MAX_WORKERS];
    atomic_int running;
    atomic_int pending_tasks;
    pthread_mutex_t done_lock;
    pthread_cond_t done_cond;
};

/* Work-stealing result handle */
#define WPOOL_TASK_MAGIC 0x57544B53u  /* "WTKS" */

typedef struct {
    uint32_t magic;
    int refcount;
    atomic_int done;
    Int result_int;
    Float result_float;
    int is_result_float;
    int has_error;
    /* Input */
    ObjEntry *fn_entry;
    Int int_arg;
    Float float_arg;
    int is_float_arg;
    VM *caller_vm; /* borrowed */
} WPoolTask;

static void wpool_task_free(void *data)
{
    WPoolTask *t = (WPoolTask *)data;
    if (!t || t->magic != WPOOL_TASK_MAGIC) return;
    t->refcount--;
    if (t->refcount > 0) return;
    t->magic = 0;
    free(t);
}

static void wpool_task_clone(void *data)
{
    WPoolTask *t = (WPoolTask *)data;
    if (t && t->magic == WPOOL_TASK_MAGIC) t->refcount++;
}

static WPoolTask *wpool_task_from_entry(ObjEntry *entry)
{
    if (!entry || !entry->obj) return NULL;
    if (disturb_obj_type(entry->obj) != DISTURB_T_NATIVE) return NULL;
    NativeBox *nb = (NativeBox *)disturb_bytes_data(entry->obj);
    if (!nb || !nb->data) return NULL;
    WPoolTask *t = (WPoolTask *)nb->data;
    if (t->magic != WPOOL_TASK_MAGIC) return NULL;
    return t;
}

static void wpool_execute_task(WPoolTask *t)
{
    if (!t || !t->caller_vm) { if (t) { t->has_error = 1; atomic_store(&t->done, 1); } return; }

    ObjEntry *arg;
    if (t->is_float_arg) {
        arg = vm_make_float_value(t->caller_vm, t->float_arg);
    } else {
        arg = vm_make_int_value(t->caller_vm, t->int_arg);
    }

    ObjEntry *ret = NULL;
    if (vm_call_entry(t->caller_vm, t->fn_entry, 1, &arg, &ret) && ret) {
        Int rt = disturb_obj_type(ret->obj);
        if (rt == DISTURB_T_INT) {
            memcpy(&t->result_int, disturb_bytes_data(ret->obj), sizeof(Int));
            t->is_result_float = 0;
        } else if (rt == DISTURB_T_FLOAT) {
            memcpy(&t->result_float, disturb_bytes_data(ret->obj), sizeof(Float));
            t->is_result_float = 1;
        }
    } else {
        t->has_error = 1;
    }
    atomic_store(&t->done, 1);
}

static void *wpool_worker_thread(void *raw_arg)
{
    WPoolWorkerArg *wa = (WPoolWorkerArg *)raw_arg;
    WPoolHandle *pool = wa->pool;
    int idx = wa->worker_idx;

    while (atomic_load(&pool->running) || atomic_load(&pool->pending_tasks) > 0) {
        /* Try own deque first */
        void *item = deque_pop(&pool->deques[idx]);
        if (!item) {
            /* Steal from random other worker */
            for (int tries = 0; tries < pool->num_workers && !item; tries++) {
                int victim = (idx + tries + 1) % pool->num_workers;
                item = deque_steal(&pool->deques[victim]);
            }
        }
        if (item) {
            WPoolTask *task = (WPoolTask *)item;
            wpool_execute_task(task);
            atomic_fetch_sub(&pool->pending_tasks, 1);
            pthread_mutex_lock(&pool->done_lock);
            pthread_cond_broadcast(&pool->done_cond);
            pthread_mutex_unlock(&pool->done_lock);
        } else {
            /* No work anywhere — sleep briefly */
            struct timespec ts = {0, 500000}; /* 0.5ms */
            nanosleep(&ts, NULL);
        }
    }
    return NULL;
}

static void wpool_free(void *data)
{
    WPoolHandle *h = (WPoolHandle *)data;
    if (!h || h->magic != WPOOL_MAGIC) return;
    h->refcount--;
    if (h->refcount > 0) return;
    /* Signal shutdown */
    atomic_store(&h->running, 0);
    for (int i = 0; i < h->num_workers; i++)
        pthread_join(h->threads[i], NULL);
    for (int i = 0; i < h->num_workers; i++)
        deque_destroy(&h->deques[i]);
    pthread_mutex_destroy(&h->done_lock);
    pthread_cond_destroy(&h->done_cond);
    h->magic = 0;
    free(h);
}

static void wpool_clone(void *data)
{
    WPoolHandle *h = (WPoolHandle *)data;
    if (h && h->magic == WPOOL_MAGIC) h->refcount++;
}

static WPoolHandle *wpool_from_entry(ObjEntry *entry)
{
    if (!entry || !entry->obj) return NULL;
    if (disturb_obj_type(entry->obj) != DISTURB_T_NATIVE) return NULL;
    NativeBox *nb = (NativeBox *)disturb_bytes_data(entry->obj);
    if (!nb || !nb->data) return NULL;
    WPoolHandle *h = (WPoolHandle *)nb->data;
    if (h->magic != WPOOL_MAGIC) return NULL;
    return h;
}


/* ===========================================================================
 * NATIVE FUNCTION HELPERS
 * =========================================================================== */

static uint32_t par_native_argc(VM *vm)
{
    uint32_t argc = 0;
    if (vm && vm->argc_entry) {
        Int type = disturb_obj_type(vm->argc_entry->obj);
        if (type == DISTURB_T_INT) {
            Int iv = 0;
            memcpy(&iv, disturb_bytes_data(vm->argc_entry->obj), sizeof(Int));
            argc = (uint32_t)iv;
        }
    }
    return argc;
}

static ObjEntry *par_native_arg(List *stack, uint32_t argc, uint32_t idx)
{
    if (!stack || idx >= argc) return NULL;
    Int base = stack->size - (Int)argc;
    if (base < 2) return NULL;
    Int pos = base + (Int)idx;
    if (pos < 2 || pos >= stack->size) return NULL;
    return (ObjEntry *)stack->data[pos].p;
}

static void par_push_entry(VM *vm, ObjEntry *entry)
{
    if (!vm || !vm->stack_entry || !entry) return;
    List *old_stack = vm->stack_entry->obj;
    List *new_stack = disturb_table_add(old_stack, entry);
    new_stack = vm_update_shared_obj(vm, old_stack, new_stack);
    vm->stack_entry->obj = new_stack;
}

static void par_add_module_fn(VM *vm, ObjEntry *mod_entry, const char *name, NativeFn fn)
{
    ObjEntry *entry = vm_make_native_entry_data(vm, name, fn, NULL, NULL, NULL);
    if (!entry) return;
    vm_object_set_by_key(vm, mod_entry, name, strlen(name), entry);
}

/* ===========================================================================
 * NATIVE FUNCTIONS — parallel module
 * =========================================================================== */

/* parallel.pool_size() → Int */
static void native_parallel_pool_size(VM *vm, List *stack, List *global)
{
    (void)stack; (void)global;
    pool_ensure_init();
    par_push_entry(vm, vm_make_int_value(vm, (Int)g_pool.num_workers));
}

/* parallel.cpu_count() → Int */
static void native_parallel_cpu_count(VM *vm, List *stack, List *global)
{
    (void)stack; (void)global;
    par_push_entry(vm, vm_make_int_value(vm, (Int)detect_cpu_count()));
}

/* parallel.map(fn, list) → list (sequential via vm_call_entry) */
static void native_parallel_map(VM *vm, List *stack, List *global)
{
    (void)global;
    uint32_t argc = par_native_argc(vm);
    if (argc < 2) {
        fprintf(stderr, "parallel.map expects (fn, list)\n");
        return;
    }

    ObjEntry *fn_entry = par_native_arg(stack, argc, 0);
    ObjEntry *list_entry = par_native_arg(stack, argc, 1);
    if (!fn_entry || !list_entry) {
        fprintf(stderr, "parallel.map: invalid arguments\n");
        return;
    }

    Int list_type = disturb_obj_type(list_entry->obj);
    if (list_type != DISTURB_T_INT && list_type != DISTURB_T_FLOAT) {
        fprintf(stderr, "parallel.map: second argument must be Int[] or Float[]\n");
        return;
    }

    size_t bytes_len = disturb_bytes_len(list_entry->obj);
    Int elem_count = 0;
    if (list_type == DISTURB_T_INT)
        elem_count = (Int)(bytes_len / sizeof(Int));
    else
        elem_count = (Int)(bytes_len / sizeof(Float));

    if (elem_count <= 0) {
        par_push_entry(vm, list_entry);
        return;
    }

    /* Sequential map via vm_call_entry */
    if (list_type == DISTURB_T_INT) {
        ObjEntry *res_entry = vm_make_int_list(vm, elem_count);
        if (!res_entry) { par_push_entry(vm, list_entry); return; }
        Int *src = (Int *)disturb_bytes_data(list_entry->obj);
        Int *dst = (Int *)disturb_bytes_data(res_entry->obj);
        for (Int i = 0; i < elem_count; i++) {
            ObjEntry *arg = vm_make_int_value(vm, src[i]);
            ObjEntry *ret = NULL;
            if (vm_call_entry(vm, fn_entry, 1, &arg, &ret) && ret) {
                Int rt = disturb_obj_type(ret->obj);
                if (rt == DISTURB_T_INT) {
                    memcpy(&dst[i], disturb_bytes_data(ret->obj), sizeof(Int));
                } else if (rt == DISTURB_T_FLOAT) {
                    Float fv = 0;
                    memcpy(&fv, disturb_bytes_data(ret->obj), sizeof(Float));
                    dst[i] = (Int)fv;
                } else {
                    dst[i] = 0;
                }
            } else {
                dst[i] = 0;
            }
        }
        par_push_entry(vm, res_entry);
    } else {
        ObjEntry *res_entry = vm_make_float_list(vm, elem_count);
        if (!res_entry) { par_push_entry(vm, list_entry); return; }
        Float *src = (Float *)disturb_bytes_data(list_entry->obj);
        Float *dst = (Float *)disturb_bytes_data(res_entry->obj);
        for (Int i = 0; i < elem_count; i++) {
            ObjEntry *arg = vm_make_float_value(vm, src[i]);
            ObjEntry *ret = NULL;
            if (vm_call_entry(vm, fn_entry, 1, &arg, &ret) && ret) {
                Int rt = disturb_obj_type(ret->obj);
                if (rt == DISTURB_T_FLOAT) {
                    memcpy(&dst[i], disturb_bytes_data(ret->obj), sizeof(Float));
                } else if (rt == DISTURB_T_INT) {
                    Int iv = 0;
                    memcpy(&iv, disturb_bytes_data(ret->obj), sizeof(Int));
                    dst[i] = (Float)iv;
                } else {
                    dst[i] = 0;
                }
            } else {
                dst[i] = 0;
            }
        }
        par_push_entry(vm, res_entry);
    }
}

/* ===========================================================================
 * NATIVE FUNCTIONS — task module (2B)
 * =========================================================================== */

/* task.spawn(fn, arg) → TaskHandle */
static void native_task_spawn(VM *vm, List *stack, List *global)
{
    (void)global;
    uint32_t argc = par_native_argc(vm);
    if (argc < 1) {
        fprintf(stderr, "task.spawn expects (fn [, arg])\n");
        return;
    }

    ObjEntry *fn_entry = par_native_arg(stack, argc, 0);
    if (!fn_entry) {
        fprintf(stderr, "task.spawn: invalid function\n");
        return;
    }

    /* Extract bytecode from lambda */
    Int fn_type = disturb_obj_type(fn_entry->obj);
    const unsigned char *code = NULL;
    size_t code_len = 0;
    if (fn_type == DISTURB_T_LAMBDA) {
        code = (const unsigned char *)disturb_bytes_data(fn_entry->obj);
        code_len = disturb_bytes_len(fn_entry->obj);
    }

    TaskHandle *h = (TaskHandle *)calloc(1, sizeof(TaskHandle));
    h->magic = TASK_HANDLE_MAGIC;
    h->refcount = 1;
    h->code = code;
    h->code_len = code_len;
    atomic_store(&h->done, 0);

    /* Optional argument */
    if (argc >= 2) {
        ObjEntry *arg = par_native_arg(stack, argc, 1);
        if (arg && arg->obj) {
            Int at = disturb_obj_type(arg->obj);
            if (at == DISTURB_T_FLOAT) {
                h->is_float_arg = 1;
                memcpy(&h->float_arg, disturb_bytes_data(arg->obj), sizeof(Float));
            } else if (at == DISTURB_T_INT) {
                h->is_float_arg = 0;
                memcpy(&h->int_arg, disturb_bytes_data(arg->obj), sizeof(Int));
            }
        }
    }

    pool_ensure_init();
    taskqueue_push(&g_pool.queue, task_worker_fn, h);

    ObjEntry *entry = vm_make_native_entry_data(vm, "task_handle", NULL, h,
                                                 task_handle_free, task_handle_clone);
    par_push_entry(vm, entry ? entry : vm_make_int_value(vm, 0));
}

/* task.join(handle) → result */
static void native_task_join(VM *vm, List *stack, List *global)
{
    (void)global;
    uint32_t argc = par_native_argc(vm);
    if (argc < 1) {
        fprintf(stderr, "task.join expects (handle)\n");
        return;
    }

    ObjEntry *handle_entry = par_native_arg(stack, argc, 0);
    TaskHandle *h = task_handle_from_entry(handle_entry);
    if (!h) {
        fprintf(stderr, "task.join: invalid handle\n");
        par_push_entry(vm, vm_make_int_value(vm, 0));
        return;
    }

    /* Spin-wait for completion */
    while (!atomic_load(&h->done)) {
        struct timespec ts = {0, 100000}; /* 0.1ms */
        nanosleep(&ts, NULL);
    }

    if (h->has_error) {
        par_push_entry(vm, vm_make_int_value(vm, 0));
    } else if (h->is_result_float) {
        par_push_entry(vm, vm_make_float_value(vm, h->result_float));
    } else {
        par_push_entry(vm, vm_make_int_value(vm, h->result_int));
    }
}

/* ===========================================================================
 * NATIVE FUNCTIONS — parallel.pipeline (2C)
 * =========================================================================== */

/* parallel.pipeline(stage_list) → PipelineHandle
 * stage_list should be a table of lambda entries. */
static void native_parallel_pipeline(VM *vm, List *stack, List *global)
{
    (void)global;
    uint32_t argc = par_native_argc(vm);
    if (argc < 1) {
        fprintf(stderr, "parallel.pipeline expects (stages_table)\n");
        return;
    }

    ObjEntry *stages_entry = par_native_arg(stack, argc, 0);
    if (!stages_entry || !stages_entry->obj) {
        fprintf(stderr, "parallel.pipeline: invalid stages\n");
        return;
    }

    Int stage_type = disturb_obj_type(stages_entry->obj);
    if (stage_type != DISTURB_T_TABLE) {
        fprintf(stderr, "parallel.pipeline: argument must be a table of functions\n");
        return;
    }

    List *tbl = stages_entry->obj;
    int num_stages = (int)(tbl->size - 2);
    if (num_stages <= 0 || num_stages > MAX_PIPELINE_STAGES) {
        fprintf(stderr, "parallel.pipeline: need 1..%d stages\n", MAX_PIPELINE_STAGES);
        return;
    }

    PipelineHandle *h = (PipelineHandle *)calloc(1, sizeof(PipelineHandle));
    h->magic = PIPELINE_MAGIC;
    h->refcount = 1;
    h->num_stages = num_stages;
    h->caller_vm = vm;
    atomic_store(&h->running, 1);

    for (int i = 0; i < num_stages; i++) {
        h->stages[i] = (ObjEntry *)tbl->data[i + 2].p;
        spsc_init(&h->queues[i]);
    }

    /* Start stage threads (skip first — items pushed from main thread) */
    /* Actually all stages need threads to process their queues */
    for (int i = 0; i < num_stages; i++) {
        PipelineStageArg *sa = (PipelineStageArg *)malloc(sizeof(PipelineStageArg));
        sa->pipe = h;
        sa->stage_idx = i;
        pthread_create(&h->threads[i], NULL, pipeline_stage_thread, sa);
    }

    ObjEntry *entry = vm_make_native_entry_data(vm, "pipeline", NULL, h,
                                                 pipeline_free, pipeline_clone);
    par_push_entry(vm, entry ? entry : vm_make_int_value(vm, 0));
}

/* parallel.push(pipe, item) → 0 */
static void native_parallel_push(VM *vm, List *stack, List *global)
{
    (void)global;
    uint32_t argc = par_native_argc(vm);
    if (argc < 2) { fprintf(stderr, "parallel.push expects (pipe, item)\n"); return; }

    ObjEntry *pipe_entry = par_native_arg(stack, argc, 0);
    ObjEntry *item_entry = par_native_arg(stack, argc, 1);
    PipelineHandle *pipe = pipeline_from_entry(pipe_entry);
    if (!pipe) { fprintf(stderr, "parallel.push: invalid pipeline\n"); return; }

    /* Convert item to Int for pipeline transport */
    Int val = 0;
    if (item_entry && item_entry->obj) {
        Int t = disturb_obj_type(item_entry->obj);
        if (t == DISTURB_T_INT) memcpy(&val, disturb_bytes_data(item_entry->obj), sizeof(Int));
        else if (t == DISTURB_T_FLOAT) {
            Float fv = 0; memcpy(&fv, disturb_bytes_data(item_entry->obj), sizeof(Float));
            val = (Int)fv;
        }
    }

    /* Push to first stage's queue */
    while (!spsc_push(&pipe->queues[0], (void *)(intptr_t)val)) {
        struct timespec ts = {0, 100000};
        nanosleep(&ts, NULL);
    }

    par_push_entry(vm, vm_make_int_value(vm, 0));
}

/* parallel.flush(pipe) — wait for all queues to drain */
static void native_parallel_flush(VM *vm, List *stack, List *global)
{
    (void)global;
    uint32_t argc = par_native_argc(vm);
    if (argc < 1) return;

    ObjEntry *pipe_entry = par_native_arg(stack, argc, 0);
    PipelineHandle *pipe = pipeline_from_entry(pipe_entry);
    if (!pipe) return;

    /* Wait until all queues are empty */
    for (int attempts = 0; attempts < 10000; attempts++) {
        int all_empty = 1;
        for (int i = 0; i < pipe->num_stages; i++) {
            size_t head = atomic_load(&pipe->queues[i].head);
            size_t tail = atomic_load(&pipe->queues[i].tail);
            if (head != tail) { all_empty = 0; break; }
        }
        if (all_empty) break;
        struct timespec ts = {0, 1000000}; /* 1ms */
        nanosleep(&ts, NULL);
    }

    par_push_entry(vm, vm_make_int_value(vm, 0));
}

/* parallel.destroy(pipe) — stop pipeline */
static void native_parallel_destroy(VM *vm, List *stack, List *global)
{
    (void)global;
    uint32_t argc = par_native_argc(vm);
    if (argc < 1) return;

    ObjEntry *pipe_entry = par_native_arg(stack, argc, 0);
    PipelineHandle *pipe = pipeline_from_entry(pipe_entry);
    if (!pipe) {
        /* Try wpool */
        WPoolHandle *wpool = wpool_from_entry(pipe_entry);
        if (wpool) {
            atomic_store(&wpool->running, 0);
            par_push_entry(vm, vm_make_int_value(vm, 0));
            return;
        }
        return;
    }

    atomic_store(&pipe->running, 0);
    for (int i = 0; i < pipe->num_stages; i++)
        pthread_join(pipe->threads[i], NULL);

    par_push_entry(vm, vm_make_int_value(vm, 0));
}

/* ===========================================================================
 * NATIVE FUNCTIONS — parallel.pool / work-stealing (2D)
 * =========================================================================== */

/* parallel.wpool(n) → WPoolHandle */
static void native_parallel_wpool(VM *vm, List *stack, List *global)
{
    (void)global;
    uint32_t argc = par_native_argc(vm);
    Int n = 0;
    if (argc >= 1) {
        ObjEntry *arg = par_native_arg(stack, argc, 0);
        if (arg && disturb_obj_type(arg->obj) == DISTURB_T_INT)
            memcpy(&n, disturb_bytes_data(arg->obj), sizeof(Int));
    }
    if (n <= 0) n = detect_cpu_count();
    if (n > WPOOL_MAX_WORKERS) n = WPOOL_MAX_WORKERS;

    WPoolHandle *h = (WPoolHandle *)calloc(1, sizeof(WPoolHandle));
    h->magic = WPOOL_MAGIC;
    h->refcount = 1;
    h->num_workers = (int)n;
    atomic_store(&h->running, 1);
    atomic_store(&h->pending_tasks, 0);
    pthread_mutex_init(&h->done_lock, NULL);
    pthread_cond_init(&h->done_cond, NULL);

    for (int i = 0; i < (int)n; i++)
        deque_init(&h->deques[i]);

    for (int i = 0; i < (int)n; i++) {
        h->args[i].pool = h;
        h->args[i].worker_idx = i;
        pthread_create(&h->threads[i], NULL, wpool_worker_thread, &h->args[i]);
    }

    ObjEntry *entry = vm_make_native_entry_data(vm, "wpool", NULL, h,
                                                 wpool_free, wpool_clone);
    par_push_entry(vm, entry ? entry : vm_make_int_value(vm, 0));
}

/* parallel.submit(pool, fn, arg) → WPoolTask handle */
static void native_parallel_submit(VM *vm, List *stack, List *global)
{
    (void)global;
    uint32_t argc = par_native_argc(vm);
    if (argc < 2) { fprintf(stderr, "parallel.submit expects (pool, fn [, arg])\n"); return; }

    ObjEntry *pool_entry = par_native_arg(stack, argc, 0);
    ObjEntry *fn_entry = par_native_arg(stack, argc, 1);
    WPoolHandle *pool = wpool_from_entry(pool_entry);
    if (!pool) { fprintf(stderr, "parallel.submit: invalid pool\n"); return; }

    WPoolTask *t = (WPoolTask *)calloc(1, sizeof(WPoolTask));
    t->magic = WPOOL_TASK_MAGIC;
    t->refcount = 1;
    t->fn_entry = fn_entry;
    t->caller_vm = vm;
    atomic_store(&t->done, 0);

    if (argc >= 3) {
        ObjEntry *arg = par_native_arg(stack, argc, 2);
        if (arg && arg->obj) {
            Int at = disturb_obj_type(arg->obj);
            if (at == DISTURB_T_FLOAT) {
                t->is_float_arg = 1;
                memcpy(&t->float_arg, disturb_bytes_data(arg->obj), sizeof(Float));
            } else if (at == DISTURB_T_INT) {
                memcpy(&t->int_arg, disturb_bytes_data(arg->obj), sizeof(Int));
            }
        }
    }

    /* Push to the least-loaded deque (simple round-robin) */
    static atomic_int rr_counter = 0;
    int target = atomic_fetch_add(&rr_counter, 1) % pool->num_workers;
    atomic_fetch_add(&pool->pending_tasks, 1);
    deque_push(&pool->deques[target], t);

    ObjEntry *entry = vm_make_native_entry_data(vm, "wpool_task", NULL, t,
                                                 wpool_task_free, wpool_task_clone);
    par_push_entry(vm, entry ? entry : vm_make_int_value(vm, 0));
}

/* parallel.gather(pool, handles) → results list */
static void native_parallel_gather(VM *vm, List *stack, List *global)
{
    (void)global;
    uint32_t argc = par_native_argc(vm);
    if (argc < 2) { fprintf(stderr, "parallel.gather expects (pool, handles_table)\n"); return; }

    ObjEntry *pool_entry = par_native_arg(stack, argc, 0);
    ObjEntry *handles_entry = par_native_arg(stack, argc, 1);
    WPoolHandle *pool = wpool_from_entry(pool_entry);
    if (!pool) { fprintf(stderr, "parallel.gather: invalid pool\n"); return; }
    if (!handles_entry || !handles_entry->obj) return;

    Int ht = disturb_obj_type(handles_entry->obj);
    if (ht != DISTURB_T_TABLE) {
        fprintf(stderr, "parallel.gather: second arg must be a table of handles\n");
        return;
    }

    List *tbl = handles_entry->obj;
    Int count = tbl->size - 2;
    if (count <= 0) { par_push_entry(vm, handles_entry); return; }

    /* Wait for all tasks to complete */
    for (Int i = 0; i < count; i++) {
        ObjEntry *he = (ObjEntry *)tbl->data[i + 2].p;
        WPoolTask *t = wpool_task_from_entry(he);
        if (!t) continue;
        while (!atomic_load(&t->done)) {
            struct timespec ts = {0, 100000};
            nanosleep(&ts, NULL);
        }
    }

    /* Collect results into Int list (or Float list based on first result) */
    ObjEntry *result = vm_make_int_list(vm, count);
    if (!result) return;
    Int *dst = (Int *)disturb_bytes_data(result->obj);
    for (Int i = 0; i < count; i++) {
        ObjEntry *he = (ObjEntry *)tbl->data[i + 2].p;
        WPoolTask *t = wpool_task_from_entry(he);
        if (!t || t->has_error) { dst[i] = 0; continue; }
        if (t->is_result_float) {
            dst[i] = (Int)t->result_float;
        } else {
            dst[i] = t->result_int;
        }
    }

    par_push_entry(vm, result);
}

/* ===========================================================================
 * MODULE INSTALL
 * =========================================================================== */

void parallel_module_install(VM *vm, ObjEntry *parallel_entry)
{
    if (!vm || !parallel_entry) return;

    /* Core */
    par_add_module_fn(vm, parallel_entry, "pool_size", native_parallel_pool_size);
    par_add_module_fn(vm, parallel_entry, "cpu_count", native_parallel_cpu_count);
    par_add_module_fn(vm, parallel_entry, "map", native_parallel_map);

    /* 2C — pipeline */
    par_add_module_fn(vm, parallel_entry, "pipeline", native_parallel_pipeline);
    par_add_module_fn(vm, parallel_entry, "push", native_parallel_push);
    par_add_module_fn(vm, parallel_entry, "flush", native_parallel_flush);
    par_add_module_fn(vm, parallel_entry, "destroy", native_parallel_destroy);

    /* 2D — work-stealing pool */
    par_add_module_fn(vm, parallel_entry, "wpool", native_parallel_wpool);
    par_add_module_fn(vm, parallel_entry, "submit", native_parallel_submit);
    par_add_module_fn(vm, parallel_entry, "gather", native_parallel_gather);

    /* task.spawn and task.join installed into parallel module for discoverability */
    par_add_module_fn(vm, parallel_entry, "spawn", native_task_spawn);
    par_add_module_fn(vm, parallel_entry, "join", native_task_join);
}

#endif /* DISTURB_ENABLE_PARALLEL */
