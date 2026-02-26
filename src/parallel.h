/*
 * parallel.h — Thread pool and task system for Disturb.
 *
 * Guarded by DISTURB_ENABLE_PARALLEL. Requires pthreads.
 * Each worker thread gets an isolated VM — no shared mutable state.
 *
 * Sub-layers:
 *   2A — parr_dispatch: transparent parallel array operations
 *   2B — task.spawn / task.join: parallel lambda execution w/ VM pool
 *   2C — parallel.pipeline: SPSC lock-free queue based stream pipeline
 *   2D — parallel.pool: work-stealing pool (Chase-Lev deque)
 *
 * Public API:
 *   parallel_module_install(vm, entry) — install "parallel" module
 *   parallel_shutdown()               — cleanup global state
 *   parr_dispatch(...)                — parallel array kernel dispatch (2A)
 */

#ifndef DISTURB_PARALLEL_H
#define DISTURB_PARALLEL_H

#ifdef DISTURB_ENABLE_PARALLEL

#include "vm.h"

/* Threshold: parallel array dispatch only pays off above this count */
#ifndef PARR_THRESHOLD
#  define PARR_THRESHOLD 16384
#endif

/* Install the "parallel" module into the given table entry. */
void parallel_module_install(VM *vm, ObjEntry *parallel_entry);

/* Cleanup any global thread pool state (call once at VM shutdown). */
void parallel_shutdown(void);

/* 2A: Parallel array dispatch — splits array operation across N workers.
 * op is the SIMD kernel identifier (0=add,1=sub,2=mul,3=div,4=mod).
 * For int arrays, set is_float=0; for float arrays, is_float=1. */
void parr_dispatch(const void *a, const void *b, void *out,
                   size_t count, int ba, int bb, int op, int is_float);

#endif /* DISTURB_ENABLE_PARALLEL */
#endif /* DISTURB_PARALLEL_H */
