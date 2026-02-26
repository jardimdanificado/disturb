/*
 * gpu.h — OpenCL compute module for Disturb.
 *
 * Guarded by DISTURB_ENABLE_GPU. Requires OpenCL runtime.
 * Follows the NativeBox handle pattern from ffi.c.
 *
 * Handles:
 *   GpuCtxHandle    — OpenCL context + command queue
 *   GpuBufHandle    — OpenCL buffer (device memory)
 *   GpuKernelHandle — compiled OpenCL kernel
 *
 * Public API:
 *   gpu_module_install(vm, entry) — install "gpu" module into VM
 */

#ifndef DISTURB_GPU_H
#define DISTURB_GPU_H

#ifdef DISTURB_ENABLE_GPU

#include "vm.h"

/* Install the "gpu" module into the given table entry.
 * Adds: gpu.init, gpu.release, gpu.compile, gpu.buffer, gpu.read,
 *       gpu.write, gpu.run, gpu.info */
void gpu_module_install(VM *vm, ObjEntry *gpu_entry);

/* ---- Internal auto-dispatch API (used by vm.c) ----------------------- */

/* Auto-dispatch threshold: arrays above this size may use GPU.
 * Set high to amortize CPU↔GPU transfer overhead. */
#ifndef GPU_AUTO_THRESHOLD
#  define GPU_AUTO_THRESHOLD 131072  /* 128K elements */
#endif

/* Attempt to auto-dispatch a float arithmetic operation to GPU.
 * op: 0=add,1=sub,2=mul,3=div,4=mod.
 * Returns 1 on success (result written to out), 0 if GPU unavailable/failed.
 * Handles double↔float32 conversion transparently on 64-bit. */
int gpu_auto_arith(const void *a, const void *b, void *out,
                   size_t count, int ba, int bb, int op);

/* Shutdown auto-dispatch context (call at VM cleanup). */
void gpu_auto_shutdown(void);

#endif /* DISTURB_ENABLE_GPU */
#endif /* DISTURB_GPU_H */
