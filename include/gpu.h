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

#endif /* DISTURB_ENABLE_GPU */
#endif /* DISTURB_GPU_H */
