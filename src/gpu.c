/*
 * gpu.c — OpenCL compute module for Disturb.
 *
 * Guarded by DISTURB_ENABLE_GPU.
 * Follows the NativeBox handle pattern from ffi.c:
 *   - Magic number + refcount for each handle type
 *   - free_data / clone_data callbacks
 *   - vm_make_native_entry_data for registration
 *
 * Module functions exposed to Disturb:
 *   gpu.init()                → GpuCtx handle
 *   gpu.release(ctx)          → release context
 *   gpu.compile(ctx, src)     → GpuKernel handle
 *   gpu.buffer(ctx, size)     → GpuBuf handle (device memory)
 *   gpu.write(buf, data)      → write Int[]/Float[] to device buffer
 *   gpu.read(buf, count)      → read device buffer → Int[]
 *   gpu.run(kernel, global_size, args...) → execute kernel
 *   gpu.info(ctx)             → device info string
 */

#ifdef DISTURB_ENABLE_GPU

#ifdef __APPLE__
#  include <OpenCL/opencl.h>
#else
#  include <CL/cl.h>
#endif

#include "gpu.h"
#include "vm.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ---- Handle magic numbers --------------------------------------------- */

#define GPU_CTX_MAGIC    0x47505543u   /* "GPUC" */
#define GPU_BUF_MAGIC    0x47505542u   /* "GPUB" */
#define GPU_KERNEL_MAGIC 0x4750554Bu   /* "GPUK" */

/* ---- Handle structs --------------------------------------------------- */

typedef struct {
    uint32_t magic;
    int refcount;
    cl_context context;
    cl_command_queue queue;
    cl_device_id device;
} GpuCtxHandle;

typedef struct {
    uint32_t magic;
    int refcount;
    cl_mem mem;
    size_t size_bytes;
    GpuCtxHandle *ctx; /* borrowed reference */
} GpuBufHandle;

typedef struct {
    uint32_t magic;
    int refcount;
    cl_kernel kernel;
    cl_program program;
    GpuCtxHandle *ctx; /* borrowed reference */
} GpuKernelHandle;

/* ---- Handle free / clone callbacks ------------------------------------ */

static void gpu_ctx_free(void *data)
{
    GpuCtxHandle *h = (GpuCtxHandle *)data;
    if (!h || h->magic != GPU_CTX_MAGIC) return;
    h->refcount--;
    if (h->refcount > 0) return;
    if (h->queue) clReleaseCommandQueue(h->queue);
    if (h->context) clReleaseContext(h->context);
    h->magic = 0;
    free(h);
}

static void gpu_ctx_clone(void *data)
{
    GpuCtxHandle *h = (GpuCtxHandle *)data;
    if (h && h->magic == GPU_CTX_MAGIC) h->refcount++;
}

static void gpu_buf_free(void *data)
{
    GpuBufHandle *h = (GpuBufHandle *)data;
    if (!h || h->magic != GPU_BUF_MAGIC) return;
    h->refcount--;
    if (h->refcount > 0) return;
    if (h->mem) clReleaseMemObject(h->mem);
    h->magic = 0;
    free(h);
}

static void gpu_buf_clone(void *data)
{
    GpuBufHandle *h = (GpuBufHandle *)data;
    if (h && h->magic == GPU_BUF_MAGIC) h->refcount++;
}

static void gpu_kernel_free(void *data)
{
    GpuKernelHandle *h = (GpuKernelHandle *)data;
    if (!h || h->magic != GPU_KERNEL_MAGIC) return;
    h->refcount--;
    if (h->refcount > 0) return;
    if (h->kernel) clReleaseKernel(h->kernel);
    if (h->program) clReleaseProgram(h->program);
    h->magic = 0;
    free(h);
}

static void gpu_kernel_clone(void *data)
{
    GpuKernelHandle *h = (GpuKernelHandle *)data;
    if (h && h->magic == GPU_KERNEL_MAGIC) h->refcount++;
}

/* ---- Handle extraction from ObjEntry ---------------------------------- */

static GpuCtxHandle *gpu_ctx_from_entry(ObjEntry *entry)
{
    if (!entry || !entry->obj) return NULL;
    if (disturb_obj_type(entry->obj) != DISTURB_T_NATIVE) return NULL;
    NativeBox *nb = (NativeBox *)disturb_bytes_data(entry->obj);
    if (!nb || !nb->data) return NULL;
    GpuCtxHandle *h = (GpuCtxHandle *)nb->data;
    if (h->magic != GPU_CTX_MAGIC) return NULL;
    return h;
}

static GpuBufHandle *gpu_buf_from_entry(ObjEntry *entry)
{
    if (!entry || !entry->obj) return NULL;
    if (disturb_obj_type(entry->obj) != DISTURB_T_NATIVE) return NULL;
    NativeBox *nb = (NativeBox *)disturb_bytes_data(entry->obj);
    if (!nb || !nb->data) return NULL;
    GpuBufHandle *h = (GpuBufHandle *)nb->data;
    if (h->magic != GPU_BUF_MAGIC) return NULL;
    return h;
}

static GpuKernelHandle *gpu_kernel_from_entry(ObjEntry *entry)
{
    if (!entry || !entry->obj) return NULL;
    if (disturb_obj_type(entry->obj) != DISTURB_T_NATIVE) return NULL;
    NativeBox *nb = (NativeBox *)disturb_bytes_data(entry->obj);
    if (!nb || !nb->data) return NULL;
    GpuKernelHandle *h = (GpuKernelHandle *)nb->data;
    if (h->magic != GPU_KERNEL_MAGIC) return NULL;
    return h;
}

/* ---- Argument helpers (same pattern as ffi.c) ------------------------- */

static uint32_t gpu_native_argc(VM *vm)
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

static ObjEntry *gpu_native_arg(List *stack, uint32_t argc, uint32_t idx)
{
    if (!stack || idx >= argc) return NULL;
    Int base = stack->size - (Int)argc;
    if (base < 2) return NULL;
    Int pos = base + (Int)idx;
    if (pos < 2 || pos >= stack->size) return NULL;
    return (ObjEntry *)stack->data[pos].p;
}

static void gpu_push_entry(VM *vm, ObjEntry *entry)
{
    if (!vm || !vm->stack_entry || !entry) return;
    List *old_stack = vm->stack_entry->obj;
    List *new_stack = disturb_table_add(old_stack, entry);
    new_stack = vm_update_shared_obj(vm, old_stack, new_stack);
    vm->stack_entry->obj = new_stack;
}

static void gpu_add_module_fn(VM *vm, ObjEntry *mod_entry, const char *name, NativeFn fn)
{
    ObjEntry *entry = vm_make_native_entry_data(vm, name, fn, NULL, NULL, NULL);
    if (!entry) return;
    vm_object_set_by_key(vm, mod_entry, name, strlen(name), entry);
}

/* ---- Native functions ------------------------------------------------- */

/* gpu.init() → GpuCtx handle */
static void native_gpu_init(VM *vm, List *stack, List *global)
{
    (void)stack; (void)global;
    cl_int err;
    cl_platform_id platform;
    cl_device_id device;

    err = clGetPlatformIDs(1, &platform, NULL);
    if (err != CL_SUCCESS) {
        fprintf(stderr, "gpu.init: no OpenCL platform found (err=%d)\n", err);
        gpu_push_entry(vm, vm_make_int_value(vm, 0));
        return;
    }

    err = clGetDeviceIDs(platform, CL_DEVICE_TYPE_GPU, 1, &device, NULL);
    if (err != CL_SUCCESS) {
        /* Fallback to any device */
        err = clGetDeviceIDs(platform, CL_DEVICE_TYPE_ALL, 1, &device, NULL);
        if (err != CL_SUCCESS) {
            fprintf(stderr, "gpu.init: no OpenCL device found (err=%d)\n", err);
            gpu_push_entry(vm, vm_make_int_value(vm, 0));
            return;
        }
    }

    cl_context context = clCreateContext(NULL, 1, &device, NULL, NULL, &err);
    if (err != CL_SUCCESS || !context) {
        fprintf(stderr, "gpu.init: failed to create context (err=%d)\n", err);
        gpu_push_entry(vm, vm_make_int_value(vm, 0));
        return;
    }

    /* Use clCreateCommandQueueWithProperties on OpenCL 2.0+, fallback to legacy */
#if defined(CL_VERSION_2_0)
    cl_command_queue queue = clCreateCommandQueueWithProperties(context, device, NULL, &err);
#else
    cl_command_queue queue = clCreateCommandQueue(context, device, 0, &err);
#endif
    if (err != CL_SUCCESS || !queue) {
        clReleaseContext(context);
        fprintf(stderr, "gpu.init: failed to create command queue (err=%d)\n", err);
        gpu_push_entry(vm, vm_make_int_value(vm, 0));
        return;
    }

    GpuCtxHandle *h = (GpuCtxHandle *)calloc(1, sizeof(GpuCtxHandle));
    h->magic = GPU_CTX_MAGIC;
    h->refcount = 1;
    h->context = context;
    h->queue = queue;
    h->device = device;

    ObjEntry *entry = vm_make_native_entry_data(vm, "gpu_ctx", NULL, h,
                                                 gpu_ctx_free, gpu_ctx_clone);
    gpu_push_entry(vm, entry ? entry : vm_make_int_value(vm, 0));
}

/* gpu.release(ctx) → 0 */
static void native_gpu_release(VM *vm, List *stack, List *global)
{
    (void)global;
    uint32_t argc = gpu_native_argc(vm);
    if (argc < 1) { fprintf(stderr, "gpu.release expects (handle)\n"); return; }
    ObjEntry *arg = gpu_native_arg(stack, argc, 0);
    if (!arg) return;

    /* Try each handle type */
    GpuCtxHandle *ctx = gpu_ctx_from_entry(arg);
    if (ctx) { gpu_ctx_free(ctx); gpu_push_entry(vm, vm_make_int_value(vm, 0)); return; }
    GpuBufHandle *buf = gpu_buf_from_entry(arg);
    if (buf) { gpu_buf_free(buf); gpu_push_entry(vm, vm_make_int_value(vm, 0)); return; }
    GpuKernelHandle *ker = gpu_kernel_from_entry(arg);
    if (ker) { gpu_kernel_free(ker); gpu_push_entry(vm, vm_make_int_value(vm, 0)); return; }

    fprintf(stderr, "gpu.release: not a valid GPU handle\n");
}

/* gpu.compile(ctx, source_string) → GpuKernel handle */
static void native_gpu_compile(VM *vm, List *stack, List *global)
{
    (void)global;
    uint32_t argc = gpu_native_argc(vm);
    if (argc < 2) { fprintf(stderr, "gpu.compile expects (ctx, source)\n"); return; }

    ObjEntry *ctx_entry = gpu_native_arg(stack, argc, 0);
    ObjEntry *src_entry = gpu_native_arg(stack, argc, 1);
    GpuCtxHandle *ctx = gpu_ctx_from_entry(ctx_entry);
    if (!ctx) { fprintf(stderr, "gpu.compile: invalid context\n"); return; }
    if (!src_entry || !src_entry->is_string) {
        fprintf(stderr, "gpu.compile: second argument must be a string\n");
        return;
    }

    const char *src = disturb_bytes_data(src_entry->obj);
    size_t src_len = disturb_bytes_len(src_entry->obj);

    cl_int err;
    cl_program program = clCreateProgramWithSource(ctx->context, 1, &src, &src_len, &err);
    if (err != CL_SUCCESS) {
        fprintf(stderr, "gpu.compile: clCreateProgramWithSource failed (err=%d)\n", err);
        gpu_push_entry(vm, vm_make_int_value(vm, 0));
        return;
    }

    err = clBuildProgram(program, 1, &ctx->device, NULL, NULL, NULL);
    if (err != CL_SUCCESS) {
        char log[4096];
        log[0] = 0;
        clGetProgramBuildInfo(program, ctx->device, CL_PROGRAM_BUILD_LOG, sizeof(log), log, NULL);
        fprintf(stderr, "gpu.compile: build failed:\n%s\n", log);
        clReleaseProgram(program);
        gpu_push_entry(vm, vm_make_int_value(vm, 0));
        return;
    }

    /* Get the first kernel from the program.
     * The user's source should define exactly one __kernel function.
     * We extract its name from the program info. */
    cl_uint num_kernels = 0;
    clCreateKernelsInProgram(program, 0, NULL, &num_kernels);
    if (num_kernels == 0) {
        fprintf(stderr, "gpu.compile: no kernels found in source\n");
        clReleaseProgram(program);
        gpu_push_entry(vm, vm_make_int_value(vm, 0));
        return;
    }

    cl_kernel kernel = NULL;
    clCreateKernelsInProgram(program, 1, &kernel, NULL);
    if (!kernel) {
        clReleaseProgram(program);
        gpu_push_entry(vm, vm_make_int_value(vm, 0));
        return;
    }

    GpuKernelHandle *h = (GpuKernelHandle *)calloc(1, sizeof(GpuKernelHandle));
    h->magic = GPU_KERNEL_MAGIC;
    h->refcount = 1;
    h->kernel = kernel;
    h->program = program;
    h->ctx = ctx;

    ObjEntry *entry = vm_make_native_entry_data(vm, "gpu_kernel", NULL, h,
                                                 gpu_kernel_free, gpu_kernel_clone);
    gpu_push_entry(vm, entry ? entry : vm_make_int_value(vm, 0));
}

/* gpu.buffer(ctx, size_in_bytes) → GpuBuf handle */
static void native_gpu_buffer(VM *vm, List *stack, List *global)
{
    (void)global;
    uint32_t argc = gpu_native_argc(vm);
    if (argc < 2) { fprintf(stderr, "gpu.buffer expects (ctx, size)\n"); return; }

    ObjEntry *ctx_entry = gpu_native_arg(stack, argc, 0);
    ObjEntry *size_entry = gpu_native_arg(stack, argc, 1);
    GpuCtxHandle *ctx = gpu_ctx_from_entry(ctx_entry);
    if (!ctx) { fprintf(stderr, "gpu.buffer: invalid context\n"); return; }

    Int size_bytes = 0;
    if (size_entry && disturb_obj_type(size_entry->obj) == DISTURB_T_INT)
        memcpy(&size_bytes, disturb_bytes_data(size_entry->obj), sizeof(Int));
    if (size_bytes <= 0) {
        fprintf(stderr, "gpu.buffer: size must be > 0\n");
        return;
    }

    cl_int err;
    cl_mem mem = clCreateBuffer(ctx->context, CL_MEM_READ_WRITE, (size_t)size_bytes, NULL, &err);
    if (err != CL_SUCCESS || !mem) {
        fprintf(stderr, "gpu.buffer: clCreateBuffer failed (err=%d)\n", err);
        gpu_push_entry(vm, vm_make_int_value(vm, 0));
        return;
    }

    GpuBufHandle *h = (GpuBufHandle *)calloc(1, sizeof(GpuBufHandle));
    h->magic = GPU_BUF_MAGIC;
    h->refcount = 1;
    h->mem = mem;
    h->size_bytes = (size_t)size_bytes;
    h->ctx = ctx;

    ObjEntry *entry = vm_make_native_entry_data(vm, "gpu_buf", NULL, h,
                                                 gpu_buf_free, gpu_buf_clone);
    gpu_push_entry(vm, entry ? entry : vm_make_int_value(vm, 0));
}

/* gpu.write(buf, data) → 0
 * Writes Int[] or Float[] data to the device buffer.
 * On 64-bit: Float[] (double) is auto-converted to float32 for GPU. */
static void native_gpu_write(VM *vm, List *stack, List *global)
{
    (void)global;
    uint32_t argc = gpu_native_argc(vm);
    if (argc < 2) { fprintf(stderr, "gpu.write expects (buf, data)\n"); return; }

    ObjEntry *buf_entry = gpu_native_arg(stack, argc, 0);
    ObjEntry *data_entry = gpu_native_arg(stack, argc, 1);
    GpuBufHandle *buf = gpu_buf_from_entry(buf_entry);
    if (!buf || !buf->ctx) {
        fprintf(stderr, "gpu.write: invalid buffer\n");
        return;
    }
    if (!data_entry || !data_entry->obj) {
        fprintf(stderr, "gpu.write: invalid data\n");
        return;
    }

    Int data_type = disturb_obj_type(data_entry->obj);
    size_t data_len = disturb_bytes_len(data_entry->obj);
    const void *write_ptr = disturb_bytes_data(data_entry->obj);
    size_t write_len = data_len;
    float *tmp_f32 = NULL;

#if INTPTR_MAX == INT64_MAX
    /* Cam3: auto-convert double → float32 for GPU */
    if (data_type == DISTURB_T_FLOAT) {
        size_t count = data_len / sizeof(double);
        size_t f32_bytes = count * sizeof(float);
        tmp_f32 = (float *)malloc(f32_bytes);
        if (tmp_f32) {
            const double *src = (const double *)disturb_bytes_data(data_entry->obj);
            for (size_t i = 0; i < count; i++)
                tmp_f32[i] = (float)src[i];
            write_ptr = tmp_f32;
            write_len = f32_bytes;
        }
    }
#else
    (void)data_type;
#endif

    if (write_len > buf->size_bytes) write_len = buf->size_bytes;

    cl_int err = clEnqueueWriteBuffer(buf->ctx->queue, buf->mem, CL_TRUE,
                                       0, write_len, write_ptr,
                                       0, NULL, NULL);
    if (err != CL_SUCCESS) {
        fprintf(stderr, "gpu.write: clEnqueueWriteBuffer failed (err=%d)\n", err);
    }

    free(tmp_f32);
    gpu_push_entry(vm, vm_make_int_value(vm, err == CL_SUCCESS ? 0 : (Int)err));
}

/* gpu.read(buf, count [, "float"]) → Int[] or Float[]
 * Reads count values from the device buffer.
 * If 3rd arg is "float", reads as float32 and converts to Float[] (double on 64-bit). */
static void native_gpu_read(VM *vm, List *stack, List *global)
{
    (void)global;
    uint32_t argc = gpu_native_argc(vm);
    if (argc < 2) { fprintf(stderr, "gpu.read expects (buf, count [, \"float\"])\n"); return; }

    ObjEntry *buf_entry = gpu_native_arg(stack, argc, 0);
    ObjEntry *count_entry = gpu_native_arg(stack, argc, 1);
    GpuBufHandle *buf = gpu_buf_from_entry(buf_entry);
    if (!buf || !buf->ctx) {
        fprintf(stderr, "gpu.read: invalid buffer\n");
        return;
    }

    Int count = 0;
    if (count_entry && disturb_obj_type(count_entry->obj) == DISTURB_T_INT)
        memcpy(&count, disturb_bytes_data(count_entry->obj), sizeof(Int));
    if (count <= 0) {
        fprintf(stderr, "gpu.read: count must be > 0\n");
        return;
    }

    /* Check optional 3rd arg for "float" type hint */
    int read_as_float = 0;
    if (argc >= 3) {
        ObjEntry *type_entry = gpu_native_arg(stack, argc, 2);
        if (type_entry && type_entry->is_string) {
            const char *ts = disturb_bytes_data(type_entry->obj);
            if (ts && (ts[0] == 'f' || ts[0] == 'F')) read_as_float = 1;
        }
    }

    if (read_as_float) {
        /* Read float32 from GPU → convert to Float[] (double on 64-bit) */
        size_t f32_bytes = (size_t)count * sizeof(float);
        if (f32_bytes > buf->size_bytes) f32_bytes = buf->size_bytes;

        float *tmp = (float *)malloc(f32_bytes);
        if (!tmp) { fprintf(stderr, "gpu.read: OOM\n"); return; }

        cl_int err = clEnqueueReadBuffer(buf->ctx->queue, buf->mem, CL_TRUE,
                                          0, f32_bytes, tmp, 0, NULL, NULL);
        if (err != CL_SUCCESS) {
            fprintf(stderr, "gpu.read: clEnqueueReadBuffer failed (err=%d)\n", err);
            free(tmp);
            return;
        }

        ObjEntry *res_entry = vm_make_float_list(vm, count);
        if (!res_entry) { free(tmp); return; }
        Float *dst = (Float *)disturb_bytes_data(res_entry->obj);
#if INTPTR_MAX == INT64_MAX
        /* Convert float32 → double */
        for (Int i = 0; i < count; i++)
            dst[i] = (double)tmp[i];
#else
        /* 32-bit: Float is already float, direct copy */
        memcpy(dst, tmp, f32_bytes);
#endif
        free(tmp);
        gpu_push_entry(vm, res_entry);
    } else {
        /* Original Int[] path */
        size_t read_bytes = (size_t)count * sizeof(Int);
        if (read_bytes > buf->size_bytes) read_bytes = buf->size_bytes;

        List *result = vm_alloc_bytes(vm, DISTURB_T_INT, NULL, NULL, read_bytes);
        if (!result) return;

        cl_int err = clEnqueueReadBuffer(buf->ctx->queue, buf->mem, CL_TRUE,
                                          0, read_bytes,
                                          disturb_bytes_data(result),
                                          0, NULL, NULL);
        if (err != CL_SUCCESS) {
            fprintf(stderr, "gpu.read: clEnqueueReadBuffer failed (err=%d)\n", err);
        }

        ObjEntry *res_entry = vm_reg_alloc(vm, result);
        gpu_push_entry(vm, res_entry);
    }
}

/* gpu.run(kernel, global_size, buf0, buf1, ...)
 * Sets kernel args (all must be GpuBuf handles) and enqueues 1D NDRange. */
static void native_gpu_run(VM *vm, List *stack, List *global)
{
    (void)global;
    uint32_t argc = gpu_native_argc(vm);
    if (argc < 2) { fprintf(stderr, "gpu.run expects (kernel, global_size, ...bufs)\n"); return; }

    ObjEntry *ker_entry = gpu_native_arg(stack, argc, 0);
    ObjEntry *size_entry = gpu_native_arg(stack, argc, 1);
    GpuKernelHandle *ker = gpu_kernel_from_entry(ker_entry);
    if (!ker || !ker->ctx) {
        fprintf(stderr, "gpu.run: invalid kernel\n");
        return;
    }

    Int global_size = 0;
    if (size_entry && disturb_obj_type(size_entry->obj) == DISTURB_T_INT)
        memcpy(&global_size, disturb_bytes_data(size_entry->obj), sizeof(Int));
    if (global_size <= 0) {
        fprintf(stderr, "gpu.run: global_size must be > 0\n");
        return;
    }

    /* Set buffer arguments */
    for (uint32_t i = 2; i < argc; i++) {
        ObjEntry *arg = gpu_native_arg(stack, argc, i);
        GpuBufHandle *buf = gpu_buf_from_entry(arg);
        if (!buf) {
            fprintf(stderr, "gpu.run: arg %u is not a gpu buffer\n", i);
            return;
        }
        cl_int err = clSetKernelArg(ker->kernel, i - 2, sizeof(cl_mem), &buf->mem);
        if (err != CL_SUCCESS) {
            fprintf(stderr, "gpu.run: clSetKernelArg(%u) failed (err=%d)\n", i - 2, err);
            return;
        }
    }

    size_t gws = (size_t)global_size;
    cl_int err = clEnqueueNDRangeKernel(ker->ctx->queue, ker->kernel,
                                         1, NULL, &gws, NULL, 0, NULL, NULL);
    if (err != CL_SUCCESS) {
        fprintf(stderr, "gpu.run: clEnqueueNDRangeKernel failed (err=%d)\n", err);
    }
    clFinish(ker->ctx->queue);

    gpu_push_entry(vm, vm_make_int_value(vm, err == CL_SUCCESS ? 0 : (Int)err));
}

/* gpu.info(ctx) → string with device name */
static void native_gpu_info(VM *vm, List *stack, List *global)
{
    (void)global;
    uint32_t argc = gpu_native_argc(vm);
    if (argc < 1) { fprintf(stderr, "gpu.info expects (ctx)\n"); return; }

    ObjEntry *ctx_entry = gpu_native_arg(stack, argc, 0);
    GpuCtxHandle *ctx = gpu_ctx_from_entry(ctx_entry);
    if (!ctx) {
        fprintf(stderr, "gpu.info: invalid context\n");
        return;
    }

    char name[256] = {0};
    clGetDeviceInfo(ctx->device, CL_DEVICE_NAME, sizeof(name), name, NULL);
    size_t nlen = strlen(name);

    ObjEntry *str = vm_make_bytes_value(vm, name, nlen);
    if (str) str->is_string = 1;
    gpu_push_entry(vm, str ? str : vm_make_int_value(vm, 0));
}

/* ---- Module install --------------------------------------------------- */

void gpu_module_install(VM *vm, ObjEntry *gpu_entry)
{
    if (!vm || !gpu_entry) return;
    gpu_add_module_fn(vm, gpu_entry, "init", native_gpu_init);
    gpu_add_module_fn(vm, gpu_entry, "release", native_gpu_release);
    gpu_add_module_fn(vm, gpu_entry, "compile", native_gpu_compile);
    gpu_add_module_fn(vm, gpu_entry, "buffer", native_gpu_buffer);
    gpu_add_module_fn(vm, gpu_entry, "write", native_gpu_write);
    gpu_add_module_fn(vm, gpu_entry, "read", native_gpu_read);
    gpu_add_module_fn(vm, gpu_entry, "run", native_gpu_run);
    gpu_add_module_fn(vm, gpu_entry, "info", native_gpu_info);
}

#endif /* DISTURB_ENABLE_GPU */
