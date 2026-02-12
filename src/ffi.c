#ifdef DISTURB_ENABLE_FFI

#include "vm.h"
#ifdef DISTURB_ENABLE_FFI_CALLS
#include <ffi.h>
#endif
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <stdarg.h>

#if defined(__GNUC__) || defined(__clang__)
#define UNUSED_FN __attribute__((unused))
#else
#define UNUSED_FN
#endif

#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif

typedef enum {
    FFI_BASE_VOID = 0,
    FFI_BASE_I8,
    FFI_BASE_U8,
    FFI_BASE_I16,
    FFI_BASE_U16,
    FFI_BASE_I32,
    FFI_BASE_U32,
    FFI_BASE_I64,
    FFI_BASE_U64,
    FFI_BASE_F32,
    FFI_BASE_F64,
    FFI_BASE_CSTR,
    FFI_BASE_PTR
} FfiBase;

typedef struct FfiLayout FfiLayout;

typedef struct {
    FfiBase base;
    int is_ptr;
    int is_array;
    int array_len;
    char *schema_name; /* struct<schema>, union<schema>, or pointer<schema> */
    int schema_is_pointer; /* 0 => by-value schema, 1 => pointer<schema> */
    int schema_is_union;   /* 1 => union<schema>, 0 => struct<schema> */
    FfiLayout *schema_layout; /* resolved struct layout for schema */
    void *schema_ffi_type; /* resolved ffi type for struct<schema>/union<schema> */
    void *schema_ffi_owner; /* owned dynamic ffi type graph */
} FfiType;

#ifdef DISTURB_ENABLE_FFI_CALLS
static char *ffi_strdup(const char *s);
typedef struct {
    int refcount;
    void *handle;
    void *fn_ptr;
    FfiType ret;
    FfiType *args;
    int argc;
    int fixed_argc;
    int has_varargs;
    ffi_cif cif;
    ffi_type **arg_types;
    ffi_type *ret_type;
} FfiFunction;

typedef struct {
    uint32_t magic;
    int refcount;
    VM *vm;
    ffi_closure *closure;
    void *code_ptr;
    ffi_cif cif;
    ffi_type **arg_types;
    ffi_type *ret_type;
    FfiType ret;
    FfiType *args;
    int argc;
    int callback_id;
    char lambda_key[64];
} FfiCallback;

typedef union {
    int8_t i8;
    uint8_t u8;
    int16_t i16;
    uint16_t u16;
    int32_t i32;
    uint32_t u32;
    int64_t i;
    uint64_t u;
    double f;
    float f32;
    void *p;
} FfiValue;
#endif

typedef enum {
    FFI_LAYOUT_PRIM = 1,
    FFI_LAYOUT_STRUCT,
    FFI_LAYOUT_ARRAY
} FfiLayoutKind;

typedef struct {
    char *name;
    size_t name_len;
    size_t offset;
    FfiLayout *layout;
    char *fn_sig; /* non-NULL => function pointer field (function<signature>, fn<...> alias) */
    int is_const;
    int bit_width;   /* 0 => normal field, >0 => bitfield width */
    int bit_shift;   /* bit offset inside storage unit */
} FfiLayoutField;

struct FfiLayout {
    FfiLayoutKind kind;
    FfiBase base;
    int is_const;
    FfiLayout *elem;
    FfiLayout *pointee; /* for FFI_BASE_PTR when typed pointer field exists */
    int array_len;
    size_t size;
    size_t align;
    int packed;
    int forced_align;
    int is_union;
    int bit_width; /* only for primitive bitfield declarations */
    int field_count;
    FfiLayoutField *fields;
};

typedef struct FfiLayoutCacheNode {
    uint64_t hash;
    char *sig;
    size_t sig_len;
    FfiLayout *layout;
    struct FfiLayoutCacheNode *next;
} FfiLayoutCacheNode;

typedef struct FfiDynTypeNode {
#ifdef DISTURB_ENABLE_FFI_CALLS
    ffi_type type;
    ffi_type **elements;
#endif
    struct FfiDynTypeNode **owned_children;
    int owned_count;
} FfiDynTypeNode;

typedef struct {
    char *data;
    size_t len;
    size_t cap;
} FfiSigBuf;

typedef struct {
    uint32_t magic;
    int refcount;
    FfiLayout *layout;
} FfiLayoutHandle;

typedef struct {
    uint32_t magic;
    int refcount;
    uintptr_t base_ptr;
    size_t base_offset;
    FfiLayout *layout;
    void *owned_mem;
    int readonly;
} FfiViewHandle;

typedef struct {
    uint32_t magic;
    int refcount;
    uintptr_t base_ptr;
    FfiLayout *elem_layout;
    int len;
    int own_elem_layout;
    int readonly;
} FfiArrayViewHandle;

typedef struct {
    uint32_t magic;
    int refcount;
    uintptr_t ptr;
    int owned;
} FfiPtrHandle;

enum {
    FFI_LAYOUT_HANDLE_MAGIC = 0x4646494cU, /* FFIL */
    FFI_VIEW_HANDLE_MAGIC = 0x46464956U,   /* FFIV */
    FFI_ARRAY_VIEW_HANDLE_MAGIC = 0x46464941U, /* FFIA */
    FFI_PTR_HANDLE_MAGIC = 0x46464950U, /* FFIP */
    FFI_LIB_HANDLE_MAGIC = 0x46464944U /* FFID */
};

#ifdef DISTURB_ENABLE_FFI_CALLS
typedef struct {
    uint32_t magic;
    int refcount;
    void *handle;
} FfiLibHandle;
#endif

#ifdef DISTURB_ENABLE_FFI_CALLS
enum {
    FFI_CALLBACK_MAGIC = 0x46464943U /* FFIC */
};
static int g_ffi_callback_seq = 1;
#endif

static FfiLayoutCacheNode *g_ffi_layout_cache = NULL;
static FfiArrayViewHandle *ffi_array_view_handle_from_entry(ObjEntry *entry);
static FfiPtrHandle *ffi_ptr_handle_from_entry(ObjEntry *entry);
static ObjEntry *ffi_make_ptr_handle_entry(VM *vm, uintptr_t ptr, int owned);
static int entry_number_scalar(ObjEntry *entry, Int *out_i, Float *out_f, int *out_is_float);
static int ffi_entry_to_ptr(ObjEntry *entry, uintptr_t *out_ptr);
static int ffi_view_decode(ObjEntry *entry, uintptr_t *base_ptr, size_t *base_offset, FfiLayout **layout, int *readonly);
static void native_ffi_handle_noop(VM *vm, List *stack, List *global);
static int parse_base_type(const char *name, FfiBase *out);
static ObjEntry *ffi_lookup_schema_entry(VM *vm, const char *name, size_t name_len);
#ifdef DISTURB_ENABLE_FFI_CALLS
static FfiCallback *ffi_callback_from_entry(ObjEntry *entry);
static ObjEntry *ffi_bind_ptr_sig_entry(VM *vm, uintptr_t addr, const char *sig, char *err, size_t err_cap);
#endif

static int ffi_trace_mouse_enabled(void)
{
    static int initialized = 0;
    static int enabled = 0;
    if (!initialized) {
        const char *env = getenv("DISTURB_FFI_TRACE_MOUSE");
        enabled = (env && env[0] && !(env[0] == '0' && env[1] == '\0')) ? 1 : 0;
        initialized = 1;
    }
    return enabled;
}

static int ffi_trace_mouse_slot(const char *name, size_t len)
{
    if (!name) return -1;
    if (len == 17 && memcmp(name, "IsMouseButtonDown", 17) == 0) return 0;
    if (len == 20 && memcmp(name, "IsMouseButtonPressed", 20) == 0) return 1;
    if (len == 21 && memcmp(name, "IsMouseButtonReleased", 21) == 0) return 2;
    if (len == 18 && memcmp(name, "GetTouchPointCount", 18) == 0) return 3;
    return -1;
}

static int ffi_trace_mouse_last[4] = { INT_MIN, INT_MIN, INT_MIN, INT_MIN };

static void ffi_dyn_type_node_free(FfiDynTypeNode *node)
{
    if (!node) return;
    for (int i = 0; i < node->owned_count; i++) {
        ffi_dyn_type_node_free(node->owned_children[i]);
    }
    free(node->owned_children);
#ifdef DISTURB_ENABLE_FFI_CALLS
    free(node->elements);
#endif
    free(node);
}

static void ffi_type_release_runtime(FfiType *t)
{
    if (!t) return;
    free(t->schema_name);
    t->schema_name = NULL;
    t->schema_is_pointer = 0;
    t->schema_is_union = 0;
#ifdef DISTURB_ENABLE_FFI_CALLS
    if (t->schema_ffi_owner) {
        ffi_dyn_type_node_free((FfiDynTypeNode*)t->schema_ffi_owner);
        t->schema_ffi_owner = NULL;
    }
    t->schema_ffi_type = NULL;
#else
    t->schema_ffi_owner = NULL;
    t->schema_ffi_type = NULL;
#endif
    t->schema_layout = NULL;
}

static void ffi_types_release_array(FfiType *arr, int count)
{
    if (!arr) return;
    for (int i = 0; i < count; i++) {
        ffi_type_release_runtime(&arr[i]);
    }
}

#ifdef _WIN32
static char g_ffi_dl_error[256];

static void ffi_dl_set_error_win32(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(g_ffi_dl_error, sizeof(g_ffi_dl_error), fmt, ap);
    va_end(ap);
}

static void ffi_dl_set_error_last(const char *prefix)
{
    DWORD code = GetLastError();
    if (code == 0) {
        ffi_dl_set_error_win32("%s", prefix);
        return;
    }
    char *msg = NULL;
    DWORD n = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                                 FORMAT_MESSAGE_IGNORE_INSERTS,
                             NULL, code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                             (LPSTR)&msg, 0, NULL);
    if (n > 0 && msg) {
        while (n > 0 && (msg[n - 1] == '\r' || msg[n - 1] == '\n')) {
            msg[n - 1] = 0;
            n--;
        }
        ffi_dl_set_error_win32("%s: %s", prefix, msg);
    } else {
        ffi_dl_set_error_win32("%s (code=%lu)", prefix, (unsigned long)code);
    }
    if (msg) LocalFree(msg);
}

static void *ffi_dlopen(const char *path)
{
    SetLastError(0);
    HMODULE h = LoadLibraryA(path);
    if (!h) {
        ffi_dl_set_error_last("ffi.open failed");
    }
    return (void*)h;
}

static void *ffi_dlsym(void *handle, const char *name)
{
    SetLastError(0);
    FARPROC p = GetProcAddress((HMODULE)handle, name);
    if (!p) {
        ffi_dl_set_error_last("ffi: missing symbol");
        return NULL;
    }
    return (void*)p;
}

static int ffi_dlclose(void *handle)
{
    if (!handle) return 1;
    SetLastError(0);
    if (!FreeLibrary((HMODULE)handle)) {
        ffi_dl_set_error_last("ffi.close failed");
        return 0;
    }
    return 1;
}

static const char *ffi_dlerror_msg(void)
{
    return g_ffi_dl_error[0] ? g_ffi_dl_error : "ffi dynamic loading error";
}
#else
static void *ffi_dlopen(const char *path)
{
    return dlopen(path, RTLD_LAZY);
}

static void *ffi_dlsym(void *handle, const char *name)
{
    return dlsym(handle, name);
}

static int ffi_dlclose(void *handle)
{
    if (!handle) return 1;
    return dlclose(handle) == 0;
}

static const char *ffi_dlerror_msg(void)
{
    const char *e = dlerror();
    return e ? e : "ffi dynamic loading error";
}
#endif

#ifdef DISTURB_ENABLE_FFI_CALLS
static void ffi_function_retain(void *data)
{
    FfiFunction *fn = (FfiFunction*)data;
    if (fn) fn->refcount++;
}

static void ffi_function_release(void *data)
{
    FfiFunction *fn = (FfiFunction*)data;
    if (!fn) return;
    fn->refcount--;
    if (fn->refcount > 0) return;
    ffi_type_release_runtime(&fn->ret);
    if (fn->args) {
        for (int i = 0; i < fn->argc; i++) {
            ffi_type_release_runtime(&fn->args[i]);
        }
    }
    free(fn->args);
    free(fn->arg_types);
    free(fn);
}

static FfiCallback *ffi_callback_from_entry(ObjEntry *entry)
{
    if (!entry || disturb_obj_type(entry->obj) != DISTURB_T_NATIVE || entry->obj->size < 3) return NULL;
    NativeBox *box = (NativeBox*)entry->obj->data[2].p;
    if (!box || !box->data) return NULL;
    FfiCallback *cb = (FfiCallback*)box->data;
    if (!cb || cb->magic != FFI_CALLBACK_MAGIC) return NULL;
    return cb;
}

static void ffi_callback_retain(void *data)
{
    FfiCallback *cb = (FfiCallback*)data;
    if (cb && cb->magic == FFI_CALLBACK_MAGIC) cb->refcount++;
}

static void ffi_callback_release(void *data)
{
    FfiCallback *cb = (FfiCallback*)data;
    if (!cb || cb->magic != FFI_CALLBACK_MAGIC) return;
    cb->refcount--;
    if (cb->refcount > 0) return;
    if (cb->closure) {
        ffi_closure_free(cb->closure);
        cb->closure = NULL;
    }
    ffi_type_release_runtime(&cb->ret);
    if (cb->args) {
        for (int i = 0; i < cb->argc; i++) ffi_type_release_runtime(&cb->args[i]);
        free(cb->args);
    }
    free(cb->arg_types);
    cb->magic = 0;
    free(cb);
}

static ObjEntry *ffi_callback_arg_to_entry(VM *vm, const FfiType *t, void *argp)
{
    if (!vm || !t) return vm ? vm->null_entry : NULL;
    if (t->is_ptr || t->is_array || t->base == FFI_BASE_PTR || t->base == FFI_BASE_CSTR || (t->schema_name && t->schema_is_pointer)) {
        void *p = NULL;
        memcpy(&p, argp, sizeof(p));
        if (t->base == FFI_BASE_CSTR && p) {
            return vm_make_bytes_value(vm, (const char*)p, strlen((const char*)p));
        }
        return ffi_make_ptr_handle_entry(vm, (uintptr_t)p, 0);
    }
    switch (t->base) {
    case FFI_BASE_F32: {
        float v = 0.0f;
        memcpy(&v, argp, sizeof(v));
        return vm_make_float_value(vm, (Float)v);
    }
    case FFI_BASE_F64: {
        double v = 0.0;
        memcpy(&v, argp, sizeof(v));
        return vm_make_float_value(vm, (Float)v);
    }
    case FFI_BASE_I8: {
        int8_t v = 0;
        memcpy(&v, argp, sizeof(v));
        return vm_make_int_value(vm, (Int)v);
    }
    case FFI_BASE_U8: {
        uint8_t v = 0;
        memcpy(&v, argp, sizeof(v));
        return vm_make_int_value(vm, (Int)v);
    }
    case FFI_BASE_I16: {
        int16_t v = 0;
        memcpy(&v, argp, sizeof(v));
        return vm_make_int_value(vm, (Int)v);
    }
    case FFI_BASE_U16: {
        uint16_t v = 0;
        memcpy(&v, argp, sizeof(v));
        return vm_make_int_value(vm, (Int)v);
    }
    case FFI_BASE_I32: {
        int32_t v = 0;
        memcpy(&v, argp, sizeof(v));
        return vm_make_int_value(vm, (Int)v);
    }
    case FFI_BASE_U32: {
        uint32_t v = 0;
        memcpy(&v, argp, sizeof(v));
        return vm_make_int_value(vm, (Int)v);
    }
    case FFI_BASE_U64: {
        uint64_t v = 0;
        memcpy(&v, argp, sizeof(v));
        return vm_make_int_value(vm, (Int)v);
    }
    case FFI_BASE_I64:
    default: {
        int64_t v = 0;
        memcpy(&v, argp, sizeof(v));
        return vm_make_int_value(vm, (Int)v);
    }
    }
}

static void ffi_callback_write_ret(VM *vm, const FfiType *t, ObjEntry *ret_entry, void *ret_out)
{
    if (!t || !ret_out) return;
    if (t->base == FFI_BASE_VOID && !t->schema_name) return;
    if (!ret_entry) ret_entry = vm ? vm->null_entry : NULL;
    if (t->is_ptr || t->is_array || t->base == FFI_BASE_PTR || t->base == FFI_BASE_CSTR || (t->schema_name && t->schema_is_pointer)) {
        uintptr_t ptr = 0;
        if (ret_entry) ffi_entry_to_ptr(ret_entry, &ptr);
        void *p = (void*)ptr;
        memcpy(ret_out, &p, sizeof(p));
        return;
    }
    Int iv = 0;
    Float fv = 0;
    int is_float = 0;
    if (ret_entry) entry_number_scalar(ret_entry, &iv, &fv, &is_float);
    switch (t->base) {
    case FFI_BASE_F32: {
        float v = is_float ? (float)fv : (float)iv;
        memcpy(ret_out, &v, sizeof(v));
        break;
    }
    case FFI_BASE_F64: {
        double v = is_float ? (double)fv : (double)iv;
        memcpy(ret_out, &v, sizeof(v));
        break;
    }
    case FFI_BASE_I8: {
        int8_t v = (int8_t)(is_float ? fv : iv);
        memcpy(ret_out, &v, sizeof(v));
        break;
    }
    case FFI_BASE_U8: {
        uint8_t v = (uint8_t)(is_float ? fv : iv);
        memcpy(ret_out, &v, sizeof(v));
        break;
    }
    case FFI_BASE_I16: {
        int16_t v = (int16_t)(is_float ? fv : iv);
        memcpy(ret_out, &v, sizeof(v));
        break;
    }
    case FFI_BASE_U16: {
        uint16_t v = (uint16_t)(is_float ? fv : iv);
        memcpy(ret_out, &v, sizeof(v));
        break;
    }
    case FFI_BASE_I32: {
        int32_t v = (int32_t)(is_float ? fv : iv);
        memcpy(ret_out, &v, sizeof(v));
        break;
    }
    case FFI_BASE_U32: {
        uint32_t v = (uint32_t)(is_float ? fv : iv);
        memcpy(ret_out, &v, sizeof(v));
        break;
    }
    case FFI_BASE_U64: {
        uint64_t v = (uint64_t)(is_float ? fv : iv);
        memcpy(ret_out, &v, sizeof(v));
        break;
    }
    case FFI_BASE_I64:
    default: {
        int64_t v = (int64_t)(is_float ? fv : iv);
        memcpy(ret_out, &v, sizeof(v));
        break;
    }
    }
}

static void ffi_callback_dispatch(ffi_cif *cif, void *ret, void **args, void *userdata)
{
    (void)cif;
    FfiCallback *cb = (FfiCallback*)userdata;
    if (!cb || cb->magic != FFI_CALLBACK_MAGIC || !cb->vm) return;
    VM *vm = cb->vm;
    ObjEntry *lambda = vm_global_find_by_key(vm->global_entry->obj, cb->lambda_key);
    if (!lambda || lambda == vm->null_entry) {
        return;
    }

    ObjEntry **arg_entries = (ObjEntry**)calloc((size_t)cb->argc, sizeof(ObjEntry*));
    if (!arg_entries) return;
    for (int i = 0; i < cb->argc; i++) {
        arg_entries[i] = ffi_callback_arg_to_entry(vm, &cb->args[i], args[i]);
        if (!arg_entries[i]) arg_entries[i] = vm->null_entry;
    }
    ObjEntry *ret_entry = vm->null_entry;
    if (!vm_call_entry(vm, lambda, (uint32_t)cb->argc, arg_entries, &ret_entry) || !ret_entry) {
        ret_entry = vm->null_entry;
    }
    free(arg_entries);
    ffi_callback_write_ret(vm, &cb->ret, ret_entry, ret);
}
#endif

static int entry_is_string(ObjEntry *entry)
{
    return entry && entry->is_string && disturb_obj_type(entry->obj) == DISTURB_T_INT;
}

static int entry_number_scalar(ObjEntry *entry, Int *out_i, Float *out_f, int *out_is_float)
{
    if (!entry || !entry->in_use) return 0;
    Int type = disturb_obj_type(entry->obj);
    if (type == DISTURB_T_INT) {
        if (entry_is_string(entry)) return 0;
        if (disturb_bytes_len(entry->obj) != sizeof(Int)) return 0;
        Int v = 0;
        memcpy(&v, disturb_bytes_data(entry->obj), sizeof(Int));
        if (out_i) *out_i = v;
        if (out_f) *out_f = (Float)v;
        if (out_is_float) *out_is_float = 0;
        return 1;
    }
    if (type == DISTURB_T_FLOAT) {
        if (disturb_bytes_len(entry->obj) != sizeof(Float)) return 0;
        Float v = 0;
        memcpy(&v, disturb_bytes_data(entry->obj), sizeof(Float));
        if (out_i) *out_i = (Int)v;
        if (out_f) *out_f = v;
        if (out_is_float) *out_is_float = 1;
        return 1;
    }
    return 0;
}

static int entry_as_cstr(ObjEntry *entry, const char **out)
{
    if (!entry || !entry_is_string(entry)) return 0;
    *out = disturb_bytes_data(entry->obj);
    return 1;
}

static int ffi_entry_to_ptr(ObjEntry *entry, uintptr_t *out_ptr)
{
    if (!out_ptr) return 0;
    *out_ptr = 0;
    if (!entry || !entry->in_use || disturb_obj_type(entry->obj) == DISTURB_T_NULL) return 1;
    FfiPtrHandle *ph = ffi_ptr_handle_from_entry(entry);
    if (ph) {
        *out_ptr = ph->ptr;
        return 1;
    }
#ifdef DISTURB_ENABLE_FFI_CALLS
    FfiCallback *cb = ffi_callback_from_entry(entry);
    if (cb) {
        *out_ptr = (uintptr_t)cb->code_ptr;
        return 1;
    }
#endif
    uintptr_t base_ptr = 0;
    size_t base_offset = 0;
    FfiLayout *layout = NULL;
    if (ffi_view_decode(entry, &base_ptr, &base_offset, &layout, NULL)) {
        (void)layout;
        *out_ptr = base_ptr + base_offset;
        return 1;
    }
    Int iv = 0;
    Float fv = 0;
    int is_float = 0;
    if (entry_number_scalar(entry, &iv, &fv, &is_float)) {
        *out_ptr = (uintptr_t)(UInt)(is_float ? (Int)fv : iv);
        return 1;
    }
    return 0;
}

#ifdef DISTURB_ENABLE_FFI_CALLS
static ffi_type *ffi_type_for_base(FfiBase base)
{
    switch (base) {
    case FFI_BASE_I8: return &ffi_type_sint8;
    case FFI_BASE_U8: return &ffi_type_uint8;
    case FFI_BASE_I16: return &ffi_type_sint16;
    case FFI_BASE_U16: return &ffi_type_uint16;
    case FFI_BASE_I32: return &ffi_type_sint32;
    case FFI_BASE_U32: return &ffi_type_uint32;
    case FFI_BASE_I64: return &ffi_type_sint64;
    case FFI_BASE_U64: return &ffi_type_uint64;
    case FFI_BASE_F32: return &ffi_type_float;
    case FFI_BASE_F64: return &ffi_type_double;
    case FFI_BASE_CSTR: return &ffi_type_pointer;
    case FFI_BASE_PTR: return &ffi_type_pointer;
    case FFI_BASE_VOID: return &ffi_type_void;
    default: return &ffi_type_pointer;
    }
}

static size_t ffi_elem_size(const FfiType *t)
{
    switch (t->base) {
    case FFI_BASE_I8:
    case FFI_BASE_U8:
        return 1;
    case FFI_BASE_I16:
    case FFI_BASE_U16:
        return 2;
    case FFI_BASE_I32:
    case FFI_BASE_U32:
    case FFI_BASE_F32:
        return 4;
    case FFI_BASE_I64:
    case FFI_BASE_U64:
    case FFI_BASE_F64:
        return 8;
    default:
        return sizeof(void*);
    }
}
#endif

static size_t ffi_align_up(size_t value, size_t align)
{
    if (align <= 1) return value;
    size_t rem = value % align;
    return rem ? (value + (align - rem)) : value;
}

UNUSED_FN static uint64_t ffi_hash_bytes(const char *data, size_t len)
{
    uint64_t h = 1469598103934665603ULL;
    for (size_t i = 0; i < len; i++) {
        h ^= (unsigned char)data[i];
        h *= 1099511628211ULL;
    }
    return h;
}

UNUSED_FN static void ffi_sigbuf_init(FfiSigBuf *b)
{
    b->data = NULL;
    b->len = 0;
    b->cap = 0;
}

UNUSED_FN static int ffi_sigbuf_grow(FfiSigBuf *b, size_t add)
{
    if (add > SIZE_MAX - b->len - 1) return 0;
    size_t need = b->len + add + 1;
    if (need <= b->cap) return 1;
    size_t next = b->cap ? b->cap : 128;
    while (next < need) {
        if (next > SIZE_MAX / 2) return 0;
        next *= 2;
    }
    char *p = (char*)realloc(b->data, next);
    if (!p) return 0;
    b->data = p;
    b->cap = next;
    return 1;
}

UNUSED_FN static int ffi_sigbuf_append_bytes(FfiSigBuf *b, const char *s, size_t len)
{
    if (!len) return 1;
    if (!ffi_sigbuf_grow(b, len)) return 0;
    memcpy(b->data + b->len, s, len);
    b->len += len;
    b->data[b->len] = 0;
    return 1;
}

UNUSED_FN static int ffi_sigbuf_append_cstr(FfiSigBuf *b, const char *s)
{
    return ffi_sigbuf_append_bytes(b, s, strlen(s));
}

UNUSED_FN static int ffi_sigbuf_append_u64(FfiSigBuf *b, uint64_t v)
{
    char tmp[32];
    int n = snprintf(tmp, sizeof(tmp), "%llu", (unsigned long long)v);
    if (n < 0) return 0;
    return ffi_sigbuf_append_bytes(b, tmp, (size_t)n);
}

UNUSED_FN static void ffi_sigbuf_free(FfiSigBuf *b)
{
    free(b->data);
    b->data = NULL;
    b->len = 0;
    b->cap = 0;
}

static ObjEntry *ffi_table_find_field(List *obj, const char *name, size_t name_len)
{
    if (!obj || disturb_obj_type(obj) != DISTURB_T_TABLE) return NULL;
    for (Int i = 2; i < obj->size; i++) {
        ObjEntry *entry = (ObjEntry*)obj->data[i].p;
        ObjEntry *key = vm_entry_key(entry);
        if (!key || !entry_is_string(key)) continue;
        if (disturb_bytes_len(key->obj) != name_len) continue;
        if (memcmp(disturb_bytes_data(key->obj), name, name_len) == 0) return entry;
    }
    return NULL;
}

static ObjEntry *ffi_lookup_schema_entry(VM *vm, const char *name, size_t name_len)
{
    if (!vm || !name || name_len == 0) return NULL;
    if (vm->local_entry && vm->local_entry->obj &&
        disturb_obj_type(vm->local_entry->obj) == DISTURB_T_TABLE) {
        ObjEntry *local_hit = ffi_table_find_field(vm->local_entry->obj, name, name_len);
        if (local_hit && disturb_obj_type(local_hit->obj) != DISTURB_T_NULL) return local_hit;
    }
    char tmp[96];
    char *q = tmp;
    if (name_len + 1 > sizeof(tmp)) {
        q = (char*)malloc(name_len + 1);
        if (!q) return NULL;
    }
    memcpy(q, name, name_len);
    q[name_len] = 0;
    ObjEntry *global_hit = vm_global_find_by_key(vm->global_entry ? vm->global_entry->obj : NULL, q);
    if (q != tmp) free(q);
    if (global_hit && disturb_obj_type(global_hit->obj) == DISTURB_T_NULL) return NULL;
    return global_hit;
}

typedef struct {
    const char *name;
    size_t name_len;
    ObjEntry *value;
} FfiSchemaFieldRef;

typedef struct {
    int packed;
    int has_align;
    int align;
    int is_union;
} FfiSchemaMeta;

static int ffi_parse_schema_meta(ObjEntry *schema, FfiSchemaMeta *meta, char *err, size_t err_cap)
{
    meta->packed = 0;
    meta->has_align = 0;
    meta->align = 0;
    meta->is_union = 0;
    if (!schema || disturb_obj_type(schema->obj) != DISTURB_T_TABLE) return 1;
    ObjEntry *meta_entry = ffi_table_find_field(schema->obj, "__meta", 6);
    if (!meta_entry || disturb_obj_type(meta_entry->obj) == DISTURB_T_NULL) return 1;
    if (disturb_obj_type(meta_entry->obj) != DISTURB_T_TABLE) {
        snprintf(err, err_cap, "ffi: schema.__meta must be a table");
        return 0;
    }
    ObjEntry *packed_entry = ffi_table_find_field(meta_entry->obj, "packed", 6);
    if (packed_entry) {
        Int iv = 0;
        Float fv = 0;
        int is_float = 0;
        if (!entry_number_scalar(packed_entry, &iv, &fv, &is_float)) {
            snprintf(err, err_cap, "ffi: schema.__meta.packed expects number");
            return 0;
        }
        meta->packed = is_float ? (((Int)fv) != 0) : (iv != 0);
    }
    ObjEntry *align_entry = ffi_table_find_field(meta_entry->obj, "align", 5);
    if (align_entry) {
        Int iv = 0;
        Float fv = 0;
        int is_float = 0;
        if (!entry_number_scalar(align_entry, &iv, &fv, &is_float)) {
            snprintf(err, err_cap, "ffi: schema.__meta.align expects integer");
            return 0;
        }
        if (is_float) {
            Int cast = (Int)fv;
            if ((Float)cast != fv) {
                snprintf(err, err_cap, "ffi: schema.__meta.align expects integer");
                return 0;
            }
            iv = cast;
        }
        if (iv <= 0) {
            snprintf(err, err_cap, "ffi: schema.__meta.align expects positive integer");
            return 0;
        }
        meta->has_align = 1;
        meta->align = (int)iv;
    }
    ObjEntry *union_entry = ffi_table_find_field(meta_entry->obj, "union", 5);
    if (union_entry) {
        Int iv = 0;
        Float fv = 0;
        int is_float = 0;
        if (!entry_number_scalar(union_entry, &iv, &fv, &is_float)) {
            snprintf(err, err_cap, "ffi: schema.__meta.union expects number");
            return 0;
        }
        meta->is_union = is_float ? (((Int)fv) != 0) : (iv != 0);
    }
    return 1;
}

static int ffi_schema_collect_fields(ObjEntry *schema, FfiSchemaFieldRef **out_fields,
                                     int *out_count, char *err, size_t err_cap)
{
    *out_fields = NULL;
    *out_count = 0;
    if (!schema || disturb_obj_type(schema->obj) != DISTURB_T_TABLE) {
        snprintf(err, err_cap, "ffi: schema struct must be a table");
        return 0;
    }
    List *obj = schema->obj;
    int count = 0;
    for (Int i = 2; i < obj->size; i++) {
        ObjEntry *entry = (ObjEntry*)obj->data[i].p;
        ObjEntry *key = vm_entry_key(entry);
        if (!key || !entry_is_string(key)) continue;
        size_t klen = disturb_bytes_len(key->obj);
        const char *k = disturb_bytes_data(key->obj);
        if ((klen == 6 && memcmp(k, "__meta", 6) == 0) ||
            (klen == 7 && memcmp(k, "__order", 7) == 0)) {
            continue;
        }
        count++;
    }
    if (count <= 0) {
        *out_fields = NULL;
        *out_count = 0;
        return 1;
    }
    FfiSchemaFieldRef *fields = (FfiSchemaFieldRef*)calloc((size_t)count, sizeof(FfiSchemaFieldRef));
    if (!fields) {
        snprintf(err, err_cap, "ffi: out of memory");
        return 0;
    }

    unsigned char *used = (unsigned char*)calloc((size_t)count, 1);
    if (!used) {
        free(fields);
        snprintf(err, err_cap, "ffi: out of memory");
        return 0;
    }

    int out = 0;
    ObjEntry *order_entry = ffi_table_find_field(obj, "__order", 7);
    if (order_entry && disturb_obj_type(order_entry->obj) != DISTURB_T_NULL) {
        if (disturb_obj_type(order_entry->obj) != DISTURB_T_TABLE) {
            free(used);
            free(fields);
            snprintf(err, err_cap, "ffi: schema.__order must be a table of field names");
            return 0;
        }
        for (Int oi = 2; oi < order_entry->obj->size; oi++) {
            ObjEntry *name_entry = (ObjEntry*)order_entry->obj->data[oi].p;
            if (!name_entry || !entry_is_string(name_entry)) {
                free(used);
                free(fields);
                snprintf(err, err_cap, "ffi: schema.__order expects only string names");
                return 0;
            }
            const char *name = disturb_bytes_data(name_entry->obj);
            size_t name_len = disturb_bytes_len(name_entry->obj);
            ObjEntry *field = ffi_table_find_field(obj, name, name_len);
            if (!field) {
                free(used);
                free(fields);
                snprintf(err, err_cap, "ffi: schema.__order references unknown field");
                return 0;
            }
            int duplicate = 0;
            for (int j = 0; j < out; j++) {
                if (fields[j].name_len == name_len && memcmp(fields[j].name, name, name_len) == 0) {
                    duplicate = 1;
                    break;
                }
            }
            if (duplicate) continue;
            fields[out].name = name;
            fields[out].name_len = name_len;
            fields[out].value = field;
            out++;
        }
    }

    for (Int i = 2; i < obj->size; i++) {
        ObjEntry *entry = (ObjEntry*)obj->data[i].p;
        ObjEntry *key = vm_entry_key(entry);
        if (!key || !entry_is_string(key)) continue;
        const char *name = disturb_bytes_data(key->obj);
        size_t name_len = disturb_bytes_len(key->obj);
        if ((name_len == 6 && memcmp(name, "__meta", 6) == 0) ||
            (name_len == 7 && memcmp(name, "__order", 7) == 0)) {
            continue;
        }
        int seen = 0;
        for (int j = 0; j < out; j++) {
            if (fields[j].name_len == name_len && memcmp(fields[j].name, name, name_len) == 0) {
                seen = 1;
                break;
            }
        }
        if (seen) continue;
        fields[out].name = name;
        fields[out].name_len = name_len;
        fields[out].value = entry;
        out++;
    }

    (void)used;
    free(used);
    *out_fields = fields;
    *out_count = out;
    return 1;
}

static int ffi_parse_schema_type_string(const char *name, size_t len,
                                        FfiBase *out_base, int *out_is_array, int *out_len, int *out_bits,
                                        int *out_is_const)
{
    if (!name || len == 0 || len >= 64) return 0;
    char buf[64];
    memcpy(buf, name, len);
    buf[len] = 0;
    if (out_bits) *out_bits = 0;
    if (out_is_const) *out_is_const = 0;

    char *cursor = buf;
    int saw_const = 0;
    for (;;) {
        while (*cursor == ' ' || *cursor == '\t' || *cursor == '\n' || *cursor == '\r') cursor++;
        if (strncmp(cursor, "const", 5) == 0 &&
            (cursor[5] == 0 || cursor[5] == ' ' || cursor[5] == '\t' || cursor[5] == '\n' || cursor[5] == '\r')) {
            saw_const = 1;
            cursor += 5;
            continue;
        }
        if (strncmp(cursor, "volatile", 8) == 0 &&
            (cursor[8] == 0 || cursor[8] == ' ' || cursor[8] == '\t' || cursor[8] == '\n' || cursor[8] == '\r')) {
            cursor += 8;
            continue;
        }
        if (strncmp(cursor, "restrict", 8) == 0 &&
            (cursor[8] == 0 || cursor[8] == ' ' || cursor[8] == '\t' || cursor[8] == '\n' || cursor[8] == '\r')) {
            cursor += 8;
            continue;
        }
        break;
    }
    if (cursor != buf) {
        size_t remain = strlen(cursor);
        memmove(buf, cursor, remain + 1);
    }

    char *lb = strchr(buf, '[');
    int is_array = 0;
    int array_len = 0;
    if (lb) {
        char *rb = strchr(lb + 1, ']');
        if (!rb || rb[1] != 0) return 0;
        *lb = 0;
        *rb = 0;
        if (lb[1] == 0) {
            is_array = 1;
            array_len = -1; /* unsized pointer-style */
        } else {
            char *end = NULL;
            long n = strtol(lb + 1, &end, 10);
            if (!end || *end != 0 || n <= 0 || n > INT_MAX) return 0;
            is_array = 1;
            array_len = (int)n;
        }
    }

    char *colon = strchr(buf, ':');
    if (colon) {
        if (is_array) return 0;
        char *end = NULL;
        long bits = strtol(colon + 1, &end, 10);
        if (!end || *end != 0 || bits <= 0 || bits > 64) return 0;
        *colon = 0;
        if (out_bits) *out_bits = (int)bits;
    }

    FfiBase base = FFI_BASE_VOID;
    if (!parse_base_type(buf, &base)) {
        if (strcmp(buf, "int8") == 0) base = FFI_BASE_I8;
        else if (strcmp(buf, "uint8") == 0) base = FFI_BASE_U8;
        else if (strcmp(buf, "int16") == 0) base = FFI_BASE_I16;
        else if (strcmp(buf, "uint16") == 0) base = FFI_BASE_U16;
        else if (strcmp(buf, "int32") == 0) base = FFI_BASE_I32;
        else if (strcmp(buf, "uint32") == 0) base = FFI_BASE_U32;
        else if (strcmp(buf, "int64") == 0) base = FFI_BASE_I64;
        else if (strcmp(buf, "uint64") == 0) base = FFI_BASE_U64;
        else if (strcmp(buf, "float32") == 0) base = FFI_BASE_F32;
        else if (strcmp(buf, "float64") == 0) base = FFI_BASE_F64;
        else if (strcmp(buf, "ptr") == 0) base = FFI_BASE_PTR;
        else return 0;
    }

    if (out_base) *out_base = base;
    if (out_is_array) *out_is_array = is_array;
    if (out_len) *out_len = array_len;
    if (out_is_const) *out_is_const = saw_const;
    return 1;
}

static int ffi_parse_schema_fnptr_string(const char *name, size_t len, int *out_is_const,
                                         char *out_sig, size_t out_sig_cap)
{
    if (!name || len == 0 || !out_sig || out_sig_cap == 0) return 0;
    while (len > 0 && (*name == ' ' || *name == '\t' || *name == '\n' || *name == '\r')) {
        name++;
        len--;
    }
    while (len > 0 && (name[len - 1] == ' ' || name[len - 1] == '\t' || name[len - 1] == '\n' || name[len - 1] == '\r')) {
        len--;
    }
    int saw_const = 0;
    for (;;) {
        while (len > 0 && (*name == ' ' || *name == '\t' || *name == '\n' || *name == '\r')) {
            name++;
            len--;
        }
        if (len >= 5 && memcmp(name, "const", 5) == 0 &&
            (len == 5 || name[5] == ' ' || name[5] == '\t' || name[5] == '\n' || name[5] == '\r')) {
            saw_const = 1;
            name += 5;
            len -= 5;
            continue;
        }
        if (len >= 8 && memcmp(name, "volatile", 8) == 0 &&
            (len == 8 || name[8] == ' ' || name[8] == '\t' || name[8] == '\n' || name[8] == '\r')) {
            name += 8;
            len -= 8;
            continue;
        }
        if (len >= 8 && memcmp(name, "restrict", 8) == 0 &&
            (len == 8 || name[8] == ' ' || name[8] == '\t' || name[8] == '\n' || name[8] == '\r')) {
            name += 8;
            len -= 8;
            continue;
        }
        break;
    }

    while (len > 0 && (*name == ' ' || *name == '\t' || *name == '\n' || *name == '\r')) {
        name++;
        len--;
    }
    size_t head_len = 0;
    if (len >= 10 && memcmp(name, "function<", 9) == 0 && name[len - 1] == '>') {
        head_len = 9;
    } else if (len >= 5 && memcmp(name, "fn<", 3) == 0 && name[len - 1] == '>') {
        head_len = 3; /* compatibility alias */
    } else {
        return 0;
    }
    size_t sig_len = len - (head_len + 1); /* function<...> or fn<...> */
    if (sig_len == 0 || sig_len + 1 > out_sig_cap) return 0;
    memcpy(out_sig, name + head_len, sig_len);
    out_sig[sig_len] = 0;
    if (out_is_const) *out_is_const = saw_const ? 1 : 0;
    return 1;
}

static int ffi_parse_schema_ref_string(const char *name, size_t len,
                                       int *out_is_pointer, int *out_is_union, int *out_is_const,
                                       char *out_schema, size_t out_cap)
{
    if (!name || len == 0 || !out_schema || out_cap == 0) return 0;
    int saw_const = 0;
    while (len > 0 && (*name == ' ' || *name == '\t' || *name == '\n' || *name == '\r')) {
        name++;
        len--;
    }
    while (len >= 5 && memcmp(name, "const", 5) == 0 &&
           (name[5] == 0 || name[5] == ' ' || name[5] == '\t' || name[5] == '\n' || name[5] == '\r')) {
        saw_const = 1;
        name += 5;
        len -= 5;
        while (len > 0 && (*name == ' ' || *name == '\t' || *name == '\n' || *name == '\r')) {
            name++;
            len--;
        }
    }
    while (len >= 8 && memcmp(name, "volatile", 8) == 0 &&
           (name[8] == 0 || name[8] == ' ' || name[8] == '\t' || name[8] == '\n' || name[8] == '\r')) {
        name += 8;
        len -= 8;
        while (len > 0 && (*name == ' ' || *name == '\t' || *name == '\n' || *name == '\r')) {
            name++;
            len--;
        }
    }
    while (len >= 8 && memcmp(name, "restrict", 8) == 0 &&
           (name[8] == 0 || name[8] == ' ' || name[8] == '\t' || name[8] == '\n' || name[8] == '\r')) {
        name += 8;
        len -= 8;
        while (len > 0 && (*name == ' ' || *name == '\t' || *name == '\n' || *name == '\r')) {
            name++;
            len--;
        }
    }
    while (len > 0) {
        char c = name[len - 1];
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') len--;
        else break;
    }
    const char *prefix = NULL;
    size_t prefix_len = 0;
    int is_pointer = 0;
    int is_union = 0;
    if (len > 8 && memcmp(name, "struct<", 7) == 0 && name[len - 1] == '>') {
        prefix = name + 7;
        prefix_len = len - 8;
        is_pointer = 0;
        is_union = 0;
    } else if (len > 7 && memcmp(name, "union<", 6) == 0 && name[len - 1] == '>') {
        prefix = name + 6;
        prefix_len = len - 7;
        is_pointer = 0;
        is_union = 1;
    } else if (len > 9 && memcmp(name, "pointer<", 8) == 0 && name[len - 1] == '>') {
        prefix = name + 8;
        prefix_len = len - 9;
        is_pointer = 1;
        is_union = 0;
    } else {
        return 0;
    }
    while (prefix_len > 0 && (*prefix == ' ' || *prefix == '\t' || *prefix == '\n' || *prefix == '\r')) {
        prefix++;
        prefix_len--;
    }
    while (prefix_len > 0) {
        char c = prefix[prefix_len - 1];
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') prefix_len--;
        else break;
    }
    if (prefix_len == 0 || prefix_len + 1 > out_cap) return 0;
    for (size_t i = 0; i < prefix_len; i++) {
        char c = prefix[i];
        if (!(isalnum((unsigned char)c) || c == '_')) return 0;
    }
    memcpy(out_schema, prefix, prefix_len);
    out_schema[prefix_len] = 0;
    if (out_is_pointer) *out_is_pointer = is_pointer;
    if (out_is_union) *out_is_union = is_union;
    if (out_is_const) *out_is_const = saw_const;
    return 1;
}

static int ffi_decl_has_const_prefix(const char *name, size_t len)
{
    if (!name || len == 0) return 0;
    while (len > 0 && (*name == ' ' || *name == '\t' || *name == '\n' || *name == '\r')) {
        name++;
        len--;
    }
    for (;;) {
        if (len >= 5 && memcmp(name, "const", 5) == 0 &&
            (len == 5 || name[5] == ' ' || name[5] == '\t' || name[5] == '\n' || name[5] == '\r')) {
            return 1;
        }
        if (len >= 8 && memcmp(name, "volatile", 8) == 0 &&
            (len == 8 || name[8] == ' ' || name[8] == '\t' || name[8] == '\n' || name[8] == '\r')) {
            name += 8;
            len -= 8;
            while (len > 0 && (*name == ' ' || *name == '\t' || *name == '\n' || *name == '\r')) {
                name++;
                len--;
            }
            continue;
        }
        if (len >= 8 && memcmp(name, "restrict", 8) == 0 &&
            (len == 8 || name[8] == ' ' || name[8] == '\t' || name[8] == '\n' || name[8] == '\r')) {
            name += 8;
            len -= 8;
            while (len > 0 && (*name == ' ' || *name == '\t' || *name == '\n' || *name == '\r')) {
                name++;
                len--;
            }
            continue;
        }
        break;
    }
    return 0;
}

static int ffi_type_spec_from_entry(ObjEntry *entry, FfiBase *out_base, int *out_is_array, int *out_len, int *out_is_const)
{
    const char *name = NULL;
    if (!entry_as_cstr(entry, &name)) return 0;
    return ffi_parse_schema_type_string(name, disturb_bytes_len(entry->obj),
                                        out_base, out_is_array, out_len, NULL, out_is_const);
}

static int ffi_schema_ref_spec_from_entry(ObjEntry *entry, int *out_is_pointer,
                                          int *out_is_union,
                                          int *out_is_const,
                                          char *out_schema, size_t out_cap)
{
    const char *name = NULL;
    if (!entry_as_cstr(entry, &name)) return 0;
    return ffi_parse_schema_ref_string(name, disturb_bytes_len(entry->obj),
                                       out_is_pointer, out_is_union, out_is_const, out_schema, out_cap);
}

static void ffi_layout_free(FfiLayout *layout)
{
    if (!layout) return;
    if (layout->pointee) {
        ffi_layout_free(layout->pointee);
        layout->pointee = NULL;
    }
    if (layout->kind == FFI_LAYOUT_ARRAY && layout->elem) {
        ffi_layout_free(layout->elem);
    }
    if (layout->kind == FFI_LAYOUT_STRUCT && layout->fields) {
        for (int i = 0; i < layout->field_count; i++) {
            free(layout->fields[i].name);
            free(layout->fields[i].fn_sig);
            ffi_layout_free(layout->fields[i].layout);
        }
        free(layout->fields);
    }
    free(layout);
}

static int ffi_prim_size_align(FfiBase base, size_t *out_size, size_t *out_align)
{
    switch (base) {
    case FFI_BASE_I8:
    case FFI_BASE_U8:
        *out_size = 1; *out_align = 1; return 1;
    case FFI_BASE_I16:
    case FFI_BASE_U16:
        *out_size = 2; *out_align = 2; return 1;
    case FFI_BASE_I32:
    case FFI_BASE_U32:
    case FFI_BASE_F32:
        *out_size = 4; *out_align = 4; return 1;
    case FFI_BASE_I64:
    case FFI_BASE_U64:
    case FFI_BASE_F64:
        *out_size = 8; *out_align = 8; return 1;
    case FFI_BASE_PTR:
        *out_size = sizeof(void*);
        *out_align = sizeof(void*);
        return 1;
    default:
        return 0;
    }
}

UNUSED_FN static int ffi_build_schema_sig(VM *vm, ObjEntry *schema, FfiSigBuf *sig, int depth, char *err, size_t err_cap);

UNUSED_FN static int ffi_append_field_name_sig(FfiSigBuf *sig, const char *name, size_t len)
{
    return ffi_sigbuf_append_cstr(sig, "N") &&
           ffi_sigbuf_append_u64(sig, (uint64_t)len) &&
           ffi_sigbuf_append_cstr(sig, ":") &&
           ffi_sigbuf_append_bytes(sig, name, len);
}

UNUSED_FN static int ffi_build_schema_sig(VM *vm, ObjEntry *schema, FfiSigBuf *sig, int depth, char *err, size_t err_cap)
{
    if (depth > 64) {
        snprintf(err, err_cap, "ffi: schema nesting too deep");
        return 0;
    }

    {
        const char *fn_decl = NULL;
        char fn_sig[192];
        int fn_const = 0;
        if (entry_as_cstr(schema, &fn_decl) &&
            ffi_parse_schema_fnptr_string(fn_decl, disturb_bytes_len(schema->obj), &fn_const,
                                          fn_sig, sizeof(fn_sig))) {
            return ffi_sigbuf_append_cstr(sig, "Fnptr(") &&
                   ffi_sigbuf_append_cstr(sig, fn_sig) &&
                   ffi_sigbuf_append_cstr(sig, ",") &&
                   ffi_sigbuf_append_u64(sig, (uint64_t)(fn_const ? 1 : 0)) &&
                   ffi_sigbuf_append_cstr(sig, ")");
        }
        FfiBase base = FFI_BASE_VOID;
        int is_array = 0;
        int array_len = 0;
        int is_const = 0;
        if (ffi_type_spec_from_entry(schema, &base, &is_array, &array_len, &is_const)) {
            if (!is_array || array_len < 0) {
                /* Unsized [] is treated like pointer to first element. */
                FfiBase out_base = (!is_array) ? base : FFI_BASE_PTR;
                return ffi_sigbuf_append_cstr(sig, "P") &&
                       ffi_sigbuf_append_u64(sig, (uint64_t)out_base) &&
                       ffi_sigbuf_append_cstr(sig, ",c=") &&
                       ffi_sigbuf_append_u64(sig, (uint64_t)(is_const ? 1 : 0)) &&
                       ffi_sigbuf_append_cstr(sig, ";");
            }
            return ffi_sigbuf_append_cstr(sig, "A(") &&
                   ffi_sigbuf_append_u64(sig, (uint64_t)base) &&
                   ffi_sigbuf_append_cstr(sig, ",") &&
                   ffi_sigbuf_append_u64(sig, (uint64_t)array_len) &&
                   ffi_sigbuf_append_cstr(sig, ",c=") &&
                   ffi_sigbuf_append_u64(sig, (uint64_t)(is_const ? 1 : 0)) &&
                   ffi_sigbuf_append_cstr(sig, ");");
        }
        int schema_is_pointer = 0;
        int schema_is_union = 0;
        int schema_is_const = 0;
        char schema_name[96];
        if (ffi_schema_ref_spec_from_entry(schema, &schema_is_pointer, &schema_is_union, &schema_is_const, schema_name, sizeof(schema_name))) {
            if (schema_is_pointer) {
                return ffi_sigbuf_append_cstr(sig, "Rptr(") &&
                       ffi_sigbuf_append_cstr(sig, schema_name) &&
                       ffi_sigbuf_append_cstr(sig, ",c=") &&
                       ffi_sigbuf_append_u64(sig, (uint64_t)(schema_is_const ? 1 : 0)) &&
                       ffi_sigbuf_append_cstr(sig, ");");
            }
            ObjEntry *ref_schema = ffi_lookup_schema_entry(vm, schema_name, strlen(schema_name));
            if (!ref_schema) {
                snprintf(err, err_cap, "ffi: unknown schema '%s' in schema field", schema_name);
                return 0;
            }
            return ffi_sigbuf_append_cstr(sig, schema_is_union ? "Runion(" : "Rval(") &&
                   ffi_sigbuf_append_cstr(sig, schema_name) &&
                   ffi_sigbuf_append_cstr(sig, ",c=") &&
                   ffi_sigbuf_append_u64(sig, (uint64_t)(schema_is_const ? 1 : 0)) &&
                   ffi_sigbuf_append_cstr(sig, "){") &&
                   ffi_build_schema_sig(vm, ref_schema, sig, depth + 1, err, err_cap) &&
                   ffi_sigbuf_append_cstr(sig, "};");
        }
    }

    if (!schema || disturb_obj_type(schema->obj) != DISTURB_T_TABLE) {
        Int type = (!schema || !schema->obj) ? DISTURB_T_NULL : disturb_obj_type(schema->obj);
        snprintf(err, err_cap, "ffi: schema field must be type string (got %s)",
                 disturb_type_name(type));
        return 0;
    }
    FfiSchemaMeta meta;
    if (!ffi_parse_schema_meta(schema, &meta, err, err_cap)) return 0;
    FfiSchemaFieldRef *fields = NULL;
    int field_count = 0;
    if (!ffi_schema_collect_fields(schema, &fields, &field_count, err, err_cap)) return 0;

    int ok = 1;
    ok = ok && ffi_sigbuf_append_cstr(sig, "S(");
    ok = ok && ffi_sigbuf_append_cstr(sig, "p=") && ffi_sigbuf_append_u64(sig, (uint64_t)(meta.packed ? 1 : 0));
    ok = ok && ffi_sigbuf_append_cstr(sig, ",a=");
    ok = ok && ffi_sigbuf_append_u64(sig, (uint64_t)(meta.has_align ? meta.align : 0));
    ok = ok && ffi_sigbuf_append_cstr(sig, "){");
    for (int i = 0; ok && i < field_count; i++) {
        const char *field_decl = NULL;
        if (!entry_as_cstr(fields[i].value, &field_decl)) {
            free(fields);
            snprintf(err, err_cap, "ffi: schema field '%.*s' must be a type string",
                     (int)fields[i].name_len, fields[i].name);
            return 0;
        }
        ok = ok && ffi_append_field_name_sig(sig, fields[i].name, fields[i].name_len);
        ok = ok && ffi_sigbuf_append_cstr(sig, "=");
        ok = ok && ffi_build_schema_sig(vm, fields[i].value, sig, depth + 1, err, err_cap);
        ok = ok && ffi_sigbuf_append_cstr(sig, ";");
    }
    ok = ok && ffi_sigbuf_append_cstr(sig, "}");

    free(fields);
    if (!ok) {
        snprintf(err, err_cap, "ffi: out of memory");
        return 0;
    }
    return 1;
}

static FfiLayout *ffi_compile_schema_layout(VM *vm, ObjEntry *schema, int depth, char *err, size_t err_cap)
{
    if (depth > 64) {
        snprintf(err, err_cap, "ffi: schema nesting too deep");
        return NULL;
    }

    {
        const char *fn_decl = NULL;
        char fn_sig[192];
        int fn_const = 0;
        if (entry_as_cstr(schema, &fn_decl) &&
            ffi_parse_schema_fnptr_string(fn_decl, disturb_bytes_len(schema->obj), &fn_const,
                                          fn_sig, sizeof(fn_sig))) {
            size_t size = sizeof(void*);
            FfiLayout *layout = (FfiLayout*)calloc(1, sizeof(FfiLayout));
            if (!layout) {
                snprintf(err, err_cap, "ffi: out of memory");
                return NULL;
            }
            layout->kind = FFI_LAYOUT_PRIM;
            layout->base = FFI_BASE_PTR;
            layout->is_const = fn_const ? 1 : 0;
            layout->size = size;
            layout->align = size;
            return layout;
        }

        FfiBase base = FFI_BASE_VOID;
        int is_array = 0;
        int array_len = 0;
        int bit_width = 0;
        int is_const = 0;
        const char *type_name = NULL;
        if (entry_as_cstr(schema, &type_name) &&
            ffi_parse_schema_type_string(type_name, disturb_bytes_len(schema->obj),
                                         &base, &is_array, &array_len, &bit_width, &is_const)) {
            if (!is_array || array_len < 0) {
                FfiBase out_base = (!is_array) ? base : FFI_BASE_PTR;
                size_t size = 0;
                size_t align = 0;
                if (!ffi_prim_size_align(out_base, &size, &align)) {
                    snprintf(err, err_cap, "ffi: unsupported primitive in schema");
                    return NULL;
                }
                FfiLayout *layout = (FfiLayout*)calloc(1, sizeof(FfiLayout));
                if (!layout) {
                    snprintf(err, err_cap, "ffi: out of memory");
                    return NULL;
                }
                layout->kind = FFI_LAYOUT_PRIM;
                layout->base = out_base;
                layout->is_const = is_const ? 1 : 0;
                layout->size = size;
                layout->align = align;
                layout->bit_width = bit_width;
                return layout;
            }

            FfiLayout *elem = (FfiLayout*)calloc(1, sizeof(FfiLayout));
            FfiLayout *arr = (FfiLayout*)calloc(1, sizeof(FfiLayout));
            size_t elem_size = 0;
            size_t elem_align = 0;
            if (!elem || !arr || !ffi_prim_size_align(base, &elem_size, &elem_align)) {
                free(elem);
                free(arr);
                snprintf(err, err_cap, "ffi: unsupported or out of memory");
                return NULL;
            }
            elem->kind = FFI_LAYOUT_PRIM;
            elem->base = base;
            elem->is_const = is_const ? 1 : 0;
            elem->size = elem_size;
            elem->align = elem_align;

            arr->kind = FFI_LAYOUT_ARRAY;
            arr->is_const = is_const ? 1 : 0;
            arr->elem = elem;
            arr->array_len = array_len;
            arr->align = elem_align;
            arr->size = elem_size * (size_t)array_len;
            return arr;
        }
        int schema_is_pointer = 0;
        int schema_is_union = 0;
        int schema_is_const = 0;
        char schema_name[96];
        if (ffi_schema_ref_spec_from_entry(schema, &schema_is_pointer, &schema_is_union, &schema_is_const, schema_name, sizeof(schema_name))) {
            if (schema_is_pointer) {
                size_t size = sizeof(void*);
                FfiLayout *layout = (FfiLayout*)calloc(1, sizeof(FfiLayout));
                if (!layout) {
                    snprintf(err, err_cap, "ffi: out of memory");
                    return NULL;
                }
                layout->kind = FFI_LAYOUT_PRIM;
                layout->base = FFI_BASE_PTR;
                layout->is_const = schema_is_const ? 1 : 0;
                layout->size = size;
                layout->align = size;
                ObjEntry *ref_schema = ffi_lookup_schema_entry(vm, schema_name, strlen(schema_name));
                if (!ref_schema) {
                    ffi_layout_free(layout);
                    snprintf(err, err_cap, "ffi: unknown schema '%s' in schema field", schema_name);
                    return NULL;
                }
                FfiLayout *pointee = ffi_compile_schema_layout(vm, ref_schema, depth + 1, err, err_cap);
                if (!pointee || pointee->kind != FFI_LAYOUT_STRUCT) {
                    if (pointee) ffi_layout_free(pointee);
                    ffi_layout_free(layout);
                    if (!err[0]) snprintf(err, err_cap, "ffi: pointer<%s> requires struct schema", schema_name);
                    return NULL;
                }
                layout->pointee = pointee;
                return layout;
            }
            ObjEntry *ref_schema = ffi_lookup_schema_entry(vm, schema_name, strlen(schema_name));
            if (!ref_schema) {
                snprintf(err, err_cap, "ffi: unknown schema '%s' in schema field", schema_name);
                return NULL;
            }
            FfiLayout *resolved = ffi_compile_schema_layout(vm, ref_schema, depth + 1, err, err_cap);
            if (!resolved) return NULL;
            if (schema_is_union && !resolved->is_union) {
                ffi_layout_free(resolved);
                snprintf(err, err_cap, "ffi: union<%s> requires union schema", schema_name);
                return NULL;
            }
            if (!schema_is_union && resolved->is_union) {
                ffi_layout_free(resolved);
                snprintf(err, err_cap, "ffi: struct<%s> cannot reference union schema; use union<%s>",
                         schema_name, schema_name);
                return NULL;
            }
            return resolved;
        }
    }

    if (!schema || disturb_obj_type(schema->obj) != DISTURB_T_TABLE) {
        Int type = (!schema || !schema->obj) ? DISTURB_T_NULL : disturb_obj_type(schema->obj);
        snprintf(err, err_cap, "ffi: schema field must be type string (got %s)",
                 disturb_type_name(type));
        return NULL;
    }
    FfiSchemaMeta meta;
    if (!ffi_parse_schema_meta(schema, &meta, err, err_cap)) return NULL;

    FfiSchemaFieldRef *fields_ref = NULL;
    int field_count = 0;
    if (!ffi_schema_collect_fields(schema, &fields_ref, &field_count, err, err_cap)) return NULL;

    FfiLayout *layout = (FfiLayout*)calloc(1, sizeof(FfiLayout));
    if (!layout) {
        free(fields_ref);
        snprintf(err, err_cap, "ffi: out of memory");
        return NULL;
    }
    layout->kind = FFI_LAYOUT_STRUCT;
    layout->packed = meta.packed;
    layout->forced_align = meta.has_align ? meta.align : 0;
    layout->is_union = meta.is_union;
    layout->field_count = field_count;
    if (field_count > 0) {
        layout->fields = (FfiLayoutField*)calloc((size_t)field_count, sizeof(FfiLayoutField));
        if (!layout->fields) {
            free(fields_ref);
            ffi_layout_free(layout);
            snprintf(err, err_cap, "ffi: out of memory");
            return NULL;
        }
    }

    size_t offset = 0;
    size_t max_align = meta.packed ? 1 : 1;
    size_t union_size = 0;
    int bf_open = 0;
    FfiBase bf_base = FFI_BASE_VOID;
    size_t bf_container_size = 0;
    size_t bf_container_align = 1;
    int bf_used = 0;
    size_t bf_offset = 0;
    for (int i = 0; i < field_count; i++) {
        if (!fields_ref[i].value) {
            snprintf(err, err_cap, "ffi: schema field value missing");
            free(fields_ref);
            ffi_layout_free(layout);
            return NULL;
        }
        const char *field_decl = NULL;
        if (!entry_as_cstr(fields_ref[i].value, &field_decl)) {
            snprintf(err, err_cap, "ffi: schema field '%.*s' must be a type string",
                     (int)fields_ref[i].name_len, fields_ref[i].name);
            free(fields_ref);
            ffi_layout_free(layout);
            return NULL;
        }
        FfiLayout *child = ffi_compile_schema_layout(vm, fields_ref[i].value, depth + 1, err, err_cap);
        if (!child) {
            free(fields_ref);
            ffi_layout_free(layout);
            return NULL;
        }
        char *name = (char*)malloc(fields_ref[i].name_len + 1);
        if (!name) {
            free(fields_ref);
            ffi_layout_free(child);
            ffi_layout_free(layout);
            snprintf(err, err_cap, "ffi: out of memory");
            return NULL;
        }
        memcpy(name, fields_ref[i].name, fields_ref[i].name_len);
        name[fields_ref[i].name_len] = 0;

        size_t field_align = meta.packed ? 1 : child->align;
        if (field_align == 0) field_align = 1;

        int bit_width = child->bit_width;
        int bit_shift = 0;
        if (bit_width > 0) {
            size_t container_bits = child->size * 8;
            if (!(child->base == FFI_BASE_I8 || child->base == FFI_BASE_U8 ||
                  child->base == FFI_BASE_I16 || child->base == FFI_BASE_U16 ||
                  child->base == FFI_BASE_I32 || child->base == FFI_BASE_U32 ||
                  child->base == FFI_BASE_I64 || child->base == FFI_BASE_U64) ||
                (size_t)bit_width > container_bits || meta.is_union) {
                snprintf(err, err_cap, "ffi: invalid bitfield declaration");
                free(name);
                free(fields_ref);
                ffi_layout_free(child);
                ffi_layout_free(layout);
                return NULL;
            }
            if (!bf_open || bf_base != child->base ||
                (size_t)(bf_used + bit_width) > container_bits) {
                if (bf_open) offset = bf_offset + bf_container_size;
                bf_open = 1;
                bf_base = child->base;
                bf_container_size = child->size;
                bf_container_align = field_align;
                offset = ffi_align_up(offset, bf_container_align);
                bf_offset = offset;
                bf_used = 0;
            }
            bit_shift = bf_used;
            bf_used += bit_width;
            if ((size_t)bf_used == container_bits) {
                offset = bf_offset + bf_container_size;
                bf_open = 0;
                bf_used = 0;
            }
        } else if (bf_open) {
            offset = bf_offset + bf_container_size;
            bf_open = 0;
            bf_used = 0;
        }

        size_t field_offset = 0;
        if (meta.is_union) {
            field_offset = 0;
            if (child->size > union_size) union_size = child->size;
        } else if (bit_width > 0) {
            field_offset = bf_offset;
        } else {
            offset = ffi_align_up(offset, field_align);
            field_offset = offset;
            offset += child->size;
        }
        layout->fields[i].name = name;
        layout->fields[i].name_len = fields_ref[i].name_len;
        layout->fields[i].offset = field_offset;
        layout->fields[i].layout = child;
        {
            char fn_sig[192];
            int fn_const = 0;
            if (ffi_parse_schema_fnptr_string(field_decl, disturb_bytes_len(fields_ref[i].value->obj),
                                              &fn_const, fn_sig, sizeof(fn_sig))) {
                size_t n = strlen(fn_sig);
                layout->fields[i].fn_sig = (char*)malloc(n + 1);
                if (!layout->fields[i].fn_sig) {
                    snprintf(err, err_cap, "ffi: out of memory");
                    free(fields_ref);
                    ffi_layout_free(layout);
                    return NULL;
                }
                memcpy(layout->fields[i].fn_sig, fn_sig, n + 1);
            }
        }
        layout->fields[i].is_const = (child->is_const ||
                                      ffi_decl_has_const_prefix(field_decl, disturb_bytes_len(fields_ref[i].value->obj))) ? 1 : 0;
        layout->fields[i].bit_width = bit_width;
        layout->fields[i].bit_shift = bit_shift;
        if (field_align > max_align) max_align = field_align;
    }
    if (bf_open) {
        offset = bf_offset + bf_container_size;
    }
    free(fields_ref);

    size_t struct_align = meta.packed ? 1 : max_align;
    if (layout->forced_align > 0 && (size_t)layout->forced_align > struct_align) {
        struct_align = (size_t)layout->forced_align;
    }
    if (struct_align == 0) struct_align = 1;
    layout->align = struct_align;
    size_t payload = meta.is_union ? union_size : offset;
    layout->size = ffi_align_up(payload, struct_align);
    return layout;
}

UNUSED_FN static FfiLayout *ffi_cache_lookup(uint64_t hash, const char *sig, size_t sig_len)
{
    for (FfiLayoutCacheNode *it = g_ffi_layout_cache; it; it = it->next) {
        if (it->hash != hash) continue;
        if (it->sig_len != sig_len) continue;
        if (memcmp(it->sig, sig, sig_len) == 0) return it->layout;
    }
    return NULL;
}

UNUSED_FN static int ffi_cache_insert(uint64_t hash, const char *sig, size_t sig_len, FfiLayout *layout)
{
    FfiLayoutCacheNode *node = (FfiLayoutCacheNode*)calloc(1, sizeof(FfiLayoutCacheNode));
    if (!node) return 0;
    node->sig = (char*)malloc(sig_len + 1);
    if (!node->sig) {
        free(node);
        return 0;
    }
    memcpy(node->sig, sig, sig_len);
    node->sig[sig_len] = 0;
    node->sig_len = sig_len;
    node->hash = hash;
    node->layout = layout;
    node->next = g_ffi_layout_cache;
    g_ffi_layout_cache = node;
    return 1;
}

static FfiLayout *ffi_compile_schema_cached(VM *vm, ObjEntry *schema, char *err, size_t err_cap)
{
    return ffi_compile_schema_layout(vm, schema, 0, err, err_cap);
}

static FfiLayoutHandle *ffi_layout_handle_new(FfiLayout *layout)
{
    FfiLayoutHandle *h = (FfiLayoutHandle*)calloc(1, sizeof(FfiLayoutHandle));
    if (!h) return NULL;
    h->magic = FFI_LAYOUT_HANDLE_MAGIC;
    h->refcount = 1;
    h->layout = layout;
    return h;
}

static void ffi_layout_handle_clone(void *data)
{
    FfiLayoutHandle *h = (FfiLayoutHandle*)data;
    if (!h || h->magic != FFI_LAYOUT_HANDLE_MAGIC) return;
    h->refcount++;
}

static void ffi_layout_handle_free(void *data)
{
    FfiLayoutHandle *h = (FfiLayoutHandle*)data;
    if (!h || h->magic != FFI_LAYOUT_HANDLE_MAGIC) return;
    h->refcount--;
    if (h->refcount <= 0) {
        h->magic = 0;
        free(h);
    }
}

static FfiLayoutHandle *ffi_layout_handle_from_entry(ObjEntry *entry)
{
    if (!entry || disturb_obj_type(entry->obj) != DISTURB_T_NATIVE || entry->obj->size < 3) return NULL;
    NativeBox *box = (NativeBox*)entry->obj->data[2].p;
    if (!box || !box->data) return NULL;
    FfiLayoutHandle *h = (FfiLayoutHandle*)box->data;
    if (!h || h->magic != FFI_LAYOUT_HANDLE_MAGIC) return NULL;
    return h;
}

static FfiViewHandle *ffi_view_handle_new(uintptr_t base_ptr, FfiLayout *layout, size_t base_offset, void *owned_mem, int readonly)
{
    FfiViewHandle *h = (FfiViewHandle*)calloc(1, sizeof(FfiViewHandle));
    if (!h) return NULL;
    h->magic = FFI_VIEW_HANDLE_MAGIC;
    h->refcount = 1;
    h->base_ptr = base_ptr;
    h->base_offset = base_offset;
    h->layout = layout;
    h->owned_mem = owned_mem;
    h->readonly = readonly ? 1 : 0;
    return h;
}

static void ffi_view_handle_clone(void *data)
{
    FfiViewHandle *h = (FfiViewHandle*)data;
    if (!h || h->magic != FFI_VIEW_HANDLE_MAGIC) return;
    h->refcount++;
}

static void ffi_view_handle_free(void *data)
{
    FfiViewHandle *h = (FfiViewHandle*)data;
    if (!h || h->magic != FFI_VIEW_HANDLE_MAGIC) return;
    h->refcount--;
    if (h->refcount <= 0) {
        free(h->owned_mem);
        h->owned_mem = NULL;
        h->magic = 0;
        free(h);
    }
}

static FfiViewHandle *ffi_view_handle_from_entry(ObjEntry *entry)
{
    if (!entry || disturb_obj_type(entry->obj) != DISTURB_T_NATIVE || entry->obj->size < 3) return NULL;
    NativeBox *box = (NativeBox*)entry->obj->data[2].p;
    if (!box || !box->data) return NULL;
    FfiViewHandle *h = (FfiViewHandle*)box->data;
    if (!h || h->magic != FFI_VIEW_HANDLE_MAGIC) return NULL;
    return h;
}

static FfiArrayViewHandle *ffi_array_view_handle_new(uintptr_t base_ptr, FfiLayout *elem_layout, int len, int own_elem_layout, int readonly)
{
    FfiArrayViewHandle *h = (FfiArrayViewHandle*)calloc(1, sizeof(FfiArrayViewHandle));
    if (!h) return NULL;
    h->magic = FFI_ARRAY_VIEW_HANDLE_MAGIC;
    h->refcount = 1;
    h->base_ptr = base_ptr;
    h->elem_layout = elem_layout;
    h->len = len;
    h->own_elem_layout = own_elem_layout ? 1 : 0;
    h->readonly = readonly ? 1 : 0;
    return h;
}

static FfiPtrHandle *ffi_ptr_handle_new(uintptr_t ptr, int owned)
{
    FfiPtrHandle *h = (FfiPtrHandle*)calloc(1, sizeof(FfiPtrHandle));
    if (!h) return NULL;
    h->magic = FFI_PTR_HANDLE_MAGIC;
    h->refcount = 1;
    h->ptr = ptr;
    h->owned = owned ? 1 : 0;
    return h;
}

static void ffi_ptr_handle_clone(void *data)
{
    FfiPtrHandle *h = (FfiPtrHandle*)data;
    if (!h || h->magic != FFI_PTR_HANDLE_MAGIC) return;
    h->refcount++;
}

static void ffi_ptr_handle_free(void *data)
{
    FfiPtrHandle *h = (FfiPtrHandle*)data;
    if (!h || h->magic != FFI_PTR_HANDLE_MAGIC) return;
    h->refcount--;
    if (h->refcount > 0) return;
    if (h->owned && h->ptr) {
        free((void*)h->ptr);
        h->ptr = 0;
    }
    h->magic = 0;
    free(h);
}

static FfiPtrHandle *ffi_ptr_handle_from_entry(ObjEntry *entry)
{
    if (!entry || disturb_obj_type(entry->obj) != DISTURB_T_NATIVE || entry->obj->size < 3) return NULL;
    NativeBox *box = (NativeBox*)entry->obj->data[2].p;
    if (!box || !box->data) return NULL;
    FfiPtrHandle *h = (FfiPtrHandle*)box->data;
    if (!h || h->magic != FFI_PTR_HANDLE_MAGIC) return NULL;
    return h;
}

static ObjEntry *ffi_make_ptr_handle_entry(VM *vm, uintptr_t ptr, int owned)
{
    FfiPtrHandle *h = ffi_ptr_handle_new(ptr, owned);
    if (!h) return NULL;
    ObjEntry *entry = vm_make_native_entry_data(vm, NULL, native_ffi_handle_noop, h,
                                                ffi_ptr_handle_free, ffi_ptr_handle_clone);
    if (!entry) {
        ffi_ptr_handle_free(h);
        return NULL;
    }
    return entry;
}

#ifdef DISTURB_ENABLE_FFI_CALLS
static FfiLibHandle *ffi_lib_handle_new(void *handle)
{
    FfiLibHandle *h = (FfiLibHandle*)calloc(1, sizeof(FfiLibHandle));
    if (!h) return NULL;
    h->magic = FFI_LIB_HANDLE_MAGIC;
    h->refcount = 1;
    h->handle = handle;
    return h;
}

static void ffi_lib_handle_clone(void *data)
{
    FfiLibHandle *h = (FfiLibHandle*)data;
    if (!h || h->magic != FFI_LIB_HANDLE_MAGIC) return;
    h->refcount++;
}

static void ffi_lib_handle_free(void *data)
{
    FfiLibHandle *h = (FfiLibHandle*)data;
    if (!h || h->magic != FFI_LIB_HANDLE_MAGIC) return;
    h->refcount--;
    if (h->refcount > 0) return;
    if (h->handle) {
        ffi_dlclose(h->handle);
        h->handle = NULL;
    }
    h->magic = 0;
    free(h);
}

static FfiLibHandle *ffi_lib_handle_from_entry(ObjEntry *entry)
{
    if (!entry || disturb_obj_type(entry->obj) != DISTURB_T_NATIVE || entry->obj->size < 3) return NULL;
    NativeBox *box = (NativeBox*)entry->obj->data[2].p;
    if (!box || !box->data) return NULL;
    FfiLibHandle *h = (FfiLibHandle*)box->data;
    if (!h || h->magic != FFI_LIB_HANDLE_MAGIC) return NULL;
    return h;
}
#endif

static void ffi_array_view_handle_clone(void *data)
{
    FfiArrayViewHandle *h = (FfiArrayViewHandle*)data;
    if (!h || h->magic != FFI_ARRAY_VIEW_HANDLE_MAGIC) return;
    h->refcount++;
}

static void ffi_array_view_handle_free(void *data)
{
    FfiArrayViewHandle *h = (FfiArrayViewHandle*)data;
    if (!h || h->magic != FFI_ARRAY_VIEW_HANDLE_MAGIC) return;
    h->refcount--;
    if (h->refcount <= 0) {
        if (h->own_elem_layout && h->elem_layout) {
            ffi_layout_free(h->elem_layout);
            h->elem_layout = NULL;
        }
        h->magic = 0;
        free(h);
    }
}

static FfiArrayViewHandle *ffi_array_view_handle_from_entry(ObjEntry *entry)
{
    if (!entry || disturb_obj_type(entry->obj) != DISTURB_T_NATIVE || entry->obj->size < 3) return NULL;
    NativeBox *box = (NativeBox*)entry->obj->data[2].p;
    if (!box || !box->data) return NULL;
    FfiArrayViewHandle *h = (FfiArrayViewHandle*)box->data;
    if (!h || h->magic != FFI_ARRAY_VIEW_HANDLE_MAGIC) return NULL;
    return h;
}

static FfiLayoutField *ffi_layout_find_field(FfiLayout *layout, const char *name, size_t len)
{
    if (!layout || layout->kind != FFI_LAYOUT_STRUCT) return NULL;
    for (int i = 0; i < layout->field_count; i++) {
        if (layout->fields[i].name_len != len) continue;
        if (memcmp(layout->fields[i].name, name, len) == 0) return &layout->fields[i];
    }
    return NULL;
}

#ifdef DISTURB_ENABLE_FFI_CALLS
typedef struct {
    const char *src;
    size_t pos;
} SigParser;

static void sig_skip_ws(SigParser *p)
{
    while (p->src[p->pos] == ' ' || p->src[p->pos] == '\t' || p->src[p->pos] == '\n' || p->src[p->pos] == '\r') {
        p->pos++;
    }
}

static int sig_is_ident_start(char c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_';
}

static int sig_is_ident_char(char c)
{
    return sig_is_ident_start(c) || (c >= '0' && c <= '9');
}

static int sig_read_ident(SigParser *p, char *out, size_t cap)
{
    sig_skip_ws(p);
    size_t start = p->pos;
    if (!sig_is_ident_start(p->src[p->pos])) return 0;
    p->pos++;
    while (sig_is_ident_char(p->src[p->pos])) p->pos++;
    size_t len = p->pos - start;
    if (len >= cap) len = cap - 1;
    memcpy(out, p->src + start, len);
    out[len] = 0;
    return 1;
}

static int sig_skip_qualifier(SigParser *p)
{
    size_t old = p->pos;
    char ident[32];
    if (!sig_read_ident(p, ident, sizeof(ident))) return 0;
    if (strcmp(ident, "const") == 0 ||
        strcmp(ident, "volatile") == 0 ||
        strcmp(ident, "restrict") == 0) {
        return 1;
    }
    p->pos = old;
    return 0;
}

static void sig_skip_qualifiers(SigParser *p)
{
    while (sig_skip_qualifier(p)) { }
}

static int sig_read_number(SigParser *p, int *out)
{
    sig_skip_ws(p);
    int value = 0;
    int has = 0;
    while (p->src[p->pos] >= '0' && p->src[p->pos] <= '9') {
        has = 1;
        value = value * 10 + (p->src[p->pos] - '0');
        p->pos++;
    }
    if (!has) return 0;
    *out = value;
    return 1;
}

static int sig_match_char(SigParser *p, char c)
{
    sig_skip_ws(p);
    if (p->src[p->pos] == c) {
        p->pos++;
        return 1;
    }
    return 0;
}

static int sig_match_ellipsis(SigParser *p)
{
    sig_skip_ws(p);
    if (p->src[p->pos] == '.' && p->src[p->pos + 1] == '.' && p->src[p->pos + 2] == '.') {
        p->pos += 3;
        return 1;
    }
    return 0;
}

static int parse_base_type(const char *name, FfiBase *out)
{
    if (strcmp(name, "void") == 0) { *out = FFI_BASE_VOID; return 1; }
    if (strcmp(name, "char") == 0) { *out = FFI_BASE_I8; return 1; }
    if (strcmp(name, "schar") == 0) { *out = FFI_BASE_I8; return 1; }
    if (strcmp(name, "uchar") == 0 || strcmp(name, "u8") == 0) { *out = FFI_BASE_U8; return 1; }
    if (strcmp(name, "int8_t") == 0) { *out = FFI_BASE_I8; return 1; }
    if (strcmp(name, "uint8_t") == 0) { *out = FFI_BASE_U8; return 1; }
    if (strcmp(name, "i8") == 0) { *out = FFI_BASE_I8; return 1; }
    if (strcmp(name, "i16") == 0 || strcmp(name, "short") == 0) { *out = FFI_BASE_I16; return 1; }
    if (strcmp(name, "u16") == 0 || strcmp(name, "ushort") == 0) { *out = FFI_BASE_U16; return 1; }
    if (strcmp(name, "int16_t") == 0) { *out = FFI_BASE_I16; return 1; }
    if (strcmp(name, "uint16_t") == 0) { *out = FFI_BASE_U16; return 1; }
    if (strcmp(name, "i32") == 0 || strcmp(name, "int") == 0) { *out = FFI_BASE_I32; return 1; }
    if (strcmp(name, "u32") == 0 || strcmp(name, "uint") == 0) { *out = FFI_BASE_U32; return 1; }
    if (strcmp(name, "int32_t") == 0) { *out = FFI_BASE_I32; return 1; }
    if (strcmp(name, "uint32_t") == 0) { *out = FFI_BASE_U32; return 1; }
    if (strcmp(name, "i64") == 0 || strcmp(name, "long") == 0 || strcmp(name, "longlong") == 0) { *out = FFI_BASE_I64; return 1; }
    if (strcmp(name, "u64") == 0 || strcmp(name, "ulong") == 0 || strcmp(name, "ulonglong") == 0) { *out = FFI_BASE_U64; return 1; }
    if (strcmp(name, "int64_t") == 0) { *out = FFI_BASE_I64; return 1; }
    if (strcmp(name, "uint64_t") == 0) { *out = FFI_BASE_U64; return 1; }
    if (strcmp(name, "f32") == 0 || strcmp(name, "float") == 0) { *out = FFI_BASE_F32; return 1; }
    if (strcmp(name, "f64") == 0 || strcmp(name, "double") == 0) { *out = FFI_BASE_F64; return 1; }
    if (strcmp(name, "size_t") == 0 || strcmp(name, "uintptr_t") == 0) {
#if SIZE_MAX == UINT64_MAX
        *out = FFI_BASE_U64;
#else
        *out = FFI_BASE_U32;
#endif
        return 1;
    }
    if (strcmp(name, "intptr_t") == 0 || strcmp(name, "ptrdiff_t") == 0) {
#if SIZE_MAX == UINT64_MAX
        *out = FFI_BASE_I64;
#else
        *out = FFI_BASE_I32;
#endif
        return 1;
    }
    return 0;
}

static int sig_parse_type(SigParser *p, FfiType *out, char *err, size_t err_cap)
{
    memset(out, 0, sizeof(*out));
    sig_skip_ws(p);
    sig_skip_qualifiers(p);

    char ident[64];
    if (!sig_read_ident(p, ident, sizeof(ident))) {
        snprintf(err, err_cap, "expected type");
        return 0;
    }

    if (strcmp(ident, "struct") == 0 || strcmp(ident, "union") == 0 || strcmp(ident, "pointer") == 0) {
        int is_ptr_schema = (strcmp(ident, "pointer") == 0);
        int is_union_schema = (strcmp(ident, "union") == 0);
        if (!sig_match_char(p, '<')) {
            snprintf(err, err_cap, "expected '<' after %s", ident);
            return 0;
        }
        char schema[64];
        if (!sig_read_ident(p, schema, sizeof(schema))) {
            snprintf(err, err_cap, "expected schema name in %s<...>", ident);
            return 0;
        }
        if (!sig_match_char(p, '>')) {
            snprintf(err, err_cap, "expected '>' after schema name");
            return 0;
        }
        out->schema_name = ffi_strdup(schema);
        if (!out->schema_name) {
            snprintf(err, err_cap, "out of memory");
            return 0;
        }
        out->schema_is_pointer = is_ptr_schema;
        out->schema_is_union = is_union_schema;
        out->base = FFI_BASE_VOID;
        out->is_ptr = 0;
        out->is_array = 0;
        out->array_len = -1;
        sig_skip_ws(p);
        if (p->src[p->pos] == '*' || p->src[p->pos] == '[') {
            snprintf(err, err_cap, "%s<%s> does not support '*' or '[]' suffix",
                     ident, schema);
            free(out->schema_name);
            out->schema_name = NULL;
            out->schema_is_pointer = 0;
            out->schema_is_union = 0;
            return 0;
        }
        return 1;
    }

    char combined[64];
    combined[0] = 0;
    if (strcmp(ident, "unsigned") == 0) {
        char next[64];
        if (!sig_read_ident(p, next, sizeof(next))) {
            snprintf(err, err_cap, "expected type after unsigned");
            return 0;
        }
        if (strcmp(next, "long") == 0) {
            size_t old_pos = p->pos;
            char next2[64];
            if (sig_read_ident(p, next2, sizeof(next2)) && strcmp(next2, "long") == 0) {
                snprintf(combined, sizeof(combined), "ulonglong");
            } else {
                p->pos = old_pos;
                snprintf(combined, sizeof(combined), "ulong");
            }
        } else {
            size_t next_len = strlen(next);
            if (next_len > sizeof(combined) - 2) next_len = sizeof(combined) - 2;
            combined[0] = 'u';
            memcpy(combined + 1, next, next_len);
            combined[1 + next_len] = 0;
        }
    } else if (strcmp(ident, "signed") == 0) {
        char next[64];
        if (!sig_read_ident(p, next, sizeof(next))) {
            snprintf(err, err_cap, "expected type after signed");
            return 0;
        }
        if (strcmp(next, "long") == 0) {
            size_t old_pos = p->pos;
            char next2[64];
            if (sig_read_ident(p, next2, sizeof(next2)) && strcmp(next2, "long") == 0) {
                snprintf(combined, sizeof(combined), "longlong");
            } else {
                p->pos = old_pos;
                snprintf(combined, sizeof(combined), "long");
            }
        } else {
            snprintf(combined, sizeof(combined), "%s", next);
        }
    } else if (strcmp(ident, "long") == 0) {
        size_t old_pos = p->pos;
        char next[64];
        if (sig_read_ident(p, next, sizeof(next)) && strcmp(next, "long") == 0) {
            snprintf(combined, sizeof(combined), "longlong");
        } else {
            p->pos = old_pos;
            snprintf(combined, sizeof(combined), "long");
        }
    } else {
        snprintf(combined, sizeof(combined), "%s", ident);
    }

    FfiBase base = FFI_BASE_VOID;
    if (!parse_base_type(combined, &base)) {
        snprintf(err, err_cap, "unknown type '%s'", combined);
        return 0;
    }

    int is_ptr = 0;
    int is_array = 0;
    int array_len = -1;

    sig_skip_ws(p);
    if (sig_match_char(p, '*')) {
        is_ptr = 1;
        sig_skip_qualifiers(p);
    }

    sig_skip_ws(p);
    if (sig_match_char(p, '[')) {
        int n = 0;
        if (sig_read_number(p, &n)) {
            array_len = n;
        } else {
            array_len = 0;
        }
        if (!sig_match_char(p, ']')) {
            snprintf(err, err_cap, "expected ']'");
            return 0;
        }
        is_array = 1;
        is_ptr = 1;
    }

    if (base == FFI_BASE_I8 || base == FFI_BASE_U8) {
        if (is_ptr) {
            base = FFI_BASE_CSTR;
        }
    }

    if (base == FFI_BASE_VOID && is_ptr) {
        base = FFI_BASE_PTR;
    }

    out->base = base;
    out->is_ptr = is_ptr;
    out->is_array = is_array;
    out->array_len = array_len;
    return 1;
}

static int sig_skip_arg_name(SigParser *p)
{
    char tmp[64];
    return sig_read_ident(p, tmp, sizeof(tmp));
}

static char *ffi_strdup(const char *s)
{
    size_t len = strlen(s);
    char *out = (char*)malloc(len + 1);
    if (!out) return NULL;
    memcpy(out, s, len);
    out[len] = 0;
    return out;
}

static FfiFunction *ffi_parse_signature(const char *sig, char *err, size_t err_cap, const char **out_name)
{
    SigParser p = { sig, 0 };
    FfiType ret = {0};
    if (!sig_parse_type(&p, &ret, err, err_cap)) return NULL;
    char name[128];
    if (!sig_read_ident(&p, name, sizeof(name))) {
        snprintf(err, err_cap, "expected function name");
        return NULL;
    }
    if (!sig_match_char(&p, '(')) {
        snprintf(err, err_cap, "expected '('");
        return NULL;
    }

    FfiType *args = NULL;
    int argc = 0;
    int fixed_argc = 0;
    int has_varargs = 0;
    int cap = 0;
    sig_skip_ws(&p);
    if (sig_match_char(&p, ')')) {
        // no args
    } else {
        for (;;) {
            if (sig_match_ellipsis(&p)) {
                has_varargs = 1;
                fixed_argc = argc;
                sig_skip_ws(&p);
                if (!sig_match_char(&p, ')')) {
                    snprintf(err, err_cap, "variadic marker '...' must be last");
                    ffi_types_release_array(args, argc);
                    free(args);
                    ffi_type_release_runtime(&ret);
                    return NULL;
                }
                break;
            }
            FfiType arg = {0};
            if (!sig_parse_type(&p, &arg, err, err_cap)) {
                ffi_types_release_array(args, argc);
                free(args);
                ffi_type_release_runtime(&ret);
                return NULL;
            }
            sig_skip_arg_name(&p);
            if (argc == cap) {
                int next = cap == 0 ? 4 : cap * 2;
                FfiType *tmp = (FfiType*)realloc(args, (size_t)next * sizeof(FfiType));
                if (!tmp) {
                    snprintf(err, err_cap, "out of memory");
                    ffi_type_release_runtime(&arg);
                    ffi_types_release_array(args, argc);
                    free(args);
                    ffi_type_release_runtime(&ret);
                    return NULL;
                }
                args = tmp;
                cap = next;
            }
            args[argc++] = arg;
            sig_skip_ws(&p);
            if (sig_match_char(&p, ',')) continue;
            if (sig_match_char(&p, ')')) break;
            snprintf(err, err_cap, "expected ',' or ')'");
            ffi_types_release_array(args, argc);
            free(args);
            ffi_type_release_runtime(&ret);
            return NULL;
        }
    }

    FfiFunction *fn = (FfiFunction*)calloc(1, sizeof(FfiFunction));
    if (!fn) {
        ffi_types_release_array(args, argc);
        free(args);
        ffi_type_release_runtime(&ret);
        return NULL;
    }
    fn->refcount = 1;
    fn->ret = ret;
    fn->args = args;
    fn->argc = argc;
    fn->fixed_argc = has_varargs ? fixed_argc : argc;
    fn->has_varargs = has_varargs;
    *out_name = ffi_strdup(name);
    if (!*out_name) {
        ffi_types_release_array(args, argc);
        ffi_type_release_runtime(&ret);
        free(args);
        free(fn);
        return NULL;
    }
    return fn;
}
#endif

#ifndef DISTURB_ENABLE_FFI_CALLS
static int parse_base_type(const char *name, FfiBase *out)
{
    if (strcmp(name, "void") == 0) { *out = FFI_BASE_VOID; return 1; }
    if (strcmp(name, "char") == 0) { *out = FFI_BASE_I8; return 1; }
    if (strcmp(name, "schar") == 0) { *out = FFI_BASE_I8; return 1; }
    if (strcmp(name, "uchar") == 0 || strcmp(name, "u8") == 0) { *out = FFI_BASE_U8; return 1; }
    if (strcmp(name, "int8_t") == 0) { *out = FFI_BASE_I8; return 1; }
    if (strcmp(name, "uint8_t") == 0) { *out = FFI_BASE_U8; return 1; }
    if (strcmp(name, "i8") == 0) { *out = FFI_BASE_I8; return 1; }
    if (strcmp(name, "i16") == 0 || strcmp(name, "short") == 0) { *out = FFI_BASE_I16; return 1; }
    if (strcmp(name, "u16") == 0 || strcmp(name, "ushort") == 0) { *out = FFI_BASE_U16; return 1; }
    if (strcmp(name, "int16_t") == 0) { *out = FFI_BASE_I16; return 1; }
    if (strcmp(name, "uint16_t") == 0) { *out = FFI_BASE_U16; return 1; }
    if (strcmp(name, "i32") == 0 || strcmp(name, "int") == 0) { *out = FFI_BASE_I32; return 1; }
    if (strcmp(name, "u32") == 0 || strcmp(name, "uint") == 0) { *out = FFI_BASE_U32; return 1; }
    if (strcmp(name, "int32_t") == 0) { *out = FFI_BASE_I32; return 1; }
    if (strcmp(name, "uint32_t") == 0) { *out = FFI_BASE_U32; return 1; }
    if (strcmp(name, "i64") == 0 || strcmp(name, "long") == 0 || strcmp(name, "longlong") == 0) { *out = FFI_BASE_I64; return 1; }
    if (strcmp(name, "u64") == 0 || strcmp(name, "ulong") == 0 || strcmp(name, "ulonglong") == 0) { *out = FFI_BASE_U64; return 1; }
    if (strcmp(name, "int64_t") == 0) { *out = FFI_BASE_I64; return 1; }
    if (strcmp(name, "uint64_t") == 0) { *out = FFI_BASE_U64; return 1; }
    if (strcmp(name, "f32") == 0 || strcmp(name, "float") == 0) { *out = FFI_BASE_F32; return 1; }
    if (strcmp(name, "f64") == 0 || strcmp(name, "double") == 0) { *out = FFI_BASE_F64; return 1; }
    if (strcmp(name, "size_t") == 0 || strcmp(name, "uintptr_t") == 0) {
#if SIZE_MAX == UINT64_MAX
        *out = FFI_BASE_U64;
#else
        *out = FFI_BASE_U32;
#endif
        return 1;
    }
    if (strcmp(name, "intptr_t") == 0 || strcmp(name, "ptrdiff_t") == 0) {
#if SIZE_MAX == UINT64_MAX
        *out = FFI_BASE_I64;
#else
        *out = FFI_BASE_I32;
#endif
        return 1;
    }
    return 0;
}
#endif

#ifdef DISTURB_ENABLE_FFI_CALLS
static ObjEntry *ffi_make_int_list(VM *vm, int count)
{
    ObjEntry *entry = vm_make_int_list(vm, (Int)count);
    if (!entry) return NULL;
    return entry;
}

static ObjEntry *ffi_make_float_list(VM *vm, int count)
{
    ObjEntry *entry = vm_make_float_list(vm, (Int)count);
    if (!entry) return NULL;
    return entry;
}

static void ffi_fill_int_list(ObjEntry *entry, const void *ptr, int count, size_t elem_size, int is_signed)
{
    (void)is_signed;
    if (!entry || !ptr || count <= 0) return;
    char *dst = disturb_bytes_data(entry->obj);
    for (int i = 0; i < count; i++) {
        int64_t v = 0;
        memcpy(&v, (const char*)ptr + (size_t)i * elem_size, elem_size);
        memcpy(dst + (size_t)i * sizeof(Int), &v, sizeof(Int));
    }
}

static void ffi_fill_float_list(ObjEntry *entry, const void *ptr, int count, size_t elem_size)
{
    if (!entry || !ptr || count <= 0) return;
    char *dst = disturb_bytes_data(entry->obj);
    for (int i = 0; i < count; i++) {
        double v = 0.0;
        memcpy(&v, (const char*)ptr + (size_t)i * elem_size, elem_size);
        Float out = (Float)v;
        memcpy(dst + (size_t)i * sizeof(Float), &out, sizeof(Float));
    }
}

static int ffi_arg_is_float(const FfiType *t)
{
    return t->base == FFI_BASE_F32 || t->base == FFI_BASE_F64;
}

static int ffi_arg_is_int(const FfiType *t)
{
    switch (t->base) {
    case FFI_BASE_I8:
    case FFI_BASE_U8:
    case FFI_BASE_I16:
    case FFI_BASE_U16:
    case FFI_BASE_I32:
    case FFI_BASE_U32:
    case FFI_BASE_I64:
    case FFI_BASE_U64:
        return 1;
    default:
        return 0;
    }
}

#ifdef DISTURB_ENABLE_FFI_CALLS
static ffi_type *ffi_type_for_vararg_entry(ObjEntry *arg, int *out_kind)
{
    if (out_kind) *out_kind = 0; /* 1=int64,2=double,3=ptr */
    if (!arg || disturb_obj_type(arg->obj) == DISTURB_T_NULL) {
        if (out_kind) *out_kind = 3;
        return &ffi_type_pointer;
    }
    Int t = disturb_obj_type(arg->obj);
    if (t == DISTURB_T_FLOAT) {
        if (out_kind) *out_kind = 2;
        return &ffi_type_double;
    }
    if (t == DISTURB_T_INT) {
        if (entry_is_string(arg)) {
            if (out_kind) *out_kind = 3;
            return &ffi_type_pointer;
        }
        if (out_kind) *out_kind = 1;
        return &ffi_type_sint64;
    }
    if (out_kind) *out_kind = 3;
    return &ffi_type_pointer;
}
#endif
#endif

static void ffi_push_entry(VM *vm, ObjEntry *entry)
{
    if (!vm || !vm->stack_entry || !entry) return;
    List *old_stack = vm->stack_entry->obj;
    List *stack = disturb_table_add(old_stack, entry);
    stack = vm_update_shared_obj(vm, old_stack, stack);
    vm->stack_entry->obj = stack;
}

static void native_ffi_handle_noop(VM *vm, List *stack, List *global)
{
    (void)vm;
    (void)stack;
    (void)global;
}

static ObjEntry *ffi_make_array_view_entry(VM *vm, uintptr_t base_ptr, FfiLayout *elem_layout, int len, int readonly)
{
    FfiArrayViewHandle *h = ffi_array_view_handle_new(base_ptr, elem_layout, len, 0, readonly);
    if (!h) return NULL;
    ObjEntry *entry = vm_make_native_entry_data(vm, NULL, native_ffi_handle_noop, h,
                                                ffi_array_view_handle_free, ffi_array_view_handle_clone);
    if (!entry) {
        ffi_array_view_handle_free(h);
        return NULL;
    }
    return entry;
}

static ObjEntry *ffi_make_array_view_entry_owned(VM *vm, uintptr_t base_ptr, FfiLayout *elem_layout, int len, int readonly)
{
    FfiArrayViewHandle *h = ffi_array_view_handle_new(base_ptr, elem_layout, len, 1, readonly);
    if (!h) return NULL;
    ObjEntry *entry = vm_make_native_entry_data(vm, NULL, native_ffi_handle_noop, h,
                                                ffi_array_view_handle_free, ffi_array_view_handle_clone);
    if (!entry) {
        ffi_array_view_handle_free(h);
        return NULL;
    }
    return entry;
}

static uint32_t ffi_native_argc(VM *vm)
{
    uint32_t argc = 0;
    if (vm && vm->argc_entry) {
        Int iv = 0;
        if (entry_number_scalar(vm->argc_entry, &iv, NULL, NULL)) {
            argc = (uint32_t)iv;
        }
    }
    return argc;
}

static ObjEntry *ffi_native_arg(List *stack, uint32_t argc, uint32_t idx)
{
    if (!stack || idx >= argc) return NULL;
    Int base = stack->size - (Int)argc;
    if (base < 2) return NULL;
    Int pos = base + (Int)idx;
    if (pos < 2 || pos >= stack->size) return NULL;
    return (ObjEntry*)stack->data[pos].p;
}

static FfiLayout *ffi_layout_from_schema_or_layout(VM *vm, ObjEntry *entry, char *err, size_t err_cap)
{
    FfiLayoutHandle *h = ffi_layout_handle_from_entry(entry);
    if (h && h->layout) return h->layout;
    return ffi_compile_schema_cached(vm, entry, err, err_cap);
}

static FfiLayout *ffi_layout_from_elem_spec(VM *vm, ObjEntry *entry, char *err, size_t err_cap)
{
    FfiLayoutHandle *h = ffi_layout_handle_from_entry(entry);
    if (h && h->layout) return h->layout;

    const char *s = NULL;
    if (entry_as_cstr(entry, &s)) {
        FfiBase base = FFI_BASE_VOID;
        int is_array = 0;
        int len = 0;
        int bits = 0;
        int is_const = 0;
        if (ffi_parse_schema_type_string(s, disturb_bytes_len(entry->obj),
                                         &base, &is_array, &len, &bits, &is_const)) {
            if (is_array || bits > 0) {
                snprintf(err, err_cap, "ffi.viewArray element type must be scalar or struct schema");
                return NULL;
            }
            size_t sz = 0, al = 0;
            if (!ffi_prim_size_align(base, &sz, &al)) {
                snprintf(err, err_cap, "ffi.viewArray unsupported element type");
                return NULL;
            }
            FfiLayout *elem = (FfiLayout*)calloc(1, sizeof(FfiLayout));
            if (!elem) {
                snprintf(err, err_cap, "ffi: out of memory");
                return NULL;
            }
            elem->kind = FFI_LAYOUT_PRIM;
            elem->base = base;
            elem->is_const = is_const ? 1 : 0;
            elem->size = sz;
            elem->align = al;
            return elem;
        }
    }
    return ffi_compile_schema_cached(vm, entry, err, err_cap);
}

static ObjEntry *ffi_make_struct_view(VM *vm, uintptr_t base_ptr, FfiLayout *layout, size_t base_offset, int readonly)
{
    if (!layout || layout->kind != FFI_LAYOUT_STRUCT) return NULL;
    FfiViewHandle *h = ffi_view_handle_new(base_ptr, layout, base_offset, NULL, readonly);
    if (!h) return NULL;
    ObjEntry *entry = vm_make_native_entry_data(vm, NULL, native_ffi_handle_noop, h,
                                                ffi_view_handle_free, ffi_view_handle_clone);
    if (!entry) {
        ffi_view_handle_free(h);
        return NULL;
    }
    return entry;
}

static ObjEntry *ffi_make_struct_view_owned(VM *vm, void *owned_mem, FfiLayout *layout)
{
    if (!layout || layout->kind != FFI_LAYOUT_STRUCT || !owned_mem) return NULL;
    FfiViewHandle *h = ffi_view_handle_new((uintptr_t)owned_mem, layout, 0, owned_mem, layout && layout->is_const);
    if (!h) {
        free(owned_mem);
        return NULL;
    }
    ObjEntry *entry = vm_make_native_entry_data(vm, NULL, native_ffi_handle_noop, h,
                                                ffi_view_handle_free, ffi_view_handle_clone);
    if (!entry) {
        ffi_view_handle_free(h);
        return NULL;
    }
    return entry;
}

static int ffi_is_struct_view_entry(ObjEntry *entry)
{
    return ffi_view_handle_from_entry(entry) != NULL;
}

static int ffi_view_decode(ObjEntry *entry, uintptr_t *base_ptr, size_t *base_offset, FfiLayout **layout, int *readonly)
{
    FfiViewHandle *h = ffi_view_handle_from_entry(entry);
    if (!h) return 0;
    if (base_ptr) *base_ptr = h->base_ptr;
    if (base_offset) *base_offset = h->base_offset;
    if (layout) *layout = h->layout;
    if (readonly) *readonly = h->readonly;
    return 1;
}

static int ffi_layout_equal(const FfiLayout *a, const FfiLayout *b)
{
    if (a == b) return 1;
    if (!a || !b) return 0;
    if (a->kind != b->kind) return 0;
    if (a->size != b->size || a->align != b->align) return 0;
    if (a->kind == FFI_LAYOUT_PRIM) {
        return a->base == b->base;
    }
    if (a->kind == FFI_LAYOUT_ARRAY) {
        if (a->array_len != b->array_len) return 0;
        return ffi_layout_equal(a->elem, b->elem);
    }
    if (a->field_count != b->field_count) return 0;
    for (int i = 0; i < a->field_count; i++) {
        if (a->fields[i].name_len != b->fields[i].name_len) return 0;
        if (memcmp(a->fields[i].name, b->fields[i].name, a->fields[i].name_len) != 0) return 0;
        if (a->fields[i].offset != b->fields[i].offset) return 0;
        if (!!a->fields[i].fn_sig != !!b->fields[i].fn_sig) return 0;
        if (a->fields[i].fn_sig && strcmp(a->fields[i].fn_sig, b->fields[i].fn_sig) != 0) return 0;
        if (!ffi_layout_equal(a->fields[i].layout, b->fields[i].layout)) return 0;
    }
    return 1;
}

static ObjEntry *ffi_load_prim_value(VM *vm, uintptr_t addr, FfiBase base)
{
    switch (base) {
    case FFI_BASE_I8: {
        int8_t v = 0;
        memcpy(&v, (void*)addr, sizeof(v));
        return vm_make_int_value(vm, (Int)v);
    }
    case FFI_BASE_U8: {
        uint8_t v = 0;
        memcpy(&v, (void*)addr, sizeof(v));
        return vm_make_int_value(vm, (Int)v);
    }
    case FFI_BASE_I16: {
        int16_t v = 0;
        memcpy(&v, (void*)addr, sizeof(v));
        return vm_make_int_value(vm, (Int)v);
    }
    case FFI_BASE_U16: {
        uint16_t v = 0;
        memcpy(&v, (void*)addr, sizeof(v));
        return vm_make_int_value(vm, (Int)v);
    }
    case FFI_BASE_I32: {
        int32_t v = 0;
        memcpy(&v, (void*)addr, sizeof(v));
        return vm_make_int_value(vm, (Int)v);
    }
    case FFI_BASE_U32: {
        uint32_t v = 0;
        memcpy(&v, (void*)addr, sizeof(v));
        return vm_make_int_value(vm, (Int)v);
    }
    case FFI_BASE_I64: {
        int64_t v = 0;
        memcpy(&v, (void*)addr, sizeof(v));
        return vm_make_int_value(vm, (Int)v);
    }
    case FFI_BASE_U64: {
        uint64_t v = 0;
        memcpy(&v, (void*)addr, sizeof(v));
        return vm_make_int_value(vm, (Int)v);
    }
    case FFI_BASE_F32: {
        float v = 0.0f;
        memcpy(&v, (void*)addr, sizeof(v));
        return vm_make_float_value(vm, (Float)v);
    }
    case FFI_BASE_F64: {
        double v = 0.0;
        memcpy(&v, (void*)addr, sizeof(v));
        return vm_make_float_value(vm, (Float)v);
    }
    case FFI_BASE_PTR: {
        void *p = NULL;
        memcpy(&p, (void*)addr, sizeof(p));
        return vm_make_int_value(vm, (Int)(UInt)(uintptr_t)p);
    }
    default:
        return vm->null_entry;
    }
}

static int ffi_store_prim_value(FfiBase base, uintptr_t addr, ObjEntry *value)
{
    if (!value) return 0;
    if (base == FFI_BASE_PTR) {
        uintptr_t raw = 0;
        if (!ffi_entry_to_ptr(value, &raw)) return 0;
        void *p = (void*)raw;
        memcpy((void*)addr, &p, sizeof(p));
        return 1;
    }

    Int iv = 0;
    Float fv = 0;
    int is_float = 0;
    if (!entry_number_scalar(value, &iv, &fv, &is_float)) return 0;

    switch (base) {
    case FFI_BASE_I8: {
        int8_t out = (int8_t)(is_float ? fv : iv);
        memcpy((void*)addr, &out, sizeof(out));
        return 1;
    }
    case FFI_BASE_U8: {
        uint8_t out = (uint8_t)(is_float ? fv : iv);
        memcpy((void*)addr, &out, sizeof(out));
        return 1;
    }
    case FFI_BASE_I16: {
        int16_t out = (int16_t)(is_float ? fv : iv);
        memcpy((void*)addr, &out, sizeof(out));
        return 1;
    }
    case FFI_BASE_U16: {
        uint16_t out = (uint16_t)(is_float ? fv : iv);
        memcpy((void*)addr, &out, sizeof(out));
        return 1;
    }
    case FFI_BASE_I32: {
        int32_t out = (int32_t)(is_float ? fv : iv);
        memcpy((void*)addr, &out, sizeof(out));
        return 1;
    }
    case FFI_BASE_U32: {
        uint32_t out = (uint32_t)(is_float ? fv : iv);
        memcpy((void*)addr, &out, sizeof(out));
        return 1;
    }
    case FFI_BASE_I64: {
        int64_t out = (int64_t)(is_float ? fv : iv);
        memcpy((void*)addr, &out, sizeof(out));
        return 1;
    }
    case FFI_BASE_U64: {
        uint64_t out = (uint64_t)(is_float ? fv : iv);
        memcpy((void*)addr, &out, sizeof(out));
        return 1;
    }
    case FFI_BASE_F32: {
        float out = is_float ? (float)fv : (float)iv;
        memcpy((void*)addr, &out, sizeof(out));
        return 1;
    }
    case FFI_BASE_F64: {
        double out = is_float ? (double)fv : (double)iv;
        memcpy((void*)addr, &out, sizeof(out));
        return 1;
    }
    default:
        return 0;
    }
}

static uint64_t ffi_read_u64_le(uintptr_t addr, size_t size)
{
    uint64_t v = 0;
    memcpy(&v, (void*)addr, size);
    return v;
}

static int64_t ffi_sign_extend_bits(uint64_t v, int bits)
{
    if (bits <= 0 || bits >= 64) return (int64_t)v;
    uint64_t m = 1ULL << (bits - 1);
    return (int64_t)((v ^ m) - m);
}

static ObjEntry *ffi_load_bitfield_value(VM *vm, FfiLayoutField *field, uintptr_t addr)
{
    if (!field || !field->layout || field->bit_width <= 0) return vm->null_entry;
    uint64_t raw = ffi_read_u64_le(addr, field->layout->size);
    uint64_t mask = (field->bit_width >= 64) ? UINT64_MAX : ((1ULL << field->bit_width) - 1ULL);
    uint64_t bits = (raw >> field->bit_shift) & mask;
    switch (field->layout->base) {
    case FFI_BASE_I8:
    case FFI_BASE_I16:
    case FFI_BASE_I32:
    case FFI_BASE_I64:
        return vm_make_int_value(vm, (Int)ffi_sign_extend_bits(bits, field->bit_width));
    default:
        return vm_make_int_value(vm, (Int)bits);
    }
}

static int ffi_store_bitfield_value(FfiLayoutField *field, uintptr_t addr, ObjEntry *value)
{
    if (!field || !field->layout || field->bit_width <= 0 || !value) return 0;
    Int iv = 0;
    Float fv = 0;
    int is_float = 0;
    if (!entry_number_scalar(value, &iv, &fv, &is_float)) return 0;
    int64_t in = is_float ? (int64_t)fv : (int64_t)iv;
    uint64_t mask = (field->bit_width >= 64) ? UINT64_MAX : ((1ULL << field->bit_width) - 1ULL);
    uint64_t u = ((uint64_t)in) & mask;
    uint64_t raw = ffi_read_u64_le(addr, field->layout->size);
    raw &= ~(mask << field->bit_shift);
    raw |= (u << field->bit_shift);
    memcpy((void*)addr, &raw, field->layout->size);
    return 1;
}

int ffi_view_meta_get(VM *vm, ObjEntry *target, ObjEntry *index, ObjEntry **out)
{
    if (out) *out = NULL;
    if (!vm || !target || !index || !entry_is_string(index)) return 0;
    if (!ffi_is_struct_view_entry(target)) return 0;

    uintptr_t base_ptr = 0;
    size_t base_offset = 0;
    FfiLayout *layout = NULL;
    int parent_readonly = 0;
    if (!ffi_view_decode(target, &base_ptr, &base_offset, &layout, &parent_readonly) || !layout) {
        if (out) *out = vm->null_entry;
        return 1;
    }

    const char *name = disturb_bytes_data(index->obj);
    size_t name_len = disturb_bytes_len(index->obj);
    FfiLayoutField *field = ffi_layout_find_field(layout, name, name_len);
    if (!field) {
        fprintf(stderr, "ffi.view: unknown field '%.*s'\n", (int)name_len, name);
        if (out) *out = vm->null_entry;
        return 1;
    }

    uintptr_t addr = base_ptr + base_offset + field->offset;
    if (field->layout->kind == FFI_LAYOUT_PRIM) {
        if (field->bit_width > 0) {
            ObjEntry *v = ffi_load_bitfield_value(vm, field, addr);
            if (out) *out = v ? v : vm->null_entry;
            return 1;
        }
        if (field->layout->base == FFI_BASE_PTR && field->layout->pointee) {
            uintptr_t ptr = 0;
            void *p = NULL;
            memcpy(&p, (void*)addr, sizeof(p));
            ptr = (uintptr_t)p;
            if (!ptr) {
                if (out) *out = vm->null_entry;
                return 1;
            }
            FfiLayout *sub_layout = field->layout->pointee;
            int child_readonly = parent_readonly || field->is_const || (field->layout && field->layout->is_const);
            ObjEntry *sub = ffi_make_struct_view(vm, ptr, sub_layout, 0, child_readonly);
            if (out) *out = sub ? sub : vm->null_entry;
            return 1;
        }
        if (field->layout->base == FFI_BASE_PTR && field->fn_sig) {
            uintptr_t ptr = 0;
            void *p = NULL;
            memcpy(&p, (void*)addr, sizeof(p));
            ptr = (uintptr_t)p;
            if (!ptr) {
                if (out) *out = vm->null_entry;
                return 1;
            }
#ifdef DISTURB_ENABLE_FFI_CALLS
            char err[160] = {0};
            ObjEntry *fn = ffi_bind_ptr_sig_entry(vm, ptr, field->fn_sig, err, sizeof(err));
            if (!fn) {
                fprintf(stderr, "%s\n", err[0] ? err : "ffi: failed to bind function pointer field");
                if (out) *out = vm->null_entry;
                return 1;
            }
            if (out) *out = fn;
            return 1;
#else
            if (out) *out = vm_make_int_value(vm, (Int)(UInt)ptr);
            return 1;
#endif
        }
        ObjEntry *v = ffi_load_prim_value(vm, addr, field->layout->base);
        if (out) *out = v ? v : vm->null_entry;
        return 1;
    }
    if (field->layout->kind == FFI_LAYOUT_ARRAY) {
        FfiLayout *elem_layout = field->layout->elem;
        int child_readonly = parent_readonly || field->is_const || (field->layout && field->layout->is_const);
        ObjEntry *arr = ffi_make_array_view_entry(vm, addr, elem_layout, field->layout->array_len, child_readonly);
        if (out) *out = arr ? arr : vm->null_entry;
        return 1;
    }
    FfiLayout *sub_layout = field->layout;
    int child_readonly = parent_readonly || field->is_const || (field->layout && field->layout->is_const);
    ObjEntry *sub = ffi_make_struct_view(vm, base_ptr, sub_layout, base_offset + field->offset, child_readonly);
    if (out) *out = sub ? sub : vm->null_entry;
    return 1;
}

int ffi_view_meta_set(VM *vm, ObjEntry *target, ObjEntry *index, ObjEntry *value, size_t pc)
{
    (void)pc;
    if (!vm || !target || !index || !entry_is_string(index)) return 0;
    if (!ffi_is_struct_view_entry(target)) return 0;

    uintptr_t base_ptr = 0;
    size_t base_offset = 0;
    FfiLayout *layout = NULL;
    int readonly = 0;
    if (!ffi_view_decode(target, &base_ptr, &base_offset, &layout, &readonly) || !layout) {
        fprintf(stderr, "ffi.view: invalid view\n");
        return -1;
    }

    const char *name = disturb_bytes_data(index->obj);
    size_t name_len = disturb_bytes_len(index->obj);
    FfiLayoutField *field = ffi_layout_find_field(layout, name, name_len);
    if (!field) {
        fprintf(stderr, "ffi.view: unknown field '%.*s'\n", (int)name_len, name);
        return -1;
    }
    if (field->layout->kind != FFI_LAYOUT_PRIM) {
        fprintf(stderr, "ffi.view: field '%.*s' is not a scalar field\n", (int)name_len, name);
        return -1;
    }
    if (readonly || field->is_const || (field->layout && field->layout->is_const)) {
        if (vm->strict_mode) {
            PANIC("ffi.view: write to const field");
        }
        fprintf(stderr, "warning: ffi.view write to const field '%.*s' ignored\n", (int)name_len, name);
        return 1;
    }
    uintptr_t addr = base_ptr + base_offset + field->offset;
    if (field->bit_width > 0) {
        if (!ffi_store_bitfield_value(field, addr, value)) {
            fprintf(stderr, "ffi.view: invalid value for bitfield '%.*s'\n", (int)name_len, name);
            return -1;
        }
        return 1;
    }
    if (!ffi_store_prim_value(field->layout->base, addr, value)) {
        fprintf(stderr, "ffi.view: invalid value for field '%.*s'\n", (int)name_len, name);
        return -1;
    }
    return 1;
}

int ffi_native_index_get(VM *vm, ObjEntry *target, ObjEntry *index, ObjEntry **out, size_t pc)
{
    (void)pc;
    if (out) *out = NULL;
    if (!vm || !target || !index) return 0;

    FfiArrayViewHandle *av = ffi_array_view_handle_from_entry(target);
    if (av) {
        Int idx = 0;
        Float fv = 0;
        int is_float = 0;
        if (!entry_number_scalar(index, &idx, &fv, &is_float) || is_float) return 0;
        if (idx < 0 || idx >= (Int)av->len) {
            fprintf(stderr, "ffi.view: array index out of bounds\n");
            if (out) *out = vm->null_entry;
            return 1;
        }
        uintptr_t addr = av->base_ptr + (size_t)idx * av->elem_layout->size;
        if (av->elem_layout->kind == FFI_LAYOUT_PRIM) {
            if (out) *out = ffi_load_prim_value(vm, addr, av->elem_layout->base);
            return 1;
        }
        if (av->elem_layout->kind == FFI_LAYOUT_STRUCT) {
            if (out) *out = ffi_make_struct_view(vm, addr, av->elem_layout, 0, av->readonly || (av->elem_layout && av->elem_layout->is_const));
            return 1;
        }
        if (av->elem_layout->kind == FFI_LAYOUT_ARRAY) {
            if (out) *out = ffi_make_array_view_entry(vm, addr, av->elem_layout->elem, av->elem_layout->array_len,
                                                     av->readonly || (av->elem_layout && av->elem_layout->is_const));
            return 1;
        }
        return -1;
    }
    return 0;
}

int ffi_native_index_set(VM *vm, ObjEntry *target, ObjEntry *index, ObjEntry *value, size_t pc)
{
    (void)pc;
    if (!vm || !target || !index) return 0;
    FfiArrayViewHandle *av = ffi_array_view_handle_from_entry(target);
    if (!av) return 0;

    Int idx = 0;
    Float fv = 0;
    int is_float = 0;
    if (!entry_number_scalar(index, &idx, &fv, &is_float) || is_float) {
        fprintf(stderr, "ffi.view: array index must be integer\n");
        return -1;
    }
    if (idx < 0 || idx >= (Int)av->len) {
        fprintf(stderr, "ffi.view: array index out of bounds\n");
        return -1;
    }
    if (av->readonly || (av->elem_layout && av->elem_layout->is_const)) {
        if (vm->strict_mode) {
            PANIC("ffi.view: write to const array element");
        }
        fprintf(stderr, "warning: ffi.view write to const array element ignored\n");
        return 1;
    }
    if (av->elem_layout->kind != FFI_LAYOUT_PRIM) {
        fprintf(stderr, "ffi.view: array assignment supports scalar elements only\n");
        return -1;
    }
    uintptr_t addr = av->base_ptr + (size_t)idx * av->elem_layout->size;
    if (!ffi_store_prim_value(av->elem_layout->base, addr, value)) {
        fprintf(stderr, "ffi.view: invalid value for array element\n");
        return -1;
    }
    return 1;
}

#ifdef DISTURB_ENABLE_FFI_CALLS
static int ffi_layout_is_byvalue_compatible(FfiLayout *layout, char *err, size_t err_cap)
{
    if (!layout) {
        snprintf(err, err_cap, "ffi: missing struct layout");
        return 0;
    }
    if (layout->kind == FFI_LAYOUT_PRIM) return 1;
    if (layout->kind == FFI_LAYOUT_ARRAY) {
        if (layout->array_len <= 0) {
            snprintf(err, err_cap, "ffi: unsized arrays are not supported in by-value structs");
            return 0;
        }
        return ffi_layout_is_byvalue_compatible(layout->elem, err, err_cap);
    }
    if (layout->packed || layout->forced_align > 0) {
        snprintf(err, err_cap, "ffi: packed/forced-align structs are not supported for by-value calls");
        return 0;
    }
    for (int i = 0; i < layout->field_count; i++) {
        if (!ffi_layout_is_byvalue_compatible(layout->fields[i].layout, err, err_cap)) {
            return 0;
        }
    }
    return 1;
}

static int ffi_build_dynamic_type_for_layout(FfiLayout *layout, ffi_type **out_type,
                                             FfiDynTypeNode **out_owner, char *err, size_t err_cap)
{
    if (!layout || !out_type || !out_owner) return 0;
    *out_type = NULL;
    *out_owner = NULL;

    if (layout->kind == FFI_LAYOUT_PRIM) {
        *out_type = ffi_type_for_base(layout->base);
        return 1;
    }

    if (layout->kind == FFI_LAYOUT_ARRAY) {
        if (layout->array_len <= 0 || !layout->elem) {
            snprintf(err, err_cap, "ffi: invalid by-value array layout");
            return 0;
        }

        ffi_type *elem_type = NULL;
        FfiDynTypeNode *elem_owner = NULL;
        if (!ffi_build_dynamic_type_for_layout(layout->elem, &elem_type, &elem_owner, err, err_cap)) {
            return 0;
        }

        FfiDynTypeNode *node = (FfiDynTypeNode*)calloc(1, sizeof(FfiDynTypeNode));
        if (!node) {
            ffi_dyn_type_node_free(elem_owner);
            snprintf(err, err_cap, "ffi: out of memory");
            return 0;
        }
        node->elements = (ffi_type**)calloc((size_t)layout->array_len + 1, sizeof(ffi_type*));
        if (!node->elements) {
            ffi_dyn_type_node_free(elem_owner);
            free(node);
            snprintf(err, err_cap, "ffi: out of memory");
            return 0;
        }
        for (int i = 0; i < layout->array_len; i++) {
            node->elements[i] = elem_type;
        }
        node->elements[layout->array_len] = NULL;
        node->type.type = FFI_TYPE_STRUCT;
        node->type.elements = node->elements;
        if (elem_owner) {
            node->owned_children = (FfiDynTypeNode**)calloc(1, sizeof(FfiDynTypeNode*));
            if (!node->owned_children) {
                ffi_dyn_type_node_free(elem_owner);
                ffi_dyn_type_node_free(node);
                snprintf(err, err_cap, "ffi: out of memory");
                return 0;
            }
            node->owned_children[0] = elem_owner;
            node->owned_count = 1;
        }
        *out_type = &node->type;
        *out_owner = node;
        return 1;
    }

    if (layout->kind != FFI_LAYOUT_STRUCT) {
        snprintf(err, err_cap, "ffi: unsupported layout kind for by-value calls");
        return 0;
    }

    FfiDynTypeNode *node = (FfiDynTypeNode*)calloc(1, sizeof(FfiDynTypeNode));
    if (!node) {
        snprintf(err, err_cap, "ffi: out of memory");
        return 0;
    }
    node->elements = (ffi_type**)calloc((size_t)layout->field_count + 1, sizeof(ffi_type*));
    if (!node->elements) {
        free(node);
        snprintf(err, err_cap, "ffi: out of memory");
        return 0;
    }

    for (int i = 0; i < layout->field_count; i++) {
        ffi_type *field_type = NULL;
        FfiDynTypeNode *field_owner = NULL;
        if (!ffi_build_dynamic_type_for_layout(layout->fields[i].layout, &field_type, &field_owner, err, err_cap)) {
            ffi_dyn_type_node_free(node);
            return 0;
        }
        node->elements[i] = field_type;
        if (field_owner) {
            FfiDynTypeNode **next =
                (FfiDynTypeNode**)realloc(node->owned_children, (size_t)(node->owned_count + 1) * sizeof(FfiDynTypeNode*));
            if (!next) {
                ffi_dyn_type_node_free(field_owner);
                ffi_dyn_type_node_free(node);
                snprintf(err, err_cap, "ffi: out of memory");
                return 0;
            }
            node->owned_children = next;
            node->owned_children[node->owned_count++] = field_owner;
        }
    }
    node->elements[layout->field_count] = NULL;
    node->type.type = FFI_TYPE_STRUCT;
    node->type.elements = node->elements;
    *out_type = &node->type;
    *out_owner = node;
    return 1;
}

static int ffi_resolve_schema_type(VM *vm, FfiType *t, char *err, size_t err_cap)
{
    if (!t || !t->schema_name) return 1;
    if (!vm) {
        snprintf(err, err_cap, "ffi: missing vm");
        return 0;
    }

    ObjEntry *schema = ffi_lookup_schema_entry(vm, t->schema_name, strlen(t->schema_name));
    if (!schema) {
        snprintf(err, err_cap, "ffi: unknown schema '%s'", t->schema_name);
        return 0;
    }

    FfiLayout *layout = ffi_compile_schema_cached(vm, schema, err, err_cap);
    if (!layout) return 0;
    if (layout->kind != FFI_LAYOUT_STRUCT) {
        snprintf(err, err_cap, "ffi: '%s' must reference a struct schema", t->schema_name);
        return 0;
    }
    if (t->schema_is_union && !layout->is_union) {
        snprintf(err, err_cap, "ffi: union<%s> requires union schema", t->schema_name);
        return 0;
    }
    if (!t->schema_is_union && !t->schema_is_pointer && layout->is_union) {
        snprintf(err, err_cap, "ffi: struct<%s> cannot reference union schema; use union<%s>",
                 t->schema_name, t->schema_name);
        return 0;
    }

    t->schema_layout = layout;
    if (t->schema_is_pointer) {
        t->schema_ffi_type = NULL;
        t->schema_ffi_owner = NULL;
        return 1;
    }

    if (!ffi_layout_is_byvalue_compatible(layout, err, err_cap)) return 0;
    ffi_type *ft = NULL;
    FfiDynTypeNode *owner = NULL;
    if (!ffi_build_dynamic_type_for_layout(layout, &ft, &owner, err, err_cap)) return 0;
    t->schema_ffi_type = ft;
    t->schema_ffi_owner = owner;
    return 1;
}

static void native_ffi_call(VM *vm, List *stack, List *global)
{
    (void)global;
    uint32_t argc = 0;
    if (vm && vm->argc_entry) {
        Int iv = 0;
        if (entry_number_scalar(vm->argc_entry, &iv, NULL, NULL)) {
            argc = (uint32_t)iv;
        }
    }
    ObjEntry *self = vm && vm->call_entry ? vm->call_entry : NULL;
    if (!self || disturb_obj_type(self->obj) != DISTURB_T_NATIVE || self->obj->size < 3) {
        fprintf(stderr, "ffi: invalid function\n");
        return;
    }
    NativeBox *box = (NativeBox*)self->obj->data[2].p;
    FfiFunction *fn = box ? (FfiFunction*)box->data : NULL;
    if (!fn) {
        fprintf(stderr, "ffi: missing function data\n");
        return;
    }
    ObjEntry *self_key = vm_entry_key(self);
    const char *self_name = NULL;
    size_t self_name_len = 0;
    int trace_slot = -1;
    if (self_key && entry_is_string(self_key)) {
        self_name = disturb_bytes_data(self_key->obj);
        self_name_len = disturb_bytes_len(self_key->obj);
        if (ffi_trace_mouse_enabled()) trace_slot = ffi_trace_mouse_slot(self_name, self_name_len);
    }
    if ((!fn->has_varargs && (int)argc != fn->argc) ||
        (fn->has_varargs && (int)argc < fn->fixed_argc)) {
        fprintf(stderr, "ffi: argc mismatch\n");
        return;
    }

    int call_argc = (int)argc;
    FfiValue *values = (FfiValue*)calloc((size_t)call_argc, sizeof(FfiValue));
    void **argv = (void**)calloc((size_t)call_argc, sizeof(void*));
    ffi_type **call_types = (ffi_type**)calloc((size_t)call_argc, sizeof(ffi_type*));
    if (!values || !argv || !call_types) {
        free(values);
        free(argv);
        free(call_types);
        fprintf(stderr, "ffi: out of memory\n");
        return;
    }

    for (int i = 0; i < call_argc; i++) {
        ObjEntry *arg = NULL;
        if (stack && stack->size >= (Int)argc + 2) {
            Int base = stack->size - (Int)argc;
            Int pos = base + (Int)i;
            if (pos >= 2 && pos < stack->size) {
                arg = (ObjEntry*)stack->data[pos].p;
            }
        }
        if (i >= fn->argc) {
            int kind = 0;
            call_types[i] = ffi_type_for_vararg_entry(arg, &kind);
            if (kind == 2) {
                Int iv = 0;
                Float fv = 0;
                int is_float = 0;
                double val = 0.0;
                if (arg && entry_number_scalar(arg, &iv, &fv, &is_float)) {
                    val = is_float ? (double)fv : (double)iv;
                }
                values[i].f = val;
                argv[i] = &values[i].f;
            } else if (kind == 1) {
                Int iv = 0;
                if (arg && entry_number_scalar(arg, &iv, NULL, NULL)) {
                    values[i].i = (int64_t)iv;
                } else {
                    values[i].i = 0;
                }
                argv[i] = &values[i].i;
            } else {
                if (!arg || disturb_obj_type(arg->obj) == DISTURB_T_NULL) {
                    values[i].p = NULL;
                } else if (entry_is_string(arg)) {
                    const char *s = NULL;
                    if (entry_as_cstr(arg, &s)) values[i].p = (void*)s;
                    else values[i].p = NULL;
                } else {
                    uintptr_t ptr = 0;
                    if (ffi_entry_to_ptr(arg, &ptr)) values[i].p = (void*)ptr;
                    else values[i].p = disturb_bytes_data(arg->obj);
                }
                argv[i] = &values[i].p;
            }
            continue;
        }
        FfiType *t = &fn->args[i];
        call_types[i] = fn->arg_types ? fn->arg_types[i] : NULL;
        if (t->schema_name) {
            if (t->schema_is_pointer) {
                if (!arg || disturb_obj_type(arg->obj) == DISTURB_T_NULL) {
                    values[i].p = NULL;
                } else {
                    uintptr_t ptr = 0;
                    if (!ffi_entry_to_ptr(arg, &ptr)) ptr = 0;
                    values[i].p = (void*)ptr;
                }
                argv[i] = &values[i].p;
                continue;
            }
            uintptr_t src_addr = 0;
            uintptr_t base_ptr = 0;
            size_t base_offset = 0;
            FfiLayout *layout = NULL;
            if (arg && ffi_view_decode(arg, &base_ptr, &base_offset, &layout, NULL) &&
                ffi_layout_equal(layout, t->schema_layout)) {
                src_addr = base_ptr + base_offset;
            } else if (arg) {
                Int iv = 0;
                Float fv = 0;
                int is_float = 0;
                if (entry_number_scalar(arg, &iv, &fv, &is_float)) {
                    src_addr = (uintptr_t)(UInt)(is_float ? (Int)fv : iv);
                }
            }
                if (!src_addr) {
                    free(values);
                    free(argv);
                    free(call_types);
                    fprintf(stderr, "ffi: invalid value for by-value schema arg %d (%s<%s>)\n",
                            i, t->schema_is_union ? "union" : "struct", t->schema_name);
                    return;
            }
            argv[i] = (void*)src_addr;
            continue;
        }
        if (t->base == FFI_BASE_CSTR) {
            const char *s = NULL;
            if (arg && entry_as_cstr(arg, &s)) {
                values[i].p = (void*)s;
            } else if (arg) {
                uintptr_t ptr = 0;
                if (ffi_entry_to_ptr(arg, &ptr)) {
                    values[i].p = (void*)ptr;
                } else {
                    values[i].p = NULL;
                }
            } else {
                values[i].p = NULL;
            }
            argv[i] = &values[i].p;
            continue;
        }
        if (t->base == FFI_BASE_PTR) {
            if (!arg || disturb_obj_type(arg->obj) == DISTURB_T_NULL) {
                values[i].p = NULL;
            } else {
                uintptr_t ptr = 0;
                if (ffi_entry_to_ptr(arg, &ptr)) {
                    values[i].p = (void*)ptr;
                } else if (disturb_obj_type(arg->obj) == DISTURB_T_INT || disturb_obj_type(arg->obj) == DISTURB_T_FLOAT) {
                    values[i].p = disturb_bytes_data(arg->obj);
                } else {
                    values[i].p = NULL;
                }
            }
            argv[i] = &values[i].p;
            continue;
        }
        if (t->is_ptr || t->is_array) {
            if (!arg || disturb_obj_type(arg->obj) == DISTURB_T_NULL) {
                values[i].p = NULL;
            } else if (disturb_obj_type(arg->obj) == DISTURB_T_INT || disturb_obj_type(arg->obj) == DISTURB_T_FLOAT) {
                values[i].p = disturb_bytes_data(arg->obj);
            } else {
                values[i].p = NULL;
            }
            argv[i] = &values[i].p;
            continue;
        }
        if (ffi_arg_is_float(t)) {
            Float fv = 0;
            Int iv = 0;
            int is_float = 0;
            double val = 0.0;
            if (arg && entry_number_scalar(arg, &iv, &fv, &is_float)) {
                val = is_float ? (double)fv : (double)iv;
            }
            if (t->base == FFI_BASE_F32) {
                values[i].f32 = (float)val;
                argv[i] = &values[i].f32;
            } else {
                values[i].f = val;
                argv[i] = &values[i].f;
            }
            continue;
        }
        if (ffi_arg_is_int(t)) {
            Int iv = 0;
            int64_t v = 0;
            if (arg && entry_number_scalar(arg, &iv, NULL, NULL)) v = (int64_t)iv;
            switch (t->base) {
            case FFI_BASE_I8:
                values[i].i8 = (int8_t)v;
                argv[i] = &values[i].i8;
                break;
            case FFI_BASE_U8:
                values[i].u8 = (uint8_t)v;
                argv[i] = &values[i].u8;
                break;
            case FFI_BASE_I16:
                values[i].i16 = (int16_t)v;
                argv[i] = &values[i].i16;
                break;
            case FFI_BASE_U16:
                values[i].u16 = (uint16_t)v;
                argv[i] = &values[i].u16;
                break;
            case FFI_BASE_I32:
                values[i].i32 = (int32_t)v;
                argv[i] = &values[i].i32;
                break;
            case FFI_BASE_U32:
                values[i].u32 = (uint32_t)v;
                argv[i] = &values[i].u32;
                break;
            case FFI_BASE_U64:
                values[i].u = (uint64_t)v;
                argv[i] = &values[i].u;
                break;
            case FFI_BASE_I64:
            default:
                values[i].i = (int64_t)v;
                argv[i] = &values[i].i;
                break;
            }
            continue;
        }
        values[i].p = NULL;
        argv[i] = &values[i].p;
    }

    FfiValue ret = {0};
    void *ret_buf = NULL;
    void *ret_ptr = &ret;
    if (fn->ret.schema_name && !fn->ret.schema_is_pointer) {
        ret_buf = calloc(1, fn->ret.schema_layout ? fn->ret.schema_layout->size : 0);
        if (!ret_buf) {
            free(values);
            free(argv);
            free(call_types);
            fprintf(stderr, "ffi: out of memory\n");
            return;
        }
        ret_ptr = ret_buf;
    }
    ffi_cif *call_cif = &fn->cif;
    ffi_cif var_cif;
    if (fn->has_varargs) {
        if (ffi_prep_cif_var(&var_cif, FFI_DEFAULT_ABI, (unsigned)fn->fixed_argc, (unsigned)call_argc,
                             fn->ret_type, call_types) != FFI_OK) {
            free(values);
            free(argv);
            free(call_types);
            if (ret_buf) free(ret_buf);
            fprintf(stderr, "ffi: failed to prepare variadic call\n");
            return;
        }
        call_cif = &var_cif;
    }
    ffi_call(call_cif, FFI_FN(fn->fn_ptr), ret_ptr, argv);

    if (trace_slot >= 0) {
        long long arg0 = 0;
        if (call_argc > 0) {
            FfiType *t0 = (fn->argc > 0) ? &fn->args[0] : NULL;
            if (t0 && ffi_arg_is_int(t0)) {
                switch (t0->base) {
                case FFI_BASE_I8: arg0 = (long long)values[0].i8; break;
                case FFI_BASE_U8: arg0 = (long long)values[0].u8; break;
                case FFI_BASE_I16: arg0 = (long long)values[0].i16; break;
                case FFI_BASE_U16: arg0 = (long long)values[0].u16; break;
                case FFI_BASE_I32: arg0 = (long long)values[0].i32; break;
                case FFI_BASE_U32: arg0 = (long long)values[0].u32; break;
                case FFI_BASE_U64: arg0 = (long long)values[0].u; break;
                case FFI_BASE_I64:
                default: arg0 = (long long)values[0].i; break;
                }
            }
        }
        long long out = 0;
        if (ffi_arg_is_int(&fn->ret)) {
            switch (fn->ret.base) {
            case FFI_BASE_I8: out = (long long)ret.i8; break;
            case FFI_BASE_U8: out = (long long)ret.u8; break;
            case FFI_BASE_I16: out = (long long)ret.i16; break;
            case FFI_BASE_U16: out = (long long)ret.u16; break;
            case FFI_BASE_I32: out = (long long)ret.i32; break;
            case FFI_BASE_U32: out = (long long)ret.u32; break;
            case FFI_BASE_U64: out = (long long)ret.u; break;
            case FFI_BASE_I64:
            default: out = (long long)ret.i; break;
            }
        } else if (ffi_arg_is_float(&fn->ret)) {
            out = (long long)((fn->ret.base == FFI_BASE_F32) ? ret.f32 : ret.f);
        }
        int out_i = (int)out;
        if (ffi_trace_mouse_last[trace_slot] != out_i) {
            fprintf(stderr, "ffi-trace: %.*s(arg0=%lld) -> %d\n",
                    (int)self_name_len, self_name ? self_name : "<?>", arg0, out_i);
            ffi_trace_mouse_last[trace_slot] = out_i;
        }
    }

    free(values);
    free(argv);
    free(call_types);

    if (fn->ret.schema_name && fn->ret.schema_is_pointer) {
        ObjEntry *ptr_entry = ffi_make_ptr_handle_entry(vm, (uintptr_t)ret.p, 0);
        if (!ptr_entry) {
            ffi_push_entry(vm, vm_make_int_value(vm, (Int)(uintptr_t)ret.p));
        } else {
            ffi_push_entry(vm, ptr_entry);
        }
        return;
    }

    if (fn->ret.schema_name) {
        ObjEntry *view = ffi_make_struct_view_owned(vm, ret_buf, fn->ret.schema_layout);
        if (!view) {
            free(ret_buf);
            ffi_push_entry(vm, vm->null_entry);
            return;
        }
        ffi_push_entry(vm, view);
        return;
    }

    if (fn->ret.base == FFI_BASE_VOID) {
        ffi_push_entry(vm, vm->null_entry);
        return;
    }

    if (fn->ret.base == FFI_BASE_CSTR) {
        const char *s = (const char*)ret.p;
        if (!s) {
            ffi_push_entry(vm, vm->null_entry);
            return;
        }
        ffi_push_entry(vm, vm_make_bytes_value(vm, s, strlen(s)));
        return;
    }

    if (fn->ret.is_ptr || fn->ret.is_array || fn->ret.base == FFI_BASE_PTR) {
        void *ptr = ret.p;
        if (fn->ret.base == FFI_BASE_PTR) {
            ffi_push_entry(vm, vm_make_int_value(vm, (Int)(uintptr_t)ptr));
            return;
        }
        int len = 0;
        if (vm && vm->has_call_override && vm->call_override_len >= 0) {
            len = (int)vm->call_override_len;
        } else if (fn->ret.is_array && fn->ret.array_len > 0) {
            len = fn->ret.array_len;
        } else {
            len = 0;
        }
        if (!ptr) {
            ffi_push_entry(vm, vm->null_entry);
            return;
        }
        if (fn->ret.base == FFI_BASE_F32 || fn->ret.base == FFI_BASE_F64) {
            ObjEntry *entry = ffi_make_float_list(vm, len);
            if (!entry) return;
            if (len > 0) {
                ffi_fill_float_list(entry, ptr, len, ffi_elem_size(&fn->ret));
            }
            ffi_push_entry(vm, entry);
            return;
        }
        if (ffi_arg_is_int(&fn->ret)) {
            ObjEntry *entry = ffi_make_int_list(vm, len);
            if (!entry) return;
            if (len > 0) {
                ffi_fill_int_list(entry, ptr, len, ffi_elem_size(&fn->ret), 1);
            }
            ffi_push_entry(vm, entry);
            return;
        }
    }

    if (ffi_arg_is_float(&fn->ret)) {
        Float rv = (fn->ret.base == FFI_BASE_F32) ? (Float)ret.f32 : (Float)ret.f;
        ffi_push_entry(vm, vm_make_float_value(vm, rv));
        return;
    }
    if (ffi_arg_is_int(&fn->ret)) {
        Int out = 0;
        switch (fn->ret.base) {
        case FFI_BASE_I8: out = (Int)ret.i8; break;
        case FFI_BASE_U8: out = (Int)ret.u8; break;
        case FFI_BASE_I16: out = (Int)ret.i16; break;
        case FFI_BASE_U16: out = (Int)ret.u16; break;
        case FFI_BASE_I32: out = (Int)ret.i32; break;
        case FFI_BASE_U32: out = (Int)ret.u32; break;
        case FFI_BASE_U64: out = (Int)ret.u; break;
        case FFI_BASE_I64:
        default:
            out = (Int)ret.i;
            break;
        }
        ffi_push_entry(vm, vm_make_int_value(vm, out));
        return;
    }

    ffi_push_entry(vm, vm->null_entry);
}

static int ffi_prepare_ptr(VM *vm, FfiFunction *fn, void *fn_ptr, char *err, size_t err_cap)
{
    fn->handle = NULL;
    fn->fn_ptr = fn_ptr;
    if (!fn->fn_ptr) {
        snprintf(err, err_cap, "ffi.bind expects non-null function pointer");
        return 0;
    }

    if (!ffi_resolve_schema_type(vm, &fn->ret, err, err_cap)) return 0;
    for (int i = 0; i < fn->argc; i++) {
        if (!ffi_resolve_schema_type(vm, &fn->args[i], err, err_cap)) return 0;
    }

    fn->arg_types = (ffi_type**)calloc((size_t)fn->argc, sizeof(ffi_type*));
    if (!fn->arg_types) {
        snprintf(err, err_cap, "ffi: out of memory");
        return 0;
    }
    for (int i = 0; i < fn->argc; i++) {
        FfiType *t = &fn->args[i];
        if (t->schema_name) {
            fn->arg_types[i] = t->schema_is_pointer ? &ffi_type_pointer : t->schema_ffi_type;
            continue;
        }
        if (t->is_ptr || t->is_array || t->base == FFI_BASE_CSTR || t->base == FFI_BASE_PTR) {
            fn->arg_types[i] = &ffi_type_pointer;
        } else {
            fn->arg_types[i] = ffi_type_for_base(t->base);
        }
    }
    if (fn->ret.schema_name) {
        fn->ret_type = fn->ret.schema_is_pointer ? &ffi_type_pointer : fn->ret.schema_ffi_type;
    } else if (fn->ret.is_ptr || fn->ret.is_array || fn->ret.base == FFI_BASE_CSTR || fn->ret.base == FFI_BASE_PTR) {
        fn->ret_type = &ffi_type_pointer;
    } else {
        fn->ret_type = ffi_type_for_base(fn->ret.base);
    }

    if (!fn->has_varargs) {
        if (ffi_prep_cif(&fn->cif, FFI_DEFAULT_ABI, (unsigned)fn->argc, fn->ret_type, fn->arg_types) != FFI_OK) {
            snprintf(err, err_cap, "ffi: failed to prepare call");
            return 0;
        }
    }
    return 1;
}

static ObjEntry *ffi_bind_ptr_sig_entry(VM *vm, uintptr_t addr, const char *sig, char *err, size_t err_cap)
{
    if (!vm || !addr || !sig) {
        snprintf(err, err_cap, "ffi.bind expects non-null ptr and signature");
        return NULL;
    }
    const char *name = NULL;
    FfiFunction *fn = ffi_parse_signature(sig, err, err_cap, &name);
    if (!fn) return NULL;
    if (!ffi_prepare_ptr(vm, fn, (void*)addr, err, err_cap)) {
        free((void*)name);
        ffi_function_release(fn);
        return NULL;
    }
    ObjEntry *entry = vm_make_native_entry_data(vm, name, native_ffi_call, fn,
                                                ffi_function_release, ffi_function_retain);
    free((void*)name);
    if (!entry) {
        ffi_function_release(fn);
        snprintf(err, err_cap, "ffi: failed to create bound function");
        return NULL;
    }
    return entry;
}

void native_ffi_callback(VM *vm, List *stack, List *global)
{
    (void)global;
    uint32_t argc = ffi_native_argc(vm);
    if (argc < 2) {
        fprintf(stderr, "ffi.callback expects signature and lambda\n");
        return;
    }
    ObjEntry *sig_entry = ffi_native_arg(stack, argc, 0);
    ObjEntry *lambda_entry = ffi_native_arg(stack, argc, 1);
    if (!lambda_entry || disturb_obj_type(lambda_entry->obj) != DISTURB_T_LAMBDA) {
        fprintf(stderr, "ffi.callback expects lambda as second argument\n");
        return;
    }
    const char *sig = NULL;
    if (!entry_as_cstr(sig_entry, &sig)) {
        fprintf(stderr, "ffi.callback expects string signature\n");
        return;
    }
    char err[160] = {0};
    const char *name = NULL;
    FfiFunction *fn = ffi_parse_signature(sig, err, sizeof(err), &name);
    if (!fn) {
        fprintf(stderr, "%s\n", err[0] ? err : "ffi: invalid signature");
        return;
    }
    free((void*)name);
    if (fn->has_varargs) {
        ffi_function_release(fn);
        fprintf(stderr, "ffi.callback does not support variadic signatures yet\n");
        return;
    }
    if (fn->ret.schema_name) {
        ffi_function_release(fn);
        fprintf(stderr, "ffi.callback does not support struct schema return yet\n");
        return;
    }
    for (int i = 0; i < fn->argc; i++) {
        if (fn->args[i].schema_name && !fn->args[i].schema_is_pointer) {
            ffi_function_release(fn);
            fprintf(stderr, "ffi.callback does not support by-value struct args yet\n");
            return;
        }
    }

    FfiCallback *cb = (FfiCallback*)calloc(1, sizeof(FfiCallback));
    if (!cb) {
        ffi_function_release(fn);
        fprintf(stderr, "ffi: out of memory\n");
        return;
    }
    cb->magic = FFI_CALLBACK_MAGIC;
    cb->refcount = 1;
    cb->vm = vm;
    cb->argc = fn->argc;
    cb->ret = fn->ret;
    memset(&fn->ret, 0, sizeof(fn->ret));
    cb->args = fn->args;
    fn->args = NULL;
    cb->callback_id = g_ffi_callback_seq++;
    snprintf(cb->lambda_key, sizeof(cb->lambda_key), "__ffi_cb_lambda_%d", cb->callback_id);
    vm_object_set_by_key(vm, vm->global_entry, cb->lambda_key, strlen(cb->lambda_key), lambda_entry);

    cb->arg_types = (ffi_type**)calloc((size_t)cb->argc, sizeof(ffi_type*));
    if (!cb->arg_types) {
        ffi_callback_release(cb);
        ffi_function_release(fn);
        fprintf(stderr, "ffi: out of memory\n");
        return;
    }
    for (int i = 0; i < cb->argc; i++) {
        FfiType *t = &cb->args[i];
        if (t->schema_name) {
            cb->arg_types[i] = &ffi_type_pointer;
        } else if (t->is_ptr || t->is_array || t->base == FFI_BASE_CSTR || t->base == FFI_BASE_PTR) {
            cb->arg_types[i] = &ffi_type_pointer;
        } else {
            cb->arg_types[i] = ffi_type_for_base(t->base);
        }
    }
    if (cb->ret.is_ptr || cb->ret.is_array || cb->ret.base == FFI_BASE_CSTR || cb->ret.base == FFI_BASE_PTR) {
        cb->ret_type = &ffi_type_pointer;
    } else {
        cb->ret_type = ffi_type_for_base(cb->ret.base);
    }

    if (ffi_prep_cif(&cb->cif, FFI_DEFAULT_ABI, (unsigned)cb->argc, cb->ret_type, cb->arg_types) != FFI_OK) {
        ffi_callback_release(cb);
        ffi_function_release(fn);
        fprintf(stderr, "ffi: failed to prepare callback\n");
        return;
    }
    cb->closure = ffi_closure_alloc(sizeof(ffi_closure), &cb->code_ptr);
    if (!cb->closure) {
        ffi_callback_release(cb);
        ffi_function_release(fn);
        fprintf(stderr, "ffi: failed to allocate callback closure\n");
        return;
    }
    if (ffi_prep_closure_loc(cb->closure, &cb->cif, ffi_callback_dispatch, cb, cb->code_ptr) != FFI_OK) {
        ffi_callback_release(cb);
        ffi_function_release(fn);
        fprintf(stderr, "ffi: failed to prepare callback closure\n");
        return;
    }

    ObjEntry *entry = vm_make_native_entry_data(vm, NULL, native_ffi_handle_noop, cb,
                                                ffi_callback_release, ffi_callback_retain);
    if (!entry) {
        ffi_callback_release(cb);
        ffi_function_release(fn);
        return;
    }
    ffi_function_release(fn);
    ffi_push_entry(vm, entry);
}

void native_ffi_bind(VM *vm, List *stack, List *global)
{
    (void)global;
    uint32_t argc = ffi_native_argc(vm);
    if (argc < 2) {
        fprintf(stderr, "ffi.bind expects ptr and signature\n");
        return;
    }
    ObjEntry *ptr_entry = ffi_native_arg(stack, argc, 0);
    ObjEntry *sig_entry = ffi_native_arg(stack, argc, 1);

    uintptr_t addr = 0;
    if (!ffi_entry_to_ptr(ptr_entry, &addr)) {
        fprintf(stderr, "ffi.bind expects ptr\n");
        return;
    }
    if (addr == 0) {
        fprintf(stderr, "ffi.bind expects non-null ptr\n");
        return;
    }

    const char *sig = NULL;
    if (!entry_as_cstr(sig_entry, &sig)) {
        fprintf(stderr, "ffi.bind expects string signature\n");
        return;
    }

    char err[128] = {0};
    ObjEntry *entry = ffi_bind_ptr_sig_entry(vm, addr, sig, err, sizeof(err));
    if (!entry) {
        fprintf(stderr, "%s\n", err[0] ? err : "ffi: bind failed");
        return;
    }
    ffi_push_entry(vm, entry);
}

void native_ffi_open(VM *vm, List *stack, List *global)
{
    (void)global;
    uint32_t argc = ffi_native_argc(vm);
    if (argc < 1) {
        fprintf(stderr, "ffi.open expects library path\n");
        return;
    }
    ObjEntry *path_entry = ffi_native_arg(stack, argc, 0);
    const char *path = NULL;
    if (!path_entry || !entry_as_cstr(path_entry, &path)) {
        fprintf(stderr, "ffi.open expects string path\n");
        return;
    }
    void *handle = ffi_dlopen(path);
    if (!handle) {
        fprintf(stderr, "%s\n", ffi_dlerror_msg());
        return;
    }
    FfiLibHandle *h = ffi_lib_handle_new(handle);
    if (!h) {
        ffi_dlclose(handle);
        fprintf(stderr, "ffi: out of memory\n");
        return;
    }
    ObjEntry *entry = vm_make_native_entry_data(vm, NULL, native_ffi_handle_noop, h,
                                                ffi_lib_handle_free, ffi_lib_handle_clone);
    if (!entry) {
        ffi_lib_handle_free(h);
        fprintf(stderr, "ffi: out of memory\n");
        return;
    }
    ffi_push_entry(vm, entry);
}

void native_ffi_close(VM *vm, List *stack, List *global)
{
    (void)global;
    uint32_t argc = ffi_native_argc(vm);
    if (argc < 1) {
        fprintf(stderr, "ffi.close expects library handle\n");
        return;
    }
    ObjEntry *lib_entry = ffi_native_arg(stack, argc, 0);
    FfiLibHandle *h = ffi_lib_handle_from_entry(lib_entry);
    if (!h) {
        fprintf(stderr, "ffi.close expects library handle\n");
        return;
    }
    if (h->handle && !ffi_dlclose(h->handle)) {
        fprintf(stderr, "%s\n", ffi_dlerror_msg());
        return;
    }
    h->handle = NULL;
    ffi_push_entry(vm, vm->null_entry);
}

void native_ffi_sym(VM *vm, List *stack, List *global)
{
    (void)global;
    uint32_t argc = ffi_native_argc(vm);
    if (argc < 2) {
        fprintf(stderr, "ffi.sym expects library handle and symbol name\n");
        return;
    }
    ObjEntry *lib_entry = ffi_native_arg(stack, argc, 0);
    ObjEntry *name_entry = ffi_native_arg(stack, argc, 1);
    FfiLibHandle *h = ffi_lib_handle_from_entry(lib_entry);
    if (!h || !h->handle) {
        fprintf(stderr, "ffi.sym expects open library handle\n");
        return;
    }
    if (!name_entry || !entry_is_string(name_entry)) {
        fprintf(stderr, "ffi.sym expects string symbol name\n");
        return;
    }
    size_t name_len = disturb_bytes_len(name_entry->obj);
    const char *name_src = disturb_bytes_data(name_entry->obj);
    char *name = (char*)calloc(1, name_len + 1);
    if (!name) {
        fprintf(stderr, "ffi: out of memory\n");
        return;
    }
    memcpy(name, name_src, name_len);
    name[name_len] = 0;
    void *ptr = ffi_dlsym(h->handle, name);
    free(name);
    if (!ptr) {
        fprintf(stderr, "%s\n", ffi_dlerror_msg());
        return;
    }
    ObjEntry *out = ffi_make_ptr_handle_entry(vm, (uintptr_t)ptr, 0);
    if (!out) {
        ffi_push_entry(vm, vm_make_int_value(vm, (Int)(uintptr_t)ptr));
        return;
    }
    ffi_push_entry(vm, out);
}

#else
void native_ffi_callback(VM *vm, List *stack, List *global)
{
    (void)vm; (void)stack; (void)global;
    fprintf(stderr, "ffi.callback unavailable: build without DISTURB_ENABLE_FFI_CALLS\n");
}

void native_ffi_bind(VM *vm, List *stack, List *global)
{
    (void)vm; (void)stack; (void)global;
    fprintf(stderr, "ffi.bind unavailable: build without DISTURB_ENABLE_FFI_CALLS\n");
}

void native_ffi_open(VM *vm, List *stack, List *global)
{
    (void)vm; (void)stack; (void)global;
    fprintf(stderr, "ffi.open unavailable: build without DISTURB_ENABLE_FFI_CALLS\n");
}

void native_ffi_close(VM *vm, List *stack, List *global)
{
    (void)vm; (void)stack; (void)global;
    fprintf(stderr, "ffi.close unavailable: build without DISTURB_ENABLE_FFI_CALLS\n");
}

void native_ffi_sym(VM *vm, List *stack, List *global)
{
    (void)vm; (void)stack; (void)global;
    fprintf(stderr, "ffi.sym unavailable: build without DISTURB_ENABLE_FFI_CALLS\n");
}
#endif

void native_ffi_compile(VM *vm, List *stack, List *global)
{
    (void)global;
    uint32_t argc = ffi_native_argc(vm);
    if (argc < 1) {
        fprintf(stderr, "ffi.compile expects schema\n");
        return;
    }
    ObjEntry *schema = ffi_native_arg(stack, argc, 0);
    char err[160] = {0};
    FfiLayout *layout = ffi_compile_schema_cached(vm, schema, err, sizeof(err));
    if (!layout) {
        fprintf(stderr, "%s\n", err[0] ? err : "ffi: compile failed");
        return;
    }
    FfiLayoutHandle *h = ffi_layout_handle_new(layout);
    if (!h) {
        fprintf(stderr, "ffi: out of memory\n");
        return;
    }
    ObjEntry *entry = vm_make_native_entry_data(vm, NULL, native_ffi_handle_noop, h,
                                                ffi_layout_handle_free, ffi_layout_handle_clone);
    if (!entry) {
        ffi_layout_handle_free(h);
        return;
    }
    ffi_push_entry(vm, entry);
}

void native_ffi_new(VM *vm, List *stack, List *global)
{
    (void)global;
    uint32_t argc = ffi_native_argc(vm);
    if (argc < 1) {
        fprintf(stderr, "ffi.new expects schema or compiled layout\n");
        return;
    }
    ObjEntry *schema_or_layout = ffi_native_arg(stack, argc, 0);
    char err[160] = {0};
    FfiLayout *layout = ffi_layout_from_schema_or_layout(vm, schema_or_layout, err, sizeof(err));
    if (!layout) {
        fprintf(stderr, "%s\n", err[0] ? err : "ffi: new failed");
        return;
    }
    if (layout->kind != FFI_LAYOUT_STRUCT) {
        fprintf(stderr, "ffi.new expects struct schema/layout\n");
        return;
    }
    size_t bytes = layout->size ? layout->size : 1;
    void *mem = calloc(1, bytes);
    if (!mem) {
        fprintf(stderr, "ffi: out of memory\n");
        return;
    }
    ObjEntry *owned = ffi_make_ptr_handle_entry(vm, (uintptr_t)mem, 1);
    if (!owned) {
        free(mem);
        fprintf(stderr, "ffi: out of memory\n");
        return;
    }
    ffi_push_entry(vm, owned);
}

void native_ffi_free(VM *vm, List *stack, List *global)
{
    (void)global;
    uint32_t argc = ffi_native_argc(vm);
    if (argc < 1) {
        fprintf(stderr, "ffi.free expects ptr\n");
        return;
    }
    ObjEntry *ptr_entry = ffi_native_arg(stack, argc, 0);
    if (!ptr_entry || disturb_obj_type(ptr_entry->obj) == DISTURB_T_NULL) {
        ffi_push_entry(vm, vm->null_entry);
        return;
    }
    FfiPtrHandle *h = ffi_ptr_handle_from_entry(ptr_entry);
    if (h) {
        if (h->owned && h->ptr) {
            free((void*)h->ptr);
        }
        h->ptr = 0;
        h->owned = 0;
        ffi_push_entry(vm, vm->null_entry);
        return;
    }
    uintptr_t ptr = 0;
    if (!ffi_entry_to_ptr(ptr_entry, &ptr)) {
        fprintf(stderr, "ffi.free expects ptr\n");
        return;
    }
    if (ptr) free((void*)ptr);
    ffi_push_entry(vm, vm->null_entry);
}

void native_ffi_sizeof(VM *vm, List *stack, List *global)
{
    (void)global;
    uint32_t argc = ffi_native_argc(vm);
    if (argc < 1) {
        fprintf(stderr, "ffi.sizeof expects schema or compiled layout\n");
        return;
    }
    ObjEntry *arg = ffi_native_arg(stack, argc, 0);
    char err[160] = {0};
    FfiLayout *layout = ffi_layout_from_schema_or_layout(vm, arg, err, sizeof(err));
    if (!layout) {
        fprintf(stderr, "%s\n", err[0] ? err : "ffi: sizeof failed");
        return;
    }
    ffi_push_entry(vm, vm_make_int_value(vm, (Int)layout->size));
}

void native_ffi_alignof(VM *vm, List *stack, List *global)
{
    (void)global;
    uint32_t argc = ffi_native_argc(vm);
    if (argc < 1) {
        fprintf(stderr, "ffi.alignof expects schema or compiled layout\n");
        return;
    }
    ObjEntry *arg = ffi_native_arg(stack, argc, 0);
    char err[160] = {0};
    FfiLayout *layout = ffi_layout_from_schema_or_layout(vm, arg, err, sizeof(err));
    if (!layout) {
        fprintf(stderr, "%s\n", err[0] ? err : "ffi: alignof failed");
        return;
    }
    ffi_push_entry(vm, vm_make_int_value(vm, (Int)layout->align));
}

void native_ffi_view(VM *vm, List *stack, List *global)
{
    (void)global;
    uint32_t argc = ffi_native_argc(vm);
    if (argc < 2) {
        fprintf(stderr, "ffi.view expects ptr and schema/layout\n");
        return;
    }
    ObjEntry *ptr_entry = ffi_native_arg(stack, argc, 0);
    ObjEntry *schema_or_layout = ffi_native_arg(stack, argc, 1);
    uintptr_t ptr = 0;
    if (!ffi_entry_to_ptr(ptr_entry, &ptr)) {
        fprintf(stderr, "ffi.view expects ptr\n");
        return;
    }
    char err[160] = {0};
    FfiLayout *layout = ffi_layout_from_schema_or_layout(vm, schema_or_layout, err, sizeof(err));
    if (!layout) {
        fprintf(stderr, "%s\n", err[0] ? err : "ffi: view failed");
        return;
    }
    if (layout->kind != FFI_LAYOUT_STRUCT) {
        fprintf(stderr, "ffi.view expects struct schema/layout\n");
        return;
    }
    ObjEntry *view = ffi_make_struct_view(vm, ptr, layout, 0, layout && layout->is_const);
    if (!view) {
        fprintf(stderr, "ffi: failed to create view\n");
        return;
    }
    ffi_push_entry(vm, view);
}

void native_ffi_view_array(VM *vm, List *stack, List *global)
{
    (void)global;
    uint32_t argc = ffi_native_argc(vm);
    if (argc < 3) {
        fprintf(stderr, "ffi.viewArray expects ptr, elemSpec, len\n");
        return;
    }
    ObjEntry *ptr_entry = ffi_native_arg(stack, argc, 0);
    ObjEntry *elem_spec = ffi_native_arg(stack, argc, 1);
    ObjEntry *len_entry = ffi_native_arg(stack, argc, 2);
    uintptr_t ptr = 0;
    if (!ffi_entry_to_ptr(ptr_entry, &ptr)) {
        fprintf(stderr, "ffi.viewArray expects ptr\n");
        return;
    }
    Int iv = 0;
    Float fv = 0;
    int is_float = 0;
    if (!entry_number_scalar(len_entry, &iv, &fv, &is_float) || is_float || iv < 0 || iv > INT_MAX) {
        fprintf(stderr, "ffi.viewArray expects non-negative integer len\n");
        return;
    }
    char err[160] = {0};
    FfiLayout *elem = ffi_layout_from_elem_spec(vm, elem_spec, err, sizeof(err));
    if (!elem) {
        fprintf(stderr, "%s\n", err[0] ? err : "ffi: viewArray failed");
        return;
    }
    int elem_owned = ffi_layout_handle_from_entry(elem_spec) ? 0 : 1;
    ObjEntry *arr = elem_owned ?
        ffi_make_array_view_entry_owned(vm, ptr, elem, (int)iv, elem && elem->is_const) :
        ffi_make_array_view_entry(vm, ptr, elem, (int)iv, elem && elem->is_const);
    if (!arr) {
        if (elem_owned) ffi_layout_free(elem);
        fprintf(stderr, "ffi: failed to create array view\n");
        return;
    }
    ffi_push_entry(vm, arr);
}

void native_ffi_offsetof(VM *vm, List *stack, List *global)
{
    (void)global;
    uint32_t argc = ffi_native_argc(vm);
    if (argc < 2) {
        fprintf(stderr, "ffi.offsetof expects schema/layout and field path\n");
        return;
    }
    ObjEntry *schema_or_layout = ffi_native_arg(stack, argc, 0);
    ObjEntry *path_entry = ffi_native_arg(stack, argc, 1);
    const char *path = NULL;
    if (!entry_as_cstr(path_entry, &path)) {
        fprintf(stderr, "ffi.offsetof expects string path\n");
        return;
    }
    size_t path_len = disturb_bytes_len(path_entry->obj);

    char err[160] = {0};
    FfiLayout *layout = ffi_layout_from_schema_or_layout(vm, schema_or_layout, err, sizeof(err));
    if (!layout) {
        fprintf(stderr, "%s\n", err[0] ? err : "ffi: offsetof failed");
        return;
    }
    if (layout->kind != FFI_LAYOUT_STRUCT) {
        fprintf(stderr, "ffi.offsetof expects struct schema/layout\n");
        return;
    }

    size_t off = 0;
    size_t start = 0;
    FfiLayout *cur = layout;
    while (start <= path_len) {
        size_t end = start;
        while (end < path_len && path[end] != '.') end++;
        size_t seg_len = end - start;
        if (seg_len == 0) {
            fprintf(stderr, "ffi.offsetof invalid path\n");
            return;
        }
        FfiLayoutField *field = ffi_layout_find_field(cur, path + start, seg_len);
        if (!field) {
            fprintf(stderr, "ffi.offsetof unknown field in path\n");
            return;
        }
        off += field->offset;
        cur = field->layout;
        if (end >= path_len) break;
        if (!cur || cur->kind != FFI_LAYOUT_STRUCT) {
            fprintf(stderr, "ffi.offsetof path traverses non-struct field\n");
            return;
        }
        start = end + 1;
    }

    ffi_push_entry(vm, vm_make_int_value(vm, (Int)off));
}

void native_ffi_buffer(VM *vm, List *stack, List *global)
{
    (void)global;
    uint32_t argc = ffi_native_argc(vm);
    if (argc < 1) {
        fprintf(stderr, "ffi.buffer expects byte length\n");
        return;
    }
    ObjEntry *len_entry = ffi_native_arg(stack, argc, 0);
    Int iv = 0;
    Float fv = 0;
    int is_float = 0;
    if (!entry_number_scalar(len_entry, &iv, &fv, &is_float) || is_float || iv < 0) {
        fprintf(stderr, "ffi.buffer expects non-negative integer length\n");
        return;
    }
    size_t len = (size_t)iv;
    void *mem = calloc(1, len ? len : 1);
    if (!mem) {
        fprintf(stderr, "ffi: out of memory\n");
        return;
    }
    ObjEntry *owned = ffi_make_ptr_handle_entry(vm, (uintptr_t)mem, 1);
    if (!owned) {
        free(mem);
        fprintf(stderr, "ffi: out of memory\n");
        return;
    }
    ffi_push_entry(vm, owned);
}

void native_ffi_string(VM *vm, List *stack, List *global)
{
    (void)global;
    uint32_t argc = ffi_native_argc(vm);
    if (argc < 1) {
        fprintf(stderr, "ffi.string expects ptr and optional len\n");
        return;
    }
    ObjEntry *ptr_entry = ffi_native_arg(stack, argc, 0);
    uintptr_t ptr = 0;
    if (!ffi_entry_to_ptr(ptr_entry, &ptr)) {
        fprintf(stderr, "ffi.string expects ptr\n");
        return;
    }
    if (!ptr) {
        ffi_push_entry(vm, vm->null_entry);
        return;
    }
    if (argc >= 2) {
        ObjEntry *len_entry = ffi_native_arg(stack, argc, 1);
        Int iv = 0;
        Float fv = 0;
        int is_float = 0;
        if (!entry_number_scalar(len_entry, &iv, &fv, &is_float) || is_float || iv < 0) {
            fprintf(stderr, "ffi.string len must be non-negative integer\n");
            return;
        }
        ffi_push_entry(vm, vm_make_bytes_value(vm, (const char*)ptr, (size_t)iv));
        return;
    }
    const char *s = (const char*)ptr;
    ffi_push_entry(vm, vm_make_bytes_value(vm, s, strlen(s)));
}

static void ffi_add_module_fn(VM *vm, ObjEntry *ffi_entry, const char *name, NativeFn fn)
{
    ObjEntry *entry = vm_make_native_entry_data(vm, name, fn, NULL, NULL, NULL);
    if (!entry) return;
    vm_object_set_by_key(vm, ffi_entry, name, strlen(name), entry);
}

void ffi_module_install(VM *vm, ObjEntry *ffi_entry)
{
    if (!vm || !ffi_entry) return;
#ifdef DISTURB_ENABLE_FFI_CALLS
    ffi_add_module_fn(vm, ffi_entry, "open", native_ffi_open);
    ffi_add_module_fn(vm, ffi_entry, "close", native_ffi_close);
    ffi_add_module_fn(vm, ffi_entry, "sym", native_ffi_sym);
    ffi_add_module_fn(vm, ffi_entry, "bind", native_ffi_bind);
    ffi_add_module_fn(vm, ffi_entry, "callback", native_ffi_callback);
#endif
    ffi_add_module_fn(vm, ffi_entry, "compile", native_ffi_compile);
    ffi_add_module_fn(vm, ffi_entry, "new", native_ffi_new);
    ffi_add_module_fn(vm, ffi_entry, "free", native_ffi_free);
    ffi_add_module_fn(vm, ffi_entry, "sizeof", native_ffi_sizeof);
    ffi_add_module_fn(vm, ffi_entry, "alignof", native_ffi_alignof);
    ffi_add_module_fn(vm, ffi_entry, "view", native_ffi_view);
    ffi_add_module_fn(vm, ffi_entry, "viewArray", native_ffi_view_array);
    ffi_add_module_fn(vm, ffi_entry, "offsetof", native_ffi_offsetof);
    ffi_add_module_fn(vm, ffi_entry, "buffer", native_ffi_buffer);
    ffi_add_module_fn(vm, ffi_entry, "string", native_ffi_string);
}

#endif
