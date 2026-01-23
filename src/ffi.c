#ifdef DISTURB_ENABLE_FFI

#include "vm.h"
#include <dlfcn.h>
#include <ffi.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>

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

typedef struct {
    FfiBase base;
    int is_ptr;
    int is_array;
    int array_len;
} FfiType;

typedef struct {
    int refcount;
    void *handle;
    void *fn_ptr;
    FfiType ret;
    FfiType *args;
    int argc;
    ffi_cif cif;
    ffi_type **arg_types;
    ffi_type *ret_type;
} FfiFunction;

typedef union {
    int64_t i;
    uint64_t u;
    double f;
    void *p;
} FfiValue;

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
    free(fn->args);
    free(fn->arg_types);
    free(fn);
}

static int entry_is_string(ObjEntry *entry)
{
    return entry && entry->is_string && urb_obj_type(entry->obj) == URB_T_INT;
}

static int entry_number_scalar(ObjEntry *entry, Int *out_i, Float *out_f, int *out_is_float)
{
    if (!entry || !entry->in_use) return 0;
    Int type = urb_obj_type(entry->obj);
    if (type == URB_T_INT) {
        if (entry_is_string(entry)) return 0;
        if (urb_bytes_len(entry->obj) != sizeof(Int)) return 0;
        Int v = 0;
        memcpy(&v, urb_bytes_data(entry->obj), sizeof(Int));
        if (out_i) *out_i = v;
        if (out_f) *out_f = (Float)v;
        if (out_is_float) *out_is_float = 0;
        return 1;
    }
    if (type == URB_T_FLOAT) {
        if (urb_bytes_len(entry->obj) != sizeof(Float)) return 0;
        Float v = 0;
        memcpy(&v, urb_bytes_data(entry->obj), sizeof(Float));
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
    *out = urb_bytes_data(entry->obj);
    return 1;
}

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
    if (strcmp(name, "ssize_t") == 0 || strcmp(name, "intptr_t") == 0 ||
        strcmp(name, "ptrdiff_t") == 0) {
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
    char ident[64];
    if (!sig_read_ident(p, ident, sizeof(ident))) {
        snprintf(err, err_cap, "expected type");
        return 0;
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
    int cap = 0;
    sig_skip_ws(&p);
    if (sig_match_char(&p, ')')) {
        // no args
    } else {
        for (;;) {
            FfiType arg = {0};
            if (!sig_parse_type(&p, &arg, err, err_cap)) {
                free(args);
                return NULL;
            }
            sig_skip_arg_name(&p);
            if (argc == cap) {
                int next = cap == 0 ? 4 : cap * 2;
                FfiType *tmp = (FfiType*)realloc(args, (size_t)next * sizeof(FfiType));
                if (!tmp) {
                    snprintf(err, err_cap, "out of memory");
                    free(args);
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
            free(args);
            return NULL;
        }
    }

    FfiFunction *fn = (FfiFunction*)calloc(1, sizeof(FfiFunction));
    if (!fn) {
        free(args);
        return NULL;
    }
    fn->refcount = 1;
    fn->ret = ret;
    fn->args = args;
    fn->argc = argc;
    *out_name = ffi_strdup(name);
    if (!*out_name) {
        free(args);
        free(fn);
        return NULL;
    }
    return fn;
}

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
    char *dst = urb_bytes_data(entry->obj);
    for (int i = 0; i < count; i++) {
        int64_t v = 0;
        memcpy(&v, (const char*)ptr + (size_t)i * elem_size, elem_size);
        memcpy(dst + (size_t)i * sizeof(Int), &v, sizeof(Int));
    }
}

static void ffi_fill_float_list(ObjEntry *entry, const void *ptr, int count, size_t elem_size)
{
    if (!entry || !ptr || count <= 0) return;
    char *dst = urb_bytes_data(entry->obj);
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

static void ffi_push_entry(VM *vm, ObjEntry *entry)
{
    if (!vm || !vm->stack_entry || !entry) return;
    List *old_stack = vm->stack_entry->obj;
    List *stack = urb_table_add(old_stack, entry);
    stack = vm_update_shared_obj(vm, old_stack, stack);
    vm->stack_entry->obj = stack;
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
    if (!self || urb_obj_type(self->obj) != URB_T_NATIVE || self->obj->size < 3) {
        fprintf(stderr, "ffi: invalid function\n");
        return;
    }
    NativeBox *box = (NativeBox*)self->obj->data[2].p;
    FfiFunction *fn = box ? (FfiFunction*)box->data : NULL;
    if (!fn) {
        fprintf(stderr, "ffi: missing function data\n");
        return;
    }
    if ((int)argc != fn->argc) {
        fprintf(stderr, "ffi: argc mismatch\n");
        return;
    }

    FfiValue *values = (FfiValue*)calloc((size_t)fn->argc, sizeof(FfiValue));
    void **argv = (void**)calloc((size_t)fn->argc, sizeof(void*));
    if (!values || !argv) {
        free(values);
        free(argv);
        fprintf(stderr, "ffi: out of memory\n");
        return;
    }

    for (int i = 0; i < fn->argc; i++) {
        ObjEntry *arg = NULL;
        if (stack && stack->size >= (Int)argc + 2) {
            Int base = stack->size - (Int)argc;
            Int pos = base + (Int)i;
            if (pos >= 2 && pos < stack->size) {
                arg = (ObjEntry*)stack->data[pos].p;
            }
        }
        FfiType *t = &fn->args[i];
        if (t->base == FFI_BASE_CSTR) {
            const char *s = NULL;
            if (arg && entry_as_cstr(arg, &s)) {
                values[i].p = (void*)s;
            } else {
                values[i].p = NULL;
            }
            argv[i] = &values[i].p;
            continue;
        }
        if (t->base == FFI_BASE_PTR || t->is_ptr || t->is_array) {
            if (!arg || urb_obj_type(arg->obj) == URB_T_NULL) {
                values[i].p = NULL;
            } else if (urb_obj_type(arg->obj) == URB_T_INT || urb_obj_type(arg->obj) == URB_T_FLOAT) {
                values[i].p = urb_bytes_data(arg->obj);
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
            if (!arg || !entry_number_scalar(arg, &iv, &fv, &is_float)) {
                values[i].f = 0.0;
            } else {
                values[i].f = is_float ? (double)fv : (double)iv;
            }
            argv[i] = &values[i].f;
            continue;
        }
        if (ffi_arg_is_int(t)) {
            Int iv = 0;
            if (!arg || !entry_number_scalar(arg, &iv, NULL, NULL)) {
                values[i].i = 0;
            } else {
                values[i].i = (int64_t)iv;
            }
            argv[i] = &values[i].i;
            continue;
        }
        values[i].p = NULL;
        argv[i] = &values[i].p;
    }

    FfiValue ret = {0};
    ffi_call(&fn->cif, FFI_FN(fn->fn_ptr), &ret, argv);

    free(values);
    free(argv);

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
        ffi_push_entry(vm, vm_make_float_value(vm, (Float)ret.f));
        return;
    }
    if (ffi_arg_is_int(&fn->ret)) {
        ffi_push_entry(vm, vm_make_int_value(vm, (Int)ret.i));
        return;
    }

    ffi_push_entry(vm, vm->null_entry);
}

static int ffi_prepare(FfiFunction *fn, const char *name, void *handle, char *err, size_t err_cap)
{
    fn->handle = handle;
    fn->fn_ptr = dlsym(handle, name);
    if (!fn->fn_ptr) {
        snprintf(err, err_cap, "ffi: missing symbol '%s'", name);
        return 0;
    }

    fn->arg_types = (ffi_type**)calloc((size_t)fn->argc, sizeof(ffi_type*));
    if (!fn->arg_types) {
        snprintf(err, err_cap, "ffi: out of memory");
        return 0;
    }
    for (int i = 0; i < fn->argc; i++) {
        FfiType *t = &fn->args[i];
        if (t->is_ptr || t->is_array || t->base == FFI_BASE_CSTR || t->base == FFI_BASE_PTR) {
            fn->arg_types[i] = &ffi_type_pointer;
        } else {
            fn->arg_types[i] = ffi_type_for_base(t->base);
        }
    }
    if (fn->ret.is_ptr || fn->ret.is_array || fn->ret.base == FFI_BASE_CSTR || fn->ret.base == FFI_BASE_PTR) {
        fn->ret_type = &ffi_type_pointer;
    } else {
        fn->ret_type = ffi_type_for_base(fn->ret.base);
    }

    if (ffi_prep_cif(&fn->cif, FFI_DEFAULT_ABI, (unsigned)fn->argc, fn->ret_type, fn->arg_types) != FFI_OK) {
        snprintf(err, err_cap, "ffi: failed to prepare call");
        return 0;
    }
    return 1;
}

void native_ffi_load(VM *vm, List *stack, List *global)
{
    (void)global;
    uint32_t argc = 0;
    if (vm && vm->argc_entry) {
        Int iv = 0;
        if (entry_number_scalar(vm->argc_entry, &iv, NULL, NULL)) {
            argc = (uint32_t)iv;
        }
    }
    if (argc < 1) {
        fprintf(stderr, "ffi.load expects library path and signatures\n");
        return;
    }
    ObjEntry *path_entry = NULL;
    if (stack && stack->size >= (Int)argc + 2) {
        Int base = stack->size - (Int)argc;
        path_entry = (ObjEntry*)stack->data[base].p;
    }
    const char *path = NULL;
    if (!path_entry || !entry_as_cstr(path_entry, &path)) {
        fprintf(stderr, "ffi.load expects string path\n");
        return;
    }
    void *handle = dlopen(path, RTLD_LAZY);
    if (!handle) {
        fprintf(stderr, "ffi.load failed: %s\n", dlerror());
        return;
    }

    ObjEntry *table = vm_make_table_value(vm, (Int)(argc - 1));
    if (!table) return;
    for (uint32_t i = 1; i < argc; i++) {
        ObjEntry *sig_entry = NULL;
        Int base = stack->size - (Int)argc;
        Int pos = base + (Int)i;
        if (pos >= 2 && pos < stack->size) {
            sig_entry = (ObjEntry*)stack->data[pos].p;
        }
        const char *sig = NULL;
        if (!sig_entry || !entry_as_cstr(sig_entry, &sig)) {
            fprintf(stderr, "ffi.load expects string signatures\n");
            continue;
        }
        char err[128] = {0};
        const char *name = NULL;
        FfiFunction *fn = ffi_parse_signature(sig, err, sizeof(err), &name);
        if (!fn) {
            fprintf(stderr, "%s\n", err[0] ? err : "ffi: invalid signature");
            continue;
        }
        if (!ffi_prepare(fn, name, handle, err, sizeof(err))) {
            fprintf(stderr, "%s\n", err[0] ? err : "ffi: prepare failed");
            free((void*)name);
            ffi_function_release(fn);
            continue;
        }
        ObjEntry *entry = vm_make_native_entry_data(vm, name, native_ffi_call, fn,
                                                    ffi_function_release, ffi_function_retain);
        free((void*)name);
        if (!entry) {
            ffi_function_release(fn);
            continue;
        }
        table->obj = vm_update_shared_obj(vm, table->obj, urb_table_add(table->obj, entry));
    }
    ffi_push_entry(vm, table);
}

#endif
