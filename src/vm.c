#include "vm.h"
#include "bytecode.h"
#include "papagaio.h"
#include <math.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    unsigned char *code;
    size_t len;
    uint32_t argc;
    int has_vararg;
    char **arg_names;
    size_t *arg_lens;
    unsigned char **default_code;
    size_t *default_lens;
    uint8_t *has_default;
} FunctionBox;

typedef struct {
    char *data;
    size_t len;
    size_t cap;
} StrBuf;

typedef enum {
    VIEW_I8 = 0,
    VIEW_U8,
    VIEW_I16,
    VIEW_U16,
    VIEW_I32,
    VIEW_U32,
    VIEW_I64,
    VIEW_U64,
    VIEW_F32,
    VIEW_F64
} ViewType;

int lre_check_stack_overflow(void *opaque, size_t alloca_size)
{
    (void)opaque;
    (void)alloca_size;
    return 0;
}

int lre_check_timeout(void *opaque)
{
    (void)opaque;
    return 0;
}

void *lre_realloc(void *opaque, void *ptr, size_t size)
{
    (void)opaque;
    if (!size) {
        free(ptr);
        return NULL;
    }
    return realloc(ptr, size);
}

static int vm_object_set_by_key_len(VM *vm, List **objp, const char *name, size_t len,
                                    ObjEntry *value, size_t pc);


static void sb_init(StrBuf *b)
{
    b->cap = 256;
    b->len = 0;
    b->data = (char*)malloc(b->cap);
    b->data[0] = 0;
}

static void sb_grow(StrBuf *b, size_t n)
{
    size_t need = b->len + n + 1;
    if (need <= b->cap) return;
    size_t cap = b->cap;
    while (cap < need) cap <<= 1;
    b->data = (char*)realloc(b->data, cap);
    b->cap = cap;
}

static void sb_append_n(StrBuf *b, const char *s, size_t n)
{
    if (!n) return;
    sb_grow(b, n);
    memcpy(b->data + b->len, s, n);
    b->len += n;
    b->data[b->len] = 0;
}

static void sb_append_char(StrBuf *b, char c)
{
    sb_grow(b, 1);
    b->data[b->len++] = c;
    b->data[b->len] = 0;
}

static void sb_free(StrBuf *b)
{
    free(b->data);
    b->data = NULL;
    b->len = 0;
    b->cap = 0;
}

static size_t disturb_bytes_max(void)
{
    return (size_t)(~(UHalf)0);
}

const char *disturb_type_name(Int type)
{
    switch (type) {
    case DISTURB_T_NULL: return "null";
    case DISTURB_T_INT: return "int";
    case DISTURB_T_FLOAT: return "float";
    case DISTURB_T_TABLE: return "table";
    
    case DISTURB_T_NATIVE: return "native";
    case DISTURB_T_LAMBDA: return "lambda";
    case DISTURB_T_VIEW: return "view";
    default: return "unknown";
    }
}

Int disturb_obj_type(const List *obj)
{
    return obj->data[0].i;
}

ObjEntry *disturb_obj_key(const List *obj)
{
    return (ObjEntry*)obj->data[1].p;
}

ObjEntry *vm_entry_key(const ObjEntry *entry)
{
    if (!entry) return NULL;
    if (entry->key) return entry->key;
    if (!entry->obj) return NULL;
    return disturb_obj_key(entry->obj);
}

List *vm_update_shared_obj(VM *vm, List *old_obj, List *new_obj)
{
    if (!vm || !old_obj || old_obj == new_obj) return new_obj;
    for (Int i = 0; i < vm->reg_count; i++) {
        ObjEntry *entry = vm->reg[i];
        if (!entry || !entry->in_use) continue;
        if (entry->obj == old_obj) entry->obj = new_obj;
    }
    return new_obj;
}

char *disturb_bytes_data(List *obj)
{
    return (char*)(obj->data + 2);
}

size_t disturb_bytes_len(const List *obj)
{
    if (obj->size < 2) return 0;
    return (size_t)obj->size - 2;
}

static int disturb_bytes_eq_bytes(const List *obj, const char *s, size_t len)
{
    if (disturb_bytes_len(obj) != len) return 0;
    return memcmp(disturb_bytes_data((List*)obj), s, len) == 0;
}

static int entry_is_string(const ObjEntry *entry)
{
    return entry && entry->is_string && disturb_obj_type(entry->obj) == DISTURB_T_INT;
}

static size_t vm_elem_size(Int type)
{
    if (type == DISTURB_T_INT) return sizeof(Int);
    if (type == DISTURB_T_FLOAT) return sizeof(Float);
    return 1;
}

static Int vm_bytes_to_count(size_t bytes_len, Int type)
{
    size_t elem = vm_elem_size(type);
    if (elem == 0) return 0;
    return (Int)(bytes_len / elem);
}

static int vm_read_int_at(const List *obj, Int index, Int *out)
{
    if (!obj || index < 0) return 0;
    size_t bytes_len = disturb_bytes_len((List*)obj);
    size_t offset = (size_t)index * sizeof(Int);
    if (offset + sizeof(Int) > bytes_len) return 0;
    memcpy(out, disturb_bytes_data((List*)obj) + offset, sizeof(Int));
    return 1;
}

static int vm_write_int_at(List *obj, Int index, Int value)
{
    if (!obj || index < 0) return 0;
    size_t bytes_len = disturb_bytes_len(obj);
    size_t offset = (size_t)index * sizeof(Int);
    if (offset + sizeof(Int) > bytes_len) return 0;
    memcpy(disturb_bytes_data(obj) + offset, &value, sizeof(Int));
    return 1;
}

static int vm_read_float_at(const List *obj, Int index, Float *out)
{
    if (!obj || index < 0) return 0;
    size_t bytes_len = disturb_bytes_len((List*)obj);
    size_t offset = (size_t)index * sizeof(Float);
    if (offset + sizeof(Float) > bytes_len) return 0;
    memcpy(out, disturb_bytes_data((List*)obj) + offset, sizeof(Float));
    return 1;
}

static int vm_write_float_at(List *obj, Int index, Float value)
{
    if (!obj || index < 0) return 0;
    size_t bytes_len = disturb_bytes_len(obj);
    size_t offset = (size_t)index * sizeof(Float);
    if (offset + sizeof(Float) > bytes_len) return 0;
    memcpy(disturb_bytes_data(obj) + offset, &value, sizeof(Float));
    return 1;
}

static void vm_set_int_single(List *obj, Int value)
{
    if (!obj) return;
    size_t len = sizeof(Int);
    if ((size_t)obj->capacity < len + 2) return;
    obj->size = (UHalf)(len + 2);
    memcpy(disturb_bytes_data(obj), &value, sizeof(Int));
}

static void vm_set_float_single(List *obj, Float value)
{
    if (!obj) return;
    size_t len = sizeof(Float);
    if ((size_t)obj->capacity < len + 2) return;
    obj->size = (UHalf)(len + 2);
    memcpy(disturb_bytes_data(obj), &value, sizeof(Float));
}

static int vm_view_from_name(const char *name, size_t len, ViewType *out)
{
    if (len == 2) {
        if (memcmp(name, "i8", 2) == 0) { *out = VIEW_I8; return 1; }
        if (memcmp(name, "u8", 2) == 0) { *out = VIEW_U8; return 1; }
    }
    if (len == 3) {
        if (memcmp(name, "i16", 3) == 0) { *out = VIEW_I16; return 1; }
        if (memcmp(name, "u16", 3) == 0) { *out = VIEW_U16; return 1; }
        if (memcmp(name, "i32", 3) == 0) { *out = VIEW_I32; return 1; }
        if (memcmp(name, "u32", 3) == 0) { *out = VIEW_U32; return 1; }
        if (memcmp(name, "i64", 3) == 0) { *out = VIEW_I64; return 1; }
        if (memcmp(name, "u64", 3) == 0) { *out = VIEW_U64; return 1; }
        if (memcmp(name, "f32", 3) == 0) { *out = VIEW_F32; return 1; }
        if (memcmp(name, "f64", 3) == 0) { *out = VIEW_F64; return 1; }
    }
    return 0;
}

static size_t vm_view_stride(ViewType view)
{
    switch (view) {
    case VIEW_I8:
    case VIEW_U8:
        return 1;
    case VIEW_I16:
    case VIEW_U16:
        return 2;
    case VIEW_I32:
    case VIEW_U32:
    case VIEW_F32:
        return 4;
    case VIEW_I64:
    case VIEW_U64:
    case VIEW_F64:
        return 8;
    default:
        return 1;
    }
}

static int vm_view_is_float(ViewType view)
{
    return view == VIEW_F32 || view == VIEW_F64;
}

static List *disturb_obj_new_list(Int type, ObjEntry *key_entry, Int reserve)
{
    List *obj = disturb_new(2 + reserve);
    Value v;
    v.i = type;
    obj = disturb_push(obj, v);
    v.p = key_entry;
    obj = disturb_push(obj, v);
    return obj;
}

List *vm_alloc_list(VM *vm, Int type, ObjEntry *key_entry, Int reserve)
{
    size_t need = (size_t)reserve + 2;
    FreeNode *prev = NULL;
    FreeNode *cur = vm->free_lists;
    while (cur) {
        List *obj = cur->obj;
        if (obj && (size_t)obj->capacity >= need) {
            if (prev) prev->next = cur->next;
            else vm->free_lists = cur->next;
            free(cur);
            obj->data[0].i = type;
            obj->data[1].p = key_entry;
            obj->size = 2;
            return obj;
        }
        prev = cur;
        cur = cur->next;
    }
    return disturb_obj_new_list(type, key_entry, reserve);
}

static List *disturb_obj_new_bytes(Int type, ObjEntry *key_entry, const char *s, size_t len)
{
    if (len > disturb_bytes_max() - 2) {
        PANIC("byte object too large.");
    }

    size_t bytes = sizeof(List) + 2 * sizeof(Value) + len;
    List *obj = (List*)malloc(bytes);
    obj->capacity = (UHalf)(len + 2);
    obj->size = (UHalf)(len + 2);
    obj->data[0].i = type;
    obj->data[1].p = key_entry;
    if (len && s) {
        memcpy(disturb_bytes_data(obj), s, len);
    }
    return obj;
}



static void disturb_obj_clear(List *obj)
{
    if (disturb_obj_type(obj) == DISTURB_T_NATIVE && obj->size >= 3) {
        NativeBox *box = (NativeBox*)obj->data[2].p;
        if (box) {
            if (box->free_data && box->data) {
                box->free_data(box->data);
            }
            free(box);
        }
    }
    if (disturb_obj_type(obj) == DISTURB_T_LAMBDA && obj->size >= 3) {
        FunctionBox *box = (FunctionBox*)obj->data[2].p;
        if (box) {
            free(box->code);
            for (uint32_t i = 0; i < box->argc; i++) {
                free(box->arg_names[i]);
                if (box->has_default && box->has_default[i]) {
                    free(box->default_code[i]);
                }
            }
            free(box->arg_names);
            free(box->arg_lens);
            free(box->default_code);
            free(box->default_lens);
            free(box->has_default);
            free(box);
        }
    }
}

static void disturb_obj_free(List *obj)
{
    disturb_obj_clear(obj);
    free(obj);
}

void vm_free_list(List *obj)
{
    disturb_obj_free(obj);
}

static List *vm_alloc_bytes(VM *vm, Int type, ObjEntry *key_entry, const char *s, size_t len)
{
    size_t need = len + 2;
    FreeNode *prev = NULL;
    FreeNode *cur = vm->free_bytes;
    while (cur) {
        List *obj = cur->obj;
        if (obj && (size_t)obj->capacity >= need) {
            if (prev) prev->next = cur->next;
            else vm->free_bytes = cur->next;
            free(cur);
            obj->data[0].i = type;
            obj->data[1].p = key_entry;
            obj->size = (UHalf)(len + 2);
            if ((size_t)obj->capacity < need) obj->capacity = (UHalf)need;
            if (len && s) memcpy(disturb_bytes_data(obj), s, len);
            return obj;
        }
        prev = cur;
        cur = cur->next;
    }
    return disturb_obj_new_bytes(type, key_entry, s, len);
}

static void vm_pool_push(VM *vm, List *obj)
{
    if (!vm || !obj) return;
    disturb_obj_clear(obj);
    FreeNode *node = (FreeNode*)malloc(sizeof(FreeNode));
    if (!node) {
        return;
    }
    node->obj = obj;
    if (disturb_obj_type(obj) == DISTURB_T_INT || disturb_obj_type(obj) == DISTURB_T_FLOAT) {
        node->next = vm->free_bytes;
        vm->free_bytes = node;
    } else {
        node->next = vm->free_lists;
        vm->free_lists = node;
    }
}

void vm_reuse_list(VM *vm, List *obj)
{
    vm_pool_push(vm, obj);
}

void vm_flush_reuse(VM *vm)
{
    if (!vm) return;
    while (vm->free_lists) {
        FreeNode *node = vm->free_lists;
        vm->free_lists = node->next;
        vm_free_list(node->obj);
        free(node);
    }
    while (vm->free_bytes) {
        FreeNode *node = vm->free_bytes;
        vm->free_bytes = node->next;
        vm_free_list(node->obj);
        free(node);
    }
}

static size_t vm_obj_alloc_bytes(const List *obj)
{
    if (!obj) return 0;
    Int type = disturb_obj_type(obj);
    if (type == DISTURB_T_INT || type == DISTURB_T_FLOAT) {
        size_t bytes_len = obj->capacity >= 2 ? (size_t)obj->capacity - 2 : 0;
        return sizeof(List) + 2 * sizeof(Value) + bytes_len;
    }
    return sizeof(List) + (size_t)obj->capacity * sizeof(Value);
}

int vm_gc_stats(VM *vm, GcStats *out)
{
    if (!vm || !out) return 0;
    memset(out, 0, sizeof(*out));

    for (FreeNode *cur = vm->free_lists; cur; cur = cur->next) {
        out->reuse_list_count++;
        out->reuse_bytes_total += vm_obj_alloc_bytes(cur->obj);
    }
    for (FreeNode *cur = vm->free_bytes; cur; cur = cur->next) {
        out->reuse_bytes_count++;
        out->reuse_bytes_total += vm_obj_alloc_bytes(cur->obj);
    }

    for (Int i = 0; i < vm->reg_count; i++) {
        ObjEntry *entry = vm->reg[i];
        if (!entry || !entry->in_use) continue;
        entry->mark = 0;
    }

    ObjEntry *roots[] = {
        vm->global_entry,
        vm->stack_entry,
        vm->local_entry,
        vm->this_entry,
        vm->common_entry,
        vm->null_entry,
        vm->argc_entry,
        vm->gc_entry,
    };
    const size_t root_count = sizeof(roots) / sizeof(roots[0]);

    for (size_t i = 0; i < root_count; i++) {
        ObjEntry *root = roots[i];
        if (!root || !root->in_use) continue;
        if (root->mark) continue;
        List *mark_stack = disturb_new(16);
        Value v;
        v.p = root;
        mark_stack = disturb_push(mark_stack, v);
        while (mark_stack->size > 0) {
            ObjEntry *entry = (ObjEntry*)disturb_pop(mark_stack).p;
            if (!entry || !entry->in_use || entry->mark) continue;
            entry->mark = 1;
            ObjEntry *key = vm_entry_key(entry);
            if (key && key->in_use && !key->mark) {
                Value kv;
                kv.p = key;
                mark_stack = disturb_push(mark_stack, kv);
            }
            if (!entry->obj) continue;
            Int type = disturb_obj_type(entry->obj);
            if (type == DISTURB_T_TABLE) {
                List *obj = entry->obj;
                for (Int j = 2; j < obj->size; j++) {
                    ObjEntry *child = (ObjEntry*)obj->data[j].p;
                    if (child && child->in_use && !child->mark) {
                        Value cv;
                        cv.p = child;
                        mark_stack = disturb_push(mark_stack, cv);
                    }
                }
            }
        }
        disturb_free(mark_stack);
    }

    size_t obj_cap = 0;
    size_t obj_count = 0;
    List **objs = NULL;
    unsigned char *reachable = NULL;

    for (Int i = 0; i < vm->reg_count; i++) {
        ObjEntry *entry = vm->reg[i];
        if (!entry || !entry->in_use || !entry->obj) continue;
        List *obj = entry->obj;
        size_t idx = 0;
        for (; idx < obj_count; idx++) {
            if (objs[idx] == obj) break;
        }
        if (idx == obj_count) {
            if (obj_count == obj_cap) {
                size_t next_cap = obj_cap ? obj_cap * 2 : 64;
                List **next_objs = (List**)malloc(next_cap * sizeof(List*));
                unsigned char *next_reach = (unsigned char*)malloc(next_cap);
                if (!next_objs || !next_reach) {
                    free(next_objs);
                    free(next_reach);
                    free(objs);
                    free(reachable);
                    for (Int j = 0; j < vm->reg_count; j++) {
                        ObjEntry *reset = vm->reg[j];
                        if (reset && reset->in_use) reset->mark = 0;
                    }
                    return 0;
                }
                if (obj_count > 0) {
                    memcpy(next_objs, objs, obj_count * sizeof(List*));
                    memcpy(next_reach, reachable, obj_count);
                }
                free(objs);
                free(reachable);
                objs = next_objs;
                reachable = next_reach;
                obj_cap = next_cap;
            }
            objs[obj_count] = obj;
            reachable[obj_count] = entry->mark ? 1 : 0;
            obj_count++;
        } else if (entry->mark) {
            reachable[idx] = 1;
        }
    }

    for (size_t i = 0; i < obj_count; i++) {
        size_t bytes = vm_obj_alloc_bytes(objs[i]);
        if (reachable[i]) {
            out->inuse_count++;
            out->inuse_bytes += bytes;
        } else {
            out->noref_count++;
            out->noref_bytes += bytes;
        }
    }

    free(objs);
    free(reachable);

    for (Int i = 0; i < vm->reg_count; i++) {
        ObjEntry *entry = vm->reg[i];
        if (!entry || !entry->in_use) continue;
        entry->mark = 0;
    }

    out->total_bytes = out->reuse_bytes_total + out->inuse_bytes + out->noref_bytes;
    return 1;
}

static void vm_table_add_entry(VM *vm, ObjEntry *target, ObjEntry *entry)
{
    if (!target) return;
    List *old_obj = target->obj;
    target->obj = vm_update_shared_obj(vm, old_obj, disturb_table_add(old_obj, entry));
}

List *disturb_table_add(List *obj, ObjEntry *entry)
{
    Value v;
    v.p = entry;
    return disturb_push(obj, v);
}

List *disturb_bytes_append(List *obj, const char *bytes, size_t len)
{
    size_t old_len = disturb_bytes_len(obj);
    size_t new_len = old_len + len;
    if (new_len > disturb_bytes_max() - 2) {
        PANIC("byte object too large.");
    }
    size_t bytes_size = sizeof(List) + 2 * sizeof(Value) + new_len;
    obj = (List*)realloc(obj, bytes_size);
    if (len) {
        memcpy(disturb_bytes_data(obj) + old_len, bytes, len);
    }
    obj->size = (UHalf)(new_len + 2);
    obj->capacity = (UHalf)(new_len + 2);
    return obj;
}

static int disturb_bytes_eq_cstr(const List *obj, const char *s)
{
    return disturb_bytes_eq_bytes(obj, s, strlen(s));
}

static void vm_reg_init(VM *vm)
{
    vm->reg_cap = 64;
    vm->reg_count = 0;
    vm->reg = (ObjEntry**)calloc((size_t)vm->reg_cap, sizeof(ObjEntry*));
    vm->free_lists = NULL;
    vm->free_bytes = NULL;
}

static ObjEntry *vm_reg_alloc(VM *vm, List *obj)
{
    for (Int i = 0; i < vm->reg_count; i++) {
        ObjEntry *entry = vm->reg[i];
        if (entry && !entry->in_use) {
            entry->obj = obj;
            entry->key = obj ? disturb_obj_key(obj) : NULL;
            entry->in_use = 1;
            entry->mark = 0;
            entry->is_string = 0;
            entry->explicit_string = 0;
            return entry;
        }
    }

    if (vm->reg_count == vm->reg_cap) {
        vm->reg_cap = vm->reg_cap == 0 ? 64 : vm->reg_cap * 2;
        ObjEntry **next = (ObjEntry**)realloc(vm->reg, (size_t)vm->reg_cap * sizeof(ObjEntry*));
        if (!next) return NULL;
        vm->reg = next;
        memset(vm->reg + vm->reg_count, 0, (size_t)(vm->reg_cap - vm->reg_count) * sizeof(ObjEntry*));
    }

    ObjEntry *entry = (ObjEntry*)calloc(1, sizeof(ObjEntry));
    if (!entry) return NULL;
    vm->reg[vm->reg_count++] = entry;
    entry->obj = obj;
    entry->key = obj ? disturb_obj_key(obj) : NULL;
    entry->in_use = 1;
    entry->mark = 0;
    entry->is_string = 0;
    entry->explicit_string = 0;
    return entry;
}

static int vm_entry_shared(VM *vm, ObjEntry *entry)
{
    if (!vm || !entry || !entry->obj) return 0;
    for (Int i = 0; i < vm->reg_count; i++) {
        ObjEntry *other = vm->reg[i];
        if (!other || !other->in_use || other == entry) continue;
        if (other->obj == entry->obj) return 1;
    }
    return 0;
}

void vm_release_entry(VM *vm, ObjEntry *entry)
{
    if (!entry || !entry->in_use) return;
    if (entry->obj) {
        if (!vm_entry_shared(vm, entry)) {
            vm_pool_push(vm, entry->obj);
        }
        entry->obj = NULL;
    }
    entry->in_use = 0;
    entry->mark = 0;
    entry->key = NULL;
}

static ObjEntry *vm_make_key(VM *vm, const char *name)
{
    List *key_obj = vm_alloc_bytes(vm, DISTURB_T_INT, NULL, name, strlen(name));
    ObjEntry *entry = vm_reg_alloc(vm, key_obj);
    if (entry) {
        entry->is_string = 1;
        entry->explicit_string = 1;
    }
    return entry;
}

static ObjEntry *vm_make_native_entry(VM *vm, const char *key, const char *fn_name)
{
    ObjEntry *key_entry = key ? vm_make_key(vm, key) : NULL;
    NativeFn fn = vm_lookup_native(fn_name);
    if (!fn) {
        fprintf(stderr, "unknown native: %s\n", fn_name);
        return NULL;
    }
    List *obj = vm_alloc_list(vm, DISTURB_T_NATIVE, key_entry, 1);
    NativeBox *box = (NativeBox*)malloc(sizeof(NativeBox));
    box->fn = fn;
    box->data = NULL;
    box->free_data = NULL;
    box->clone_data = NULL;
    Value v;
    v.p = box;
    obj = disturb_push(obj, v);
    return vm_reg_alloc(vm, obj);
}

ObjEntry *vm_make_native_entry_data(VM *vm, const char *key, NativeFn fn, void *data,
                                    void (*free_data)(void *), void (*clone_data)(void *))
{
    ObjEntry *key_entry = key ? vm_make_key(vm, key) : NULL;
    if (!fn) return NULL;
    List *obj = vm_alloc_list(vm, DISTURB_T_NATIVE, key_entry, 1);
    NativeBox *box = (NativeBox*)malloc(sizeof(NativeBox));
    box->fn = fn;
    box->data = data;
    box->free_data = free_data;
    box->clone_data = clone_data;
    Value v;
    v.p = box;
    obj = disturb_push(obj, v);
    return vm_reg_alloc(vm, obj);
}

static ObjEntry *vm_make_key_len(VM *vm, const char *name, size_t len)
{
    List *key_obj = vm_alloc_bytes(vm, DISTURB_T_INT, NULL, name, len);
    ObjEntry *entry = vm_reg_alloc(vm, key_obj);
    if (entry) {
        entry->is_string = 1;
        entry->explicit_string = 1;
    }
    return entry;
}

static ObjEntry *vm_find_by_key(VM *vm, const char *name)
{
    for (Int i = 0; i < vm->reg_count; i++) {
        ObjEntry *entry = vm->reg[i];
        if (!entry || !entry->in_use) continue;
        ObjEntry *key = vm_entry_key(entry);
        if (!key) continue;
        if (!entry_is_string(key)) continue;
        if (disturb_bytes_eq_cstr(key->obj, name)) return entry;
    }
    return NULL;
}

static void vm_global_add(VM *vm, ObjEntry *entry)
{
    vm_table_add_entry(vm, vm->global_entry, entry);
}

int vm_global_remove_by_key(VM *vm, const char *name)
{
    List *global = vm->global_entry->obj;
    for (Int i = 2; i < global->size; i++) {
        ObjEntry *entry = (ObjEntry*)global->data[i].p;
        ObjEntry *key = vm_entry_key(entry);
        if (!key) continue;
        if (!entry_is_string(key)) continue;
        if (disturb_bytes_eq_cstr(key->obj, name)) {
            disturb_remove(global, i);
            return 1;
        }
    }
    return 0;
}

void vm_gc(VM *vm)
{
    if (!vm) return;

    /* mark */
    for (Int i = 0; i < vm->reg_count; i++) {
        ObjEntry *entry = vm->reg[i];
        if (!entry || !entry->in_use) continue;
        entry->mark = 0;
    }

    ObjEntry *roots[] = {
        vm->global_entry,
        vm->stack_entry,
        vm->local_entry,
        vm->this_entry,
        vm->common_entry,
        vm->null_entry,
        vm->argc_entry,
        vm->gc_entry,
    };
    const size_t root_count = sizeof(roots) / sizeof(roots[0]);

    for (size_t i = 0; i < root_count; i++) {
        ObjEntry *root = roots[i];
        if (!root || !root->in_use) continue;
        if (root->mark) continue;
        /* iterative mark using a simple stack */
        List *mark_stack = disturb_new(16);
        Value v;
        v.p = root;
        mark_stack = disturb_push(mark_stack, v);
        while (mark_stack->size > 0) {
            ObjEntry *entry = (ObjEntry*)disturb_pop(mark_stack).p;
            if (!entry || !entry->in_use || entry->mark) continue;
            entry->mark = 1;
            ObjEntry *key = vm_entry_key(entry);
            if (key && key->in_use && !key->mark) {
                Value kv;
                kv.p = key;
                mark_stack = disturb_push(mark_stack, kv);
            }
            if (!entry->obj) continue;
            Int type = disturb_obj_type(entry->obj);
            if (type == DISTURB_T_TABLE) {
                List *obj = entry->obj;
                for (Int j = 2; j < obj->size; j++) {
                    ObjEntry *child = (ObjEntry*)obj->data[j].p;
                    if (child && child->in_use && !child->mark) {
                        Value cv;
                        cv.p = child;
                        mark_stack = disturb_push(mark_stack, cv);
                    }
                }
            }
        }
        disturb_free(mark_stack);
    }

    /* sweep */
    for (Int i = 0; i < vm->reg_count; i++) {
        ObjEntry *entry = vm->reg[i];
        if (!entry || !entry->in_use) continue;
        if (entry->mark) {
            entry->mark = 0;
            continue;
        }
        vm_release_entry(vm, entry);
    }
}

ObjEntry *vm_stack_peek(List *stack, Int from_top)
{
    Int idx = stack->size - 1 - from_top;
    if (idx < 2) return NULL;
    return (ObjEntry*)stack->data[idx].p;
}

ObjEntry *vm_global_find_by_key(List *global, const char *name)
{
    for (Int i = 2; i < global->size; i++) {
        ObjEntry *entry = (ObjEntry*)global->data[i].p;
        if (!entry) continue;
        ObjEntry *key = vm_entry_key(entry);
        if (!key) continue;
        if (!entry_is_string(key)) continue;
        if (disturb_bytes_eq_cstr(key->obj, name)) return entry;
    }
    return NULL;
}

static ObjEntry *vm_object_find_direct(List *obj, const char *name, size_t len)
{
    if (!obj) return NULL;
    Int start = 2;
    Int type = disturb_obj_type(obj);
    if (type == DISTURB_T_NATIVE || type == DISTURB_T_LAMBDA) start = 3;
    for (Int i = start; i < obj->size; i++) {
        ObjEntry *entry = (ObjEntry*)obj->data[i].p;
        if (!entry) continue;
        ObjEntry *key = vm_entry_key(entry);
        if (!key) continue;
        if (!entry_is_string(key)) continue;
        if (disturb_bytes_eq_bytes(key->obj, name, len)) return entry;
    }
    return NULL;
}

static ObjEntry *vm_object_find_by_key_len(VM *vm, List *obj, const char *name, size_t len)
{
    ObjEntry *entry = vm_object_find_direct(obj, name, len);
    if (entry) return entry;
    if (!vm || !vm->common_entry || obj == vm->common_entry->obj) {
        return vm ? vm->null_entry : NULL;
    }
    entry = vm_object_find_direct(vm->common_entry->obj, name, len);
    if (entry) return entry;
    return vm ? vm->null_entry : NULL;
}

Int vm_value_len_entry(const ObjEntry *entry)
{
    if (!entry || !entry->in_use) return 0;
    List *obj = entry->obj;
    Int type = disturb_obj_type(obj);
    switch (type) {
    case DISTURB_T_NULL:
        return 0;
    case DISTURB_T_INT:
        if (entry_is_string(entry)) {
            return (Int)disturb_bytes_len(obj);
        }
        return vm_bytes_to_count(disturb_bytes_len(obj), DISTURB_T_INT);
    case DISTURB_T_FLOAT:
        return vm_bytes_to_count(disturb_bytes_len(obj), DISTURB_T_FLOAT);
    case DISTURB_T_TABLE:
        return obj->size - 2;
    case DISTURB_T_NATIVE:
    case DISTURB_T_LAMBDA:
    case DISTURB_T_VIEW:
        return obj->size > 2 ? 1 : 0;
    default:
        return obj->size - 2;
    }
}

static int vm_entry_truthy(const ObjEntry *entry)
{
    if (!entry || !entry->in_use) return 0;
    Int type = disturb_obj_type(entry->obj);
    if (type == DISTURB_T_NULL) return 0;
    if (type == DISTURB_T_INT && !entry_is_string(entry)) {
        size_t len = disturb_bytes_len(entry->obj);
        if (len == sizeof(Int)) {
            Int v = 0;
            if (vm_read_int_at(entry->obj, 0, &v) && v == 0) return 0;
        }
    }
    if (type == DISTURB_T_FLOAT) {
        size_t len = disturb_bytes_len(entry->obj);
        if (len == sizeof(Float)) {
            Float v = 0;
            if (vm_read_float_at(entry->obj, 0, &v) && v == 0) return 0;
        }
    }
    return 1;
}

static int vm_entry_number(const ObjEntry *entry, Int *out_i, Float *out_f, int *out_is_float,
                           const char *op, size_t pc)
{
    if (!entry || !entry->in_use) {
        fprintf(stderr, "bytecode error at pc %zu: %s expects number\n", pc, op);
        return 0;
    }
    Int type = disturb_obj_type(entry->obj);
    if (type == DISTURB_T_INT) {
        if (entry_is_string(entry)) {
            fprintf(stderr, "bytecode error at pc %zu: %s expects number\n", pc, op);
            return 0;
        }
        size_t len = disturb_bytes_len(entry->obj);
        if (len != sizeof(Int)) {
            fprintf(stderr, "bytecode error at pc %zu: %s expects number\n", pc, op);
            return 0;
        }
        Int v = 0;
        if (!vm_read_int_at(entry->obj, 0, &v)) return 0;
        if (out_i) *out_i = v;
        if (out_f) *out_f = (Float)v;
        if (out_is_float) *out_is_float = 0;
        return 1;
    }
    if (type == DISTURB_T_FLOAT) {
        size_t len = disturb_bytes_len(entry->obj);
        if (len != sizeof(Float)) {
            fprintf(stderr, "bytecode error at pc %zu: %s expects number\n", pc, op);
            return 0;
        }
        Float v = 0;
        if (!vm_read_float_at(entry->obj, 0, &v)) return 0;
        if (out_i) *out_i = (Int)v;
        if (out_f) *out_f = v;
        if (out_is_float) *out_is_float = 1;
        return 1;
    }
    fprintf(stderr, "bytecode error at pc %zu: %s expects number\n", pc, op);
    return 0;
}

static ObjEntry *vm_make_number_result(VM *vm, double value)
{
    if (value >= (double)INT_MIN && value <= (double)INT_MAX) {
        Int iv = (Int)value;
        if ((double)iv == value) {
            return vm_make_int_value(vm, iv);
        }
    }
    return vm_make_float_value(vm, (Float)value);
}

static void sb_append_number(StrBuf *b, Float v)
{
    double iv = 0.0;
    double frac = modf((double)v, &iv);
    char buf[64];
    if (frac == 0.0 && iv >= -9.22e18 && iv <= 9.22e18) {
        snprintf(buf, sizeof(buf), "%lld", (long long)iv);
    } else {
        snprintf(buf, sizeof(buf), "%.17g", (double)v);
    }
    sb_append_n(b, buf, strlen(buf));
}

static void sb_append_int(StrBuf *b, Int v)
{
    char buf[64];
    snprintf(buf, sizeof(buf), "%lld", (long long)v);
    sb_append_n(b, buf, strlen(buf));
}

static void sb_append_escaped(StrBuf *b, const char *s, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)s[i];
        switch (c) {
        case '\\': sb_append_n(b, "\\\\", 2); break;
        case '"': sb_append_n(b, "\\\"", 2); break;
        case '\n': sb_append_n(b, "\\n", 2); break;
        case '\r': sb_append_n(b, "\\r", 2); break;
        case '\t': sb_append_n(b, "\\t", 2); break;
        default:
            if (c < 32 || c >= 127) {
                char buf[5];
                snprintf(buf, sizeof(buf), "\\x%02x", c);
                sb_append_n(b, buf, strlen(buf));
            } else {
                sb_append_char(b, (char)c);
            }
            break;
        }
    }
}

static void vm_append_key_text(StrBuf *b, ObjEntry *entry)
{
    ObjEntry *key = vm_entry_key(entry);
    if (!key || !entry_is_string(key)) {
        sb_append_char(b, '_');
        return;
    }
    sb_append_n(b, disturb_bytes_data(key->obj), disturb_bytes_len(key->obj));
}

static void vm_append_value_text(VM *vm, ObjEntry *entry, StrBuf *b, int raw_string)
{
    if (!entry || !entry->in_use) {
        sb_append_n(b, "null", 4);
        return;
    }

    List *obj = entry->obj;
    Int type = disturb_obj_type(obj);
    switch (type) {
    case DISTURB_T_NULL:
        sb_append_n(b, "null", 4);
        break;
    case DISTURB_T_INT: {
        if (entry_is_string(entry)) {
            size_t len = disturb_bytes_len(obj);
            if (raw_string) {
                sb_append_n(b, disturb_bytes_data(obj), len);
                break;
            }
            if (len == 1) {
                sb_append_char(b, '\'');
                sb_append_escaped(b, disturb_bytes_data(obj), len);
                sb_append_char(b, '\'');
            } else {
                sb_append_char(b, '"');
                sb_append_escaped(b, disturb_bytes_data(obj), len);
                sb_append_char(b, '"');
            }
            break;
        }
        Int count = vm_bytes_to_count(disturb_bytes_len(obj), DISTURB_T_INT);
        if (count == 0) {
            sb_append_n(b, "[]", 2);
            break;
        }
        if (count == 1) {
            Int v = 0;
            if (vm_read_int_at(obj, 0, &v)) {
                sb_append_int(b, v);
            } else {
                sb_append_n(b, "0", 1);
            }
            break;
        }
        sb_append_char(b, '[');
        for (Int i = 0; i < count; i++) {
            Int v = 0;
            if (i) sb_append_n(b, ", ", 2);
            if (vm_read_int_at(obj, i, &v)) {
                sb_append_int(b, v);
            } else {
                sb_append_n(b, "0", 1);
            }
        }
        sb_append_char(b, ']');
        break;
    }
    case DISTURB_T_FLOAT: {
        Int count = vm_bytes_to_count(disturb_bytes_len(obj), DISTURB_T_FLOAT);
        if (count == 0) {
            sb_append_n(b, "[]", 2);
            break;
        }
        if (count == 1) {
            Float v = 0;
            if (vm_read_float_at(obj, 0, &v)) {
                sb_append_number(b, v);
            } else {
                sb_append_n(b, "0", 1);
            }
            break;
        }
        sb_append_char(b, '[');
        for (Int i = 0; i < count; i++) {
            Float v = 0;
            if (i) sb_append_n(b, ", ", 2);
            if (vm_read_float_at(obj, i, &v)) {
                sb_append_number(b, v);
            } else {
                sb_append_n(b, "0", 1);
            }
        }
        sb_append_char(b, ']');
        break;
    }
    case DISTURB_T_TABLE: {
        sb_append_char(b, '{');
        int first = 1;
        for (Int i = 2; i < obj->size; i++) {
            ObjEntry *child = (ObjEntry*)obj->data[i].p;
            if (!child) continue;
            if (!first) sb_append_n(b, ", ", 2);
            first = 0;
            vm_append_key_text(b, child);
            sb_append_n(b, " = ", 3);
            vm_append_value_text(vm, child, b, 0);
        }
        sb_append_char(b, '}');
        break;
    }
    case DISTURB_T_NATIVE:
        sb_append_n(b, "<native>", 8);
        break;
    case DISTURB_T_LAMBDA:
        sb_append_n(b, "<function>", 10);
        break;
    default:
        sb_append_n(b, "<data>", 6);
        break;
    }
}

ObjEntry *vm_stringify_value(VM *vm, ObjEntry *entry, int raw_string)
{
    StrBuf buf;
    sb_init(&buf);
    vm_append_value_text(vm, entry, &buf, raw_string);
    ObjEntry *out = vm_make_bytes_value(vm, buf.data, buf.len);
    sb_free(&buf);
    return out;
}

typedef struct {
    const List **items;
    size_t count;
    size_t cap;
} PrettySeen;

static int pretty_seen_has(const PrettySeen *seen, const List *obj)
{
    for (size_t i = 0; i < seen->count; i++) {
        if (seen->items[i] == obj) return 1;
    }
    return 0;
}

static int pretty_seen_push(PrettySeen *seen, const List *obj)
{
    if (seen->count == seen->cap) {
        size_t next = seen->cap == 0 ? 8 : seen->cap * 2;
        const List **tmp = (const List**)realloc(seen->items, next * sizeof(List*));
        if (!tmp) return 0;
        seen->items = tmp;
        seen->cap = next;
    }
    seen->items[seen->count++] = obj;
    return 1;
}

static void pretty_seen_pop(PrettySeen *seen)
{
    if (seen->count > 0) seen->count--;
}

static void sb_append_indent(StrBuf *b, int depth, int indent)
{
    int total = depth * indent;
    for (int i = 0; i < total; i++) {
        sb_append_char(b, ' ');
    }
}

static void vm_append_pretty_value(VM *vm, ObjEntry *entry, StrBuf *b, int indent, int depth, PrettySeen *seen)
{
    if (!entry || !entry->in_use) {
        sb_append_n(b, "null", 4);
        return;
    }

    List *obj = entry->obj;
    Int type = disturb_obj_type(obj);
    switch (type) {
    case DISTURB_T_NULL:
        sb_append_n(b, "null", 4);
        break;
    case DISTURB_T_INT: {
        if (entry_is_string(entry)) {
            vm_append_value_text(vm, entry, b, 0);
            break;
        }
        Int count = vm_bytes_to_count(disturb_bytes_len(obj), DISTURB_T_INT);
        if (count <= 1) {
            vm_append_value_text(vm, entry, b, 0);
            break;
        }
        sb_append_char(b, '[');
        sb_append_char(b, '\n');
        for (Int i = 0; i < count; i++) {
            Int v = 0;
            sb_append_indent(b, depth + 1, indent);
            if (vm_read_int_at(obj, i, &v)) {
                sb_append_int(b, v);
            } else {
                sb_append_n(b, "0", 1);
            }
            if (i + 1 < count) sb_append_char(b, ',');
            sb_append_char(b, '\n');
        }
        sb_append_indent(b, depth, indent);
        sb_append_char(b, ']');
        break;
    }
    case DISTURB_T_FLOAT: {
        Int count = vm_bytes_to_count(disturb_bytes_len(obj), DISTURB_T_FLOAT);
        if (count <= 1) {
            vm_append_value_text(vm, entry, b, 0);
            break;
        }
        sb_append_char(b, '[');
        sb_append_char(b, '\n');
        for (Int i = 0; i < count; i++) {
            Float v = 0;
            sb_append_indent(b, depth + 1, indent);
            if (vm_read_float_at(obj, i, &v)) {
                sb_append_number(b, v);
            } else {
                sb_append_n(b, "0", 1);
            }
            if (i + 1 < count) sb_append_char(b, ',');
            sb_append_char(b, '\n');
        }
        sb_append_indent(b, depth, indent);
        sb_append_char(b, ']');
        break;
    }
    case DISTURB_T_TABLE: {
        if (pretty_seen_has(seen, obj)) {
            sb_append_n(b, "<cycle>", 7);
            break;
        }
        if (!pretty_seen_push(seen, obj)) {
            sb_append_n(b, "<oom>", 5);
            break;
        }
        Int count = 0;
        for (Int i = 2; i < obj->size; i++) {
            if (obj->data[i].p) count++;
        }
        if (count <= 0) {
            sb_append_n(b, "{}", 2);
            pretty_seen_pop(seen);
            break;
        }
        sb_append_n(b, "{\n", 2);
        Int printed = 0;
        for (Int i = 2; i < obj->size; i++) {
            ObjEntry *child = (ObjEntry*)obj->data[i].p;
            if (!child) continue;
            sb_append_indent(b, depth + 1, indent);
            vm_append_key_text(b, child);
            sb_append_n(b, " = ", 3);
            vm_append_pretty_value(vm, child, b, indent, depth + 1, seen);
            printed++;
            if (printed < count) sb_append_char(b, ',');
            sb_append_char(b, '\n');
        }
        sb_append_indent(b, depth, indent);
        sb_append_char(b, '}');
        pretty_seen_pop(seen);
        break;
    }
    case DISTURB_T_NATIVE:
        sb_append_n(b, "<native>", 8);
        break;
    case DISTURB_T_LAMBDA:
        sb_append_n(b, "<function>", 10);
        break;
    default:
        sb_append_n(b, "<data>", 6);
        break;
    }
}

ObjEntry *vm_pretty_value(VM *vm, ObjEntry *entry)
{
    StrBuf buf;
    sb_init(&buf);
    PrettySeen seen;
    memset(&seen, 0, sizeof(seen));
    vm_append_pretty_value(vm, entry, &buf, 2, 0, &seen);
    free(seen.items);
    ObjEntry *out = vm_make_bytes_value(vm, buf.data, buf.len);
    sb_free(&buf);
    return out;
}

static int vm_entry_equal(ObjEntry *a, ObjEntry *b)
{
    if (a == b) return 1;
    if (!a || !b || !a->in_use || !b->in_use) return 0;
    Int at = disturb_obj_type(a->obj);
    Int bt = disturb_obj_type(b->obj);
    if ((at == DISTURB_T_INT && entry_is_string(a)) ||
        (bt == DISTURB_T_INT && entry_is_string(b))) {
        if (!(at == DISTURB_T_INT && entry_is_string(a) && bt == DISTURB_T_INT && entry_is_string(b))) {
            return 0;
        }
        size_t al = disturb_bytes_len(a->obj);
        size_t bl = disturb_bytes_len(b->obj);
        if (al != bl) return 0;
        return memcmp(disturb_bytes_data(a->obj), disturb_bytes_data(b->obj), al) == 0;
    }
    if ((at == DISTURB_T_INT || at == DISTURB_T_FLOAT) &&
        (bt == DISTURB_T_INT || bt == DISTURB_T_FLOAT)) {
        size_t al = disturb_bytes_len(a->obj);
        size_t bl = disturb_bytes_len(b->obj);
        size_t asz = vm_elem_size(at);
        size_t bsz = vm_elem_size(bt);
        if (al == asz && bl == bsz) {
            double av = 0.0;
            double bv = 0.0;
            if (at == DISTURB_T_INT) {
                Int v = 0;
                if (!vm_read_int_at(a->obj, 0, &v)) return 0;
                av = (double)v;
            } else {
                Float v = 0;
                if (!vm_read_float_at(a->obj, 0, &v)) return 0;
                av = (double)v;
            }
            if (bt == DISTURB_T_INT) {
                Int v = 0;
                if (!vm_read_int_at(b->obj, 0, &v)) return 0;
                bv = (double)v;
            } else {
                Float v = 0;
                if (!vm_read_float_at(b->obj, 0, &v)) return 0;
                bv = (double)v;
            }
            return av == bv;
        }
        if (at != bt) return 0;
        Int ac = vm_bytes_to_count(al, at);
        Int bc = vm_bytes_to_count(bl, bt);
        if (ac != bc) return 0;
        if (at == DISTURB_T_INT) {
            for (Int i = 0; i < ac; i++) {
                Int av = 0;
                Int bv = 0;
                if (!vm_read_int_at(a->obj, i, &av) || !vm_read_int_at(b->obj, i, &bv)) return 0;
                if (av != bv) return 0;
            }
        } else {
            for (Int i = 0; i < ac; i++) {
                Float av = 0;
                Float bv = 0;
                if (!vm_read_float_at(a->obj, i, &av) || !vm_read_float_at(b->obj, i, &bv)) return 0;
                if (av != bv) return 0;
            }
        }
        return 1;
    }
    if (at == DISTURB_T_NULL) return 1;
    return 0;
}

static int vm_entry_compare(ObjEntry *a, ObjEntry *b, int *out)
{
    if (!a || !b || !a->in_use || !b->in_use) return 0;
    Int at = disturb_obj_type(a->obj);
    Int bt = disturb_obj_type(b->obj);
    if ((at == DISTURB_T_INT && entry_is_string(a)) ||
        (bt == DISTURB_T_INT && entry_is_string(b))) {
        if (!(at == DISTURB_T_INT && entry_is_string(a) && bt == DISTURB_T_INT && entry_is_string(b))) {
            return 0;
        }
        size_t al = disturb_bytes_len(a->obj);
        size_t bl = disturb_bytes_len(b->obj);
        size_t min = al < bl ? al : bl;
        int cmp = memcmp(disturb_bytes_data(a->obj), disturb_bytes_data(b->obj), min);
        if (cmp < 0) *out = -1;
        else if (cmp > 0) *out = 1;
        else if (al < bl) *out = -1;
        else if (al > bl) *out = 1;
        else *out = 0;
        return 1;
    }
    if ((at == DISTURB_T_INT || at == DISTURB_T_FLOAT) &&
        (bt == DISTURB_T_INT || bt == DISTURB_T_FLOAT)) {
        size_t al = disturb_bytes_len(a->obj);
        size_t bl = disturb_bytes_len(b->obj);
        size_t asz = vm_elem_size(at);
        size_t bsz = vm_elem_size(bt);
        if (al == asz && bl == bsz) {
            double av = 0.0;
            double bv = 0.0;
            if (at == DISTURB_T_INT) {
                Int v = 0;
                if (!vm_read_int_at(a->obj, 0, &v)) return 0;
                av = (double)v;
            } else {
                Float v = 0;
                if (!vm_read_float_at(a->obj, 0, &v)) return 0;
                av = (double)v;
            }
            if (bt == DISTURB_T_INT) {
                Int v = 0;
                if (!vm_read_int_at(b->obj, 0, &v)) return 0;
                bv = (double)v;
            } else {
                Float v = 0;
                if (!vm_read_float_at(b->obj, 0, &v)) return 0;
                bv = (double)v;
            }
            if (av < bv) *out = -1;
            else if (av > bv) *out = 1;
            else *out = 0;
            return 1;
        }
        return 0;
    }
    return 0;
}

static void print_key(FILE *out, ObjEntry *entry)
{
    ObjEntry *key = vm_entry_key(entry);
    if (!key) {
        fputs("_", out);
        return;
    }
    List *key_obj = key->obj;
    if (!entry_is_string(key)) {
        fputs("<?>", out);
        return;
    }
    fwrite(disturb_bytes_data(key_obj), 1, disturb_bytes_len(key_obj), out);
}

void print_plain_entry(FILE *out, VM *vm, ObjEntry *entry)
{
    if (!entry || !entry->in_use) {
        fputs("null", out);
        return;
    }

    List *obj = entry->obj;
    Int type = disturb_obj_type(obj);
    int print_as_string = entry_is_string(entry);
    if (vm && vm->strict_mode && print_as_string && !entry->explicit_string) {
        print_as_string = 0;
    }

    switch (type) {
    case DISTURB_T_NULL:
        fputs("null", out);
        break;
    case DISTURB_T_INT:
        if (print_as_string) {
            fwrite(disturb_bytes_data(obj), 1, disturb_bytes_len(obj), out);
            break;
        }
        {
            Int count = vm_bytes_to_count(disturb_bytes_len(obj), DISTURB_T_INT);
            for (Int i = 0; i < count; i++) {
                if (i > 0) fputs(" ", out);
                Int v = 0;
                if (vm_read_int_at(obj, i, &v)) {
                    fprintf(out, "%lld", (long long)v);
                } else {
                    fputs("0", out);
                }
            }
        }
        break;
    case DISTURB_T_FLOAT: {
        Int count = vm_bytes_to_count(disturb_bytes_len(obj), DISTURB_T_FLOAT);
        for (Int i = 0; i < count; i++) {
            if (i > 0) fputs(" ", out);
            Float v = 0;
            if (vm_read_float_at(obj, i, &v)) {
                fprintf(out, "%g", (double)v);
            } else {
                fputs("0", out);
            }
        }
        break;
    }
    case DISTURB_T_TABLE:
        for (Int i = 2; i < obj->size; i++) {
            if (i > 2) fputs(" ", out);
            ObjEntry *child = (ObjEntry*)obj->data[i].p;
            if (!child) {
                fputs("null", out);
                continue;
            }
            print_key(out, child);
        }
        break;
    case DISTURB_T_NATIVE:
        fputs("<native>", out);
        break;
    default:
        fputs("<data>", out);
        break;
    }
}

void print_entry(FILE *out, VM *vm, ObjEntry *entry)
{
    if (!entry || !entry->in_use) {
        fputs("null", out);
        return;
    }

    List *obj = entry->obj;
    Int type = disturb_obj_type(obj);
    int print_as_string = entry_is_string(entry);
    if (vm && vm->strict_mode && print_as_string && !entry->explicit_string) {
        print_as_string = 0;
    }

    fputs("[", out);
    fputs(disturb_type_name(type), out);
    fputs(" ", out);
    print_key(out, entry);
    fputs("] ", out);

    switch (type) {
    case DISTURB_T_NULL:
        fputs("null", out);
        break;
    case DISTURB_T_INT:
        if (print_as_string) {
            fputs("\"", out);
            fwrite(disturb_bytes_data(obj), 1, disturb_bytes_len(obj), out);
            fputs("\"", out);
        } else {
            fputs("[", out);
            Int count = vm_bytes_to_count(disturb_bytes_len(obj), DISTURB_T_INT);
            for (Int i = 0; i < count; i++) {
                if (i > 0) fputs(" ", out);
                Int v = 0;
                if (vm_read_int_at(obj, i, &v)) {
                    fprintf(out, "%lld", (long long)v);
                } else {
                    fputs("0", out);
                }
            }
            fputs("]", out);
        }
        break;
    case DISTURB_T_FLOAT:
        fputs("[", out);
        {
            Int count = vm_bytes_to_count(disturb_bytes_len(obj), DISTURB_T_FLOAT);
            for (Int i = 0; i < count; i++) {
                if (i > 0) fputs(" ", out);
                Float v = 0;
                if (vm_read_float_at(obj, i, &v)) {
                    fprintf(out, "%g", (double)v);
                } else {
                    fputs("0", out);
                }
            }
        }
        fputs("]", out);
        break;
    case DISTURB_T_TABLE:
        fputs("[", out);
        for (Int i = 2; i < obj->size; i++) {
            if (i > 2) fputs(" ", out);
            ObjEntry *child = (ObjEntry*)obj->data[i].p;
            if (!child) {
                fputs("null", out);
                continue;
            }
            print_key(out, child);
        }
        fputs("]", out);
        break;
    case DISTURB_T_NATIVE:
        fputs("<native>", out);
        break;
    default:
        fputs("<data>", out);
        break;
    }
}

void vm_init(VM *vm)
{
    memset(vm, 0, sizeof(*vm));
    vm_reg_init(vm);
    vm->gc_entry = NULL;
    vm->call_override_len = -1;
    vm->has_call_override = 0;
    vm->call_entry = NULL;
    vm->strict_mode = 0;

    ObjEntry *global_key = vm_make_key(vm, "global");
    List *global_obj = vm_alloc_list(vm, DISTURB_T_TABLE, global_key, 8);
    vm->global_entry = vm_reg_alloc(vm, global_obj);

    ObjEntry *stack_key = vm_make_key(vm, "stack");
    List *stack_obj = vm_alloc_list(vm, DISTURB_T_TABLE, stack_key, 8);
    vm->stack_entry = vm_reg_alloc(vm, stack_obj);
    vm_global_add(vm, vm->stack_entry);

    vm->local_entry = NULL;

    ObjEntry *null_key = vm_make_key(vm, "null");
    List *null_obj = vm_alloc_list(vm, DISTURB_T_NULL, null_key, 0);
    vm->null_entry = vm_reg_alloc(vm, null_obj);
    vm_global_add(vm, vm->null_entry);

    ObjEntry *inf_key = vm_make_key(vm, "inf");
    ObjEntry *inf_entry = vm_make_float_value(vm, (Float)INFINITY);
    if (inf_entry) {
        inf_entry->key = inf_key;
        vm_global_add(vm, inf_entry);
    }

    ObjEntry *proto_key = vm_make_key(vm, "common");
    List *proto_obj = vm_alloc_list(vm, DISTURB_T_TABLE, proto_key, 16);
    vm->common_entry = vm_reg_alloc(vm, proto_obj);
    vm_global_add(vm, vm->common_entry);

    ObjEntry *argc_key = vm_make_key(vm, "__argc");
    List *argc_obj = vm_alloc_bytes(vm, DISTURB_T_INT, argc_key, NULL, sizeof(Int));
    vm_set_int_single(argc_obj, 0);
    vm->argc_entry = vm_reg_alloc(vm, argc_obj);
    vm_global_add(vm, vm->argc_entry);

    vm->this_entry = vm->null_entry;

    ObjEntry *len_key = vm_make_key(vm, "__len");
    List *len_obj = vm_alloc_bytes(vm, DISTURB_T_INT, len_key, NULL, sizeof(Int));
    vm_set_int_single(len_obj, 0);
    ObjEntry *len_entry = vm_reg_alloc(vm, len_obj);
    vm_global_add(vm, len_entry);

    ObjEntry *gc_key = vm_make_key(vm, "gc");
    List *gc_obj = vm_alloc_list(vm, DISTURB_T_TABLE, gc_key, 4);
    vm->gc_entry = vm_reg_alloc(vm, gc_obj);
    vm_global_add(vm, vm->gc_entry);

    ObjEntry *collect_entry = vm_make_native_entry(vm, "collect", "gcCollect");
    if (collect_entry) {
        gc_obj = disturb_table_add(gc_obj, collect_entry);
        vm->gc_entry->obj = gc_obj;
    }
    ObjEntry *free_entry = vm_make_native_entry(vm, "free", "gcFree");
    if (free_entry) {
        gc_obj = disturb_table_add(gc_obj, free_entry);
        vm->gc_entry->obj = gc_obj;
    }
    ObjEntry *sweep_entry = vm_make_native_entry(vm, "sweep", "gcSweep");
    if (sweep_entry) {
        gc_obj = disturb_table_add(gc_obj, sweep_entry);
        vm->gc_entry->obj = gc_obj;
    }
    ObjEntry *new_entry = vm_make_native_entry(vm, "new", "gcNew");
    if (new_entry) {
        gc_obj = disturb_table_add(gc_obj, new_entry);
        vm->gc_entry->obj = gc_obj;
    }
    ObjEntry *debug_entry = vm_make_native_entry(vm, "debug", "gcDebug");
    if (debug_entry) {
        gc_obj = disturb_table_add(gc_obj, debug_entry);
        vm->gc_entry->obj = gc_obj;
    }
    ObjEntry *stats_entry = vm_make_native_entry(vm, "stats", "gcStats");
    if (stats_entry) {
        gc_obj = disturb_table_add(gc_obj, stats_entry);
        vm->gc_entry->obj = gc_obj;
    }

    ObjEntry *entry = NULL;
    entry = vm_define_native(vm, "print", "print");
    if (entry) vm_table_add_entry(vm, vm->common_entry, entry);
    entry = vm_define_native(vm, "println", "println");
    if (entry) vm_table_add_entry(vm, vm->common_entry, entry);
    entry = vm_define_native(vm, "len", "len");
    if (entry) vm_table_add_entry(vm, vm->common_entry, entry);
    entry = vm_define_native(vm, "pretty", "pretty");
    if (entry) vm_table_add_entry(vm, vm->common_entry, entry);
    entry = vm_define_native(vm, "clone", "clone");
    if (entry) vm_table_add_entry(vm, vm->common_entry, entry);
    entry = vm_define_native(vm, "copy", "copy");
    if (entry) vm_table_add_entry(vm, vm->common_entry, entry);
    entry = vm_define_native(vm, "toInt", "toInt");
    if (entry) vm_table_add_entry(vm, vm->common_entry, entry);
    entry = vm_define_native(vm, "toFloat", "toFloat");
    if (entry) vm_table_add_entry(vm, vm->common_entry, entry);
    entry = vm_define_native(vm, "gc", "gc");
    if (entry) vm_table_add_entry(vm, vm->common_entry, entry);
    #ifdef DISTURB_ENABLE_IO
    entry = vm_define_native(vm, "read", "read");
    if (entry) vm_table_add_entry(vm, vm->common_entry, entry);
    entry = vm_define_native(vm, "write", "write");
    if (entry) vm_table_add_entry(vm, vm->common_entry, entry);
    #endif
    #ifdef DISTURB_ENABLE_SYSTEM
    entry = vm_define_native(vm, "system", "system");
    if (entry) vm_table_add_entry(vm, vm->common_entry, entry);
    #endif
    entry = vm_define_native(vm, "eval", "eval");
    if (entry) vm_table_add_entry(vm, vm->common_entry, entry);
    entry = vm_define_native(vm, "parse", "parse");
    if (entry) vm_table_add_entry(vm, vm->common_entry, entry);
    entry = vm_define_native(vm, "emit", "emit");
    if (entry) vm_table_add_entry(vm, vm->common_entry, entry);
    entry = vm_define_native(vm, "evalBytecode", "evalBytecode");
    if (entry) vm_table_add_entry(vm, vm->common_entry, entry);
    entry = vm_define_native(vm, "bytecodeToAst", "bytecodeToAst");
    if (entry) vm_table_add_entry(vm, vm->common_entry, entry);
    entry = vm_define_native(vm, "astToSource", "astToSource");
    if (entry) vm_table_add_entry(vm, vm->common_entry, entry);
    entry = vm_define_native(vm, "append", "append");
    if (entry) vm_table_add_entry(vm, vm->common_entry, entry);
    entry = vm_define_native(vm, "add", "add");
    if (entry) vm_table_add_entry(vm, vm->common_entry, entry);
    entry = vm_define_native(vm, "sub", "sub");
    if (entry) vm_table_add_entry(vm, vm->common_entry, entry);
    entry = vm_define_native(vm, "mul", "mul");
    if (entry) vm_table_add_entry(vm, vm->common_entry, entry);
    entry = vm_define_native(vm, "div", "div");
    if (entry) vm_table_add_entry(vm, vm->common_entry, entry);
    entry = vm_define_native(vm, "mod", "mod");
    if (entry) vm_table_add_entry(vm, vm->common_entry, entry);
    entry = vm_define_native(vm, "pow", "pow");
    if (entry) vm_table_add_entry(vm, vm->common_entry, entry);
    entry = vm_define_native(vm, "min", "min");
    if (entry) vm_table_add_entry(vm, vm->common_entry, entry);
    entry = vm_define_native(vm, "max", "max");
    if (entry) vm_table_add_entry(vm, vm->common_entry, entry);
    entry = vm_define_native(vm, "abs", "abs");
    if (entry) vm_table_add_entry(vm, vm->common_entry, entry);
    entry = vm_define_native(vm, "floor", "floor");
    if (entry) vm_table_add_entry(vm, vm->common_entry, entry);
    entry = vm_define_native(vm, "ceil", "ceil");
    if (entry) vm_table_add_entry(vm, vm->common_entry, entry);
    entry = vm_define_native(vm, "round", "round");
    if (entry) vm_table_add_entry(vm, vm->common_entry, entry);
    entry = vm_define_native(vm, "sqrt", "sqrt");
    if (entry) vm_table_add_entry(vm, vm->common_entry, entry);
    entry = vm_define_native(vm, "sin", "sin");
    if (entry) vm_table_add_entry(vm, vm->common_entry, entry);
    entry = vm_define_native(vm, "cos", "cos");
    if (entry) vm_table_add_entry(vm, vm->common_entry, entry);
    entry = vm_define_native(vm, "tan", "tan");
    if (entry) vm_table_add_entry(vm, vm->common_entry, entry);
    entry = vm_define_native(vm, "asin", "asin");
    if (entry) vm_table_add_entry(vm, vm->common_entry, entry);
    entry = vm_define_native(vm, "acos", "acos");
    if (entry) vm_table_add_entry(vm, vm->common_entry, entry);
    entry = vm_define_native(vm, "atan", "atan");
    if (entry) vm_table_add_entry(vm, vm->common_entry, entry);
    entry = vm_define_native(vm, "log", "log");
    if (entry) vm_table_add_entry(vm, vm->common_entry, entry);
    entry = vm_define_native(vm, "exp", "exp");
    if (entry) vm_table_add_entry(vm, vm->common_entry, entry);
    entry = vm_define_native(vm, "slice", "slice");
    if (entry) vm_table_add_entry(vm, vm->common_entry, entry);
    entry = vm_define_native(vm, "substr", "substr");
    if (entry) vm_table_add_entry(vm, vm->common_entry, entry);
    entry = vm_define_native(vm, "split", "split");
    if (entry) vm_table_add_entry(vm, vm->common_entry, entry);
    entry = vm_define_native(vm, "join", "join");
    if (entry) vm_table_add_entry(vm, vm->common_entry, entry);
    entry = vm_define_native(vm, "upper", "upper");
    if (entry) vm_table_add_entry(vm, vm->common_entry, entry);
    entry = vm_define_native(vm, "lower", "lower");
    if (entry) vm_table_add_entry(vm, vm->common_entry, entry);
    entry = vm_define_native(vm, "trim", "trim");
    if (entry) vm_table_add_entry(vm, vm->common_entry, entry);
    entry = vm_define_native(vm, "startsWith", "startsWith");
    if (entry) vm_table_add_entry(vm, vm->common_entry, entry);
    entry = vm_define_native(vm, "endsWith", "endsWith");
    if (entry) vm_table_add_entry(vm, vm->common_entry, entry);
    entry = vm_define_native(vm, "replace", "replace");
    if (entry) vm_table_add_entry(vm, vm->common_entry, entry);
    entry = vm_define_native(vm, "replaceAll", "replaceAll");
    if (entry) vm_table_add_entry(vm, vm->common_entry, entry);
    entry = vm_define_native(vm, "papagaio", "papagaio");
    if (entry) vm_table_add_entry(vm, vm->common_entry, entry);
    entry = vm_define_native(vm, "keys", "keys");
    if (entry) vm_table_add_entry(vm, vm->common_entry, entry);
    entry = vm_define_native(vm, "values", "values");
    if (entry) vm_table_add_entry(vm, vm->common_entry, entry);
    entry = vm_define_native(vm, "has", "has");
    if (entry) vm_table_add_entry(vm, vm->common_entry, entry);
    entry = vm_define_native(vm, "delete", "delete");
    if (entry) vm_table_add_entry(vm, vm->common_entry, entry);
    entry = vm_define_native(vm, "push", "push");
    if (entry) vm_table_add_entry(vm, vm->common_entry, entry);
    entry = vm_define_native(vm, "pop", "pop");
    if (entry) vm_table_add_entry(vm, vm->common_entry, entry);
    entry = vm_define_native(vm, "shift", "shift");
    if (entry) vm_table_add_entry(vm, vm->common_entry, entry);
    entry = vm_define_native(vm, "unshift", "unshift");
    if (entry) vm_table_add_entry(vm, vm->common_entry, entry);
    entry = vm_define_native(vm, "insert", "insert");
    if (entry) vm_table_add_entry(vm, vm->common_entry, entry);
    entry = vm_define_native(vm, "remove", "remove");
    if (entry) vm_table_add_entry(vm, vm->common_entry, entry);

    #ifdef DISTURB_ENABLE_FFI
    ObjEntry *ffi_key = vm_make_key(vm, "ffi");
    List *ffi_obj = vm_alloc_list(vm, DISTURB_T_TABLE, ffi_key, 1);
    ObjEntry *ffi_entry = vm_reg_alloc(vm, ffi_obj);
    vm_global_add(vm, ffi_entry);
    ObjEntry *load_entry = vm_make_native_entry(vm, "load", "ffiLoad");
    if (load_entry) {
        ffi_obj = disturb_table_add(ffi_obj, load_entry);
        ffi_entry->obj = ffi_obj;
    }
    #endif
}

void vm_free(VM *vm)
{
    for (Int i = 0; i < vm->reg_count; i++) {
        ObjEntry *entry = vm->reg[i];
        if (!entry) continue;
        if (entry->in_use && entry->obj) {
            List *obj = entry->obj;
            disturb_obj_free(obj);
            for (Int j = 0; j < vm->reg_count; j++) {
                ObjEntry *other = vm->reg[j];
                if (!other || other->obj != obj) continue;
                other->obj = NULL;
            }
        }
    }
    for (Int i = 0; i < vm->reg_count; i++) {
        ObjEntry *entry = vm->reg[i];
        if (!entry) continue;
        free(entry);
        vm->reg[i] = NULL;
    }
    while (vm->free_lists) {
        FreeNode *node = vm->free_lists;
        vm->free_lists = node->next;
        vm_free_list(node->obj);
        free(node);
    }
    while (vm->free_bytes) {
        FreeNode *node = vm->free_bytes;
        vm->free_bytes = node->next;
        vm_free_list(node->obj);
        free(node);
    }
    free(vm->reg);
}

typedef struct {
    ObjEntry *src;
    ObjEntry *dst;
} ClonePair;

static ObjEntry *vm_clone_key_entry(VM *vm, ObjEntry *key_entry)
{
    if (!key_entry) return NULL;
    if (!entry_is_string(key_entry)) return NULL;
    return vm_make_key_len(vm, disturb_bytes_data(key_entry->obj), disturb_bytes_len(key_entry->obj));
}

static ObjEntry *vm_clone_entry_internal(VM *vm, ObjEntry *src, ObjEntry *forced_key,
                                         ClonePair **pairs, size_t *count, size_t *cap)
{
    if (!src || !src->in_use) return NULL;

    if (!forced_key) {
        for (size_t i = 0; i < *count; i++) {
            if ((*pairs)[i].src == src) return (*pairs)[i].dst;
        }
    }

    ObjEntry *key_entry = forced_key ? forced_key : vm_clone_key_entry(vm, vm_entry_key(src));
    List *obj = src->obj;
    Int type = disturb_obj_type(obj);

    List *copy = NULL;
    ObjEntry *entry = NULL;

    switch (type) {
    case DISTURB_T_NULL:
        copy = vm_alloc_list(vm, DISTURB_T_NULL, key_entry, 0);
        break;
    case DISTURB_T_INT:
        copy = vm_alloc_bytes(vm, DISTURB_T_INT, key_entry, disturb_bytes_data(obj), disturb_bytes_len(obj));
        break;
    case DISTURB_T_FLOAT:
        copy = vm_alloc_bytes(vm, DISTURB_T_FLOAT, key_entry, disturb_bytes_data(obj), disturb_bytes_len(obj));
        break;
    case DISTURB_T_VIEW: {
        Int n = (Int)(obj->size - 2);
        copy = vm_alloc_list(vm, DISTURB_T_VIEW, key_entry, n);
        for (Int i = 2; i < obj->size; i++) {
            copy = disturb_push(copy, obj->data[i]);
        }
        break;
    }
    case DISTURB_T_TABLE: {
        Int n = (Int)(obj->size - 2);
        copy = vm_alloc_list(vm, DISTURB_T_TABLE, key_entry, n);
        break;
    }
    case DISTURB_T_NATIVE: {
        copy = vm_alloc_list(vm, DISTURB_T_NATIVE, key_entry, 1);
        NativeBox *src_box = obj->size >= 3 ? (NativeBox*)obj->data[2].p : NULL;
        NativeBox *box = (NativeBox*)malloc(sizeof(NativeBox));
        box->fn = src_box ? src_box->fn : NULL;
        box->data = src_box ? src_box->data : NULL;
        box->free_data = src_box ? src_box->free_data : NULL;
        box->clone_data = src_box ? src_box->clone_data : NULL;
        if (box->clone_data && box->data) {
            box->clone_data(box->data);
        }
        Value v;
        v.p = box;
        copy = disturb_push(copy, v);
        break;
    }
    case DISTURB_T_LAMBDA: {
        copy = vm_alloc_list(vm, DISTURB_T_LAMBDA, key_entry, 1);
        FunctionBox *src_box = obj->size >= 3 ? (FunctionBox*)obj->data[2].p : NULL;
        FunctionBox *box = (FunctionBox*)malloc(sizeof(FunctionBox));
        memset(box, 0, sizeof(*box));
        if (src_box) {
            box->len = src_box->len;
            box->argc = src_box->argc;
            box->has_vararg = src_box->has_vararg;
            if (box->len) {
                box->code = (unsigned char*)malloc(box->len);
                memcpy(box->code, src_box->code, box->len);
            }
            if (box->argc) {
                box->arg_names = (char**)calloc(box->argc, sizeof(char*));
                box->arg_lens = (size_t*)calloc(box->argc, sizeof(size_t));
                box->default_code = (unsigned char**)calloc(box->argc, sizeof(unsigned char*));
                box->default_lens = (size_t*)calloc(box->argc, sizeof(size_t));
                box->has_default = (uint8_t*)calloc(box->argc, sizeof(uint8_t));
                for (uint32_t i = 0; i < box->argc; i++) {
                    size_t len = src_box->arg_lens[i];
                    box->arg_lens[i] = len;
                    box->arg_names[i] = (char*)malloc(len + 1);
                    memcpy(box->arg_names[i], src_box->arg_names[i], len);
                    box->arg_names[i][len] = 0;
                    if (src_box->has_default && src_box->has_default[i]) {
                        box->has_default[i] = 1;
                        box->default_lens[i] = src_box->default_lens[i];
                        if (box->default_lens[i]) {
                            box->default_code[i] = (unsigned char*)malloc(box->default_lens[i]);
                            memcpy(box->default_code[i], src_box->default_code[i], box->default_lens[i]);
                        }
                    }
                }
            }
        }
        Value v;
        v.p = box;
        copy = disturb_push(copy, v);
        break;
    }
    default:
        copy = vm_alloc_list(vm, type, key_entry, (Int)(obj->size - 2));
        for (Int i = 2; i < obj->size; i++) {
            copy = disturb_push(copy, obj->data[i]);
        }
        break;
    }

    entry = vm_reg_alloc(vm, copy);
    if (entry) {
        entry->is_string = src->is_string;
        entry->explicit_string = src->explicit_string;
    }

    if (*count == *cap) {
        size_t new_cap = *cap == 0 ? 8 : (*cap * 2);
        ClonePair *next = (ClonePair*)realloc(*pairs, new_cap * sizeof(ClonePair));
        if (!next) return entry;
        *pairs = next;
        *cap = new_cap;
    }
    (*pairs)[*count].src = src;
    (*pairs)[*count].dst = entry;
    (*count)++;

    if (type == DISTURB_T_TABLE) {
        for (Int i = 2; i < obj->size; i++) {
            ObjEntry *child = (ObjEntry*)obj->data[i].p;
            ObjEntry *child_copy = vm_clone_entry_internal(vm, child, NULL, pairs, count, cap);
            if (child_copy) {
                copy = disturb_table_add(copy, child_copy);
            }
        }
    }

    return entry;
}

ObjEntry *vm_clone_entry_deep(VM *vm, ObjEntry *src, ObjEntry *forced_key)
{
    ClonePair *pairs = NULL;
    size_t count = 0;
    size_t cap = 0;
    ObjEntry *entry = vm_clone_entry_internal(vm, src, forced_key, &pairs, &count, &cap);
    free(pairs);
    return entry;
}

ObjEntry *vm_clone_entry_shallow(VM *vm, ObjEntry *src, ObjEntry *forced_key)
{
    if (!src || !src->in_use) return NULL;
    ObjEntry *entry = vm_reg_alloc(vm, src->obj);
    if (!entry) return NULL;
    entry->key = forced_key ? forced_key : vm_entry_key(src);
    entry->is_string = src->is_string;
    entry->explicit_string = src->explicit_string;
    return entry;
}

ObjEntry *vm_clone_entry_shallow_copy(VM *vm, ObjEntry *src, ObjEntry *forced_key)
{
    if (!src || !src->in_use) return NULL;
    ObjEntry *key_entry = forced_key ? forced_key : vm_entry_key(src);
    List *obj = src->obj;
    Int type = disturb_obj_type(obj);
    List *copy = NULL;

    switch (type) {
    case DISTURB_T_NULL:
        copy = vm_alloc_list(vm, DISTURB_T_NULL, key_entry, 0);
        break;
    case DISTURB_T_INT:
        copy = vm_alloc_bytes(vm, DISTURB_T_INT, key_entry, disturb_bytes_data(obj), disturb_bytes_len(obj));
        break;
    case DISTURB_T_FLOAT:
        copy = vm_alloc_bytes(vm, DISTURB_T_FLOAT, key_entry, disturb_bytes_data(obj), disturb_bytes_len(obj));
        break;
    case DISTURB_T_VIEW: {
        Int n = (Int)(obj->size - 2);
        copy = vm_alloc_list(vm, DISTURB_T_VIEW, key_entry, n);
        for (Int i = 2; i < obj->size; i++) {
            copy = disturb_push(copy, obj->data[i]);
        }
        break;
    }
    case DISTURB_T_TABLE: {
        Int n = (Int)(obj->size - 2);
        copy = vm_alloc_list(vm, DISTURB_T_TABLE, key_entry, n);
        for (Int i = 2; i < obj->size; i++) {
            Value v = obj->data[i];
            copy = disturb_push(copy, v);
        }
        break;
    }
    case DISTURB_T_NATIVE:
    case DISTURB_T_LAMBDA: {
        Int n = (Int)(obj->size - 2);
        copy = vm_alloc_list(vm, type, key_entry, n);
        for (Int i = 2; i < obj->size; i++) {
            copy = disturb_push(copy, obj->data[i]);
        }
        break;
    }
    default: {
        Int n = (Int)(obj->size - 2);
        copy = vm_alloc_list(vm, type, key_entry, n);
        for (Int i = 2; i < obj->size; i++) {
            copy = disturb_push(copy, obj->data[i]);
        }
        break;
    }
    }

    if (!copy) return NULL;
    ObjEntry *entry = vm_reg_alloc(vm, copy);
    if (!entry) return NULL;
    entry->key = key_entry;
    entry->is_string = src->is_string;
    entry->explicit_string = src->explicit_string;
    return entry;
}

ObjEntry *vm_define_bytes(VM *vm, const char *key, const char *value)
{
    ObjEntry *key_entry = NULL;
    if (key) {
        key_entry = vm_make_key(vm, key);
    }

    List *obj = vm_alloc_bytes(vm, DISTURB_T_INT, key_entry, value, strlen(value));
    ObjEntry *entry = vm_reg_alloc(vm, obj);
    if (entry) {
        entry->is_string = 1;
        entry->explicit_string = 0;
    }
    vm_global_add(vm, entry);
    return entry;
}

ObjEntry *vm_define_byte(VM *vm, const char *key, char **items, int count, int start)
{
    ObjEntry *key_entry = NULL;
    if (key) {
        key_entry = vm_make_key(vm, key);
    }

    size_t len = (size_t)(count - start);
    List *obj = vm_alloc_bytes(vm, DISTURB_T_INT, key_entry, NULL, len);
    for (int i = start; i < count; i++) {
        char *end = NULL;
        long value = strtol(items[i], &end, 10);
        if (!end || *end != 0 || value < 0 || value > 255) {
            fprintf(stderr, "byte expects uint8 values: %s\n", items[i]);
            value = 0;
        }
        disturb_bytes_data(obj)[i - start] = (char)(unsigned char)value;
    }
    ObjEntry *entry = vm_reg_alloc(vm, obj);
    vm_global_add(vm, entry);
    return entry;
}

ObjEntry *vm_define_number(VM *vm, const char *key, char **items, int count, int start)
{
    ObjEntry *key_entry = NULL;
    if (key) {
        key_entry = vm_make_key(vm, key);
    }

    Int n = (Int)(count - start);
    int is_float = 0;
    for (int i = start; i < count; i++) {
        char *end = NULL;
        double v = strtod(items[i], &end);
        if (!end || *end != 0) continue;
        if (v != (double)(Int)v) {
            is_float = 1;
            break;
        }
    }

    size_t elem_size = is_float ? sizeof(Float) : sizeof(Int);
    List *obj = vm_alloc_bytes(vm, is_float ? DISTURB_T_FLOAT : DISTURB_T_INT, key_entry, NULL, (size_t)n * elem_size);
    for (Int i = 0; i < n; i++) {
        double v = strtod(items[start + i], NULL);
        if (is_float) {
            Float fv = (Float)v;
            vm_write_float_at(obj, i, fv);
        } else {
            Int iv = (Int)v;
            vm_write_int_at(obj, i, iv);
        }
    }

    ObjEntry *entry = vm_reg_alloc(vm, obj);
    vm_global_add(vm, entry);
    return entry;
}

ObjEntry *vm_define_table(VM *vm, const char *key, char **items, int count, int start)
{
    ObjEntry *key_entry = NULL;
    if (key) {
        key_entry = vm_make_key(vm, key);
    }

    Int n = (Int)(count - start);
    List *obj = vm_alloc_list(vm, DISTURB_T_TABLE, key_entry, n);
    for (int i = start; i < count; i++) {
        ObjEntry *child = vm_find_by_key(vm, items[i]);
        if (!child) {
            fprintf(stderr, "unknown key: %s\n", items[i]);
            continue;
        }
        obj = disturb_table_add(obj, child);
    }

    ObjEntry *entry = vm_reg_alloc(vm, obj);
    vm_global_add(vm, entry);
    return entry;
}

ObjEntry *vm_define_native(VM *vm, const char *key, const char *fn_name)
{
    ObjEntry *key_entry = NULL;
    if (key) {
        key_entry = vm_make_key(vm, key);
    }

    NativeFn fn = vm_lookup_native(fn_name);
    if (!fn) {
        fprintf(stderr, "unknown native: %s\n", fn_name);
        return NULL;
    }

    List *obj = vm_alloc_list(vm, DISTURB_T_NATIVE, key_entry, 1);
    NativeBox *box = (NativeBox*)malloc(sizeof(NativeBox));
    box->fn = fn;
    box->data = NULL;
    box->free_data = NULL;
    box->clone_data = NULL;
    Value v;
    v.p = box;
    obj = disturb_push(obj, v);
    ObjEntry *entry = vm_reg_alloc(vm, obj);
    vm_global_add(vm, entry);
    return entry;
}

void vm_push_stack(VM *vm, const char *key)
{
    ObjEntry *entry = vm_find_by_key(vm, key);
    if (!entry) {
        fprintf(stderr, "unknown key: %s\n", key);
        return;
    }
    vm_table_add_entry(vm, vm->stack_entry, entry);
}

void vm_pop_stack(VM *vm)
{
    List *stack = vm->stack_entry->obj;
    if (stack->size <= 2) {
        fprintf(stderr, "stack empty\n");
        return;
    }
    disturb_pop(stack);
}

void vm_call_native(VM *vm, const char *key)
{
    ObjEntry *entry = vm_find_by_key(vm, key);
    if (!entry) {
        fprintf(stderr, "unknown key: %s\n", key);
        return;
    }
    if (disturb_obj_type(entry->obj) != DISTURB_T_NATIVE) {
        fprintf(stderr, "not a native: %s\n", key);
        return;
    }
    if (entry->obj->size < 3) {
        fprintf(stderr, "native missing function: %s\n", key);
        return;
    }
    NativeBox *box = (NativeBox*)entry->obj->data[2].p;
    NativeFn fn = box ? box->fn : NULL;
    if (!fn) {
        fprintf(stderr, "native null function: %s\n", key);
        return;
    }
    fn(vm, vm->stack_entry->obj, vm->global_entry->obj);
}

void vm_dump_global(VM *vm)
{
    List *global = vm->global_entry->obj;
    for (Int i = 2; i < global->size; i++) {
        ObjEntry *entry = (ObjEntry*)global->data[i].p;
        print_entry(stdout, vm, entry);
        fputs("\n", stdout);
    }
}

static int bc_read_u8(const unsigned char *data, size_t len, size_t *pc, uint8_t *out)
{
    if (*pc + 1 > len) return 0;
    *out = data[(*pc)++];
    return 1;
}

static int bc_read_u32(const unsigned char *data, size_t len, size_t *pc, uint32_t *out)
{
    if (*pc + 4 > len) return 0;
    uint32_t v = 0;
    v |= (uint32_t)data[(*pc)++];
    v |= (uint32_t)data[(*pc)++] << 8;
    v |= (uint32_t)data[(*pc)++] << 16;
    v |= (uint32_t)data[(*pc)++] << 24;
    *out = v;
    return 1;
}

static int bc_read_f64(const unsigned char *data, size_t len, size_t *pc, double *out)
{
    if (*pc + 8 > len) return 0;
    union {
        double d;
        unsigned char b[8];
    } u;
    for (int i = 0; i < 8; i++) {
        u.b[i] = data[(*pc)++];
    }
    *out = u.d;
    return 1;
}

static int bc_read_i64(const unsigned char *data, size_t len, size_t *pc, int64_t *out)
{
    if (*pc + 8 > len) return 0;
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) {
        v |= (uint64_t)data[(*pc)++] << (i * 8);
    }
    *out = (int64_t)v;
    return 1;
}

static int bc_read_string(const unsigned char *data, size_t len, size_t *pc, unsigned char **out, size_t *out_len)
{
    uint32_t slen = 0;
    if (!bc_read_u32(data, len, pc, &slen)) return 0;
    if (*pc + slen > len) return 0;
    unsigned char *buf = (unsigned char*)malloc(slen + 1);
    if (!buf) return 0;
    memcpy(buf, data + *pc, slen);
    buf[slen] = 0;
    *pc += slen;
    *out = buf;
    *out_len = slen;
    return 1;
}

static int ast_set_kv(VM *vm, ObjEntry *obj, const char *key, ObjEntry *value)
{
    if (!vm || !obj || !value) return 0;
    return vm_object_set_by_key_len(vm, &obj->obj, key, strlen(key), value, 0);
}

static ObjEntry *ast_make_op(VM *vm, const char *op_name)
{
    ObjEntry *node = vm_make_table_value(vm, 4);
    if (!node) return NULL;
    ObjEntry *op_val = vm_make_bytes_value(vm, op_name, strlen(op_name));
    ast_set_kv(vm, node, "op", op_val);
    return node;
}

ObjEntry *vm_bytecode_to_ast(VM *vm, const unsigned char *data, size_t len)
{
    if (!vm || (!data && len > 0)) return NULL;

    ObjEntry *root = vm_make_table_value(vm, 4);
    ObjEntry *ops = vm_make_table_value(vm, 16);
    if (!root || !ops) return NULL;

    size_t pc = 0;
    while (pc < len) {
        uint8_t op = 0;
        if (!bc_read_u8(data, len, &pc, &op)) {
            fprintf(stderr, "bytecodeToAst: truncated opcode at pc %zu\n", pc);
            return NULL;
        }
        const char *op_name = bc_opcode_name(op);
        if (strcmp(op_name, "UNKNOWN") == 0) {
            fprintf(stderr, "bytecodeToAst: unknown opcode %u at pc %zu\n", (unsigned)op, pc - 1);
            return NULL;
        }
        ObjEntry *node = ast_make_op(vm, op_name);
        if (!node) return NULL;

        switch (op) {
        case BC_PUSH_INT: {
            int64_t v = 0;
            if (!bc_read_i64(data, len, &pc, &v)) {
                fprintf(stderr, "bytecodeToAst: truncated PUSH_INT at pc %zu\n", pc);
                return NULL;
            }
            ast_set_kv(vm, node, "value", vm_make_int_value(vm, (Int)v));
            break;
        }
        case BC_PUSH_FLOAT: {
            double v = 0.0;
            if (!bc_read_f64(data, len, &pc, &v)) {
                fprintf(stderr, "bytecodeToAst: truncated PUSH_FLOAT at pc %zu\n", pc);
                return NULL;
            }
            ast_set_kv(vm, node, "value", vm_make_float_value(vm, (Float)v));
            break;
        }
        case BC_PUSH_CHAR:
        case BC_PUSH_STRING:
        case BC_PUSH_CHAR_RAW:
        case BC_PUSH_STRING_RAW: {
            unsigned char *buf = NULL;
            size_t slen = 0;
            if (!bc_read_string(data, len, &pc, &buf, &slen)) {
                fprintf(stderr, "bytecodeToAst: truncated string at pc %zu\n", pc);
                return NULL;
            }
            ast_set_kv(vm, node, "value", vm_make_bytes_value(vm, (const char*)buf, slen));
            free(buf);
            break;
        }
        case BC_BUILD_INT:
        case BC_BUILD_FLOAT:
        case BC_BUILD_OBJECT: {
            uint32_t count = 0;
            if (!bc_read_u32(data, len, &pc, &count)) {
                fprintf(stderr, "bytecodeToAst: truncated BUILD_* at pc %zu\n", pc);
                return NULL;
            }
            ast_set_kv(vm, node, "count", vm_make_int_value(vm, (Int)count));
            break;
        }
        case BC_BUILD_INT_LIT:
        case BC_BUILD_FLOAT_LIT: {
            uint32_t count = 0;
            if (!bc_read_u32(data, len, &pc, &count)) {
                fprintf(stderr, "bytecodeToAst: truncated BUILD_*_LIT at pc %zu\n", pc);
                return NULL;
            }
            ObjEntry *values = vm_make_table_value(vm, (Int)count);
            for (uint32_t i = 0; i < count; i++) {
                if (op == BC_BUILD_INT_LIT) {
                    int64_t v = 0;
                    if (!bc_read_i64(data, len, &pc, &v)) {
                        fprintf(stderr, "bytecodeToAst: truncated BUILD_INT_LIT value at pc %zu\n", pc);
                        return NULL;
                    }
                    values->obj = vm_update_shared_obj(vm, values->obj,
                                                       disturb_table_add(values->obj, vm_make_int_value(vm, (Int)v)));
                } else {
                    double v = 0.0;
                    if (!bc_read_f64(data, len, &pc, &v)) {
                        fprintf(stderr, "bytecodeToAst: truncated BUILD_FLOAT_LIT value at pc %zu\n", pc);
                        return NULL;
                    }
                    values->obj = vm_update_shared_obj(vm, values->obj,
                                                       disturb_table_add(values->obj, vm_make_float_value(vm, (Float)v)));
                }
            }
            ast_set_kv(vm, node, "count", vm_make_int_value(vm, (Int)count));
            ast_set_kv(vm, node, "values", values);
            break;
        }
        case BC_BUILD_FUNCTION: {
            uint32_t argc = 0;
            uint32_t vararg = 0;
            uint32_t code_len = 0;
            if (!bc_read_u32(data, len, &pc, &argc) ||
                !bc_read_u32(data, len, &pc, &vararg) ||
                !bc_read_u32(data, len, &pc, &code_len)) {
                fprintf(stderr, "bytecodeToAst: truncated BUILD_FUNCTION at pc %zu\n", pc);
                return NULL;
            }
            if (pc + code_len > len) {
                fprintf(stderr, "bytecodeToAst: BUILD_FUNCTION code out of bounds at pc %zu\n", pc);
                return NULL;
            }
            ObjEntry *code = vm_make_byte_value(vm, (const char*)(data + pc), code_len);
            pc += code_len;
            ObjEntry *args = vm_make_table_value(vm, (Int)argc);

            for (uint32_t i = 0; i < argc; i++) {
                unsigned char *name = NULL;
                size_t name_len = 0;
                if (!bc_read_string(data, len, &pc, &name, &name_len)) {
                    fprintf(stderr, "bytecodeToAst: truncated BUILD_FUNCTION arg name at pc %zu\n", pc);
                    return NULL;
                }
                uint32_t def_len = 0;
                if (!bc_read_u32(data, len, &pc, &def_len)) {
                    free(name);
                    fprintf(stderr, "bytecodeToAst: truncated BUILD_FUNCTION default length at pc %zu\n", pc);
                    return NULL;
                }
                if (pc + def_len > len) {
                    free(name);
                    fprintf(stderr, "bytecodeToAst: BUILD_FUNCTION default out of bounds at pc %zu\n", pc);
                    return NULL;
                }
                ObjEntry *arg = vm_make_table_value(vm, 2);
                ast_set_kv(vm, arg, "name", vm_make_bytes_value(vm, (const char*)name, name_len));
                if (def_len > 0) {
                    ObjEntry *def = vm_make_byte_value(vm, (const char*)(data + pc), def_len);
                    ast_set_kv(vm, arg, "default", def);
                } else {
                    ast_set_kv(vm, arg, "default", vm->null_entry);
                }
                pc += def_len;
                args->obj = vm_update_shared_obj(vm, args->obj,
                                                 disturb_table_add(args->obj, arg));
                free(name);
            }

            ast_set_kv(vm, node, "argc", vm_make_int_value(vm, (Int)argc));
            ast_set_kv(vm, node, "vararg", vm_make_int_value(vm, (Int)vararg));
            ast_set_kv(vm, node, "code", code);
            ast_set_kv(vm, node, "args", args);
            break;
        }
        case BC_LOAD_GLOBAL:
        case BC_STORE_GLOBAL:
        case BC_CALL:
        case BC_CALL_EX: {
            unsigned char *name = NULL;
            size_t name_len = 0;
            if (!bc_read_string(data, len, &pc, &name, &name_len)) {
                fprintf(stderr, "bytecodeToAst: truncated name at pc %zu\n", pc);
                return NULL;
            }
            ast_set_kv(vm, node, "name", vm_make_bytes_value(vm, (const char*)name, name_len));
            free(name);
            if (op == BC_CALL || op == BC_CALL_EX) {
                uint32_t argc = 0;
                if (!bc_read_u32(data, len, &pc, &argc)) {
                    fprintf(stderr, "bytecodeToAst: truncated CALL argc at pc %zu\n", pc);
                    return NULL;
                }
                ast_set_kv(vm, node, "argc", vm_make_int_value(vm, (Int)argc));
                if (op == BC_CALL_EX) {
                    uint32_t override_len = 0;
                    if (!bc_read_u32(data, len, &pc, &override_len)) {
                        fprintf(stderr, "bytecodeToAst: truncated CALL_EX override at pc %zu\n", pc);
                        return NULL;
                    }
                    ast_set_kv(vm, node, "override", vm_make_int_value(vm, (Int)override_len));
                }
            }
            break;
        }
        case BC_STRICT:
            break;
        case BC_JMP:
        case BC_JMP_IF_FALSE: {
            uint32_t target = 0;
            if (!bc_read_u32(data, len, &pc, &target)) {
                fprintf(stderr, "bytecodeToAst: truncated jump at pc %zu\n", pc);
                return NULL;
            }
            ast_set_kv(vm, node, "target", vm_make_int_value(vm, (Int)target));
            break;
        }
        case BC_INDEX:
        case BC_STORE_INDEX:
        case BC_LOAD_ROOT:
        case BC_LOAD_THIS:
        case BC_SET_THIS:
        case BC_RETURN:
        case BC_POP:
        case BC_DUP:
        case BC_GC:
        case BC_DUMP:
        case BC_ADD:
        case BC_SUB:
        case BC_MUL:
        case BC_DIV:
        case BC_MOD:
        case BC_NEG:
        case BC_NOT:
        case BC_EQ:
        case BC_NEQ:
        case BC_LT:
        case BC_LTE:
        case BC_GT:
        case BC_GTE:
        case BC_AND:
        case BC_OR:
            break;
        default:
            fprintf(stderr, "bytecodeToAst: unsupported opcode %u at pc %zu\n", (unsigned)op, pc - 1);
            return NULL;
        }

        ops->obj = vm_update_shared_obj(vm, ops->obj,
                                        disturb_table_add(ops->obj, node));
    }

    ast_set_kv(vm, root, "type", vm_make_bytes_value(vm, "bytecode", 8));
    ast_set_kv(vm, root, "ops", ops);
    return root;
}

static ObjEntry *vm_stack_pop_entry(VM *vm, const char *op, size_t pc)
{
    List *stack = vm->stack_entry->obj;
    if (stack->size <= 2) {
        fprintf(stderr, "bytecode error at pc %zu: %s stack underflow\n", pc, op);
        return NULL;
    }
    return (ObjEntry*)disturb_pop(stack).p;
}

static int vm_key_is(ObjEntry *index, const char *name)
{
    if (!index || !entry_is_string(index)) return 0;
    return disturb_bytes_eq_bytes(index->obj, name, strlen(name));
}

static ObjEntry *vm_make_type_name(VM *vm, ObjEntry *target)
{
    const char *name = "unknown";
    if (!target) {
        name = "null";
    } else {
        Int type = disturb_obj_type(target->obj);
        if (type == DISTURB_T_INT && entry_is_string(target)) {
            size_t len = disturb_bytes_len(target->obj);
            if (len == 1) {
                name = "char";
            } else {
                name = "string";
            }
        } else {
            name = disturb_type_name(type);
        }
    }
    ObjEntry *entry = vm_reg_alloc(vm, vm_alloc_bytes(vm, DISTURB_T_INT, NULL, name, strlen(name)));
    if (entry) {
        entry->is_string = 1;
        entry->explicit_string = 1;
    }
    return entry;
}

ObjEntry *vm_make_int_value(VM *vm, Int value)
{
    List *obj = vm_alloc_bytes(vm, DISTURB_T_INT, NULL, NULL, sizeof(Int));
    vm_set_int_single(obj, value);
    return vm_reg_alloc(vm, obj);
}

ObjEntry *vm_make_float_value(VM *vm, Float value)
{
    List *obj = vm_alloc_bytes(vm, DISTURB_T_FLOAT, NULL, NULL, sizeof(Float));
    vm_set_float_single(obj, value);
    return vm_reg_alloc(vm, obj);
}

ObjEntry *vm_make_int_list(VM *vm, Int count)
{
    if (count < 0) return NULL;
    List *obj = vm_alloc_bytes(vm, DISTURB_T_INT, NULL, NULL, (size_t)count * sizeof(Int));
    return vm_reg_alloc(vm, obj);
}

ObjEntry *vm_make_float_list(VM *vm, Int count)
{
    if (count < 0) return NULL;
    List *obj = vm_alloc_bytes(vm, DISTURB_T_FLOAT, NULL, NULL, (size_t)count * sizeof(Float));
    return vm_reg_alloc(vm, obj);
}

ObjEntry *vm_make_bytes_value(VM *vm, const char *s, size_t len)
{
    List *obj = vm_alloc_bytes(vm, DISTURB_T_INT, NULL, s, len);
    ObjEntry *entry = vm_reg_alloc(vm, obj);
    if (entry) {
        entry->is_string = 1;
        entry->explicit_string = 0;
    }
    return entry;
}

ObjEntry *vm_make_byte_value(VM *vm, const char *s, size_t len)
{
    List *obj = vm_alloc_bytes(vm, DISTURB_T_INT, NULL, s, len);
    ObjEntry *entry = vm_reg_alloc(vm, obj);
    if (entry) {
        entry->is_string = 1;
        entry->explicit_string = 0;
    }
    return entry;
}

ObjEntry *vm_make_table_value(VM *vm, Int reserve)
{
    List *obj = vm_alloc_list(vm, DISTURB_T_TABLE, NULL, reserve);
    return vm_reg_alloc(vm, obj);
}

static ObjEntry *vm_make_view(VM *vm, ObjEntry *base, ViewType view)
{
    if (!base || !base->in_use) return NULL;
    List *obj = vm_alloc_list(vm, DISTURB_T_VIEW, NULL, 2);
    Value v;
    v.p = base;
    obj = disturb_push(obj, v);
    v.i = (Int)view;
    obj = disturb_push(obj, v);
    return vm_reg_alloc(vm, obj);
}

static List *vm_clone_obj_shallow_copy(VM *vm, ObjEntry *src, ObjEntry *key_entry,
                                       int *out_is_string, int *out_explicit_string)
{
    if (!src || !src->in_use) return NULL;
    List *obj = src->obj;
    Int type = disturb_obj_type(obj);
    List *copy = NULL;

    switch (type) {
    case DISTURB_T_NULL:
        copy = vm_alloc_list(vm, DISTURB_T_NULL, key_entry, 0);
        break;
    case DISTURB_T_INT:
        copy = vm_alloc_bytes(vm, DISTURB_T_INT, key_entry, disturb_bytes_data(obj), disturb_bytes_len(obj));
        break;
    case DISTURB_T_FLOAT:
        copy = vm_alloc_bytes(vm, DISTURB_T_FLOAT, key_entry, disturb_bytes_data(obj), disturb_bytes_len(obj));
        break;
    case DISTURB_T_VIEW: {
        Int n = (Int)(obj->size - 2);
        copy = vm_alloc_list(vm, DISTURB_T_VIEW, key_entry, n);
        for (Int i = 2; i < obj->size; i++) {
            copy = disturb_push(copy, obj->data[i]);
        }
        break;
    }
    case DISTURB_T_TABLE:
    case DISTURB_T_NATIVE:
    case DISTURB_T_LAMBDA:
    default: {
        Int n = (Int)(obj->size - 2);
        copy = vm_alloc_list(vm, type, key_entry, n);
        for (Int i = 2; i < obj->size; i++) {
            copy = disturb_push(copy, obj->data[i]);
        }
        break;
    }
    }

    if (out_is_string) *out_is_string = src->is_string;
    if (out_explicit_string) *out_explicit_string = src->explicit_string;
    return copy;
}

static Int vm_meta_size_entry(const ObjEntry *entry)
{
    if (!entry || !entry->in_use) return 0;
    List *obj = entry->obj;
    Int type = disturb_obj_type(obj);
    if (type == DISTURB_T_NULL) return 0;
    if (type == DISTURB_T_TABLE) {
        if (obj->size < 2) return 0;
        return obj->size - 2;
    }
    if (type == DISTURB_T_INT) {
        if (entry_is_string(entry)) return (Int)disturb_bytes_len(obj);
        return vm_bytes_to_count(disturb_bytes_len(obj), DISTURB_T_INT);
    }
    if (type == DISTURB_T_FLOAT) {
        return vm_bytes_to_count(disturb_bytes_len(obj), DISTURB_T_FLOAT);
    }
    if (obj->size < 2) return 0;
    return obj->size - 2;
}

static Int vm_meta_capacity_entry(const ObjEntry *entry)
{
    if (!entry || !entry->in_use) return 0;
    List *obj = entry->obj;
    Int type = disturb_obj_type(obj);
    if (type == DISTURB_T_NULL) return 0;
    if (type == DISTURB_T_TABLE) {
        if (obj->capacity < 2) return 0;
        return obj->capacity - 2;
    }
    if (type == DISTURB_T_INT) {
        size_t bytes = obj->capacity >= 2 ? (size_t)obj->capacity - 2 : 0;
        if (entry_is_string(entry)) return (Int)bytes;
        return vm_bytes_to_count(bytes, DISTURB_T_INT);
    }
    if (type == DISTURB_T_FLOAT) {
        size_t bytes = obj->capacity >= 2 ? (size_t)obj->capacity - 2 : 0;
        return vm_bytes_to_count(bytes, DISTURB_T_FLOAT);
    }
    if (obj->capacity < 2) return 0;
    return obj->capacity - 2;
}

static ObjEntry *vm_meta_get(VM *vm, ObjEntry *target, ObjEntry *index, size_t pc)
{
    (void)pc;
    if (!target || !index || !entry_is_string(index)) return NULL;
    if (vm_key_is(index, "name")) {
        ObjEntry *key = vm_entry_key(target);
        return key ? key : vm->null_entry;
    }
    if (vm_key_is(index, "type")) {
        return vm_make_type_name(vm, target);
    }
    if (vm_key_is(index, "size")) {
        return vm_make_int_value(vm, vm_meta_size_entry(target));
    }
    if (vm_key_is(index, "capacity")) {
        return vm_make_int_value(vm, vm_meta_capacity_entry(target));
    }
    if (vm_key_is(index, "value")) {
        ObjEntry *out = vm_clone_entry_shallow_copy(vm, target, NULL);
        if (!out) return NULL;
        out->key = NULL;
        return out;
    }
    if (vm_key_is(index, "string")) {
        if (disturb_obj_type(target->obj) != DISTURB_T_INT) return NULL;
        ObjEntry *out = vm_reg_alloc(vm, target->obj);
        if (!out) return NULL;
        out->key = vm_entry_key(target);
        out->is_string = 1;
        out->explicit_string = 1;
        return out;
    }
    {
        const char *name = disturb_bytes_data(index->obj);
        size_t len = disturb_bytes_len(index->obj);
        ViewType view;
        if (vm_view_from_name(name, len, &view)) {
            Int type = disturb_obj_type(target->obj);
            if (type == DISTURB_T_INT && !vm_view_is_float(view)) {
                return vm_make_view(vm, target, view);
            }
            if (type == DISTURB_T_FLOAT && vm_view_is_float(view)) {
                return vm_make_view(vm, target, view);
            }
        }
    }
    return NULL;
}

static List *vm_resize_bytes(List *obj, Int new_size)
{
    if (new_size < 0) return 0;
    size_t len = (size_t)new_size;
    if (len > disturb_bytes_max() - 2) return NULL;
    size_t bytes = sizeof(List) + 2 * sizeof(Value) + len;
    obj = (List*)realloc(obj, bytes);
    if (!obj) return NULL;
    size_t old_len = disturb_bytes_len(obj);
    if (len > old_len) {
        memset(disturb_bytes_data(obj) + old_len, 0, len - old_len);
    }
    obj->size = (UHalf)(len + 2);
    obj->capacity = (UHalf)(len + 2);
    return obj;
}

static List *vm_resize_bytes_capacity(List *obj, Int new_cap)
{
    if (new_cap < 0) return NULL;
    size_t cap = (size_t)new_cap;
    if (cap > disturb_bytes_max() - 2) return NULL;
    size_t bytes = sizeof(List) + 2 * sizeof(Value) + cap;
    size_t old_len = disturb_bytes_len(obj);
    List *resized = (List*)realloc(obj, bytes);
    if (!resized && cap > 0) return NULL;
    if (resized) obj = resized;
    obj->capacity = (UHalf)(cap + 2);
    if (old_len > cap) {
        obj->size = (UHalf)(cap + 2);
    }
    return obj;
}

static List *vm_resize_list(List *obj, Int new_size, ObjEntry *null_entry)
{
    if (new_size < 0) return NULL;
    size_t payload = (size_t)new_size;
    size_t new_cap = payload + 2;
    size_t bytes = sizeof(List) + new_cap * sizeof(Value);
    obj = (List*)realloc(obj, bytes);
    if (!obj && new_cap > 0) return NULL;
    if ((size_t)obj->capacity < new_cap) {
        memset(obj->data + obj->capacity, 0, (new_cap - obj->capacity) * sizeof(Value));
    }
    obj->capacity = (UHalf)new_cap;
    size_t new_total = payload + 2;
    if (obj->size < (UHalf)new_total) {
        for (size_t i = obj->size; i < new_total; i++) {
            Value v;
            if (disturb_obj_type(obj) == DISTURB_T_TABLE) {
                v.p = null_entry;
            } else {
                v.f = 0;
            }
            obj->data[i] = v;
        }
    }
    obj->size = (UHalf)new_total;
    return obj;
}

static int vm_set_size_bytes(VM *vm, ObjEntry *target, Int new_size)
{
    if (new_size < 0) return 0;
    if (!target || !target->obj) return 0;
    List *obj = target->obj;
    List *old_obj = obj;
    size_t cap = obj->capacity >= 2 ? (size_t)obj->capacity - 2 : 0;
    size_t old_len = disturb_bytes_len(obj);
    size_t len = (size_t)new_size;
    if (len <= cap) {
        if (len > old_len) {
            memset(disturb_bytes_data(obj) + old_len, 0, len - old_len);
        }
        obj->size = (UHalf)(len + 2);
        return 1;
    }
    obj = vm_resize_bytes(obj, new_size);
    if (!obj) return 0;
    target->obj = vm_update_shared_obj(vm, old_obj, obj);
    return 1;
}

static int vm_set_size_list(VM *vm, ObjEntry *target, Int new_size, ObjEntry *null_entry)
{
    if (new_size < 0) return 0;
    if (!target || !target->obj) return 0;
    List *obj = target->obj;
    List *old_obj = obj;
    size_t cap = obj->capacity >= 2 ? (size_t)obj->capacity - 2 : 0;
    size_t old_size = obj->size >= 2 ? (size_t)obj->size - 2 : 0;
    size_t len = (size_t)new_size;
    if (len <= cap) {
        size_t new_total = len + 2;
        if (len > old_size) {
            for (size_t i = old_size + 2; i < new_total; i++) {
                Value v;
                if (disturb_obj_type(obj) == DISTURB_T_TABLE) {
                    v.p = null_entry;
                } else {
                    v.f = 0;
                }
                obj->data[i] = v;
            }
        }
        obj->size = (UHalf)new_total;
        return 1;
    }
    obj = vm_resize_list(obj, new_size, null_entry);
    if (!obj) return 0;
    target->obj = vm_update_shared_obj(vm, old_obj, obj);
    return 1;
}
static void vm_stack_push_entry(VM *vm, ObjEntry *entry)
{
    if (!entry) return;
    vm_table_add_entry(vm, vm->stack_entry, entry);
}

static void vm_stack_remove_range(List *stack, Int start, Int count)
{
    if (!stack || count <= 0) return;
    if (start < 2) start = 2;
    Int end = start + count;
    if (end > stack->size) end = stack->size;
    Int move = stack->size - end;
    if (move > 0) {
        memmove(&stack->data[start], &stack->data[end], (size_t)move * sizeof(Value));
    }
    stack->size -= (UHalf)(end - start);
}

static ObjEntry *vm_stack_arg(List *stack, uint32_t argc, uint32_t idx)
{
    if (!stack || idx >= argc) return NULL;
    Int base = stack->size - (Int)argc;
    if (base < 2) return NULL;
    Int pos = base + (Int)idx;
    if (pos < 2 || pos >= stack->size) return NULL;
    return (ObjEntry*)stack->data[pos].p;
}

static void vm_set_argc(VM *vm, uint32_t argc)
{
    if (!vm || !vm->argc_entry) return;
    vm_set_int_single(vm->argc_entry->obj, (Int)argc);
}

static ObjEntry *vm_eval_default(VM *vm, List *stack, unsigned char *code, size_t len)
{
    if (!vm || !stack) return NULL;
    Int stack_before = stack->size;
    if (!vm_exec_bytecode(vm, code, len)) return NULL;
    ObjEntry *val = NULL;
    if (stack->size > stack_before) {
        val = (ObjEntry*)stack->data[stack->size - 1].p;
    }
    if (stack->size > stack_before) {
        vm_stack_remove_range(stack, stack_before, stack->size - stack_before);
    }
    return val ? val : (vm ? vm->null_entry : NULL);
}

static int vm_entry_on_stack(List *stack, ObjEntry *entry)
{
    if (!stack || !entry) return 0;
    for (Int i = 2; i < stack->size; i++) {
        if ((ObjEntry*)stack->data[i].p == entry) return 1;
    }
    return 0;
}

static void vm_release_local_scope(VM *vm, ObjEntry *local, List *stack)
{
    if (!vm || !local || !local->obj) return;
    List *obj = local->obj;
    for (Int i = 2; i < obj->size; i++) {
        ObjEntry *entry = (ObjEntry*)obj->data[i].p;
        ObjEntry *key = vm_entry_key(entry);
        if (key && entry_is_string(key) &&
            disturb_bytes_eq_cstr(key->obj, "local")) {
            continue;
        }
        if (vm_entry_on_stack(stack, entry)) continue;
        if (entry) vm_release_entry(vm, entry);
    }
    vm_release_entry(vm, local);
}

static int vm_bind_args(VM *vm, FunctionBox *box, List *stack, uint32_t argc, ObjEntry *local)
{
    if (!vm || !box) return 0;
    uint32_t fixed = box->argc;
    if (box->has_vararg && fixed > 0) fixed--;
    for (uint32_t i = 0; i < fixed; i++) {
        ObjEntry *arg = vm_stack_arg(stack, argc, i);
        if (!arg) {
            if (box->has_default && box->has_default[i]) {
                arg = vm_eval_default(vm, stack, box->default_code[i], box->default_lens[i]);
            }
            if (!arg) arg = vm->null_entry;
        }
        if (!local) return 0;
        if (!vm_object_set_by_key_len(vm, &local->obj,
                                      box->arg_names[i],
                                      box->arg_lens[i],
                                      arg, 0)) {
            return 0;
        }
    }
    if (box->has_vararg) {
        ObjEntry *list = vm_make_table_value(vm, (Int)(argc > fixed ? argc - fixed : 0));
        for (uint32_t i = fixed; i < argc; i++) {
            ObjEntry *arg = vm_stack_arg(stack, argc, i);
            if (!arg) arg = vm->null_entry;
            list->obj = vm_update_shared_obj(vm, list->obj,
                                             disturb_table_add(list->obj, arg));
        }
        if (!local) return 0;
        if (!vm_object_set_by_key_len(vm, &local->obj,
                                      box->arg_names[box->argc - 1],
                                      box->arg_lens[box->argc - 1],
                                      list, 0)) {
            return 0;
        }
    }
    if (!vm_object_set_by_key_len(vm, &local->obj, "local", 5, local, 0)) {
        return 0;
    }
    return 1;
}

static int vm_number_to_index(ObjEntry *entry, Int *out, const char *op, size_t pc)
{
    Int iv = 0;
    Float fv = 0;
    int is_float = 0;
    if (!vm_entry_number(entry, &iv, &fv, &is_float, op, pc)) {
        fprintf(stderr, "bytecode error at pc %zu: %s expects number index\n", pc, op);
        return 0;
    }
    if (is_float) {
        Int fiv = (Int)fv;
        if ((Float)fiv != fv) {
            fprintf(stderr, "bytecode error at pc %zu: %s index must be integer\n", pc, op);
            return 0;
        }
        iv = fiv;
    }
    *out = iv;
    return 1;
}

static ObjEntry *vm_index_get(VM *vm, ObjEntry *target, ObjEntry *index, size_t pc)
{
    if (!target) {
        fprintf(stderr, "bytecode error at pc %zu: INDEX target is null\n", pc);
        return NULL;
    }

    ObjEntry *meta = vm_meta_get(vm, target, index, pc);
    if (meta) return meta;

    Int type = disturb_obj_type(target->obj);
    if (type == DISTURB_T_NULL) {
        return vm->null_entry;
    }
    if (type == DISTURB_T_VIEW) {
        if (!index) {
            fprintf(stderr, "bytecode error at pc %zu: INDEX missing view index\n", pc);
            return NULL;
        }
        ObjEntry *base = (ObjEntry*)target->obj->data[2].p;
        ViewType view = (ViewType)target->obj->data[3].i;
        if (!base || !base->in_use) {
            fprintf(stderr, "bytecode error at pc %zu: INDEX view base missing\n", pc);
            return NULL;
        }
        Int idx = 0;
        if (!vm_number_to_index(index, &idx, "INDEX", pc)) return NULL;
        if (idx < 0) {
            fprintf(stderr, "bytecode error at pc %zu: INDEX out of bounds\n", pc);
            return vm->null_entry;
        }
        size_t stride = vm_view_stride(view);
        size_t offset = (size_t)idx * stride;
        size_t len = disturb_bytes_len(base->obj);
        if (offset + stride > len) {
            fprintf(stderr, "bytecode error at pc %zu: INDEX out of bounds\n", pc);
            return vm->null_entry;
        }
        unsigned char *buf = (unsigned char*)disturb_bytes_data(base->obj) + offset;
        if (vm_view_is_float(view)) {
            if (view == VIEW_F32) {
                float fv = 0.0f;
                memcpy(&fv, buf, sizeof(fv));
                return vm_make_float_value(vm, (Float)fv);
            }
            if (view == VIEW_F64) {
                double dv = 0.0;
                memcpy(&dv, buf, sizeof(dv));
                return vm_make_float_value(vm, (Float)dv);
            }
        } else {
            Int out = 0;
            switch (view) {
            case VIEW_I8: {
                int8_t v = 0;
                memcpy(&v, buf, sizeof(v));
                out = (Int)v;
                break;
            }
            case VIEW_U8: {
                uint8_t v = 0;
                memcpy(&v, buf, sizeof(v));
                out = (Int)v;
                break;
            }
            case VIEW_I16: {
                int16_t v = 0;
                memcpy(&v, buf, sizeof(v));
                out = (Int)v;
                break;
            }
            case VIEW_U16: {
                uint16_t v = 0;
                memcpy(&v, buf, sizeof(v));
                out = (Int)v;
                break;
            }
            case VIEW_I32: {
                int32_t v = 0;
                memcpy(&v, buf, sizeof(v));
                out = (Int)v;
                break;
            }
            case VIEW_U32: {
                uint32_t v = 0;
                memcpy(&v, buf, sizeof(v));
                out = (Int)v;
                break;
            }
            case VIEW_I64: {
                int64_t v = 0;
                memcpy(&v, buf, sizeof(v));
                out = (Int)v;
                break;
            }
            case VIEW_U64: {
                uint64_t v = 0;
                memcpy(&v, buf, sizeof(v));
                out = (Int)v;
                break;
            }
            default:
                break;
            }
            return vm_make_int_value(vm, out);
        }
        return vm->null_entry;
    }
    if (type == DISTURB_T_TABLE) {
        if (!index) {
            fprintf(stderr, "bytecode error at pc %zu: INDEX object missing key/index\n", pc);
            return NULL;
        }
        if (entry_is_string(index)) {
            return vm_object_find_by_key_len(vm, target->obj,
                                             disturb_bytes_data(index->obj),
                                             disturb_bytes_len(index->obj));
        }
        Int idx = 0;
        if (!vm_number_to_index(index, &idx, "INDEX", pc)) return NULL;
        Int pos = idx + 2;
        if (idx < 0 || pos >= target->obj->size) {
            fprintf(stderr, "bytecode error at pc %zu: INDEX out of bounds\n", pc);
            return vm->null_entry;
        }
        return (ObjEntry*)target->obj->data[pos].p;
    }

    if (type == DISTURB_T_NATIVE && index && entry_is_string(index)) {
        return vm_object_find_by_key_len(vm, target->obj,
                                         disturb_bytes_data(index->obj),
                                         disturb_bytes_len(index->obj));
    }

    if (index && entry_is_string(index)) {
        if (vm && vm->common_entry) {
            ObjEntry *method = vm_object_find_direct(vm->common_entry->obj,
                                                     disturb_bytes_data(index->obj),
                                                     disturb_bytes_len(index->obj));
            if (method) return method;
        }
        return vm->null_entry;
    }

    Int idx = 0;
    if (!vm_number_to_index(index, &idx, "INDEX", pc)) return NULL;

    if (type == DISTURB_T_INT) {
        if (entry_is_string(target)) {
            size_t len = disturb_bytes_len(target->obj);
            if (idx < 0 || (size_t)idx >= len) {
                fprintf(stderr, "bytecode error at pc %zu: INDEX out of bounds\n", pc);
                return vm->null_entry;
            }
            char c = disturb_bytes_data(target->obj)[idx];
            ObjEntry *entry = vm_reg_alloc(vm, vm_alloc_bytes(vm, DISTURB_T_INT, NULL, &c, 1));
            if (entry) {
                entry->is_string = 1;
                entry->explicit_string = target->explicit_string;
            }
            return entry;
        }
        Int count = vm_bytes_to_count(disturb_bytes_len(target->obj), DISTURB_T_INT);
        if (idx < 0 || idx >= count) {
            fprintf(stderr, "bytecode error at pc %zu: INDEX out of bounds\n", pc);
            return vm->null_entry;
        }
        Int v = 0;
        if (!vm_read_int_at(target->obj, idx, &v)) return vm->null_entry;
        return vm_make_int_value(vm, v);
    }

    if (type == DISTURB_T_FLOAT) {
        Int count = vm_bytes_to_count(disturb_bytes_len(target->obj), DISTURB_T_FLOAT);
        if (idx < 0 || idx >= count) {
            fprintf(stderr, "bytecode error at pc %zu: INDEX out of bounds\n", pc);
            return vm->null_entry;
        }
        Float v = 0;
        if (!vm_read_float_at(target->obj, idx, &v)) return vm->null_entry;
        return vm_make_float_value(vm, v);
    }

    fprintf(stderr, "bytecode error at pc %zu: INDEX unsupported type %s\n",
            pc, disturb_type_name(type));
    return NULL;
}

static int vm_object_set_by_key_len(VM *vm, List **objp, const char *name, size_t len, ObjEntry *value, size_t pc)
{
    if (!objp || !*objp || !value) {
        fprintf(stderr, "bytecode error at pc %zu: STORE_INDEX missing target/value\n", pc);
        return 0;
    }
    List *obj = *objp;
    Int start = 2;
    Int type = disturb_obj_type(obj);
    if (type == DISTURB_T_NATIVE || type == DISTURB_T_LAMBDA) start = 3;
    ObjEntry *found = NULL;
    for (Int i = start; i < obj->size; i++) {
        ObjEntry *entry = (ObjEntry*)obj->data[i].p;
        ObjEntry *key = vm_entry_key(entry);
        if (!key || !entry_is_string(key)) continue;
        if (disturb_bytes_eq_bytes(key->obj, name, len)) {
            found = entry;
            break;
        }
    }
    if (found) {
        if (found->obj == value->obj) return 1;
        Int found_type = disturb_obj_type(found->obj);
        Int value_type = disturb_obj_type(value->obj);
        if ((found_type == DISTURB_T_INT && value_type == DISTURB_T_INT) ||
            (found_type == DISTURB_T_FLOAT && value_type == DISTURB_T_FLOAT)) {
            List *dst = found->obj;
            List *src = value->obj;
            size_t len_bytes = disturb_bytes_len(src);
            List *old_dst = dst;
            dst = vm_resize_bytes(dst, (Int)len_bytes);
            if (!dst) return 0;
            dst = vm_update_shared_obj(vm, old_dst, dst);
            found->obj = dst;
            if (len_bytes) {
                memcpy(disturb_bytes_data(dst), disturb_bytes_data(src), len_bytes);
            }
            found->is_string = value->is_string;
            found->explicit_string = value->explicit_string;
            return 1;
        }
        if (found_type == DISTURB_T_TABLE && value_type == DISTURB_T_TABLE) {
            List *dst = found->obj;
            List *src = value->obj;
            size_t count = src->size >= 2 ? (size_t)(src->size - 2) : 0;
            size_t cap = dst->capacity >= 2 ? (size_t)(dst->capacity - 2) : 0;
            if (count > cap) {
                List *old_dst = dst;
                dst = vm_resize_list(dst, (Int)count, vm->null_entry);
                if (!dst) return 0;
                dst = vm_update_shared_obj(vm, old_dst, dst);
                found->obj = dst;
            }
            dst->size = (UHalf)(count + 2);
            for (size_t i = 0; i < count; i++) {
                dst->data[i + 2] = src->data[i + 2];
            }
            return 1;
        }
        found->obj = value->obj;
        return 1;
    }

    ObjEntry *key_entry = vm_make_key_len(vm, name, len);
    ObjEntry *copy = vm_clone_entry_shallow(vm, value, key_entry);
    if (!copy) {
        fprintf(stderr, "bytecode error at pc %zu: STORE_INDEX clone failed\n", pc);
        return 0;
    }
    List *old_obj = obj;
    obj = disturb_table_add(obj, copy);
    *objp = vm_update_shared_obj(vm, old_obj, obj);
    return 1;
}

int vm_object_set_by_key(VM *vm, ObjEntry *target, const char *name, size_t len, ObjEntry *value)
{
    if (!target) return 0;
    Int type = disturb_obj_type(target->obj);
    if (type != DISTURB_T_TABLE && type != DISTURB_T_NATIVE) return 0;
    return vm_object_set_by_key_len(vm, &target->obj, name, len, value, 0);
}

static int vm_meta_set(VM *vm, ObjEntry *target, ObjEntry *index, ObjEntry *value, size_t pc)
{
    if (!target || !index || !entry_is_string(index)) return 0;
    if (vm_key_is(index, "name")) {
        if (!value || disturb_obj_type(value->obj) == DISTURB_T_NULL) {
            target->key = NULL;
            return 1;
        }
        if (!entry_is_string(value)) {
            fprintf(stderr, "bytecode error at pc %zu: name expects string or null\n", pc);
            return -1;
        }
        ObjEntry *key_entry = vm_make_key_len(vm, disturb_bytes_data(value->obj), disturb_bytes_len(value->obj));
        target->key = key_entry;
        return 1;
    }
    if (vm_key_is(index, "type")) {
        if (!value || !entry_is_string(value)) {
            fprintf(stderr, "bytecode error at pc %zu: type expects string\n", pc);
            return -1;
        }
        const char *name = disturb_bytes_data(value->obj);
        size_t len = disturb_bytes_len(value->obj);
        Int next = -1;
        if (len == 4 && strncmp(name, "null", 4) == 0) next = DISTURB_T_NULL;
        else if (len == 3 && strncmp(name, "int", 3) == 0) next = DISTURB_T_INT;
        else if (len == 5 && strncmp(name, "float", 5) == 0) next = DISTURB_T_FLOAT;
        else if (len == 5 && strncmp(name, "table", 5) == 0) next = DISTURB_T_TABLE;
        else if (len == 4 && strncmp(name, "char", 4) == 0) next = DISTURB_T_INT;
        else if (len == 6 && strncmp(name, "string", 6) == 0) next = DISTURB_T_INT;
        else if (len == 6 && strncmp(name, "native", 6) == 0) next = DISTURB_T_NATIVE;
        else if (len == 6 && strncmp(name, "lambda", 6) == 0) next = DISTURB_T_LAMBDA;
        else {
            fprintf(stderr, "bytecode error at pc %zu: unknown type '%.*s'\n", pc, (int)len, name);
            return -1;
        }
        target->obj->data[0].i = next;
        if (next == DISTURB_T_INT && (len == 4 || len == 6)) {
            target->is_string = 1;
            target->explicit_string = 1;
        } else if (next == DISTURB_T_INT || next == DISTURB_T_FLOAT) {
            target->is_string = 0;
            target->explicit_string = 0;
        }
        return 1;
    }
    if (vm_key_is(index, "value")) {
        if (!value) {
            fprintf(stderr, "bytecode error at pc %zu: value expects a value\n", pc);
            return -1;
        }
        if (value == vm->null_entry || disturb_obj_type(value->obj) == DISTURB_T_NULL) {
            target->obj = vm->null_entry->obj;
            target->is_string = 0;
            return 1;
        }
        int is_string = 0;
        int explicit_string = 0;
        ObjEntry *key_entry = vm_entry_key(target);
        List *copy = vm_clone_obj_shallow_copy(vm, value, key_entry, &is_string, &explicit_string);
        if (!copy) {
            fprintf(stderr, "bytecode error at pc %zu: value assignment failed\n", pc);
            return -1;
        }
        target->obj = copy;
        target->is_string = is_string;
        target->explicit_string = explicit_string;
        return 1;
    }
    if (vm_key_is(index, "size")) {
        Int iv = 0;
        Float fv = 0;
        int is_float = 0;
        if (!vm_entry_number(value, &iv, &fv, &is_float, "size", pc)) {
            fprintf(stderr, "bytecode error at pc %zu: size expects number\n", pc);
            return -1;
        }
        if (is_float) {
            Int cast = (Int)fv;
            if ((Float)cast != fv) {
                fprintf(stderr, "bytecode error at pc %zu: size expects integer\n", pc);
                return -1;
            }
            iv = cast;
        }
        Int new_size = iv;
        if (new_size < 0) {
            fprintf(stderr, "bytecode error at pc %zu: size expects integer\n", pc);
            return -1;
        }
        Int type = disturb_obj_type(target->obj);
        if (type == DISTURB_T_INT || type == DISTURB_T_FLOAT) {
            Int bytes = new_size;
            if (!(type == DISTURB_T_INT && entry_is_string(target))) {
                bytes = (Int)((size_t)new_size * vm_elem_size(type));
            }
            if (!vm_set_size_bytes(vm, target, bytes)) {
                fprintf(stderr, "bytecode error at pc %zu: failed to resize bytes\n", pc);
                return -1;
            }
            return 1;
        }
        if (type == DISTURB_T_TABLE) {
            if (!vm_set_size_list(vm, target, new_size, vm->null_entry)) {
                fprintf(stderr, "bytecode error at pc %zu: failed to resize list\n", pc);
                return -1;
            }
            return 1;
        }
        fprintf(stderr, "bytecode error at pc %zu: size not supported on %s\n", pc, disturb_type_name(type));
        return -1;
    }
    if (vm_key_is(index, "capacity")) {
        Int iv = 0;
        Float fv = 0;
        int is_float = 0;
        if (!vm_entry_number(value, &iv, &fv, &is_float, "capacity", pc)) {
            fprintf(stderr, "bytecode error at pc %zu: capacity expects number\n", pc);
            return -1;
        }
        if (is_float) {
            Int cast = (Int)fv;
            if ((Float)cast != fv) {
                fprintf(stderr, "bytecode error at pc %zu: capacity expects integer\n", pc);
                return -1;
            }
            iv = cast;
        }
        Int new_cap = iv;
        if (new_cap < 0) {
            fprintf(stderr, "bytecode error at pc %zu: capacity expects integer\n", pc);
            return -1;
        }
        Int type = disturb_obj_type(target->obj);
        if (type == DISTURB_T_INT || type == DISTURB_T_FLOAT) {
            Int bytes = new_cap;
            if (!(type == DISTURB_T_INT && entry_is_string(target))) {
                bytes = (Int)((size_t)new_cap * vm_elem_size(type));
            }
            List *old_obj = target->obj;
            List *resized = vm_resize_bytes_capacity(target->obj, bytes);
            if (!resized) {
                fprintf(stderr, "bytecode error at pc %zu: failed to resize bytes\n", pc);
                return -1;
            }
            target->obj = vm_update_shared_obj(vm, old_obj, resized);
            return 1;
        }
        if (type == DISTURB_T_TABLE) {
            size_t payload = (size_t)new_cap;
            size_t new_total = payload + 2;
            size_t bytes = sizeof(List) + new_total * sizeof(Value);
            List *resized = (List*)realloc(target->obj, bytes);
            if (!resized && new_total > 0) {
                fprintf(stderr, "bytecode error at pc %zu: failed to resize list\n", pc);
                return -1;
            }
            target->obj = resized;
            if ((size_t)target->obj->capacity < new_total) {
                memset(target->obj->data + target->obj->capacity, 0,
                       (new_total - target->obj->capacity) * sizeof(Value));
            }
            target->obj->capacity = (UHalf)new_total;
            if (target->obj->size > target->obj->capacity) {
                target->obj->size = target->obj->capacity;
            }
            if (disturb_obj_type(target->obj) == DISTURB_T_TABLE) {
                for (Int i = 2; i < target->obj->size; i++) {
                    if (!target->obj->data[i].p) {
                        target->obj->data[i].p = vm->null_entry;
                    }
                }
            }
            return 1;
        }
        fprintf(stderr, "bytecode error at pc %zu: capacity not supported on %s\n", pc, disturb_type_name(type));
        return -1;
    }
    return 0;
}

int vm_exec_bytecode(VM *vm, const unsigned char *data, size_t len)
{
    size_t pc = 0;
    while (pc < len) {
        uint8_t op = 0;
        if (!bc_read_u8(data, len, &pc, &op)) {
            fprintf(stderr, "bytecode error at pc %zu: truncated opcode\n", pc);
            return 0;
        }

        switch (op) {
        case BC_PUSH_INT: {
            int64_t v = 0;
            if (!bc_read_i64(data, len, &pc, &v)) {
                fprintf(stderr, "bytecode error at pc %zu: truncated PUSH_INT\n", pc);
                return 0;
            }
            vm_stack_push_entry(vm, vm_make_int_value(vm, (Int)v));
            break;
        }
        case BC_PUSH_FLOAT: {
            double v = 0.0;
            if (!bc_read_f64(data, len, &pc, &v)) {
                fprintf(stderr, "bytecode error at pc %zu: truncated PUSH_FLOAT\n", pc);
                return 0;
            }
            vm_stack_push_entry(vm, vm_make_float_value(vm, (Float)v));
            break;
        }
        case BC_PUSH_CHAR:
        case BC_PUSH_STRING: {
            unsigned char *buf = NULL;
            size_t slen = 0;
            if (!bc_read_string(data, len, &pc, &buf, &slen)) {
                fprintf(stderr, "bytecode error at pc %zu: truncated string\n", pc);
                return 0;
            }
            char *processed = papagaio_process_text(vm, (const char*)buf, slen);
            if (processed) {
                List *obj = vm_alloc_bytes(vm, DISTURB_T_INT, NULL, processed, strlen(processed));
                free(processed);
                free(buf);
                ObjEntry *entry = vm_reg_alloc(vm, obj);
                if (entry) {
                    entry->is_string = 1;
                    entry->explicit_string = 0;
                }
                vm_stack_push_entry(vm, entry);
                break;
            }
            List *obj = vm_alloc_bytes(vm, DISTURB_T_INT, NULL, (const char*)buf, slen);
            free(buf);
            ObjEntry *entry = vm_reg_alloc(vm, obj);
            if (entry) {
                entry->is_string = 1;
                entry->explicit_string = 0;
            }
            vm_stack_push_entry(vm, entry);
            break;
        }
        case BC_PUSH_CHAR_RAW:
        case BC_PUSH_STRING_RAW: {
            unsigned char *buf = NULL;
            size_t slen = 0;
            if (!bc_read_string(data, len, &pc, &buf, &slen)) {
                fprintf(stderr, "bytecode error at pc %zu: truncated string\n", pc);
                return 0;
            }
            List *obj = vm_alloc_bytes(vm, DISTURB_T_INT, NULL, (const char*)buf, slen);
            free(buf);
            ObjEntry *entry = vm_reg_alloc(vm, obj);
            if (entry) {
                entry->is_string = 1;
                entry->explicit_string = 0;
            }
            vm_stack_push_entry(vm, entry);
            break;
        }
        case BC_BUILD_INT: {
            uint32_t count = 0;
            if (!bc_read_u32(data, len, &pc, &count)) {
                fprintf(stderr, "bytecode error at pc %zu: truncated BUILD_INT\n", pc);
                return 0;
            }
            List *obj = vm_alloc_bytes(vm, DISTURB_T_INT, NULL, NULL, (size_t)count * sizeof(Int));
            for (uint32_t i = 0; i < count; i++) {
                ObjEntry *entry = vm_stack_pop_entry(vm, "BUILD_INT", pc);
                Int iv = 0;
                Float fv = 0;
                int is_float = 0;
                if (!entry) return 0;
                if (!vm_entry_number(entry, &iv, &fv, &is_float, "BUILD_INT", pc) || is_float) {
                    fprintf(stderr, "bytecode error at pc %zu: BUILD_INT expects int values\n", pc);
                    return 0;
                }
                vm_write_int_at(obj, (Int)(count - 1 - i), iv);
            }
            vm_stack_push_entry(vm, vm_reg_alloc(vm, obj));
            break;
        }
        case BC_BUILD_FLOAT: {
            uint32_t count = 0;
            if (!bc_read_u32(data, len, &pc, &count)) {
                fprintf(stderr, "bytecode error at pc %zu: truncated BUILD_FLOAT\n", pc);
                return 0;
            }
            List *obj = vm_alloc_bytes(vm, DISTURB_T_FLOAT, NULL, NULL, (size_t)count * sizeof(Float));
            for (uint32_t i = 0; i < count; i++) {
                ObjEntry *entry = vm_stack_pop_entry(vm, "BUILD_FLOAT", pc);
                Int iv = 0;
                Float fv = 0;
                int is_float = 0;
                if (!entry) return 0;
                if (!vm_entry_number(entry, &iv, &fv, &is_float, "BUILD_FLOAT", pc)) {
                    return 0;
                }
                vm_write_float_at(obj, (Int)(count - 1 - i), is_float ? fv : (Float)iv);
            }
            vm_stack_push_entry(vm, vm_reg_alloc(vm, obj));
            break;
        }
        case BC_BUILD_INT_LIT: {
            uint32_t count = 0;
            if (!bc_read_u32(data, len, &pc, &count)) {
                fprintf(stderr, "bytecode error at pc %zu: truncated BUILD_INT_LIT\n", pc);
                return 0;
            }
            List *obj = vm_alloc_bytes(vm, DISTURB_T_INT, NULL, NULL, (size_t)count * sizeof(Int));
            for (uint32_t i = 0; i < count; i++) {
                int64_t v = 0;
                if (!bc_read_i64(data, len, &pc, &v)) {
                    fprintf(stderr, "bytecode error at pc %zu: truncated BUILD_INT_LIT value\n", pc);
                    return 0;
                }
                vm_write_int_at(obj, (Int)i, (Int)v);
            }
            vm_stack_push_entry(vm, vm_reg_alloc(vm, obj));
            break;
        }
        case BC_BUILD_FLOAT_LIT: {
            uint32_t count = 0;
            if (!bc_read_u32(data, len, &pc, &count)) {
                fprintf(stderr, "bytecode error at pc %zu: truncated BUILD_FLOAT_LIT\n", pc);
                return 0;
            }
            List *obj = vm_alloc_bytes(vm, DISTURB_T_FLOAT, NULL, NULL, (size_t)count * sizeof(Float));
            for (uint32_t i = 0; i < count; i++) {
                double v = 0.0;
                if (!bc_read_f64(data, len, &pc, &v)) {
                    fprintf(stderr, "bytecode error at pc %zu: truncated BUILD_FLOAT_LIT value\n", pc);
                    return 0;
                }
                vm_write_float_at(obj, (Int)i, (Float)v);
            }
            vm_stack_push_entry(vm, vm_reg_alloc(vm, obj));
            break;
        }
        case BC_BUILD_OBJECT: {
            uint32_t count = 0;
            if (!bc_read_u32(data, len, &pc, &count)) {
                fprintf(stderr, "bytecode error at pc %zu: truncated BUILD_OBJECT\n", pc);
                return 0;
            }
            List *obj = vm_alloc_list(vm, DISTURB_T_TABLE, NULL, (Int)count);
            ObjEntry **keys = (ObjEntry**)calloc(count, sizeof(ObjEntry*));
            ObjEntry **vals = (ObjEntry**)calloc(count, sizeof(ObjEntry*));
            if (!keys || !vals) {
                fprintf(stderr, "bytecode error at pc %zu: out of memory\n", pc);
                free(keys);
                free(vals);
                return 0;
            }
            for (uint32_t i = 0; i < count; i++) {
                ObjEntry *val = vm_stack_pop_entry(vm, "BUILD_OBJECT", pc);
                ObjEntry *key = vm_stack_pop_entry(vm, "BUILD_OBJECT", pc);
                if (!key || !entry_is_string(key)) {
                    fprintf(stderr, "bytecode error at pc %zu: BUILD_OBJECT expects string keys\n", pc);
                    free(keys);
                    free(vals);
                    return 0;
                }
                keys[count - 1 - i] = key;
                vals[count - 1 - i] = val;
            }
            for (uint32_t i = 0; i < count; i++) {
                ObjEntry *key_entry = vm_make_key_len(vm,
                                                     disturb_bytes_data(keys[i]->obj),
                                                     disturb_bytes_len(keys[i]->obj));
                ObjEntry *copy = vm_clone_entry_shallow(vm, vals[i], key_entry);
                if (!copy) {
                    fprintf(stderr, "bytecode error at pc %zu: BUILD_OBJECT clone failed\n", pc);
                    free(keys);
                    free(vals);
                    return 0;
                }
                obj = disturb_table_add(obj, copy);
            }
            free(keys);
            free(vals);
            vm_stack_push_entry(vm, vm_reg_alloc(vm, obj));
            break;
        }
        case BC_BUILD_FUNCTION: {
            uint32_t argc = 0;
            uint32_t vararg = 0;
            uint32_t code_len = 0;
            if (!bc_read_u32(data, len, &pc, &argc) ||
                !bc_read_u32(data, len, &pc, &vararg) ||
                !bc_read_u32(data, len, &pc, &code_len)) {
                fprintf(stderr, "bytecode error at pc %zu: truncated BUILD_FUNCTION\n", pc);
                return 0;
            }
            if (pc + code_len > len) {
                fprintf(stderr, "bytecode error at pc %zu: BUILD_FUNCTION code out of bounds\n", pc);
                return 0;
            }
            unsigned char *code = (unsigned char*)malloc(code_len);
            if (code_len) memcpy(code, data + pc, code_len);
            pc += code_len;
            char **arg_names = NULL;
            size_t *arg_lens = NULL;
            unsigned char **default_code = NULL;
            size_t *default_lens = NULL;
            uint8_t *has_default = NULL;
            if (argc > 0) {
                arg_names = (char**)calloc(argc, sizeof(char*));
                arg_lens = (size_t*)calloc(argc, sizeof(size_t));
                default_code = (unsigned char**)calloc(argc, sizeof(unsigned char*));
                default_lens = (size_t*)calloc(argc, sizeof(size_t));
                has_default = (uint8_t*)calloc(argc, sizeof(uint8_t));
                if (!arg_names || !arg_lens || !default_code || !default_lens || !has_default) {
                    fprintf(stderr, "bytecode error at pc %zu: BUILD_FUNCTION alloc failed\n", pc);
                    free(code);
                    free(arg_names);
                    free(arg_lens);
                    free(default_code);
                    free(default_lens);
                    free(has_default);
                    return 0;
                }
            }
            for (uint32_t i = 0; i < argc; i++) {
                unsigned char *name = NULL;
                size_t name_len = 0;
                if (!bc_read_string(data, len, &pc, &name, &name_len)) {
                    fprintf(stderr, "bytecode error at pc %zu: BUILD_FUNCTION arg name truncated\n", pc);
                    free(code);
                    for (uint32_t j = 0; j < i; j++) free(arg_names[j]);
                    free(arg_names);
                    free(arg_lens);
                    for (uint32_t j = 0; j < i; j++) free(default_code[j]);
                    free(default_code);
                    free(default_lens);
                    free(has_default);
                    return 0;
                }
                arg_names[i] = (char*)name;
                arg_lens[i] = name_len;
                uint32_t def_len = 0;
                if (!bc_read_u32(data, len, &pc, &def_len)) {
                    fprintf(stderr, "bytecode error at pc %zu: BUILD_FUNCTION default truncated\n", pc);
                    free(code);
                    for (uint32_t j = 0; j <= i; j++) free(arg_names[j]);
                    free(arg_names);
                    free(arg_lens);
                    for (uint32_t j = 0; j < i; j++) free(default_code[j]);
                    free(default_code);
                    free(default_lens);
                    free(has_default);
                    return 0;
                }
                if (def_len > 0) {
                    if (pc + def_len > len) {
                        fprintf(stderr, "bytecode error at pc %zu: BUILD_FUNCTION default out of bounds\n", pc);
                        free(code);
                        for (uint32_t j = 0; j <= i; j++) free(arg_names[j]);
                        free(arg_names);
                        free(arg_lens);
                        for (uint32_t j = 0; j < i; j++) free(default_code[j]);
                        free(default_code);
                        free(default_lens);
                        free(has_default);
                        return 0;
                    }
                    unsigned char *def_code = (unsigned char*)malloc(def_len);
                    if (!def_code) {
                        fprintf(stderr, "bytecode error at pc %zu: BUILD_FUNCTION default alloc failed\n", pc);
                        free(code);
                        for (uint32_t j = 0; j <= i; j++) free(arg_names[j]);
                        free(arg_names);
                        free(arg_lens);
                        for (uint32_t j = 0; j < i; j++) free(default_code[j]);
                        free(default_code);
                        free(default_lens);
                        free(has_default);
                        return 0;
                    }
                    memcpy(def_code, data + pc, def_len);
                    pc += def_len;
                    default_code[i] = def_code;
                    default_lens[i] = def_len;
                    has_default[i] = 1;
                }
            }
            FunctionBox *box = (FunctionBox*)malloc(sizeof(FunctionBox));
            box->code = code;
            box->len = code_len;
            box->argc = argc;
            box->has_vararg = vararg ? 1 : 0;
            box->arg_names = arg_names;
            box->arg_lens = arg_lens;
            box->default_code = default_code;
            box->default_lens = default_lens;
            box->has_default = has_default;
            List *obj = vm_alloc_list(vm, DISTURB_T_LAMBDA, NULL, 1);
            Value v;
            v.p = box;
            obj = disturb_push(obj, v);
            vm_stack_push_entry(vm, vm_reg_alloc(vm, obj));
            break;
        }
        case BC_INDEX: {
            ObjEntry *index = vm_stack_pop_entry(vm, "INDEX", pc);
            ObjEntry *target = vm_stack_pop_entry(vm, "INDEX", pc);
            if (!index || !target) return 0;
            ObjEntry *res = vm_index_get(vm, target, index, pc);
            if (!res) return 0;
            vm_stack_push_entry(vm, res);
            break;
        }
        case BC_STORE_INDEX: {
            ObjEntry *value = vm_stack_pop_entry(vm, "STORE_INDEX", pc);
            ObjEntry *index = vm_stack_pop_entry(vm, "STORE_INDEX", pc);
            ObjEntry *target = vm_stack_pop_entry(vm, "STORE_INDEX", pc);
            if (!value || !index || !target) return 0;

            int meta = vm_meta_set(vm, target, index, value, pc);
            if (meta < 0) return 0;
            if (meta > 0) break;

            Int type = disturb_obj_type(target->obj);
            if (type == DISTURB_T_TABLE && entry_is_string(index)) {
                if (!vm_object_set_by_key_len(vm, &target->obj,
                                              disturb_bytes_data(index->obj),
                                              disturb_bytes_len(index->obj),
                                              value, pc)) {
                    return 0;
                }
                break;
            }

            Int idx = 0;
            if (!vm_number_to_index(index, &idx, "STORE_INDEX", pc)) return 0;

            if (type == DISTURB_T_VIEW) {
                ObjEntry *base = (ObjEntry*)target->obj->data[2].p;
                ViewType view = (ViewType)target->obj->data[3].i;
                if (!base || !base->in_use) {
                    fprintf(stderr, "bytecode error at pc %zu: STORE_INDEX view base missing\n", pc);
                    return 0;
                }
                if (idx < 0) {
                    fprintf(stderr, "bytecode error at pc %zu: STORE_INDEX out of bounds\n", pc);
                    return 0;
                }
                size_t stride = vm_view_stride(view);
                size_t offset = (size_t)idx * stride;
                size_t len = disturb_bytes_len(base->obj);
                if (offset + stride > len) {
                    fprintf(stderr, "bytecode error at pc %zu: STORE_INDEX out of bounds\n", pc);
                    return 0;
                }
                unsigned char *buf = (unsigned char*)disturb_bytes_data(base->obj) + offset;
                Int iv = 0;
                Float fv = 0;
                int is_float = 0;
                if (!vm_entry_number(value, &iv, &fv, &is_float, "STORE_INDEX", pc)) {
                    return 0;
                }
                if (vm_view_is_float(view)) {
                    if (view == VIEW_F32) {
                        float out = is_float ? (float)fv : (float)iv;
                        memcpy(buf, &out, sizeof(out));
                        break;
                    }
                    if (view == VIEW_F64) {
                        double out = is_float ? (double)fv : (double)iv;
                        memcpy(buf, &out, sizeof(out));
                        break;
                    }
                } else {
                    switch (view) {
                    case VIEW_I8: {
                        int8_t v = (int8_t)(is_float ? fv : iv);
                        memcpy(buf, &v, sizeof(v));
                        break;
                    }
                    case VIEW_U8: {
                        uint8_t v = (uint8_t)(is_float ? fv : iv);
                        memcpy(buf, &v, sizeof(v));
                        break;
                    }
                    case VIEW_I16: {
                        int16_t v = (int16_t)(is_float ? fv : iv);
                        memcpy(buf, &v, sizeof(v));
                        break;
                    }
                    case VIEW_U16: {
                        uint16_t v = (uint16_t)(is_float ? fv : iv);
                        memcpy(buf, &v, sizeof(v));
                        break;
                    }
                    case VIEW_I32: {
                        int32_t v = (int32_t)(is_float ? fv : iv);
                        memcpy(buf, &v, sizeof(v));
                        break;
                    }
                    case VIEW_U32: {
                        uint32_t v = (uint32_t)(is_float ? fv : iv);
                        memcpy(buf, &v, sizeof(v));
                        break;
                    }
                    case VIEW_I64: {
                        int64_t v = (int64_t)(is_float ? fv : iv);
                        memcpy(buf, &v, sizeof(v));
                        break;
                    }
                    case VIEW_U64: {
                        uint64_t v = (uint64_t)(is_float ? fv : iv);
                        memcpy(buf, &v, sizeof(v));
                        break;
                    }
                    default:
                        break;
                    }
                }
                break;
            }

            if (type == DISTURB_T_INT) {
                if (entry_is_string(target)) {
                    size_t len = disturb_bytes_len(target->obj);
                    if (idx < 0 || (size_t)idx >= len) {
                        fprintf(stderr, "bytecode error at pc %zu: STORE_INDEX out of bounds\n", pc);
                        return 0;
                    }
                    if (entry_is_string(value) && disturb_bytes_len(value->obj) == 1) {
                        disturb_bytes_data(target->obj)[idx] = disturb_bytes_data(value->obj)[0];
                        break;
                    }
                    Int iv = 0;
                    Float fv = 0;
                    int is_float = 0;
                    if (!vm_entry_number(value, &iv, &fv, &is_float, "STORE_INDEX", pc)) {
                        return 0;
                    }
                    if (is_float) {
                        Int cast = (Int)fv;
                        if ((Float)cast != fv) {
                            fprintf(stderr, "bytecode error at pc %zu: STORE_INDEX expects byte-sized number\n", pc);
                            return 0;
                        }
                        iv = cast;
                    }
                    if (iv < 0 || iv > 255) {
                        fprintf(stderr, "bytecode error at pc %zu: STORE_INDEX expects byte-sized number\n", pc);
                        return 0;
                    }
                    disturb_bytes_data(target->obj)[idx] = (unsigned char)iv;
                    break;
                }
                Int count = vm_bytes_to_count(disturb_bytes_len(target->obj), DISTURB_T_INT);
                if (idx < 0 || idx >= count) {
                    fprintf(stderr, "bytecode error at pc %zu: STORE_INDEX out of bounds\n", pc);
                    return 0;
                }
                Int iv = 0;
                Float fv = 0;
                int is_float = 0;
                if (!vm_entry_number(value, &iv, &fv, &is_float, "STORE_INDEX", pc) || is_float) {
                    fprintf(stderr, "bytecode error at pc %zu: STORE_INDEX expects int\n", pc);
                    return 0;
                }
                vm_write_int_at(target->obj, idx, iv);
                break;
            }

            if (type == DISTURB_T_FLOAT) {
                Int count = vm_bytes_to_count(disturb_bytes_len(target->obj), DISTURB_T_FLOAT);
                if (idx < 0 || idx >= count) {
                    fprintf(stderr, "bytecode error at pc %zu: STORE_INDEX out of bounds\n", pc);
                    return 0;
                }
                Int iv = 0;
                Float fv = 0;
                int is_float = 0;
                if (!vm_entry_number(value, &iv, &fv, &is_float, "STORE_INDEX", pc)) {
                    return 0;
                }
                vm_write_float_at(target->obj, idx, is_float ? fv : (Float)iv);
                break;
            }

            if (type == DISTURB_T_TABLE) {
                Int pos = idx + 2;
                if (idx < 0 || pos >= target->obj->size) {
                    fprintf(stderr, "bytecode error at pc %zu: STORE_INDEX out of bounds\n", pc);
                    return 0;
                }
                ObjEntry *copy = vm_clone_entry_shallow(vm, value, NULL);
                if (!copy) {
                    fprintf(stderr, "bytecode error at pc %zu: STORE_INDEX clone failed\n", pc);
                    return 0;
                }
                target->obj->data[pos].p = copy;
                break;
            }

            fprintf(stderr, "bytecode error at pc %zu: STORE_INDEX unsupported type %s\n",
                    pc, disturb_type_name(type));
            return 0;
        }
        case BC_LOAD_ROOT:
            vm_stack_push_entry(vm, vm->global_entry);
            break;
        case BC_LOAD_GLOBAL: {
            unsigned char *name = NULL;
            size_t name_len = 0;
            if (!bc_read_string(data, len, &pc, &name, &name_len)) {
                fprintf(stderr, "bytecode error at pc %zu: truncated LOAD_GLOBAL\n", pc);
                return 0;
            }
            ObjEntry *entry = NULL;
            if (vm->local_entry) {
                entry = vm_object_find_direct(vm->local_entry->obj, (char*)name, name_len);
            }
            if (!entry) {
                entry = vm_object_find_by_key_len(vm, vm->global_entry->obj, (char*)name, name_len);
            }
            free(name);
            vm_stack_push_entry(vm, entry);
            break;
        }
        case BC_LOAD_THIS:
            vm_stack_push_entry(vm, vm->this_entry ? vm->this_entry : vm->null_entry);
            break;
        case BC_STORE_GLOBAL: {
            unsigned char *name = NULL;
            size_t name_len = 0;
            if (!bc_read_string(data, len, &pc, &name, &name_len)) {
                fprintf(stderr, "bytecode error at pc %zu: truncated STORE_GLOBAL\n", pc);
                return 0;
            }
            ObjEntry *value = vm_stack_pop_entry(vm, "STORE_GLOBAL", pc);
            if (!value) {
                free(name);
                return 0;
            }
            int ok = 0;
            if (vm->local_entry) {
                ok = vm_object_set_by_key_len(vm, &vm->local_entry->obj, (char*)name, name_len, value, pc);
            } else {
                ok = vm_object_set_by_key_len(vm, &vm->global_entry->obj, (char*)name, name_len, value, pc);
            }
            free(name);
            if (!ok) return 0;
            break;
        }
        case BC_SET_THIS: {
            ObjEntry *value = vm_stack_pop_entry(vm, "SET_THIS", pc);
            vm->this_entry = value ? value : vm->null_entry;
            break;
        }
        case BC_STRICT:
            vm->strict_mode = 1;
            break;
        case BC_CALL:
        case BC_CALL_EX: {
            unsigned char *name = NULL;
            size_t name_len = 0;
            if (!bc_read_string(data, len, &pc, &name, &name_len)) {
                fprintf(stderr, "bytecode error at pc %zu: truncated CALL\n", pc);
                return 0;
            }
            uint32_t argc = 0;
            if (!bc_read_u32(data, len, &pc, &argc)) {
                fprintf(stderr, "bytecode error at pc %zu: truncated CALL argc\n", pc);
                free(name);
                return 0;
            }
            Int override_len = -1;
            int has_override = 0;
            if (op == BC_CALL_EX) {
                uint32_t override_u32 = 0;
                if (!bc_read_u32(data, len, &pc, &override_u32)) {
                    fprintf(stderr, "bytecode error at pc %zu: truncated CALL_EX override\n", pc);
                    free(name);
                    return 0;
                }
                override_len = (Int)override_u32;
                has_override = 1;
            }
            ObjEntry *old_this = vm->this_entry;
            Int old_argc = 0;
            if (vm->argc_entry) {
                vm_read_int_at(vm->argc_entry->obj, 0, &old_argc);
            }
            vm_set_argc(vm, argc);
            Int old_override = vm->call_override_len;
            int old_has_override = vm->has_call_override;
            vm->call_override_len = override_len;
            vm->has_call_override = has_override;
            Int stack_before = vm->stack_entry->obj->size;
            ObjEntry *target = NULL;
            ObjEntry *old_call_entry = vm->call_entry;
            if (vm->this_entry && vm->this_entry->in_use) {
                Int this_type = disturb_obj_type(vm->this_entry->obj);
                if (this_type == DISTURB_T_TABLE) {
                    target = vm_object_find_by_key_len(vm, vm->this_entry->obj, (char*)name, name_len);
                    if (target == vm->null_entry) target = NULL;
                } else if (this_type == DISTURB_T_INT || this_type == DISTURB_T_FLOAT || this_type == DISTURB_T_VIEW) {
                    if (vm->common_entry) {
                        target = vm_object_find_direct(vm->common_entry->obj, (char*)name, name_len);
                    }
                }
            }
            ObjEntry *entry = vm_object_find_by_key_len(vm, vm->global_entry->obj, (char*)name, name_len);
            if (entry == vm->null_entry) entry = NULL;
            if (!target) target = entry;
            if (!target) {
                fprintf(stderr, "bytecode error at pc %zu: unknown native '%s'\n", pc, name);
                free(name);
                return 0;
            }
            free(name);
            if (disturb_obj_type(target->obj) == DISTURB_T_NATIVE) {
                vm->call_entry = target;
                if (target->obj->size < 3) {
                    fprintf(stderr, "bytecode error at pc %zu: CALL missing function\n", pc);
                    return 0;
                }
                NativeBox *box = (NativeBox*)target->obj->data[2].p;
                NativeFn fn = box ? box->fn : NULL;
                if (!fn) {
                    fprintf(stderr, "bytecode error at pc %zu: CALL null function\n", pc);
                    return 0;
                }
                fn(vm, vm->stack_entry->obj, vm->global_entry->obj);
            } else if (disturb_obj_type(target->obj) == DISTURB_T_LAMBDA) {
                vm->call_entry = target;
                if (target->obj->size < 3) {
                    fprintf(stderr, "bytecode error at pc %zu: CALL missing function\n", pc);
                    return 0;
                }
                FunctionBox *box = (FunctionBox*)target->obj->data[2].p;
                if (!box) {
                    fprintf(stderr, "bytecode error at pc %zu: CALL null function\n", pc);
                    return 0;
                }
                ObjEntry *old_local = vm->local_entry;
                ObjEntry *local = vm_make_table_value(vm, (Int)box->argc);
                vm->local_entry = local;
                if (!vm_bind_args(vm, box, vm->stack_entry->obj, argc, local)) {
                    fprintf(stderr, "bytecode error at pc %zu: CALL arg bind failed\n", pc);
                    vm->local_entry = old_local;
                    if (local) vm_release_local_scope(vm, local, vm->stack_entry->obj);
                    return 0;
                }
                if (!vm_exec_bytecode(vm, box->code, box->len)) {
                    vm->local_entry = old_local;
                    if (local) vm_release_local_scope(vm, local, vm->stack_entry->obj);
                    return 0;
                }
                vm->local_entry = old_local;
                if (local) vm_release_local_scope(vm, local, vm->stack_entry->obj);
            } else {
                fprintf(stderr, "bytecode error at pc %zu: CALL target not callable\n", pc);
                return 0;
            }
            int has_return = vm->stack_entry->obj->size > stack_before;
            if (argc > 0 && vm->stack_entry->obj->size >= stack_before) {
                Int start = (Int)stack_before - (Int)argc;
                vm_stack_remove_range(vm->stack_entry->obj, start, (Int)argc);
            }
            if (!has_return) {
                vm_stack_push_entry(vm, vm->null_entry);
            }
            vm->this_entry = old_this;
            vm->call_override_len = old_override;
            vm->has_call_override = old_has_override;
            vm->call_entry = old_call_entry;
            if (vm->argc_entry && vm->argc_entry->obj->size >= 3) {
                vm_set_int_single(vm->argc_entry->obj, old_argc);
            }
            break;
        }
        case BC_JMP: {
            uint32_t target = 0;
            if (!bc_read_u32(data, len, &pc, &target)) {
                fprintf(stderr, "bytecode error at pc %zu: truncated JMP\n", pc);
                return 0;
            }
            if (target > len) {
                fprintf(stderr, "bytecode error at pc %zu: JMP out of bounds\n", pc);
                return 0;
            }
            pc = target;
            break;
        }
        case BC_JMP_IF_FALSE: {
            uint32_t target = 0;
            if (!bc_read_u32(data, len, &pc, &target)) {
                fprintf(stderr, "bytecode error at pc %zu: truncated JMP_IF_FALSE\n", pc);
                return 0;
            }
            if (target > len) {
                fprintf(stderr, "bytecode error at pc %zu: JMP_IF_FALSE out of bounds\n", pc);
                return 0;
            }
            ObjEntry *value = vm_stack_pop_entry(vm, "JMP_IF_FALSE", pc);
            if (!value) return 0;
            if (!vm_entry_truthy(value)) {
                pc = target;
            }
            break;
        }
        case BC_RETURN:
            return 1;
        case BC_ADD:
        case BC_SUB:
        case BC_MUL:
        case BC_DIV:
        case BC_MOD:
        case BC_EQ:
        case BC_NEQ:
        case BC_LT:
        case BC_LTE:
        case BC_GT:
        case BC_GTE:
        case BC_AND:
        case BC_OR: {
            ObjEntry *right = vm_stack_pop_entry(vm, "OP", pc);
            ObjEntry *left = vm_stack_pop_entry(vm, "OP", pc);
            if (!left || !right) return 0;
            if (op == BC_ADD &&
                (entry_is_string(left) || entry_is_string(right))) {
                StrBuf buf;
                sb_init(&buf);
                vm_append_value_text(vm, left, &buf, 1);
                vm_append_value_text(vm, right, &buf, 1);
                ObjEntry *entry = vm_reg_alloc(vm, vm_alloc_bytes(vm, DISTURB_T_INT, NULL, buf.data, buf.len));
                if (entry) {
                    entry->is_string = 1;
                    entry->explicit_string = left->explicit_string || right->explicit_string;
                }
                sb_free(&buf);
                vm_stack_push_entry(vm, entry);
                break;
            }
            if (vm->strict_mode) {
                Int lt = disturb_obj_type(left->obj);
                Int rt = disturb_obj_type(right->obj);
                if (lt == DISTURB_T_NULL || rt == DISTURB_T_NULL) {
                    fprintf(stderr, "bytecode error at pc %zu: strict mode forbids null in numeric ops\n", pc);
                    return 0;
                }
            }
            if (op == BC_AND || op == BC_OR) {
                int l = vm_entry_truthy(left);
                int r = vm_entry_truthy(right);
                int res = op == BC_AND ? (l && r) : (l || r);
                vm_stack_push_entry(vm, vm_make_int_value(vm, res ? 1 : 0));
                break;
            }
            if (op == BC_EQ || op == BC_NEQ) {
                if (vm->strict_mode) {
                    Int lt = disturb_obj_type(left->obj);
                    Int rt = disturb_obj_type(right->obj);
                    if ((lt == DISTURB_T_INT || lt == DISTURB_T_FLOAT) &&
                        (rt == DISTURB_T_INT && entry_is_string(right))) {
                        fprintf(stderr, "bytecode error at pc %zu: strict mode forbids number/string comparisons\n", pc);
                        return 0;
                    }
                    if ((rt == DISTURB_T_INT || rt == DISTURB_T_FLOAT) &&
                        (lt == DISTURB_T_INT && entry_is_string(left))) {
                        fprintf(stderr, "bytecode error at pc %zu: strict mode forbids number/string comparisons\n", pc);
                        return 0;
                    }
                    if ((lt == DISTURB_T_INT || lt == DISTURB_T_FLOAT) &&
                        (rt == DISTURB_T_INT || rt == DISTURB_T_FLOAT) &&
                        lt != rt) {
                        fprintf(stderr, "bytecode error at pc %zu: strict mode forbids mixed numeric types\n", pc);
                        return 0;
                    }
                }
                int eq = vm_entry_equal(left, right);
                int res = op == BC_EQ ? eq : !eq;
                vm_stack_push_entry(vm, vm_make_int_value(vm, res ? 1 : 0));
                break;
            }
            if (op == BC_LT || op == BC_LTE || op == BC_GT || op == BC_GTE) {
                if (vm->strict_mode) {
                    Int lt = disturb_obj_type(left->obj);
                    Int rt = disturb_obj_type(right->obj);
                    if ((lt == DISTURB_T_INT || lt == DISTURB_T_FLOAT) &&
                        (rt == DISTURB_T_INT && entry_is_string(right))) {
                        fprintf(stderr, "bytecode error at pc %zu: strict mode forbids number/string comparisons\n", pc);
                        return 0;
                    }
                    if ((rt == DISTURB_T_INT || rt == DISTURB_T_FLOAT) &&
                        (lt == DISTURB_T_INT && entry_is_string(left))) {
                        fprintf(stderr, "bytecode error at pc %zu: strict mode forbids number/string comparisons\n", pc);
                        return 0;
                    }
                    if ((lt == DISTURB_T_INT || lt == DISTURB_T_FLOAT) &&
                        (rt == DISTURB_T_INT || rt == DISTURB_T_FLOAT) &&
                        lt != rt) {
                        fprintf(stderr, "bytecode error at pc %zu: strict mode forbids mixed numeric types\n", pc);
                        return 0;
                    }
                }
                int cmp = 0;
                if (!vm_entry_compare(left, right, &cmp)) {
                    fprintf(stderr, "bytecode error at pc %zu: comparison expects matching number/string types\n", pc);
                    return 0;
                }
                int res = 0;
                if (op == BC_LT) res = cmp < 0;
                else if (op == BC_LTE) res = cmp <= 0;
                else if (op == BC_GT) res = cmp > 0;
                else if (op == BC_GTE) res = cmp >= 0;
                vm_stack_push_entry(vm, vm_make_int_value(vm, res ? 1 : 0));
                break;
            }

            Int li = 0;
            Int ri = 0;
            Float lf = 0;
            Float rf = 0;
            int lf_is_float = 0;
            int rf_is_float = 0;
            if (!vm_entry_number(left, &li, &lf, &lf_is_float, "OP", pc)) return 0;
            if (!vm_entry_number(right, &ri, &rf, &rf_is_float, "OP", pc)) return 0;
            if (vm->strict_mode && lf_is_float != rf_is_float) {
                fprintf(stderr, "bytecode error at pc %zu: strict mode forbids mixed numeric types\n", pc);
                return 0;
            }
            double l = lf_is_float ? (double)lf : (double)li;
            double r = rf_is_float ? (double)rf : (double)ri;
            double out = 0.0;
            switch (op) {
            case BC_ADD: out = l + r; break;
            case BC_SUB: out = l - r; break;
            case BC_MUL: out = l * r; break;
            case BC_DIV: out = l / r; break;
            case BC_MOD: out = fmod(l, r); break;
            default: break;
            }
            vm_stack_push_entry(vm, vm_make_number_result(vm, out));
            break;
        }
        case BC_NEG: {
            ObjEntry *value = vm_stack_pop_entry(vm, "NEG", pc);
            if (!value) return 0;
            if (vm->strict_mode && disturb_obj_type(value->obj) == DISTURB_T_NULL) {
                fprintf(stderr, "bytecode error at pc %zu: strict mode forbids null in numeric ops\n", pc);
                return 0;
            }
            Int iv = 0;
            Float fv = 0;
            int is_float = 0;
            if (!vm_entry_number(value, &iv, &fv, &is_float, "NEG", pc)) return 0;
            double out = is_float ? -(double)fv : -(double)iv;
            vm_stack_push_entry(vm, vm_make_number_result(vm, out));
            break;
        }
        case BC_NOT: {
            ObjEntry *value = vm_stack_pop_entry(vm, "NOT", pc);
            if (!value) return 0;
            int res = vm_entry_truthy(value) ? 0 : 1;
            vm_stack_push_entry(vm, vm_make_int_value(vm, res));
            break;
        }
        case BC_POP:
            vm_pop_stack(vm);
            break;
        case BC_DUP: {
            ObjEntry *top = vm_stack_peek(vm->stack_entry->obj, 0);
            if (!top) {
                fprintf(stderr, "bytecode error at pc %zu: DUP empty stack\n", pc);
                return 0;
            }
            Int type = disturb_obj_type(top->obj);
            if (type == DISTURB_T_INT || type == DISTURB_T_FLOAT) {
                ObjEntry *dup = vm_clone_entry_deep(vm, top, NULL);
                if (!dup) return 0;
                vm_stack_push_entry(vm, dup);
            } else {
                vm_stack_push_entry(vm, top);
            }
            break;
        }
        case BC_GC:
            vm_gc(vm);
            break;
        case BC_DUMP:
            vm_dump_global(vm);
            break;
        default:
            fprintf(stderr, "bytecode error at pc %zu: unknown opcode %u\n", pc, (unsigned)op);
            return 0;
        }
    }
    return 1;
}

ObjEntry *vm_eval_source(VM *vm, const char *src, size_t len)
{
    if (!vm || !src) return NULL;
    char *buf = (char*)malloc(len + 1);
    if (!buf) return NULL;
    memcpy(buf, src, len);
    buf[len] = 0;

    Bytecode bc;
    char err[256];
    err[0] = 0;
    if (!vm_compile_source(buf, &bc, err, sizeof(err))) {
        fprintf(stderr, "%s\n", err[0] ? err : "eval error");
        free(buf);
        return NULL;
    }
    free(buf);

    Int stack_before = vm->stack_entry->obj->size;
    if (!vm_exec_bytecode(vm, bc.data, bc.len)) {
        bc_free(&bc);
        return NULL;
    }
    List *stack = vm->stack_entry->obj;
    ObjEntry *result = NULL;
    if (stack->size > stack_before) {
        result = (ObjEntry*)stack->data[stack->size - 1].p;
    }
    while (stack->size > stack_before) {
        disturb_pop(stack);
    }
    bc_free(&bc);
    return result ? result : vm->null_entry;
}
