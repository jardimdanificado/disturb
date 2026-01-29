#include "urb_runtime.h"
#include "bytecode.h"
#include "urb.h"
#include "urb_bridge.h"

#include <ctype.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int vm_compile_source(const char *src, Bytecode *out, char *err, size_t err_cap);

typedef struct UObj UObj;
typedef struct UEntry UEntry;
typedef struct UFunc UFunc;
typedef struct UNative UNative;
typedef struct UrbVM UrbVM;

typedef void (*UrbNativeFn)(UrbVM *vm, List *stack, UEntry *global);

enum {
    U_T_NULL = 0,
    U_T_INT,
    U_T_FLOAT,
    U_T_TABLE,
    U_T_NATIVE,
    U_T_LAMBDA,
    U_T_VIEW
};

struct UObj {
    int type;
    union {
        struct {
            unsigned char *data;
            size_t len;
        } bytes;
        struct {
            UEntry **items;
            size_t size;
            size_t cap;
        } table;
        struct {
            UNative *native;
        } native;
        struct {
            UFunc *func;
        } lambda;
        struct {
            void *view;
        } view;
    } as;
};

struct UEntry {
    UObj *obj;
    UEntry *key;
    unsigned is_string : 1;
    unsigned explicit_string : 1;
};

struct UNative {
    UrbNativeFn fn;
    void *data;
    void (*free_data)(void *data);
};

struct UFunc {
    List *mem;
    uint32_t argc;
    int has_vararg;
    char **arg_names;
    size_t *arg_lens;
    List **default_mem;
    uint8_t *has_default;
};

struct UrbVM {
    UEntry *global_entry;
    UEntry *stack_entry;
    UEntry *local_entry;
    UEntry *null_entry;
    UEntry *common_entry;
    UEntry *argc_entry;
    UEntry *this_entry;
    int strict_mode;
    Int call_override_len;
    int has_call_override;
    List *exec;
};

static UrbVM *g_vm = NULL;

static UObj *uobj_new(int type);
static UEntry *uent_new(UObj *obj);
static int table_set_by_key_len(UEntry *table, const char *name, size_t len, UEntry *value);
static void stack_push_entry(List *stack, UEntry *entry);
static void exec_bytecode_in_vm(UrbVM *vm, const unsigned char *data, size_t len, List *stack);

static void register_native(UrbVM *v, const char *name, UrbNativeFn fn, int to_common)
{
    UObj *native_obj = uobj_new(U_T_NATIVE);
    UNative *box = (UNative*)calloc(1, sizeof(UNative));
    box->fn = fn;
    native_obj->as.native.native = box;
    UEntry *entry = uent_new(native_obj);
    table_set_by_key_len(v->global_entry, name, strlen(name), entry);
    if (to_common && v->common_entry) {
        table_set_by_key_len(v->common_entry, name, strlen(name), entry);
    }
}

static const char *u_type_name(int type)
{
    switch (type) {
    case U_T_NULL: return "null";
    case U_T_INT: return "int";
    case U_T_FLOAT: return "float";
    case U_T_TABLE: return "table";
    case U_T_NATIVE: return "native";
    case U_T_LAMBDA: return "lambda";
    case U_T_VIEW: return "view";
    default: return "unknown";
    }
}

static UObj *uobj_new(int type)
{
    UObj *obj = (UObj*)calloc(1, sizeof(UObj));
    if (!obj) return NULL;
    obj->type = type;
    return obj;
}

static UEntry *uent_new(UObj *obj)
{
    UEntry *entry = (UEntry*)calloc(1, sizeof(UEntry));
    if (!entry) return NULL;
    entry->obj = obj;
    return entry;
}

static UEntry *uent_make_null(void)
{
    UObj *obj = uobj_new(U_T_NULL);
    return uent_new(obj);
}

static UEntry *uent_make_int_scalar(Int v)
{
    UObj *obj = uobj_new(U_T_INT);
    if (!obj) return NULL;
    obj->as.bytes.len = sizeof(Int);
    obj->as.bytes.data = (unsigned char*)malloc(obj->as.bytes.len);
    if (!obj->as.bytes.data) return NULL;
    memcpy(obj->as.bytes.data, &v, sizeof(Int));
    return uent_new(obj);
}

static UEntry *uent_make_float_scalar(Float v)
{
    UObj *obj = uobj_new(U_T_FLOAT);
    if (!obj) return NULL;
    obj->as.bytes.len = sizeof(Float);
    obj->as.bytes.data = (unsigned char*)malloc(obj->as.bytes.len);
    if (!obj->as.bytes.data) return NULL;
    memcpy(obj->as.bytes.data, &v, sizeof(Float));
    return uent_new(obj);
}

static UEntry *uent_make_bytes(const char *s, size_t len, int is_string, int explicit_string)
{
    UObj *obj = uobj_new(U_T_INT);
    if (!obj) return NULL;
    obj->as.bytes.len = len;
    obj->as.bytes.data = NULL;
    if (len) {
        obj->as.bytes.data = (unsigned char*)malloc(len);
        if (!obj->as.bytes.data) return NULL;
        memcpy(obj->as.bytes.data, s, len);
    }
    UEntry *entry = uent_new(obj);
    if (entry) {
        entry->is_string = is_string ? 1 : 0;
        entry->explicit_string = explicit_string ? 1 : 0;
    }
    return entry;
}

static UEntry *uent_make_string(const char *s, size_t len)
{
    return uent_make_bytes(s, len, 1, 1);
}

static UEntry *uent_make_int_list(Int count)
{
    if (count < 0) count = 0;
    UObj *obj = uobj_new(U_T_INT);
    if (!obj) return NULL;
    obj->as.bytes.len = (size_t)count * sizeof(Int);
    obj->as.bytes.data = NULL;
    if (obj->as.bytes.len) {
        obj->as.bytes.data = (unsigned char*)calloc(1, obj->as.bytes.len);
        if (!obj->as.bytes.data) return NULL;
    }
    return uent_new(obj);
}

static UEntry *uent_make_float_list(Int count)
{
    if (count < 0) count = 0;
    UObj *obj = uobj_new(U_T_FLOAT);
    if (!obj) return NULL;
    obj->as.bytes.len = (size_t)count * sizeof(Float);
    obj->as.bytes.data = NULL;
    if (obj->as.bytes.len) {
        obj->as.bytes.data = (unsigned char*)calloc(1, obj->as.bytes.len);
        if (!obj->as.bytes.data) return NULL;
    }
    return uent_new(obj);
}

static UEntry *uent_make_table(Int reserve)
{
    if (reserve < 0) reserve = 0;
    UObj *obj = uobj_new(U_T_TABLE);
    if (!obj) return NULL;
    obj->as.table.cap = (size_t)reserve;
    obj->as.table.size = 0;
    obj->as.table.items = reserve > 0 ? (UEntry**)calloc((size_t)reserve, sizeof(UEntry*)) : NULL;
    if (reserve > 0 && !obj->as.table.items) return NULL;
    return uent_new(obj);
}

static int entry_is_string(const UEntry *entry)
{
    return entry && entry->is_string && entry->obj && entry->obj->type == U_T_INT;
}

static size_t entry_bytes_len(const UEntry *entry)
{
    if (!entry || !entry->obj) return 0;
    return entry->obj->as.bytes.len;
}

static unsigned char *entry_bytes_data(const UEntry *entry)
{
    if (!entry || !entry->obj) return NULL;
    return entry->obj->as.bytes.data;
}

static Int entry_bytes_count(const UEntry *entry, int type)
{
    size_t elem = 0;
    if (type == U_T_INT) elem = sizeof(Int);
    if (type == U_T_FLOAT) elem = sizeof(Float);
    if (!elem) return 0;
    return (Int)(entry_bytes_len(entry) / elem);
}

static int entry_read_int(const UEntry *entry, Int index, Int *out)
{
    if (!entry || !entry->obj || entry->obj->type != U_T_INT) return 0;
    size_t off = (size_t)index * sizeof(Int);
    if (off + sizeof(Int) > entry->obj->as.bytes.len) return 0;
    memcpy(out, entry->obj->as.bytes.data + off, sizeof(Int));
    return 1;
}

static int entry_read_float(const UEntry *entry, Int index, Float *out)
{
    if (!entry || !entry->obj || entry->obj->type != U_T_FLOAT) return 0;
    size_t off = (size_t)index * sizeof(Float);
    if (off + sizeof(Float) > entry->obj->as.bytes.len) return 0;
    memcpy(out, entry->obj->as.bytes.data + off, sizeof(Float));
    return 1;
}

static int entry_is_scalar_int(const UEntry *entry)
{
    return entry && entry->obj && entry->obj->type == U_T_INT &&
           entry->obj->as.bytes.len == sizeof(Int);
}

static int entry_is_scalar_float(const UEntry *entry)
{
    return entry && entry->obj && entry->obj->type == U_T_FLOAT &&
           entry->obj->as.bytes.len == sizeof(Float);
}

static void entry_write_int(UEntry *entry, Int index, Int value)
{
    if (!entry || !entry->obj || entry->obj->type != U_T_INT) return;
    size_t off = (size_t)index * sizeof(Int);
    if (off + sizeof(Int) > entry->obj->as.bytes.len) return;
    memcpy(entry->obj->as.bytes.data + off, &value, sizeof(Int));
}

static void entry_write_float(UEntry *entry, Int index, Float value)
{
    if (!entry || !entry->obj || entry->obj->type != U_T_FLOAT) return;
    size_t off = (size_t)index * sizeof(Float);
    if (off + sizeof(Float) > entry->obj->as.bytes.len) return;
    memcpy(entry->obj->as.bytes.data + off, &value, sizeof(Float));
}

static UEntry *entry_clone_shallow(UEntry *src, UEntry *forced_key)
{
    if (!src) return NULL;
    UEntry *out = uent_new(src->obj);
    if (!out) return NULL;
    out->is_string = src->is_string;
    out->explicit_string = src->explicit_string;
    out->key = forced_key ? forced_key : src->key;
    return out;
}

static UEntry *entry_clone_deep(const UEntry *src)
{
    if (!src || !src->obj) return NULL;
    UObj *obj = NULL;
    if (src->obj->type == U_T_INT || src->obj->type == U_T_FLOAT) {
        obj = uobj_new(src->obj->type);
        if (!obj) return NULL;
        obj->as.bytes.len = src->obj->as.bytes.len;
        if (obj->as.bytes.len > 0) {
            obj->as.bytes.data = (unsigned char*)malloc(obj->as.bytes.len);
            if (!obj->as.bytes.data) return NULL;
            memcpy(obj->as.bytes.data, src->obj->as.bytes.data, obj->as.bytes.len);
        }
    } else if (src->obj->type == U_T_TABLE) {
        obj = uobj_new(U_T_TABLE);
        if (!obj) return NULL;
        obj->as.table.cap = src->obj->as.table.size;
        obj->as.table.size = 0;
        obj->as.table.items = obj->as.table.cap ? (UEntry**)calloc(obj->as.table.cap, sizeof(UEntry*)) : NULL;
        if (obj->as.table.cap && !obj->as.table.items) return NULL;
        for (size_t i = 0; i < src->obj->as.table.size; i++) {
            UEntry *child = src->obj->as.table.items[i];
            if (!child) continue;
            UEntry *clone = entry_clone_shallow(child, child->key);
            obj->as.table.items[obj->as.table.size++] = clone;
        }
    } else {
        obj = src->obj;
    }
    UEntry *entry = uent_new(obj);
    if (!entry) return NULL;
    entry->is_string = src->is_string;
    entry->explicit_string = src->explicit_string;
    entry->key = src->key;
    return entry;
}

static UEntry *table_find_by_key_len(UEntry *table, const char *name, size_t len)
{
    if (!table || !table->obj || table->obj->type != U_T_TABLE) return NULL;
    for (size_t i = 0; i < table->obj->as.table.size; i++) {
        UEntry *entry = table->obj->as.table.items[i];
        UEntry *key = entry ? entry->key : NULL;
        if (!entry_is_string(key)) continue;
        if (entry_bytes_len(key) == len &&
            memcmp(entry_bytes_data(key), name, len) == 0) {
            return entry;
        }
    }
    return NULL;
}

static void table_add_entry(UEntry *table, UEntry *entry)
{
    if (!table || !table->obj || table->obj->type != U_T_TABLE || !entry) return;
    if (table->obj->as.table.size == table->obj->as.table.cap) {
        size_t next = table->obj->as.table.cap == 0 ? 8 : table->obj->as.table.cap * 2;
        UEntry **items = (UEntry**)realloc(table->obj->as.table.items, next * sizeof(UEntry*));
        if (!items) return;
        table->obj->as.table.items = items;
        table->obj->as.table.cap = next;
    }
    table->obj->as.table.items[table->obj->as.table.size++] = entry;
}

static int table_set_by_key_len(UEntry *table, const char *name, size_t len, UEntry *value)
{
    if (!table || !table->obj || table->obj->type != U_T_TABLE || !value) return 0;
    for (size_t i = 0; i < table->obj->as.table.size; i++) {
        UEntry *entry = table->obj->as.table.items[i];
        UEntry *key = entry ? entry->key : NULL;
        if (!entry_is_string(key)) continue;
        if (entry_bytes_len(key) == len &&
            memcmp(entry_bytes_data(key), name, len) == 0) {
            UEntry *copy = entry_clone_shallow(value, key);
            table->obj->as.table.items[i] = copy;
            return 1;
        }
    }
    UEntry *key_entry = uent_make_bytes(name, len, 1, 1);
    UEntry *copy = entry_clone_shallow(value, key_entry);
    table_add_entry(table, copy);
    return 1;
}

static int entry_truthy(const UEntry *entry)
{
    if (!entry || !entry->obj) return 0;
    int type = entry->obj->type;
    if (type == U_T_NULL) return 0;
    if (type == U_T_INT && !entry_is_string(entry)) {
        if (entry->obj->as.bytes.len == sizeof(Int)) {
            Int v = 0;
            memcpy(&v, entry->obj->as.bytes.data, sizeof(Int));
            if (v == 0) return 0;
        }
    }
    if (type == U_T_FLOAT) {
        if (entry->obj->as.bytes.len == sizeof(Float)) {
            Float v = 0;
            memcpy(&v, entry->obj->as.bytes.data, sizeof(Float));
            if (v == 0) return 0;
        }
    }
    return 1;
}

static int entry_number(const UEntry *entry, Int *out_i, Float *out_f, int *out_is_float)
{
    if (!entry || !entry->obj) return 0;
    int type = entry->obj->type;
    if (type == U_T_INT) {
        if (entry_is_string(entry)) return 0;
        if (entry->obj->as.bytes.len != sizeof(Int)) return 0;
        Int v = 0;
        memcpy(&v, entry->obj->as.bytes.data, sizeof(Int));
        if (out_i) *out_i = v;
        if (out_f) *out_f = (Float)v;
        if (out_is_float) *out_is_float = 0;
        return 1;
    }
    if (type == U_T_FLOAT) {
        if (entry->obj->as.bytes.len != sizeof(Float)) return 0;
        Float v = 0;
        memcpy(&v, entry->obj->as.bytes.data, sizeof(Float));
        if (out_i) *out_i = (Int)v;
        if (out_f) *out_f = v;
        if (out_is_float) *out_is_float = 1;
        return 1;
    }
    return 0;
}

static int entry_number_to_int(const UEntry *entry, Int *out)
{
    Int iv = 0;
    Float fv = 0;
    int is_float = 0;
    if (!entry_number(entry, &iv, &fv, &is_float)) return 0;
    if (is_float) {
        Int cast = (Int)fv;
        if ((Float)cast != fv) return 0;
        iv = cast;
    }
    *out = iv;
    return 1;
}

static int entry_as_number(UEntry *entry, Float *out)
{
    Int iv = 0;
    Float fv = 0;
    int is_float = 0;
    if (!entry_number(entry, &iv, &fv, &is_float)) return 0;
    *out = is_float ? fv : (Float)iv;
    return 1;
}

static int entry_as_string(UEntry *entry, const char **out, size_t *len)
{
    if (!entry || !entry_is_string(entry)) return 0;
    *out = (const char*)entry_bytes_data(entry);
    *len = entry_bytes_len(entry);
    return 1;
}

static void push_entry(List *stack, UEntry *entry)
{
    if (!stack || !entry) return;
    stack_push_entry(stack, entry);
}

static void push_number(List *stack, double value)
{
    if (!stack) return;
    if (value >= (double)INT_MIN && value <= (double)INT_MAX) {
        Int iv = (Int)value;
        if ((double)iv == value) {
            push_entry(stack, uent_make_int_scalar(iv));
            return;
        }
    }
    push_entry(stack, uent_make_float_scalar((Float)value));
}

static void push_string(List *stack, const char *s, size_t len)
{
    push_entry(stack, uent_make_bytes(s, len, 1, 1));
}

static Int list_pos_from_index(UEntry *obj, Int index)
{
    if (!obj || !obj->obj || obj->obj->type != U_T_TABLE) return 0;
    Int size = (Int)obj->obj->as.table.size;
    if (index < 0) index = size + index;
    return index;
}

static int list_index_valid(UEntry *obj, Int index)
{
    if (!obj || !obj->obj || obj->obj->type != U_T_TABLE) return 0;
    Int size = (Int)obj->obj->as.table.size;
    if (index < 0) index = size + index;
    return index >= 0 && index < size;
}

static Int bytes_list_count(UEntry *entry, size_t elem_size)
{
    size_t len = entry_bytes_len(entry);
    if (elem_size == 0) return 0;
    return (Int)(len / elem_size);
}

static int bytes_list_index(Int count, Int index, Int *out_index)
{
    if (index < 0) index = count + index;
    if (index < 0 || index >= count) return 0;
    *out_index = index;
    return 1;
}

static Int bytes_list_insert_index(Int count, Int index)
{
    if (index < 0) index = count + index;
    if (index < 0) return 0;
    if (index > count) return count;
    return index;
}

static int bytes_list_insert(UEntry *target, size_t offset, const void *data, size_t len)
{
    if (!target || !target->obj) return 0;
    size_t old_len = target->obj->as.bytes.len;
    size_t new_len = old_len + len;
    unsigned char *buf = (unsigned char*)realloc(target->obj->as.bytes.data, new_len);
    if (!buf && new_len > 0) return 0;
    target->obj->as.bytes.data = buf;
    memmove(buf + offset + len, buf + offset, old_len - offset);
    memcpy(buf + offset, data, len);
    target->obj->as.bytes.len = new_len;
    return 1;
}

static int bytes_list_remove(UEntry *target, size_t offset, void *out, size_t len)
{
    if (!target || !target->obj) return 0;
    size_t old_len = target->obj->as.bytes.len;
    if (offset + len > old_len) return 0;
    if (out) memcpy(out, target->obj->as.bytes.data + offset, len);
    memmove(target->obj->as.bytes.data + offset,
            target->obj->as.bytes.data + offset + len,
            old_len - offset - len);
    target->obj->as.bytes.len = old_len - len;
    target->obj->as.bytes.data = (unsigned char*)realloc(target->obj->as.bytes.data, target->obj->as.bytes.len);
    return 1;
}

static int entry_equal(UEntry *a, UEntry *b)
{
    if (a == b) return 1;
    if (!a || !b || !a->obj || !b->obj) return 0;
    int at = a->obj->type;
    int bt = b->obj->type;
    if ((at == U_T_INT && entry_is_string(a)) ||
        (bt == U_T_INT && entry_is_string(b))) {
        if (!(at == U_T_INT && entry_is_string(a) && bt == U_T_INT && entry_is_string(b))) {
            return 0;
        }
        size_t al = entry_bytes_len(a);
        size_t bl = entry_bytes_len(b);
        if (al != bl) return 0;
        return memcmp(entry_bytes_data(a), entry_bytes_data(b), al) == 0;
    }
    if ((at == U_T_INT || at == U_T_FLOAT) &&
        (bt == U_T_INT || bt == U_T_FLOAT)) {
        size_t asz = at == U_T_INT ? sizeof(Int) : sizeof(Float);
        size_t bsz = bt == U_T_INT ? sizeof(Int) : sizeof(Float);
        if (a->obj->as.bytes.len == asz && b->obj->as.bytes.len == bsz) {
            double av = 0.0;
            double bv = 0.0;
            if (at == U_T_INT) {
                Int v = 0;
                memcpy(&v, a->obj->as.bytes.data, sizeof(Int));
                av = (double)v;
            } else {
                Float v = 0;
                memcpy(&v, a->obj->as.bytes.data, sizeof(Float));
                av = (double)v;
            }
            if (bt == U_T_INT) {
                Int v = 0;
                memcpy(&v, b->obj->as.bytes.data, sizeof(Int));
                bv = (double)v;
            } else {
                Float v = 0;
                memcpy(&v, b->obj->as.bytes.data, sizeof(Float));
                bv = (double)v;
            }
            return av == bv;
        }
        if (at != bt) return 0;
        Int ac = entry_bytes_count(a, at);
        Int bc = entry_bytes_count(b, bt);
        if (ac != bc) return 0;
        if (at == U_T_INT) {
            for (Int i = 0; i < ac; i++) {
                Int av = 0;
                Int bv = 0;
                if (!entry_read_int(a, i, &av) || !entry_read_int(b, i, &bv)) return 0;
                if (av != bv) return 0;
            }
        } else {
            for (Int i = 0; i < ac; i++) {
                Float av = 0;
                Float bv = 0;
                if (!entry_read_float(a, i, &av) || !entry_read_float(b, i, &bv)) return 0;
                if (av != bv) return 0;
            }
        }
        return 1;
    }
    if (at == U_T_NULL) return 1;
    return 0;
}

static int entry_compare(UEntry *a, UEntry *b, int *out)
{
    if (!a || !b || !a->obj || !b->obj) return 0;
    int at = a->obj->type;
    int bt = b->obj->type;
    if ((at == U_T_INT && entry_is_string(a)) ||
        (bt == U_T_INT && entry_is_string(b))) {
        if (!(at == U_T_INT && entry_is_string(a) && bt == U_T_INT && entry_is_string(b))) {
            return 0;
        }
        size_t al = entry_bytes_len(a);
        size_t bl = entry_bytes_len(b);
        size_t min = al < bl ? al : bl;
        int cmp = memcmp(entry_bytes_data(a), entry_bytes_data(b), min);
        if (cmp < 0) *out = -1;
        else if (cmp > 0) *out = 1;
        else if (al < bl) *out = -1;
        else if (al > bl) *out = 1;
        else *out = 0;
        return 1;
    }
    if ((at == U_T_INT || at == U_T_FLOAT) &&
        (bt == U_T_INT || bt == U_T_FLOAT)) {
        double av = 0.0;
        double bv = 0.0;
        if (at == U_T_INT) {
            Int v = 0;
            memcpy(&v, a->obj->as.bytes.data, sizeof(Int));
            av = (double)v;
        } else {
            Float v = 0;
            memcpy(&v, a->obj->as.bytes.data, sizeof(Float));
            av = (double)v;
        }
        if (bt == U_T_INT) {
            Int v = 0;
            memcpy(&v, b->obj->as.bytes.data, sizeof(Int));
            bv = (double)v;
        } else {
            Float v = 0;
            memcpy(&v, b->obj->as.bytes.data, sizeof(Float));
            bv = (double)v;
        }
        if (av < bv) *out = -1;
        else if (av > bv) *out = 1;
        else *out = 0;
        return 1;
    }
    return 0;
}

static Int entry_value_len(const UEntry *entry)
{
    if (!entry || !entry->obj) return 0;
    int type = entry->obj->type;
    switch (type) {
    case U_T_NULL:
        return 0;
    case U_T_INT:
        if (entry_is_string(entry)) {
            return (Int)entry_bytes_len(entry);
        }
        return entry_bytes_count(entry, U_T_INT);
    case U_T_FLOAT:
        return entry_bytes_count(entry, U_T_FLOAT);
    case U_T_TABLE:
        return (Int)entry->obj->as.table.size;
    case U_T_NATIVE:
    case U_T_LAMBDA:
    case U_T_VIEW:
        return 1;
    default:
        return 0;
    }
}

typedef struct {
    char *data;
    size_t len;
    size_t cap;
} StrBuf;

static void sb_init(StrBuf *b)
{
    b->cap = 256;
    b->len = 0;
    b->data = (char*)malloc(b->cap);
    b->data[0] = 0;
}

static void sb_grow(StrBuf *b, size_t add)
{
    size_t need = b->len + add + 1;
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

static void sb_append_int(StrBuf *b, Int v)
{
    char buf[64];
    snprintf(buf, sizeof(buf), "%lld", (long long)v);
    sb_append_n(b, buf, strlen(buf));
}

static void sb_append_number(StrBuf *b, double v)
{
    double iv = 0.0;
    double frac = modf(v, &iv);
    char buf[64];
    if (frac == 0.0 && iv >= -9.22e18 && iv <= 9.22e18) {
        snprintf(buf, sizeof(buf), "%lld", (long long)iv);
    } else {
        snprintf(buf, sizeof(buf), "%.17g", v);
    }
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

static void sb_free(StrBuf *b)
{
    free(b->data);
    b->data = NULL;
    b->len = 0;
    b->cap = 0;
}

static void append_key_text(StrBuf *b, UEntry *entry)
{
    UEntry *key = entry ? entry->key : NULL;
    if (!entry_is_string(key)) {
        sb_append_char(b, '_');
        return;
    }
    sb_append_n(b, (const char*)entry_bytes_data(key), entry_bytes_len(key));
}

static void append_value_text(UrbVM *vm, UEntry *entry, StrBuf *b, int raw_string)
{
    if (!entry || !entry->obj) {
        sb_append_n(b, "null", 4);
        return;
    }
    int type = entry->obj->type;
    switch (type) {
    case U_T_NULL:
        sb_append_n(b, "null", 4);
        break;
    case U_T_INT: {
        if (entry_is_string(entry)) {
            size_t len = entry_bytes_len(entry);
            if (raw_string) {
                sb_append_n(b, (const char*)entry_bytes_data(entry), len);
                break;
            }
            if (len == 1) {
                sb_append_char(b, '\'');
                sb_append_escaped(b, (const char*)entry_bytes_data(entry), len);
                sb_append_char(b, '\'');
            } else {
                sb_append_char(b, '"');
                sb_append_escaped(b, (const char*)entry_bytes_data(entry), len);
                sb_append_char(b, '"');
            }
            break;
        }
        Int count = entry_bytes_count(entry, U_T_INT);
        if (count == 0) {
            sb_append_n(b, "[]", 2);
            break;
        }
        if (count == 1) {
            Int v = 0;
            if (entry_read_int(entry, 0, &v)) sb_append_int(b, v);
            else sb_append_n(b, "0", 1);
            break;
        }
        sb_append_char(b, '[');
        for (Int i = 0; i < count; i++) {
            Int v = 0;
            if (i) sb_append_n(b, ", ", 2);
            if (entry_read_int(entry, i, &v)) sb_append_int(b, v);
            else sb_append_n(b, "0", 1);
        }
        sb_append_char(b, ']');
        break;
    }
    case U_T_FLOAT: {
        Int count = entry_bytes_count(entry, U_T_FLOAT);
        if (count == 0) {
            sb_append_n(b, "[]", 2);
            break;
        }
        if (count == 1) {
            Float v = 0;
            if (entry_read_float(entry, 0, &v)) sb_append_number(b, v);
            else sb_append_n(b, "0", 1);
            break;
        }
        sb_append_char(b, '[');
        for (Int i = 0; i < count; i++) {
            Float v = 0;
            if (i) sb_append_n(b, ", ", 2);
            if (entry_read_float(entry, i, &v)) sb_append_number(b, v);
            else sb_append_n(b, "0", 1);
        }
        sb_append_char(b, ']');
        break;
    }
    case U_T_TABLE: {
        sb_append_char(b, '{');
        int first = 1;
        for (size_t i = 0; i < entry->obj->as.table.size; i++) {
            UEntry *child = entry->obj->as.table.items[i];
            if (!child) continue;
            if (!first) sb_append_n(b, ", ", 2);
            first = 0;
            append_key_text(b, child);
            sb_append_n(b, " = ", 3);
            append_value_text(vm, child, b, 0);
        }
        sb_append_char(b, '}');
        break;
    }
    case U_T_NATIVE:
        sb_append_n(b, "<native>", 8);
        break;
    case U_T_LAMBDA:
        sb_append_n(b, "<function>", 10);
        break;
    default:
        sb_append_n(b, "<data>", 6);
        break;
    }
}

static void print_plain_entry(FILE *out, UrbVM *vm, UEntry *entry)
{
    if (!entry || !entry->obj) {
        fputs("null", out);
        return;
    }
    int type = entry->obj->type;
    int print_as_string = entry_is_string(entry);
    if (vm && vm->strict_mode && print_as_string && !entry->explicit_string) {
        print_as_string = 0;
    }
    switch (type) {
    case U_T_NULL:
        fputs("null", out);
        break;
    case U_T_INT:
        if (print_as_string) {
            fwrite(entry_bytes_data(entry), 1, entry_bytes_len(entry), out);
            break;
        }
        if (entry_is_scalar_int(entry)) {
            Int v = 0;
            char buf[32];
            if (entry_read_int(entry, 0, &v)) {
                int n = snprintf(buf, sizeof(buf), "%lld", (long long)v);
                if (n > 0) fwrite(buf, 1, (size_t)n, out);
            } else {
                fputs("0", out);
            }
            break;
        }
        {
            Int count = entry_bytes_count(entry, U_T_INT);
            for (Int i = 0; i < count; i++) {
                if (i) fputs(" ", out);
                Int v = 0;
                if (entry_read_int(entry, i, &v)) fprintf(out, "%lld", (long long)v);
                else fputs("0", out);
            }
        }
        break;
    case U_T_FLOAT: {
        if (entry_is_scalar_float(entry)) {
            Float v = 0;
            char buf[48];
            if (entry_read_float(entry, 0, &v)) {
                int n = snprintf(buf, sizeof(buf), "%g", (double)v);
                if (n > 0) fwrite(buf, 1, (size_t)n, out);
            } else {
                fputs("0", out);
            }
            break;
        }
        Int count = entry_bytes_count(entry, U_T_FLOAT);
        for (Int i = 0; i < count; i++) {
            if (i) fputs(" ", out);
            Float v = 0;
            if (entry_read_float(entry, i, &v)) fprintf(out, "%g", (double)v);
            else fputs("0", out);
        }
        break;
    }
    case U_T_TABLE:
        for (size_t i = 0; i < entry->obj->as.table.size; i++) {
            if (i) fputs(" ", out);
            UEntry *child = entry->obj->as.table.items[i];
            if (!child) {
                fputs("null", out);
                continue;
            }
            UEntry *key = child->key;
            if (!entry_is_string(key)) {
                fputs("<?>", out);
            } else {
                fwrite(entry_bytes_data(key), 1, entry_bytes_len(key), out);
            }
        }
        break;
    case U_T_NATIVE:
        fputs("<native>", out);
        break;
    default:
        fputs("<data>", out);
        break;
    }
}

static void print_entry(FILE *out, UrbVM *vm, UEntry *entry)
{
    if (!entry || !entry->obj) {
        fputs("null", out);
        return;
    }
    int type = entry->obj->type;
    int print_as_string = entry_is_string(entry);
    if (vm && vm->strict_mode && print_as_string && !entry->explicit_string) {
        print_as_string = 0;
    }
    fputs("[", out);
    fputs(u_type_name(type), out);
    fputs(" ", out);
    if (entry->key && entry_is_string(entry->key)) {
        fwrite(entry_bytes_data(entry->key), 1, entry_bytes_len(entry->key), out);
    } else {
        fputs("_", out);
    }
    fputs("] ", out);
    switch (type) {
    case U_T_NULL:
        fputs("null", out);
        break;
    case U_T_INT:
        if (print_as_string) {
            fputs("\"", out);
            fwrite(entry_bytes_data(entry), 1, entry_bytes_len(entry), out);
            fputs("\"", out);
        } else {
            fputs("[", out);
            if (entry_is_scalar_int(entry)) {
                Int v = 0;
                char buf[32];
                if (entry_read_int(entry, 0, &v)) {
                    int n = snprintf(buf, sizeof(buf), "%lld", (long long)v);
                    if (n > 0) fwrite(buf, 1, (size_t)n, out);
                } else {
                    fputs("0", out);
                }
            } else {
                Int count = entry_bytes_count(entry, U_T_INT);
                for (Int i = 0; i < count; i++) {
                    if (i) fputs(" ", out);
                    Int v = 0;
                    if (entry_read_int(entry, i, &v)) fprintf(out, "%lld", (long long)v);
                    else fputs("0", out);
                }
            }
            fputs("]", out);
        }
        break;
    case U_T_FLOAT:
        fputs("[", out);
        {
            if (entry_is_scalar_float(entry)) {
                Float v = 0;
                char buf[48];
                if (entry_read_float(entry, 0, &v)) {
                    int n = snprintf(buf, sizeof(buf), "%g", (double)v);
                    if (n > 0) fwrite(buf, 1, (size_t)n, out);
                } else {
                    fputs("0", out);
                }
            } else {
                Int count = entry_bytes_count(entry, U_T_FLOAT);
                for (Int i = 0; i < count; i++) {
                    if (i) fputs(" ", out);
                    Float v = 0;
                    if (entry_read_float(entry, i, &v)) fprintf(out, "%g", (double)v);
                    else fputs("0", out);
                }
            }
        }
        fputs("]", out);
        break;
    case U_T_TABLE:
        fputs("[", out);
        for (size_t i = 0; i < entry->obj->as.table.size; i++) {
            if (i) fputs(" ", out);
            UEntry *child = entry->obj->as.table.items[i];
            if (!child) {
                fputs("null", out);
                continue;
            }
            UEntry *key = child->key;
            if (!entry_is_string(key)) {
                fputs("<?>", out);
            } else {
                fwrite(entry_bytes_data(key), 1, entry_bytes_len(key), out);
            }
        }
        fputs("]", out);
        break;
    case U_T_NATIVE:
        fputs("<native>", out);
        break;
    default:
        fputs("<data>", out);
        break;
    }
}

static int print_fast_scalar_plain(FILE *out, UrbVM *vm, UEntry *entry, int newline)
{
    if (!entry || !entry->obj) return 0;
    int type = entry->obj->type;
    if (type == U_T_INT) {
        int print_as_string = entry_is_string(entry);
        if (vm && vm->strict_mode && print_as_string && !entry->explicit_string) {
            print_as_string = 0;
        }
        if (print_as_string || !entry_is_scalar_int(entry)) return 0;
        Int v = 0;
        if (!entry_read_int(entry, 0, &v)) return 0;
        char buf[40];
        int n = snprintf(buf, sizeof(buf), newline ? "%lld\n" : "%lld", (long long)v);
        if (n > 0) fwrite(buf, 1, (size_t)n, out);
        return 1;
    }
    if (type == U_T_FLOAT) {
        int print_as_string = entry_is_string(entry);
        if (vm && vm->strict_mode && print_as_string && !entry->explicit_string) {
            print_as_string = 0;
        }
        if (print_as_string || !entry_is_scalar_float(entry)) return 0;
        Float v = 0;
        if (!entry_read_float(entry, 0, &v)) return 0;
        char buf[64];
        int n = snprintf(buf, sizeof(buf), newline ? "%g\n" : "%g", (double)v);
        if (n > 0) fwrite(buf, 1, (size_t)n, out);
        return 1;
    }
    return 0;
}

static UEntry *stack_pop_entry(List *stack)
{
    Value v = urb_pop(stack);
    return (UEntry*)v.p;
}

static void stack_push_entry(List *stack, UEntry *entry)
{
    Value v;
    v.p = entry;
    urb_push(stack, v);
}

static UEntry *stack_peek_entry(List *stack, Int from_top)
{
    if (!stack || stack->size == 0) return NULL;
    Int idx = (Int)stack->size - 1 - from_top;
    if (idx < 0 || idx >= (Int)stack->size) return NULL;
    return (UEntry*)stack->data[idx].p;
}

static void stack_remove_range(List *stack, Int start, Int count)
{
    if (!stack || count <= 0) return;
    Int end = start + count;
    if (end > stack->size) end = stack->size;
    Int move = stack->size - end;
    if (move > 0) {
        memmove(&stack->data[start], &stack->data[end], (size_t)move * sizeof(Value));
    }
    stack->size -= (UHalf)(end - start);
}

static UEntry *stack_arg(List *stack, uint32_t argc, uint32_t idx)
{
    if (!stack || idx >= argc) return NULL;
    Int base = (Int)stack->size - (Int)argc;
    Int pos = base + (Int)idx;
    if (pos < 0 || pos >= (Int)stack->size) return NULL;
    return (UEntry*)stack->data[pos].p;
}

static uint32_t native_argc(UrbVM *vm)
{
    if (!vm || !vm->argc_entry) return 0;
    Int v = 0;
    if (!entry_read_int(vm->argc_entry, 0, &v)) return 0;
    if (v < 0) return 0;
    return (uint32_t)v;
}

static UEntry *native_arg(List *stack, uint32_t argc, uint32_t idx)
{
    return stack_arg(stack, argc, idx);
}

static UEntry *native_this(UrbVM *vm)
{
    if (!vm) return NULL;
    return vm->this_entry;
}

static UEntry *native_target(UrbVM *vm, List *stack, uint32_t argc)
{
    UEntry *self = native_this(vm);
    if (self) {
        int type = self->obj ? self->obj->type : U_T_NULL;
        if (type == U_T_TABLE || type == U_T_INT || type == U_T_FLOAT) return self;
    }
    return native_arg(stack, argc, 0);
}

static void vm_set_argc(UrbVM *vm, uint32_t argc)
{
    if (!vm || !vm->argc_entry) return;
    entry_write_int(vm->argc_entry, 0, (Int)argc);
}

static void native_print(UrbVM *vm, List *stack, UEntry *global)
{
    (void)global;
    uint32_t argc = native_argc(vm);
    if (argc == 0) {
        if (stack && stack->size > 0) {
            UEntry *entry = (UEntry*)stack->data[stack->size - 1].p;
            print_plain_entry(stdout, vm, entry);
            return;
        }
        fputs("(stack empty)", stdout);
        return;
    }
    if (argc == 1) {
        UEntry *entry = native_arg(stack, argc, 0);
        if (print_fast_scalar_plain(stdout, vm, entry, 1)) return;
    }
    for (uint32_t i = 0; i < argc; i++) {
        UEntry *entry = native_arg(stack, argc, i);
        if (i) fputc(' ', stdout);
        print_entry(stdout, vm, entry);
    }
    fputc('\n', stdout);
}

static void native_println(UrbVM *vm, List *stack, UEntry *global)
{
    (void)global;
    uint32_t argc = native_argc(vm);
    if (argc == 0) {
        if (stack && stack->size > 0) {
            UEntry *entry = (UEntry*)stack->data[stack->size - 1].p;
            print_plain_entry(stdout, vm, entry);
        }
        fputc('\n', stdout);
        return;
    }
    if (argc == 1) {
        UEntry *entry = native_arg(stack, argc, 0);
        if (print_fast_scalar_plain(stdout, vm, entry, 1)) return;
    }
    for (uint32_t i = 0; i < argc; i++) {
        UEntry *entry = native_arg(stack, argc, i);
        if (i) fputc(' ', stdout);
        print_plain_entry(stdout, vm, entry);
    }
    fputc('\n', stdout);
}

static void native_len(UrbVM *vm, List *stack, UEntry *global)
{
    (void)global;
    uint32_t argc = native_argc(vm);
    UEntry *target = native_target(vm, stack, argc);
    if (!target) return;
    Int length = entry_value_len(target);
    stack_push_entry(stack, uent_make_int_scalar(length));
}

static void native_pretty(UrbVM *vm, List *stack, UEntry *global)
{
    (void)global;
    uint32_t argc = native_argc(vm);
    UEntry *target = native_target(vm, stack, argc);
    if (!target) return;
    StrBuf buf;
    sb_init(&buf);
    append_value_text(vm, target, &buf, 0);
    push_string(stack, buf.data, buf.len);
    sb_free(&buf);
}

static UEntry *entry_clone_shallow_copy(UEntry *src)
{
    if (!src || !src->obj) return NULL;
    if (src->obj->type == U_T_INT || src->obj->type == U_T_FLOAT) {
        UObj *obj = uobj_new(src->obj->type);
        obj->as.bytes.len = src->obj->as.bytes.len;
        if (obj->as.bytes.len) {
            obj->as.bytes.data = (unsigned char*)malloc(obj->as.bytes.len);
            memcpy(obj->as.bytes.data, src->obj->as.bytes.data, obj->as.bytes.len);
        }
        UEntry *out = uent_new(obj);
        out->is_string = src->is_string;
        out->explicit_string = src->explicit_string;
        out->key = src->key;
        return out;
    }
    if (src->obj->type == U_T_TABLE) {
        UEntry *out = uent_make_table((Int)src->obj->as.table.size);
        for (size_t i = 0; i < src->obj->as.table.size; i++) {
            UEntry *child = src->obj->as.table.items[i];
            if (!child) continue;
            table_add_entry(out, entry_clone_shallow(child, child->key));
        }
        return out;
    }
    return entry_clone_shallow((UEntry*)src, src->key);
}

static UEntry *entry_clone_deep_copy(UEntry *src)
{
    if (!src || !src->obj) return NULL;
    if (src->obj->type == U_T_INT || src->obj->type == U_T_FLOAT) {
        return entry_clone_shallow_copy(src);
    }
    if (src->obj->type == U_T_TABLE) {
        UEntry *out = uent_make_table((Int)src->obj->as.table.size);
        for (size_t i = 0; i < src->obj->as.table.size; i++) {
            UEntry *child = src->obj->as.table.items[i];
            if (!child) continue;
            UEntry *deep = entry_clone_deep_copy(child);
            if (!deep) continue;
            deep->key = child->key;
            table_add_entry(out, deep);
        }
        return out;
    }
    return entry_clone_shallow((UEntry*)src, src->key);
}

static void native_clone(UrbVM *vm, List *stack, UEntry *global)
{
    (void)global;
    uint32_t argc = native_argc(vm);
    UEntry *target = native_target(vm, stack, argc);
    if (!target) return;
    UEntry *out = entry_clone_shallow_copy(target);
    if (!out) return;
    push_entry(stack, out);
}

static void native_copy(UrbVM *vm, List *stack, UEntry *global)
{
    (void)global;
    uint32_t argc = native_argc(vm);
    UEntry *target = native_target(vm, stack, argc);
    if (!target) return;
    UEntry *out = entry_clone_deep_copy(target);
    if (!out) return;
    push_entry(stack, out);
}

static void native_to_int(UrbVM *vm, List *stack, UEntry *global)
{
    (void)global;
    uint32_t argc = native_argc(vm);
    UEntry *target = native_target(vm, stack, argc);
    if (!target || !target->obj || target->obj->type != U_T_FLOAT) {
        fprintf(stderr, "toInt expects a float list\n");
        return;
    }
    Int count = entry_value_len(target);
    UEntry *entry = uent_make_int_list(count);
    if (!entry) return;
    for (Int i = 0; i < count; i++) {
        Float v = 0;
        entry_read_float(target, i, &v);
        entry_write_int(entry, i, (Int)v);
    }
    push_entry(stack, entry);
}

static void native_to_float(UrbVM *vm, List *stack, UEntry *global)
{
    (void)global;
    uint32_t argc = native_argc(vm);
    UEntry *target = native_target(vm, stack, argc);
    if (!target || !target->obj || target->obj->type != U_T_INT) {
        fprintf(stderr, "toFloat expects an int list\n");
        return;
    }
    size_t bytes_len = entry_bytes_len(target);
    Int count = entry_is_string(target) ? (Int)bytes_len : (Int)(bytes_len / sizeof(Int));
    UEntry *entry = uent_make_float_list(count);
    if (!entry) return;
    if (entry_is_string(target)) {
        for (Int i = 0; i < count; i++) {
            unsigned char b = (unsigned char)entry_bytes_data(target)[i];
            entry_write_float(entry, i, (Float)b);
        }
    } else {
        for (Int i = 0; i < count; i++) {
            Int v = 0;
            entry_read_int(target, i, &v);
            entry_write_float(entry, i, (Float)v);
        }
    }
    push_entry(stack, entry);
}

static void native_append(UrbVM *vm, List *stack, UEntry *global)
{
    (void)global;
    uint32_t argc = native_argc(vm);
    UEntry *self = native_this(vm);
    UEntry *dst = NULL;
    UEntry *src = NULL;
    if (self) {
        dst = self;
        src = native_arg(stack, argc, 0);
    } else {
        dst = native_arg(stack, argc, 0);
        src = native_arg(stack, argc, 1);
    }
    if (!dst || !src || !entry_is_string(dst) || !entry_is_string(src)) {
        fprintf(stderr, "append expects string values\n");
        return;
    }
    size_t old_len = entry_bytes_len(dst);
    size_t add = entry_bytes_len(src);
    size_t new_len = old_len + add;
    dst->obj->as.bytes.data = (unsigned char*)realloc(dst->obj->as.bytes.data, new_len);
    memcpy(dst->obj->as.bytes.data + old_len, entry_bytes_data(src), add);
    dst->obj->as.bytes.len = new_len;
}

static int native_number_seed(UrbVM *vm, List *stack, UEntry *global, Float *out, uint32_t *start)
{
    uint32_t argc = native_argc(vm);
    UEntry *self = native_this(vm);
    if (self && entry_as_number(self, out)) {
        *start = 0;
        return 1;
    }
    UEntry *arg0 = native_arg(stack, argc, 0);
    if (!arg0 || !entry_as_number(arg0, out)) return 0;
    *start = 1;
    return 1;
}

static int native_unary_number(UrbVM *vm, List *stack, UEntry *global, Float *out)
{
    (void)global;
    uint32_t argc = native_argc(vm);
    UEntry *self = native_this(vm);
    if (self && entry_as_number(self, out)) return 1;
    UEntry *arg0 = native_arg(stack, argc, 0);
    if (!arg0 || !entry_as_number(arg0, out)) return 0;
    return 1;
}

static void native_add(UrbVM *vm, List *stack, UEntry *global)
{
    Float acc = 0;
    uint32_t start = 0;
    if (!native_number_seed(vm, stack, global, &acc, &start)) {
        fprintf(stderr, "add expects numbers\n");
        return;
    }
    uint32_t argc = native_argc(vm);
    for (uint32_t i = start; i < argc; i++) {
        UEntry *arg = native_arg(stack, argc, i);
        Float v = 0;
        if (!entry_as_number(arg, &v)) {
            fprintf(stderr, "add expects numbers\n");
            return;
        }
        acc += v;
    }
    push_number(stack, acc);
}

static void native_sub(UrbVM *vm, List *stack, UEntry *global)
{
    Float acc = 0;
    uint32_t start = 0;
    if (!native_number_seed(vm, stack, global, &acc, &start)) {
        fprintf(stderr, "sub expects numbers\n");
        return;
    }
    uint32_t argc = native_argc(vm);
    for (uint32_t i = start; i < argc; i++) {
        UEntry *arg = native_arg(stack, argc, i);
        Float v = 0;
        if (!entry_as_number(arg, &v)) {
            fprintf(stderr, "sub expects numbers\n");
            return;
        }
        acc -= v;
    }
    push_number(stack, acc);
}

static void native_mul(UrbVM *vm, List *stack, UEntry *global)
{
    Float acc = 0;
    uint32_t start = 0;
    if (!native_number_seed(vm, stack, global, &acc, &start)) {
        fprintf(stderr, "mul expects numbers\n");
        return;
    }
    uint32_t argc = native_argc(vm);
    for (uint32_t i = start; i < argc; i++) {
        UEntry *arg = native_arg(stack, argc, i);
        Float v = 0;
        if (!entry_as_number(arg, &v)) {
            fprintf(stderr, "mul expects numbers\n");
            return;
        }
        acc *= v;
    }
    push_number(stack, acc);
}

static void native_div(UrbVM *vm, List *stack, UEntry *global)
{
    Float acc = 0;
    uint32_t start = 0;
    if (!native_number_seed(vm, stack, global, &acc, &start)) {
        fprintf(stderr, "div expects numbers\n");
        return;
    }
    uint32_t argc = native_argc(vm);
    for (uint32_t i = start; i < argc; i++) {
        UEntry *arg = native_arg(stack, argc, i);
        Float v = 0;
        if (!entry_as_number(arg, &v)) {
            fprintf(stderr, "div expects numbers\n");
            return;
        }
        acc /= v;
    }
    push_number(stack, acc);
}

static void native_mod(UrbVM *vm, List *stack, UEntry *global)
{
    uint32_t argc = native_argc(vm);
    UEntry *self = native_this(vm);
    Float a = 0;
    Float b = 0;
    if (self && entry_as_number(self, &a)) {
        UEntry *arg0 = native_arg(stack, argc, 0);
        if (!arg0 || !entry_as_number(arg0, &b)) {
            fprintf(stderr, "mod expects numbers\n");
            return;
        }
    } else {
        UEntry *arg0 = native_arg(stack, argc, 0);
        UEntry *arg1 = native_arg(stack, argc, 1);
        if (!arg0 || !arg1 || !entry_as_number(arg0, &a) || !entry_as_number(arg1, &b)) {
            fprintf(stderr, "mod expects numbers\n");
            return;
        }
    }
    push_number(stack, (Float)fmod((double)a, (double)b));
}

static void native_pow(UrbVM *vm, List *stack, UEntry *global)
{
    uint32_t argc = native_argc(vm);
    UEntry *self = native_this(vm);
    Float base = 0;
    Float expv = 0;
    if (self && entry_as_number(self, &base)) {
        UEntry *arg0 = native_arg(stack, argc, 0);
        if (!arg0 || !entry_as_number(arg0, &expv)) {
            fprintf(stderr, "pow expects numbers\n");
            return;
        }
    } else {
        UEntry *arg0 = native_arg(stack, argc, 0);
        UEntry *arg1 = native_arg(stack, argc, 1);
        if (!arg0 || !arg1 || !entry_as_number(arg0, &base) || !entry_as_number(arg1, &expv)) {
            fprintf(stderr, "pow expects numbers\n");
            return;
        }
    }
    push_number(stack, (Float)pow((double)base, (double)expv));
}

static void native_min(UrbVM *vm, List *stack, UEntry *global)
{
    Float acc = 0;
    uint32_t start = 0;
    if (!native_number_seed(vm, stack, global, &acc, &start)) {
        fprintf(stderr, "min expects numbers\n");
        return;
    }
    uint32_t argc = native_argc(vm);
    for (uint32_t i = start; i < argc; i++) {
        UEntry *arg = native_arg(stack, argc, i);
        Float v = 0;
        if (!entry_as_number(arg, &v)) {
            fprintf(stderr, "min expects numbers\n");
            return;
        }
        if (v < acc) acc = v;
    }
    push_number(stack, acc);
}

static void native_max(UrbVM *vm, List *stack, UEntry *global)
{
    Float acc = 0;
    uint32_t start = 0;
    if (!native_number_seed(vm, stack, global, &acc, &start)) {
        fprintf(stderr, "max expects numbers\n");
        return;
    }
    uint32_t argc = native_argc(vm);
    for (uint32_t i = start; i < argc; i++) {
        UEntry *arg = native_arg(stack, argc, i);
        Float v = 0;
        if (!entry_as_number(arg, &v)) {
            fprintf(stderr, "max expects numbers\n");
            return;
        }
        if (v > acc) acc = v;
    }
    push_number(stack, acc);
}

static void native_abs(UrbVM *vm, List *stack, UEntry *global)
{
    Float v = 0;
    if (!native_unary_number(vm, stack, global, &v)) {
        fprintf(stderr, "abs expects a number\n");
        return;
    }
    push_number(stack, (Float)fabs((double)v));
}

static void native_floor(UrbVM *vm, List *stack, UEntry *global)
{
    Float v = 0;
    if (!native_unary_number(vm, stack, global, &v)) {
        fprintf(stderr, "floor expects a number\n");
        return;
    }
    push_number(stack, (Float)floor((double)v));
}

static void native_ceil(UrbVM *vm, List *stack, UEntry *global)
{
    Float v = 0;
    if (!native_unary_number(vm, stack, global, &v)) {
        fprintf(stderr, "ceil expects a number\n");
        return;
    }
    push_number(stack, (Float)ceil((double)v));
}

static void native_round(UrbVM *vm, List *stack, UEntry *global)
{
    Float v = 0;
    if (!native_unary_number(vm, stack, global, &v)) {
        fprintf(stderr, "round expects a number\n");
        return;
    }
    push_number(stack, (Float)round((double)v));
}

static void native_sqrt(UrbVM *vm, List *stack, UEntry *global)
{
    Float v = 0;
    if (!native_unary_number(vm, stack, global, &v)) {
        fprintf(stderr, "sqrt expects a number\n");
        return;
    }
    push_number(stack, (Float)sqrt((double)v));
}

static void native_sin(UrbVM *vm, List *stack, UEntry *global)
{
    Float v = 0;
    if (!native_unary_number(vm, stack, global, &v)) {
        fprintf(stderr, "sin expects a number\n");
        return;
    }
    push_number(stack, (Float)sin((double)v));
}

static void native_cos(UrbVM *vm, List *stack, UEntry *global)
{
    Float v = 0;
    if (!native_unary_number(vm, stack, global, &v)) {
        fprintf(stderr, "cos expects a number\n");
        return;
    }
    push_number(stack, (Float)cos((double)v));
}

static void native_tan(UrbVM *vm, List *stack, UEntry *global)
{
    Float v = 0;
    if (!native_unary_number(vm, stack, global, &v)) {
        fprintf(stderr, "tan expects a number\n");
        return;
    }
    push_number(stack, (Float)tan((double)v));
}

static void native_asin(UrbVM *vm, List *stack, UEntry *global)
{
    Float v = 0;
    if (!native_unary_number(vm, stack, global, &v)) {
        fprintf(stderr, "asin expects a number\n");
        return;
    }
    push_number(stack, (Float)asin((double)v));
}

static void native_acos(UrbVM *vm, List *stack, UEntry *global)
{
    Float v = 0;
    if (!native_unary_number(vm, stack, global, &v)) {
        fprintf(stderr, "acos expects a number\n");
        return;
    }
    push_number(stack, (Float)acos((double)v));
}

static void native_atan(UrbVM *vm, List *stack, UEntry *global)
{
    Float v = 0;
    if (!native_unary_number(vm, stack, global, &v)) {
        fprintf(stderr, "atan expects a number\n");
        return;
    }
    push_number(stack, (Float)atan((double)v));
}

static void native_log(UrbVM *vm, List *stack, UEntry *global)
{
    Float v = 0;
    if (!native_unary_number(vm, stack, global, &v)) {
        fprintf(stderr, "log expects a number\n");
        return;
    }
    push_number(stack, (Float)log((double)v));
}

static void native_exp(UrbVM *vm, List *stack, UEntry *global)
{
    Float v = 0;
    if (!native_unary_number(vm, stack, global, &v)) {
        fprintf(stderr, "exp expects a number\n");
        return;
    }
    push_number(stack, (Float)exp((double)v));
}

static UEntry *native_string_target(UrbVM *vm, List *stack, uint32_t argc)
{
    UEntry *self = native_this(vm);
    if (self && entry_is_string(self)) return self;
    UEntry *arg0 = native_arg(stack, argc, 0);
    if (arg0 && entry_is_string(arg0)) return arg0;
    return NULL;
}

static Int clamp_index(Int i, Int len)
{
    if (i < 0) i = len + i;
    if (i < 0) i = 0;
    if (i > len) i = len;
    return i;
}

static void native_slice(UrbVM *vm, List *stack, UEntry *global)
{
    uint32_t argc = native_argc(vm);
    UEntry *target = native_string_target(vm, stack, argc);
    UEntry *start_entry = native_arg(stack, argc, 0);
    UEntry *end_entry = native_arg(stack, argc, 1);
    if (!target) {
        fprintf(stderr, "slice expects a string target\n");
        return;
    }
    Int start = 0;
    Int end = (Int)entry_bytes_len(target);
    if (start_entry && !entry_number_to_int(start_entry, &start)) {
        fprintf(stderr, "slice expects integer start\n");
        return;
    }
    if (end_entry && !entry_number_to_int(end_entry, &end)) {
        fprintf(stderr, "slice expects integer end\n");
        return;
    }
    Int len = (Int)entry_bytes_len(target);
    start = clamp_index(start, len);
    end = clamp_index(end, len);
    if (end < start) end = start;
    size_t out_len = (size_t)(end - start);
    push_string(stack, (const char*)entry_bytes_data(target) + start, out_len);
}

static void native_substr(UrbVM *vm, List *stack, UEntry *global)
{
    uint32_t argc = native_argc(vm);
    UEntry *target = native_string_target(vm, stack, argc);
    UEntry *start_entry = native_arg(stack, argc, 0);
    UEntry *len_entry = native_arg(stack, argc, 1);
    if (!target) {
        fprintf(stderr, "substr expects a string target\n");
        return;
    }
    Int start = 0;
    Int count = (Int)entry_bytes_len(target);
    if (start_entry && !entry_number_to_int(start_entry, &start)) {
        fprintf(stderr, "substr expects integer start\n");
        return;
    }
    if (len_entry && !entry_number_to_int(len_entry, &count)) {
        fprintf(stderr, "substr expects integer len\n");
        return;
    }
    Int len = (Int)entry_bytes_len(target);
    if (start < 0) start = len + start;
    if (start < 0) start = 0;
    if (start > len) start = len;
    if (count < 0) count = 0;
    if (start + count > len) count = len - start;
    push_string(stack, (const char*)entry_bytes_data(target) + start, (size_t)count);
}

static void native_upper(UrbVM *vm, List *stack, UEntry *global)
{
    uint32_t argc = native_argc(vm);
    UEntry *target = native_string_target(vm, stack, argc);
    if (!target) {
        fprintf(stderr, "upper expects a string target\n");
        return;
    }
    size_t len = entry_bytes_len(target);
    char *buf = (char*)malloc(len);
    if (!buf && len > 0) return;
    for (size_t i = 0; i < len; i++) {
        buf[i] = (char)toupper((unsigned char)entry_bytes_data(target)[i]);
    }
    push_string(stack, buf, len);
    free(buf);
}

static void native_lower(UrbVM *vm, List *stack, UEntry *global)
{
    uint32_t argc = native_argc(vm);
    UEntry *target = native_string_target(vm, stack, argc);
    if (!target) {
        fprintf(stderr, "lower expects a string target\n");
        return;
    }
    size_t len = entry_bytes_len(target);
    char *buf = (char*)malloc(len);
    if (!buf && len > 0) return;
    for (size_t i = 0; i < len; i++) {
        buf[i] = (char)tolower((unsigned char)entry_bytes_data(target)[i]);
    }
    push_string(stack, buf, len);
    free(buf);
}

static void native_trim(UrbVM *vm, List *stack, UEntry *global)
{
    uint32_t argc = native_argc(vm);
    UEntry *target = native_string_target(vm, stack, argc);
    if (!target) {
        fprintf(stderr, "trim expects a string target\n");
        return;
    }
    const char *s = (const char*)entry_bytes_data(target);
    size_t len = entry_bytes_len(target);
    size_t start = 0;
    while (start < len && isspace((unsigned char)s[start])) start++;
    size_t end = len;
    while (end > start && isspace((unsigned char)s[end - 1])) end--;
    push_string(stack, s + start, end - start);
}

static int starts_with(const char *hay, size_t hlen, const char *needle, size_t nlen)
{
    if (nlen > hlen) return 0;
    return memcmp(hay, needle, nlen) == 0;
}

static int ends_with(const char *hay, size_t hlen, const char *needle, size_t nlen)
{
    if (nlen > hlen) return 0;
    return memcmp(hay + hlen - nlen, needle, nlen) == 0;
}

static size_t find_substring(const char *hay, size_t hlen, const char *needle, size_t nlen, size_t start)
{
    if (nlen == 0) return start <= hlen ? start : SIZE_MAX;
    if (nlen > hlen) return SIZE_MAX;
    for (size_t i = start; i + nlen <= hlen; i++) {
        if (memcmp(hay + i, needle, nlen) == 0) return i;
    }
    return SIZE_MAX;
}

static void native_starts_with(UrbVM *vm, List *stack, UEntry *global)
{
    uint32_t argc = native_argc(vm);
    UEntry *target = native_string_target(vm, stack, argc);
    UEntry *arg0 = native_arg(stack, argc, 0);
    if (!target || !arg0 || !entry_is_string(arg0)) {
        fprintf(stderr, "startsWith expects string values\n");
        return;
    }
    const char *s = (const char*)entry_bytes_data(target);
    size_t slen = entry_bytes_len(target);
    const char *n = (const char*)entry_bytes_data(arg0);
    size_t nlen = entry_bytes_len(arg0);
    push_number(stack, starts_with(s, slen, n, nlen) ? 1 : 0);
}

static void native_ends_with(UrbVM *vm, List *stack, UEntry *global)
{
    uint32_t argc = native_argc(vm);
    UEntry *target = native_string_target(vm, stack, argc);
    UEntry *arg0 = native_arg(stack, argc, 0);
    if (!target || !arg0 || !entry_is_string(arg0)) {
        fprintf(stderr, "endsWith expects string values\n");
        return;
    }
    const char *s = (const char*)entry_bytes_data(target);
    size_t slen = entry_bytes_len(target);
    const char *n = (const char*)entry_bytes_data(arg0);
    size_t nlen = entry_bytes_len(arg0);
    push_number(stack, ends_with(s, slen, n, nlen) ? 1 : 0);
}

static void native_find(UrbVM *vm, List *stack, UEntry *global)
{
    uint32_t argc = native_argc(vm);
    UEntry *target = native_string_target(vm, stack, argc);
    UEntry *arg0 = native_arg(stack, argc, 0);
    if (!target || !arg0 || !entry_is_string(arg0)) {
        fprintf(stderr, "find expects string values\n");
        return;
    }
    const char *hay = (const char*)entry_bytes_data(target);
    size_t hlen = entry_bytes_len(target);
    const char *needle = (const char*)entry_bytes_data(arg0);
    size_t nlen = entry_bytes_len(arg0);
    size_t pos = find_substring(hay, hlen, needle, nlen, 0);
    push_number(stack, pos == SIZE_MAX ? -1 : (Int)pos);
}

static void native_rfind(UrbVM *vm, List *stack, UEntry *global)
{
    uint32_t argc = native_argc(vm);
    UEntry *target = native_string_target(vm, stack, argc);
    UEntry *arg0 = native_arg(stack, argc, 0);
    if (!target || !arg0 || !entry_is_string(arg0)) {
        fprintf(stderr, "rfind expects string values\n");
        return;
    }
    const char *hay = (const char*)entry_bytes_data(target);
    size_t hlen = entry_bytes_len(target);
    const char *needle = (const char*)entry_bytes_data(arg0);
    size_t nlen = entry_bytes_len(arg0);
    size_t pos = SIZE_MAX;
    if (nlen <= hlen) {
        for (size_t i = hlen - nlen + 1; i-- > 0;) {
            if (memcmp(hay + i, needle, nlen) == 0) {
                pos = i;
                break;
            }
            if (i == 0) break;
        }
    }
    push_number(stack, pos == SIZE_MAX ? -1 : (Int)pos);
}

static void native_contains(UrbVM *vm, List *stack, UEntry *global)
{
    uint32_t argc = native_argc(vm);
    UEntry *target = native_string_target(vm, stack, argc);
    UEntry *arg0 = native_arg(stack, argc, 0);
    if (!target || !arg0 || !entry_is_string(arg0)) {
        fprintf(stderr, "contains expects string values\n");
        return;
    }
    const char *hay = (const char*)entry_bytes_data(target);
    size_t hlen = entry_bytes_len(target);
    const char *needle = (const char*)entry_bytes_data(arg0);
    size_t nlen = entry_bytes_len(arg0);
    size_t pos = find_substring(hay, hlen, needle, nlen, 0);
    push_number(stack, pos == SIZE_MAX ? 0 : 1);
}

static void native_replace_impl(UrbVM *vm, List *stack, UEntry *global, int replace_all, const char *name)
{
    uint32_t argc = native_argc(vm);
    UEntry *target = native_string_target(vm, stack, argc);
    UEntry *needle = native_arg(stack, argc, 0);
    UEntry *repl = native_arg(stack, argc, 1);
    if (!target || !needle || !repl || !entry_is_string(needle) || !entry_is_string(repl)) {
        fprintf(stderr, "%s expects string values\n", name);
        return;
    }
    const char *hay = (const char*)entry_bytes_data(target);
    size_t hlen = entry_bytes_len(target);
    const char *n = (const char*)entry_bytes_data(needle);
    size_t nlen = entry_bytes_len(needle);
    const char *r = (const char*)entry_bytes_data(repl);
    size_t rlen = entry_bytes_len(repl);
    if (nlen == 0) {
        push_string(stack, hay, hlen);
        return;
    }
    StrBuf out;
    sb_init(&out);
    size_t pos = 0;
    size_t match = find_substring(hay, hlen, n, nlen, 0);
    if (match == SIZE_MAX) {
        push_string(stack, hay, hlen);
        sb_free(&out);
        return;
    }
    while (match != SIZE_MAX) {
        sb_append_n(&out, hay + pos, match - pos);
        sb_append_n(&out, r, rlen);
        pos = match + nlen;
        if (!replace_all) break;
        match = find_substring(hay, hlen, n, nlen, pos);
    }
    sb_append_n(&out, hay + pos, hlen - pos);
    push_string(stack, out.data, out.len);
    sb_free(&out);
}

static void native_replace(UrbVM *vm, List *stack, UEntry *global)
{
    native_replace_impl(vm, stack, global, 0, "replace");
}

static void native_replace_all(UrbVM *vm, List *stack, UEntry *global)
{
    native_replace_impl(vm, stack, global, 1, "replaceAll");
}

static void native_split(UrbVM *vm, List *stack, UEntry *global)
{
    uint32_t argc = native_argc(vm);
    UEntry *target = native_string_target(vm, stack, argc);
    UEntry *sep = native_arg(stack, argc, 0);
    if (!target || !sep || !entry_is_string(sep)) {
        fprintf(stderr, "split expects string values\n");
        return;
    }
    const char *s = (const char*)entry_bytes_data(target);
    size_t slen = entry_bytes_len(target);
    const char *d = (const char*)entry_bytes_data(sep);
    size_t dlen = entry_bytes_len(sep);
    UEntry *out = uent_make_table(8);
    if (dlen == 0) {
        for (size_t i = 0; i < slen; i++) {
            push_entry(stack, out);
            UEntry *part = uent_make_bytes(s + i, 1, 1, 1);
            table_add_entry(out, part);
        }
        push_entry(stack, out);
        return;
    }
    size_t pos = 0;
    size_t next = find_substring(s, slen, d, dlen, 0);
    while (next != SIZE_MAX) {
        UEntry *part = uent_make_bytes(s + pos, next - pos, 1, 1);
        table_add_entry(out, part);
        pos = next + dlen;
        next = find_substring(s, slen, d, dlen, pos);
    }
    UEntry *part = uent_make_bytes(s + pos, slen - pos, 1, 1);
    table_add_entry(out, part);
    push_entry(stack, out);
}

static void native_join(UrbVM *vm, List *stack, UEntry *global)
{
    uint32_t argc = native_argc(vm);
    UEntry *target = native_target(vm, stack, argc);
    UEntry *sep = native_arg(stack, argc, 0);
    if (!target || !target->obj || target->obj->type != U_T_TABLE || !sep || !entry_is_string(sep)) {
        fprintf(stderr, "join expects a list and separator string\n");
        return;
    }
    const char *delim = (const char*)entry_bytes_data(sep);
    size_t dlen = entry_bytes_len(sep);
    StrBuf buf;
    sb_init(&buf);
    for (size_t i = 0; i < target->obj->as.table.size; i++) {
        UEntry *part = target->obj->as.table.items[i];
        if (!part || !entry_is_string(part)) continue;
        if (i) sb_append_n(&buf, delim, dlen);
        sb_append_n(&buf, (const char*)entry_bytes_data(part), entry_bytes_len(part));
    }
    push_string(stack, buf.data, buf.len);
    sb_free(&buf);
}

static void native_papagaio(UrbVM *vm, List *stack, UEntry *global)
{
    (void)global;
    uint32_t argc = native_argc(vm);
    UEntry *target = native_string_target(vm, stack, argc);
    if (!target) {
        fprintf(stderr, "papagaio expects a string target\n");
        return;
    }
    const char *input = (const char*)entry_bytes_data(target);
    size_t input_len = entry_bytes_len(target);
    char *out = urb_bridge_papagaio(input, input_len);
    if (!out) {
        fprintf(stderr, "papagaio failed\n");
        return;
    }
    push_string(stack, out, strlen(out));
    free(out);
}

static void native_keys(UrbVM *vm, List *stack, UEntry *global)
{
    (void)global;
    uint32_t argc = native_argc(vm);
    UEntry *target = native_target(vm, stack, argc);
    if (!target || !target->obj || target->obj->type != U_T_TABLE) {
        fprintf(stderr, "keys expects a table\n");
        return;
    }
    UEntry *out = uent_make_table((Int)target->obj->as.table.size);
    for (size_t i = 0; i < target->obj->as.table.size; i++) {
        UEntry *child = target->obj->as.table.items[i];
        UEntry *key = child ? child->key : NULL;
        if (!key) continue;
        table_add_entry(out, entry_clone_shallow(key, NULL));
    }
    push_entry(stack, out);
}

static void native_values(UrbVM *vm, List *stack, UEntry *global)
{
    (void)global;
    uint32_t argc = native_argc(vm);
    UEntry *target = native_target(vm, stack, argc);
    if (!target || !target->obj || target->obj->type != U_T_TABLE) {
        fprintf(stderr, "values expects a table\n");
        return;
    }
    UEntry *out = uent_make_table((Int)target->obj->as.table.size);
    for (size_t i = 0; i < target->obj->as.table.size; i++) {
        UEntry *child = target->obj->as.table.items[i];
        if (!child) continue;
        table_add_entry(out, entry_clone_shallow(child, NULL));
    }
    push_entry(stack, out);
}

static void native_has(UrbVM *vm, List *stack, UEntry *global)
{
    (void)global;
    uint32_t argc = native_argc(vm);
    UEntry *target = native_target(vm, stack, argc);
    UEntry *idx = native_arg(stack, argc, 0);
    if (!target || !idx) {
        fprintf(stderr, "has expects target and key\n");
        return;
    }
    if (target->obj && target->obj->type == U_T_TABLE && entry_is_string(idx)) {
        UEntry *entry = table_find_by_key_len(target,
                                              (const char*)entry_bytes_data(idx),
                                              entry_bytes_len(idx));
        push_number(stack, entry ? 1 : 0);
        return;
    }
    push_number(stack, 0);
}

static void native_delete(UrbVM *vm, List *stack, UEntry *global)
{
    (void)global;
    uint32_t argc = native_argc(vm);
    UEntry *target = native_target(vm, stack, argc);
    UEntry *idx = native_arg(stack, argc, 0);
    if (!target || !idx || !target->obj || target->obj->type != U_T_TABLE) {
        fprintf(stderr, "delete expects table and key\n");
        return;
    }
    if (!entry_is_string(idx)) {
        fprintf(stderr, "delete expects string key\n");
        return;
    }
    size_t key_len = entry_bytes_len(idx);
    for (size_t i = 0; i < target->obj->as.table.size; i++) {
        UEntry *entry = target->obj->as.table.items[i];
        UEntry *key = entry ? entry->key : NULL;
        if (!entry_is_string(key)) continue;
        if (entry_bytes_len(key) == key_len &&
            memcmp(entry_bytes_data(key), entry_bytes_data(idx), key_len) == 0) {
            memmove(&target->obj->as.table.items[i],
                    &target->obj->as.table.items[i + 1],
                    (target->obj->as.table.size - i - 1) * sizeof(UEntry*));
            target->obj->as.table.size--;
            return;
        }
    }
}

static void native_push(UrbVM *vm, List *stack, UEntry *global)
{
    (void)global;
    uint32_t argc = native_argc(vm);
    UEntry *target = native_target(vm, stack, argc);
    if (!target || !target->obj) {
        fprintf(stderr, "push expects target\n");
        return;
    }
    uint32_t start = native_this(vm) ? 0 : 1;
    int type = target->obj->type;
    for (uint32_t i = start; i < argc; i++) {
        UEntry *arg = native_arg(stack, argc, i);
        if (!arg) continue;
        if (type == U_T_TABLE) {
            table_add_entry(target, entry_clone_shallow(arg, NULL));
        } else if (type == U_T_INT && entry_is_string(target)) {
            if (!entry_is_string(arg)) {
                fprintf(stderr, "push expects string values\n");
                return;
            }
            size_t add = entry_bytes_len(arg);
            size_t old_len = entry_bytes_len(target);
            target->obj->as.bytes.data = (unsigned char*)realloc(target->obj->as.bytes.data, old_len + add);
            memcpy(target->obj->as.bytes.data + old_len, entry_bytes_data(arg), add);
            target->obj->as.bytes.len = old_len + add;
        } else if (type == U_T_INT) {
            Int iv = 0;
            Float fv = 0;
            int is_float = 0;
            if (!entry_number(arg, &iv, &fv, &is_float) || is_float) {
                fprintf(stderr, "push expects int values\n");
                return;
            }
            size_t offset = entry_bytes_len(target);
            if (!bytes_list_insert(target, offset, &iv, sizeof(Int))) return;
        } else if (type == U_T_FLOAT) {
            Int iv = 0;
            Float fv = 0;
            int is_float = 0;
            if (!entry_number(arg, &iv, &fv, &is_float)) {
                fprintf(stderr, "push expects number values\n");
                return;
            }
            Float out = is_float ? fv : (Float)iv;
            size_t offset = entry_bytes_len(target);
            if (!bytes_list_insert(target, offset, &out, sizeof(Float))) return;
        }
    }
}

static void native_pop(UrbVM *vm, List *stack, UEntry *global)
{
    (void)global;
    uint32_t argc = native_argc(vm);
    UEntry *target = native_target(vm, stack, argc);
    if (!target || !target->obj) {
        fprintf(stderr, "pop expects target\n");
        return;
    }
    int type = target->obj->type;
    if (type == U_T_TABLE) {
        if (target->obj->as.table.size == 0) return;
        UEntry *entry = target->obj->as.table.items[target->obj->as.table.size - 1];
        target->obj->as.table.size--;
        push_entry(stack, entry ? entry : g_vm->null_entry);
        return;
    }
    if (type == U_T_INT && entry_is_string(target)) {
        size_t len = entry_bytes_len(target);
        if (len == 0) return;
        char c = (char)entry_bytes_data(target)[len - 1];
        bytes_list_remove(target, len - 1, NULL, 1);
        push_string(stack, &c, 1);
        return;
    }
    if (type == U_T_INT) {
        Int count = bytes_list_count(target, sizeof(Int));
        if (count <= 0) return;
        Int v = 0;
        bytes_list_remove(target, (size_t)(count - 1) * sizeof(Int), &v, sizeof(Int));
        push_number(stack, (double)v);
        return;
    }
    if (type == U_T_FLOAT) {
        Int count = bytes_list_count(target, sizeof(Float));
        if (count <= 0) return;
        Float v = 0;
        bytes_list_remove(target, (size_t)(count - 1) * sizeof(Float), &v, sizeof(Float));
        push_number(stack, (double)v);
        return;
    }
}

static void native_shift(UrbVM *vm, List *stack, UEntry *global)
{
    (void)global;
    uint32_t argc = native_argc(vm);
    UEntry *target = native_target(vm, stack, argc);
    if (!target || !target->obj) {
        fprintf(stderr, "shift expects target\n");
        return;
    }
    int type = target->obj->type;
    if (type == U_T_TABLE) {
        if (target->obj->as.table.size == 0) return;
        UEntry *entry = target->obj->as.table.items[0];
        memmove(&target->obj->as.table.items[0],
                &target->obj->as.table.items[1],
                (target->obj->as.table.size - 1) * sizeof(UEntry*));
        target->obj->as.table.size--;
        push_entry(stack, entry ? entry : g_vm->null_entry);
        return;
    }
    if (type == U_T_INT && entry_is_string(target)) {
        size_t len = entry_bytes_len(target);
        if (len == 0) return;
        char c = (char)entry_bytes_data(target)[0];
        bytes_list_remove(target, 0, NULL, 1);
        push_string(stack, &c, 1);
        return;
    }
    if (type == U_T_INT) {
        Int v = 0;
        if (!bytes_list_remove(target, 0, &v, sizeof(Int))) return;
        push_number(stack, (double)v);
        return;
    }
    if (type == U_T_FLOAT) {
        Float v = 0;
        if (!bytes_list_remove(target, 0, &v, sizeof(Float))) return;
        push_number(stack, (double)v);
        return;
    }
}

static void native_unshift(UrbVM *vm, List *stack, UEntry *global)
{
    (void)global;
    uint32_t argc = native_argc(vm);
    UEntry *target = native_target(vm, stack, argc);
    if (!target || !target->obj) {
        fprintf(stderr, "unshift expects target\n");
        return;
    }
    uint32_t start = native_this(vm) ? 0 : 1;
    int type = target->obj->type;
    for (uint32_t i = argc; i-- > start;) {
        UEntry *arg = native_arg(stack, argc, i);
        if (!arg) continue;
        if (type == U_T_TABLE) {
            if (target->obj->as.table.size == target->obj->as.table.cap) {
                size_t next = target->obj->as.table.cap == 0 ? 8 : target->obj->as.table.cap * 2;
                target->obj->as.table.items = (UEntry**)realloc(target->obj->as.table.items, next * sizeof(UEntry*));
                target->obj->as.table.cap = next;
            }
            memmove(&target->obj->as.table.items[1],
                    &target->obj->as.table.items[0],
                    target->obj->as.table.size * sizeof(UEntry*));
            target->obj->as.table.items[0] = entry_clone_shallow(arg, NULL);
            target->obj->as.table.size++;
        } else if (type == U_T_INT && entry_is_string(target)) {
            if (!entry_is_string(arg)) {
                fprintf(stderr, "unshift expects string values\n");
                return;
            }
            size_t add = entry_bytes_len(arg);
            bytes_list_insert(target, 0, entry_bytes_data(arg), add);
        } else if (type == U_T_INT) {
            Int iv = 0;
            Float fv = 0;
            int is_float = 0;
            if (!entry_number(arg, &iv, &fv, &is_float) || is_float) {
                fprintf(stderr, "unshift expects int values\n");
                return;
            }
            bytes_list_insert(target, 0, &iv, sizeof(Int));
        } else if (type == U_T_FLOAT) {
            Int iv = 0;
            Float fv = 0;
            int is_float = 0;
            if (!entry_number(arg, &iv, &fv, &is_float)) {
                fprintf(stderr, "unshift expects number values\n");
                return;
            }
            Float out = is_float ? fv : (Float)iv;
            bytes_list_insert(target, 0, &out, sizeof(Float));
        }
    }
}

static void native_insert(UrbVM *vm, List *stack, UEntry *global)
{
    (void)global;
    uint32_t argc = native_argc(vm);
    UEntry *target = native_target(vm, stack, argc);
    UEntry *idx = native_arg(stack, argc, 0);
    UEntry *val = native_arg(stack, argc, 1);
    if (!target || !idx || !val || !target->obj) {
        fprintf(stderr, "insert expects target, index, value\n");
        return;
    }
    Int index = 0;
    if (!entry_number_to_int(idx, &index)) {
        fprintf(stderr, "insert expects integer index\n");
        return;
    }
    int type = target->obj->type;
    if (type == U_T_TABLE) {
        if (target->obj->as.table.size == target->obj->as.table.cap) {
            size_t next = target->obj->as.table.cap == 0 ? 8 : target->obj->as.table.cap * 2;
            target->obj->as.table.items = (UEntry**)realloc(target->obj->as.table.items, next * sizeof(UEntry*));
            target->obj->as.table.cap = next;
        }
        Int pos = list_pos_from_index(target, index);
        if (pos < 0) pos = 0;
        if ((size_t)pos > target->obj->as.table.size) pos = (Int)target->obj->as.table.size;
        memmove(&target->obj->as.table.items[pos + 1],
                &target->obj->as.table.items[pos],
                (target->obj->as.table.size - (size_t)pos) * sizeof(UEntry*));
        target->obj->as.table.items[pos] = entry_clone_shallow(val, NULL);
        target->obj->as.table.size++;
        return;
    }
    if (type == U_T_INT && entry_is_string(target)) {
        if (!entry_is_string(val)) {
            fprintf(stderr, "insert expects string value\n");
            return;
        }
        size_t len = entry_bytes_len(target);
        Int insert_at = bytes_list_insert_index((Int)len, index);
        bytes_list_insert(target, (size_t)insert_at, entry_bytes_data(val), entry_bytes_len(val));
        return;
    }
    if (type == U_T_INT) {
        Int iv = 0;
        Float fv = 0;
        int is_float = 0;
        if (!entry_number(val, &iv, &fv, &is_float) || is_float) {
            fprintf(stderr, "insert expects int value\n");
            return;
        }
        Int count = bytes_list_count(target, sizeof(Int));
        Int insert_at = bytes_list_insert_index(count, index);
        bytes_list_insert(target, (size_t)insert_at * sizeof(Int), &iv, sizeof(Int));
        return;
    }
    if (type == U_T_FLOAT) {
        Int iv = 0;
        Float fv = 0;
        int is_float = 0;
        if (!entry_number(val, &iv, &fv, &is_float)) {
            fprintf(stderr, "insert expects number value\n");
            return;
        }
        Float out = is_float ? fv : (Float)iv;
        Int count = bytes_list_count(target, sizeof(Float));
        Int insert_at = bytes_list_insert_index(count, index);
        bytes_list_insert(target, (size_t)insert_at * sizeof(Float), &out, sizeof(Float));
        return;
    }
}

static void native_remove(UrbVM *vm, List *stack, UEntry *global)
{
    (void)global;
    uint32_t argc = native_argc(vm);
    UEntry *target = native_target(vm, stack, argc);
    UEntry *idx = native_arg(stack, argc, 0);
    if (!target || !idx || !target->obj) {
        fprintf(stderr, "remove expects target and index\n");
        return;
    }
    int type = target->obj->type;
    if (type == U_T_TABLE) {
        if (entry_is_string(idx)) {
            size_t key_len = entry_bytes_len(idx);
            for (size_t i = 0; i < target->obj->as.table.size; i++) {
                UEntry *entry = target->obj->as.table.items[i];
                UEntry *key = entry ? entry->key : NULL;
                if (!entry_is_string(key)) continue;
                if (entry_bytes_len(key) == key_len &&
                    memcmp(entry_bytes_data(key), entry_bytes_data(idx), key_len) == 0) {
                    UEntry *ret = entry;
                    memmove(&target->obj->as.table.items[i],
                            &target->obj->as.table.items[i + 1],
                            (target->obj->as.table.size - i - 1) * sizeof(UEntry*));
                    target->obj->as.table.size--;
                    push_entry(stack, ret);
                    return;
                }
            }
            return;
        }
        Int index = 0;
        if (!entry_number_to_int(idx, &index)) {
            fprintf(stderr, "remove expects string key or integer index\n");
            return;
        }
        if (!list_index_valid(target, index)) return;
        Int pos = list_pos_from_index(target, index);
        UEntry *ret = target->obj->as.table.items[pos];
        memmove(&target->obj->as.table.items[pos],
                &target->obj->as.table.items[pos + 1],
                (target->obj->as.table.size - (size_t)pos - 1) * sizeof(UEntry*));
        target->obj->as.table.size--;
        push_entry(stack, ret);
        return;
    }
    Int index = 0;
    if (!entry_number_to_int(idx, &index)) {
        fprintf(stderr, "remove expects integer index\n");
        return;
    }
    if (type == U_T_INT && entry_is_string(target)) {
        size_t len = entry_bytes_len(target);
        Int pos = 0;
        if (!bytes_list_index((Int)len, index, &pos)) return;
        char c = 0;
        bytes_list_remove(target, (size_t)pos, &c, 1);
        push_string(stack, &c, 1);
        return;
    }
    if (type == U_T_INT) {
        Int count = bytes_list_count(target, sizeof(Int));
        Int pos = 0;
        if (!bytes_list_index(count, index, &pos)) return;
        Int iv = 0;
        bytes_list_remove(target, (size_t)pos * sizeof(Int), &iv, sizeof(Int));
        push_number(stack, (double)iv);
        return;
    }
    if (type == U_T_FLOAT) {
        Int count = bytes_list_count(target, sizeof(Float));
        Int pos = 0;
        if (!bytes_list_index(count, index, &pos)) return;
        Float fv = 0;
        bytes_list_remove(target, (size_t)pos * sizeof(Float), &fv, sizeof(Float));
        push_number(stack, (double)fv);
        return;
    }
}

static void native_read(UrbVM *vm, List *stack, UEntry *global)
{
    (void)vm;
    (void)global;
    uint32_t argc = native_argc(vm);
    UEntry *target = native_arg(stack, argc, 0);
    const char *path = NULL;
    size_t path_len = 0;
    if (!target || !entry_as_string(target, &path, &path_len)) {
        fprintf(stderr, "read expects a string path\n");
        return;
    }
    char *path_buf = (char*)malloc(path_len + 1);
    memcpy(path_buf, path, path_len);
    path_buf[path_len] = 0;
    FILE *fp = fopen(path_buf, "rb");
    free(path_buf);
    if (!fp) {
        fprintf(stderr, "read failed\n");
        return;
    }
    size_t cap = 4096;
    size_t len = 0;
    char *buf = (char*)malloc(cap);
    int c;
    while ((c = fgetc(fp)) != EOF) {
        if (len + 1 > cap) {
            size_t next = cap * 2;
            char *tmp = (char*)realloc(buf, next);
            if (!tmp) break;
            buf = tmp;
            cap = next;
        }
        buf[len++] = (char)c;
    }
    fclose(fp);
    push_string(stack, buf, len);
    free(buf);
}

static void native_write(UrbVM *vm, List *stack, UEntry *global)
{
    (void)vm;
    (void)global;
    uint32_t argc = native_argc(vm);
    UEntry *path_entry = native_arg(stack, argc, 0);
    UEntry *data_entry = native_arg(stack, argc, 1);
    const char *path = NULL;
    size_t path_len = 0;
    const char *data = NULL;
    size_t data_len = 0;
    if (!path_entry || !data_entry ||
        !entry_as_string(path_entry, &path, &path_len) ||
        !entry_as_string(data_entry, &data, &data_len)) {
        fprintf(stderr, "write expects path and data strings\n");
        return;
    }
    char *path_buf = (char*)malloc(path_len + 1);
    memcpy(path_buf, path, path_len);
    path_buf[path_len] = 0;
    FILE *fp = fopen(path_buf, "wb");
    free(path_buf);
    if (!fp) {
        fprintf(stderr, "write failed\n");
        return;
    }
    fwrite(data, 1, data_len, fp);
    fclose(fp);
    push_entry(stack, g_vm->null_entry);
}

static void native_system(UrbVM *vm, List *stack, UEntry *global)
{
    (void)vm;
    (void)global;
    uint32_t argc = native_argc(vm);
    UEntry *cmd_entry = native_arg(stack, argc, 0);
    const char *cmd = NULL;
    size_t cmd_len = 0;
    if (!cmd_entry || !entry_as_string(cmd_entry, &cmd, &cmd_len)) {
        fprintf(stderr, "system expects a string command\n");
        return;
    }
    char *cmd_buf = (char*)malloc(cmd_len + 1);
    memcpy(cmd_buf, cmd, cmd_len);
    cmd_buf[cmd_len] = 0;
    int res = system(cmd_buf);
    free(cmd_buf);
    push_number(stack, res);
}

static void native_ffi_load(UrbVM *vm, List *stack, UEntry *global)
{
    (void)vm;
    (void)global;
    fprintf(stderr, "ffiLoad is not supported in URB runtime yet\n");
    push_entry(stack, g_vm->null_entry);
}

static void native_eval(UrbVM *vm, List *stack, UEntry *global)
{
    (void)global;
    uint32_t argc = native_argc(vm);
    UEntry *target = native_target(vm, stack, argc);
    const char *src = NULL;
    size_t src_len = 0;
    if (!target || !entry_as_string(target, &src, &src_len)) {
        fprintf(stderr, "eval expects string source\n");
        return;
    }
    Bytecode bc;
    char err[256];
    err[0] = 0;
    if (!vm_compile_source(src, &bc, err, sizeof(err))) {
        fprintf(stderr, "%s\n", err[0] ? err : "eval compile failed");
        return;
    }
    Int before = stack->size;
    exec_bytecode_in_vm(vm, bc.data, bc.len, stack);
    bc_free(&bc);
    if (stack->size == (UHalf)before) {
        push_entry(stack, g_vm->null_entry);
    }
}

static void native_eval_bytecode(UrbVM *vm, List *stack, UEntry *global)
{
    (void)global;
    uint32_t argc = native_argc(vm);
    UEntry *target = native_target(vm, stack, argc);
    const char *data = NULL;
    size_t len = 0;
    if (!target || !entry_as_string(target, &data, &len)) {
        fprintf(stderr, "evalBytecode expects byte/string data\n");
        return;
    }
    exec_bytecode_in_vm(vm, (const unsigned char*)data, len, stack);
    push_entry(stack, g_vm->null_entry);
}

static void native_parse(UrbVM *vm, List *stack, UEntry *global)
{
    (void)vm;
    (void)global;
    fprintf(stderr, "parse is not supported in URB runtime\n");
    push_entry(stack, g_vm->null_entry);
}

static void native_emit(UrbVM *vm, List *stack, UEntry *global)
{
    (void)vm;
    (void)global;
    fprintf(stderr, "emit is not supported in URB runtime\n");
    push_entry(stack, g_vm->null_entry);
}

static void native_gc_collect(UrbVM *vm, List *stack, UEntry *global)
{
    (void)vm;
    (void)global;
    stack_push_entry(stack, g_vm->null_entry);
}

static void uobj_free(UObj *obj)
{
    if (!obj) return;
    if (obj->type == U_T_INT || obj->type == U_T_FLOAT) {
        free(obj->as.bytes.data);
    } else if (obj->type == U_T_TABLE) {
        free(obj->as.table.items);
    } else if (obj->type == U_T_NATIVE) {
        UNative *n = obj->as.native.native;
        if (n && n->free_data) n->free_data(n->data);
        free(n);
    } else if (obj->type == U_T_LAMBDA) {
        UFunc *fn = obj->as.lambda.func;
        if (fn) {
            for (uint32_t i = 0; i < fn->argc; i++) {
                free(fn->arg_names ? fn->arg_names[i] : NULL);
                if (fn->default_mem && fn->default_mem[i]) urb_free(fn->default_mem[i]);
            }
            free(fn->arg_names);
            free(fn->arg_lens);
            free(fn->default_mem);
            free(fn->has_default);
            free(fn);
        }
    }
    free(obj);
}

static void native_gc_free(UrbVM *vm, List *stack, UEntry *global)
{
    (void)global;
    uint32_t argc = native_argc(vm);
    UEntry *target = native_arg(stack, argc, 0);
    if (!target || !target->obj) {
        fprintf(stderr, "gc.free expects a value\n");
        return;
    }
    if (target == vm->global_entry || target == vm->stack_entry ||
        target == vm->null_entry || target == vm->common_entry ||
        target == vm->argc_entry) {
        fprintf(stderr, "gc.free cannot free protected values\n");
        return;
    }
    uobj_free(target->obj);
    target->obj = uobj_new(U_T_NULL);
    stack_push_entry(stack, uent_make_int_scalar(1));
}

static void native_gc_sweep(UrbVM *vm, List *stack, UEntry *global)
{
    (void)global;
    uint32_t argc = native_argc(vm);
    UEntry *target = native_arg(stack, argc, 0);
    if (!target || !target->obj) {
        fprintf(stderr, "gc.sweep expects a value\n");
        return;
    }
    if (target == vm->global_entry || target == vm->stack_entry ||
        target == vm->null_entry || target == vm->common_entry ||
        target == vm->argc_entry) {
        fprintf(stderr, "gc.sweep cannot sweep protected values\n");
        return;
    }
    uobj_free(target->obj);
    target->obj = uobj_new(U_T_NULL);
    stack_push_entry(stack, uent_make_int_scalar(1));
}

static void native_gc_new(UrbVM *vm, List *stack, UEntry *global)
{
    (void)global;
    uint32_t argc = native_argc(vm);
    Int size = 0;
    if (argc >= 1) {
        UEntry *arg0 = native_arg(stack, argc, 0);
        if (!entry_number_to_int(arg0, &size) || size < 0) {
            fprintf(stderr, "gc.new expects non-negative size\n");
            return;
        }
    }
    UEntry *entry = uent_make_table(size);
    stack_push_entry(stack, entry);
}

static void native_gc_debug(UrbVM *vm, List *stack, UEntry *global)
{
    (void)vm;
    (void)global;
    stack_push_entry(stack, g_vm->null_entry);
}

static void native_gc_stats(UrbVM *vm, List *stack, UEntry *global)
{
    (void)vm;
    (void)global;
    stack_push_entry(stack, g_vm->null_entry);
}

static UEntry *object_find_by_key(UrbVM *vm, UEntry *obj, const char *name, size_t len)
{
    if (!obj || !obj->obj || obj->obj->type != U_T_TABLE) return vm ? vm->null_entry : NULL;
    UEntry *entry = table_find_by_key_len(obj, name, len);
    if (entry) return entry;
    if (!vm || !vm->common_entry || obj == vm->common_entry) {
        return vm ? vm->null_entry : NULL;
    }
    entry = table_find_by_key_len(vm->common_entry, name, len);
    return entry ? entry : vm->null_entry;
}

static int bind_args(UrbVM *vm, UFunc *fn, List *stack, uint32_t argc, UEntry *local)
{
    if (!vm || !fn || !local) return 0;
    uint32_t fixed = fn->argc;
    if (fn->has_vararg && fixed > 0) fixed--;
    for (uint32_t i = 0; i < fixed; i++) {
        UEntry *arg = stack_arg(stack, argc, i);
        if (!arg) {
            if (fn->has_default && fn->has_default[i] && fn->default_mem && fn->default_mem[i]) {
                Int before = stack->size;
                urb_interpret(vm->exec, fn->default_mem[i], stack);
                if (stack->size > (UHalf)before) {
                    arg = (UEntry*)stack->data[stack->size - 1].p;
                    stack_remove_range(stack, before, (Int)(stack->size - (UHalf)before));
                }
            }
            if (!arg) arg = vm->null_entry;
        }
        table_set_by_key_len(local, fn->arg_names[i], fn->arg_lens[i], arg);
    }
    if (fn->has_vararg) {
        UEntry *list = uent_make_table((Int)(argc > fixed ? argc - fixed : 0));
        for (uint32_t i = fixed; i < argc; i++) {
            UEntry *arg = stack_arg(stack, argc, i);
            if (!arg) arg = vm->null_entry;
            table_add_entry(list, entry_clone_shallow(arg, NULL));
        }
        table_set_by_key_len(local, fn->arg_names[fn->argc - 1], fn->arg_lens[fn->argc - 1], list);
    }
    table_set_by_key_len(local, "local", 5, local);
    return 1;
}

static void op_build_int(List *stack)
{
    Int count = urb_pop(stack).i;
    UEntry *list = uent_make_int_list(count);
    for (Int i = 0; i < count; i++) {
        UEntry *entry = stack_pop_entry(stack);
        Int iv = 0;
        Float fv = 0;
        int is_float = 0;
        if (!entry_number(entry, &iv, &fv, &is_float) || is_float) {
            iv = 0;
        }
        entry_write_int(list, count - 1 - i, iv);
    }
    stack_push_entry(stack, list);
}

static void op_build_float(List *stack)
{
    Int count = urb_pop(stack).i;
    UEntry *list = uent_make_float_list(count);
    for (Int i = 0; i < count; i++) {
        UEntry *entry = stack_pop_entry(stack);
        Int iv = 0;
        Float fv = 0;
        int is_float = 0;
        if (!entry_number(entry, &iv, &fv, &is_float)) {
            iv = 0;
            fv = 0;
            is_float = 1;
        }
        entry_write_float(list, count - 1 - i, is_float ? fv : (Float)iv);
    }
    stack_push_entry(stack, list);
}

static void op_build_object(List *stack)
{
    Int count = urb_pop(stack).i;
    UEntry *obj = uent_make_table(count);
    UEntry **keys = (UEntry**)calloc((size_t)count, sizeof(UEntry*));
    UEntry **vals = (UEntry**)calloc((size_t)count, sizeof(UEntry*));
    if (!keys || !vals) return;
    for (Int i = 0; i < count; i++) {
        UEntry *val = stack_pop_entry(stack);
        UEntry *key = stack_pop_entry(stack);
        keys[count - 1 - i] = key;
        vals[count - 1 - i] = val;
    }
    for (Int i = 0; i < count; i++) {
        UEntry *key_entry = uent_make_bytes((const char*)entry_bytes_data(keys[i]),
                                            entry_bytes_len(keys[i]), 1, 1);
        UEntry *copy = entry_clone_shallow(vals[i], key_entry);
        table_add_entry(obj, copy);
    }
    free(keys);
    free(vals);
    stack_push_entry(stack, obj);
}

static void op_index(List *stack)
{
    UEntry *index = stack_pop_entry(stack);
    UEntry *target = stack_pop_entry(stack);
    if (!target || !target->obj) {
        stack_push_entry(stack, g_vm->null_entry);
        return;
    }
    int type = target->obj->type;
    if (type == U_T_NULL) {
        stack_push_entry(stack, g_vm->null_entry);
        return;
    }
    if (type == U_T_TABLE) {
        if (entry_is_string(index)) {
            UEntry *res = object_find_by_key(g_vm, target,
                                             (const char*)entry_bytes_data(index),
                                             entry_bytes_len(index));
            stack_push_entry(stack, res ? res : g_vm->null_entry);
            return;
        }
        Int idx = 0;
        if (!entry_number_to_int(index, &idx)) {
            stack_push_entry(stack, g_vm->null_entry);
            return;
        }
        if (idx < 0 || (size_t)idx >= target->obj->as.table.size) {
            stack_push_entry(stack, g_vm->null_entry);
            return;
        }
        stack_push_entry(stack, target->obj->as.table.items[idx]);
        return;
    }
    if (type == U_T_INT) {
        Int idx = 0;
        if (!entry_number_to_int(index, &idx)) {
            stack_push_entry(stack, g_vm->null_entry);
            return;
        }
        if (entry_is_string(target)) {
            size_t len = entry_bytes_len(target);
            if (idx < 0 || (size_t)idx >= len) {
                stack_push_entry(stack, g_vm->null_entry);
                return;
            }
            char c = (char)entry_bytes_data(target)[idx];
            UEntry *out = uent_make_bytes(&c, 1, 1, target->explicit_string);
            stack_push_entry(stack, out);
            return;
        }
        Int count = entry_bytes_count(target, U_T_INT);
        if (idx < 0 || idx >= count) {
            stack_push_entry(stack, g_vm->null_entry);
            return;
        }
        Int v = 0;
        if (!entry_read_int(target, idx, &v)) v = 0;
        stack_push_entry(stack, uent_make_int_scalar(v));
        return;
    }
    if (type == U_T_FLOAT) {
        Int idx = 0;
        if (!entry_number_to_int(index, &idx)) {
            stack_push_entry(stack, g_vm->null_entry);
            return;
        }
        Int count = entry_bytes_count(target, U_T_FLOAT);
        if (idx < 0 || idx >= count) {
            stack_push_entry(stack, g_vm->null_entry);
            return;
        }
        Float v = 0;
        if (!entry_read_float(target, idx, &v)) v = 0;
        stack_push_entry(stack, uent_make_float_scalar(v));
        return;
    }
    if (index && entry_is_string(index)) {
        UEntry *res = object_find_by_key(g_vm, g_vm->common_entry,
                                         (const char*)entry_bytes_data(index),
                                         entry_bytes_len(index));
        stack_push_entry(stack, res ? res : g_vm->null_entry);
        return;
    }
    stack_push_entry(stack, g_vm->null_entry);
}

static void op_store_index(List *stack)
{
    UEntry *value = stack_pop_entry(stack);
    UEntry *index = stack_pop_entry(stack);
    UEntry *target = stack_pop_entry(stack);
    if (!target || !target->obj) return;
    int type = target->obj->type;
    if (type == U_T_TABLE && entry_is_string(index)) {
        table_set_by_key_len(target, (const char*)entry_bytes_data(index), entry_bytes_len(index), value);
        return;
    }
    Int idx = 0;
    if (!entry_number_to_int(index, &idx)) return;
    if (type == U_T_INT) {
        if (entry_is_string(target)) return;
        Int count = entry_bytes_count(target, U_T_INT);
        if (idx < 0 || idx >= count) return;
        Int iv = 0;
        Float fv = 0;
        int is_float = 0;
        if (!entry_number(value, &iv, &fv, &is_float) || is_float) return;
        entry_write_int(target, idx, iv);
        return;
    }
    if (type == U_T_FLOAT) {
        Int count = entry_bytes_count(target, U_T_FLOAT);
        if (idx < 0 || idx >= count) return;
        Int iv = 0;
        Float fv = 0;
        int is_float = 0;
        if (!entry_number(value, &iv, &fv, &is_float)) return;
        entry_write_float(target, idx, is_float ? fv : (Float)iv);
        return;
    }
    if (type == U_T_TABLE) {
        if (idx < 0 || (size_t)idx >= target->obj->as.table.size) return;
        UEntry *copy = entry_clone_shallow(value, NULL);
        target->obj->as.table.items[idx] = copy;
        return;
    }
}

static void op_load_root(List *stack)
{
    stack_push_entry(stack, g_vm->global_entry);
}

static void op_load_global(List *stack)
{
    UEntry *name = stack_pop_entry(stack);
    if (!name || !entry_is_string(name)) {
        stack_push_entry(stack, g_vm->null_entry);
        return;
    }
    UEntry *entry = NULL;
    if (g_vm->local_entry) {
        entry = table_find_by_key_len(g_vm->local_entry,
                                      (const char*)entry_bytes_data(name),
                                      entry_bytes_len(name));
    }
    if (!entry || entry == g_vm->null_entry) {
        entry = object_find_by_key(g_vm, g_vm->global_entry,
                                   (const char*)entry_bytes_data(name),
                                   entry_bytes_len(name));
    }
    stack_push_entry(stack, entry ? entry : g_vm->null_entry);
}

static void op_load_this(List *stack)
{
    stack_push_entry(stack, g_vm->this_entry ? g_vm->this_entry : g_vm->null_entry);
}

static void op_store_global(List *stack)
{
    UEntry *name = stack_pop_entry(stack);
    UEntry *value = stack_pop_entry(stack);
    if (!name || !entry_is_string(name) || !value) return;
    if (g_vm->local_entry) {
        table_set_by_key_len(g_vm->local_entry,
                             (const char*)entry_bytes_data(name),
                             entry_bytes_len(name), value);
    } else {
        table_set_by_key_len(g_vm->global_entry,
                             (const char*)entry_bytes_data(name),
                             entry_bytes_len(name), value);
    }
}

static void op_set_this(List *stack)
{
    UEntry *value = stack_pop_entry(stack);
    g_vm->this_entry = value ? value : g_vm->null_entry;
}

static void call_entry(UEntry *target, List *stack, uint32_t argc, Int override_len, int has_override)
{
    UEntry *old_this = g_vm->this_entry;
    UEntry *old_local = g_vm->local_entry;
    Int old_override = g_vm->call_override_len;
    int old_has_override = g_vm->has_call_override;
    Int old_argc = 0;
    if (g_vm->argc_entry) entry_read_int(g_vm->argc_entry, 0, &old_argc);
    g_vm->call_override_len = override_len;
    g_vm->has_call_override = has_override;
    vm_set_argc(g_vm, argc);

    Int stack_before = stack->size;
    if (target && target->obj && target->obj->type == U_T_NATIVE) {
        UNative *box = target->obj->as.native.native;
        if (box && box->fn) {
            box->fn(g_vm, stack, g_vm->global_entry);
        }
    } else if (target && target->obj && target->obj->type == U_T_LAMBDA) {
        UFunc *fn = target->obj->as.lambda.func;
        UEntry *local = uent_make_table((Int)fn->argc);
        g_vm->local_entry = local;
        if (bind_args(g_vm, fn, stack, argc, local)) {
            urb_interpret(g_vm->exec, fn->mem, stack);
        }
        g_vm->local_entry = old_local;
    }
    int has_return = stack->size > (UHalf)stack_before;
    if (argc > 0 && stack->size >= (UHalf)stack_before) {
        Int start = (Int)stack_before - (Int)argc;
        if (start < 0) start = 0;
        stack_remove_range(stack, start, (Int)argc);
    }
    if (!has_return) {
        stack_push_entry(stack, g_vm->null_entry);
    }
    g_vm->this_entry = old_this;
    g_vm->call_override_len = old_override;
    g_vm->has_call_override = old_has_override;
    if (g_vm->argc_entry) entry_write_int(g_vm->argc_entry, 0, old_argc);
}

static void op_call(List *stack)
{
    Int argc = urb_pop(stack).i;
    UEntry *name = stack_pop_entry(stack);
    if (!name || !entry_is_string(name)) {
        stack_push_entry(stack, g_vm->null_entry);
        return;
    }
    UEntry *target = NULL;
    if (g_vm->this_entry) {
        int this_type = g_vm->this_entry->obj ? g_vm->this_entry->obj->type : U_T_NULL;
        if (this_type == U_T_TABLE) {
            target = object_find_by_key(g_vm, g_vm->this_entry,
                                        (const char*)entry_bytes_data(name),
                                        entry_bytes_len(name));
            if (target == g_vm->null_entry) target = NULL;
        } else if (this_type == U_T_INT || this_type == U_T_FLOAT) {
            if (g_vm->common_entry) {
                target = object_find_by_key(g_vm, g_vm->common_entry,
                                            (const char*)entry_bytes_data(name),
                                            entry_bytes_len(name));
            }
        }
    }
    UEntry *entry = object_find_by_key(g_vm, g_vm->global_entry,
                                       (const char*)entry_bytes_data(name),
                                       entry_bytes_len(name));
    if (entry == g_vm->null_entry) entry = NULL;
    if (!target) target = entry;
    if (!target) {
        stack_push_entry(stack, g_vm->null_entry);
        return;
    }
    call_entry(target, stack, (uint32_t)argc, -1, 0);
}

static void op_call_ex(List *stack)
{
    Int override_len = urb_pop(stack).i;
    Int argc = urb_pop(stack).i;
    UEntry *name = stack_pop_entry(stack);
    if (!name || !entry_is_string(name)) {
        stack_push_entry(stack, g_vm->null_entry);
        return;
    }
    UEntry *target = NULL;
    if (g_vm->this_entry) {
        int this_type = g_vm->this_entry->obj ? g_vm->this_entry->obj->type : U_T_NULL;
        if (this_type == U_T_TABLE) {
            target = object_find_by_key(g_vm, g_vm->this_entry,
                                        (const char*)entry_bytes_data(name),
                                        entry_bytes_len(name));
            if (target == g_vm->null_entry) target = NULL;
        } else if (this_type == U_T_INT || this_type == U_T_FLOAT) {
            if (g_vm->common_entry) {
                target = object_find_by_key(g_vm, g_vm->common_entry,
                                            (const char*)entry_bytes_data(name),
                                            entry_bytes_len(name));
            }
        }
    }
    UEntry *entry = object_find_by_key(g_vm, g_vm->global_entry,
                                       (const char*)entry_bytes_data(name),
                                       entry_bytes_len(name));
    if (entry == g_vm->null_entry) entry = NULL;
    if (!target) target = entry;
    if (!target) {
        stack_push_entry(stack, g_vm->null_entry);
        return;
    }
    call_entry(target, stack, (uint32_t)argc, override_len, 1);
}

static void op_strict(List *stack)
{
    (void)stack;
    g_vm->strict_mode = 1;
}

static void op_add(List *stack)
{
    UEntry *right = stack_pop_entry(stack);
    UEntry *left = stack_pop_entry(stack);
    if (!left || !right) {
        stack_push_entry(stack, g_vm->null_entry);
        return;
    }
    if (entry_is_string(left) || entry_is_string(right)) {
        StrBuf buf;
        sb_init(&buf);
        append_value_text(g_vm, left, &buf, 1);
        append_value_text(g_vm, right, &buf, 1);
        UEntry *entry = uent_make_bytes(buf.data, buf.len, 1, left->explicit_string || right->explicit_string);
        sb_free(&buf);
        stack_push_entry(stack, entry);
        return;
    }
    Int li = 0, ri = 0;
    Float lf = 0, rf = 0;
    int lf_is_float = 0, rf_is_float = 0;
    if (!entry_number(left, &li, &lf, &lf_is_float) ||
        !entry_number(right, &ri, &rf, &rf_is_float)) {
        stack_push_entry(stack, g_vm->null_entry);
        return;
    }
    if (g_vm->strict_mode && lf_is_float != rf_is_float) {
        stack_push_entry(stack, g_vm->null_entry);
        return;
    }
    double l = lf_is_float ? (double)lf : (double)li;
    double r = rf_is_float ? (double)rf : (double)ri;
    double out = l + r;
    if (out >= (double)INT_MIN && out <= (double)INT_MAX) {
        Int iv = (Int)out;
        if ((double)iv == out) {
            stack_push_entry(stack, uent_make_int_scalar(iv));
            return;
        }
    }
    stack_push_entry(stack, uent_make_float_scalar((Float)out));
}

static void op_sub(List *stack)
{
    UEntry *right = stack_pop_entry(stack);
    UEntry *left = stack_pop_entry(stack);
    Int li = 0, ri = 0;
    Float lf = 0, rf = 0;
    int lf_is_float = 0, rf_is_float = 0;
    if (!entry_number(left, &li, &lf, &lf_is_float) ||
        !entry_number(right, &ri, &rf, &rf_is_float)) {
        stack_push_entry(stack, g_vm->null_entry);
        return;
    }
    if (g_vm->strict_mode && lf_is_float != rf_is_float) {
        stack_push_entry(stack, g_vm->null_entry);
        return;
    }
    double l = lf_is_float ? (double)lf : (double)li;
    double r = rf_is_float ? (double)rf : (double)ri;
    double out = l - r;
    if (out >= (double)INT_MIN && out <= (double)INT_MAX) {
        Int iv = (Int)out;
        if ((double)iv == out) {
            stack_push_entry(stack, uent_make_int_scalar(iv));
            return;
        }
    }
    stack_push_entry(stack, uent_make_float_scalar((Float)out));
}

static void op_mul(List *stack)
{
    UEntry *right = stack_pop_entry(stack);
    UEntry *left = stack_pop_entry(stack);
    Int li = 0, ri = 0;
    Float lf = 0, rf = 0;
    int lf_is_float = 0, rf_is_float = 0;
    if (!entry_number(left, &li, &lf, &lf_is_float) ||
        !entry_number(right, &ri, &rf, &rf_is_float)) {
        stack_push_entry(stack, g_vm->null_entry);
        return;
    }
    if (g_vm->strict_mode && lf_is_float != rf_is_float) {
        stack_push_entry(stack, g_vm->null_entry);
        return;
    }
    double l = lf_is_float ? (double)lf : (double)li;
    double r = rf_is_float ? (double)rf : (double)ri;
    double out = l * r;
    if (out >= (double)INT_MIN && out <= (double)INT_MAX) {
        Int iv = (Int)out;
        if ((double)iv == out) {
            stack_push_entry(stack, uent_make_int_scalar(iv));
            return;
        }
    }
    stack_push_entry(stack, uent_make_float_scalar((Float)out));
}

static void op_div(List *stack)
{
    UEntry *right = stack_pop_entry(stack);
    UEntry *left = stack_pop_entry(stack);
    Int li = 0, ri = 0;
    Float lf = 0, rf = 0;
    int lf_is_float = 0, rf_is_float = 0;
    if (!entry_number(left, &li, &lf, &lf_is_float) ||
        !entry_number(right, &ri, &rf, &rf_is_float)) {
        stack_push_entry(stack, g_vm->null_entry);
        return;
    }
    if (g_vm->strict_mode && lf_is_float != rf_is_float) {
        stack_push_entry(stack, g_vm->null_entry);
        return;
    }
    double l = lf_is_float ? (double)lf : (double)li;
    double r = rf_is_float ? (double)rf : (double)ri;
    double out = l / r;
    if (out >= (double)INT_MIN && out <= (double)INT_MAX) {
        Int iv = (Int)out;
        if ((double)iv == out) {
            stack_push_entry(stack, uent_make_int_scalar(iv));
            return;
        }
    }
    stack_push_entry(stack, uent_make_float_scalar((Float)out));
}

static void op_mod(List *stack)
{
    UEntry *right = stack_pop_entry(stack);
    UEntry *left = stack_pop_entry(stack);
    Int li = 0, ri = 0;
    Float lf = 0, rf = 0;
    int lf_is_float = 0, rf_is_float = 0;
    if (!entry_number(left, &li, &lf, &lf_is_float) ||
        !entry_number(right, &ri, &rf, &rf_is_float)) {
        stack_push_entry(stack, g_vm->null_entry);
        return;
    }
    if (g_vm->strict_mode && lf_is_float != rf_is_float) {
        stack_push_entry(stack, g_vm->null_entry);
        return;
    }
    double l = lf_is_float ? (double)lf : (double)li;
    double r = rf_is_float ? (double)rf : (double)ri;
    double out = fmod(l, r);
    if (out >= (double)INT_MIN && out <= (double)INT_MAX) {
        Int iv = (Int)out;
        if ((double)iv == out) {
            stack_push_entry(stack, uent_make_int_scalar(iv));
            return;
        }
    }
    stack_push_entry(stack, uent_make_float_scalar((Float)out));
}

static void op_neg(List *stack)
{
    UEntry *value = stack_pop_entry(stack);
    Int iv = 0;
    Float fv = 0;
    int is_float = 0;
    if (!entry_number(value, &iv, &fv, &is_float)) {
        stack_push_entry(stack, g_vm->null_entry);
        return;
    }
    double out = is_float ? -(double)fv : -(double)iv;
    if (out >= (double)INT_MIN && out <= (double)INT_MAX) {
        Int iout = (Int)out;
        if ((double)iout == out) {
            stack_push_entry(stack, uent_make_int_scalar(iout));
            return;
        }
    }
    stack_push_entry(stack, uent_make_float_scalar((Float)out));
}

static void op_not(List *stack)
{
    UEntry *value = stack_pop_entry(stack);
    int res = entry_truthy(value) ? 0 : 1;
    stack_push_entry(stack, uent_make_int_scalar(res));
}

static void op_eq(List *stack)
{
    UEntry *right = stack_pop_entry(stack);
    UEntry *left = stack_pop_entry(stack);
    if (g_vm->strict_mode) {
        int lt = left && left->obj ? left->obj->type : U_T_NULL;
        int rt = right && right->obj ? right->obj->type : U_T_NULL;
        if ((lt == U_T_INT || lt == U_T_FLOAT) &&
            (rt == U_T_INT && entry_is_string(right))) {
            stack_push_entry(stack, g_vm->null_entry);
            return;
        }
        if ((rt == U_T_INT || rt == U_T_FLOAT) &&
            (lt == U_T_INT && entry_is_string(left))) {
            stack_push_entry(stack, g_vm->null_entry);
            return;
        }
        if ((lt == U_T_INT || lt == U_T_FLOAT) &&
            (rt == U_T_INT || rt == U_T_FLOAT) && lt != rt) {
            stack_push_entry(stack, g_vm->null_entry);
            return;
        }
    }
    int eq = entry_equal(left, right);
    stack_push_entry(stack, uent_make_int_scalar(eq ? 1 : 0));
}

static void op_neq(List *stack)
{
    UEntry *right = stack_pop_entry(stack);
    UEntry *left = stack_pop_entry(stack);
    if (g_vm->strict_mode) {
        int lt = left && left->obj ? left->obj->type : U_T_NULL;
        int rt = right && right->obj ? right->obj->type : U_T_NULL;
        if ((lt == U_T_INT || lt == U_T_FLOAT) &&
            (rt == U_T_INT && entry_is_string(right))) {
            stack_push_entry(stack, g_vm->null_entry);
            return;
        }
        if ((rt == U_T_INT || rt == U_T_FLOAT) &&
            (lt == U_T_INT && entry_is_string(left))) {
            stack_push_entry(stack, g_vm->null_entry);
            return;
        }
        if ((lt == U_T_INT || lt == U_T_FLOAT) &&
            (rt == U_T_INT || rt == U_T_FLOAT) && lt != rt) {
            stack_push_entry(stack, g_vm->null_entry);
            return;
        }
    }
    int eq = entry_equal(left, right);
    stack_push_entry(stack, uent_make_int_scalar(eq ? 0 : 1));
}

static void op_cmp(List *stack, int op)
{
    UEntry *right = stack_pop_entry(stack);
    UEntry *left = stack_pop_entry(stack);
    if (g_vm->strict_mode) {
        int lt = left && left->obj ? left->obj->type : U_T_NULL;
        int rt = right && right->obj ? right->obj->type : U_T_NULL;
        if ((lt == U_T_INT || lt == U_T_FLOAT) &&
            (rt == U_T_INT && entry_is_string(right))) {
            stack_push_entry(stack, g_vm->null_entry);
            return;
        }
        if ((rt == U_T_INT || rt == U_T_FLOAT) &&
            (lt == U_T_INT && entry_is_string(left))) {
            stack_push_entry(stack, g_vm->null_entry);
            return;
        }
        if ((lt == U_T_INT || lt == U_T_FLOAT) &&
            (rt == U_T_INT || rt == U_T_FLOAT) && lt != rt) {
            stack_push_entry(stack, g_vm->null_entry);
            return;
        }
    }
    int cmp = 0;
    if (!entry_compare(left, right, &cmp)) {
        stack_push_entry(stack, g_vm->null_entry);
        return;
    }
    int res = 0;
    if (op == BC_LT) res = cmp < 0;
    else if (op == BC_LTE) res = cmp <= 0;
    else if (op == BC_GT) res = cmp > 0;
    else if (op == BC_GTE) res = cmp >= 0;
    stack_push_entry(stack, uent_make_int_scalar(res ? 1 : 0));
}

static void op_and(List *stack)
{
    UEntry *right = stack_pop_entry(stack);
    UEntry *left = stack_pop_entry(stack);
    int l = entry_truthy(left);
    int r = entry_truthy(right);
    int res = l && r;
    stack_push_entry(stack, uent_make_int_scalar(res ? 1 : 0));
}

static void op_or(List *stack)
{
    UEntry *right = stack_pop_entry(stack);
    UEntry *left = stack_pop_entry(stack);
    int l = entry_truthy(left);
    int r = entry_truthy(right);
    int res = l || r;
    stack_push_entry(stack, uent_make_int_scalar(res ? 1 : 0));
}

static void op_lt(List *stack)
{
    op_cmp(stack, BC_LT);
}

static void op_lte(List *stack)
{
    op_cmp(stack, BC_LTE);
}

static void op_gt(List *stack)
{
    op_cmp(stack, BC_GT);
}

static void op_gte(List *stack)
{
    op_cmp(stack, BC_GTE);
}

static void op_pop(List *stack)
{
    if (stack && stack->size > 0) {
        urb_pop(stack);
    }
}

static void op_dup(List *stack)
{
    UEntry *top = stack_peek_entry(stack, 0);
    if (!top || !top->obj) return;
    if (top->obj->type == U_T_INT || top->obj->type == U_T_FLOAT) {
        UEntry *dup = entry_clone_deep(top);
        stack_push_entry(stack, dup);
    } else {
        stack_push_entry(stack, top);
    }
}

static void op_gc(List *stack)
{
    (void)stack;
}

static void op_dump(List *stack)
{
    (void)stack;
}

static void op_truthy(List *stack)
{
    UEntry *value = stack_pop_entry(stack);
    Int res = entry_truthy(value) ? 1 : 0;
    Value v;
    v.i = res;
    urb_push(stack, v);
}

static void op_not_int(List *stack)
{
    Int v = urb_pop(stack).i;
    Value out;
    out.i = v ? 0 : 1;
    urb_push(stack, out);
}

static void op_swap(List *stack)
{
    if (!stack || stack->size < 2) return;
    Value a = urb_pop(stack);
    Value b = urb_pop(stack);
    urb_push(stack, a);
    urb_push(stack, b);
}

enum {
    OP_BUILD_INT = 0,
    OP_BUILD_FLOAT,
    OP_BUILD_OBJECT,
    OP_INDEX,
    OP_STORE_INDEX,
    OP_LOAD_ROOT,
    OP_LOAD_GLOBAL,
    OP_LOAD_THIS,
    OP_STORE_GLOBAL,
    OP_SET_THIS,
    OP_CALL,
    OP_CALL_EX,
    OP_STRICT,
    OP_ADD,
    OP_SUB,
    OP_MUL,
    OP_DIV,
    OP_MOD,
    OP_NEG,
    OP_NOT,
    OP_EQ,
    OP_NEQ,
    OP_LT,
    OP_LTE,
    OP_GT,
    OP_GTE,
    OP_AND,
    OP_OR,
    OP_POP,
    OP_DUP,
    OP_GC,
    OP_DUMP,
    OP_TRUTHY,
    OP_NOT_INT,
    OP_SWAP,
    OP_COUNT
};

static void exec_init(List **out_exec)
{
    List *exec = urb_new(OP_COUNT);
    exec->size = OP_COUNT;
    exec->data[OP_BUILD_INT].fn = op_build_int;
    exec->data[OP_BUILD_FLOAT].fn = op_build_float;
    exec->data[OP_BUILD_OBJECT].fn = op_build_object;
    exec->data[OP_INDEX].fn = op_index;
    exec->data[OP_STORE_INDEX].fn = op_store_index;
    exec->data[OP_LOAD_ROOT].fn = op_load_root;
    exec->data[OP_LOAD_GLOBAL].fn = op_load_global;
    exec->data[OP_LOAD_THIS].fn = op_load_this;
    exec->data[OP_STORE_GLOBAL].fn = op_store_global;
    exec->data[OP_SET_THIS].fn = op_set_this;
    exec->data[OP_CALL].fn = op_call;
    exec->data[OP_CALL_EX].fn = op_call_ex;
    exec->data[OP_STRICT].fn = op_strict;
    exec->data[OP_ADD].fn = op_add;
    exec->data[OP_SUB].fn = op_sub;
    exec->data[OP_MUL].fn = op_mul;
    exec->data[OP_DIV].fn = op_div;
    exec->data[OP_MOD].fn = op_mod;
    exec->data[OP_NEG].fn = op_neg;
    exec->data[OP_NOT].fn = op_not;
    exec->data[OP_EQ].fn = op_eq;
    exec->data[OP_NEQ].fn = op_neq;
    exec->data[OP_LT].fn = op_lt;
    exec->data[OP_LTE].fn = op_lte;
    exec->data[OP_GT].fn = op_gt;
    exec->data[OP_GTE].fn = op_gte;
    exec->data[OP_AND].fn = op_and;
    exec->data[OP_OR].fn = op_or;
    exec->data[OP_POP].fn = op_pop;
    exec->data[OP_DUP].fn = op_dup;
    exec->data[OP_GC].fn = op_gc;
    exec->data[OP_DUMP].fn = op_dump;
    exec->data[OP_TRUTHY].fn = op_truthy;
    exec->data[OP_NOT_INT].fn = op_not_int;
    exec->data[OP_SWAP].fn = op_swap;
    *out_exec = exec;
}

static Value op_token(int op_index)
{
    Value v;
    v.i = (Int)(INT_MIN + OP_CODES_OFFSET + op_index);
    return v;
}

typedef struct {
    Value *data;
    size_t len;
    size_t cap;
} ValVec;

static void vec_init(ValVec *v)
{
    v->data = NULL;
    v->len = 0;
    v->cap = 0;
}

static void vec_push(ValVec *v, Value val)
{
    if (v->len == v->cap) {
        size_t next = v->cap == 0 ? 128 : v->cap * 2;
        Value *data = (Value*)realloc(v->data, next * sizeof(Value));
        if (!data) return;
        v->data = data;
        v->cap = next;
    }
    v->data[v->len++] = val;
}

typedef struct {
    size_t mem_index;
    size_t target_pc;
} Patch;

typedef struct {
    Patch *data;
    size_t len;
    size_t cap;
} PatchVec;

static void patch_push(PatchVec *v, size_t mem_index, size_t target_pc)
{
    if (v->len == v->cap) {
        size_t next = v->cap == 0 ? 64 : v->cap * 2;
        Patch *data = (Patch*)realloc(v->data, next * sizeof(Patch));
        if (!data) return;
        v->data = data;
        v->cap = next;
    }
    v->data[v->len].mem_index = mem_index;
    v->data[v->len].target_pc = target_pc;
    v->len++;
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

static int bc_read_string(const unsigned char *data, size_t len, size_t *pc, unsigned char **out, size_t *out_len)
{
    uint32_t slen = 0;
    if (!bc_read_u32(data, len, pc, &slen)) return 0;
    if (*pc + slen > len) return 0;
    unsigned char *buf = NULL;
    if (slen) {
        buf = (unsigned char*)malloc(slen);
        if (!buf) return 0;
        memcpy(buf, data + *pc, slen);
    }
    *pc += slen;
    *out = buf;
    *out_len = slen;
    return 1;
}

typedef struct {
    List *mem;
    List *exec;
} UrbProgram;

static UrbProgram translate_bytecode(const unsigned char *data, size_t len, List *exec)
{
    UrbProgram prog;
    prog.mem = NULL;
    prog.exec = exec;

    size_t *pc_to_mem = (size_t*)malloc((len + 1) * sizeof(size_t));
    for (size_t i = 0; i <= len; i++) pc_to_mem[i] = (size_t)-1;

    ValVec vec;
    vec_init(&vec);
    PatchVec patches = {0};
    PatchVec returns = {0};

    size_t pc = 0;
    while (pc < len) {
        pc_to_mem[pc] = vec.len;
        uint8_t op = 0;
        if (!bc_read_u8(data, len, &pc, &op)) break;
        switch (op) {
        case BC_PUSH_INT: {
            int64_t v = 0;
            if (!bc_read_i64(data, len, &pc, &v)) break;
            Value val;
            val.p = uent_make_int_scalar((Int)v);
            vec_push(&vec, val);
            break;
        }
        case BC_PUSH_FLOAT: {
            double v = 0.0;
            if (!bc_read_f64(data, len, &pc, &v)) break;
            Value val;
            val.p = uent_make_float_scalar((Float)v);
            vec_push(&vec, val);
            break;
        }
        case BC_PUSH_CHAR:
        case BC_PUSH_STRING: {
            unsigned char *buf = NULL;
            size_t slen = 0;
            if (!bc_read_string(data, len, &pc, &buf, &slen)) break;
            char *processed = urb_bridge_papagaio((const char*)buf, slen);
            if (processed) {
                Value val;
                val.p = uent_make_bytes(processed, strlen(processed), 1, 0);
                free(processed);
                free(buf);
                vec_push(&vec, val);
                break;
            }
            Value val;
            val.p = uent_make_bytes((const char*)buf, slen, 1, 0);
            free(buf);
            vec_push(&vec, val);
            break;
        }
        case BC_PUSH_CHAR_RAW:
        case BC_PUSH_STRING_RAW: {
            unsigned char *buf = NULL;
            size_t slen = 0;
            if (!bc_read_string(data, len, &pc, &buf, &slen)) break;
            Value val;
            val.p = uent_make_bytes((const char*)buf, slen, 1, 0);
            free(buf);
            vec_push(&vec, val);
            break;
        }
        case BC_BUILD_INT: {
            uint32_t count = 0;
            if (!bc_read_u32(data, len, &pc, &count)) break;
            Value cnt; cnt.i = (Int)count;
            vec_push(&vec, cnt);
            vec_push(&vec, op_token(OP_BUILD_INT));
            break;
        }
        case BC_BUILD_FLOAT: {
            uint32_t count = 0;
            if (!bc_read_u32(data, len, &pc, &count)) break;
            Value cnt; cnt.i = (Int)count;
            vec_push(&vec, cnt);
            vec_push(&vec, op_token(OP_BUILD_FLOAT));
            break;
        }
        case BC_BUILD_OBJECT: {
            uint32_t count = 0;
            if (!bc_read_u32(data, len, &pc, &count)) break;
            Value cnt; cnt.i = (Int)count;
            vec_push(&vec, cnt);
            vec_push(&vec, op_token(OP_BUILD_OBJECT));
            break;
        }
        case BC_BUILD_INT_LIT: {
            uint32_t count = 0;
            if (!bc_read_u32(data, len, &pc, &count)) break;
            UEntry *list = uent_make_int_list((Int)count);
            for (uint32_t i = 0; i < count; i++) {
                int64_t v = 0;
                if (!bc_read_i64(data, len, &pc, &v)) break;
                entry_write_int(list, (Int)i, (Int)v);
            }
            Value val; val.p = list;
            vec_push(&vec, val);
            break;
        }
        case BC_BUILD_FLOAT_LIT: {
            uint32_t count = 0;
            if (!bc_read_u32(data, len, &pc, &count)) break;
            UEntry *list = uent_make_float_list((Int)count);
            for (uint32_t i = 0; i < count; i++) {
                double v = 0.0;
                if (!bc_read_f64(data, len, &pc, &v)) break;
                entry_write_float(list, (Int)i, (Float)v);
            }
            Value val; val.p = list;
            vec_push(&vec, val);
            break;
        }
        case BC_BUILD_FUNCTION: {
            uint32_t argc = 0;
            uint32_t vararg = 0;
            uint32_t code_len = 0;
            if (!bc_read_u32(data, len, &pc, &argc) ||
                !bc_read_u32(data, len, &pc, &vararg) ||
                !bc_read_u32(data, len, &pc, &code_len)) break;
            if (pc + code_len > len) break;
            unsigned char *code = NULL;
            if (code_len) {
                code = (unsigned char*)malloc(code_len);
                if (!code) break;
                memcpy(code, data + pc, code_len);
            }
            pc += code_len;
            char **arg_names = argc ? (char**)calloc(argc, sizeof(char*)) : NULL;
            size_t *arg_lens = argc ? (size_t*)calloc(argc, sizeof(size_t)) : NULL;
            List **default_mem = argc ? (List**)calloc(argc, sizeof(List*)) : NULL;
            uint8_t *has_default = argc ? (uint8_t*)calloc(argc, sizeof(uint8_t)) : NULL;
            for (uint32_t i = 0; i < argc; i++) {
                unsigned char *name = NULL;
                size_t name_len = 0;
                if (!bc_read_string(data, len, &pc, &name, &name_len)) break;
                arg_names[i] = (char*)name;
                arg_lens[i] = name_len;
                uint32_t def_len = 0;
                if (!bc_read_u32(data, len, &pc, &def_len)) break;
                if (def_len > 0) {
                    if (pc + def_len > len) break;
                    UrbProgram defp = translate_bytecode(data + pc, def_len, exec);
                    default_mem[i] = defp.mem;
                    has_default[i] = 1;
                    pc += def_len;
                }
            }
            UrbProgram body = translate_bytecode(code, code_len, exec);
            free(code);
            UFunc *fn = (UFunc*)calloc(1, sizeof(UFunc));
            fn->mem = body.mem;
            fn->argc = argc;
            fn->has_vararg = vararg ? 1 : 0;
            fn->arg_names = arg_names;
            fn->arg_lens = arg_lens;
            fn->default_mem = default_mem;
            fn->has_default = has_default;
            UObj *obj = uobj_new(U_T_LAMBDA);
            obj->as.lambda.func = fn;
            UEntry *entry = uent_new(obj);
            Value val; val.p = entry;
            vec_push(&vec, val);
            break;
        }
        case BC_INDEX:
            vec_push(&vec, op_token(OP_INDEX));
            break;
        case BC_STORE_INDEX:
            vec_push(&vec, op_token(OP_STORE_INDEX));
            break;
        case BC_LOAD_ROOT:
            vec_push(&vec, op_token(OP_LOAD_ROOT));
            break;
        case BC_LOAD_THIS:
            vec_push(&vec, op_token(OP_LOAD_THIS));
            break;
        case BC_LOAD_GLOBAL:
        case BC_STORE_GLOBAL: {
            unsigned char *name = NULL;
            size_t name_len = 0;
            if (!bc_read_string(data, len, &pc, &name, &name_len)) break;
            Value val;
            val.p = uent_make_bytes((const char*)name, name_len, 1, 1);
            free(name);
            vec_push(&vec, val);
            vec_push(&vec, op_token(op == BC_LOAD_GLOBAL ? OP_LOAD_GLOBAL : OP_STORE_GLOBAL));
            break;
        }
        case BC_SET_THIS:
            vec_push(&vec, op_token(OP_SET_THIS));
            break;
        case BC_CALL:
        case BC_CALL_EX: {
            unsigned char *name = NULL;
            size_t name_len = 0;
            if (!bc_read_string(data, len, &pc, &name, &name_len)) break;
            uint32_t argc = 0;
            if (!bc_read_u32(data, len, &pc, &argc)) break;
            Value name_val; name_val.p = uent_make_bytes((const char*)name, name_len, 1, 1);
            free(name);
            vec_push(&vec, name_val);
            Value argc_val; argc_val.i = (Int)argc;
            vec_push(&vec, argc_val);
            if (op == BC_CALL_EX) {
                uint32_t override_len = 0;
                if (!bc_read_u32(data, len, &pc, &override_len)) break;
                Value ov; ov.i = (Int)override_len;
                vec_push(&vec, ov);
                vec_push(&vec, op_token(OP_CALL_EX));
            } else {
                vec_push(&vec, op_token(OP_CALL));
            }
            break;
        }
        case BC_STRICT:
            vec_push(&vec, op_token(OP_STRICT));
            break;
        case BC_JMP: {
            uint32_t target = 0;
            if (!bc_read_u32(data, len, &pc, &target)) break;
            Value t; t.i = 0;
            size_t t_index = vec.len;
            vec_push(&vec, t);
            vec_push(&vec, (Value){.i = ALIAS_GOTO});
            patch_push(&patches, t_index, target);
            break;
        }
        case BC_JMP_IF_FALSE: {
            uint32_t target = 0;
            if (!bc_read_u32(data, len, &pc, &target)) break;
            vec_push(&vec, op_token(OP_TRUTHY));
            vec_push(&vec, op_token(OP_NOT_INT));
            Value t; t.i = 0;
            size_t t_index = vec.len;
            vec_push(&vec, t);
            vec_push(&vec, op_token(OP_SWAP));
            vec_push(&vec, (Value){.i = ALIAS_GOIF});
            patch_push(&patches, t_index, target);
            break;
        }
        case BC_RETURN: {
            Value t; t.i = 0;
            size_t t_index = vec.len;
            vec_push(&vec, t);
            vec_push(&vec, (Value){.i = ALIAS_GOTO});
            patch_push(&returns, t_index, (size_t)-1);
            break;
        }
        case BC_POP:
            vec_push(&vec, op_token(OP_POP));
            break;
        case BC_DUP:
            vec_push(&vec, op_token(OP_DUP));
            break;
        case BC_GC:
            vec_push(&vec, op_token(OP_GC));
            break;
        case BC_DUMP:
            vec_push(&vec, op_token(OP_DUMP));
            break;
        case BC_ADD:
            vec_push(&vec, op_token(OP_ADD));
            break;
        case BC_SUB:
            vec_push(&vec, op_token(OP_SUB));
            break;
        case BC_MUL:
            vec_push(&vec, op_token(OP_MUL));
            break;
        case BC_DIV:
            vec_push(&vec, op_token(OP_DIV));
            break;
        case BC_MOD:
            vec_push(&vec, op_token(OP_MOD));
            break;
        case BC_NEG:
            vec_push(&vec, op_token(OP_NEG));
            break;
        case BC_NOT:
            vec_push(&vec, op_token(OP_NOT));
            break;
        case BC_EQ:
            vec_push(&vec, op_token(OP_EQ));
            break;
        case BC_NEQ:
            vec_push(&vec, op_token(OP_NEQ));
            break;
        case BC_LT:
            vec_push(&vec, op_token(OP_LT));
            break;
        case BC_LTE:
            vec_push(&vec, op_token(OP_LTE));
            break;
        case BC_GT:
            vec_push(&vec, op_token(OP_GT));
            break;
        case BC_GTE:
            vec_push(&vec, op_token(OP_GTE));
            break;
        case BC_AND:
            vec_push(&vec, op_token(OP_AND));
            break;
        case BC_OR:
            vec_push(&vec, op_token(OP_OR));
            break;
        default:
            break;
        }
    }

    for (size_t i = 0; i < patches.len; i++) {
        size_t target_pc = patches.data[i].target_pc;
        size_t mem_index = pc_to_mem[target_pc];
        if (mem_index == (size_t)-1) mem_index = vec.len;
        vec.data[patches.data[i].mem_index].i = (Int)mem_index;
    }
    for (size_t i = 0; i < returns.len; i++) {
        vec.data[returns.data[i].mem_index].i = (Int)vec.len;
    }

    List *mem = urb_new((Int)vec.len);
    mem->size = (UHalf)vec.len;
    if (vec.len > 0) {
        memcpy(mem->data, vec.data, vec.len * sizeof(Value));
    }
    prog.mem = mem;

    free(vec.data);
    free(patches.data);
    free(returns.data);
    free(pc_to_mem);
    return prog;
}

static void exec_bytecode_in_vm(UrbVM *vm, const unsigned char *data, size_t len, List *stack)
{
    if (!vm || !data || len == 0) return;
    UrbProgram program = translate_bytecode(data, len, vm->exec);
    if (program.mem) {
        urb_interpret(vm->exec, program.mem, stack);
        urb_free(program.mem);
    }
}

static void vm_init(UrbVM *vm)
{
    memset(vm, 0, sizeof(*vm));
    vm->strict_mode = 0;
    vm->call_override_len = -1;
    vm->has_call_override = 0;
    exec_init(&vm->exec);

    vm->global_entry = uent_make_table(8);
    UEntry *stack_entry = uent_make_table(8);
    vm->stack_entry = stack_entry;
    vm->null_entry = uent_make_null();
    vm->common_entry = uent_make_table(16);
    vm->argc_entry = uent_make_int_scalar(0);
    vm->this_entry = vm->null_entry;

    table_set_by_key_len(vm->global_entry, "global", 6, vm->global_entry);
    table_set_by_key_len(vm->global_entry, "stack", 5, vm->stack_entry);
    table_set_by_key_len(vm->global_entry, "null", 4, vm->null_entry);
    table_set_by_key_len(vm->global_entry, "common", 6, vm->common_entry);
    table_set_by_key_len(vm->global_entry, "__argc", 6, vm->argc_entry);

    UEntry *gc_entry = uent_make_table(8);
    table_set_by_key_len(vm->global_entry, "gc", 2, gc_entry);

    register_native(vm, "print", native_print, 1);
    register_native(vm, "println", native_println, 1);
    register_native(vm, "len", native_len, 1);
    register_native(vm, "pretty", native_pretty, 1);
    register_native(vm, "clone", native_clone, 1);
    register_native(vm, "copy", native_copy, 1);
    register_native(vm, "toInt", native_to_int, 1);
    register_native(vm, "toFloat", native_to_float, 1);
    register_native(vm, "gc", native_gc_collect, 1);

    #ifdef DISTURB_ENABLE_IO
    register_native(vm, "read", native_read, 1);
    register_native(vm, "write", native_write, 1);
    #endif
    #ifdef DISTURB_ENABLE_SYSTEM
    register_native(vm, "system", native_system, 1);
    #endif
    #ifdef DISTURB_ENABLE_FFI
    register_native(vm, "ffiLoad", native_ffi_load, 1);
    #endif

    register_native(vm, "eval", native_eval, 1);
    register_native(vm, "parse", native_parse, 1);
    register_native(vm, "emit", native_emit, 1);
    register_native(vm, "evalBytecode", native_eval_bytecode, 1);

    register_native(vm, "append", native_append, 1);
    register_native(vm, "add", native_add, 1);
    register_native(vm, "sub", native_sub, 1);
    register_native(vm, "mul", native_mul, 1);
    register_native(vm, "div", native_div, 1);
    register_native(vm, "mod", native_mod, 1);
    register_native(vm, "pow", native_pow, 1);
    register_native(vm, "min", native_min, 1);
    register_native(vm, "max", native_max, 1);
    register_native(vm, "abs", native_abs, 1);
    register_native(vm, "floor", native_floor, 1);
    register_native(vm, "ceil", native_ceil, 1);
    register_native(vm, "round", native_round, 1);
    register_native(vm, "sqrt", native_sqrt, 1);
    register_native(vm, "sin", native_sin, 1);
    register_native(vm, "cos", native_cos, 1);
    register_native(vm, "tan", native_tan, 1);
    register_native(vm, "asin", native_asin, 1);
    register_native(vm, "acos", native_acos, 1);
    register_native(vm, "atan", native_atan, 1);
    register_native(vm, "log", native_log, 1);
    register_native(vm, "exp", native_exp, 1);
    register_native(vm, "slice", native_slice, 1);
    register_native(vm, "substr", native_substr, 1);
    register_native(vm, "split", native_split, 1);
    register_native(vm, "join", native_join, 1);
    register_native(vm, "upper", native_upper, 1);
    register_native(vm, "lower", native_lower, 1);
    register_native(vm, "trim", native_trim, 1);
    register_native(vm, "startsWith", native_starts_with, 1);
    register_native(vm, "endsWith", native_ends_with, 1);
    register_native(vm, "find", native_find, 1);
    register_native(vm, "rfind", native_rfind, 1);
    register_native(vm, "contains", native_contains, 1);
    register_native(vm, "replace", native_replace, 1);
    register_native(vm, "replaceAll", native_replace_all, 1);
    register_native(vm, "papagaio", native_papagaio, 1);
    register_native(vm, "keys", native_keys, 1);
    register_native(vm, "values", native_values, 1);
    register_native(vm, "has", native_has, 1);
    register_native(vm, "delete", native_delete, 1);
    register_native(vm, "push", native_push, 1);
    register_native(vm, "pop", native_pop, 1);
    register_native(vm, "shift", native_shift, 1);
    register_native(vm, "unshift", native_unshift, 1);
    register_native(vm, "insert", native_insert, 1);
    register_native(vm, "remove", native_remove, 1);

    register_native(vm, "gcCollect", native_gc_collect, 0);
    register_native(vm, "gcFree", native_gc_free, 0);
    register_native(vm, "gcSweep", native_gc_sweep, 0);
    register_native(vm, "gcNew", native_gc_new, 0);
    register_native(vm, "gcDebug", native_gc_debug, 0);
    register_native(vm, "gcStats", native_gc_stats, 0);

    table_set_by_key_len(gc_entry, "collect", 7, table_find_by_key_len(vm->global_entry, "gcCollect", 9));
    table_set_by_key_len(gc_entry, "free", 4, table_find_by_key_len(vm->global_entry, "gcFree", 6));
    table_set_by_key_len(gc_entry, "sweep", 5, table_find_by_key_len(vm->global_entry, "gcSweep", 7));
    table_set_by_key_len(gc_entry, "new", 3, table_find_by_key_len(vm->global_entry, "gcNew", 5));
    table_set_by_key_len(gc_entry, "debug", 5, table_find_by_key_len(vm->global_entry, "gcDebug", 7));
    table_set_by_key_len(gc_entry, "stats", 5, table_find_by_key_len(vm->global_entry, "gcStats", 7));
}

static void vm_set_args(UrbVM *vm, int argc, char **argv)
{
    if (!vm) return;
    UEntry *args = uent_make_table(argc);
    char buf[32];
    for (int i = 0; i < argc; i++) {
        snprintf(buf, sizeof(buf), "arg_%d", i);
        UEntry *arg_val = uent_make_string(argv[i], strlen(argv[i]));
        table_set_by_key_len(vm->global_entry, buf, strlen(buf), arg_val);
        table_add_entry(args, entry_clone_shallow(arg_val, NULL));
    }
    table_set_by_key_len(vm->global_entry, "args", 4, args);
    snprintf(buf, sizeof(buf), "%d", argc);
    table_set_by_key_len(vm->global_entry, "argc", 4, uent_make_string(buf, strlen(buf)));
}

int urb_exec_bytecode(const unsigned char *data, size_t len, int argc, char **argv)
{
    if (!data || len == 0) return 0;
    UrbVM vm;
    vm_init(&vm);
    g_vm = &vm;
    // Match Disturb behavior: ensure stdout is fully buffered for heavy println loops.
    // This significantly reduces per-line overhead when output is redirected.
    setvbuf(stdout, NULL, _IOFBF, 1 << 20);
    vm_set_args(&vm, argc, argv);

    UrbProgram program = translate_bytecode(data, len, vm.exec);

    List *stack = urb_new(URB_DEFAULT_SIZE);
    urb_interpret(vm.exec, program.mem, stack);

    urb_free(stack);
    urb_free(program.mem);
    urb_free(vm.exec);
    return 1;
}
