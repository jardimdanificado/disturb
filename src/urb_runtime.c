#include "urb_runtime.h"
#include "bytecode.h"
#include "urb.h"

#include <ctype.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
            Int count = entry_bytes_count(entry, U_T_INT);
            for (Int i = 0; i < count; i++) {
                if (i) fputs(" ", out);
                Int v = 0;
                if (entry_read_int(entry, i, &v)) fprintf(out, "%lld", (long long)v);
                else fputs("0", out);
            }
            fputs("]", out);
        }
        break;
    case U_T_FLOAT:
        fputs("[", out);
        {
            Int count = entry_bytes_count(entry, U_T_FLOAT);
            for (Int i = 0; i < count; i++) {
                if (i) fputs(" ", out);
                Float v = 0;
                if (entry_read_float(entry, i, &v)) fprintf(out, "%g", (double)v);
                else fputs("0", out);
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

    UObj *native_obj = uobj_new(U_T_NATIVE);
    UNative *print_native = (UNative*)calloc(1, sizeof(UNative));
    print_native->fn = native_print;
    native_obj->as.native.native = print_native;
    UEntry *print_entry = uent_new(native_obj);
    table_set_by_key_len(vm->global_entry, "print", 5, print_entry);

    native_obj = uobj_new(U_T_NATIVE);
    UNative *println_native = (UNative*)calloc(1, sizeof(UNative));
    println_native->fn = native_println;
    native_obj->as.native.native = println_native;
    UEntry *println_entry = uent_new(native_obj);
    table_set_by_key_len(vm->global_entry, "println", 7, println_entry);

    native_obj = uobj_new(U_T_NATIVE);
    UNative *len_native = (UNative*)calloc(1, sizeof(UNative));
    len_native->fn = native_len;
    native_obj->as.native.native = len_native;
    UEntry *len_entry = uent_new(native_obj);
    table_set_by_key_len(vm->global_entry, "len", 3, len_entry);
}

int urb_exec_bytecode(const unsigned char *data, size_t len)
{
    if (!data || len == 0) return 0;
    UrbVM vm;
    vm_init(&vm);
    g_vm = &vm;

    UrbProgram program = translate_bytecode(data, len, vm.exec);

    List *stack = urb_new(URB_DEFAULT_SIZE);
    urb_interpret(vm.exec, program.mem, stack);

    urb_free(stack);
    urb_free(program.mem);
    urb_free(vm.exec);
    return 1;
}
