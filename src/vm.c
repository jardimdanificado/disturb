#include "vm.h"
#include "bytecode.h"
#include "papagaio.h"
#include <math.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    NativeFn fn;
} NativeBox;

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

static size_t urb_bytes_max(void)
{
    return (size_t)(~(UHalf)0);
}

const char *urb_type_name(Int type)
{
    switch (type) {
    case URB_T_NULL: return "null";
    case URB_T_BYTE: return "byte";
    case URB_T_NUMBER: return "number";
    case URB_T_TABLE: return "table";
    
    case URB_T_NATIVE: return "native";
    case URB_T_LAMBDA: return "lambda";
    default: return "unknown";
    }
}

Int urb_obj_type(const List *obj)
{
    return obj->data[0].i;
}

ObjEntry *urb_obj_key(const List *obj)
{
    return (ObjEntry*)obj->data[1].p;
}

ObjEntry *vm_entry_key(const ObjEntry *entry)
{
    if (!entry) return NULL;
    if (entry->key) return entry->key;
    if (!entry->obj) return NULL;
    return urb_obj_key(entry->obj);
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

char *urb_bytes_data(List *obj)
{
    return (char*)(obj->data + 2);
}

size_t urb_bytes_len(const List *obj)
{
    if (obj->size < 2) return 0;
    return (size_t)obj->size - 2;
}

static int urb_bytes_eq_bytes(const List *obj, const char *s, size_t len)
{
    if (urb_bytes_len(obj) != len) return 0;
    return memcmp(urb_bytes_data((List*)obj), s, len) == 0;
}

static List *urb_obj_new_list(Int type, ObjEntry *key_entry, Int reserve)
{
    List *obj = urb_new(2 + reserve);
    Value v;
    v.i = type;
    obj = urb_push(obj, v);
    v.p = key_entry;
    obj = urb_push(obj, v);
    return obj;
}

List *vm_alloc_list(Int type, ObjEntry *key_entry, Int reserve)
{
    return urb_obj_new_list(type, key_entry, reserve);
}

static List *urb_obj_new_bytes(Int type, ObjEntry *key_entry, const char *s, size_t len)
{
    if (len > urb_bytes_max() - 2) {
        PANIC("byte object too large.");
    }

    size_t bytes = sizeof(List) + 2 * sizeof(Value) + len;
    List *obj = (List*)malloc(bytes);
    obj->capacity = (UHalf)(len + 2);
    obj->size = (UHalf)(len + 2);
    obj->data[0].i = type;
    obj->data[1].p = key_entry;
    if (len && s) {
        memcpy(urb_bytes_data(obj), s, len);
    }
    return obj;
}



static List *urb_obj_new_byte(ObjEntry *key_entry, size_t len)
{
    return urb_obj_new_bytes(URB_T_BYTE, key_entry, NULL, len);
}

static void urb_obj_free(List *obj)
{
    if (urb_obj_type(obj) == URB_T_NATIVE && obj->size >= 3) {
        NativeBox *box = (NativeBox*)obj->data[2].p;
        free(box);
    }
    if (urb_obj_type(obj) == URB_T_LAMBDA && obj->size >= 3) {
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
    free(obj);
}

void vm_free_list(List *obj)
{
    urb_obj_free(obj);
}

static void vm_table_add_entry(VM *vm, ObjEntry *target, ObjEntry *entry)
{
    if (!target) return;
    List *old_obj = target->obj;
    target->obj = vm_update_shared_obj(vm, old_obj, urb_table_add(old_obj, entry));
}

List *urb_table_add(List *obj, ObjEntry *entry)
{
    Value v;
    v.p = entry;
    return urb_push(obj, v);
}

List *urb_bytes_append(List *obj, const char *bytes, size_t len)
{
    size_t old_len = urb_bytes_len(obj);
    size_t new_len = old_len + len;
    if (new_len > urb_bytes_max() - 2) {
        PANIC("byte object too large.");
    }
    size_t bytes_size = sizeof(List) + 2 * sizeof(Value) + new_len;
    obj = (List*)realloc(obj, bytes_size);
    if (len) {
        memcpy(urb_bytes_data(obj) + old_len, bytes, len);
    }
    obj->size = (UHalf)(new_len + 2);
    obj->capacity = (UHalf)(new_len + 2);
    return obj;
}

static int urb_bytes_eq_cstr(const List *obj, const char *s)
{
    return urb_bytes_eq_bytes(obj, s, strlen(s));
}

static void vm_reg_init(VM *vm)
{
    vm->reg_cap = 64;
    vm->reg_count = 0;
    vm->reg = (ObjEntry**)calloc((size_t)vm->reg_cap, sizeof(ObjEntry*));
}

static ObjEntry *vm_reg_alloc(VM *vm, List *obj)
{
    for (Int i = 0; i < vm->reg_count; i++) {
        ObjEntry *entry = vm->reg[i];
        if (entry && !entry->in_use) {
            entry->obj = obj;
            entry->key = obj ? urb_obj_key(obj) : NULL;
            entry->in_use = 1;
            entry->mark = 0;
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
    entry->key = obj ? urb_obj_key(obj) : NULL;
    entry->in_use = 1;
    entry->mark = 0;
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
            urb_obj_free(entry->obj);
        }
        entry->obj = NULL;
    }
    entry->in_use = 0;
    entry->mark = 0;
    entry->key = NULL;
}

static ObjEntry *vm_make_key(VM *vm, const char *name)
{
    List *key_obj = urb_obj_new_bytes(URB_T_BYTE,NULL, name, strlen(name));
    return vm_reg_alloc(vm, key_obj);
}

static ObjEntry *vm_make_native_entry(VM *vm, const char *key, const char *fn_name)
{
    ObjEntry *key_entry = key ? vm_make_key(vm, key) : NULL;
    NativeFn fn = vm_lookup_native(fn_name);
    if (!fn) {
        fprintf(stderr, "unknown native: %s\n", fn_name);
        return NULL;
    }
    List *obj = urb_obj_new_list(URB_T_NATIVE, key_entry, 1);
    NativeBox *box = (NativeBox*)malloc(sizeof(NativeBox));
    box->fn = fn;
    Value v;
    v.p = box;
    obj = urb_push(obj, v);
    return vm_reg_alloc(vm, obj);
}

static ObjEntry *vm_make_key_len(VM *vm, const char *name, size_t len)
{
    List *key_obj = urb_obj_new_bytes(URB_T_BYTE,NULL, name, len);
    return vm_reg_alloc(vm, key_obj);
}

static ObjEntry *vm_find_by_key(VM *vm, const char *name)
{
    for (Int i = 0; i < vm->reg_count; i++) {
        ObjEntry *entry = vm->reg[i];
        if (!entry || !entry->in_use) continue;
        ObjEntry *key = vm_entry_key(entry);
        if (!key) continue;
        if (urb_obj_type(key->obj) != URB_T_BYTE) continue;
        if (urb_bytes_eq_cstr(key->obj, name)) return entry;
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
        if (urb_obj_type(key->obj) != URB_T_BYTE) continue;
        if (urb_bytes_eq_cstr(key->obj, name)) {
            urb_remove(global, i);
            return 1;
        }
    }
    return 0;
}

void vm_gc(VM *vm)
{
    for (Int i = 0; i < vm->reg_count; i++) {
        ObjEntry *entry = vm->reg[i];
        if (!entry || !entry->in_use) continue;
        if (entry->mark) {
            List *obj = entry->obj;
            if (!obj) {
                entry->in_use = 0;
                entry->mark = 0;
                entry->key = NULL;
                continue;
            }
            int all_marked = 1;
            for (Int j = 0; j < vm->reg_count; j++) {
                ObjEntry *other = vm->reg[j];
                if (!other || !other->in_use || other->obj != obj) continue;
                if (!other->mark) {
                    all_marked = 0;
                    break;
                }
            }
            if (!all_marked) {
                entry->mark = 0;
                continue;
            }
            urb_obj_free(obj);
            for (Int j = 0; j < vm->reg_count; j++) {
                ObjEntry *other = vm->reg[j];
                if (!other || !other->in_use || other->obj != obj) continue;
                other->obj = NULL;
                other->in_use = 0;
                other->mark = 0;
                other->key = NULL;
            }
            continue;
        }
        entry->mark = 0;
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
        if (urb_obj_type(key->obj) != URB_T_BYTE) continue;
        if (urb_bytes_eq_cstr(key->obj, name)) return entry;
    }
    return NULL;
}

static ObjEntry *vm_object_find_direct(List *obj, const char *name, size_t len)
{
    if (!obj) return NULL;
    Int start = 2;
    Int type = urb_obj_type(obj);
    if (type == URB_T_NATIVE || type == URB_T_LAMBDA) start = 3;
    for (Int i = start; i < obj->size; i++) {
        ObjEntry *entry = (ObjEntry*)obj->data[i].p;
        if (!entry) continue;
        ObjEntry *key = vm_entry_key(entry);
        if (!key) continue;
        if (urb_obj_type(key->obj) != URB_T_BYTE) continue;
        if (urb_bytes_eq_bytes(key->obj, name, len)) return entry;
    }
    return NULL;
}

static int vm_object_remove_by_key_len(List *obj, const char *name, size_t len)
{
    if (!obj) return 0;
    Int start = 2;
    Int type = urb_obj_type(obj);
    if (type == URB_T_NATIVE || type == URB_T_LAMBDA) start = 3;
    for (Int i = start; i < obj->size; i++) {
        ObjEntry *entry = (ObjEntry*)obj->data[i].p;
        ObjEntry *key = vm_entry_key(entry);
        if (!key || urb_obj_type(key->obj) != URB_T_BYTE) continue;
        if (urb_bytes_eq_bytes(key->obj, name, len)) {
            urb_remove(obj, i);
            return 1;
        }
    }
    return 0;
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

Int urb_value_len(const List *obj)
{
    Int type = urb_obj_type(obj);
    switch (type) {
    case URB_T_NULL:
        return 0;
    case URB_T_BYTE:
        return (Int)urb_bytes_len(obj);
    case URB_T_NUMBER:
    case URB_T_TABLE:
        return obj->size - 2;
    case URB_T_NATIVE:
        return obj->size > 2 ? 1 : 0;
    default:
        return obj->size - 2;
    }
}

void urb_number_set_single(List *obj, Float value)
{
    obj->size = 2;
    Value v;
    v.f = value;
    obj = urb_push(obj, v);
}

static int vm_entry_truthy(const ObjEntry *entry)
{
    if (!entry || !entry->in_use) return 0;
    Int type = urb_obj_type(entry->obj);
    if (type == URB_T_NULL) return 0;
    if (type == URB_T_NUMBER && entry->obj->size == 3 && entry->obj->data[2].f == 0) return 0;
    return 1;
}

static int vm_entry_number(const ObjEntry *entry, Float *out, const char *op, size_t pc)
{
    if (!entry || urb_obj_type(entry->obj) != URB_T_NUMBER || entry->obj->size < 3) {
        fprintf(stderr, "bytecode error at pc %zu: %s expects number\n", pc, op);
        return 0;
    }
    *out = entry->obj->data[2].f;
    return 1;
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
    if (!key || urb_obj_type(key->obj) != URB_T_BYTE) {
        sb_append_char(b, '_');
        return;
    }
    sb_append_n(b, urb_bytes_data(key->obj), urb_bytes_len(key->obj));
}

static void vm_append_value_text(VM *vm, ObjEntry *entry, StrBuf *b, int raw_string)
{
    if (!entry || !entry->in_use) {
        sb_append_n(b, "null", 4);
        return;
    }

    List *obj = entry->obj;
    Int type = urb_obj_type(obj);
    switch (type) {
    case URB_T_NULL:
        sb_append_n(b, "null", 4);
        break;
    case URB_T_BYTE: {
        size_t len = urb_bytes_len(obj);
        if (raw_string) {
            sb_append_n(b, urb_bytes_data(obj), len);
            break;
        }
        if (len == 1) {
            sb_append_char(b, '\'');
            sb_append_escaped(b, urb_bytes_data(obj), len);
            sb_append_char(b, '\'');
        } else {
            sb_append_char(b, '"');
            sb_append_escaped(b, urb_bytes_data(obj), len);
            sb_append_char(b, '"');
        }
        break;
    }
    case URB_T_NUMBER: {
        Int count = obj->size - 2;
        if (raw_string && count == 1) {
            sb_append_number(b, obj->data[2].f);
            break;
        }
        if (count == 1) {
            sb_append_number(b, obj->data[2].f);
            break;
        }
        if (count == 0) {
            sb_append_n(b, "[]", 2);
            break;
        }
        sb_append_char(b, '[');
        for (Int i = 0; i < count; i++) {
            if (i) sb_append_n(b, ", ", 2);
            sb_append_number(b, obj->data[i + 2].f);
        }
        sb_append_char(b, ']');
        break;
    }
    case URB_T_TABLE: {
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
    case URB_T_NATIVE:
        sb_append_n(b, "<native>", 8);
        break;
    case URB_T_LAMBDA:
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
    Int type = urb_obj_type(obj);
    switch (type) {
    case URB_T_NULL:
        sb_append_n(b, "null", 4);
        break;
    case URB_T_BYTE:
    case URB_T_NUMBER: {
        if (type == URB_T_BYTE) {
            vm_append_value_text(vm, entry, b, 0);
            break;
        }
        Int count = obj->size - 2;
        if (count <= 1) {
            vm_append_value_text(vm, entry, b, 0);
            break;
        }
        sb_append_char(b, '[');
        sb_append_char(b, '\n');
        for (Int i = 0; i < count; i++) {
        sb_append_indent(b, depth + 1, indent);
        sb_append_number(b, obj->data[i + 2].f);
        if (i + 1 < count) sb_append_char(b, ',');
        sb_append_char(b, '\n');
    }
    sb_append_indent(b, depth, indent);
    sb_append_char(b, ']');
    break;
    }
    case URB_T_TABLE: {
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
    case URB_T_NATIVE:
        sb_append_n(b, "<native>", 8);
        break;
    case URB_T_LAMBDA:
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
    Int at = urb_obj_type(a->obj);
    Int bt = urb_obj_type(b->obj);
    if (at != bt) {
        int a_str = (at == URB_T_BYTE || at == URB_T_BYTE);
        int b_str = (bt == URB_T_BYTE || bt == URB_T_BYTE);
        if (!a_str || !b_str) return 0;
    }
    if (at == URB_T_NUMBER && bt == URB_T_NUMBER) {
        Int ac = a->obj->size - 2;
        Int bc = b->obj->size - 2;
        if (ac != bc) return 0;
        for (Int i = 0; i < ac; i++) {
            if (a->obj->data[i + 2].f != b->obj->data[i + 2].f) return 0;
        }
        return 1;
    }
    if ((at == URB_T_BYTE || at == URB_T_BYTE) &&
        (bt == URB_T_BYTE || bt == URB_T_BYTE)) {
        size_t al = urb_bytes_len(a->obj);
        size_t bl = urb_bytes_len(b->obj);
        if (al != bl) return 0;
        return memcmp(urb_bytes_data(a->obj), urb_bytes_data(b->obj), al) == 0;
    }
    if (at == URB_T_NULL) return 1;
    return 0;
}

static int vm_entry_compare(ObjEntry *a, ObjEntry *b, int *out)
{
    if (!a || !b || !a->in_use || !b->in_use) return 0;
    Int at = urb_obj_type(a->obj);
    Int bt = urb_obj_type(b->obj);
    if (at != bt) {
        int a_str = (at == URB_T_BYTE || at == URB_T_BYTE);
        int b_str = (bt == URB_T_BYTE || bt == URB_T_BYTE);
        if (!a_str || !b_str) return 0;
    }
    if (at == URB_T_NUMBER && bt == URB_T_NUMBER) {
        double av = a->obj->size >= 3 ? a->obj->data[2].f : 0.0;
        double bv = b->obj->size >= 3 ? b->obj->data[2].f : 0.0;
        if (av < bv) *out = -1;
        else if (av > bv) *out = 1;
        else *out = 0;
        return 1;
    }
    if ((at == URB_T_BYTE || at == URB_T_BYTE) &&
        (bt == URB_T_BYTE || bt == URB_T_BYTE)) {
        size_t al = urb_bytes_len(a->obj);
        size_t bl = urb_bytes_len(b->obj);
        size_t min = al < bl ? al : bl;
        int cmp = memcmp(urb_bytes_data(a->obj), urb_bytes_data(b->obj), min);
        if (cmp < 0) *out = -1;
        else if (cmp > 0) *out = 1;
        else if (al < bl) *out = -1;
        else if (al > bl) *out = 1;
        else *out = 0;
        return 1;
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
    if (urb_obj_type(key_obj) != URB_T_BYTE) {
        fputs("<?>", out);
        return;
    }
    fwrite(urb_bytes_data(key_obj), 1, urb_bytes_len(key_obj), out);
}

void print_plain_entry(FILE *out, ObjEntry *entry)
{
    if (!entry || !entry->in_use) {
        fputs("null", out);
        return;
    }

    List *obj = entry->obj;
    Int type = urb_obj_type(obj);

    switch (type) {
    case URB_T_NULL:
        fputs("null", out);
        break;
    case URB_T_BYTE:
        fwrite(urb_bytes_data(obj), 1, urb_bytes_len(obj), out);
        break;
        break;
    case URB_T_NUMBER:
        for (Int i = 2; i < obj->size; i++) {
            if (i > 2) fputs(" ", out);
            fprintf(out, "%g", (double)obj->data[i].f);
        }
        break;
    case URB_T_TABLE:
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
    case URB_T_NATIVE:
        fputs("<native>", out);
        break;
    default:
        fputs("<data>", out);
        break;
    }
}

void print_entry(FILE *out, ObjEntry *entry)
{
    if (!entry || !entry->in_use) {
        fputs("null", out);
        return;
    }

    List *obj = entry->obj;
    Int type = urb_obj_type(obj);

    fputs("[", out);
    fputs(urb_type_name(type), out);
    fputs(" ", out);
    print_key(out, entry);
    fputs("] ", out);

    switch (type) {
    case URB_T_NULL:
        fputs("null", out);
        break;
    case URB_T_BYTE:
        fputs("\"", out);
        fwrite(urb_bytes_data(obj), 1, urb_bytes_len(obj), out);
        fputs("\"", out);
        fwrite(urb_bytes_data(obj), 1, urb_bytes_len(obj), out);
        fputs("\"", out);
        break;
    case URB_T_NUMBER:
        fputs("[", out);
        for (Int i = 2; i < obj->size; i++) {
            if (i > 2) fputs(" ", out);
            fprintf(out, "%g", (double)obj->data[i].f);
        }
        fputs("]", out);
        break;
    case URB_T_TABLE:
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
    case URB_T_NATIVE:
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

    ObjEntry *global_key = vm_make_key(vm, "global");
    List *global_obj = urb_obj_new_list(URB_T_TABLE, global_key, 8);
    vm->global_entry = vm_reg_alloc(vm, global_obj);

    ObjEntry *stack_key = vm_make_key(vm, "stack");
    List *stack_obj = urb_obj_new_list(URB_T_TABLE, stack_key, 8);
    vm->stack_entry = vm_reg_alloc(vm, stack_obj);
    vm_global_add(vm, vm->stack_entry);

    ObjEntry *null_key = vm_make_key(vm, "null");
    List *null_obj = urb_obj_new_list(URB_T_NULL, null_key, 0);
    vm->null_entry = vm_reg_alloc(vm, null_obj);
    vm_global_add(vm, vm->null_entry);

    ObjEntry *proto_key = vm_make_key(vm, "common");
    List *proto_obj = urb_obj_new_list(URB_T_TABLE, proto_key, 16);
    vm->common_entry = vm_reg_alloc(vm, proto_obj);
    vm_global_add(vm, vm->common_entry);

    ObjEntry *argc_key = vm_make_key(vm, "__argc");
    List *argc_obj = urb_obj_new_list(URB_T_NUMBER, argc_key, 1);
    Value argc_v;
    argc_v.f = 0;
    argc_obj = urb_push(argc_obj, argc_v);
    vm->argc_entry = vm_reg_alloc(vm, argc_obj);
    vm_global_add(vm, vm->argc_entry);

    vm->this_entry = vm->null_entry;

    ObjEntry *len_key = vm_make_key(vm, "__len");
    List *len_obj = urb_obj_new_list(URB_T_NUMBER, len_key, 1);
    Value v;
    v.f = 0;
    len_obj = urb_push(len_obj, v);
    ObjEntry *len_entry = vm_reg_alloc(vm, len_obj);
    vm_global_add(vm, len_entry);

    ObjEntry *gc_key = vm_make_key(vm, "gc");
    List *gc_obj = urb_obj_new_list(URB_T_TABLE, gc_key, 4);
    vm->gc_entry = vm_reg_alloc(vm, gc_obj);
    vm_global_add(vm, vm->gc_entry);

    ObjEntry *collect_entry = vm_make_native_entry(vm, "collect", "gcCollect");
    if (collect_entry) {
        gc_obj = urb_table_add(gc_obj, collect_entry);
        vm->gc_entry->obj = gc_obj;
    }
    ObjEntry *free_entry = vm_make_native_entry(vm, "free", "gcFree");
    if (free_entry) {
        gc_obj = urb_table_add(gc_obj, free_entry);
        vm->gc_entry->obj = gc_obj;
    }
    ObjEntry *sweep_entry = vm_make_native_entry(vm, "sweep", "gcSweep");
    if (sweep_entry) {
        gc_obj = urb_table_add(gc_obj, sweep_entry);
        vm->gc_entry->obj = gc_obj;
    }
    ObjEntry *new_entry = vm_make_native_entry(vm, "new", "gcNew");
    if (new_entry) {
        gc_obj = urb_table_add(gc_obj, new_entry);
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
    entry = vm_define_native(vm, "toByte", "toByte");
    if (entry) vm_table_add_entry(vm, vm->common_entry, entry);
    entry = vm_define_native(vm, "toNumber", "toNumber");
    if (entry) vm_table_add_entry(vm, vm->common_entry, entry);
    entry = vm_define_native(vm, "gc", "gc");
    if (entry) vm_table_add_entry(vm, vm->common_entry, entry);
    entry = vm_define_native(vm, "read", "read");
    if (entry) vm_table_add_entry(vm, vm->common_entry, entry);
    entry = vm_define_native(vm, "write", "write");
    if (entry) vm_table_add_entry(vm, vm->common_entry, entry);
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
}

void vm_free(VM *vm)
{
    for (Int i = 0; i < vm->reg_count; i++) {
        ObjEntry *entry = vm->reg[i];
        if (!entry) continue;
        if (entry->in_use && entry->obj) {
            List *obj = entry->obj;
            urb_obj_free(obj);
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
    free(vm->reg);
}

typedef struct {
    ObjEntry *src;
    ObjEntry *dst;
} ClonePair;

static ObjEntry *vm_clone_key_entry(VM *vm, ObjEntry *key_entry)
{
    if (!key_entry) return NULL;
    if (urb_obj_type(key_entry->obj) != URB_T_BYTE) return NULL;
    return vm_make_key_len(vm, urb_bytes_data(key_entry->obj), urb_bytes_len(key_entry->obj));
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
    Int type = urb_obj_type(obj);

    List *copy = NULL;
    ObjEntry *entry = NULL;

    switch (type) {
    case URB_T_NULL:
        copy = urb_obj_new_list(URB_T_NULL, key_entry, 0);
        break;
    case URB_T_BYTE:
        copy = urb_obj_new_bytes(URB_T_BYTE,key_entry, urb_bytes_data(obj), urb_bytes_len(obj));
        break;
    case URB_T_NUMBER: {
        Int n = (Int)(obj->size - 2);
        copy = urb_obj_new_list(URB_T_NUMBER, key_entry, n);
        for (Int i = 2; i < obj->size; i++) {
            copy = urb_push(copy, obj->data[i]);
        }
        break;
    }
    case URB_T_TABLE: {
        Int n = (Int)(obj->size - 2);
        copy = urb_obj_new_list(URB_T_TABLE, key_entry, n);
        break;
    }
    case URB_T_NATIVE: {
        copy = urb_obj_new_list(URB_T_NATIVE, key_entry, 1);
        NativeBox *src_box = obj->size >= 3 ? (NativeBox*)obj->data[2].p : NULL;
        NativeBox *box = (NativeBox*)malloc(sizeof(NativeBox));
        box->fn = src_box ? src_box->fn : NULL;
        Value v;
        v.p = box;
        copy = urb_push(copy, v);
        break;
    }
    case URB_T_LAMBDA: {
        copy = urb_obj_new_list(URB_T_LAMBDA, key_entry, 1);
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
        copy = urb_push(copy, v);
        break;
    }
    default:
        copy = urb_obj_new_list(type, key_entry, (Int)(obj->size - 2));
        for (Int i = 2; i < obj->size; i++) {
            copy = urb_push(copy, obj->data[i]);
        }
        break;
    }

    entry = vm_reg_alloc(vm, copy);

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

    if (type == URB_T_TABLE) {
        for (Int i = 2; i < obj->size; i++) {
            ObjEntry *child = (ObjEntry*)obj->data[i].p;
            ObjEntry *child_copy = vm_clone_entry_internal(vm, child, NULL, pairs, count, cap);
            if (child_copy) {
                copy = urb_table_add(copy, child_copy);
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
    return entry;
}

ObjEntry *vm_clone_entry_shallow_copy(VM *vm, ObjEntry *src, ObjEntry *forced_key)
{
    if (!src || !src->in_use) return NULL;
    ObjEntry *key_entry = forced_key ? forced_key : vm_entry_key(src);
    List *obj = src->obj;
    Int type = urb_obj_type(obj);
    List *copy = NULL;

    switch (type) {
    case URB_T_NULL:
        copy = urb_obj_new_list(URB_T_NULL, key_entry, 0);
        break;
    case URB_T_BYTE:
        copy = urb_obj_new_bytes(URB_T_BYTE, key_entry, urb_bytes_data(obj), urb_bytes_len(obj));
        break;
    case URB_T_NUMBER: {
        Int n = (Int)(obj->size - 2);
        copy = urb_obj_new_list(URB_T_NUMBER, key_entry, n);
        for (Int i = 2; i < obj->size; i++) {
            copy = urb_push(copy, obj->data[i]);
        }
        break;
    }
    case URB_T_TABLE: {
        Int n = (Int)(obj->size - 2);
        copy = urb_obj_new_list(URB_T_TABLE, key_entry, n);
        for (Int i = 2; i < obj->size; i++) {
            Value v = obj->data[i];
            copy = urb_push(copy, v);
        }
        break;
    }
    case URB_T_NATIVE:
    case URB_T_LAMBDA: {
        Int n = (Int)(obj->size - 2);
        copy = urb_obj_new_list(type, key_entry, n);
        for (Int i = 2; i < obj->size; i++) {
            copy = urb_push(copy, obj->data[i]);
        }
        break;
    }
    default: {
        Int n = (Int)(obj->size - 2);
        copy = urb_obj_new_list(type, key_entry, n);
        for (Int i = 2; i < obj->size; i++) {
            copy = urb_push(copy, obj->data[i]);
        }
        break;
    }
    }

    if (!copy) return NULL;
    ObjEntry *entry = vm_reg_alloc(vm, copy);
    if (!entry) return NULL;
    entry->key = key_entry;
    return entry;
}

ObjEntry *vm_define_bytes(VM *vm, const char *key, const char *value)
{
    ObjEntry *key_entry = NULL;
    if (key) {
        key_entry = vm_make_key(vm, key);
    }

    List *obj = urb_obj_new_bytes(URB_T_BYTE,key_entry, value, strlen(value));
    ObjEntry *entry = vm_reg_alloc(vm, obj);
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
    List *obj = urb_obj_new_byte(key_entry, len);
    for (int i = start; i < count; i++) {
        char *end = NULL;
        long value = strtol(items[i], &end, 10);
        if (!end || *end != 0 || value < 0 || value > 255) {
            fprintf(stderr, "byte expects uint8 values: %s\n", items[i]);
            value = 0;
        }
        urb_bytes_data(obj)[i - start] = (char)(unsigned char)value;
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
    List *obj = urb_obj_new_list(URB_T_NUMBER, key_entry, n);
    for (int i = start; i < count; i++) {
        Value v;
        v.f = (Float)strtod(items[i], NULL);
        obj = urb_push(obj, v);
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
    List *obj = urb_obj_new_list(URB_T_TABLE, key_entry, n);
    for (int i = start; i < count; i++) {
        ObjEntry *child = vm_find_by_key(vm, items[i]);
        if (!child) {
            fprintf(stderr, "unknown key: %s\n", items[i]);
            continue;
        }
        obj = urb_table_add(obj, child);
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

    List *obj = urb_obj_new_list(URB_T_NATIVE, key_entry, 1);
    NativeBox *box = (NativeBox*)malloc(sizeof(NativeBox));
    box->fn = fn;
    Value v;
    v.p = box;
    obj = urb_push(obj, v);
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
    urb_pop(stack);
}

void vm_call_native(VM *vm, const char *key)
{
    ObjEntry *entry = vm_find_by_key(vm, key);
    if (!entry) {
        fprintf(stderr, "unknown key: %s\n", key);
        return;
    }
    if (urb_obj_type(entry->obj) != URB_T_NATIVE) {
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
        print_entry(stdout, entry);
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
        case BC_PUSH_NUM: {
            double v = 0.0;
            if (!bc_read_f64(data, len, &pc, &v)) {
                fprintf(stderr, "bytecodeToAst: truncated PUSH_NUM at pc %zu\n", pc);
                return NULL;
            }
            ast_set_kv(vm, node, "value", vm_make_number_value(vm, (Float)v));
            break;
        }
        case BC_PUSH_CHAR:
        case BC_PUSH_STRING: {
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
        case BC_PUSH_BYTE: {
            uint8_t v = 0;
            if (!bc_read_u8(data, len, &pc, &v)) {
                fprintf(stderr, "bytecodeToAst: truncated PUSH_BYTE at pc %zu\n", pc);
                return NULL;
            }
            ast_set_kv(vm, node, "value", vm_make_number_value(vm, (Float)v));
            break;
        }
        case BC_BUILD_NUMBER:
        case BC_BUILD_BYTE:
        case BC_BUILD_OBJECT: {
            uint32_t count = 0;
            if (!bc_read_u32(data, len, &pc, &count)) {
                fprintf(stderr, "bytecodeToAst: truncated BUILD_* at pc %zu\n", pc);
                return NULL;
            }
            ast_set_kv(vm, node, "count", vm_make_number_value(vm, (Float)count));
            break;
        }
        case BC_BUILD_NUMBER_LIT: {
            uint32_t count = 0;
            if (!bc_read_u32(data, len, &pc, &count)) {
                fprintf(stderr, "bytecodeToAst: truncated BUILD_NUMBER_LIT at pc %zu\n", pc);
                return NULL;
            }
            ObjEntry *values = vm_make_table_value(vm, (Int)count);
            for (uint32_t i = 0; i < count; i++) {
                double v = 0.0;
                if (!bc_read_f64(data, len, &pc, &v)) {
                    fprintf(stderr, "bytecodeToAst: truncated BUILD_NUMBER_LIT value at pc %zu\n", pc);
                    return NULL;
                }
                values->obj = vm_update_shared_obj(vm, values->obj,
                                                   urb_table_add(values->obj, vm_make_number_value(vm, (Float)v)));
            }
            ast_set_kv(vm, node, "count", vm_make_number_value(vm, (Float)count));
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
                                                 urb_table_add(args->obj, arg));
                free(name);
            }

            ast_set_kv(vm, node, "argc", vm_make_number_value(vm, (Float)argc));
            ast_set_kv(vm, node, "vararg", vm_make_number_value(vm, (Float)vararg));
            ast_set_kv(vm, node, "code", code);
            ast_set_kv(vm, node, "args", args);
            break;
        }
        case BC_LOAD_GLOBAL:
        case BC_STORE_GLOBAL:
        case BC_CALL: {
            unsigned char *name = NULL;
            size_t name_len = 0;
            if (!bc_read_string(data, len, &pc, &name, &name_len)) {
                fprintf(stderr, "bytecodeToAst: truncated name at pc %zu\n", pc);
                return NULL;
            }
            ast_set_kv(vm, node, "name", vm_make_bytes_value(vm, (const char*)name, name_len));
            free(name);
            if (op == BC_CALL) {
                uint32_t argc = 0;
                if (!bc_read_u32(data, len, &pc, &argc)) {
                    fprintf(stderr, "bytecodeToAst: truncated CALL argc at pc %zu\n", pc);
                    return NULL;
                }
                ast_set_kv(vm, node, "argc", vm_make_number_value(vm, (Float)argc));
            }
            break;
        }
        case BC_JMP:
        case BC_JMP_IF_FALSE: {
            uint32_t target = 0;
            if (!bc_read_u32(data, len, &pc, &target)) {
                fprintf(stderr, "bytecodeToAst: truncated jump at pc %zu\n", pc);
                return NULL;
            }
            ast_set_kv(vm, node, "target", vm_make_number_value(vm, (Float)target));
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
                                        urb_table_add(ops->obj, node));
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
    return (ObjEntry*)urb_pop(stack).p;
}

static int vm_key_is(ObjEntry *index, const char *name)
{
    if (!index || urb_obj_type(index->obj) != URB_T_BYTE) return 0;
    return urb_bytes_eq_bytes(index->obj, name, strlen(name));
}

static ObjEntry *vm_make_type_name(VM *vm, ObjEntry *target)
{
    const char *name = "unknown";
    if (!target) {
        name = "null";
    } else {
        Int type = urb_obj_type(target->obj);
        if (type == URB_T_BYTE) {
            size_t len = urb_bytes_len(target->obj);
            if (len == 1) {
                name = "char";
            } else {
                name = "string";
            }
        } else {
            name = urb_type_name(type);
        }
    }
    return vm_reg_alloc(vm, urb_obj_new_bytes(URB_T_BYTE,NULL, name, strlen(name)));
}

ObjEntry *vm_make_number_value(VM *vm, Float value)
{
    List *obj = urb_obj_new_list(URB_T_NUMBER, NULL, 1);
    Value v;
    v.f = value;
    obj = urb_push(obj, v);
    return vm_reg_alloc(vm, obj);
}

ObjEntry *vm_make_bytes_value(VM *vm, const char *s, size_t len)
{
    List *obj = urb_obj_new_bytes(URB_T_BYTE,NULL, s, len);
    return vm_reg_alloc(vm, obj);
}

ObjEntry *vm_make_byte_value(VM *vm, const char *s, size_t len)
{
    List *obj = urb_obj_new_bytes(URB_T_BYTE, NULL, s, len);
    return vm_reg_alloc(vm, obj);
}

ObjEntry *vm_make_table_value(VM *vm, Int reserve)
{
    List *obj = urb_obj_new_list(URB_T_TABLE, NULL, reserve);
    return vm_reg_alloc(vm, obj);
}

static Int vm_meta_size(const List *obj)
{
    Int type = urb_obj_type(obj);
    if (type == URB_T_NULL) return 0;
    if (obj->size < 2) return 0;
    return obj->size - 2;
}

static Int vm_meta_capacity(const List *obj)
{
    Int type = urb_obj_type(obj);
    if (type == URB_T_NULL) return 0;
    if (obj->capacity < 2) return 0;
    return obj->capacity - 2;
}

static ObjEntry *vm_meta_get(VM *vm, ObjEntry *target, ObjEntry *index, size_t pc)
{
    (void)pc;
    if (!target || !index || urb_obj_type(index->obj) != URB_T_BYTE) return NULL;
    if (vm_key_is(index, "name")) {
        ObjEntry *key = vm_entry_key(target);
        return key ? key : vm->null_entry;
    }
    if (vm_key_is(index, "type")) {
        return vm_make_type_name(vm, target);
    }
    if (vm_key_is(index, "size")) {
        return vm_make_number_value(vm, (Float)vm_meta_size(target->obj));
    }
    if (vm_key_is(index, "capacity")) {
        return vm_make_number_value(vm, (Float)vm_meta_capacity(target->obj));
    }
    return NULL;
}

static List *vm_resize_bytes(List *obj, Int new_size)
{
    if (new_size < 0) return 0;
    size_t len = (size_t)new_size;
    if (len > urb_bytes_max() - 2) return NULL;
    size_t bytes = sizeof(List) + 2 * sizeof(Value) + len;
    obj = (List*)realloc(obj, bytes);
    if (!obj) return NULL;
    size_t old_len = urb_bytes_len(obj);
    if (len > old_len) {
        memset(urb_bytes_data(obj) + old_len, 0, len - old_len);
    }
    obj->size = (UHalf)(len + 2);
    obj->capacity = (UHalf)(len + 2);
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
            if (urb_obj_type(obj) == URB_T_TABLE) {
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
    size_t old_len = urb_bytes_len(obj);
    size_t len = (size_t)new_size;
    if (len <= cap) {
        if (len > old_len) {
            memset(urb_bytes_data(obj) + old_len, 0, len - old_len);
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
                if (urb_obj_type(obj) == URB_T_TABLE) {
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
    urb_number_set_single(vm->argc_entry->obj, (Float)argc);
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

static int vm_global_rebind(VM *vm, const char *name, size_t len, ObjEntry *entry)
{
    if (!vm || !vm->global_entry) return 0;
    vm_object_remove_by_key_len(vm->global_entry->obj, name, len);
    if (!entry) return 1;
    List *old_obj = vm->global_entry->obj;
    vm->global_entry->obj = vm_update_shared_obj(vm, old_obj,
                                                 urb_table_add(old_obj, entry));
    return 1;
}

static int vm_bind_args(VM *vm, FunctionBox *box, List *stack, uint32_t argc, ObjEntry **bound)
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
        ObjEntry *key_entry = vm_make_key_len(vm, box->arg_names[i], box->arg_lens[i]);
        ObjEntry *entry = NULL;
        if (arg == vm->null_entry) {
            entry = vm_reg_alloc(vm, vm_alloc_list(URB_T_NULL, key_entry, 0));
            if (entry) entry->key = key_entry;
        } else {
            entry = vm_clone_entry_shallow(vm, arg, key_entry);
        }
        if (bound) bound[i] = entry;
        if (!vm_global_rebind(vm, box->arg_names[i], box->arg_lens[i], entry)) {
            return 0;
        }
    }
    if (box->has_vararg) {
        ObjEntry *list = vm_make_table_value(vm, (Int)(argc > fixed ? argc - fixed : 0));
        for (uint32_t i = fixed; i < argc; i++) {
            ObjEntry *arg = vm_stack_arg(stack, argc, i);
            if (!arg) arg = vm->null_entry;
            list->obj = vm_update_shared_obj(vm, list->obj,
                                             urb_table_add(list->obj, arg));
        }
        ObjEntry *key_entry = vm_make_key_len(vm, box->arg_names[box->argc - 1],
                                              box->arg_lens[box->argc - 1]);
        list->key = key_entry;
        if (bound) bound[box->argc - 1] = list;
        if (!vm_global_rebind(vm, box->arg_names[box->argc - 1],
                              box->arg_lens[box->argc - 1], list)) {
            return 0;
        }
    }
    return 1;
}

static int vm_number_to_index(ObjEntry *entry, Int *out, const char *op, size_t pc)
{
    if (!entry || urb_obj_type(entry->obj) != URB_T_NUMBER || entry->obj->size < 3) {
        fprintf(stderr, "bytecode error at pc %zu: %s expects number index\n", pc, op);
        return 0;
    }
    Float v = entry->obj->data[2].f;
    Int iv = (Int)v;
    if ((Float)iv != v) {
        fprintf(stderr, "bytecode error at pc %zu: %s index must be integer\n", pc, op);
        return 0;
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

    Int type = urb_obj_type(target->obj);
    if (type == URB_T_NULL) {
        return vm->null_entry;
    }
    if (type == URB_T_TABLE) {
        if (!index) {
            fprintf(stderr, "bytecode error at pc %zu: INDEX object missing key/index\n", pc);
            return NULL;
        }
        if (urb_obj_type(index->obj) == URB_T_BYTE) {
            return vm_object_find_by_key_len(vm, target->obj,
                                             urb_bytes_data(index->obj),
                                             urb_bytes_len(index->obj));
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

    if (type == URB_T_NATIVE && index && urb_obj_type(index->obj) == URB_T_BYTE) {
        return vm_object_find_by_key_len(vm, target->obj,
                                         urb_bytes_data(index->obj),
                                         urb_bytes_len(index->obj));
    }

    if (index && urb_obj_type(index->obj) == URB_T_BYTE) {
        if (vm && vm->common_entry) {
            ObjEntry *method = vm_object_find_direct(vm->common_entry->obj,
                                                     urb_bytes_data(index->obj),
                                                     urb_bytes_len(index->obj));
            if (method) return method;
        }
        return vm->null_entry;
    }

    Int idx = 0;
    if (!vm_number_to_index(index, &idx, "INDEX", pc)) return NULL;

    if (type == URB_T_BYTE || type == URB_T_BYTE) {
        size_t len = urb_bytes_len(target->obj);
        if (idx < 0 || (size_t)idx >= len) {
            fprintf(stderr, "bytecode error at pc %zu: INDEX out of bounds\n", pc);
            return vm->null_entry;
        }
        char c = urb_bytes_data(target->obj)[idx];
        ObjEntry *entry = vm_reg_alloc(vm, urb_obj_new_bytes(URB_T_BYTE, NULL, &c, 1));
        return entry;
    }

    if (type == URB_T_NUMBER) {
        Int pos = idx + 2;
        if (idx < 0 || pos >= target->obj->size) {
            fprintf(stderr, "bytecode error at pc %zu: INDEX out of bounds\n", pc);
            return vm->null_entry;
        }
        List *obj = urb_obj_new_list(URB_T_NUMBER, NULL, 1);
        obj = urb_push(obj, target->obj->data[pos]);
        return vm_reg_alloc(vm, obj);
    }

    fprintf(stderr, "bytecode error at pc %zu: INDEX unsupported type %s\n",
            pc, urb_type_name(type));
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
    Int type = urb_obj_type(obj);
    if (type == URB_T_NATIVE || type == URB_T_LAMBDA) start = 3;
    ObjEntry *found = NULL;
    for (Int i = start; i < obj->size; i++) {
        ObjEntry *entry = (ObjEntry*)obj->data[i].p;
        ObjEntry *key = vm_entry_key(entry);
        if (!key || urb_obj_type(key->obj) != URB_T_BYTE) continue;
        if (urb_bytes_eq_bytes(key->obj, name, len)) {
            found = entry;
            break;
        }
    }
    if (found) {
        if (found->obj == value->obj) return 1;
        Int found_type = urb_obj_type(found->obj);
        Int value_type = urb_obj_type(value->obj);
        if (found_type == URB_T_NUMBER && value_type == URB_T_NUMBER) {
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
        if (found_type == URB_T_BYTE && value_type == URB_T_BYTE) {
            List *dst = found->obj;
            List *src = value->obj;
            size_t len_bytes = urb_bytes_len(src);
            List *old_dst = dst;
            dst = vm_resize_bytes(dst, (Int)len_bytes);
            if (!dst) return 0;
            dst = vm_update_shared_obj(vm, old_dst, dst);
            found->obj = dst;
            if (len_bytes) {
                memcpy(urb_bytes_data(dst), urb_bytes_data(src), len_bytes);
            }
            return 1;
        }
        if (found_type == URB_T_TABLE && value_type == URB_T_TABLE) {
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
    obj = urb_table_add(obj, copy);
    *objp = vm_update_shared_obj(vm, old_obj, obj);
    return 1;
}

int vm_object_set_by_key(VM *vm, ObjEntry *target, const char *name, size_t len, ObjEntry *value)
{
    if (!target) return 0;
    Int type = urb_obj_type(target->obj);
    if (type != URB_T_TABLE && type != URB_T_NATIVE) return 0;
    return vm_object_set_by_key_len(vm, &target->obj, name, len, value, 0);
}

static int vm_meta_set(VM *vm, ObjEntry *target, ObjEntry *index, ObjEntry *value, size_t pc)
{
    if (!target || !index || urb_obj_type(index->obj) != URB_T_BYTE) return 0;
    if (vm_key_is(index, "name")) {
        if (!value || urb_obj_type(value->obj) == URB_T_NULL) {
            target->key = NULL;
            return 1;
        }
        if (urb_obj_type(value->obj) != URB_T_BYTE && urb_obj_type(value->obj) != URB_T_BYTE) {
            fprintf(stderr, "bytecode error at pc %zu: name expects string or null\n", pc);
            return -1;
        }
        ObjEntry *key_entry = vm_make_key_len(vm, urb_bytes_data(value->obj), urb_bytes_len(value->obj));
        target->key = key_entry;
        return 1;
    }
    if (vm_key_is(index, "type")) {
        if (!value || (urb_obj_type(value->obj) != URB_T_BYTE && urb_obj_type(value->obj) != URB_T_BYTE)) {
            fprintf(stderr, "bytecode error at pc %zu: type expects string\n", pc);
            return -1;
        }
        const char *name = urb_bytes_data(value->obj);
        size_t len = urb_bytes_len(value->obj);
        Int next = -1;
        if (len == 4 && strncmp(name, "null", 4) == 0) next = URB_T_NULL;
    else if (len == 6 && strncmp(name, "number", 6) == 0) next = URB_T_NUMBER;
    else if (len == 5 && strncmp(name, "table", 5) == 0) next = URB_T_TABLE;
        else if (len == 4 && strncmp(name, "char", 4) == 0) next = URB_T_BYTE;
        else if (len == 6 && strncmp(name, "string", 6) == 0) next = URB_T_BYTE;
        else if (len == 4 && strncmp(name, "byte", 4) == 0) next = URB_T_BYTE;
        else if (len == 6 && strncmp(name, "native", 6) == 0) next = URB_T_NATIVE;
        else if (len == 6 && strncmp(name, "lambda", 6) == 0) next = URB_T_LAMBDA;
        else {
            fprintf(stderr, "bytecode error at pc %zu: unknown type '%.*s'\n", pc, (int)len, name);
            return -1;
        }
        target->obj->data[0].i = next;
        return 1;
    }
    if (vm_key_is(index, "size")) {
        if (urb_obj_type(value->obj) != URB_T_NUMBER || value->obj->size < 3) {
            fprintf(stderr, "bytecode error at pc %zu: size expects number\n", pc);
            return -1;
        }
        Int new_size = (Int)value->obj->data[2].f;
        if ((Float)new_size != value->obj->data[2].f) {
            fprintf(stderr, "bytecode error at pc %zu: size expects integer\n", pc);
            return -1;
        }
        Int type = urb_obj_type(target->obj);
        if (type == URB_T_BYTE || type == URB_T_BYTE) {
            if (!vm_set_size_bytes(vm, target, new_size)) {
                fprintf(stderr, "bytecode error at pc %zu: failed to resize bytes\n", pc);
                return -1;
            }
            return 1;
        }
        if (type == URB_T_TABLE || type == URB_T_NUMBER) {
            if (!vm_set_size_list(vm, target, new_size, vm->null_entry)) {
                fprintf(stderr, "bytecode error at pc %zu: failed to resize list\n", pc);
                return -1;
            }
            return 1;
        }
        fprintf(stderr, "bytecode error at pc %zu: size not supported on %s\n", pc, urb_type_name(type));
        return -1;
    }
    if (vm_key_is(index, "capacity")) {
        if (urb_obj_type(value->obj) != URB_T_NUMBER || value->obj->size < 3) {
            fprintf(stderr, "bytecode error at pc %zu: capacity expects number\n", pc);
            return -1;
        }
        Int new_cap = (Int)value->obj->data[2].f;
        if ((Float)new_cap != value->obj->data[2].f) {
            fprintf(stderr, "bytecode error at pc %zu: capacity expects integer\n", pc);
            return -1;
        }
        if (new_cap < 0) {
            fprintf(stderr, "bytecode error at pc %zu: capacity expects non-negative\n", pc);
            return -1;
        }
        Int type = urb_obj_type(target->obj);
        if (type == URB_T_BYTE || type == URB_T_BYTE) {
            List *resized = vm_resize_bytes(target->obj, new_cap);
            if (!resized) {
                fprintf(stderr, "bytecode error at pc %zu: failed to resize bytes\n", pc);
                return -1;
            }
            target->obj = resized;
            return 1;
        }
        if (type == URB_T_TABLE || type == URB_T_NUMBER) {
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
            if (urb_obj_type(target->obj) == URB_T_TABLE) {
                for (Int i = 2; i < target->obj->size; i++) {
                    if (!target->obj->data[i].p) {
                        target->obj->data[i].p = vm->null_entry;
                    }
                }
            }
            return 1;
        }
        fprintf(stderr, "bytecode error at pc %zu: capacity not supported on %s\n", pc, urb_type_name(type));
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
        case BC_PUSH_NUM: {
            double v = 0.0;
            if (!bc_read_f64(data, len, &pc, &v)) {
                fprintf(stderr, "bytecode error at pc %zu: truncated PUSH_NUM\n", pc);
                return 0;
            }
            List *obj = urb_obj_new_list(URB_T_NUMBER, NULL, 1);
            Value val;
            val.f = (Float)v;
            obj = urb_push(obj, val);
            vm_stack_push_entry(vm, vm_reg_alloc(vm, obj));
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
                List *obj = urb_obj_new_bytes(URB_T_BYTE, NULL, processed, strlen(processed));
                free(processed);
                free(buf);
                vm_stack_push_entry(vm, vm_reg_alloc(vm, obj));
                break;
            }
            List *obj = urb_obj_new_bytes(URB_T_BYTE, NULL, (const char*)buf, slen);
            free(buf);
            vm_stack_push_entry(vm, vm_reg_alloc(vm, obj));
            break;
        }
        case BC_PUSH_BYTE: {
            uint8_t v = 0;
            if (!bc_read_u8(data, len, &pc, &v)) {
                fprintf(stderr, "bytecode error at pc %zu: truncated PUSH_BYTE\n", pc);
                return 0;
            }
            unsigned char b = v;
            List *obj = urb_obj_new_bytes(URB_T_BYTE, NULL, (const char*)&b, 1);
            vm_stack_push_entry(vm, vm_reg_alloc(vm, obj));
            break;
        }
        case BC_BUILD_NUMBER: {
            uint32_t count = 0;
            if (!bc_read_u32(data, len, &pc, &count)) {
                fprintf(stderr, "bytecode error at pc %zu: truncated BUILD_NUMBER\n", pc);
                return 0;
            }
            List *obj = urb_obj_new_list(URB_T_NUMBER, NULL, (Int)count);
            Value *vals = (Value*)calloc(count, sizeof(Value));
            if (!vals && count > 0) {
                fprintf(stderr, "bytecode error at pc %zu: out of memory\n", pc);
                return 0;
            }
            for (uint32_t i = 0; i < count; i++) {
                ObjEntry *entry = vm_stack_pop_entry(vm, "BUILD_NUMBER", pc);
                if (!entry) return 0;
                if (urb_obj_type(entry->obj) != URB_T_NUMBER || entry->obj->size < 3) {
                    fprintf(stderr, "bytecode error at pc %zu: BUILD_NUMBER expects numbers\n", pc);
                    free(vals);
                    return 0;
                }
                vals[count - 1 - i] = entry->obj->data[2];
            }
            for (uint32_t i = 0; i < count; i++) {
                obj = urb_push(obj, vals[i]);
            }
            free(vals);
            vm_stack_push_entry(vm, vm_reg_alloc(vm, obj));
            break;
        }
        case BC_BUILD_NUMBER_LIT: {
            uint32_t count = 0;
            if (!bc_read_u32(data, len, &pc, &count)) {
                fprintf(stderr, "bytecode error at pc %zu: truncated BUILD_NUMBER_LIT\n", pc);
                return 0;
            }
            List *obj = urb_obj_new_list(URB_T_NUMBER, NULL, (Int)count);
            for (uint32_t i = 0; i < count; i++) {
                double v = 0.0;
                if (!bc_read_f64(data, len, &pc, &v)) {
                    fprintf(stderr, "bytecode error at pc %zu: truncated BUILD_NUMBER_LIT value\n", pc);
                    return 0;
                }
                Value val;
                val.f = (Float)v;
                obj = urb_push(obj, val);
            }
            vm_stack_push_entry(vm, vm_reg_alloc(vm, obj));
            break;
        }
        case BC_BUILD_BYTE: {
            uint32_t count = 0;
            if (!bc_read_u32(data, len, &pc, &count)) {
                fprintf(stderr, "bytecode error at pc %zu: truncated BUILD_BYTE\n", pc);
                return 0;
            }
            if (count > 0xFFFFFFFFu) {
                fprintf(stderr, "bytecode error at pc %zu: BUILD_BYTE count too large\n", pc);
                return 0;
            }
            List *obj = urb_obj_new_byte(NULL, count);
            for (uint32_t i = 0; i < count; i++) {
                ObjEntry *entry = vm_stack_pop_entry(vm, "BUILD_BYTE", pc);
                if (!entry) return 0;
                if (urb_obj_type(entry->obj) != URB_T_BYTE || urb_bytes_len(entry->obj) != 1) {
                    fprintf(stderr, "bytecode error at pc %zu: BUILD_BYTE expects single-byte values\n", pc);
                    return 0;
                }
                urb_bytes_data(obj)[count - 1 - i] = urb_bytes_data(entry->obj)[0];
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
            List *obj = urb_obj_new_list(URB_T_TABLE, NULL, (Int)count);
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
                if (!key || urb_obj_type(key->obj) != URB_T_BYTE) {
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
                                                     urb_bytes_data(keys[i]->obj),
                                                     urb_bytes_len(keys[i]->obj));
                ObjEntry *copy = vm_clone_entry_shallow(vm, vals[i], key_entry);
                if (!copy) {
                    fprintf(stderr, "bytecode error at pc %zu: BUILD_OBJECT clone failed\n", pc);
                    free(keys);
                    free(vals);
                    return 0;
                }
                obj = urb_table_add(obj, copy);
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
            List *obj = urb_obj_new_list(URB_T_LAMBDA, NULL, 1);
            Value v;
            v.p = box;
            obj = urb_push(obj, v);
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

            Int type = urb_obj_type(target->obj);
            if (type == URB_T_TABLE && urb_obj_type(index->obj) == URB_T_BYTE) {
                if (!vm_object_set_by_key_len(vm, &target->obj,
                                              urb_bytes_data(index->obj),
                                              urb_bytes_len(index->obj),
                                              value, pc)) {
                    return 0;
                }
                break;
            }

            Int idx = 0;
            if (!vm_number_to_index(index, &idx, "STORE_INDEX", pc)) return 0;

            if (type == URB_T_NUMBER) {
                Int pos = idx + 2;
                if (idx < 0 || pos >= target->obj->size) {
                    fprintf(stderr, "bytecode error at pc %zu: STORE_INDEX out of bounds\n", pc);
                    return 0;
                }
                if (urb_obj_type(value->obj) != URB_T_NUMBER || value->obj->size < 3) {
                    fprintf(stderr, "bytecode error at pc %zu: STORE_INDEX expects number\n", pc);
                    return 0;
                }
                target->obj->data[pos] = value->obj->data[2];
                break;
            }

            if (type == URB_T_BYTE || type == URB_T_BYTE) {
                size_t len = urb_bytes_len(target->obj);
                if (idx < 0 || (size_t)idx >= len) {
                    fprintf(stderr, "bytecode error at pc %zu: STORE_INDEX out of bounds\n", pc);
                    return 0;
                }
                Int vtype = urb_obj_type(value->obj);
                if ((vtype == URB_T_BYTE || vtype == URB_T_BYTE) && urb_bytes_len(value->obj) == 1) {
                    urb_bytes_data(target->obj)[idx] = urb_bytes_data(value->obj)[0];
                    break;
                }
                if (vtype == URB_T_NUMBER && value->obj->size == 3) {
                    double v = value->obj->data[2].f;
                    Int iv = (Int)v;
                    if (v < 0 || v > 255 || (double)iv != v) {
                        fprintf(stderr, "bytecode error at pc %zu: STORE_INDEX expects byte-sized number\n", pc);
                        return 0;
                    }
                    urb_bytes_data(target->obj)[idx] = (unsigned char)iv;
                    break;
                }
                fprintf(stderr, "bytecode error at pc %zu: STORE_INDEX expects single string element or byte-sized number\n", pc);
                return 0;
                break;
            }

            if (type == URB_T_TABLE) {
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
                    pc, urb_type_name(type));
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
            ObjEntry *entry = vm_object_find_by_key_len(vm, vm->global_entry->obj, (char*)name, name_len);
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
            int ok = vm_object_set_by_key_len(vm, &vm->global_entry->obj, (char*)name, name_len, value, pc);
            free(name);
            if (!ok) return 0;
            break;
        }
        case BC_SET_THIS: {
            ObjEntry *value = vm_stack_pop_entry(vm, "SET_THIS", pc);
            vm->this_entry = value ? value : vm->null_entry;
            break;
        }
        case BC_CALL: {
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
            ObjEntry *old_this = vm->this_entry;
            Float old_argc = 0;
            if (vm->argc_entry && vm->argc_entry->obj->size >= 3) {
                old_argc = vm->argc_entry->obj->data[2].f;
            }
            vm_set_argc(vm, argc);
            Int stack_before = vm->stack_entry->obj->size;
            ObjEntry *target = NULL;
            if (vm->this_entry && vm->this_entry->in_use) {
                Int this_type = urb_obj_type(vm->this_entry->obj);
                if (this_type == URB_T_TABLE) {
                    target = vm_object_find_by_key_len(vm, vm->this_entry->obj, (char*)name, name_len);
                    if (target == vm->null_entry) target = NULL;
                } else if (this_type == URB_T_NUMBER || this_type == URB_T_BYTE || this_type == URB_T_BYTE) {
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
            if (urb_obj_type(target->obj) == URB_T_NATIVE) {
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
            } else if (urb_obj_type(target->obj) == URB_T_LAMBDA) {
                if (target->obj->size < 3) {
                    fprintf(stderr, "bytecode error at pc %zu: CALL missing function\n", pc);
                    return 0;
                }
                FunctionBox *box = (FunctionBox*)target->obj->data[2].p;
                if (!box) {
                    fprintf(stderr, "bytecode error at pc %zu: CALL null function\n", pc);
                    return 0;
                }
                ObjEntry **saved_args = NULL;
                unsigned char *saved_flags = NULL;
                ObjEntry **bound_args = NULL;
                uint32_t saved_count = box->argc;
                if (saved_count > 0) {
                    saved_args = (ObjEntry**)calloc(saved_count, sizeof(ObjEntry*));
                    saved_flags = (unsigned char*)calloc(saved_count, sizeof(unsigned char));
                    bound_args = (ObjEntry**)calloc(saved_count, sizeof(ObjEntry*));
                    if (!saved_args || !saved_flags) {
                        fprintf(stderr, "bytecode error at pc %zu: CALL out of memory\n", pc);
                        free(saved_args);
                        free(saved_flags);
                        free(bound_args);
                        return 0;
                    }
                    for (uint32_t i = 0; i < saved_count; i++) {
                        ObjEntry *existing = vm_object_find_direct(vm->global_entry->obj,
                                                                   box->arg_names[i],
                                                                   box->arg_lens[i]);
                        if (existing) {
                            saved_args[i] = existing;
                            saved_flags[i] = 1;
                        }
                    }
                }
                if (!vm_bind_args(vm, box, vm->stack_entry->obj, argc, bound_args)) {
                    fprintf(stderr, "bytecode error at pc %zu: CALL arg bind failed\n", pc);
                    if (saved_args || saved_flags) {
                        for (uint32_t i = 0; i < saved_count; i++) {
                            if (saved_flags[i]) {
                                vm_global_rebind(vm, box->arg_names[i], box->arg_lens[i], saved_args[i]);
                            } else {
                                vm_object_remove_by_key_len(vm->global_entry->obj,
                                                            box->arg_names[i],
                                                            box->arg_lens[i]);
                            }
                        }
                        free(saved_args);
                        free(saved_flags);
                        free(bound_args);
                    }
                    return 0;
                }
                if (!vm_exec_bytecode(vm, box->code, box->len)) {
                    if (saved_args || saved_flags) {
                        for (uint32_t i = 0; i < saved_count; i++) {
                            if (saved_flags[i]) {
                                vm_global_rebind(vm, box->arg_names[i], box->arg_lens[i], saved_args[i]);
                            } else {
                                vm_object_remove_by_key_len(vm->global_entry->obj,
                                                            box->arg_names[i],
                                                            box->arg_lens[i]);
                            }
                        }
                        free(saved_args);
                        free(saved_flags);
                        free(bound_args);
                    }
                    return 0;
                }
                if (saved_args || saved_flags) {
                    for (uint32_t i = 0; i < saved_count; i++) {
                        if (saved_flags[i]) {
                            vm_global_rebind(vm, box->arg_names[i], box->arg_lens[i], saved_args[i]);
                        } else {
                            vm_object_remove_by_key_len(vm->global_entry->obj,
                                                        box->arg_names[i],
                                                        box->arg_lens[i]);
                        }
                    }
                    free(saved_args);
                    free(saved_flags);
                    free(bound_args);
                }
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
            if (vm->argc_entry && vm->argc_entry->obj->size >= 3) {
                vm->argc_entry->obj->data[2].f = old_argc;
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
            Int lt = urb_obj_type(left->obj);
            Int rt = urb_obj_type(right->obj);
            if (op == BC_ADD &&
                ((lt == URB_T_BYTE || lt == URB_T_BYTE) ||
                 (rt == URB_T_BYTE || rt == URB_T_BYTE))) {
                StrBuf buf;
                sb_init(&buf);
                vm_append_value_text(vm, left, &buf, 1);
                vm_append_value_text(vm, right, &buf, 1);
                ObjEntry *entry = vm_reg_alloc(vm, urb_obj_new_bytes(URB_T_BYTE,NULL, buf.data, buf.len));
                sb_free(&buf);
                vm_stack_push_entry(vm, entry);
                break;
            }
            if (op == BC_AND || op == BC_OR) {
                int l = vm_entry_truthy(left);
                int r = vm_entry_truthy(right);
                int res = op == BC_AND ? (l && r) : (l || r);
                vm_stack_push_entry(vm, vm_make_number_value(vm, (Float)(res ? 1 : 0)));
                break;
            }
            if (op == BC_EQ || op == BC_NEQ) {
                int eq = vm_entry_equal(left, right);
                int res = op == BC_EQ ? eq : !eq;
                vm_stack_push_entry(vm, vm_make_number_value(vm, (Float)(res ? 1 : 0)));
                break;
            }
            if (op == BC_LT || op == BC_LTE || op == BC_GT || op == BC_GTE) {
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
                vm_stack_push_entry(vm, vm_make_number_value(vm, (Float)(res ? 1 : 0)));
                break;
            }

            Float lv = 0;
            Float rv = 0;
            if (!vm_entry_number(left, &lv, "OP", pc)) return 0;
            if (!vm_entry_number(right, &rv, "OP", pc)) return 0;
            Float out = 0;
            switch (op) {
            case BC_ADD: out = lv + rv; break;
            case BC_SUB: out = lv - rv; break;
            case BC_MUL: out = lv * rv; break;
            case BC_DIV: out = lv / rv; break;
            case BC_MOD: out = (Float)fmod((double)lv, (double)rv); break;
            default: break;
            }
            vm_stack_push_entry(vm, vm_make_number_value(vm, out));
            break;
        }
        case BC_NEG: {
            ObjEntry *value = vm_stack_pop_entry(vm, "NEG", pc);
            if (!value) return 0;
            Float v = 0;
            if (!vm_entry_number(value, &v, "NEG", pc)) return 0;
            vm_stack_push_entry(vm, vm_make_number_value(vm, -v));
            break;
        }
        case BC_NOT: {
            ObjEntry *value = vm_stack_pop_entry(vm, "NOT", pc);
            if (!value) return 0;
            int res = vm_entry_truthy(value) ? 0 : 1;
            vm_stack_push_entry(vm, vm_make_number_value(vm, (Float)res));
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
            Int type = urb_obj_type(top->obj);
            if (type == URB_T_NUMBER || type == URB_T_BYTE) {
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
        urb_pop(stack);
    }
    bc_free(&bc);
    return result ? result : vm->null_entry;
}
