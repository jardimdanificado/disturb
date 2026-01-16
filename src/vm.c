#include "vm.h"
#include "bytecode.h"

#include <math.h>
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
} FunctionBox;

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
    case URB_T_CHAR: return "char";
    case URB_T_BYTE: return "byte";
    case URB_T_NUMBER: return "number";
    case URB_T_OBJECT: return "object";
    case URB_T_NATIVE: return "native";
    case URB_T_FUNCTION: return "function";
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

char *urb_char_data(List *obj)
{
    return (char*)(obj->data + 2);
}

size_t urb_char_len(const List *obj)
{
    if (obj->size < 2) return 0;
    return (size_t)obj->size - 2;
}

static int urb_char_eq_bytes(const List *obj, const char *s, size_t len)
{
    if (urb_char_len(obj) != len) return 0;
    return memcmp(urb_char_data((List*)obj), s, len) == 0;
}

static List *urb_obj_new_list(Int type, ObjEntry *key_entry, Int reserve)
{
    List *obj = urb_new(2 + reserve);
    Value v;
    v.i = type;
    urb_push(obj, v);
    v.p = key_entry;
    urb_push(obj, v);
    return obj;
}

static List *urb_obj_new_bytes(Int type, ObjEntry *key_entry, const char *s, size_t len)
{
    if (len > urb_bytes_max() - 2) {
        PANIC("byte object too large.");
    }

    List *obj = (List*)malloc(sizeof(List));
    obj->capacity = (UHalf)(len + 2);
    obj->size = (UHalf)(len + 2);
    obj->data = (Value*)malloc(2 * sizeof(Value) + len);
    obj->data[0].i = type;
    obj->data[1].p = key_entry;
    if (len && s) {
        memcpy(urb_char_data(obj), s, len);
    }
    return obj;
}

static List *urb_obj_new_char(ObjEntry *key_entry, const char *s, size_t len)
{
    return urb_obj_new_bytes(URB_T_CHAR, key_entry, s, len);
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
    if (urb_obj_type(obj) == URB_T_FUNCTION && obj->size >= 3) {
        FunctionBox *box = (FunctionBox*)obj->data[2].p;
        if (box) {
            free(box->code);
            for (uint32_t i = 0; i < box->argc; i++) {
                free(box->arg_names[i]);
            }
            free(box->arg_names);
            free(box->arg_lens);
            free(box);
        }
    }
    free(obj->data);
    free(obj);
}

void urb_object_add(List *obj, ObjEntry *entry)
{
    Value v;
    v.p = entry;
    urb_push(obj, v);
}

void urb_bytes_append(List *obj, const char *bytes, size_t len)
{
    size_t old_len = urb_char_len(obj);
    size_t new_len = old_len + len;
    if (new_len > urb_bytes_max() - 2) {
        PANIC("byte object too large.");
    }
    obj->data = (Value*)realloc(obj->data, 2 * sizeof(Value) + new_len);
    if (len) {
        memcpy(urb_char_data(obj) + old_len, bytes, len);
    }
    obj->size = (UHalf)(new_len + 2);
    obj->capacity = (UHalf)(new_len + 2);
}

static int urb_char_eq_cstr(const List *obj, const char *s)
{
    return urb_char_eq_bytes(obj, s, strlen(s));
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
    entry->in_use = 1;
    entry->mark = 0;
    return entry;
}

static ObjEntry *vm_make_key(VM *vm, const char *name)
{
    List *key_obj = urb_obj_new_char(NULL, name, strlen(name));
    return vm_reg_alloc(vm, key_obj);
}

static ObjEntry *vm_make_key_len(VM *vm, const char *name, size_t len)
{
    List *key_obj = urb_obj_new_char(NULL, name, len);
    return vm_reg_alloc(vm, key_obj);
}

static ObjEntry *vm_find_by_key(VM *vm, const char *name)
{
    for (Int i = 0; i < vm->reg_count; i++) {
        ObjEntry *entry = vm->reg[i];
        if (!entry || !entry->in_use) continue;
        ObjEntry *key = urb_obj_key(entry->obj);
        if (!key) continue;
        if (urb_obj_type(key->obj) != URB_T_CHAR) continue;
        if (urb_char_eq_cstr(key->obj, name)) return entry;
    }
    return NULL;
}

static void vm_global_add(VM *vm, ObjEntry *entry)
{
    urb_object_add(vm->global_entry->obj, entry);
}

int vm_global_remove_by_key(VM *vm, const char *name)
{
    List *global = vm->global_entry->obj;
    for (Int i = 2; i < global->size; i++) {
        ObjEntry *entry = (ObjEntry*)global->data[i].p;
        ObjEntry *key = entry ? urb_obj_key(entry->obj) : NULL;
        if (!key) continue;
        if (urb_obj_type(key->obj) != URB_T_CHAR) continue;
        if (urb_char_eq_cstr(key->obj, name)) {
            urb_remove(global, i);
            return 1;
        }
    }
    return 0;
}

static void vm_mark_entry(ObjEntry *entry)
{
    if (!entry || !entry->in_use || entry->mark) return;
    entry->mark = 1;

    List *obj = entry->obj;
    ObjEntry *key = urb_obj_key(obj);
    if (key) vm_mark_entry(key);

    if (urb_obj_type(obj) == URB_T_OBJECT) {
        for (Int i = 2; i < obj->size; i++) {
            ObjEntry *child = (ObjEntry*)obj->data[i].p;
            vm_mark_entry(child);
        }
    }
}

void vm_gc(VM *vm)
{
    vm_mark_entry(vm->global_entry);
    for (Int i = 0; i < vm->reg_count; i++) {
        ObjEntry *entry = vm->reg[i];
        if (!entry || !entry->in_use) continue;
        if (!entry->mark) {
            urb_obj_free(entry->obj);
            entry->obj = NULL;
            entry->in_use = 0;
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
        ObjEntry *key = urb_obj_key(entry->obj);
        if (!key) continue;
        if (urb_obj_type(key->obj) != URB_T_CHAR) continue;
        if (urb_char_eq_cstr(key->obj, name)) return entry;
    }
    return NULL;
}

static ObjEntry *vm_object_find_direct(List *obj, const char *name, size_t len)
{
    if (!obj) return NULL;
    for (Int i = 2; i < obj->size; i++) {
        ObjEntry *entry = (ObjEntry*)obj->data[i].p;
        if (!entry) continue;
        ObjEntry *key = urb_obj_key(entry->obj);
        if (!key) continue;
        if (urb_obj_type(key->obj) != URB_T_CHAR) continue;
        if (urb_char_eq_bytes(key->obj, name, len)) return entry;
    }
    return NULL;
}

static ObjEntry *vm_object_find_by_key_len(VM *vm, List *obj, const char *name, size_t len)
{
    ObjEntry *entry = vm_object_find_direct(obj, name, len);
    if (entry) return entry;
    if (!vm || !vm->prototype_entry || obj == vm->prototype_entry->obj) {
        return vm ? vm->null_entry : NULL;
    }
    entry = vm_object_find_direct(vm->prototype_entry->obj, name, len);
    if (entry) return entry;
    return vm ? vm->null_entry : NULL;
}

Int urb_value_len(const List *obj)
{
    Int type = urb_obj_type(obj);
    switch (type) {
    case URB_T_NULL:
        return 0;
    case URB_T_CHAR:
    case URB_T_BYTE:
        return (Int)urb_char_len(obj);
    case URB_T_NUMBER:
    case URB_T_OBJECT:
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
    urb_push(obj, v);
}

static int vm_entry_truthy(const ObjEntry *entry)
{
    if (!entry || !entry->in_use) return 0;
    return urb_obj_type(entry->obj) != URB_T_NULL;
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
    ObjEntry *key = entry ? urb_obj_key(entry->obj) : NULL;
    if (!key || urb_obj_type(key->obj) != URB_T_CHAR) {
        sb_append_char(b, '_');
        return;
    }
    sb_append_n(b, urb_char_data(key->obj), urb_char_len(key->obj));
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
    case URB_T_CHAR: {
        size_t len = urb_char_len(obj);
        if (raw_string) {
            sb_append_n(b, urb_char_data(obj), len);
            break;
        }
        if (len == 1) {
            sb_append_char(b, '\'');
            sb_append_escaped(b, urb_char_data(obj), len);
            sb_append_char(b, '\'');
        } else {
            sb_append_char(b, '"');
            sb_append_escaped(b, urb_char_data(obj), len);
            sb_append_char(b, '"');
        }
        break;
    }
    case URB_T_BYTE: {
        sb_append_n(b, "(byte){", 7);
        size_t len = urb_char_len(obj);
        for (size_t i = 0; i < len; i++) {
            if (i) sb_append_n(b, ", ", 2);
            sb_append_number(b, (Float)(unsigned char)urb_char_data(obj)[i]);
        }
        sb_append_char(b, '}');
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
        sb_append_n(b, "(number){", 9);
        for (Int i = 0; i < count; i++) {
            if (i) sb_append_n(b, ", ", 2);
            sb_append_number(b, obj->data[i + 2].f);
        }
        sb_append_char(b, '}');
        break;
    }
    case URB_T_OBJECT: {
        sb_append_n(b, "(object){", 9);
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
    case URB_T_FUNCTION:
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
    ObjEntry *out = vm_make_char_value(vm, buf.data, buf.len);
    sb_free(&buf);
    return out;
}

static int vm_entry_equal(ObjEntry *a, ObjEntry *b)
{
    if (a == b) return 1;
    if (!a || !b || !a->in_use || !b->in_use) return 0;
    Int at = urb_obj_type(a->obj);
    Int bt = urb_obj_type(b->obj);
    if (at != bt) return 0;
    if (at == URB_T_NUMBER) {
        Int ac = a->obj->size - 2;
        Int bc = b->obj->size - 2;
        if (ac != bc) return 0;
        for (Int i = 0; i < ac; i++) {
            if (a->obj->data[i + 2].f != b->obj->data[i + 2].f) return 0;
        }
        return 1;
    }
    if (at == URB_T_CHAR || at == URB_T_BYTE) {
        size_t al = urb_char_len(a->obj);
        size_t bl = urb_char_len(b->obj);
        if (al != bl) return 0;
        return memcmp(urb_char_data(a->obj), urb_char_data(b->obj), al) == 0;
    }
    if (at == URB_T_NULL) return 1;
    return 0;
}

static int vm_entry_compare(ObjEntry *a, ObjEntry *b, int *out)
{
    if (!a || !b || !a->in_use || !b->in_use) return 0;
    Int at = urb_obj_type(a->obj);
    Int bt = urb_obj_type(b->obj);
    if (at != bt) return 0;
    if (at == URB_T_NUMBER) {
        double av = a->obj->size >= 3 ? a->obj->data[2].f : 0.0;
        double bv = b->obj->size >= 3 ? b->obj->data[2].f : 0.0;
        if (av < bv) *out = -1;
        else if (av > bv) *out = 1;
        else *out = 0;
        return 1;
    }
    if (at == URB_T_CHAR || at == URB_T_BYTE) {
        size_t al = urb_char_len(a->obj);
        size_t bl = urb_char_len(b->obj);
        size_t min = al < bl ? al : bl;
        int cmp = memcmp(urb_char_data(a->obj), urb_char_data(b->obj), min);
        if (cmp < 0) *out = -1;
        else if (cmp > 0) *out = 1;
        else if (al < bl) *out = -1;
        else if (al > bl) *out = 1;
        else *out = 0;
        return 1;
    }
    return 0;
}

static void print_bytes_hex(FILE *out, const unsigned char *data, size_t len)
{
    fputs("0x", out);
    for (size_t i = 0; i < len; i++) {
        fprintf(out, "%02X", (unsigned)data[i]);
    }
}

static void print_key(FILE *out, ObjEntry *entry)
{
    ObjEntry *key = entry ? urb_obj_key(entry->obj) : NULL;
    if (!key) {
        fputs("_", out);
        return;
    }
    List *key_obj = key->obj;
    if (urb_obj_type(key_obj) != URB_T_CHAR) {
        fputs("<?>", out);
        return;
    }
    fwrite(urb_char_data(key_obj), 1, urb_char_len(key_obj), out);
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
    case URB_T_CHAR:
        fwrite(urb_char_data(obj), 1, urb_char_len(obj), out);
        break;
    case URB_T_BYTE:
        print_bytes_hex(out, (unsigned char*)urb_char_data(obj), urb_char_len(obj));
        break;
    case URB_T_NUMBER:
        for (Int i = 2; i < obj->size; i++) {
            if (i > 2) fputs(" ", out);
            fprintf(out, "%g", (double)obj->data[i].f);
        }
        break;
    case URB_T_OBJECT:
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
    case URB_T_CHAR:
        fputs("\"", out);
        fwrite(urb_char_data(obj), 1, urb_char_len(obj), out);
        fputs("\"", out);
        break;
    case URB_T_BYTE:
        print_bytes_hex(out, (unsigned char*)urb_char_data(obj), urb_char_len(obj));
        break;
    case URB_T_NUMBER:
        fputs("[", out);
        for (Int i = 2; i < obj->size; i++) {
            if (i > 2) fputs(" ", out);
            fprintf(out, "%g", (double)obj->data[i].f);
        }
        fputs("]", out);
        break;
    case URB_T_OBJECT:
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

    ObjEntry *global_key = vm_make_key(vm, "global");
    List *global_obj = urb_obj_new_list(URB_T_OBJECT, global_key, 8);
    vm->global_entry = vm_reg_alloc(vm, global_obj);

    ObjEntry *stack_key = vm_make_key(vm, "stack");
    List *stack_obj = urb_obj_new_list(URB_T_OBJECT, stack_key, 8);
    vm->stack_entry = vm_reg_alloc(vm, stack_obj);
    vm_global_add(vm, vm->stack_entry);

    ObjEntry *null_key = vm_make_key(vm, "null");
    List *null_obj = urb_obj_new_list(URB_T_NULL, null_key, 0);
    vm->null_entry = vm_reg_alloc(vm, null_obj);
    vm_global_add(vm, vm->null_entry);

    ObjEntry *proto_key = vm_make_key(vm, "prototype");
    List *proto_obj = urb_obj_new_list(URB_T_OBJECT, proto_key, 16);
    vm->prototype_entry = vm_reg_alloc(vm, proto_obj);
    vm_global_add(vm, vm->prototype_entry);

    ObjEntry *argc_key = vm_make_key(vm, "__argc");
    List *argc_obj = urb_obj_new_list(URB_T_NUMBER, argc_key, 1);
    Value argc_v;
    argc_v.f = 0;
    urb_push(argc_obj, argc_v);
    vm->argc_entry = vm_reg_alloc(vm, argc_obj);
    vm_global_add(vm, vm->argc_entry);

    vm->this_entry = vm->null_entry;

    ObjEntry *len_key = vm_make_key(vm, "__len");
    List *len_obj = urb_obj_new_list(URB_T_NUMBER, len_key, 1);
    Value v;
    v.f = 0;
    urb_push(len_obj, v);
    ObjEntry *len_entry = vm_reg_alloc(vm, len_obj);
    vm_global_add(vm, len_entry);

    ObjEntry *entry = NULL;
    entry = vm_define_native(vm, "print", "print");
    if (entry) urb_object_add(vm->prototype_entry->obj, entry);
    entry = vm_define_native(vm, "println", "println");
    if (entry) urb_object_add(vm->prototype_entry->obj, entry);
    entry = vm_define_native(vm, "len", "len");
    if (entry) urb_object_add(vm->prototype_entry->obj, entry);
    entry = vm_define_native(vm, "append", "append");
    if (entry) urb_object_add(vm->prototype_entry->obj, entry);
    entry = vm_define_native(vm, "add", "add");
    if (entry) urb_object_add(vm->prototype_entry->obj, entry);
    entry = vm_define_native(vm, "sub", "sub");
    if (entry) urb_object_add(vm->prototype_entry->obj, entry);
    entry = vm_define_native(vm, "mul", "mul");
    if (entry) urb_object_add(vm->prototype_entry->obj, entry);
    entry = vm_define_native(vm, "div", "div");
    if (entry) urb_object_add(vm->prototype_entry->obj, entry);
    entry = vm_define_native(vm, "mod", "mod");
    if (entry) urb_object_add(vm->prototype_entry->obj, entry);
    entry = vm_define_native(vm, "pow", "pow");
    if (entry) urb_object_add(vm->prototype_entry->obj, entry);
    entry = vm_define_native(vm, "min", "min");
    if (entry) urb_object_add(vm->prototype_entry->obj, entry);
    entry = vm_define_native(vm, "max", "max");
    if (entry) urb_object_add(vm->prototype_entry->obj, entry);
    entry = vm_define_native(vm, "abs", "abs");
    if (entry) urb_object_add(vm->prototype_entry->obj, entry);
    entry = vm_define_native(vm, "floor", "floor");
    if (entry) urb_object_add(vm->prototype_entry->obj, entry);
    entry = vm_define_native(vm, "ceil", "ceil");
    if (entry) urb_object_add(vm->prototype_entry->obj, entry);
    entry = vm_define_native(vm, "round", "round");
    if (entry) urb_object_add(vm->prototype_entry->obj, entry);
    entry = vm_define_native(vm, "sqrt", "sqrt");
    if (entry) urb_object_add(vm->prototype_entry->obj, entry);
    entry = vm_define_native(vm, "sin", "sin");
    if (entry) urb_object_add(vm->prototype_entry->obj, entry);
    entry = vm_define_native(vm, "cos", "cos");
    if (entry) urb_object_add(vm->prototype_entry->obj, entry);
    entry = vm_define_native(vm, "tan", "tan");
    if (entry) urb_object_add(vm->prototype_entry->obj, entry);
    entry = vm_define_native(vm, "asin", "asin");
    if (entry) urb_object_add(vm->prototype_entry->obj, entry);
    entry = vm_define_native(vm, "acos", "acos");
    if (entry) urb_object_add(vm->prototype_entry->obj, entry);
    entry = vm_define_native(vm, "atan", "atan");
    if (entry) urb_object_add(vm->prototype_entry->obj, entry);
    entry = vm_define_native(vm, "log", "log");
    if (entry) urb_object_add(vm->prototype_entry->obj, entry);
    entry = vm_define_native(vm, "exp", "exp");
    if (entry) urb_object_add(vm->prototype_entry->obj, entry);
    entry = vm_define_native(vm, "slice", "slice");
    if (entry) urb_object_add(vm->prototype_entry->obj, entry);
    entry = vm_define_native(vm, "substr", "substr");
    if (entry) urb_object_add(vm->prototype_entry->obj, entry);
    entry = vm_define_native(vm, "split", "split");
    if (entry) urb_object_add(vm->prototype_entry->obj, entry);
    entry = vm_define_native(vm, "join", "join");
    if (entry) urb_object_add(vm->prototype_entry->obj, entry);
    entry = vm_define_native(vm, "upper", "upper");
    if (entry) urb_object_add(vm->prototype_entry->obj, entry);
    entry = vm_define_native(vm, "lower", "lower");
    if (entry) urb_object_add(vm->prototype_entry->obj, entry);
    entry = vm_define_native(vm, "trim", "trim");
    if (entry) urb_object_add(vm->prototype_entry->obj, entry);
    entry = vm_define_native(vm, "startsWith", "startsWith");
    if (entry) urb_object_add(vm->prototype_entry->obj, entry);
    entry = vm_define_native(vm, "endsWith", "endsWith");
    if (entry) urb_object_add(vm->prototype_entry->obj, entry);
    entry = vm_define_native(vm, "replace", "replace");
    if (entry) urb_object_add(vm->prototype_entry->obj, entry);
    entry = vm_define_native(vm, "keys", "keys");
    if (entry) urb_object_add(vm->prototype_entry->obj, entry);
    entry = vm_define_native(vm, "values", "values");
    if (entry) urb_object_add(vm->prototype_entry->obj, entry);
    entry = vm_define_native(vm, "has", "has");
    if (entry) urb_object_add(vm->prototype_entry->obj, entry);
    entry = vm_define_native(vm, "delete", "delete");
    if (entry) urb_object_add(vm->prototype_entry->obj, entry);
    entry = vm_define_native(vm, "push", "push");
    if (entry) urb_object_add(vm->prototype_entry->obj, entry);
    entry = vm_define_native(vm, "pop", "pop");
    if (entry) urb_object_add(vm->prototype_entry->obj, entry);
    entry = vm_define_native(vm, "shift", "shift");
    if (entry) urb_object_add(vm->prototype_entry->obj, entry);
    entry = vm_define_native(vm, "unshift", "unshift");
    if (entry) urb_object_add(vm->prototype_entry->obj, entry);
    entry = vm_define_native(vm, "insert", "insert");
    if (entry) urb_object_add(vm->prototype_entry->obj, entry);
    entry = vm_define_native(vm, "remove", "remove");
    if (entry) urb_object_add(vm->prototype_entry->obj, entry);
}

void vm_free(VM *vm)
{
    for (Int i = 0; i < vm->reg_count; i++) {
        ObjEntry *entry = vm->reg[i];
        if (!entry) continue;
        if (entry->in_use) {
            urb_obj_free(entry->obj);
        }
        free(entry);
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
    if (urb_obj_type(key_entry->obj) != URB_T_CHAR) return NULL;
    return vm_make_key_len(vm, urb_char_data(key_entry->obj), urb_char_len(key_entry->obj));
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

    ObjEntry *key_entry = forced_key ? forced_key : vm_clone_key_entry(vm, urb_obj_key(src->obj));
    List *obj = src->obj;
    Int type = urb_obj_type(obj);

    List *copy = NULL;
    ObjEntry *entry = NULL;

    switch (type) {
    case URB_T_NULL:
        copy = urb_obj_new_list(URB_T_NULL, key_entry, 0);
        break;
    case URB_T_CHAR:
        copy = urb_obj_new_char(key_entry, urb_char_data(obj), urb_char_len(obj));
        break;
    case URB_T_BYTE:
        copy = urb_obj_new_byte(key_entry, urb_char_len(obj));
        memcpy(urb_char_data(copy), urb_char_data(obj), urb_char_len(obj));
        break;
    case URB_T_NUMBER: {
        Int n = (Int)(obj->size - 2);
        copy = urb_obj_new_list(URB_T_NUMBER, key_entry, n);
        for (Int i = 2; i < obj->size; i++) {
            urb_push(copy, obj->data[i]);
        }
        break;
    }
    case URB_T_OBJECT: {
        Int n = (Int)(obj->size - 2);
        copy = urb_obj_new_list(URB_T_OBJECT, key_entry, n);
        break;
    }
    case URB_T_NATIVE: {
        copy = urb_obj_new_list(URB_T_NATIVE, key_entry, 1);
        NativeBox *src_box = obj->size >= 3 ? (NativeBox*)obj->data[2].p : NULL;
        NativeBox *box = (NativeBox*)malloc(sizeof(NativeBox));
        box->fn = src_box ? src_box->fn : NULL;
        Value v;
        v.p = box;
        urb_push(copy, v);
        break;
    }
    case URB_T_FUNCTION: {
        copy = urb_obj_new_list(URB_T_FUNCTION, key_entry, 1);
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
                for (uint32_t i = 0; i < box->argc; i++) {
                    size_t len = src_box->arg_lens[i];
                    box->arg_lens[i] = len;
                    box->arg_names[i] = (char*)malloc(len + 1);
                    memcpy(box->arg_names[i], src_box->arg_names[i], len);
                    box->arg_names[i][len] = 0;
                }
            }
        }
        Value v;
        v.p = box;
        urb_push(copy, v);
        break;
    }
    default:
        copy = urb_obj_new_list(type, key_entry, (Int)(obj->size - 2));
        for (Int i = 2; i < obj->size; i++) {
            urb_push(copy, obj->data[i]);
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

    if (type == URB_T_OBJECT) {
        for (Int i = 2; i < obj->size; i++) {
            ObjEntry *child = (ObjEntry*)obj->data[i].p;
            ObjEntry *child_copy = vm_clone_entry_internal(vm, child, NULL, pairs, count, cap);
            if (child_copy) {
                urb_object_add(copy, child_copy);
            }
        }
    }

    return entry;
}

static ObjEntry *vm_clone_entry(VM *vm, ObjEntry *src, ObjEntry *forced_key)
{
    ClonePair *pairs = NULL;
    size_t count = 0;
    size_t cap = 0;
    ObjEntry *entry = vm_clone_entry_internal(vm, src, forced_key, &pairs, &count, &cap);
    free(pairs);
    return entry;
}

ObjEntry *vm_define_char(VM *vm, const char *key, const char *value)
{
    ObjEntry *key_entry = NULL;
    if (key) {
        key_entry = vm_make_key(vm, key);
    }

    List *obj = urb_obj_new_char(key_entry, value, strlen(value));
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
        urb_char_data(obj)[i - start] = (char)(unsigned char)value;
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
        urb_push(obj, v);
    }

    ObjEntry *entry = vm_reg_alloc(vm, obj);
    vm_global_add(vm, entry);
    return entry;
}

ObjEntry *vm_define_object(VM *vm, const char *key, char **items, int count, int start)
{
    ObjEntry *key_entry = NULL;
    if (key) {
        key_entry = vm_make_key(vm, key);
    }

    Int n = (Int)(count - start);
    List *obj = urb_obj_new_list(URB_T_OBJECT, key_entry, n);
    for (int i = start; i < count; i++) {
        ObjEntry *child = vm_find_by_key(vm, items[i]);
        if (!child) {
            fprintf(stderr, "unknown key: %s\n", items[i]);
            continue;
        }
        urb_object_add(obj, child);
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
    urb_push(obj, v);
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
    urb_object_add(vm->stack_entry->obj, entry);
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
    if (!index || urb_obj_type(index->obj) != URB_T_CHAR) return 0;
    return urb_char_eq_bytes(index->obj, name, strlen(name));
}

static ObjEntry *vm_make_type_name(VM *vm, ObjEntry *target)
{
    const char *name = "unknown";
    if (!target) {
        name = "null";
    } else {
        Int type = urb_obj_type(target->obj);
        if (type == URB_T_CHAR) {
            name = urb_char_len(target->obj) == 1 ? "char" : "string";
        } else {
            name = urb_type_name(type);
        }
    }
    return vm_reg_alloc(vm, urb_obj_new_char(NULL, name, strlen(name)));
}

ObjEntry *vm_make_number_value(VM *vm, Float value)
{
    List *obj = urb_obj_new_list(URB_T_NUMBER, NULL, 1);
    Value v;
    v.f = value;
    urb_push(obj, v);
    return vm_reg_alloc(vm, obj);
}

ObjEntry *vm_make_char_value(VM *vm, const char *s, size_t len)
{
    List *obj = urb_obj_new_char(NULL, s, len);
    return vm_reg_alloc(vm, obj);
}

ObjEntry *vm_make_byte_value(VM *vm, const char *s, size_t len)
{
    List *obj = urb_obj_new_bytes(URB_T_BYTE, NULL, s, len);
    return vm_reg_alloc(vm, obj);
}

ObjEntry *vm_make_object_value(VM *vm, Int reserve)
{
    List *obj = urb_obj_new_list(URB_T_OBJECT, NULL, reserve);
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
    if (!target || !index || urb_obj_type(index->obj) != URB_T_CHAR) return NULL;
    if (vm_key_is(index, "name")) {
        ObjEntry *key = urb_obj_key(target->obj);
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

static int vm_resize_bytes(List *obj, Int new_size)
{
    if (new_size < 0) return 0;
    size_t len = (size_t)new_size;
    if (len > urb_bytes_max() - 2) return 0;
    obj->data = (Value*)realloc(obj->data, 2 * sizeof(Value) + len);
    size_t old_len = urb_char_len(obj);
    if (len > old_len) {
        memset(urb_char_data(obj) + old_len, 0, len - old_len);
    }
    obj->size = (UHalf)(len + 2);
    obj->capacity = (UHalf)(len + 2);
    return 1;
}

static int vm_resize_list(List *obj, Int new_size, ObjEntry *null_entry)
{
    if (new_size < 0) return 0;
    size_t payload = (size_t)new_size;
    size_t new_cap = payload + 2;
    obj->data = (Value*)realloc(obj->data, new_cap * sizeof(Value));
    if (!obj->data && new_cap > 0) return 0;
    if ((size_t)obj->capacity < new_cap) {
        memset(obj->data + obj->capacity, 0, (new_cap - obj->capacity) * sizeof(Value));
    }
    obj->capacity = (UHalf)new_cap;
    size_t new_total = payload + 2;
    if (obj->size < (UHalf)new_total) {
        for (size_t i = obj->size; i < new_total; i++) {
            Value v;
            if (urb_obj_type(obj) == URB_T_OBJECT) {
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

static int vm_set_size_bytes(List *obj, Int new_size)
{
    if (new_size < 0) return 0;
    size_t cap = obj->capacity >= 2 ? (size_t)obj->capacity - 2 : 0;
    size_t old_len = urb_char_len(obj);
    size_t len = (size_t)new_size;
    if (len <= cap) {
        if (len > old_len) {
            memset(urb_char_data(obj) + old_len, 0, len - old_len);
        }
        obj->size = (UHalf)(len + 2);
        return 1;
    }
    return vm_resize_bytes(obj, new_size);
}

static int vm_set_size_list(List *obj, Int new_size, ObjEntry *null_entry)
{
    if (new_size < 0) return 0;
    size_t cap = obj->capacity >= 2 ? (size_t)obj->capacity - 2 : 0;
    size_t old_size = obj->size >= 2 ? (size_t)obj->size - 2 : 0;
    size_t len = (size_t)new_size;
    if (len <= cap) {
        size_t new_total = len + 2;
        if (len > old_size) {
            for (size_t i = old_size + 2; i < new_total; i++) {
                Value v;
                if (urb_obj_type(obj) == URB_T_OBJECT) {
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
    return vm_resize_list(obj, new_size, null_entry);
}
static void vm_stack_push_entry(VM *vm, ObjEntry *entry)
{
    if (!entry) return;
    urb_object_add(vm->stack_entry->obj, entry);
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

static int vm_object_set_by_key_len(VM *vm, List *obj, const char *name, size_t len,
                                    ObjEntry *value, size_t pc);

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

static int vm_bind_args(VM *vm, FunctionBox *box, List *stack, uint32_t argc)
{
    if (!vm || !box) return 0;
    uint32_t fixed = box->argc;
    if (box->has_vararg && fixed > 0) fixed--;
    for (uint32_t i = 0; i < fixed; i++) {
        ObjEntry *arg = vm_stack_arg(stack, argc, i);
        if (!arg) arg = vm->null_entry;
        if (!vm_object_set_by_key_len(vm, vm->global_entry->obj,
                                      box->arg_names[i], box->arg_lens[i],
                                      arg, 0)) {
            return 0;
        }
    }
    if (box->has_vararg) {
        ObjEntry *list = vm_make_object_value(vm, (Int)(argc > fixed ? argc - fixed : 0));
        for (uint32_t i = fixed; i < argc; i++) {
            ObjEntry *arg = vm_stack_arg(stack, argc, i);
            if (!arg) arg = vm->null_entry;
            urb_object_add(list->obj, arg);
        }
        if (!vm_object_set_by_key_len(vm, vm->global_entry->obj,
                                      box->arg_names[box->argc - 1],
                                      box->arg_lens[box->argc - 1],
                                      list, 0)) {
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
    if (type == URB_T_OBJECT) {
        if (!index) {
            fprintf(stderr, "bytecode error at pc %zu: INDEX object missing key/index\n", pc);
            return NULL;
        }
        if (urb_obj_type(index->obj) == URB_T_CHAR) {
            return vm_object_find_by_key_len(vm, target->obj,
                                             urb_char_data(index->obj),
                                             urb_char_len(index->obj));
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

    if (index && urb_obj_type(index->obj) == URB_T_CHAR) {
        if (vm && vm->prototype_entry) {
            ObjEntry *method = vm_object_find_direct(vm->prototype_entry->obj,
                                                     urb_char_data(index->obj),
                                                     urb_char_len(index->obj));
            if (method) return method;
        }
        return vm->null_entry;
    }

    Int idx = 0;
    if (!vm_number_to_index(index, &idx, "INDEX", pc)) return NULL;

    if (type == URB_T_CHAR || type == URB_T_BYTE) {
        size_t len = urb_char_len(target->obj);
        if (idx < 0 || (size_t)idx >= len) {
            fprintf(stderr, "bytecode error at pc %zu: INDEX out of bounds\n", pc);
            return vm->null_entry;
        }
        char c = urb_char_data(target->obj)[idx];
        ObjEntry *entry = vm_reg_alloc(vm, urb_obj_new_bytes(type, NULL, &c, 1));
        return entry;
    }

    if (type == URB_T_NUMBER) {
        Int pos = idx + 2;
        if (idx < 0 || pos >= target->obj->size) {
            fprintf(stderr, "bytecode error at pc %zu: INDEX out of bounds\n", pc);
            return vm->null_entry;
        }
        List *obj = urb_obj_new_list(URB_T_NUMBER, NULL, 1);
        urb_push(obj, target->obj->data[pos]);
        return vm_reg_alloc(vm, obj);
    }

    fprintf(stderr, "bytecode error at pc %zu: INDEX unsupported type %s\n",
            pc, urb_type_name(type));
    return NULL;
}

static int vm_object_set_by_key_len(VM *vm, List *obj, const char *name, size_t len, ObjEntry *value, size_t pc)
{
    if (!obj || !value) {
        fprintf(stderr, "bytecode error at pc %zu: STORE_INDEX missing target/value\n", pc);
        return 0;
    }
    for (Int i = 2; i < obj->size; i++) {
        ObjEntry *entry = (ObjEntry*)obj->data[i].p;
        ObjEntry *key = entry ? urb_obj_key(entry->obj) : NULL;
        if (!key || urb_obj_type(key->obj) != URB_T_CHAR) continue;
        if (urb_char_eq_bytes(key->obj, name, len)) {
            urb_remove(obj, i);
            break;
        }
    }
    ObjEntry *key_entry = vm_make_key_len(vm, name, len);
    ObjEntry *copy = vm_clone_entry(vm, value, key_entry);
    if (!copy) {
        fprintf(stderr, "bytecode error at pc %zu: STORE_INDEX clone failed\n", pc);
        return 0;
    }
    urb_object_add(obj, copy);
    return 1;
}

static int vm_meta_set(VM *vm, ObjEntry *target, ObjEntry *index, ObjEntry *value, size_t pc)
{
    if (!target || !index || urb_obj_type(index->obj) != URB_T_CHAR) return 0;
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
        if (type == URB_T_CHAR || type == URB_T_BYTE) {
            if (!vm_set_size_bytes(target->obj, new_size)) {
                fprintf(stderr, "bytecode error at pc %zu: failed to resize bytes\n", pc);
                return -1;
            }
            return 1;
        }
        if (type == URB_T_OBJECT || type == URB_T_NUMBER) {
            if (!vm_set_size_list(target->obj, new_size, vm->null_entry)) {
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
        if (type == URB_T_CHAR || type == URB_T_BYTE) {
            if (!vm_resize_bytes(target->obj, new_cap)) {
                fprintf(stderr, "bytecode error at pc %zu: failed to resize bytes\n", pc);
                return -1;
            }
            return 1;
        }
        if (type == URB_T_OBJECT || type == URB_T_NUMBER) {
            size_t payload = (size_t)new_cap;
            size_t new_total = payload + 2;
            target->obj->data = (Value*)realloc(target->obj->data, new_total * sizeof(Value));
            if (!target->obj->data && new_total > 0) {
                fprintf(stderr, "bytecode error at pc %zu: failed to resize list\n", pc);
                return -1;
            }
            if ((size_t)target->obj->capacity < new_total) {
                memset(target->obj->data + target->obj->capacity, 0,
                       (new_total - target->obj->capacity) * sizeof(Value));
            }
            target->obj->capacity = (UHalf)new_total;
            if (target->obj->size > target->obj->capacity) {
                target->obj->size = target->obj->capacity;
            }
            if (urb_obj_type(target->obj) == URB_T_OBJECT) {
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
    if (vm_key_is(index, "name") || vm_key_is(index, "type")) {
        fprintf(stderr, "bytecode error at pc %zu: %.*s is read-only\n", pc,
                (int)urb_char_len(index->obj), urb_char_data(index->obj));
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
            urb_push(obj, val);
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
            List *obj = urb_obj_new_char(NULL, (const char*)buf, slen);
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
                urb_push(obj, vals[i]);
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
                urb_push(obj, val);
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
                if (urb_obj_type(entry->obj) != URB_T_BYTE || urb_char_len(entry->obj) != 1) {
                    fprintf(stderr, "bytecode error at pc %zu: BUILD_BYTE expects single-byte values\n", pc);
                    return 0;
                }
                urb_char_data(obj)[count - 1 - i] = urb_char_data(entry->obj)[0];
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
            List *obj = urb_obj_new_list(URB_T_OBJECT, NULL, (Int)count);
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
                if (!key || urb_obj_type(key->obj) != URB_T_CHAR) {
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
                                                     urb_char_data(keys[i]->obj),
                                                     urb_char_len(keys[i]->obj));
                ObjEntry *copy = vm_clone_entry(vm, vals[i], key_entry);
                if (!copy) {
                    fprintf(stderr, "bytecode error at pc %zu: BUILD_OBJECT clone failed\n", pc);
                    free(keys);
                    free(vals);
                    return 0;
                }
                urb_object_add(obj, copy);
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
            if (argc > 0) {
                arg_names = (char**)calloc(argc, sizeof(char*));
                arg_lens = (size_t*)calloc(argc, sizeof(size_t));
                if (!arg_names || !arg_lens) {
                    fprintf(stderr, "bytecode error at pc %zu: BUILD_FUNCTION alloc failed\n", pc);
                    free(code);
                    free(arg_names);
                    free(arg_lens);
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
                    return 0;
                }
                arg_names[i] = (char*)name;
                arg_lens[i] = name_len;
            }
            FunctionBox *box = (FunctionBox*)malloc(sizeof(FunctionBox));
            box->code = code;
            box->len = code_len;
            box->argc = argc;
            box->has_vararg = vararg ? 1 : 0;
            box->arg_names = arg_names;
            box->arg_lens = arg_lens;
            List *obj = urb_obj_new_list(URB_T_FUNCTION, NULL, 1);
            Value v;
            v.p = box;
            urb_push(obj, v);
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
            if (type == URB_T_OBJECT && urb_obj_type(index->obj) == URB_T_CHAR) {
                if (!vm_object_set_by_key_len(vm, target->obj,
                                              urb_char_data(index->obj),
                                              urb_char_len(index->obj),
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

            if (type == URB_T_CHAR || type == URB_T_BYTE) {
                size_t len = urb_char_len(target->obj);
                if (idx < 0 || (size_t)idx >= len) {
                    fprintf(stderr, "bytecode error at pc %zu: STORE_INDEX out of bounds\n", pc);
                    return 0;
                }
                if (urb_obj_type(value->obj) != type || urb_char_len(value->obj) != 1) {
                    fprintf(stderr, "bytecode error at pc %zu: STORE_INDEX expects single element\n", pc);
                    return 0;
                }
                urb_char_data(target->obj)[idx] = urb_char_data(value->obj)[0];
                break;
            }

            if (type == URB_T_OBJECT) {
                Int pos = idx + 2;
                if (idx < 0 || pos >= target->obj->size) {
                    fprintf(stderr, "bytecode error at pc %zu: STORE_INDEX out of bounds\n", pc);
                    return 0;
                }
                ObjEntry *copy = vm_clone_entry(vm, value, NULL);
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
            int ok = vm_object_set_by_key_len(vm, vm->global_entry->obj, (char*)name, name_len, value, pc);
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
                if (this_type == URB_T_OBJECT) {
                    target = vm_object_find_by_key_len(vm, vm->this_entry->obj, (char*)name, name_len);
                    if (target == vm->null_entry) target = NULL;
                } else if (this_type == URB_T_NUMBER || this_type == URB_T_CHAR || this_type == URB_T_BYTE) {
                    if (vm->prototype_entry) {
                        target = vm_object_find_direct(vm->prototype_entry->obj, (char*)name, name_len);
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
            } else if (urb_obj_type(target->obj) == URB_T_FUNCTION) {
                if (target->obj->size < 3) {
                    fprintf(stderr, "bytecode error at pc %zu: CALL missing function\n", pc);
                    return 0;
                }
                FunctionBox *box = (FunctionBox*)target->obj->data[2].p;
                if (!box) {
                    fprintf(stderr, "bytecode error at pc %zu: CALL null function\n", pc);
                    return 0;
                }
                if (!vm_bind_args(vm, box, vm->stack_entry->obj, argc)) {
                    fprintf(stderr, "bytecode error at pc %zu: CALL arg bind failed\n", pc);
                    return 0;
                }
                if (!vm_exec_bytecode(vm, box->code, box->len)) {
                    return 0;
                }
            } else {
                fprintf(stderr, "bytecode error at pc %zu: CALL target not callable\n", pc);
                return 0;
            }
            if (argc > 0 && vm->stack_entry->obj->size >= stack_before) {
                Int start = (Int)stack_before - (Int)argc;
                vm_stack_remove_range(vm->stack_entry->obj, start, (Int)argc);
            }
            vm->this_entry = old_this;
            if (vm->argc_entry && vm->argc_entry->obj->size >= 3) {
                vm->argc_entry->obj->data[2].f = old_argc;
            }
            break;
        }
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
            if (op == BC_ADD && (lt == URB_T_CHAR || rt == URB_T_CHAR)) {
                StrBuf buf;
                sb_init(&buf);
                vm_append_value_text(vm, left, &buf, 1);
                vm_append_value_text(vm, right, &buf, 1);
                ObjEntry *entry = vm_reg_alloc(vm, urb_obj_new_char(NULL, buf.data, buf.len));
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
            vm_stack_push_entry(vm, top);
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
