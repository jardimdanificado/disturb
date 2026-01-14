#include "vm.h"
#include "bytecode.h"

#include <stdlib.h>
#include <string.h>

typedef struct {
    NativeFn fn;
} NativeBox;

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

static ObjEntry *vm_object_find_by_key_len(VM *vm, List *obj, const char *name, size_t len)
{
    if (!obj) return vm ? vm->null_entry : NULL;
    for (Int i = 2; i < obj->size; i++) {
        ObjEntry *entry = (ObjEntry*)obj->data[i].p;
        if (!entry) continue;
        ObjEntry *key = urb_obj_key(entry->obj);
        if (!key) continue;
        if (urb_obj_type(key->obj) != URB_T_CHAR) continue;
        if (urb_char_eq_bytes(key->obj, name, len)) return entry;
    }
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

    ObjEntry *len_key = vm_make_key(vm, "__len");
    List *len_obj = urb_obj_new_list(URB_T_NUMBER, len_key, 1);
    Value v;
    v.f = 0;
    urb_push(len_obj, v);
    ObjEntry *len_entry = vm_reg_alloc(vm, len_obj);
    vm_global_add(vm, len_entry);

    vm_define_native(vm, "print", "print");
    vm_define_native(vm, "println", "println");
    vm_define_native(vm, "len", "len");
    vm_define_native(vm, "append", "append");
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
    fn(vm->stack_entry->obj, vm->global_entry->obj);
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

static ObjEntry *vm_make_number_value(VM *vm, Float value)
{
    List *obj = urb_obj_new_list(URB_T_NUMBER, NULL, 1);
    Value v;
    v.f = value;
    urb_push(obj, v);
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
        fprintf(stderr, "bytecode error at pc %zu: INDEX expects object for string key\n", pc);
        return NULL;
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
        case BC_CALL: {
            unsigned char *name = NULL;
            size_t name_len = 0;
            if (!bc_read_string(data, len, &pc, &name, &name_len)) {
                fprintf(stderr, "bytecode error at pc %zu: truncated CALL\n", pc);
                return 0;
            }
            ObjEntry *entry = vm_object_find_by_key_len(vm, vm->global_entry->obj, (char*)name, name_len);
            if (!entry) {
                fprintf(stderr, "bytecode error at pc %zu: unknown native '%s'\n", pc, name);
                free(name);
                return 0;
            }
            free(name);
            if (urb_obj_type(entry->obj) != URB_T_NATIVE) {
                fprintf(stderr, "bytecode error at pc %zu: CALL target not native\n", pc);
                return 0;
            }
            if (entry->obj->size < 3) {
                fprintf(stderr, "bytecode error at pc %zu: CALL missing function\n", pc);
                return 0;
            }
            NativeBox *box = (NativeBox*)entry->obj->data[2].p;
            NativeFn fn = box ? box->fn : NULL;
            if (!fn) {
                fprintf(stderr, "bytecode error at pc %zu: CALL null function\n", pc);
                return 0;
            }
            fn(vm->stack_entry->obj, vm->global_entry->obj);
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
