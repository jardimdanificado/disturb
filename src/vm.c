#include "vm.h"

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
    case URB_T_CHAR: return "char";
    case URB_T_BYTE: return "byte";
    case URB_T_NUMBER: return "number";
    case URB_T_ANY: return "any";
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
    return (size_t)obj->size;
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
    if (len > urb_bytes_max()) {
        PANIC("byte object too large.");
    }

    List *obj = (List*)malloc(sizeof(List));
    obj->capacity = (UHalf)len;
    obj->size = (UHalf)len;
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

void urb_any_add(List *any_obj, ObjEntry *entry)
{
    Value v;
    v.p = entry;
    urb_push(any_obj, v);
}

void urb_bytes_append(List *obj, const char *bytes, size_t len)
{
    size_t old_len = urb_char_len(obj);
    size_t new_len = old_len + len;
    if (new_len > urb_bytes_max()) {
        PANIC("byte object too large.");
    }
    obj->data = (Value*)realloc(obj->data, 2 * sizeof(Value) + new_len);
    if (len) {
        memcpy(urb_char_data(obj) + old_len, bytes, len);
    }
    obj->size = (UHalf)new_len;
    obj->capacity = (UHalf)new_len;
}

static int urb_char_eq_cstr(const List *obj, const char *s)
{
    size_t len = strlen(s);
    if (urb_char_len(obj) != len) return 0;
    return memcmp(urb_char_data((List*)obj), s, len) == 0;
}

static void vm_reg_init(VM *vm)
{
    vm->reg_cap = 64;
    vm->reg_count = 0;
    vm->reg = (ObjEntry*)calloc((size_t)vm->reg_cap, sizeof(ObjEntry));
}

static ObjEntry *vm_reg_alloc(VM *vm, List *obj)
{
    for (Int i = 0; i < vm->reg_count; i++) {
        ObjEntry *entry = &vm->reg[i];
        if (!entry->in_use) {
            entry->obj = obj;
            entry->in_use = 1;
            entry->mark = 0;
            return entry;
        }
    }

    if (vm->reg_count == vm->reg_cap) {
        vm->reg_cap = vm->reg_cap == 0 ? 64 : vm->reg_cap * 2;
        vm->reg = (ObjEntry*)realloc(vm->reg, (size_t)vm->reg_cap * sizeof(ObjEntry));
        memset(vm->reg + vm->reg_count, 0, (size_t)(vm->reg_cap - vm->reg_count) * sizeof(ObjEntry));
    }

    ObjEntry *entry = &vm->reg[vm->reg_count++];
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

static ObjEntry *vm_find_by_key(VM *vm, const char *name)
{
    for (Int i = 0; i < vm->reg_count; i++) {
        ObjEntry *entry = &vm->reg[i];
        if (!entry->in_use) continue;
        ObjEntry *key = urb_obj_key(entry->obj);
        if (!key) continue;
        if (urb_obj_type(key->obj) != URB_T_CHAR) continue;
        if (urb_char_eq_cstr(key->obj, name)) return entry;
    }
    return NULL;
}

static void vm_global_add(VM *vm, ObjEntry *entry)
{
    urb_any_add(vm->global_entry->obj, entry);
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

    if (urb_obj_type(obj) == URB_T_ANY) {
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
        ObjEntry *entry = &vm->reg[i];
        if (!entry->in_use) continue;
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

Int urb_value_len(const List *obj)
{
    Int type = urb_obj_type(obj);
    switch (type) {
    case URB_T_CHAR:
    case URB_T_BYTE:
        return (Int)urb_char_len(obj);
    case URB_T_NUMBER:
    case URB_T_ANY:
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
    case URB_T_ANY:
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
    case URB_T_ANY:
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
    List *global_obj = urb_obj_new_list(URB_T_ANY, global_key, 8);
    vm->global_entry = vm_reg_alloc(vm, global_obj);

    ObjEntry *stack_key = vm_make_key(vm, "stack");
    List *stack_obj = urb_obj_new_list(URB_T_ANY, stack_key, 8);
    vm->stack_entry = vm_reg_alloc(vm, stack_obj);
    vm_global_add(vm, vm->stack_entry);

    ObjEntry *len_key = vm_make_key(vm, "__len");
    List *len_obj = urb_obj_new_list(URB_T_NUMBER, len_key, 1);
    Value v;
    v.f = 0;
    urb_push(len_obj, v);
    ObjEntry *len_entry = vm_reg_alloc(vm, len_obj);
    vm_global_add(vm, len_entry);
}

void vm_free(VM *vm)
{
    for (Int i = 0; i < vm->reg_count; i++) {
        if (vm->reg[i].in_use) {
            urb_obj_free(vm->reg[i].obj);
        }
    }
    free(vm->reg);
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

ObjEntry *vm_define_any(VM *vm, const char *key, char **items, int count, int start)
{
    ObjEntry *key_entry = NULL;
    if (key) {
        key_entry = vm_make_key(vm, key);
    }

    Int n = (Int)(count - start);
    List *obj = urb_obj_new_list(URB_T_ANY, key_entry, n);
    for (int i = start; i < count; i++) {
        ObjEntry *child = vm_find_by_key(vm, items[i]);
        if (!child) {
            fprintf(stderr, "unknown key: %s\n", items[i]);
            continue;
        }
        urb_any_add(obj, child);
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
    urb_any_add(vm->stack_entry->obj, entry);
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
