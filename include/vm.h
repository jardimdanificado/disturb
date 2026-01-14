#ifndef VM_H
#define VM_H 1

#include "urb.h"

typedef struct ObjEntry ObjEntry;
typedef struct VM VM;

typedef void (*NativeFn)(List *stack, List *global);

enum {
    URB_T_NULL = 0,
    URB_T_CHAR = 1,
    URB_T_BYTE,
    URB_T_NUMBER,
    URB_T_OBJECT,
    URB_T_NATIVE,
    URB_T_FUNCTION
};

struct ObjEntry {
    List *obj;
    unsigned in_use : 1;
    unsigned mark : 1;
};

struct VM {
    ObjEntry *reg;
    Int reg_count;
    Int reg_cap;
    ObjEntry *global_entry;
    ObjEntry *stack_entry;
    ObjEntry *null_entry;
};

const char *urb_type_name(Int type);
Int urb_obj_type(const List *obj);
ObjEntry *urb_obj_key(const List *obj);
char *urb_char_data(List *obj);
size_t urb_char_len(const List *obj);
void urb_object_add(List *obj, ObjEntry *entry);
void urb_bytes_append(List *obj, const char *bytes, size_t len);
Int urb_value_len(const List *obj);
void urb_number_set_single(List *obj, Float value);

ObjEntry *vm_stack_peek(List *stack, Int from_top);
ObjEntry *vm_global_find_by_key(List *global, const char *name);

void print_entry(FILE *out, ObjEntry *entry);
void print_plain_entry(FILE *out, ObjEntry *entry);

void vm_init(VM *vm);
void vm_free(VM *vm);
void vm_gc(VM *vm);
void vm_dump_global(VM *vm);
void vm_exec_line(VM *vm, const char *line);

ObjEntry *vm_define_char(VM *vm, const char *key, const char *value);
ObjEntry *vm_define_byte(VM *vm, const char *key, char **items, int count, int start);
ObjEntry *vm_define_number(VM *vm, const char *key, char **items, int count, int start);
ObjEntry *vm_define_object(VM *vm, const char *key, char **items, int count, int start);
ObjEntry *vm_define_native(VM *vm, const char *key, const char *fn_name);

void vm_push_stack(VM *vm, const char *key);
void vm_pop_stack(VM *vm);
void vm_call_native(VM *vm, const char *key);
int vm_global_remove_by_key(VM *vm, const char *name);
int vm_exec_bytecode(VM *vm, const unsigned char *data, size_t len);

NativeFn vm_lookup_native(const char *name);

#endif
