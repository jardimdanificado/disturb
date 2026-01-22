#ifndef VM_H
#define VM_H 1

#include "urb.h"
#include "bytecode.h"

typedef struct ObjEntry ObjEntry;
typedef struct VM VM;
typedef struct FreeNode FreeNode;

typedef void (*NativeFn)(VM *vm, List *stack, List *global);

enum {
    URB_T_NULL = 0,

    URB_T_BYTE,
    URB_T_NUMBER,
    URB_T_TABLE,
    URB_T_NATIVE,
    URB_T_LAMBDA
};

struct ObjEntry {
    List *obj;
    ObjEntry *key;
    unsigned in_use : 1;
    unsigned mark : 1;
};

struct VM {
    ObjEntry **reg;
    Int reg_count;
    Int reg_cap;
    ObjEntry *global_entry;
    ObjEntry *stack_entry;
    ObjEntry *local_entry;
    ObjEntry *null_entry;
    ObjEntry *common_entry;
    ObjEntry *argc_entry;
    ObjEntry *this_entry;
    ObjEntry *gc_entry;
    FreeNode *free_lists;
    FreeNode *free_bytes;
};

const char *urb_type_name(Int type);
Int urb_obj_type(const List *obj);
ObjEntry *urb_obj_key(const List *obj);
char *urb_bytes_data(List *obj);
size_t urb_bytes_len(const List *obj);
List *urb_table_add(List *obj, ObjEntry *entry);
List *urb_bytes_append(List *obj, const char *bytes, size_t len);
Int urb_value_len(const List *obj);
void urb_number_set_single(List *obj, Float value);

ObjEntry *vm_stack_peek(List *stack, Int from_top);
ObjEntry *vm_global_find_by_key(List *global, const char *name);

void print_entry(FILE *out, ObjEntry *entry);
void print_plain_entry(FILE *out, ObjEntry *entry);

ObjEntry *vm_make_number_value(VM *vm, Float value);
ObjEntry *vm_make_bytes_value(VM *vm, const char *s, size_t len);
ObjEntry *vm_make_byte_value(VM *vm, const char *s, size_t len);
ObjEntry *vm_make_table_value(VM *vm, Int reserve);
List *vm_alloc_list(VM *vm, Int type, ObjEntry *key_entry, Int reserve);
void vm_free_list(List *obj);
void vm_reuse_list(VM *vm, List *obj);
ObjEntry *vm_entry_key(const ObjEntry *entry);
ObjEntry *vm_clone_entry_shallow(VM *vm, ObjEntry *src, ObjEntry *forced_key);
ObjEntry *vm_clone_entry_deep(VM *vm, ObjEntry *src, ObjEntry *forced_key);
ObjEntry *vm_clone_entry_shallow_copy(VM *vm, ObjEntry *src, ObjEntry *forced_key);
List *vm_update_shared_obj(VM *vm, List *old_obj, List *new_obj);
ObjEntry *vm_stringify_value(VM *vm, ObjEntry *entry, int raw_string);
ObjEntry *vm_pretty_value(VM *vm, ObjEntry *entry);
int vm_object_set_by_key(VM *vm, ObjEntry *target, const char *name, size_t len, ObjEntry *value);

int vm_exec_bytecode(VM *vm, const unsigned char *data, size_t len);
ObjEntry *vm_eval_source(VM *vm, const char *src, size_t len);
void vm_release_entry(VM *vm, ObjEntry *entry);

void vm_init(VM *vm);
void vm_free(VM *vm);
void vm_gc(VM *vm);
void vm_dump_global(VM *vm);
void vm_exec_line(VM *vm, const char *line);

ObjEntry *vm_define_bytes(VM *vm, const char *key, const char *value);
ObjEntry *vm_define_byte(VM *vm, const char *key, char **items, int count, int start);
ObjEntry *vm_define_number(VM *vm, const char *key, char **items, int count, int start);
ObjEntry *vm_define_table(VM *vm, const char *key, char **items, int count, int start);
ObjEntry *vm_define_native(VM *vm, const char *key, const char *fn_name);

void vm_push_stack(VM *vm, const char *key);
void vm_pop_stack(VM *vm);
void vm_call_native(VM *vm, const char *key);
int vm_global_remove_by_key(VM *vm, const char *name);
int vm_exec_bytecode(VM *vm, const unsigned char *data, size_t len);

NativeFn vm_lookup_native(const char *name);

int vm_compile_source(const char *src, Bytecode *out, char *err, size_t err_cap);
ObjEntry *vm_bytecode_to_ast(VM *vm, const unsigned char *data, size_t len);

#endif
