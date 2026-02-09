#ifndef VM_H
#define VM_H 1

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>
#include <stdbool.h>
#include <ctype.h>

#include "../lib/urb.h"

#undef PANIC

#include "bytecode.h"

#define DISTURB_VERSION "0.18.0"

#define PANIC(message) do {\
        fprintf(stderr, "DISTURB ERROR:" message "\n");\
        fflush(stderr);\
        abort();\
    } while (0)

typedef struct FreeDataNode FreeDataNode;

typedef struct ObjEntry ObjEntry;
typedef struct VM VM;
typedef struct FreeNode FreeNode;
typedef struct GcStats GcStats;
typedef struct ListSlab ListSlab;
typedef struct EntrySlab EntrySlab;

typedef void (*NativeFn)(VM *vm, List *stack, List *global);

typedef struct NativeBox {
    NativeFn fn;
    void *data;
    void (*free_data)(void *data);
    void (*clone_data)(void *data);
} NativeBox;

enum {
    DISTURB_T_NULL = 0,
    DISTURB_T_INT,
    DISTURB_T_FLOAT,
    DISTURB_T_TABLE,
    DISTURB_T_NATIVE,
    DISTURB_T_LAMBDA,
    DISTURB_T_VIEW
};

struct ObjEntry {
    List *obj;
    ObjEntry *key;
    Int reg_index;
    unsigned in_use : 1;
    unsigned mark : 1;
    unsigned is_string : 1;
    unsigned explicit_string : 1;
};

typedef struct {
    ObjEntry *key_entry;
    uint32_t hash;
    uint32_t len;
} InternEntry;

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
    ObjEntry *call_entry;
    FreeNode *free_list_objs;
    FreeDataNode *free_list_data;
    FreeNode *free_node_pool;
    FreeDataNode *free_data_node_pool;
    size_t free_list_obj_count;
    size_t free_list_data_count;
    size_t free_list_data_bytes;
    ListSlab *list_slabs;
    EntrySlab *entry_slabs;
    ObjEntry *int_cache_entries;
    List *int_cache_objs;
    unsigned char *int_cache_data;
    size_t int_cache_count;
    Int *reg_free;
    Int reg_free_count;
    Int reg_free_cap;
    List **obj_ref_keys;
    size_t *obj_ref_vals;
    size_t obj_ref_cap;
    size_t obj_ref_count;
    InternEntry *intern_table;
    size_t intern_cap;
    size_t intern_size;
    ObjEntry **intern_roots;
    size_t intern_roots_cap;
    size_t gc_rate;
    size_t gc_counter;
    Int call_override_len;
    int has_call_override;
    int strict_mode;
    int keyintern_enabled;
};

struct FreeNode {
    List *obj;
    struct FreeNode *next;
};

struct FreeDataNode {
    void *data;
    size_t cap_bytes;
    struct FreeDataNode *next;
};

struct GcStats {
    size_t reuse_list_count;
    size_t reuse_bytes_count;
    size_t reuse_bytes_total;
    size_t inuse_count;
    size_t inuse_bytes;
    size_t noref_count;
    size_t noref_bytes;
    size_t total_bytes;
};

const char *disturb_type_name(Int type);
Int disturb_obj_type(const List *obj);
ObjEntry *disturb_obj_key(const List *obj);
char *disturb_bytes_data(List *obj);
size_t disturb_bytes_len(const List *obj);
List *disturb_table_add(List *obj, ObjEntry *entry);
List *disturb_bytes_append(List *obj, const char *bytes, size_t len);
Int vm_value_len_entry(const ObjEntry *entry);

ObjEntry *vm_stack_peek(List *stack, Int from_top);
ObjEntry *vm_global_find_by_key(List *global, const char *name);

void print_entry(FILE *out, VM *vm, ObjEntry *entry);
void print_plain_entry(FILE *out, VM *vm, ObjEntry *entry);

ObjEntry *vm_make_int_value(VM *vm, Int value);
ObjEntry *vm_make_float_value(VM *vm, Float value);
ObjEntry *vm_make_int_list(VM *vm, Int count);
ObjEntry *vm_make_float_list(VM *vm, Int count);
ObjEntry *vm_make_bytes_value(VM *vm, const char *s, size_t len);
ObjEntry *vm_make_byte_value(VM *vm, const char *s, size_t len);
ObjEntry *vm_make_table_value(VM *vm, Int reserve);
List *vm_alloc_list(VM *vm, Int type, ObjEntry *key_entry, Int reserve);
void vm_free_list(VM *vm, List *obj);
void vm_reuse_list(VM *vm, List *obj);
void vm_flush_reuse(VM *vm);
int vm_gc_stats(VM *vm, GcStats *out);
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

ObjEntry *vm_make_native_entry_data(VM *vm, const char *key, NativeFn fn, void *data,
                                    void (*free_data)(void *), void (*clone_data)(void *));

#ifdef DISTURB_ENABLE_FFI
int ffi_view_meta_get(VM *vm, ObjEntry *target, ObjEntry *index, ObjEntry **out);
int ffi_view_meta_set(VM *vm, ObjEntry *target, ObjEntry *index, ObjEntry *value, size_t pc);
int ffi_native_index_get(VM *vm, ObjEntry *target, ObjEntry *index, ObjEntry **out, size_t pc);
int ffi_native_index_set(VM *vm, ObjEntry *target, ObjEntry *index, ObjEntry *value, size_t pc);
void ffi_module_install(VM *vm, ObjEntry *ffi_entry);
#endif

NativeFn vm_lookup_native(const char *name);

int vm_compile_source(const char *src, Bytecode *out, char *err, size_t err_cap);
ObjEntry *vm_bytecode_to_ast(VM *vm, const unsigned char *data, size_t len);

#endif
