#ifndef VM_H
#define VM_H 1

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>
#include <stdbool.h>
#include <ctype.h>

#include "bytecode.h"

#define DISTURB_VERSION "0.9.6"

typedef intptr_t Int;
typedef uintptr_t UInt;

#if INTPTR_MAX == INT64_MAX
    typedef double Float;
    typedef uint32_t UHalf;
    typedef int32_t Half;
    #define INT_MAX INT64_MAX
    #define INT_MIN INT64_MIN
#else
    typedef float Float;
    typedef uint16_t UHalf;
    typedef int16_t Half;
    #define INT_MAX INT32_MAX
    #define INT_MIN INT32_MIN
#endif

#ifndef DISTURB_DEFAULT_SIZE
    #define DISTURB_DEFAULT_SIZE 0
#endif

#define PANIC(message) do {\
        fprintf(stderr, "DISTURB ERROR:" message "\n");\
        fflush(stderr);\
        abort();\
    } while (0)

typedef struct List List;
typedef union Value Value;
typedef void (*Function)(List *stack);

union Value
{
    Int i;
    UInt u;
    Float f;
    UHalf h[2];
    void* p;
    Function fn;
};

struct List
{
    UHalf capacity;
    UHalf size;
    Value data[];
};

static inline List* disturb_new(Int size);
static inline void disturb_free(List *list);
static inline List* disturb_double(List *list);
static inline List* disturb_half(List *list);
static inline List* disturb_push(List *list, Value value);
static inline List* disturb_unshift(List *list, Value value);
static inline List* disturb_insert(List *list, Int i, Value value);
static inline Value disturb_pop(List *list);
static inline Value disturb_shift(List *list);
static inline Value disturb_remove(List *list, Int i);

#define INDEX_CYCLE(index) ((index < 0) ? (list->size + index) : index)

static inline List *disturb_new(Int size)
{
    if (size < 0)
        PANIC("cannot create a list with negative size.");
    size_t cap = (size_t)size;
    size_t bytes = sizeof(List) + cap * sizeof(Value);
    List *list = (List*)malloc(bytes);
    list->size = 0;
    list->capacity = size;

    return list;
}

static inline void disturb_free(List *list)
{
    free(list);
}

static inline List *disturb_double(List *list)
{
    list->capacity = list->capacity == 0 ? 1 : list->capacity * 2;
    size_t bytes = sizeof(List) + (size_t)list->capacity * sizeof(Value);
    List *next = (List*)realloc(list, bytes);
    return next ? next : list;
}

static inline List *disturb_half(List *list)
{
    list->capacity /= 2;
    size_t bytes = sizeof(List) + (size_t)list->capacity * sizeof(Value);
    List *next = (List*)realloc(list, bytes);

    if (list->size > list->capacity)
        list->size = list->capacity;
    return next ? next : list;
}

static inline List *disturb_push(List *list, Value value)
{
    if (list->size == list->capacity)
        list = disturb_double(list);
    list->data[list->size] = value;
    list->size++;
    return list;
}

static inline List *disturb_unshift(List *list, Value value)
{
    if (list->size == list->capacity)
        list = disturb_double(list);
    memmove(&(list->data[1]), &(list->data[0]), (size_t)list->size * sizeof(Value));
    list->data[0] = value;

    list->size++;
    return list;
}

static inline List *disturb_insert(List *list, Int index, Value value)
{
    if (list->size == list->capacity)
        list = disturb_double(list);

    index = INDEX_CYCLE(index);

    if(index > list->size || index < 0)
        PANIC("cannot insert a value in a index out-of-bounds.");
    
    memmove(&(list->data[index + 1]), &(list->data[index]), (size_t)(list->size - index) * sizeof(Value));
    list->data[index] = value;
    list->size++;
    return list;
}

static inline Value disturb_pop(List *list)
{
    if (list->size <= 0)
        PANIC("cannot pop a empty list.");
    return list->data[--list->size];
}

static inline Value disturb_shift(List *list)
{
    if (list->size <= 0)
        PANIC("cannot shift a empty list.");
    Value ret = list->data[0];
    memmove(&(list->data[0]), &(list->data[1]), (size_t)(list->size - 1) * sizeof(Value)); 
    list->size--; 
    return ret;
}

static inline Value disturb_remove(List *list, Int i)
{
    i = INDEX_CYCLE(i);

    if (list->size <= 0)
        PANIC("cannot remove from a empty list.");
    else if(i > list->size || i < 0)
        PANIC("cannot remove a out-of-bounds value.");
    
    Value ret = list->data[i];
    Int elements_to_move = list->size - i - 1;
    memmove(&(list->data[i]), &(list->data[i + 1]), elements_to_move * sizeof(Value)); 
    list->size--; 
    return ret;
}

typedef struct ObjEntry ObjEntry;
typedef struct VM VM;
typedef struct FreeNode FreeNode;
typedef struct GcStats GcStats;

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
    unsigned in_use : 1;
    unsigned mark : 1;
    unsigned is_string : 1;
    unsigned explicit_string : 1;
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
    ObjEntry *call_entry;
    FreeNode *free_lists;
    FreeNode *free_bytes;
    Int call_override_len;
    int has_call_override;
    int strict_mode;
};

struct FreeNode {
    List *obj;
    struct FreeNode *next;
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
void vm_free_list(List *obj);
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

NativeFn vm_lookup_native(const char *name);

int vm_compile_source(const char *src, Bytecode *out, char *err, size_t err_cap);
ObjEntry *vm_bytecode_to_ast(VM *vm, const unsigned char *data, size_t len);

#endif
