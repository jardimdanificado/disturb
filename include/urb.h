// urb
// urb use no other libraries beside the standard C99 libraries
// urb.h is standalone and is not dependant on any other file of the repo

#ifndef URB_H
#define URB_H 1

// standard library
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>
#include <stdbool.h>
#include <ctype.h>

// version
#define URB_VERSION "0.9.5"

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

#ifndef URB_DEFAULT_SIZE
    #define URB_DEFAULT_SIZE 0
#endif

#define PANIC(message) do {\
        fprintf(stderr, "URB ERROR:" message "\n");\
        fflush(stderr);\
        abort();\
    } while (0)

typedef struct List List;
typedef union Value Value;
typedef void (*Function)(List *stack);

// we use unions here for type punning
// by the c standards this is considered a undefined behavior
union Value
{
    // all types depend on the size of the pointer
    Int i;
    UInt u;
    Float f;
    UHalf h[2];
    void* p;
    Function fn;
};

struct List
{
    // the real size
    UHalf capacity;
    // the current size
    UHalf size;
    // the data, it is a pointer to a Value array
    Value *data;
};

// List functions   
// create a new list with the given size, if size is 0, it will be initialized with NULL data and then allocated when needed
static inline List*              urb_new(Int size);
// free the list    
static inline void               urb_free(List *list);
// double the list capacity   
static inline void               urb_double(List *list);
// halve the list capacity   
static inline void               urb_half(List *list);
// push a value to the end of the list
static inline void               urb_push(List *list, Value value);
// unshift a value to the start of the list
static inline void               urb_unshift(List *list, Value value);
// insert a value at index i in the list
static inline void               urb_insert(List *list, Int i, Value value);
// pop a value from the end of the list
static inline Value              urb_pop(List *list);
// shift a value from the start of the list
static inline Value              urb_shift(List *list);
// remove and return the value at index i in the list, shifting the rest of the list
static inline Value              urb_remove(List *list, Int i);

// index cycle deal with negative indexes, -1 is the last value, and so on
#define INDEX_CYCLE(index) ((index < 0) ? (list->size + index) : index)

static inline List *urb_new(Int size)
{
    if (size < 0)
        PANIC("cannot create a list with negative size.");
    List *list = (List*)malloc(sizeof(List));
    list->data = (size == 0) ? NULL : (Value*)malloc((size_t)size * sizeof(Value));
    list->size = 0;
    list->capacity = size;

    return list;
}

static inline void urb_free(List *list)
{
    free(list->data);
    free(list);
}

static inline void urb_double(List *list)
{
    list->capacity = list->capacity == 0 ? 1 : list->capacity * 2;
    Value *new_data = (Value*)realloc(list->data, (size_t)list->capacity * sizeof(Value));
    list->data = new_data;
}

static inline void urb_half(List *list)
{
    list->capacity /= 2;
    Value *new_data = (Value*)realloc(list->data, (size_t)list->capacity * sizeof(Value));
    list->data = new_data;

    if (list->size > list->capacity)
        list->size = list->capacity;
}

static inline void urb_push(List *list, Value value)
{
    if (list->size == list->capacity)
        urb_double(list);
    list->data[list->size] = value;
    list->size++;
}

static inline void urb_unshift(List *list, Value value)
{
    if (list->size == list->capacity)
        urb_double(list);
    memmove(&(list->data[1]), &(list->data[0]), (size_t)list->size * sizeof(Value));
    list->data[0] = value;

    list->size++;
}

static inline void urb_insert(List *list, Int index, Value value)
{
    if (list->size == list->capacity)
        urb_double(list);

    index = INDEX_CYCLE(index);

    if(index > list->size || index < 0)
        PANIC("cannot insert a value in a index out-of-bounds.");
    
    memmove(&(list->data[index + 1]), &(list->data[index]), (size_t)(list->size - index) * sizeof(Value));
    list->data[index] = value;
    list->size++;
}

static inline Value urb_pop(List *list)
{
    if (list->size <= 0)
        PANIC("cannot pop a empty list.");
    return list->data[--list->size];
}

static inline Value urb_shift(List *list)
{
    if (list->size <= 0)
        PANIC("cannot shift a empty list.");
    Value ret = list->data[0];
    memmove(&(list->data[0]), &(list->data[1]), (size_t)(list->size - 1) * sizeof(Value)); 
    list->size--; 
    return ret;
}

static inline Value urb_remove(List *list, Int i)
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

#endif // ifndef URB_H macro
