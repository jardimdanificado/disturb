#include "urb.h"

// interpret
void URB_memcpy(List* stack)
{
    void* dest = urb_pop(stack).p;
    void* origin = urb_pop(stack).p;
    Int len = urb_pop(stack).i;
    memcpy(dest, origin, len);
}

void URB_memmove(List* stack)
{
    void* dest = urb_pop(stack).p;
    void* origin = urb_pop(stack).p;
    Int len = urb_pop(stack).i;
    memcpy(dest, origin, len);
}

void URB_memfree(List* stack)
{
    free(urb_pop(stack).p);
}

void URB_memalloc(List* stack)
{
    urb_push(stack, (Value){.p = malloc(urb_pop(stack).i)});
}

void URB_memcalloc(List* stack)
{
    urb_push(stack, (Value){.p = calloc(urb_pop(stack).i, 1)});
}

void URB_memset(List* stack)
{
    void* ptr = urb_pop(stack).p;
    uint8_t value = urb_pop(stack).i;
    Int len = urb_pop(stack).i;
    memset(ptr, value, len);
}

void URB_memget(List* stack)
{
    uint8_t* ptr = urb_pop(stack).p;
    Int index = urb_pop(stack).i;
    urb_push(stack, (Value){.i = ptr[index]});
}

void URB_memcmp(List* stack)
{
    void* mem1 = urb_pop(stack).p;
    void* mem2 = urb_pop(stack).p;
    Int memsize = urb_pop(stack).i;
    urb_push(stack, (Value){.i = memcmp(mem1, mem2, memsize)});
}
