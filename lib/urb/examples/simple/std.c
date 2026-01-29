#include "urb.h"

// interpret
void URB_interpret(List* stack)
{
    List* exec = urb_pop(stack).p;
    List* mem = urb_pop(stack).p;
    List* _stack = urb_pop(stack).p;
    urb_interpret(exec, mem, _stack);
}

void URB_stack(List* stack)
{
    urb_push(stack, (Value){.p = stack});
}

void URB_dup(List* stack)
{
    urb_push(stack, stack->data[stack->size - 1]);
}

void URB_over(List* stack)
{
    Value a = urb_pop(stack);
    Value b = urb_pop(stack);
    urb_push(stack, b);
    urb_push(stack, a);
    urb_push(stack, b);
}

void URB_rot(List* stack)
{
    Value a = urb_pop(stack);
    Value b = urb_pop(stack);
    Value c = urb_pop(stack);
    urb_push(stack, b);
    urb_push(stack, a);
    urb_push(stack, c);
}

void URB_drop(List* stack)
{
    urb_pop(stack);
}
