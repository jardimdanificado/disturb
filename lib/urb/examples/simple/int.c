#include "urb.h"

void URB_add(List* stack)
{
    Int a = urb_pop(stack).i;
    Int b = urb_pop(stack).i;
    urb_push(stack, (Value){.i = a + b});
}

void URB_sub(List* stack)
{
    Int a = urb_pop(stack).i;
    Int b = urb_pop(stack).i;
    urb_push(stack, (Value){.i = a - b});
}

void URB_mul(List* stack)
{
    Int a = urb_pop(stack).i;
    Int b = urb_pop(stack).i;
    urb_push(stack, (Value){.i = a * b});
}

void URB_div(List* stack)
{
    Int a = urb_pop(stack).i;
    Int b = urb_pop(stack).i;
    if (a == 0) {
        urb_push(stack, (Value){.i = 0}); // evitar divisão por zero
        return;
    }
    urb_push(stack, (Value){.i = a / b});
}

void URB_mod(List* stack)
{
    Int a = urb_pop(stack).i;
    Int b = urb_pop(stack).i;
    if (a == 0) {
        urb_push(stack, (Value){.i = 0});
        return;
    }
    urb_push(stack, (Value){.i = a % b});
}

// bitwise stuff

void URB_band(List* stack)
{
    Int a = urb_pop(stack).i;
    Int b = urb_pop(stack).i;
    urb_push(stack, (Value){.i = a & b});
}

void URB_bor(List* stack)
{
    Int a = urb_pop(stack).i;
    Int b = urb_pop(stack).i;
    urb_push(stack, (Value){.i = a | b});
}

void URB_bxor(List* stack)
{
    Int a = urb_pop(stack).i;
    Int b = urb_pop(stack).i;
    urb_push(stack, (Value){.i = a ^ b});
}

void URB_bnot(List* stack)
{
    Int a = urb_pop(stack).i;
    urb_push(stack, (Value){.i = ~a});
}

void URB_lshift(List* stack)
{
    Int a = urb_pop(stack).i;
    Int b = urb_pop(stack).i;
    urb_push(stack, (Value){.i = a << b});
}

void URB_rshift(List* stack)
{
    Int a = urb_pop(stack).i;
    Int b = urb_pop(stack).i;
    urb_push(stack, (Value){.i = a >> b});
}

// condition stuff

void URB_gt(List* stack)
{
    Int a = urb_pop(stack).i;
    Int b = urb_pop(stack).i;
    urb_push(stack, (Value){.i = a > b});
}

void URB_lt(List* stack)
{
    Int a = urb_pop(stack).i;
    Int b = urb_pop(stack).i;
    urb_push(stack, (Value){.i = a < b});
}

void URB_ge(List* stack)
{
    Int a = urb_pop(stack).i;
    Int b = urb_pop(stack).i;
    urb_push(stack, (Value){.i = a >= b});
}

void URB_le(List* stack)
{
    Int a = urb_pop(stack).i;
    Int b = urb_pop(stack).i;
    urb_push(stack, (Value){.i = a <= b});
}

void URB_eq(List* stack)
{
    Int a = urb_pop(stack).i;
    Int b = urb_pop(stack).i;
    urb_push(stack, (Value){.i = a == b});
}

void URB_ne(List* stack)
{
    Int a = urb_pop(stack).i;
    Int b = urb_pop(stack).i;
    urb_push(stack, (Value){.i = a != b});
}

void URB_not(List* stack)
{
    urb_push(stack, (Value){.i = !urb_pop(stack).i});
}
