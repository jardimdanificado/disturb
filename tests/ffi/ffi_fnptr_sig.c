/* Test library for Phase 5: function pointers in signatures */
#include <stdint.h>
#include <stdio.h>

/* Callback type: int32_t (*)(int32_t, int32_t) */
typedef int32_t (*BinOp)(int32_t, int32_t);

/* Accept a function pointer and call it */
int32_t apply_binop(BinOp fn, int32_t a, int32_t b)
{
    if (!fn) return -1;
    return fn(a, b);
}

/* Accept two function pointers and compose: f(g(a,b), g(a,b)) */
int32_t compose_binops(BinOp f, BinOp g, int32_t a, int32_t b)
{
    if (!f || !g) return -1;
    int32_t r = g(a, b);
    return f(r, r);
}

/* Internal add/mul for testing returns */
static int32_t add_impl(int32_t a, int32_t b) { return a + b; }
static int32_t mul_impl(int32_t a, int32_t b) { return a * b; }

/* Return a function pointer based on op selector */
BinOp get_op(int32_t sel)
{
    if (sel == 0) return add_impl;
    if (sel == 1) return mul_impl;
    return NULL;
}

/* Accept a void callback with int arg */
typedef void (*IntAction)(int32_t);
static int32_t g_action_result = 0;

void run_action(IntAction act, int32_t v)
{
    if (act) act(v);
}

int32_t get_action_result(void)
{
    return g_action_result;
}

void set_action_result(int32_t v)
{
    g_action_result = v;
}
