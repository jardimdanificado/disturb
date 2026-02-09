#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

struct Inner {
    int8_t a;
    int16_t b;
};

struct Outer {
    int32_t a;
    double b;
    struct Inner d;
};

struct ArrOuter {
    int32_t head;
    int64_t vals[8];
    float f32s[3];
};

struct Outer* make_outer(void)
{
    struct Outer *o = (struct Outer*)calloc(1, sizeof(struct Outer));
    return o;
}

void free_outer(struct Outer *o)
{
    free(o);
}

int outer_sizeof(void) { return (int)sizeof(struct Outer); }
int outer_off_a(void) { return (int)offsetof(struct Outer, a); }
int outer_off_b(void) { return (int)offsetof(struct Outer, b); }
int outer_off_d(void) { return (int)offsetof(struct Outer, d); }

int inner_off_a(void) { return (int)offsetof(struct Inner, a); }
int inner_off_b(void) { return (int)offsetof(struct Inner, b); }

int outer_get_a(struct Outer *o) { return o ? (int)o->a : 0; }
double outer_get_b(struct Outer *o) { return o ? o->b : 0.0; }
int inner_get_a(struct Outer *o) { return o ? (int)o->d.a : 0; }
int inner_get_b(struct Outer *o) { return o ? (int)o->d.b : 0; }

struct ArrOuter* make_arr_outer(void)
{
    return (struct ArrOuter*)calloc(1, sizeof(struct ArrOuter));
}

void free_arr_outer(struct ArrOuter *o)
{
    free(o);
}

int arr_outer_sizeof(void) { return (int)sizeof(struct ArrOuter); }
int arr_outer_off_head(void) { return (int)offsetof(struct ArrOuter, head); }
int arr_outer_off_vals(void) { return (int)offsetof(struct ArrOuter, vals); }
int arr_outer_off_f32s(void) { return (int)offsetof(struct ArrOuter, f32s); }
int arr_outer_get_val(struct ArrOuter *o, int idx) { return o ? (int)o->vals[idx] : 0; }
float arr_outer_get_f32(struct ArrOuter *o, int idx) { return o ? o->f32s[idx] : 0.0f; }

int add_i32(int a, int b)
{
    return a + b;
}

void* get_add_i32_ptr(void)
{
    return (void*)&add_i32;
}
