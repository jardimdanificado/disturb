#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdarg.h>

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

struct HalfPair {
    int16_t lo;
    int16_t hi;
};

union Bits {
    int32_t i;
    float f;
    struct HalfPair p;
};

struct UnionHolder {
    int32_t tag;
    union Bits payload;
};

typedef int (*fn_i32_i32)(int, int);
int add_i32(int a, int b);
struct FnHolder {
    fn_i32_i32 cb;
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

int bits_sizeof(void) { return (int)sizeof(union Bits); }
int bits_off_i(void) { return (int)offsetof(union Bits, i); }
int bits_off_f(void) { return (int)offsetof(union Bits, f); }
int bits_off_p(void) { return (int)offsetof(union Bits, p); }
int bits_take_value_i(union Bits b) { return (int)b.i; }
union Bits make_bits_value_i(int32_t i)
{
    union Bits b;
    b.i = i;
    return b;
}
void bits_write_i(union Bits *b, int32_t i)
{
    if (!b) return;
    b->i = i;
}
int bits_read_hi(union Bits b) { return (int)b.p.hi; }

int holder_sizeof(void) { return (int)sizeof(struct UnionHolder); }
int holder_off_tag(void) { return (int)offsetof(struct UnionHolder, tag); }
int holder_off_payload(void) { return (int)offsetof(struct UnionHolder, payload); }
int holder_take_payload_i(struct UnionHolder h) { return (int)h.payload.i; }

int fn_holder_sizeof(void) { return (int)sizeof(struct FnHolder); }
int fn_holder_off_cb(void) { return (int)offsetof(struct FnHolder, cb); }
void fn_holder_set_add(struct FnHolder *h)
{
    if (!h) return;
    h->cb = &add_i32;
}
int fn_holder_call(struct FnHolder *h, int a, int b)
{
    if (!h || !h->cb) return 0;
    return h->cb(a, b);
}

int add_i32(int a, int b)
{
    return a + b;
}

void* get_add_i32_ptr(void)
{
    return (void*)&add_i32;
}

int sum_outer_value(struct Outer o)
{
    return (int)o.a + (int)o.d.a + (int)o.d.b;
}

struct Outer make_outer_value(int32_t a, double b, int8_t da, int16_t db)
{
    struct Outer o;
    o.a = a;
    o.b = b;
    o.d.a = da;
    o.d.b = db;
    return o;
}

int sum_variadic_i32(int count, ...)
{
    va_list ap;
    va_start(ap, count);
    int out = 0;
    for (int i = 0; i < count; i++) {
        out += va_arg(ap, int);
    }
    va_end(ap);
    return out;
}

typedef int (*cb_i32_i32)(int, int);
typedef double (*cb_f64_f64)(double, double);

int call_cb_i32(cb_i32_i32 cb, int a, int b)
{
    if (!cb) return 0;
    return cb(a, b);
}

int fold_cb_i32(cb_i32_i32 cb, int start, int count)
{
    if (!cb) return 0;
    int acc = start;
    for (int i = 0; i < count; i++) {
        acc = cb(acc, i + 1);
    }
    return acc;
}

double call_cb_f64(cb_f64_f64 cb, double a, double b)
{
    if (!cb) return 0.0;
    return cb(a, b);
}

double sum_variadic_f64(int count, ...)
{
    va_list ap;
    va_start(ap, count);
    double out = 0.0;
    for (int i = 0; i < count; i++) {
        out += va_arg(ap, double);
    }
    va_end(ap);
    return out;
}

void* get_sum_variadic_i32_ptr(void)
{
    return (void*)&sum_variadic_i32;
}

int cstr_len(const char *s)
{
    if (!s) return 0;
    int n = 0;
    while (s[n] != 0) n++;
    return n;
}

int write_seq_u8(uint8_t *buf, int len, int start)
{
    if (!buf || len < 0) return 0;
    for (int i = 0; i < len; i++) {
        buf[i] = (uint8_t)(start + i);
    }
    return len;
}

int read_u8(uint8_t *buf, int idx)
{
    if (!buf || idx < 0) return 0;
    return (int)buf[idx];
}
