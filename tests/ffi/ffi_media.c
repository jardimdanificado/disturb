/* Test library for Média priority items: long double, _Bool, FAM */
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

/* 1.1: long double support */
long double ld_add(long double a, long double b) { return a + b; }
long double ld_get_pi(void) { return 3.14159265358979323846L; }
double ld_to_double(long double x) { return (double)x; }

/* 1.2: _Bool semantics */
_Bool bool_negate(_Bool x) { return !x; }
_Bool bool_and(_Bool a, _Bool b) { return a && b; }
_Bool bool_from_int(int x) { return (_Bool)x; }
int32_t bool_to_int(_Bool x) { return (int32_t)x; }

/* Struct with _Bool field */
typedef struct {
    int32_t id;
    _Bool active;
    int32_t value;
} BoolStruct;

static BoolStruct g_bs = {42, 1, 100};

BoolStruct *bool_struct_get(void) { return &g_bs; }
_Bool bool_struct_active(BoolStruct *bs) { return bs->active; }

/* 3.3: Flexible array member */
typedef struct {
    int32_t count;
    int32_t data[];
} FlexArray;

FlexArray *flex_create(int32_t n) {
    FlexArray *fa = (FlexArray*)malloc(sizeof(FlexArray) + (size_t)n * sizeof(int32_t));
    if (!fa) return NULL;
    fa->count = n;
    for (int32_t i = 0; i < n; i++) fa->data[i] = (i + 1) * 10;
    return fa;
}

void flex_free(FlexArray *fa) { free(fa); }

int32_t flex_sum(FlexArray *fa) {
    int32_t s = 0;
    for (int32_t i = 0; i < fa->count; i++) s += fa->data[i];
    return s;
}
