/* Test library for Baixa priority items */
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

/* 4.2: Packed structs — by-value is NOT possible (ABI limitation),
   so we test pointer-based access which is the documented workaround. */
typedef struct __attribute__((packed)) {
    uint8_t  tag;
    int32_t  value;
    uint8_t  flag;
} PackedSmall;  /* 6 bytes packed, would be 12 unpacked */

/* Works with pointer — the documented workaround for by-value limitation */
int32_t packed_sum_ptr(PackedSmall *s) {
    return (int32_t)s->tag + s->value + (int32_t)s->flag;
}

PackedSmall *packed_make(uint8_t tag, int32_t value, uint8_t flag) {
    PackedSmall *s = (PackedSmall*)malloc(sizeof(PackedSmall));
    s->tag = tag;
    s->value = value;
    s->flag = flag;
    return s;
}

void packed_free(PackedSmall *s) { free(s); }

/* 4.5: Array of structs as function arg */
typedef struct { float x; float y; } Vec2;

float vec2_array_sum_x(Vec2 *arr, int32_t count) {
    float sum = 0;
    for (int i = 0; i < count; i++) sum += arr[i].x;
    return sum;
}
