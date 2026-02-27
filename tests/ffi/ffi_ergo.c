/* Test library for Phase 6: ergonomia */
#include <stdint.h>
#include <string.h>

int32_t ergo_add(int32_t a, int32_t b) { return a + b; }
int32_t ergo_mul(int32_t a, int32_t b) { return a * b; }
double  ergo_half(double x) { return x / 2.0; }

typedef struct { float x; float y; } Vec2;

Vec2 ergo_vec2_add(Vec2 a, Vec2 b) {
    Vec2 r = { a.x + b.x, a.y + b.y };
    return r;
}

float ergo_vec2_dot(Vec2 a, Vec2 b) {
    return a.x * b.x + a.y * b.y;
}
