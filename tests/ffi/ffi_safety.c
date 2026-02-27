/* Test library for Phase 7: safety & debugging */
#include <stdint.h>

int32_t safety_add(int32_t a, int32_t b) { return a + b; }
double  safety_half(double x) { return x / 2.0; }
const char *safety_hello(void) { return "hello"; }
