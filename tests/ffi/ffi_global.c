/* Test library for Phase 8: global variables */
#include <stdint.h>

/* Primitive global variables */
int32_t g_counter = 42;
double  g_pi = 3.14159265358979;
float   g_ratio = 1.618f;

/* Struct global variable */
typedef struct { float x; float y; } Vec2;
Vec2 g_position = { 10.5f, 20.25f };

/* Functions that read/modify the globals (for verification) */
int32_t get_counter(void) { return g_counter; }
void    set_counter(int32_t v) { g_counter = v; }
double  get_pi(void) { return g_pi; }
float   get_position_x(void) { return g_position.x; }
float   get_position_y(void) { return g_position.y; }
void    set_position(float x, float y) { g_position.x = x; g_position.y = y; }
