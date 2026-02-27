#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Simple struct for testing */
struct Point {
    int32_t x;
    int32_t y;
};

/* Allocate a buffer with known values */
int32_t *make_int_array(int count)
{
    int32_t *arr = (int32_t *)calloc((size_t)count, sizeof(int32_t));
    if (!arr) return NULL;
    for (int i = 0; i < count; i++) arr[i] = (i + 1) * 10;
    return arr;
}

void free_buf(void *p) { free(p); }

/* Returns a pointer-to-pointer (int32_t**) for testing deref */
int32_t **make_ptr_to_int(void)
{
    int32_t **pp = (int32_t **)malloc(sizeof(int32_t *));
    if (!pp) return NULL;
    int32_t *p = (int32_t *)malloc(sizeof(int32_t));
    if (!p) { free(pp); return NULL; }
    *p = 42;
    *pp = p;
    return pp;
}

void free_ptr_to_int(int32_t **pp)
{
    if (pp) {
        if (*pp) free(*pp);
        free(pp);
    }
}

int32_t read_ptr_to_int(int32_t **pp)
{
    return (pp && *pp) ? **pp : -1;
}

/* Make a Point for testing cast */
struct Point *make_point(int32_t x, int32_t y)
{
    struct Point *p = (struct Point *)malloc(sizeof(struct Point));
    if (!p) return NULL;
    p->x = x;
    p->y = y;
    return p;
}

void free_point(struct Point *p) { free(p); }
int32_t point_get_x(struct Point *p) { return p ? p->x : 0; }
int32_t point_get_y(struct Point *p) { return p ? p->y : 0; }
int point_sizeof(void) { return (int)sizeof(struct Point); }

/* Two adjacent Points for offset testing */
struct Point *make_two_points(void)
{
    struct Point *arr = (struct Point *)calloc(2, sizeof(struct Point));
    if (!arr) return NULL;
    arr[0].x = 1; arr[0].y = 2;
    arr[1].x = 3; arr[1].y = 4;
    return arr;
}
