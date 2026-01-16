#include <stdio.h>

struct Level {
  struct Level *a;
  int value;
};

static struct Level l8 = {NULL, 12345};
static struct Level l7 = {&l8, 0};
static struct Level l6 = {&l7, 0};
static struct Level l5 = {&l6, 0};
static struct Level l4 = {&l5, 0};
static struct Level l3 = {&l4, 0};
static struct Level l2 = {&l3, 0};
static struct Level l1 = {&l2, 0};

int main(void) {
  struct Level *x = &l1;
  x = x->a->a->a->a->a->a->a;
  printf("%d\n", x->value);
  return 0;
}
