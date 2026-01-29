#include "urb.h"

void test_func(List* stack)
{
    Value v = urb_pop(stack);
    printf("value = %ld\n", v.i);
}
