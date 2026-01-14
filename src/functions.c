#include "vm.h"

#include <stdio.h>
#include <string.h>

static void native_print(List *stack, List *global)
{
    (void)global;
    if (stack->size <= 2) {
        puts("(stack empty)");
        return;
    }

    ObjEntry *entry = (ObjEntry*)stack->data[stack->size - 1].p;
    print_entry(stdout, entry);
    fputs("\n", stdout);
}

static void native_println(List *stack, List *global)
{
    (void)global;
    if (stack->size <= 2) {
        fputs("\n", stdout);
        return;
    }

    ObjEntry *entry = (ObjEntry*)stack->data[stack->size - 1].p;
    print_plain_entry(stdout, entry);
    fputs("\n", stdout);
}

static void native_len(List *stack, List *global)
{
    ObjEntry *target = vm_stack_peek(stack, 0);
    if (!target) {
        fprintf(stderr, "len expects a value on stack\n");
        return;
    }

    ObjEntry *len_entry = vm_global_find_by_key(global, "__len");
    if (!len_entry) {
        fprintf(stderr, "len buffer missing (__len)\n");
        return;
    }
    if (urb_obj_type(len_entry->obj) != URB_T_NUMBER) {
        fprintf(stderr, "__len is not a number\n");
        return;
    }

    Int length = urb_value_len(target->obj);
    urb_number_set_single(len_entry->obj, (Float)length);
    urb_object_add(stack, len_entry);
}

static void native_append(List *stack, List *global)
{
    (void)global;
    ObjEntry *src = vm_stack_peek(stack, 0);
    ObjEntry *dst = vm_stack_peek(stack, 1);
    if (!src || !dst) {
        fprintf(stderr, "append expects target and source on stack\n");
        return;
    }

    Int dst_type = urb_obj_type(dst->obj);
    Int src_type = urb_obj_type(src->obj);
    if (!((dst_type == URB_T_CHAR && src_type == URB_T_CHAR) ||
          (dst_type == URB_T_BYTE && src_type == URB_T_BYTE))) {
        fprintf(stderr, "append expects matching char or byte types\n");
        return;
    }

    urb_bytes_append(dst->obj, urb_char_data(src->obj), urb_char_len(src->obj));
    urb_pop(stack);
}

NativeFn vm_lookup_native(const char *name)
{
    if (strcmp(name, "print") == 0) return native_print;
    if (strcmp(name, "println") == 0) return native_println;
    if (strcmp(name, "len") == 0) return native_len;
    if (strcmp(name, "append") == 0) return native_append;
    return NULL;
}
