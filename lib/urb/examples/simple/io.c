#include "urb.h"

void print(List* stack)
{
    Int value = urb_pop(stack).i;
    printf("%ld", value);
}

void println(List* stack)
{
    Int value = urb_pop(stack).i;
    printf("%ld\n", value);
}

void pring(List* stack)
{
    unsigned char* str = urb_pop(stack).p;
    printf("%s", str);
}

void pringln(List* stack)
{
    unsigned char* str = urb_pop(stack).p;
    printf("%s\n", str);
}

void ls(List* stack)
{
    // [index, type, "name"] = value;
    List* list = urb_pop(stack).p;
    for (Int i = 0; i < list->size; i++)
    {
        printf("[%ld] = %ld\n", i, list->data[i].i);
    }
}

// file i/o
void load_urbin(List* stack)
{
    // all variables are misnamed because they came from another context

    char* filename = urb_pop(stack).p;
    FILE* file = fopen(filename, "rb");
    if (!file) 
    {
        PANIC("tried loading a file that doesnt exist.\n");
    }

    Int code_size;
    if (fread(&code_size, sizeof(Int), 1, file) != 1) 
    {
        PANIC("tried loading a file that is corrupted or not a valid URB binary.\n");
    }

    Int cap = 1;
    while (cap < code_size) cap *= 2;

    List* code = urb_new(cap);
    code->size = code_size;

    if (fread(code->data, sizeof(Int), code->size, file) != code->size) {
        PANIC("tried loading a file that is corrupted or not a valid URB binary.\n");
    }

    fclose(file);
    urb_push(stack, (Value){.p = code});
}
