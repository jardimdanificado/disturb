#include "urb.h"

// interpret
void URB_strdup(List* stack)
{
    char* str = urb_pop(stack).p;
    char *dup = (char*)malloc(strlen(str) + 1);
    strcpy(dup, str);
    urb_push(stack, (Value){.p = dup});
}

void URB_strcat(List* stack)
{
    char* str1 = urb_pop(stack).p;
    char* str2 = urb_pop(stack).p;
    Int len1 = strlen(str1);
    Int len2 = strlen(str2);
    char *dup = (char*)malloc(len1 + len2 + 1);
    strcpy(dup, str1);
    strcpy(dup + len1, str2);
    urb_push(stack, (Value){.p = dup});
}

void URB_strsub(List* stack)
{
    char* str = urb_pop(stack).p;
    Int pos = urb_pop(stack).i;
    Int len = urb_pop(stack).i;
    char *dup = (char*)malloc(len + 1);
    strncpy(dup, str + pos, len);
    urb_push(stack, (Value){.p = dup});
}

void URB_strtol(List* stack)
{
    char* str = urb_pop(stack).p;
    void* endptr = urb_pop(stack).p;
    Int base = urb_pop(stack).i;
    urb_push(stack, (Value){.i = strtol(str, endptr, base)});
}

void URB_strstr(List* stack)
{
    char* str1 = urb_pop(stack).p;
    char* str2 = urb_pop(stack).p;
    urb_push(stack, (Value){.p = strstr(str1, str2)});
}

void URB_strchr(List* stack)
{
    char* str = urb_pop(stack).p;
    char ch = urb_pop(stack).i;
    urb_push(stack, (Value){.p = strchr(str, ch)});
}

void URB_strcmp(List* stack)
{
    char* str1 = urb_pop(stack).p;
    char* str2 = urb_pop(stack).p;
    urb_push(stack, (Value){.i = strcmp(str1, str2)});
}
