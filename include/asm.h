#ifndef URB_ASM_H
#define URB_ASM_H 1

#include <stddef.h>
#include <stdio.h>

#include "bytecode.h"

int urb_assemble(const char *source, Bytecode *out, char *err_buf, size_t err_cap);
int urb_disassemble(const unsigned char *data, size_t len, FILE *out);

#endif
