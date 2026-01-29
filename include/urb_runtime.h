#ifndef URB_RUNTIME_H
#define URB_RUNTIME_H 1

#include <stddef.h>

/* Execute Disturb bytecode using URB runtime compatibility layer. */
int urb_exec_bytecode(const unsigned char *data, size_t len);

#endif
