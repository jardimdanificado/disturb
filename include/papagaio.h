// this is a REIMPLEMENTATION of papagaio.js in c
// do not mistake with the original papagaio.h
// https://github.com/jardimdanificado/papagaio

#ifndef PAPAGAIO_H
#define PAPAGAIO_H 1

#include "vm.h"
#include <stddef.h>

char *papagaio_process_pairs(VM *vm, const char *input,
                             const char **patterns,
                             const char **repls,
                             int pair_count);
char *papagaio_process_text(VM *vm, const char *input, size_t len);

#endif // PAPAGAIO_H
