#ifndef PAPAGAIO_H
#define PAPAGAIO_H 1

#include "vm.h"

char *papagaio_process_pairs(VM *vm, const char *input,
                             const char **patterns,
                             const char **repls,
                             int pair_count);

#endif // PAPAGAIO_H
