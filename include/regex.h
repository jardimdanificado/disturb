#ifndef REGEX_H
#define REGEX_H

#include "vm.h"
#include "regex_flags.h"

typedef struct RegexBox RegexBox;

ObjEntry *regex_box_new_entry(VM *vm, const char *pattern, size_t len, int flags,
                             char *err, size_t err_cap);
RegexBox *regex_box_from_entry(ObjEntry *entry);
RegexBox *regex_box_clone(const RegexBox *src);
void regex_box_free(RegexBox *box);
int regex_box_capture_count(const RegexBox *box);
int regex_box_flags(const RegexBox *box);
const char *regex_box_pattern(const RegexBox *box);
size_t regex_box_pattern_len(const RegexBox *box);
int regex_box_exec(const RegexBox *box, const char *input, size_t input_len,
                   size_t index, uint8_t **capture, size_t capture_len);

#endif // REGEX_H
