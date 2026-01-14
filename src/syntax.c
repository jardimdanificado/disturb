#include "vm.h"
#include "papagaio.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char **items;
    int count;
    int cap;
} Tokens;

static void tokens_push(Tokens *t, const char *start, size_t len)
{
    if (t->count == t->cap) {
        t->cap = t->cap == 0 ? 8 : t->cap * 2;
        t->items = (char**)realloc(t->items, (size_t)t->cap * sizeof(char*));
    }
    char *s = (char*)malloc(len + 1);
    memcpy(s, start, len);
    s[len] = 0;
    t->items[t->count++] = s;
}

static void tokens_free(Tokens *t)
{
    for (int i = 0; i < t->count; i++) {
        free(t->items[i]);
    }
    free(t->items);
    t->items = NULL;
    t->count = 0;
    t->cap = 0;
}

static char *normalize_line(const char *line)
{
    return papagaio_process(
        line,
        "char $key ${\"}{\"}str", "char $key @str{$str}",
        "char _ ${\"}{\"}str", "char _ @str{$str}",
        "char ${\"}{\"}str", "char _ @str{$str}",
        "any $key ${[}{]}items", "any $key $items",
        "any _ ${[}{]}items", "any _ $items",
        "any ${[}{]}items", "any _ $items"
    );
}

static Tokens tokenize_line(const char *line)
{
    Tokens t;
    t.items = NULL;
    t.count = 0;
    t.cap = 0;

    const char *p = line;
    while (*p) {
        while (*p && isspace((unsigned char)*p)) p++;
        if (!*p) break;

        if (strncmp(p, "@str{", 5) == 0) {
            p += 5;
            const char *start = p;
            while (*p && *p != '}') p++;
            tokens_push(&t, start, (size_t)(p - start));
            if (*p == '}') p++;
            continue;
        }

        const char *start = p;
        while (*p && !isspace((unsigned char)*p)) p++;
        tokens_push(&t, start, (size_t)(p - start));
    }

    return t;
}

static int is_null_key(const char *s)
{
    return strcmp(s, "_") == 0 || strcmp(s, "null") == 0 || strcmp(s, "nil") == 0;
}

static int is_number_token(const char *s)
{
    if (!*s) return 0;
    if (*s == '+' || *s == '-') s++;
    if (!*s) return 0;
    if (*s == '.') s++;
    if (!*s) return 0;
    return isdigit((unsigned char)*s);
}

static void vm_exec_tokens(VM *vm, Tokens *t)
{
    if (t->count == 0) return;
    const char *cmd = t->items[0];

    if (strcmp(cmd, "char") == 0) {
        if (t->count < 2) {
            fprintf(stderr, "char expects a string\n");
            return;
        }
        if (t->count == 2) {
            vm_define_char(vm, NULL, t->items[1]);
            return;
        }
        if (is_null_key(t->items[1])) {
            if (t->count < 3) {
                fprintf(stderr, "char expects a string\n");
                return;
            }
            vm_define_char(vm, NULL, t->items[2]);
            return;
        }
        vm_define_char(vm, t->items[1], t->items[2]);
        return;
    }

    if (strcmp(cmd, "byte") == 0) {
        if (t->count < 2) {
            fprintf(stderr, "byte expects uint8 values\n");
            return;
        }
        if (is_null_key(t->items[1])) {
            vm_define_byte(vm, NULL, t->items, t->count, 2);
            return;
        }
        vm_define_byte(vm, t->items[1], t->items, t->count, 2);
        return;
    }

    if (strcmp(cmd, "number") == 0) {
        if (t->count < 2) {
            fprintf(stderr, "number expects values\n");
            return;
        }
        if (is_null_key(t->items[1]) || is_number_token(t->items[1])) {
            vm_define_number(vm, NULL, t->items, t->count, 1);
            return;
        }
        vm_define_number(vm, t->items[1], t->items, t->count, 2);
        return;
    }

    if (strcmp(cmd, "any") == 0) {
        if (t->count < 2) {
            fprintf(stderr, "any expects members\n");
            return;
        }
        if (is_null_key(t->items[1])) {
            vm_define_any(vm, NULL, t->items, t->count, 2);
            return;
        }
        vm_define_any(vm, t->items[1], t->items, t->count, 2);
        return;
    }

    if (strcmp(cmd, "native") == 0) {
        if (t->count < 2) {
            fprintf(stderr, "native expects a function name\n");
            return;
        }
        if (is_null_key(t->items[1])) {
            if (t->count < 3) {
                fprintf(stderr, "native expects a function name\n");
                return;
            }
            vm_define_native(vm, NULL, t->items[2]);
            return;
        }
        if (t->count < 3) {
            fprintf(stderr, "native expects key and function name\n");
            return;
        }
        vm_define_native(vm, t->items[1], t->items[2]);
        return;
    }

    if (strcmp(cmd, "push") == 0) {
        if (t->count < 2) {
            fprintf(stderr, "push expects a key\n");
            return;
        }
        vm_push_stack(vm, t->items[1]);
        return;
    }

    if (strcmp(cmd, "pop") == 0) {
        vm_pop_stack(vm);
        return;
    }

    if (strcmp(cmd, "call") == 0) {
        if (t->count < 2) {
            fprintf(stderr, "call expects a key\n");
            return;
        }
        vm_call_native(vm, t->items[1]);
        return;
    }

    if (strcmp(cmd, "drop") == 0) {
        if (t->count < 2) {
            fprintf(stderr, "drop expects a key\n");
            return;
        }
        if (!vm_global_remove_by_key(vm, t->items[1])) {
            fprintf(stderr, "key not in global: %s\n", t->items[1]);
        }
        return;
    }

    if (strcmp(cmd, "gc") == 0) {
        vm_gc(vm);
        return;
    }

    if (strcmp(cmd, "dump") == 0) {
        vm_dump_global(vm);
        return;
    }

    fprintf(stderr, "unknown command: %s\n", cmd);
}

void vm_exec_line(VM *vm, const char *line)
{
    char *normalized = normalize_line(line);
    Tokens t = tokenize_line(normalized);
    vm_exec_tokens(vm, &t);
    tokens_free(&t);
    free(normalized);
}
