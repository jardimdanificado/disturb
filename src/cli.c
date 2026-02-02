#include "vm.h"
#include "urb_runtime.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

static char *read_all_text(FILE *fp)
{
    size_t cap = 4096;
    size_t len = 0;
    char *buf = (char*)malloc(cap);
    if (!buf) return NULL;

    int c;
    while ((c = fgetc(fp)) != EOF) {
        if (len + 1 >= cap) {
            size_t next = cap * 2;
            char *tmp = (char*)realloc(buf, next);
            if (!tmp) {
                free(buf);
                return NULL;
            }
            buf = tmp;
            cap = next;
        }
        buf[len++] = (char)c;
    }
    buf[len] = 0;
    return buf;
}


static void print_help(void)
{
    puts("usage:");
    puts("  disturb [script.disturb] [args...]");
    puts("  disturb --repl");
    puts("  disturb --urb [script.disturb]");
    puts("  disturb --help");
    puts("");
    puts("notes:");
    puts("  asm/disasm are available in example/asm_lib.disturb.");
}

static void repl_update_state(const char *line, int *depth, int *in_single, int *in_double, int *escape)
{
    for (const char *p = line; *p; p++) {
        char c = *p;
        if (*escape) {
            *escape = 0;
            continue;
        }
        if (c == '\\') {
            if (*in_single || *in_double) {
                *escape = 1;
            }
            continue;
        }
        if (*in_single) {
            if (c == '\'') *in_single = 0;
            continue;
        }
        if (*in_double) {
            if (c == '"') *in_double = 0;
            continue;
        }
        if (c == '\'') {
            *in_single = 1;
            continue;
        }
        if (c == '"') {
            *in_double = 1;
            continue;
        }
        if (c == '{' || c == '(' || c == '[') {
            (*depth)++;
            continue;
        }
        if (c == '}' || c == ')' || c == ']') {
            if (*depth > 0) (*depth)--;
        }
    }
}

// Função para adicionar os argumentos como um objeto na VM
static void vm_add_args(VM *vm, int argc, char **argv)
{
    char var_name[32];
    
    // Define cada argumento como variável global arg_0, arg_1, etc.
    char **items = argc > 0 ? (char**)malloc(sizeof(char*) * argc) : NULL;
    
    for (int i = 0; i < argc; i++) {
        snprintf(var_name, sizeof(var_name), "arg_%d", i);
        vm_define_bytes(vm, var_name, argv[i]);
        
        // Aloca e copia o nome da variável para o array items
        items[i] = (char*)malloc(32);
        snprintf(items[i], 32, "arg_%d", i);
    }
    
    // Define o objeto args sem chaves
    if (items) {
        vm_define_table(vm, "args", items, argc, 0);
        
        // Libera a memória alocada para os nomes
        for (int i = 0; i < argc; i++) {
            free(items[i]);
        }
        free(items);
    }
    
    // Define argc como uma variável única
    snprintf(var_name, sizeof(var_name), "%d", argc);
    vm_define_bytes(vm, "argc", var_name);
}

static int repl_run(int argc, char **argv)
{
    VM vm;
    vm_init(&vm);
    
    // Adiciona os argumentos na VM
    vm_add_args(&vm, argc, argv);

    size_t cap = 0;
    size_t len = 0;
    char *buf = NULL;
    char line[4096];
    int depth = 0;
    int in_single = 0;
    int in_double = 0;
    int escape = 0;

    while (1) {
        fputs(depth == 0 ? "disturb> " : "....> ", stdout);
        fflush(stdout);
        if (!fgets(line, sizeof(line), stdin)) break;
        if (depth == 0 && (strcmp(line, "exit\n") == 0 || strcmp(line, "quit\n") == 0)) break;

        size_t line_len = strlen(line);
        if (len + line_len + 1 > cap) {
            size_t next = cap == 0 ? 4096 : cap * 2;
            while (next < len + line_len + 1) next *= 2;
            char *tmp = (char*)realloc(buf, next);
            if (!tmp) {
                fprintf(stderr, "repl: out of memory\n");
                free(buf);
                vm_free(&vm);
                return 1;
            }
            buf = tmp;
            cap = next;
        }
        memcpy(buf + len, line, line_len);
        len += line_len;
        buf[len] = 0;

        repl_update_state(line, &depth, &in_single, &in_double, &escape);
        if (depth == 0 && !in_single && !in_double) {
            if (len > 0) vm_exec_line(&vm, buf);
            len = 0;
            if (buf) buf[0] = 0;
        }
    }

    free(buf);
    vm_free(&vm);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc > 1) {
        if (strcmp(argv[1], "--urb") == 0) {
            if (argc < 3) {
                fprintf(stderr, "disturb --urb expects a source file\n");
                return 1;
            }
            FILE *fp = fopen(argv[2], "r");
            if (!fp) {
                perror("open");
                return 1;
            }
            Bytecode bc;
            char err[256];
            err[0] = 0;
            char *src = read_all_text(fp);
            if (!src) {
                fprintf(stderr, "failed to read file\n");
                fclose(fp);
                return 1;
            }
            if (src[0] == '#' && src[1] == '!') {
                char *nl = strchr(src, '\n');
                if (!nl) {
                    src[0] = '\0';
                } else {
                    size_t offset = (size_t)(nl - src) + 1;
                    size_t remaining = strlen(src + offset);
                    memmove(src, src + offset, remaining + 1);
                }
            }
            if (!vm_compile_source(src, &bc, err, sizeof(err))) {
                fprintf(stderr, "%s\n", err[0] ? err : "compile error");
                free(src);
                fclose(fp);
                return 1;
            }
            free(src);
            fclose(fp);
            int script_argc = argc - 3;
            char **script_argv = argv + 3;
            int ok = urb_exec_bytecode(bc.data, bc.len, script_argc, script_argv);
            bc_free(&bc);
            return ok ? 0 : 1;
        }
        if (strcmp(argv[1], "--repl") == 0) {
            return repl_run(argc, argv);
        }
        if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
            print_help();
            return 0;
        }

        VM vm;
        vm_init(&vm);
        
        int script_argc = argc - 2;
        char **script_argv = argv + 2;
        vm_add_args(&vm, script_argc, script_argv);
        
        FILE *fp = fopen(argv[1], "r");
        if (!fp) {
            perror("open");
            vm_free(&vm);
            return 1;
        }
        char *src = read_all_text(fp);
        if (!src) {
            fprintf(stderr, "failed to read file\n");
            fclose(fp);
            vm_free(&vm);
            return 1;
        }

        if (src[0] == '#' && src[1] == '!') {
            char *nl = strchr(src, '\n');
            if (!nl) {
                src[0] = '\0';
            } else {
                size_t offset = (size_t)(nl - src) + 1;
                size_t remaining = strlen(src + offset);
                memmove(src, src + offset, remaining + 1);
            }
        }
        vm_exec_line(&vm, src);
        free(src);
        fclose(fp);
        vm_free(&vm);
    } else {
        return repl_run(argc, argv);
    }

    return 0;
}
