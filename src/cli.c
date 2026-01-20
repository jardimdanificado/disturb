#include "asm.h"
#include "vm.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

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

static unsigned char *read_all_bin(FILE *fp, size_t *out_len)
{
    size_t cap = 4096;
    size_t len = 0;
    unsigned char *buf = (unsigned char*)malloc(cap);
    if (!buf) return NULL;

    int c;
    while ((c = fgetc(fp)) != EOF) {
        if (len + 1 >= cap) {
            size_t next = cap * 2;
            unsigned char *tmp = (unsigned char*)realloc(buf, next);
            if (!tmp) {
                free(buf);
                return NULL;
            }
            buf = tmp;
            cap = next;
        }
        buf[len++] = (unsigned char)c;
    }
    *out_len = len;
    return buf;
}

static int write_all_bin(FILE *fp, const unsigned char *data, size_t len)
{
    if (len == 0) return 1;
    return fwrite(data, 1, len, fp) == len;
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
    // Primeiro, define cada argumento como uma variável global
    // arg_0, arg_1, arg_2, etc.
    for (int i = 0; i < argc; i++) {
        char var_name[32];
        snprintf(var_name, sizeof(var_name), "arg_%d", i);
        vm_define_bytes(vm, var_name, argv[i]);
    }
    
    // Cria um array apenas com as referências às variáveis (sem chaves)
    char **items = (char**)malloc(sizeof(char*) * argc);
    
    for (int i = 0; i < argc; i++) {
        // Aloca a referência à variável
        items[i] = (char*)malloc(32);
        snprintf(items[i], 32, "arg_%d", i);
    }
    
    // Define o objeto args sem chaves (passa apenas valores)
    vm_define_table(vm, "args", items, argc, 0);
    
    // Libera a memória alocada
    for (int i = 0; i < argc; i++) {
        free(items[i]);
    }
    free(items);
    
    // Define argc
    char argc_str[32];
    snprintf(argc_str, sizeof(argc_str), "%d", argc);
    vm_define_bytes(vm, "argc", argc_str);
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
        if (strcmp(argv[1], "--repl") == 0) {
            return repl_run(argc, argv);
        }
        if (strcmp(argv[1], "--asm") == 0) {
            if (argc < 3) {
                fprintf(stderr, "usage: disturb --asm <input.asm> [output.bin]\n");
                return 1;
            }
            FILE *fp = fopen(argv[2], "r");
            if (!fp) {
                perror("open");
                return 1;
            }
            char *src = read_all_text(fp);
            fclose(fp);
            if (!src) {
                fprintf(stderr, "failed to read asm file\n");
                return 1;
            }
            Bytecode bc;
            char err[256] = {0};
            int ok = urb_assemble(src, &bc, err, sizeof(err));
            free(src);
            if (!ok) {
                fprintf(stderr, "assemble error: %s\n", err[0] ? err : "unknown error");
                return 1;
            }
            FILE *out = stdout;
            if (argc > 3) {
                out = fopen(argv[3], "wb");
                if (!out) {
                    perror("open");
                    bc_free(&bc);
                    return 1;
                }
            }
            if (!write_all_bin(out, bc.data, bc.len)) {
                fprintf(stderr, "failed to write bytecode\n");
                if (out != stdout) fclose(out);
                bc_free(&bc);
                return 1;
            }
            if (out != stdout) fclose(out);
            bc_free(&bc);
            return 0;
        }
        if (strcmp(argv[1], "--disasm") == 0) {
            if (argc < 3) {
                fprintf(stderr, "usage: disturb --disasm <input.bin> [output.asm]\n");
                return 1;
            }
            FILE *fp = fopen(argv[2], "rb");
            if (!fp) {
                perror("open");
                return 1;
            }
            size_t len = 0;
            unsigned char *data = read_all_bin(fp, &len);
            fclose(fp);
            if (!data) {
                fprintf(stderr, "failed to read bytecode\n");
                return 1;
            }
            FILE *out = stdout;
            if (argc > 3) {
                out = fopen(argv[3], "w");
                if (!out) {
                    perror("open");
                    free(data);
                    return 1;
                }
            }
            int ok = urb_disassemble(data, len, out);
            if (out != stdout) fclose(out);
            free(data);
            if (!ok) {
                fprintf(stderr, "disassemble error: invalid bytecode\n");
                return 1;
            }
            return 0;
        }

        VM vm;
        vm_init(&vm);
        
        // Adiciona os argumentos na VM
        vm_add_args(&vm, argc, argv);
        
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
        vm_exec_line(&vm, src);
        free(src);
        fclose(fp);
        vm_free(&vm);
    } else {
        return repl_run(argc, argv);
    }

    return 0;
}