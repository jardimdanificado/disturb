#include "vm.h"

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


static void strip_shebang(char *src)
{
    if (!src) return;
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
}

static unsigned char *read_all_bytes(FILE *fp, size_t *out_len)
{
    size_t cap = 4096;
    size_t len = 0;
    unsigned char *buf = (unsigned char*)malloc(cap);
    if (!buf) return NULL;

    while (1) {
        if (len == cap) {
            size_t next = cap * 2;
            unsigned char *tmp = (unsigned char*)realloc(buf, next);
            if (!tmp) {
                free(buf);
                return NULL;
            }
            buf = tmp;
            cap = next;
        }
        size_t want = cap - len;
        size_t got = fread(buf + len, 1, want, fp);
        if (got == 0) {
            if (feof(fp)) break;
            if (ferror(fp)) {
                free(buf);
                return NULL;
            }
            break;
        }
        len += got;
    }

    if (out_len) *out_len = len;
    return buf;
}


static void print_help(void)
{
    puts("usage:");
    puts("  disturb [script.urb] [args...]");
    puts("  disturb --compile-bytecode script.urb output.bytecode");
    puts("  disturb --run-bytecode output.bytecode [args...]");
    puts("  disturb --help");
    puts("");
    puts("notes:");
    puts("  asm/disasm are available in example/asm_lib.urb.");
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

static int run_disturb_script(const char *path, int script_argc, char **script_argv)
{
    VM vm;
    vm_init(&vm);
    vm_add_args(&vm, script_argc, script_argv);

    FILE *fp = fopen(path, "r");
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

    strip_shebang(src);
    vm_exec_line(&vm, src);
    free(src);
    fclose(fp);
    vm_free(&vm);
    return 0;
}

static int compile_bytecode_file(const char *src_path, const char *out_path)
{
    VM vm;
    vm_init(&vm);

    FILE *fp = fopen(src_path, "r");
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
    strip_shebang(src);

    Bytecode bc;
    char err[256];
    err[0] = 0;
    if (!vm_compile_source_with_vm(&vm, src, &bc, err, sizeof(err))) {
        fprintf(stderr, "%s\n", err[0] ? err : "compile error");
        free(src);
        fclose(fp);
        vm_free(&vm);
        return 1;
    }
    FILE *out = fopen(out_path, "wb");
    if (!out) {
        perror("open");
        bc_free(&bc);
        free(src);
        fclose(fp);
        vm_free(&vm);
        return 1;
    }
    size_t wrote = fwrite(bc.data, 1, bc.len, out);
    if (wrote != bc.len) {
        fprintf(stderr, "failed to write bytecode\n");
        bc_free(&bc);
        free(src);
        fclose(fp);
        fclose(out);
        vm_free(&vm);
        return 1;
    }
    fclose(out);
    bc_free(&bc);
    free(src);
    fclose(fp);
    vm_free(&vm);
    return 0;
}

static int run_bytecode_file(const char *path, int script_argc, char **script_argv)
{
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        perror("open");
        return 1;
    }
    size_t len = 0;
    unsigned char *data = read_all_bytes(fp, &len);
    fclose(fp);
    if (!data) {
        fprintf(stderr, "failed to read bytecode file\n");
        return 1;
    }
    VM vm;
    vm_init(&vm);
    vm_add_args(&vm, script_argc, script_argv);
    int ok = vm_exec_bytecode(&vm, data, len);
    vm_free(&vm);
    int result = ok ? 0 : 1;
    free(data);
    return result;
}

static int disturb_main(int argc, char **argv)
{
    if (argc <= 1) {
        return repl_run(argc, argv);
    }
    if (strcmp(argv[1], "--repl") == 0) {
        return repl_run(argc, argv);
    }
    if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
        print_help();
        return 0;
    }

    int argi = 1;
    if (argc <= argi) {
        fprintf(stderr, "disturb expects a source or bytecode file\n");
        return 1;
    }

    const char *cmd = argv[argi];
    if (strcmp(cmd, "--compile-bytecode") == 0) {
        if (argc - argi < 3) {
            fprintf(stderr, "usage: disturb --compile-bytecode script.urb output.bytecode\n");
            return 1;
        }
        return compile_bytecode_file(argv[argi + 1], argv[argi + 2]);
    }
    if (strcmp(cmd, "--run-bytecode") == 0) {
        if (argc - argi < 2) {
            fprintf(stderr, "disturb expects a bytecode file\n");
            return 1;
        }
        const char *bytecode_path = argv[argi + 1];
        int script_argc = argc - (argi + 2);
        char **script_argv = argv + argi + 2;
        return run_bytecode_file(bytecode_path, script_argc, script_argv);
    }

    int script_argc = argc - (argi + 1);
    char **script_argv = argv + argi + 1;
    return run_disturb_script(cmd, script_argc, script_argv);
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IOFBF, 1 << 20);
    int code = disturb_main(argc, argv);
    fflush(stdout);
    setvbuf(stdout, NULL, _IONBF, 0);
    return code;
}
