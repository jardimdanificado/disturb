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
    puts("  disturb [options] [script.urb|script.md] [args...]");
    puts("  disturb --compile-bytecode script.urb|script.md output.bytecode");
    puts("  disturb --run-bytecode output.bytecode [args...]");
    puts("  disturb --md-extract script.md [output.urb]");
    puts("  disturb --markdown script [args...]   (force markdown mode)");
    puts("  disturb --help");
    puts("");
    puts("notes:");
    puts("  .md files are detected automatically and code fences are extracted.");
    puts("  asm/disasm are available in examples/asm_lib.urb.");
}

/* ---------------------------------------------------------------------------
 * Markdown fence extractor (CommonMark 4.5 compliant)
 * Returns a heap-allocated string with the extracted Disturb source, or NULL.
 * The caller must free() it.
 * --------------------------------------------------------------------------*/

static int md__is_ws(char c)
{
    return c == ' ' || c == '\t' || c == '\r';
}

static int md__count_leading_spaces(const char *line, int len)
{
    int i = 0;
    while (i < len && line[i] == ' ') i++;
    return i;
}

static int md__all_ws_from(const char *line, int start, int len)
{
    for (int i = start; i < len; i++) {
        if (!md__is_ws(line[i])) return 0;
    }
    return 1;
}

/* Parses a fence line. Returns 1 if fence; fills out_indent, out_ch, out_run. */
static int md__parse_fence(const char *line, int len,
                            int *out_indent, char *out_ch, int *out_run)
{
    int indent = md__count_leading_spaces(line, len);
    if (indent > 3) return 0;
    if (indent >= len) return 0;

    char ch = line[indent];
    if (ch != '`' && ch != '~') return 0;

    int run = 0;
    while (indent + run < len && line[indent + run] == ch) run++;
    if (run < 3) return 0;

    /* Backtick fence: info string must not contain a backtick */
    if (ch == '`') {
        for (int i = indent + run; i < len; i++) {
            if (line[i] == '`') return 0;
        }
    }

    *out_indent = indent;
    *out_ch     = ch;
    *out_run    = run;
    return 1;
}

static char *md_extract_urb(const char *md_source)
{
    /* Working buffer for output */
    size_t out_cap = 4096;
    size_t out_len = 0;
    char *out = (char*)malloc(out_cap);
    if (!out) return NULL;
    out[0] = '\0';

    int in_fence    = 0;
    char fence_ch   = 0;
    int  fence_run  = 0;
    int  fence_ind  = 0;

    const char *p = md_source;
    while (*p) {
        /* Find end of line */
        const char *nl = p;
        while (*nl && *nl != '\n') nl++;

        int raw_len = (int)(nl - p);
        /* Strip trailing CR */
        int line_len = raw_len;
        if (line_len > 0 && p[line_len - 1] == '\r') line_len--;

        /* Parse potential fence */
        int f_indent = 0; char f_ch = 0; int f_run = 0;
        int is_fence = md__parse_fence(p, line_len, &f_indent, &f_ch, &f_run);

        if (!in_fence) {
            if (is_fence) {
                in_fence   = 1;
                fence_ch   = f_ch;
                fence_run  = f_run;
                fence_ind  = f_indent;
            }
            /* skip non-fence lines outside a block */
        } else {
            /* Check for closing fence */
            if (is_fence && f_ch == fence_ch && f_run >= fence_run) {
                int close_pos = f_indent + f_run;
                if (md__all_ws_from(p, close_pos, line_len)) {
                    in_fence = 0;
                    fence_ch = 0; fence_run = 0; fence_ind = 0;
                    /* consume newline and continue */
                    if (*nl == '\n') nl++;
                    p = nl;
                    continue;
                }
            }

            /* Content line: strip up to fence_ind leading spaces */
            const char *content = p;
            int content_len = line_len;
            int stripped = 0;
            while (stripped < fence_ind && stripped < content_len &&
                   content[stripped] == ' ') {
                stripped++;
            }
            content     += stripped;
            content_len -= stripped;

            /* Ensure capacity: content + '\n' + '\0' */
            size_t need = out_len + (size_t)content_len + 2;
            if (need > out_cap) {
                while (out_cap < need) out_cap *= 2;
                char *tmp = (char*)realloc(out, out_cap);
                if (!tmp) { free(out); return NULL; }
                out = tmp;
            }
            memcpy(out + out_len, content, (size_t)content_len);
            out_len += (size_t)content_len;
            out[out_len++] = '\n';
            out[out_len]   = '\0';
        }

        if (*nl == '\n') nl++;
        p = nl;
    }

    return out;
}

/* Returns 1 if path ends with .md or .MD */
static int path_is_markdown(const char *path)
{
    size_t n = strlen(path);
    if (n < 3) return 0;
    return (path[n-3] == '.' &&
            (path[n-2] == 'm' || path[n-2] == 'M') &&
            (path[n-1] == 'd' || path[n-1] == 'D'));
}

/* Reads a file path, returns heap-allocated text or NULL */
static char *read_file_text(const char *path)
{
    FILE *fp = fopen(path, "r");
    if (!fp) { perror(path); return NULL; }
    char *src = read_all_text(fp);
    fclose(fp);
    return src;
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
    
    // Define argc como um inteiro escalar
    snprintf(var_name, sizeof(var_name), "%d", argc);
    {
        char *argc_items[1] = { var_name };
        vm_define_number(vm, "argc", argc_items, 1, 0);
    }
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

    char *src = read_file_text(path);
    if (!src) {
        vm_free(&vm);
        return 1;
    }

    strip_shebang(src);
    vm_exec_line(&vm, src);
    free(src);
    vm_free(&vm);
    return 0;
}

static int run_markdown_script(const char *path, int script_argc, char **script_argv)
{
    char *md_src = read_file_text(path);
    if (!md_src) return 1;

    char *urb_src = md_extract_urb(md_src);
    free(md_src);
    if (!urb_src) {
        fprintf(stderr, "disturb: failed to extract code from %s\n", path);
        return 1;
    }

    VM vm;
    vm_init(&vm);
    vm_add_args(&vm, script_argc, script_argv);
    vm_exec_line(&vm, urb_src);
    free(urb_src);
    vm_free(&vm);
    return 0;
}

static int compile_bytecode_file(const char *src_path, const char *out_path)
{
    VM vm;
    vm_init(&vm);

    char *raw = read_file_text(src_path);
    if (!raw) {
        vm_free(&vm);
        return 1;
    }

    char *src;
    if (path_is_markdown(src_path)) {
        src = md_extract_urb(raw);
        free(raw);
        if (!src) {
            fprintf(stderr, "disturb: failed to extract code from %s\n", src_path);
            vm_free(&vm);
            return 1;
        }
    } else {
        src = raw;
        strip_shebang(src);
    }

    Bytecode bc;
    char err[256];
    err[0] = 0;
    if (!vm_compile_source_with_vm(&vm, src, &bc, err, sizeof(err))) {
        fprintf(stderr, "%s\n", err[0] ? err : "compile error");
        free(src);
        vm_free(&vm);
        return 1;
    }
    FILE *out = fopen(out_path, "wb");
    if (!out) {
        perror("open");
        bc_free(&bc);
        free(src);
        vm_free(&vm);
        return 1;
    }
    size_t wrote = fwrite(bc.data, 1, bc.len, out);
    if (wrote != bc.len) {
        fprintf(stderr, "failed to write bytecode\n");
        bc_free(&bc);
        free(src);
        fclose(out);
        vm_free(&vm);
        return 1;
    }
    fclose(out);
    bc_free(&bc);
    free(src);
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

    /* --markdown / -md : force markdown mode for the next file argument */
    if (strcmp(cmd, "--markdown") == 0 || strcmp(cmd, "-md") == 0) {
        argi++;
        if (argc <= argi) {
            fprintf(stderr, "disturb: --markdown requires a file argument\n");
            return 1;
        }
        const char *md_path = argv[argi];
        int script_argc = argc - (argi + 1);
        char **script_argv = argv + argi + 1;
        return run_markdown_script(md_path, script_argc, script_argv);
    }

    /* --md-extract file.md [output.urb] */
    if (strcmp(cmd, "--md-extract") == 0) {
        argi++;
        if (argc <= argi) {
            fprintf(stderr, "usage: disturb --md-extract script.md [output.urb]\n");
            return 1;
        }
        const char *md_path = argv[argi];
        char *md_src = read_file_text(md_path);
        if (!md_src) return 1;
        char *urb_src = md_extract_urb(md_src);
        free(md_src);
        if (!urb_src) {
            fprintf(stderr, "disturb: failed to extract code from %s\n", md_path);
            return 1;
        }

        if (argc > argi + 1) {
            /* Write to output file */
            const char *out_path = argv[argi + 1];
            FILE *fp = fopen(out_path, "w");
            if (!fp) {
                perror(out_path);
                free(urb_src);
                return 1;
            }
            fputs(urb_src, fp);
            fclose(fp);
            fprintf(stderr, "disturb: extracted to %s\n", out_path);
        } else {
            /* Derive output path: replace .md with .urb */
            size_t plen = strlen(md_path);
            char *out_path;
            if (plen > 3 &&
                (md_path[plen-3] == '.') &&
                (md_path[plen-2] == 'm' || md_path[plen-2] == 'M') &&
                (md_path[plen-1] == 'd' || md_path[plen-1] == 'D')) {
                out_path = (char*)malloc(plen + 2);
                memcpy(out_path, md_path, plen - 2);
                strcpy(out_path + plen - 2, "urb");
            } else {
                out_path = (char*)malloc(plen + 5);
                memcpy(out_path, md_path, plen);
                strcpy(out_path + plen, ".urb");
            }
            FILE *fp = fopen(out_path, "w");
            if (!fp) {
                perror(out_path);
                free(urb_src);
                free(out_path);
                return 1;
            }
            fputs(urb_src, fp);
            fclose(fp);
            fprintf(stderr, "disturb: extracted to %s\n", out_path);
            free(out_path);
        }
        free(urb_src);
        return 0;
    }

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

    /* Auto-detect .md extension */
    if (path_is_markdown(cmd)) {
        return run_markdown_script(cmd, script_argc, script_argv);
    }
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
