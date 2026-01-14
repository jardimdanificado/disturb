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

int main(int argc, char **argv)
{
    if (argc > 1) {
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
        VM vm;
        vm_init(&vm);
        char *src = read_all_text(stdin);
        if (!src) {
            fprintf(stderr, "failed to read stdin\n");
            vm_free(&vm);
            return 1;
        }
        vm_exec_line(&vm, src);
        free(src);
        vm_free(&vm);
    }

    return 0;
}
