#include "vm.h"

#include <stdio.h>
#include <string.h>

static void strip_comments(char *line)
{
    char *hash = strchr(line, '#');
    char *slash = strstr(line, "//");
    char *cut = NULL;

    if (hash && slash) {
        cut = hash < slash ? hash : slash;
    } else if (hash) {
        cut = hash;
    } else if (slash) {
        cut = slash;
    }

    if (cut) *cut = 0;
}

static void vm_run_file(VM *vm, FILE *fp)
{
    char buf[4096];
    while (fgets(buf, sizeof(buf), fp)) {
        strip_comments(buf);
        size_t len = strlen(buf);
        while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r')) {
            buf[--len] = 0;
        }
        if (len == 0) continue;
        vm_exec_line(vm, buf);
    }
}

int main(int argc, char **argv)
{
    VM vm;
    vm_init(&vm);

    if (argc > 1) {
        FILE *fp = fopen(argv[1], "r");
        if (!fp) {
            perror("open");
            return 1;
        }
        vm_run_file(&vm, fp);
        fclose(fp);
    } else {
        puts("urb vm (type 'dump' or 'gc')");
        vm_run_file(&vm, stdin);
    }

    vm_free(&vm);
    return 0;
}
