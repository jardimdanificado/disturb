#include "host_io.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__EMSCRIPTEN__)
#include <emscripten.h>
#endif

// Default host I/O implementation (native filesystem).
// For WASM (Emscripten) builds, the default implementation delegates to JS via `PapagaioHost`.

static char *default_read_file(const char *path, size_t *out_len)
{
    if (!path || !out_len) return NULL;
    FILE *fp = fopen(path, "rb");
    if (!fp) return NULL;
    size_t cap = 4096;
    size_t len = 0;
    char *buf = (char*)malloc(cap);
    if (!buf) {
        fclose(fp);
        return NULL;
    }
    int c;
    while ((c = fgetc(fp)) != EOF) {
        if (len + 1 > cap) {
            size_t next = cap * 2;
            char *tmp = (char*)realloc(buf, next);
            if (!tmp) {
                free(buf);
                fclose(fp);
                return NULL;
            }
            buf = tmp;
            cap = next;
        }
        buf[len++] = (char)c;
    }
    fclose(fp);
    *out_len = len;
    return buf;
}

static int default_write_file(const char *path, const char *data, size_t len)
{
    if (!path) return 0;
    FILE *fp = fopen(path, "wb");
    if (!fp) return 0;
    size_t wrote = fwrite(data, 1, len, fp);
    fclose(fp);
    return wrote == len;
}

#if defined(__EMSCRIPTEN__)
// In Emscripten builds, delegate to JS hooks exposed as `PapagaioHost.readFile` / `writeFile`.
static char *emscripten_read_file(const char *path, size_t *out_len);
static int emscripten_write_file(const char *path, const char *data, size_t len);

EM_JS(char *, emscripten_read_file, (const char *path, size_t *out_len), {
    if (!path || !out_len) return 0;
    var s = UTF8ToString(path);
    if (typeof PapagaioHost !== "object" || typeof PapagaioHost.readFile !== "function") {
        setValue(out_len, 0, 'i32');
        return 0;
    }

    var res = PapagaioHost.readFile(s);
    if (res === null || res === undefined) {
        setValue(out_len, 0, 'i32');
        return 0;
    }

    var len = lengthBytesUTF8(res);
    var ptr = _malloc(len + 1);
    stringToUTF8(res, ptr, len + 1);
    setValue(out_len, len, 'i32');
    return ptr;
});

EM_JS(int, emscripten_write_file, (const char *path, const char *data, size_t len), {
    if (!path) return 0;
    var p = UTF8ToString(path);
    var str = data ? UTF8ToString(data, len) : "";
    if (typeof PapagaioHost !== "object" || typeof PapagaioHost.writeFile !== "function") {
        return 0;
    }
    try {
        return PapagaioHost.writeFile(p, str) ? 1 : 0;
    } catch (e) {
        return 0;
    }
});

static PapagaioHostReadFileFn g_read_fn = emscripten_read_file;
static PapagaioHostWriteFileFn g_write_fn = emscripten_write_file;
#else
static PapagaioHostReadFileFn g_read_fn = default_read_file;
static PapagaioHostWriteFileFn g_write_fn = default_write_file;
#endif

void papagaio_host_set_io_handlers(PapagaioHostReadFileFn read_fn, PapagaioHostWriteFileFn write_fn)
{
    g_read_fn = read_fn ? read_fn : (PapagaioHostReadFileFn)default_read_file;
    g_write_fn = write_fn ? write_fn : (PapagaioHostWriteFileFn)default_write_file;
}

char *papagaio_host_read_file(const char *path, size_t *out_len)
{
    return g_read_fn(path, out_len);
}

int papagaio_host_write_file(const char *path, const char *data, size_t len)
{
    return g_write_fn(path, data, len);
}
