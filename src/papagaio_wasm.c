#include "vm.h"
#include <stdlib.h>
#include <string.h>

#ifdef __EMSCRIPTEN__
#include <emscripten.h>
#define PAPAGAIO_KEEPALIVE EMSCRIPTEN_KEEPALIVE
#else
#define PAPAGAIO_KEEPALIVE
#endif

static VM *g_papagaio_vm = NULL;

static void papagaio_wasm_ensure_vm(void)
{
    if (!g_papagaio_vm) {
        g_papagaio_vm = (VM*)malloc(sizeof(VM));
        if (!g_papagaio_vm) return;
        vm_init(g_papagaio_vm);
    }
}

/// Initialize the papagaio runtime (optional; called automatically on first eval).
PAPAGAIO_KEEPALIVE void papagaio_wasm_init(void)
{
    papagaio_wasm_ensure_vm();
}

/// Evaluate a papagaio source string.
///
/// Returns 1 on success, 0 on error.
PAPAGAIO_KEEPALIVE int papagaio_wasm_eval(const char *src)
{
    if (!src) return 0;
    papagaio_wasm_ensure_vm();
    if (!g_papagaio_vm) return 0;
    vm_exec_line(g_papagaio_vm, src);
    return 1;
}

/// Free the papagaio runtime.
PAPAGAIO_KEEPALIVE void papagaio_wasm_free(void)
{
    if (!g_papagaio_vm) return;
    vm_free(g_papagaio_vm);
    free(g_papagaio_vm);
    g_papagaio_vm = NULL;
}
