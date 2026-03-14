#include "vm.h"
#include <stdlib.h>
#include <string.h>

#ifdef __EMSCRIPTEN__
#include <emscripten.h>
#define DISTURB_KEEPALIVE EMSCRIPTEN_KEEPALIVE
#else
#define DISTURB_KEEPALIVE
#endif

static VM *g_disturb_vm = NULL;

static void disturb_wasm_ensure_vm(void)
{
    if (!g_disturb_vm) {
        g_disturb_vm = (VM*)malloc(sizeof(VM));
        if (!g_disturb_vm) return;
        vm_init(g_disturb_vm);
    }
}

/// Initialize the Disturb runtime (optional; called automatically on first eval).
DISTURB_KEEPALIVE void disturb_wasm_init(void)
{
    disturb_wasm_ensure_vm();
}

/// Evaluate a Disturb source string.
///
/// Returns 1 on success, 0 on error.
DISTURB_KEEPALIVE int disturb_wasm_eval(const char *src)
{
    if (!src) return 0;
    disturb_wasm_ensure_vm();
    if (!g_disturb_vm) return 0;
    vm_exec_line(g_disturb_vm, src);
    return 1;
}

/// Free the Disturb runtime.
DISTURB_KEEPALIVE void disturb_wasm_free(void)
{
    if (!g_disturb_vm) return;
    vm_free(g_disturb_vm);
    free(g_disturb_vm);
    g_disturb_vm = NULL;
}
