#include "urb_bridge.h"
#include "vm.h"
#include "papagaio.h"
#include <string.h>

static VM urb_bridge_state;
static int urb_bridge_inited = 0;

static VM *urb_bridge_vm(void)
{
    if (!urb_bridge_inited) {
        vm_init(&urb_bridge_state);
        urb_bridge_inited = 1;
    }
    return &urb_bridge_state;
}

void urb_bridge_free(void)
{
    if (!urb_bridge_inited) return;
    vm_free(&urb_bridge_state);
    memset(&urb_bridge_state, 0, sizeof(urb_bridge_state));
    urb_bridge_inited = 0;
}

char *urb_bridge_papagaio(const char *input, size_t len)
{
    VM *vm = urb_bridge_vm();
    return papagaio_process_text(vm, input, len);
}
