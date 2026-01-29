#include "urb_bridge.h"
#include "vm.h"
#include "papagaio.h"

static VM *urb_bridge_vm(void)
{
    static VM vm;
    static int inited = 0;
    if (!inited) {
        vm_init(&vm);
        inited = 1;
    }
    return &vm;
}

char *urb_bridge_papagaio(const char *input, size_t len)
{
    VM *vm = urb_bridge_vm();
    return papagaio_process_text(vm, input, len);
}
