#include <stdio.h>
#include <sgx-lib.h>

int putchar(int c)
{
    sgx_stub_info *stub = (sgx_stub_info *)STUB_ADDR;

    acquire_lock(stub->lock);
    stub->fcode = FUNC_PUTCHAR;
    stub->out_arg1 = (int)c;

    sgx_exit(stub->trampoline);

    return stub->in_arg1; //cch added
}
