#include "time_impl.h"
#include <errno.h>

#include <string.h>
#include <sgx-lib.h>

struct tm *gmtime(const time_t *t)
{
    sgx_stub_info *stub = (sgx_stub_info *)STUB_ADDR;
    struct tm temp_tm;

    acquire_lock(stub->lock);
    stub->fcode = FUNC_GMTIME;
    //stub->out_arg4 = *t; cch: comment should be removed later 

    sgx_exit(stub->trampoline);
    //memcpy(&temp_tm, &stub->in_tm, sizeof(struct tm)); cch: comment sholud be removed later

    return &temp_tm;
}
