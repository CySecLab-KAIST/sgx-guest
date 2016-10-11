// Hello world enclave program.
// The simplest case which uses opensgx ABI.
// See sgx/user/sgxLib.c and sgx/user/sgx-user.c for detail.

#include "test.h"

int test(int off)
{
    int ret;
    asm volatile(
      "mov %%fs:(%1), %0\n\t"
      :"=r"(ret):"r"(off));
    return ret;
}

void enclave_main()
{
    int hex = test(0);
    printf("%x = %d in hex\n", hex, hex);

    sgx_exit(NULL);
}
