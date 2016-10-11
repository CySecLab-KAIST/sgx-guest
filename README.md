SGX-GUEST
=======================================

Environments & Prerequisites
----------------------------
- Guest OS: Ubuntu 12.04 (will be tested with 14.04 later)

- Source Code Editing for Your Environment
in ./sgx-guest/sgx-module/sgx-module.c, please search and refer to NOTICE (related to ERROR\_ENTRY and ERROR\_EXIT)
in ./sgx-guest/sgx-module/include/sgx-module.h, please refer to NOTICE and rewrite the definition of SYS\_CALL\_TABLE, PAGE\_FAULT, and DO\_PAGE\_FAULT 


- Compilation
(let's assume sgx-guest is located in your ~/)
move ~/sgx-guest/sgx-module
run make
it will create sgxmod.ko

move ~/sgx-guest/sgx-runtime/libsgx/musl-libc
run 'make clean' (whenever ./sgx-guest/share/include/sgx-shared.h is changed, I recommend repeating this procedure)
move ~/sgx-guest/sgx-runtime/libsgx
run 'make clean' and 'make'
move ~/sgx-guest/sgx-runtime
run 'make clean' and 'make'
it will create sgx-runtime

- Module loading
move ~/sgx-guest/sgx-module
type 'sudo insmod sgxmod.ko'

- Module unloading
move ~/sgx-guest/sgx-module
type 'sudo rmmod sgxmod'

 
- Run Test Programs
move ~/sgx-guest/sgx-runtime
run 'sgx-runtime ./test/simple-hello'



