SGX-GUEST
=======================================

Environments & Prerequisites
----------------------------
- Guest OS: Ubuntu 12.04 (will be tested with 14.04 later)

- Source Code Editing for Your Environment
in ./sgx-guest/sgx-module/sgx-module.c, please search and refer to NOTICE (related to ERROR\_ENTRY and ERROR\_EXIT)
in ./sgx-guest/sgx-module/include/sgx-module.h, please refer to NOTICE and rewrite the definition of SYS\_CALL\_TABLE, PAGE\_FAULT, and DO\_PAGE\_FAULT 


- Building and Usage
(let's assume sgx-guest is located in your (TOP) directory)

1. Building SGX-Module
   run `make` in (TOP)/sgx-guest/sgx-module

2. Building SGX-Runtime
   run `make clean` in (TOP)/sgx-guest/sgx-runtime/libsgx/musl-libc directory
   run `make clean` and `make` in (TOP)/sgx-guest/sgx-runtime/libsgx directory
   run `make clean` and `make` in (TOP)/sgx-guest/sgx-runtime directory

3. Module loading
   type `sudo insmod sgxmod.ko` in (TOP)/sgx-guest/sgx-module directory

4. Runnning Test Programs
   run `sgx-runtime ./test/simple-hello` in (TOP)/sgx-guest/sgx-runtime directory

5. Module unloading
   type `sudo rmmod sgxmod` in (TOP)/sgx-guest/sgx-module directory

