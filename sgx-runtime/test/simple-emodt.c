/*
 *  Copyright (C) 2015, OpenSGX team, Georgia Tech & KAIST, All Rights Reserved
 *
 *  This file is part of OpenSGX (https://github.com/sslab-gatech/opensgx).
 *
 *  OpenSGX is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  OpenSGX is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with OpenSGX.  If not, see <http://www.gnu.org/licenses/>.
 */

// YOU HAVE TO INITIALIZE SGXMODULE BEFORE EXECUTING THIS TEST
// BY USING THE FOLLOWING COMMANDS.
//   sudo rmmod sgxmod
//   sudo insmod sgxmod.ko


#include "test.h"

void enclu(enclu_cmd_t leaf, uint64_t rbx, uint64_t rcx, uint64_t rdx,
           out_regs_t *out_regs)
{
   printf( "before enclu\n\n");
   out_regs_t tmp;
   asm volatile(".byte 0x0F\n\t"
                ".byte 0x01\n\t"
                ".byte 0xd7\n\t"
                :"=a"(tmp.oeax),
                 "=b"(tmp.orbx),
                 "=c"(tmp.orcx),
                 "=d"(tmp.ordx)
                :"a"((uint32_t)leaf),
                 "b"(rbx),
                 "c"(rcx),
                 "d"(rdx)
                :"memory");

    // Check whether function requires out_regs
    if (out_regs != NULL) {
        asm volatile ("" : : : "memory"); // Compile time Barrier
        asm volatile ("movl %%eax, %0\n\t"
            "movq %%rbx, %1\n\t"
            "movq %%rcx, %2\n\t"
            "movq %%rdx, %3\n\t"
            :"=a"(out_regs->oeax),
             "=b"(out_regs->orbx),
             "=c"(out_regs->orcx),
             "=d"(out_regs->ordx));
    }
    printf( "after enclu\n\n");
}


void enclave_main()
{
    int i;
    sgx_stub_info *stub = (sgx_stub_info *)STUB_ADDR;

    // secinfo setting for EAUG
    secinfo_t *secinfo = memalign( SECINFO_ALIGN_SIZE, sizeof(secinfo_t));
    secinfo->flags.r = 1;
    secinfo->flags.w = 1;
    secinfo->flags.x = 0;
    secinfo->flags.pending = 1;
    secinfo->flags.modified = 0;
    secinfo->flags.reserved1 = 0;
    secinfo->flags.page_type = PT_REG;
    for (i=0 ; i<6; i++) {
        secinfo->flags.reserved2[i] = 0;
    }
     
    printf("before trampoline for EAUG\n\n");

    // EAUG  
    stub->fcode = FUNC_AUG; 
    sgx_exit(stub->trampoline);

    // handling pending page 
    unsigned long pending_page = stub->pending_page; 
    out_regs_t out; 
    enclu( ENCLU_EACCEPT, (uint64_t)secinfo, (uint64_t)pending_page, 0, &out); 
    if (out.oeax != 0 ) {  // error occurred in EACCEPT 
        printf("error occurred in EACCEPT\n");
        return NULL;
    }

    printf("after trampoline for EAUG\n\n");

    // secinfo setting for EMODT
    secinfo = memalign( SECINFO_ALIGN_SIZE, sizeof(secinfo_t));
    secinfo->flags.r = 0;
    secinfo->flags.w = 0;
    secinfo->flags.x = 0;
    secinfo->flags.pending = 0;
    secinfo->flags.modified = 1;
    secinfo->flags.reserved1 = 0;
    secinfo->flags.page_type = PT_TCS;
    for (i=0 ; i<6; i++) {
        secinfo->flags.reserved2[i] = 0;
    }

    // change EPC contents for changing from PT_REG to PT_TCS 
    tcs_t *tcs_epc = pending_page;
    tcs_epc->nssa = 1; 
    tcs_epc->fslimit = 0x0FFF; 
    tcs_epc->gslimit = 0x0FFF; 

    printf("before trampoline for EMODT\n\n");

    //acquire_lock( stub->lock );
    stub->fcode = FUNC_TYPE; 
    stub->out_arg1 = pending_page ;      // address of target EPC for changing type
    stub->out_arg2 = PT_TCS ;  // the type of EPC ( PT_TCS or PT_TRIM is possible, refer SGX documents ) 
    sgx_exit(stub->trampoline);

    // handling pending page 
    pending_page = stub->pending_page; 
    enclu( ENCLU_EACCEPT, (uint64_t)secinfo, (uint64_t)pending_page, 0, &out); 
    if (out.oeax != 0 ) {  // error occurred in EACCEPT 
        printf("error occurred in EACCEPT\n");
        return NULL;
    }

    printf("after trampoline for EMODT\n\n");

    sgx_exit(NULL);
}
