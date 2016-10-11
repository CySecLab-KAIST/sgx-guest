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

// hello world

#include "test.h"


void enclave_main()
{
    sgx_stub_info *stub = (sgx_stub_info *)STUB_ADDR;

    printf("before trampoline\n");
    stub->fcode = FUNC_RESTRICT; 
    stub->out_arg1 = 7 ; // the order of target EPC for restricting permission
    stub->out_arg2 = 0 ; // read permission     4 
                         // write permission    2
                         // ecution permission  1
    sgx_exit(stub->trampoline);
    printf("after trampoline: %d\n", stub->in_arg1);
    
    sgx_exit(NULL);
}
