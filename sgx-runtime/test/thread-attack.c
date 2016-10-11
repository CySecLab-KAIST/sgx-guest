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

// The simplest enclave enter/exit with stack.
// With -O3 option, the enclave_main() doesn't do anything
// because of code optimization. For testing this, please remove -O3 option.

#include "test.h"

void thread_main()
{
    int *secret_key_addr = 0x50003fcc;
    printf("secret_key leak : %d, 0x%x\n", *secret_key_addr, secret_key_addr); 

    sgx_exit(NULL);
}

void enclave_main()
{

    int secret_key = 1234;
    printf("secret_key : %d, 0x%x\n", secret_key, &secret_key); 

    sgx_exit(NULL);
}
