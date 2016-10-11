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

// An enclave test case for x87 FPU floating-point exception(MF).
// It will raise fpu raise exception.

#include "test.h"

void enclave_main()
{
    float f = 1.0;
    int g = 0;
    float h;

    __asm__ __volatile__ ("fld %0" ::"m" (f));
    __asm__ __volatile__ ("fidiv %0" ::"m" (g));
    __asm__ __volatile__ ("fst %0" :"=m" (h):);
    __asm__ __volatile__ ("fwait" ::);

    (void)&h;

    sgx_exit(NULL);
}
