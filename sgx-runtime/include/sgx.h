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

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// polarssl related headers
#include <polarssl/ctr_drbg.h>
#include <polarssl/entropy.h>
#include <polarssl/rsa.h>
#include <polarssl/sha1.h>
#include <polarssl/sha256.h>
#include <polarssl/aes_cmac128.h>
#include <polarssl/dhm.h>

#define OPENSGX_ABI_VERSION 1
#define SGX_USERLIB
#define NUMBER_OF_THREADS 1

#include <sgx-shared.h>
#include <sgx-dbg.h>

// round size to pages
static inline
int to_npages(int size) {
    if (size == 0)
        return 0;
    return (size - 1) / PAGE_SIZE + 1;
}

