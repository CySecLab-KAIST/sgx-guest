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

#include <sgx.h>

#define STRING_ECREATE 0x0045544145524345
#define STRING_EADD    0x0000000044444145
#define STRING_EEXTEND 0x00444E4554584545

extern void generate_enclavehash(void *hash, void *code, int code_pages,
                                 size_t tcs);

extern void generate_einittoken_mac(einittoken_t *token, uint64_t le_tcs,
                                    uint64_t le_aep);

extern void generate_launch_key(unsigned char *device_key, unsigned char *launch_key);

extern uint8_t get_tls_npages(tcs_t *tcs);

extern void set_tcs_fields(tcs_t *tcs, size_t offset);
extern void update_tcs_fields(tcs_t *tcs, int tls_page_offset, int ssa_page_offset, int code_page_offset);

// for mac generation
void cmac(unsigned char *key, unsigned char *input, size_t bytes, unsigned char *mac);

// linked from sgx-kern
extern char *empty_page;
