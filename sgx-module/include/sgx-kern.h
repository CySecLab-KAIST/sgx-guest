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
#include <linux/mm.h>

typedef enum {
    MT_SECS,
    MT_TCS,
    MT_TLS,
    MT_CODE,
    MT_SSA,
    MT_STACK,
    MT_HEAP,
} mem_type_t;

static void free_keid(int keid);
extern void encls(encls_cmd_t leaf, uint64_t rbx, uint64_t rcx, uint64_t rdx, out_regs_t* out);
extern void EPA(epc_t *epc);
extern int EBLOCK(uint64_t epc_addr); 
extern int EWB(pageinfo_t *pageinfo_addr, epc_t *epc_addr, uint64_t va_slot_addr);
extern int ELDU(pageinfo_t *pageinfo_addr, epc_t *epc_addr, uint64_t va_slot_addr);
extern int follow_pte(struct mm_struct *mm, unsigned long address, pte_t **ptepp, spinlock_t **ptlp);
