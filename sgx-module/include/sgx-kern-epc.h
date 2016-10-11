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

#define SGX_KERNEL
#include <sgx.h>
#include <linux/mm.h>
#include <linux/list.h>

#define VAID    2222 //cch: temp
#define EPC_MIN 128 //cch: test value 485
#define VA_SLOT_SIZE 8
#define NR_VA_SLOT 512
#define NR_EVICT_PAGES 16 

// cch: EPC_ADDR will be dynamically allocated in anonymous address

// linear address is in fact just addr of epc page (physical page)
static inline
void* epc_to_vaddr(epc_t *epc) {
    return epc;
}

typedef struct {
    uint64_t val;
} va_entry_t;

typedef enum {
    FREE_PAGE = 0x0,
    SECS_PAGE = 0x1,
    TCS_PAGE  = 0x2,
    REG_PAGE  = 0x3,
    VA_PAGE   = 0x4,
    RESERVED  = 0x5
} epc_type_t;

typedef enum {
    FREE_SLOT = 0x0,
    USED_SLOT = 0x1
}va_type_t;

typedef struct {
    int key;
    epc_type_t type;
    struct mm_struct *mm; //cch test
    uint64_t linaddr; //cch test
    pgprot_t pgprot; //cch test
} epc_info_t;

typedef struct {
    va_type_t type;
    epc_type_t epc_type;
    int keid;
    pgprot_t pgprot;
    uint64_t linaddr;
    uint64_t target_addr;
    pcmd_t *pcmd_addr;
    epc_t *secs;
#ifdef THREAD_PROTECTION
    epc_t *tcs;
#endif
} va_info_slot_t; 

typedef struct {
    epc_t *va_addr;
    va_info_slot_t slot[512];
    struct list_head va_info_list;
} va_info_t;

// exported

extern struct kmem_cache *pageinfo_cache;
extern struct kmem_cache *epc_t_cache;
extern struct kmem_cache *pcmd_cache;
extern struct list_head va_info_head;

extern void init_epc(int nepc);
extern void free_epc(void);

extern epc_t *get_epc(int key, epc_type_t pt);
extern epc_t *get_epc_region_beg(void);
extern epc_t *get_epc_region_end(void);
extern epc_t *alloc_epc_pages(int npages, int key);
extern epc_t **reserve_epc_pages(int npages, int key);
extern epc_t *alloc_epc_page(int key);
extern void free_epc_pages(int key);
extern int handle_fault_with_eld(uint64_t va_slot_addr, struct list_head *head, pte_t **ptepp);

extern void dbg_dump_epc(void);
extern int find_epc_type(void *addr);
static int find_epc_keid(void *addr);
static epc_t *find_epc_secs(void *addr);
#ifdef THREAD_PROTECTION
static epc_t *find_epc_tcs(void *addr);
#endif
extern void free_reserved_epc_pages(int key);

#ifdef THREAD_PROTECTION
static int use_va_info_slot(int keid, epc_type_t epc_type, uint64_t va_slot_addr, pgprot_t pgprot, uint64_t linaddr, uint64_t page_to_store, pcmd_t *pcmd_addr, epc_t *secs, epc_t *tcs, struct list_head *head);
#else
static int use_va_info_slot(int keid, epc_type_t epc_type, uint64_t va_slot_addr, pgprot_t pgprot, uint64_t linaddr, uint64_t page_to_store, pcmd_t *pcmd_addr, epc_t *secs, struct list_head *head);
#endif
static void free_va_info_slot(va_info_slot_t *va_info_slot);
extern int put_epc(epc_t *epc);
extern epc_t *find_epc(int key);

void save_linaddr_epc_info(epc_t *epc, struct mm_struct *mm, uint64_t linaddr, pgprot_t pgprot);
void restore_linaddr_epc_info(epc_t *epc, struct mm_struct **mm_p, uint64_t *linaddr_p, pgprot_t *pgprot_p);

#define VA_ADDRESS_MASK  0xFFFFFFFFFFFFF000
#define VA_OFFSET_MASK   0x1FF

static inline va_entry_t va_entry(uint64_t va_address, int index)
{
    // address 52bit | magic(11) 2bit | index 9bit | present 1bit
    va_entry_t ret;
    ret.val = (va_address & VA_ADDRESS_MASK) | 0xC00 | ((index & VA_OFFSET_MASK) << 1 );
    return ret;
}

#define __va_entry_to_pte(x)     ((pte_t) { .pte = (x).val })

static inline pte_t va_entry_to_pte(va_entry_t entry)
{
    return __va_entry_to_pte(entry);
}

#define __pte_to_va_entry(pte)         ((va_entry_t) { (pte).pte }) //cch: need to be reexamined

static inline va_entry_t pte_to_va_entry(pte_t pte)
{
    va_entry_t va_entry = __pte_to_va_entry(pte);
    return va_entry;
}

static inline bool is_va_entry(va_entry_t va_entry)
{
    unsigned long magic = 0xC00;
    return ((va_entry.val & magic) == magic);
}

static inline uint64_t va_address(va_entry_t va_entry)
{
    uint64_t va_address;
    va_address = va_entry.val & VA_ADDRESS_MASK;
    return va_address;
}

static inline int va_index(va_entry_t va_entry)
{
    int index;
    index = (va_entry.val >> 1) & VA_OFFSET_MASK;
    return index;
}
