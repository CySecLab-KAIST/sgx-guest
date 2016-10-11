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


#include <sgx-kern-epc.h>
#include <sgx-kern.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/vmalloc.h> // blueguy : to avoid compile error
#include <linux/list.h>
#include <linux/sched.h>
#include <linux/spinlock.h>

//
// NOTE.
//   bitmap can contain more useful info (e.g., eid, contiguous region &c)
//
static epc_t *g_epc;
static epc_info_t *g_epc_info;
static int g_num_epc;
static int g_num_remaining;
static spinlock_t epc_lock;
static spinlock_t va_info_lock;
static spinlock_t paging_lock;
LIST_HEAD(va_info_head);

static
void reserve_va_pages(int npages){
    int vaid = VAID;
    epc_t **va_pages = reserve_epc_pages(npages, vaid);
    if( va_pages == NULL){
        //error
    }
}

static
void invoke_epa(epc_t *va){
    if(va != NULL){
        EPA(va);
    }
}

static
int invoke_eblock(epc_t *epc_to_evict){
    int ret = -1;
    if(epc_to_evict != NULL){
        ret = EBLOCK(epc_to_evict);
    }
    return ret;
}

static
int invoke_ewb(epc_t *epc_to_evict, uint64_t va_slot_addr){
    int ret = 0;
    int keid;
    epc_type_t epc_type;
    epc_t *secs;
#ifdef THREAD_PROTECTION
    epc_t *tcs;
#endif

    epc_type = find_epc_type(epc_to_evict);
    keid = find_epc_keid(epc_to_evict);
    // get secs from epc_to_evict
    secs = find_epc_secs(epc_to_evict);
#ifdef THREAD_PROTECTION
    tcs = find_epc_tcs(epc_to_evict);
#endif

    pageinfo_t *pageinfo = kmem_cache_alloc(pageinfo_cache, GFP_KERNEL); 
    if (!pageinfo) {
        printk("failed to allocate pageinfo");
        return 0;
    }    

    char *page_to_store = (char *)kmem_cache_alloc(epc_t_cache, GFP_KERNEL);
    if (!page_to_store) {
        printk("failed to allocate page_to_store");
        return 0;
    }    

    pcmd_t *pcmd = (char *)kmem_cache_alloc(pcmd_cache, GFP_KERNEL);
    if (!pcmd) {
        printk("failed to allocate pcmd");
        return 0;
    }    

    pageinfo->linaddr = 0; 
    pageinfo->srcpge  = page_to_store; 
    pageinfo->pcmd    = pcmd; 
    pageinfo->secs    = 0;
#ifdef THREAD_PROTECTION
    pageinfo->tcs     = 0;
#endif

    EWB(pageinfo, epc_to_evict, va_slot_addr);

    uint64_t linaddr = 0;
    struct mm_struct *mm;
    pgprot_t pgprot;
    uint64_t va_addr = va_slot_addr & VA_ADDRESS_MASK;
    int va_index = (va_slot_addr - va_addr) / VA_SLOT_SIZE;
    spinlock_t *ptl;
    pte_t *ptep;
    //cch: get linaddr from epc_to_evict
    restore_linaddr_epc_info(epc_to_evict, &mm, &linaddr, &pgprot);
    sgx_dbg(kern, "linaddr for epc_to_evict is %p", linaddr); 
#ifdef THREAD_PROTECTION
    ret = use_va_info_slot(keid, epc_type, va_slot_addr, pgprot, linaddr, page_to_store, pcmd, secs, tcs, &va_info_head);
#else
    ret = use_va_info_slot(keid, epc_type, va_slot_addr, pgprot, linaddr, page_to_store, pcmd, secs, &va_info_head);
#endif

    ret = follow_pte(mm, linaddr, &ptep, &ptl);
    if(ret){
        sgx_dbg(kern, "follow_pte failed and ret is %d", ret);
        return 0;
    }
    va_entry_t va_pte = va_entry(va_addr, va_index);
    sgx_dbg(kern, "va_slot_addr is %p, va_addr is %p, va_index is %d", 
            va_slot_addr, va_addr, va_index);
    sgx_dbg(kern, "va_entry_t is %p", va_pte.val);
    set_pte(ptep, va_entry_to_pte(va_pte));
    pte_unmap_unlock(ptep, ptl);

    kmem_cache_free(pageinfo_cache, pageinfo); //cch: page_to_store and pcmd should be freed after ELDB/U 

    return 1;
}

static
int invoke_eld(epc_t *epc_to_load, va_info_slot_t *va_slot_info, uint64_t va_slot_addr){

    pageinfo_t *pageinfo = kmem_cache_alloc(pageinfo_cache, GFP_KERNEL);
    if (!pageinfo) {
        sgx_dbg(kern, "failed to allocate pageinfo");
        return 0;
    }
    
    memset(pageinfo, 0, sizeof(pageinfo_t));

    if(va_slot_info->type == FREE_SLOT) {
        sgx_dbg(kern, "va_slot_info is free");
        return 0;
    }
    pageinfo->linaddr = va_slot_info->linaddr; //cch: should this be passed as a parameter?
    pageinfo->srcpge  = va_slot_info->target_addr;
    pageinfo->pcmd    = va_slot_info->pcmd_addr;
    pageinfo->secs    = va_slot_info->secs; //cch: should this be passed as a parameter?
#ifdef THREAD_PROTECTION
    pageinfo->tcs     = va_slot_info->tcs; 
#endif
    sgx_dbg(kern, "pageinfo->linaddr is %p", pageinfo->linaddr);

    //TODO: ELDU return value check
    ELDU(pageinfo, epc_to_load, va_slot_addr);

    kmem_cache_free(pageinfo_cache, pageinfo); 
    kmem_cache_free(pcmd_cache, va_slot_info->pcmd_addr);
    kmem_cache_free(epc_t_cache, va_slot_info->target_addr);

    return 1;
}

static
void add_va_info_node(epc_t *va_addr, struct list_head *head){
    va_info_t *va_info_p = (va_info_t *)vmalloc(sizeof(va_info_t));
    memset(va_info_p, 0, sizeof(va_info_t));

    va_info_p->va_addr = va_addr;
    INIT_LIST_HEAD(&va_info_p->va_info_list);
    spin_lock(&va_info_lock);
    list_add(&va_info_p->va_info_list, head);
    spin_unlock(&va_info_lock);
}

static
va_info_t *find_va_info(epc_t *va_addr, struct list_head *head){
    struct list_head *iter;
    va_info_t *obj_p;
    
    list_for_each(iter, head) {
        obj_p = list_entry(iter, va_info_t, va_info_list);
        if (obj_p->va_addr == va_addr){
            return obj_p; 
        }
    }
    return NULL;
}

extern int handle_fault_with_eld(uint64_t va_slot_addr, struct list_head *head, pte_t **ptepp){
    va_info_t *va_info;
    va_info_slot_t *va_info_slot;
    epc_t *va_addr;
    epc_t *empty_epc;
    uint64_t offset;
    uint64_t linaddr;
    uint64_t epc_phys_addr;
    pgprot_t pgprot;
    int keid;
    int index;
    int ret;
    epc_type_t epc_type;

    va_addr = va_slot_addr & (uint64_t)(~(0xFFF));
    offset = va_slot_addr - (uint64_t)va_addr;
    index = offset / VA_SLOT_SIZE;
    va_info = find_va_info(va_addr, head);

    if (va_info == NULL){
        sgx_dbg(kern, "va_info is NULL");
        return 0;
    }
    else{
        va_info_slot = &(va_info->slot[index]);
        if (va_info_slot->type == FREE_SLOT){
            sgx_dbg(kern, "type in va_info_slot is FREE_SLOT");
            return 0;
        }
        else{
            linaddr = va_info_slot->linaddr;
            pgprot = va_info_slot->pgprot;
            keid = va_info_slot->keid;
            epc_type = va_info_slot->epc_type;
            if (epc_type != REG_PAGE){ //TODO: cch: should later consider TCS, SECS, VA
                sgx_dbg(kern, "epc_type in va_info_slot is %d, not REG_PAGE", epc_type);
                return 0;
            }
            empty_epc = alloc_epc_page(keid); //cch: this will let get_epc() succeed in the next loop
            if (empty_epc == NULL){ //error
                sgx_dbg(kern, "alloc_epc_page failed");
                return 0;
            }
            empty_epc = get_epc(keid, epc_type);
            if (empty_epc == NULL){
                sgx_dbg(kern, "get_epc failed");
                return 0;
            }
            else{
                ret = invoke_eld(empty_epc, va_info_slot, va_slot_addr);
                if (ret == 0){
                    sgx_dbg(kern, "invoke_eld failed");
                    return 0;
                } 
                epc_phys_addr = __pa((void *)empty_epc);
                //cch: fill in pte with new EPC page
                set_pte(*ptepp, __pte(epc_phys_addr | massage_pgprot(pgprot)));
                sgx_dbg(kern, "the faulting pte entry is set with the EPC page where ELD loads the saved content");
                //cch: The below saving procedure is necessary for evicing this EPC page. empty_epc is no longer empty after invoking eld. 
                save_linaddr_epc_info(empty_epc, current->mm, linaddr, pgprot); 
                free_va_info_slot(va_info_slot);
                return 1;
            }
        }
    }
}

//cch: temporary func just for test
static
uint64_t get_recent_va_slot_addr(struct list_head *head){
    struct list_head *iter;
    va_info_t *va_info;
    epc_t *va_addr;
    uint64_t va_slot_addr;
    int i = NR_VA_SLOT - 1;

    list_for_each(iter, head) {
        va_info = list_entry(iter, va_info_t, va_info_list);
        for (; i >= 0 ; i--){
            if (va_info->slot[i].type == USED_SLOT){
                va_addr = va_info->va_addr;
                va_slot_addr = (uint64_t)va_addr + i * VA_SLOT_SIZE;
                return va_slot_addr;
            }
        }
    }
    return 0;
}

static
uint64_t get_empty_va_slot(epc_t *va_addr, struct list_head *head){
    va_info_t *va_info;
    int i = 0;
    uint64_t va_slot_addr;
   
    va_info = find_va_info(va_addr, head); 

    for (; i < NR_VA_SLOT ; i++){
        if (va_info->slot[i].type == FREE_SLOT){
            va_slot_addr = (uint64_t)va_addr + i * VA_SLOT_SIZE;
            sgx_dbg(kern, "va_addr is %p, i is %d, va_slot_addr is %p", va_addr, i, va_slot_addr);
            return va_slot_addr;
        }
    }

    // used_va is full
    return 0;
}

#ifdef THREAD_PROTECTION
static
int use_va_info_slot(int keid, epc_type_t epc_type, uint64_t va_slot_addr,
                      pgprot_t pgprot, uint64_t linaddr, uint64_t page_to_store, 
                      pcmd_t *pcmd_addr, epc_t *secs, epc_t *tcs, struct list_head *head){
#else
static
int use_va_info_slot(int keid, epc_type_t epc_type, uint64_t va_slot_addr,
                      pgprot_t pgprot, uint64_t linaddr, uint64_t page_to_store, 
                      pcmd_t *pcmd_addr, epc_t *secs, struct list_head *head){
#endif
    va_info_t *va_info;
    epc_t *va_addr = va_slot_addr & (uint64_t)(~(0xFFF));
    int index = 0;
    uint64_t offset = va_slot_addr - (uint64_t)va_addr;

    index = offset / VA_SLOT_SIZE;
    sgx_dbg(kern, "va_slot_addr is %p, va_addr is %p, offset is %x, index is %d", va_slot_addr, va_addr, offset, index);
    va_info = find_va_info(va_addr, head);
    if(va_info != NULL){
        va_info->slot[index].type = USED_SLOT;
        va_info->slot[index].keid = keid;
        va_info->slot[index].pgprot = pgprot;
        va_info->slot[index].linaddr = linaddr;
        va_info->slot[index].epc_type = epc_type;
        va_info->slot[index].target_addr = page_to_store; 
        va_info->slot[index].pcmd_addr = pcmd_addr;
        va_info->slot[index].secs = secs;
#ifdef THREAD_PROTECTION
        va_info->slot[index].tcs = tcs;
#endif
        sgx_dbg(kern,"va_info->slot[%d].type = %d, target_addr = %p, pcmd_addr = %p", 
                index, va_info->slot[index].type, va_info->slot[index].target_addr, va_info->slot[index].pcmd_addr);
        return 1;
    }
    return 0;
}

static
void free_va_info_slot(va_info_slot_t *va_info_slot){
    memset(va_info_slot, 0, sizeof(va_info_slot_t));
}

static
uint64_t search_va_slot(void){
    int vaid = VAID; //temp
    int loop = 1;
    static epc_t *used_va = NULL;
    uint64_t va_slot;

    if (used_va != NULL){
        va_slot = get_empty_va_slot(used_va, &va_info_head);
        if (va_slot != 0)
            return va_slot; 
    }
    do{ 
        epc_t *new_va = get_epc(vaid, (uint64_t)VA_PAGE);
 
        if(new_va != NULL) {
            add_va_info_node(new_va, &va_info_head);
            invoke_epa(new_va);
            used_va = new_va;
            va_slot = get_empty_va_slot(used_va, &va_info_head);
            return va_slot;
        }
        else {
            epc_t *new_epc_page = alloc_epc_page(vaid); //cch: this will let get_epc() succeed in the next loop
            if (new_epc_page == NULL) {
                return 0;
            }
        }   
    } while(loop-- > 0);
    return 0;
}

static
int get_epc_index_to_evict(void){
    //cch: LRU mechanism is recommended to be added
    static int last = 0;
    for (int i = 0; i < g_num_epc; i++) {
        int idx = (i + last) % g_num_epc;
        if (g_epc_info[idx].type == REG_PAGE) { //cch: should later include TCS_PAGE and VA_PAGE
            last = idx; 
            return idx;
        }   
    }   
    return -1; 
}

static
epc_t *get_epc_to_evict(void){
    int idx = get_epc_index_to_evict();
    sgx_dbg(kern, "index of epc to evict : %d", idx);
    if (idx != -1)
        return &g_epc[idx];
    return NULL;
}

void launch_sgx_paging(void) {
    int vaid = VAID;  //temp
    int loop = NR_EVICT_PAGES;
    uint64_t va_slot = 0;
    epc_t *epc_to_evict = NULL;
    int ret = 0;

    do{
        begin:
        spin_lock(&paging_lock);
        va_slot = search_va_slot(); //get_empty_va_slot() is invoked here
        if(va_slot != 0){
             epc_to_evict = get_epc_to_evict();
             if (epc_to_evict == NULL){
                 spin_unlock(&paging_lock);
                 break;
             }
             ret = invoke_eblock(epc_to_evict);
             sgx_dbg(kern, "epc_to_evict: %p, va_slot: %p", epc_to_evict, va_slot);
             ret = invoke_ewb(epc_to_evict, va_slot); //use_va_info_slot() is invoked here
             spin_unlock(&paging_lock);
             if (ret != 0){
                 ret = put_epc(epc_to_evict);
             }
             else{
                 goto begin;
             }
        }
        else{
             spin_unlock(&paging_lock);
        }
    } while(--loop > 0);
}

void init_epc(int nepc) {
    int va_npages = 1;
    g_num_epc = nepc;
    g_num_remaining = nepc;

    //toward making g_num_epc configurable
    //kmalloc can allocate at most 128 Kbytes, thus EPC allocation needs to be done in boot time

    g_epc = kmalloc(g_num_epc * sizeof(epc_t), GFP_KERNEL);

    sgx_dbg(kern, "g_epc: %p", (void *)g_epc);
    sgx_dbg(info, "kernel epc n: %d",g_num_epc);
    sgx_dbg(info, "kernel epc_t size: %d",sizeof(epc_t));
    sgx_dbg(info, "kernel epc size: %p", g_num_epc * sizeof(epc_t));

    //cch : error check routine need to be inserted
    if (!g_epc)
        printk("failed to allocate EPC\n");

    g_epc_info = kmalloc(g_num_epc * sizeof(epc_info_t), GFP_KERNEL);
    if (!g_epc_info)
        printk("failed to allocate EPC map in kernel\n");

    memset(g_epc, 0, g_num_epc * sizeof(epc_t));
    memset(g_epc_info, 0, g_num_epc * sizeof(epc_info_t));

    spin_lock_init(&epc_lock);
    spin_lock_init(&va_info_lock);
    spin_lock_init(&paging_lock);

    reserve_va_pages(va_npages);
}

void free_all_va_info(struct list_head *head){
    struct list_head *iter;
    va_info_t *va;

    redo:
    list_for_each(iter, head){
        va = list_entry(iter, va_info_t, va_info_list);
        if (va != NULL){
            list_del(&va->va_info_list);
            vfree(va);
        }
        goto redo;
    }
}

void free_epc(void){
    kfree(g_epc);
    kfree(g_epc_info);
    free_all_va_info(&va_info_head);
}

static
int get_epc_index(int key, epc_type_t pt)
{
    for (int idx = 0; idx < g_num_epc; idx++) {
        if (g_epc_info[idx].key == key
            && g_epc_info[idx].type == RESERVED) {
            g_epc_info[idx].type = pt;
            return idx;
        }
    }
    return -1;
}

static
int find_epc_index(int key) 
{
    static int last = 0;
    for (int i = 0; i < g_num_epc; i++) {
        int idx = (i + last) % g_num_epc;
        if (g_epc_info[idx].key == key
            && g_epc_info[idx].type != FREE_PAGE) {
            last = idx; 
            return idx;
        }
    }
    return -1;
}

static
void put_epc_index(int index)
{
    WARN_ON(index < 0 || index >= g_num_epc);
    WARN_ON(g_epc_info[index].type == FREE_PAGE);

    g_epc_info[index].type = FREE_PAGE;
    g_epc_info[index].key = 0;
    //below cch added
    g_epc_info[index].mm = NULL;
    g_epc_info[index].linaddr = 0;
    g_epc_info[index].pgprot.pgprot = 0;

    g_num_remaining += 1;
}

epc_t *get_epc(int key, epc_type_t pt)
{
    int idx = get_epc_index(key, pt);
    if (idx != -1)
        return &g_epc[idx];
    return NULL;
}

epc_t *find_epc(int key)
{
    int idx = find_epc_index(key);
    if (idx != -1)
        return &g_epc[idx];
    return NULL;
}

int put_epc(epc_t * epc)
{
    int ret = 0;
    WARN_ON ((uint64_t)epc & (uint64_t)0xFFF != 0x0);
    
    for (int idx = 0; idx < g_num_epc; idx++) {
        if(&g_epc[idx] == epc){
            put_epc_index(idx);
            ret = 1;
            break;
        }
    }
    return ret;
}

epc_t *get_epc_region_beg(void)
{
    return &g_epc[0];
}

epc_t *get_epc_region_end(void)
{
    return &g_epc[g_num_epc];
}

static
const char *epc_bitmap_to_str(epc_type_t type)
{
    switch (type) {
        case FREE_PAGE: return "FREE";
        case SECS_PAGE: return "SECS";
        case TCS_PAGE : return "TCS ";
        case REG_PAGE : return "REG ";
        case VA_PAGE  : return "VA  ";
        case RESERVED : return "RERV";
        default:
        {
            sgx_dbg(err, "unknown epc page type (%d)", type);
	    WARN_ON(true);
        }
    }
}

void dbg_dump_epc(void)
{
    for (int i = 0; i < g_num_epc; i++) {
        printk("[%02d] %p (%02d/%s)\n",
                i, g_epc[i],
                g_epc_info[i].key,
                epc_bitmap_to_str(g_epc_info[i].type));
    }
    printk("\n");
}

int find_epc_type(void *addr)
{
    for (int i = 0; i < g_num_epc; i++) {
        if (addr == &g_epc[i])
            return g_epc_info[i].type;
    }

    return -1;
}

static
int find_epc_keid(void *addr)
{
    for (int i = 0; i < g_num_epc; i++) {
        if (addr == &g_epc[i])
            return g_epc_info[i].key;
    }

    return -1;
}

static
epc_t *find_epc_secs(void *addr)
{
    int keid = -1;
    int i;

    for (i = 0; i < g_num_epc; i++) {
        if (addr == &g_epc[i]) {
            keid = g_epc_info[i].key;
        }
    }
    for (i = 0; i < g_num_epc; i++) {
        if ((g_epc_info[i].key == keid) && (g_epc_info[i].type == SECS_PAGE)) {
            return &g_epc[i];
        }
    }
    return NULL;
}

#ifdef THREAD_PROTECTION
static
epc_t *find_epc_tcs(void *addr)
{
    int keid = -1; 
    int i;

    for (i = 0; i < g_num_epc; i++) {
        if (addr == &g_epc[i]) {
            keid = g_epc_info[i].key;
        }
    }   
    for (i = 0; i < g_num_epc; i++) {
        if ((g_epc_info[i].key == keid) && (g_epc_info[i].type == TCS_PAGE)) {
            return &g_epc[i];
        }
    }   
    return NULL;
}
#endif

static
int reserve_epc_index(int key)
{
    spin_lock(&epc_lock);
    for (int i = 0; i < g_num_epc; i++) {
        int idx = i % g_num_epc;
        if (g_epc_info[idx].type == FREE_PAGE) {
            g_epc_info[idx].key = key;
            g_epc_info[idx].type = RESERVED;
            g_num_remaining -= 1;
            spin_unlock(&epc_lock);
            return idx;
        }
    }
    spin_unlock(&epc_lock);
    return -1;
}

static
int alloc_epc_index_pages(int npages, int key)
{
    int beg = reserve_epc_index(key);
    if (beg == -1)
        return -1;

    // request too many pages
    if (beg + npages >= g_num_epc) {
        put_epc_index(beg);
        return -1;
    }

    // check if we have npages
    int i;
    for (i = beg + 1; i < beg + npages; i++) {
        if (g_epc_info[i].type != FREE_PAGE) {
            // restore and return
            for (int j = beg; j < i; j ++) {
                put_epc_index(i);
            }
            return -1;
        }
        g_epc_info[i].key = key;
        g_epc_info[i].type = RESERVED;
        g_num_remaining -= 1;
    }

    // npages epcs allocated
    return beg;
}


epc_t *alloc_epc_pages(int npages, int key)
{
    int idx = alloc_epc_index_pages(npages, key);
    if (idx != -1){
        sgx_dbg(kern, "g_num_remaining: %d, EPC_min: %d", g_num_remaining, EPC_MIN);
        if (g_num_remaining < EPC_MIN){
            launch_sgx_paging(); 
        }
        return &g_epc[idx];
    }
    return NULL;
}

//cch: replacement for alloc_epc_pages. this func can reserve non-contiguous EPC page slots
epc_t **reserve_epc_pages(int npages, int key)
{
    epc_t **reserved_pages;
    int idx;
    reserved_pages = (epc_t **)kmalloc(sizeof(void *) * npages, GFP_KERNEL);

    sgx_dbg(kern, "g_num_remaining: %d, EPC_min: %d", g_num_remaining, EPC_MIN);
    if (g_num_remaining < EPC_MIN){
        launch_sgx_paging();
    }

    for (int i = 0; i < npages; i++){
        idx = reserve_epc_index(key);
        if (idx != -1){
            reserved_pages[i] = &g_epc[idx];
        }
        else{
            for(int j = 0; j < i ; j++){
                put_epc_index(j);
            }
            return NULL;
        }
    }
    return reserved_pages;
}

epc_t *alloc_epc_page(int key)   //cch: ELDU/B and EAUG affects this function
{
    int idx = reserve_epc_index(key);
    if (idx != -1){
        /*
        sgx_dbg(kern, "g_num_remaining: %d, EPC_min: %d", g_num_remaining, EPC_MIN);
        if (g_num_remaining < EPC_MIN){
            launch_sgx_paging(); 
        }
        */
        return &g_epc[idx];
    }
    return NULL;
}

void free_reserved_epc_pages(int key){
    for (int i = 0; i < g_num_epc; i++){
        if ((g_epc_info[i].key == key) && (g_epc_info[i].type == RESERVED)){
            g_epc_info[i].key = 0;
            g_epc_info[i].type = FREE_PAGE;
            g_num_remaining += 1;
        }
    }
}

void free_epc_pages(int key)
{
    for (int i = 0; i < g_num_epc; i ++) {
        if (g_epc_info[i].key == key) {
            g_epc_info[i].key = 0;
            g_epc_info[i].type = FREE_PAGE;
            g_epc_info[i].mm = NULL;
            g_epc_info[i].linaddr = 0;
            g_epc_info[i].pgprot.pgprot = 0;
            g_num_remaining += 1;
        }
    }
}

void save_linaddr_epc_info(epc_t *epc, struct mm_struct *mm, uint64_t linaddr, pgprot_t pgprot){
    for (int i = 0; i < g_num_epc; i++){
        if(epc == &g_epc[i]){
            g_epc_info[i].mm = mm;
            g_epc_info[i].linaddr = linaddr;
            g_epc_info[i].pgprot = pgprot;
        }
    }
}

void restore_linaddr_epc_info(epc_t *epc, struct mm_struct **mm_p, uint64_t *linaddr_p, pgprot_t *pgprot_p){
    for (int i = 0; i < g_num_epc; i++){
        if(epc == &g_epc[i]){
            *mm_p = g_epc_info[i].mm;
            *linaddr_p = g_epc_info[i].linaddr;
            *pgprot_p = g_epc_info[i].pgprot;
        }
    }
}
