#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/mm.h>
#include <asm/unistd.h>
#include <asm/page.h>
#include <linux/string.h> //cch: memcpy and memset in kernel
#include <linux/errno.h>  //cch: errno
#include <linux/sched.h>  //cch: current
#include <linux/mm.h>     //cch: __pmd_alloc, __pud_alloc
#include <linux/rmap.h>   //cch: anon_vma_lock_write
#include <asm/pgalloc.h>  //cch: pmd_free
#include <linux/vmalloc.h> // blueguy : to avoid compile error
#define SGX_KERNEL
#include <sgx-kern.h>
#include <sgx-kern-epc.h>
#include <sgx-signature.h>
#include <sgx-utils.h>

keid_t kenclaves[MAX_ENCLAVES];

char *empty_page;
static unsigned long heap_begin;
static unsigned long heap_end;

struct kmem_cache *pageinfo_cache; //cch: linux kernel 3.13.11-ckt29
struct kmem_cache *secinfo_cache; //cch: linux kernel 3.13.11-ckt29
struct kmem_cache *pcmd_cache; //cch: linux kernel 3.13.11-ckt29
struct kmem_cache *epc_t_cache; //cch: linux kernel 3.13.11-ckt29

#define PGALLOC_GFP GFP_KERNEL | __GFP_NOTRACK | __GFP_REPEAT | __GFP_ZERO
#ifdef CONFIG_HIGHPTE
#define PGALLOC_USER_GFP __GFP_HIGHMEM
#else
#define PGALLOC_USER_GFP 0
#endif

gfp_t __userpte_alloc_gfp = PGALLOC_GFP | PGALLOC_USER_GFP;

pgtable_t pte_alloc_one(struct mm_struct *mm, unsigned long address)
{
        struct page *pte;

        pte = alloc_pages(__userpte_alloc_gfp, 0); 
        if (!pte)
                return NULL;
        if (!pgtable_page_ctor(pte)) {
                __free_page(pte);
                return NULL;
        }   
        return pte;
}

int __pte_alloc(struct mm_struct *mm, struct vm_area_struct *vma,
                pmd_t *pmd, unsigned long address)
{
        spinlock_t *ptl;
        pgtable_t new = pte_alloc_one(mm, address);
        int wait_split_huge_page;
        if (!new)
                return -ENOMEM;

        /*   
         * Ensure all pte setup (eg. pte page lock and page clearing) are
         * visible before the pte is made visible to other CPUs by being
         * put into page tables.
         *
         * The other side of the story is the pointer chasing in the page
         * table walking code (when walking the page table without locking;
         * ie. most of the time). Fortunately, these data accesses consist
         * of a chain of data-dependent loads, meaning most CPUs (alpha
         * being the notable exception) will already guarantee loads are
         * seen in-order. See the alpha page table accessors for the
         * smp_read_barrier_depends() barriers in page table walking code.
         */
        smp_wmb(); /* Could be smp_wmb__xxx(before|after)_spin_lock */

        ptl = pmd_lock(mm, pmd);
        wait_split_huge_page = 0; 
        if (likely(pmd_none(*pmd))) {   /* Has another populated it ? */
                atomic_long_inc(&mm->nr_ptes);
                pmd_populate(mm, pmd, new);
                new = NULL;
        } else if (unlikely(pmd_trans_splitting(*pmd)))
                wait_split_huge_page = 1; 
        spin_unlock(ptl);
        if (new)
                pte_free(mm, new);
        if (wait_split_huge_page)
                wait_split_huge_page(vma->anon_vma, pmd);
        return 0;
}


/*
 * Allocate page upper directory.
 * We've already handled the fast-path in-line.
 */
int __pud_alloc(struct mm_struct *mm, pgd_t *pgd, unsigned long address)
{
        pud_t *new = pud_alloc_one(mm, address);
        if (!new)
                return -ENOMEM;

        smp_wmb(); /* See comment in __pte_alloc */

        spin_lock(&mm->page_table_lock);
        if (pgd_present(*pgd))          /* Another has populated it */
                pud_free(mm, new);
        else 
                pgd_populate(mm, pgd, new);
        spin_unlock(&mm->page_table_lock);
        return 0;
}

/*
 * Allocate page middle directory.
 * We've already handled the fast-path in-line.
 */
int __pmd_alloc(struct mm_struct *mm, pud_t *pud, unsigned long address)
{
        pmd_t *new = pmd_alloc_one(mm, address);
        if (!new)
                return -ENOMEM;

        smp_wmb(); /* See comment in __pte_alloc */

        spin_lock(&mm->page_table_lock);
#ifndef __ARCH_HAS_4LEVEL_HACK
        if (pud_present(*pud))          /* Another has populated it */
                pmd_free(mm, new);
        else 
                pud_populate(mm, pud, new);
#else
        if (pgd_present(*pud))          /* Another has populated it */
                pmd_free(mm, new);
        else 
                pgd_populate(mm, pud, new);
#endif /* __ARCH_HAS_4LEVEL_HACK */
        spin_unlock(&mm->page_table_lock);
        return 0;
}

static pmd_t *alloc_new_pmd(struct mm_struct *mm, struct vm_area_struct *vma,
                            unsigned long addr)
{
        pgd_t *pgd;
        pud_t *pud;
        pmd_t *pmd;

        pgd = pgd_offset(mm, addr);
        pud = pud_alloc(mm, pgd, addr);
        if (!pud)
                return NULL;

        pmd = pmd_alloc(mm, pud, addr);
        if (!pmd)
                return NULL;

        VM_BUG_ON(pmd_trans_huge(*pmd));

        return pmd;
}

static int __follow_pte(struct mm_struct *mm, unsigned long address,
                pte_t **ptepp, spinlock_t **ptlp)
{
        pgd_t *pgd;
        pud_t *pud;
        pmd_t *pmd;
        pte_t *ptep;

        pgd = pgd_offset(mm, address);
        if (pgd_none(*pgd) || unlikely(pgd_bad(*pgd)))
                goto out;

        pud = pud_offset(pgd, address);
        unsigned long tmp = (unsigned long)native_pud_val(*pud);
        if (pud_none(*pud) || unlikely(pud_bad(*pud))) //cch:comment removed
                goto out;

        pmd = pmd_offset(pud, address);
        VM_BUG_ON(pmd_trans_huge(*pmd));
        tmp = native_pmd_val(*pmd);
        if (pmd_none(*pmd) || unlikely(pmd_bad(*pmd)))  //cch:comment removed
                goto out;

        ptep = pte_offset_map_lock(mm, pmd, address, ptlp);
        if (!ptep)
                goto out;
        //if (!pte_present(*ptep))
        //        goto unlock;
        *ptepp = ptep;
        return 0;
unlock:
        pte_unmap_unlock(ptep, *ptlp);
out:
        return -EINVAL;
}

extern int follow_pte(struct mm_struct *mm, unsigned long address,
                             pte_t **ptepp, spinlock_t **ptlp)
{
        int res;

        /* (void) is needed to make gcc happy */
        (void) __cond_lock(*ptlp,
                           !(res = __follow_pte(mm, address, ptepp, ptlp)));
        return res;
}

// encls() : Execute an encls instruction
// out_regs store the output value returned from qemu
void encls(encls_cmd_t leaf, uint64_t rbx, uint64_t rcx,
           uint64_t rdx, out_regs_t* out)
{
   /*
   sgx_dbg(kern,
           "leaf=%d, rbx=0x%"PRIx64", rcx=0x%"PRIx64", rdx=0x%"PRIx64")",
           leaf, rbx, rcx, rdx);
   */

   out_regs_t tmp;
   asm volatile(".byte 0x0F\n\t"
                ".byte 0x01\n\t"
                ".byte 0xcf\n\t"
                :"=a"(tmp.oeax),
                 "=b"(tmp.orbx),
                 "=c"(tmp.orcx),
                 "=d"(tmp.ordx)
                :"a"((uint32_t)leaf),
                 "b"(rbx),
                 "c"(rcx),
                 "d"(rdx)
                :"memory");

    if (out != NULL) {
        *out = tmp;
    }
}

static
void encls_qemu_init(uint64_t startPage, uint64_t endPage)
{
    // Function just for initializing EPCM within QEMU
    // based on EPC address in user code
    encls(ENCLS_OSGX_INIT, startPage, endPage, 0x0, NULL);
}

static
void ECREATE(pageinfo_t *pageinfo, epc_t *epc)
{
    // RBX: PAGEINFO(In, EA)
    // RCX: EPCPAGE(In, EA)
    encls(ENCLS_ECREATE,
          (uint64_t)pageinfo,
          (uint64_t)epc,
          0x0, NULL);
}

static
void EREMOVE(epc_t *epc)
{
    // RCX: EPCPAGE(In, EA)
    encls(ENCLS_EREMOVE,
          0x0,
          (uint64_t)epc,
          0x0, NULL);
}

static
int EINIT(uint64_t sigstruct, epc_t *secs, uint64_t einittoken)
{
    // RBX: SIGSTRUCT(In, EA)
    // RCX: SECS(In, EA)
    // RDX: EINITTOKEN(In, EA)
    // RAX: ERRORCODE(Out)
    out_regs_t out;
    encls(ENCLS_EINIT, sigstruct, (uint64_t)secs, einittoken, &out);
    return -(int)(out.oeax);
}

static
void EADD(pageinfo_t *pageinfo, epc_t *epc)
{
    // RBX: PAGEINFO(In, EA)
    // RCX: EPCPAGE(In, EA)
    encls(ENCLS_EADD,
          (uint64_t)pageinfo,
          (uint64_t)epc,
          0x0, NULL);
}

static
void EEXTEND(uint64_t pageChunk)
{
    // RCX: 256B Page Chunk to be hashed(In, EA)
    encls(ENCLS_EEXTEND, 0x0, pageChunk, 0x0, NULL);
}

void EPA(epc_t *epc)
{
    // RBX: PT_VA(In, Constant)
    // RCX: EPCPAGE(In, EA)
    encls(ENCLS_EPA,
          PT_VA,
          (uint64_t)epc,
          0x0, NULL);
}

int EBLOCK(uint64_t epc_addr)
{
    // RCX: EPC Addr(In, EA)
    // EAX: Error Code(Out)
    out_regs_t out;
    encls(ENCLS_EBLOCK, 0x0, epc_addr, 0x0, &out);

    return (int)(out.oeax);
}

int EWB(pageinfo_t *pageinfo_addr, epc_t *epc_addr, uint64_t va_slot_addr)
{
    // EAX: Error(Out)
    // RBX: Pageinfo Addr(In)
    // RCX: EPC addr(In)
    // RDX: VA slot addr(In)
    out_regs_t out;
    encls(ENCLS_EWB, (uint64_t)pageinfo_addr, (uint64_t)epc_addr, va_slot_addr, &out);
    return (int)(out.oeax);
}

int ELDU(pageinfo_t *pageinfo_addr, epc_t *epc_addr, uint64_t va_slot_addr)
{
    // EAX: Error(Out)
    // RBX: Pageinfo Addr(In)
    // RCX: EPC addr(In)
    // RDX: VA slot addr(In)
    out_regs_t out; 
    encls(ENCLS_ELDU, (uint64_t)pageinfo_addr, (uint64_t)epc_addr, va_slot_addr, &out);
    return (int)(out.oeax);
}

int ELDB(pageinfo_t *pageinfo_addr, epc_t *epc_addr, uint64_t va_slot_addr)
{
    // EAX: Error(Out)
    // RBX: Pageinfo Addr(In)
    // RCX: EPC addr(In)
    // RDX: VA slot addr(In)
    out_regs_t out; 
    encls(ENCLS_ELDB, (uint64_t)pageinfo_addr, (uint64_t)epc_addr, va_slot_addr, &out);
    return (int)(out.oeax);
}

static
void EAUG(pageinfo_t *pageinfo, epc_t *epc)
{
    // RBX: PAGEINFO(In, EA)
    // RCX: EPCPAGE(In, EA)
    encls(ENCLS_EAUG,
          (uint64_t)pageinfo,
          (uint64_t)epc_to_vaddr(epc),
          0x0, NULL);
}

static
void EMODPR(secinfo_t *secinfo, epc_t *epc)
{
    // RBX: PAGEINFO(In, EA)
    // RCX: EPCPAGE(In, EA)
    encls(ENCLS_EMODPR,
          (uint64_t)secinfo,
          (uint64_t)epc_to_vaddr(epc),
          0x0, NULL);
}

static
void EMODT(secinfo_t *secinfo, epc_t *epc)
{
    // RBX: PAGEINFO(In, EA)
    // RCX: EPCPAGE(In, EA)
    encls(ENCLS_EMODT,
          (uint64_t)secinfo,
          (uint64_t)epc_to_vaddr(epc),
          0x0, NULL);
}

static
void encls_stat(int keid, qstat_t *qstat)
{
    encls(ENCLS_OSGX_STAT, keid, (uint64_t)qstat, 0x0, NULL);
}

static
void set_cpusvn(uint8_t svn)
{
    // Set cpu svn.
    encls(ENCLS_OSGX_CPUSVN, svn, 0x0, 0x0, NULL);
}

static
int init_enclave(epc_t *secs, sigstruct_t *sig, einittoken_t *token)
{
    return EINIT((uint64_t)sig, secs, (uint64_t)token);
}

static
secinfo_t *alloc_secinfo(bool r, bool w, bool x, page_type_t pt) {
    secinfo_t *secinfo = kmem_cache_alloc(secinfo_cache, GFP_KERNEL);
    if (!secinfo)
        return NULL;

    memset(secinfo, 0, sizeof(secinfo_t));

    secinfo->flags.page_type = pt;
    secinfo->flags.r = r;
    secinfo->flags.w = w;
    secinfo->flags.x = x;

    return secinfo;
}

secs_t *alloc_secs(uint64_t enclave_addr, uint64_t enclave_size, bool intel_flag)
{
    const int SECS_SIZE = MIN_ALLOC * PAGE_SIZE;
    //cch: check whether the size of SECS is 4096 or 8192 in spec
    secs_t *secs = (secs_t *)kmem_cache_alloc(epc_t_cache, GFP_KERNEL);

    if (!secs) 
        return NULL;

    memset(secs, 0, sizeof(secs_t));

    // XXX. set ssaFramesize, currently use it as 1 temporarily
    secs->ssaFrameSize         = 1;
    secs->attributes.mode64bit = true;
    secs->attributes.debug     = false;
    secs->attributes.xfrm      = 0x03;

    if (intel_flag) {
        secs->attributes.provisionkey  = false;
        secs->attributes.einittokenkey = true;
    } else {
        secs->attributes.provisionkey  = true;
        secs->attributes.einittokenkey = false;
    }       

    secs->baseAddr = enclave_addr;
    secs->size     = enclave_size;
    sgx_dbg(info, "enclave addr: %p (size: 0x%x)",
            enclave_addr, enclave_size); //cch added for debug

    return secs;
}

static
epc_t *ecreate(int eid, uint64_t enclave_addr, uint64_t enclave_size, bool intel_flag)
{
    pageinfo_t *pageinfo = kmem_cache_alloc(pageinfo_cache, GFP_KERNEL);
    if (!pageinfo)
        printk("failed to allocate pageinfo\n");

    secs_t *secs = alloc_secs(enclave_addr, enclave_size, intel_flag);
    if (!secs)
        printk("failed to allocate sec\n");

    secinfo_t *secinfo = alloc_secinfo(true, true, false, PT_SECS);
    if (!secinfo)
        printk("failed to allocate secinfo\n");

    pageinfo->srcpge  = (uint64_t)secs;
    pageinfo->secinfo = (uint64_t)secinfo;
    pageinfo->secs    = 0; // not used  cch: check why not used
    pageinfo->linaddr = 0; // not used
#ifdef THREAD_PROTECTION
    pageinfo->tcs     = 0;
#endif

    epc_t *epc = get_epc(eid, SECS_PAGE);
    if (!epc)
        printk("failed to allocate EPC page for SECS\n");

    sgx_dbg(info, "pageinfo: %p, epc: %p", pageinfo, epc); //cch: just for debug
    ECREATE(pageinfo, epc);
    sgx_dbg(info, "ECREATE is invoked"); //cch: just for debug

    //
    // NOTE.
    //  upon ECREATE error, it faults. safely assumes it succeeds.
    //

    kmem_cache_free(pageinfo_cache, pageinfo);
    kmem_cache_free(secinfo_cache, secinfo);
    kmem_cache_free(epc_t_cache, secs);

    return epc;
}

static
void measure_enclave_page(uint64_t page_chunk_addr)
{
    EEXTEND(page_chunk_addr);
}

static
bool link_linaddr_with_epc(unsigned long linaddr, epc_t *epc, pgprot_t pgprot){
        /*   
           cch: (PAGE_OFFSET calculation or __pa() is enough for obtaining 
                physical address from kmalloc allocated memory)
        */
        unsigned long epc_phys_addr = __pa(((void *)epc));
        sgx_dbg(kern, "epc virt %p, epc phys %p", epc, epc_phys_addr);
        spinlock_t *ptl;
        pte_t *ptep = NULL;
        sgx_dbg(kern, "linaddr %p", linaddr);
        int ret = -EINVAL;
        sgx_dbg(kern, "ptep is %p", ptep);
        struct vm_area_struct *vma = find_vma(current->mm, linaddr);
        if (!vma)
           sgx_dbg(kern, "cch debug vma is NULL");
        else if(vma->vm_start <= linaddr){
           sgx_dbg(kern, "cch debug there exists vma");
        }
        else{
           sgx_dbg(kern, "cch debug there is no vma including linaddr");
        }
        /*   
           cch: since the target address has no pagetable entries (pmd, pud, pte), 
                they needs to be allocated first.
        */
        pmd_t *new_pmd = alloc_new_pmd(current->mm, vma, linaddr);
        if(!new_pmd){
            sgx_dbg(kern, "alloc_new_pmd failed");
            return false;
        }    
        if (pmd_none(*new_pmd) && __pte_alloc(current->mm, vma, new_pmd, linaddr)){
            sgx_dbg(kern, "alloc_new_pmd failed");
            return false;
        }    
        /*   
           cch: I used follow_pte for obtaining the address of the pte pointing to linaddr. 
                This function acquires ptl lock, thus it needs to be released later.
        */
        ret = follow_pte(current->mm, linaddr, &ptep, &ptl); 
        if (ret) {
            sgx_dbg(kern, "follow_pte failed, and ret is %d", ret);
            return false; //should be changed to ret;
        }
        sgx_dbg(kern, "ptep is %p", ptep);
        set_pte(ptep, __pte(epc_phys_addr | massage_pgprot(pgprot)));
        pte_unmap_unlock(ptep, ptl);
   
        return true;
}

#ifdef THREAD_PROTECTION
// add (copy) a single page to a epc page
static
bool add_page_to_epc(void *page, epc_t *epc, epc_t *secs, epc_t *tcs, page_type_t pt, unsigned long linaddr) {
#else
static
bool add_page_to_epc(void *page, epc_t *epc, epc_t *secs, page_type_t pt, unsigned long linaddr) {
#endif
    pageinfo_t *pageinfo = kmem_cache_alloc(pageinfo_cache, GFP_KERNEL);
    if (!pageinfo){
        printk("failed to allocate pageinfo\n");
        return false; //cch added
    }

    secinfo_t *secinfo = alloc_secinfo(true, true, false, pt);
    if (!secinfo){
        printk("failed to allocate secinfo\n");
        return false; //cch added
    }

    if (pt == PT_REG) {
        secinfo->flags.x = true;
        // change permissions of a page table entry
        sgx_dbg(kern, "+x to %p", (void *)epc);
        // cch: do I need to consider the following things?
        //if (mprotect(epc, PAGE_SIZE, PROT_READ|PROT_WRITE|PROT_EXEC) == -1) //cch: should be changed
            //printk("failed to add executable permission\n");
    }

    pageinfo->srcpge  = (uint64_t)page;
    pageinfo->secinfo = (uint64_t)secinfo;
    pageinfo->secs    = (uint64_t)epc_to_vaddr(secs);
    pageinfo->linaddr = linaddr; //cch modified from (uint64_t)epc_to_vaddr(epc);
#ifdef THREAD_PROTECTION
    pageinfo->tcs     = (uint64_t)epc_to_vaddr(tcs);
#endif

    sgx_dbg(kern, "add/copy %p -> %p", page, epc_to_vaddr(epc));
    
    //hexdump(page, 32);

    EADD(pageinfo, epc_to_vaddr(epc)); //cch modified from epc

    // for EEXTEND
    for(int i = 0; i < PAGE_SIZE/MEASUREMENT_SIZE; i++)
        measure_enclave_page((uint64_t)epc_to_vaddr(epc) + i*MEASUREMENT_SIZE);

    kmem_cache_free(pageinfo_cache, pageinfo);
    kmem_cache_free(secinfo_cache, secinfo);

    return true;
}

#ifdef THREAD_PROTECTION
static
bool aug_page_to_epc(epc_t *epc, epc_t *secs, epc_t *tcs, unsigned long linaddr) {
#else
static
bool aug_page_to_epc(epc_t *epc, epc_t *secs, unsigned long linaddr) {
#endif
    pageinfo_t *pageinfo = kmem_cache_alloc(pageinfo_cache, GFP_KERNEL); //cch modified from memalign
    if (!pageinfo) {
        printk("failed to allocate pageinfo");
        return false;
    }

    pageinfo->srcpge  = 0;
    pageinfo->secinfo = 0;
    pageinfo->secs    = (uint64_t)secs;
    pageinfo->linaddr = linaddr; //cch modified from (uint64_t)epc_to_vaddr(epc);
#ifdef THREAD_PROTECTION
    pageinfo->tcs     = tcs;
#endif

    EAUG(pageinfo, epc);

    kmem_cache_free(pageinfo_cache, pageinfo); //cch modified from free

    return true;
}

#ifdef THREAD_PROTECTION
// add multiple pages to epc pages (will be allocated)
// cch: code and data should be treated differently since data should not be executable
static
bool add_pages_to_epc(int eid, void *load_addr, int npages, epc_t *secs, epc_t *tcs, 
                     epc_type_t epc_pt, page_type_t pt, unsigned long enclave_addr) {
#else
static
bool add_pages_to_epc(int eid, void *load_addr, int npages, epc_t *secs, 
                     epc_type_t epc_pt, page_type_t pt, unsigned long enclave_addr) {
#endif
    void *page = load_addr;
    unsigned long linaddr = enclave_addr;

    for (int i = 0; i < npages; i++) {
        epc_t *epc = get_epc(eid, (uint64_t)epc_pt);
        if (!epc){
            sgx_dbg(kern, "get_epc failed");
            return false;
        }
        linaddr = enclave_addr + i * 0x1000;
        if(!link_linaddr_with_epc(linaddr, epc_to_vaddr(epc), PAGE_SHARED_EXEC)){
            sgx_dbg(kern, "link_linaddr_with_epc failed"); 
            return false;
        }
        save_linaddr_epc_info(epc, current->mm, linaddr, PAGE_SHARED_EXEC);
#ifdef THREAD_PROTECTION
        if (!add_page_to_epc(page, epc, secs, tcs, pt, linaddr)){
#else
        if (!add_page_to_epc(page, epc, secs, pt, linaddr)){
#endif
            sgx_dbg(kern, "add page_to_epc failed");
            return false;
        }
        page = (void *)((uintptr_t)page + PAGE_SIZE);
    }   
    return true;
}

#ifdef THREAD_PROTECTION
// add multiple empty pages to epc pages (will be allocated)
static
bool add_empty_pages_to_epc(int eid, int npages, epc_t *secs, epc_t *tcs,
                            epc_type_t epc_pt, page_type_t pt, mem_type_t mt, 
                            unsigned long enclave_addr) {
#else
static
bool add_empty_pages_to_epc(int eid, int npages, epc_t *secs,
                            epc_type_t epc_pt, page_type_t pt, mem_type_t mt, 
                            unsigned long enclave_addr) {
#endif
    unsigned long linaddr = enclave_addr;

    for (int i = 0; i < npages; i ++) {
        epc_t *epc = get_epc(eid, epc_pt);
        if (!epc){
            sgx_dbg(kern, "get_epc failed");
            return false;
        }
        if (mt == MT_HEAP) {
            linaddr = enclave_addr + i * 0x1000;
            if(!link_linaddr_with_epc(linaddr, epc_to_vaddr(epc), PAGE_SHARED)){
                sgx_dbg(kern, "link_linaddr_with_epc failed"); 
                return false;
            }
            save_linaddr_epc_info(epc, current->mm, linaddr, PAGE_SHARED);
            if (i == 0){ //cch:does this need?
                heap_begin = linaddr;
                sgx_dbg(kern, "heap_begin is set as %p", (void *)heap_begin);
            }
            if (i == npages - 1) {
                heap_end = enclave_addr + (i + 1) * 0x1000; //cch: epc_heap_end is changed from kernel virtual address to enclave(user) virtual address
                sgx_dbg(kern, "heap_end is set as %p",(void *)heap_end);
            }   
        }
        else if (mt == MT_STACK) {
            linaddr = enclave_addr - (i + 1) * 0x1000;
            sgx_dbg(kern, "stack linaddr in add_empty %d : %p", i, linaddr); 
            if(!link_linaddr_with_epc(linaddr, epc_to_vaddr(epc), PAGE_SHARED)){
                sgx_dbg(kern, "link_linaddr_with_epc failed"); 
                return false;
            }
            save_linaddr_epc_info(epc, current->mm, linaddr, PAGE_SHARED);
        }
        else { //cch added
            linaddr = enclave_addr + i * 0x1000;
            if(!link_linaddr_with_epc(linaddr, epc_to_vaddr(epc), PAGE_SHARED)){
                sgx_dbg(kern, "link_linaddr_with_epc failed"); 
                return false;
            }
            save_linaddr_epc_info(epc, current->mm, linaddr, PAGE_SHARED);
        }
#ifdef THREAD_PROTECTION
        if (!add_page_to_epc(empty_page, epc, secs, tcs, pt, linaddr)){
#else
        if (!add_page_to_epc(empty_page, epc, secs, pt, linaddr)){
#endif
            sgx_dbg(kern, "add page_to_epc failed");
            return false;
        }
    }   
    return true;
}

#ifdef THREAD_PROTECTION
static
bool add_tls_pages_to_epc(int eid, int npages, epc_t *secs, epc_t *tcs, 
                          epc_type_t epc_pt, page_type_t pt, 
                          unsigned long enclave_addr, unsigned long stack_linaddr) {
#else
static
bool add_tls_pages_to_epc(int eid, int npages, epc_t *secs,
                          epc_type_t epc_pt, page_type_t pt, 
                          unsigned long enclave_addr, unsigned long stack_linaddr) {
#endif
    unsigned long linaddr = enclave_addr;
    unsigned long stack_begin = stack_linaddr - 0x1000 + 0xff0; //cch: I am not sure. which one is better between 0xff0, 0xfff, and 0x1000? 
    sgx_dbg(kern, "stack begin to set: %p", stack_begin); 
    char *tls_page = (char *)kmem_cache_alloc(epc_t_cache, GFP_KERNEL); //cch need to be freed after usage
    memset(tls_page, 0, PAGE_SIZE); //just for test
    memcpy(tls_page, &stack_begin, sizeof(unsigned long));
    for (int i = 0; i < npages; i ++) {
        epc_t *epc = get_epc(eid, epc_pt);
        if (!epc){
            sgx_dbg(kern, "get_epc failed");
            return false;
        }
        {//cch added
            linaddr = enclave_addr + i * 0x1000;
            if(!link_linaddr_with_epc(linaddr, epc_to_vaddr(epc), PAGE_SHARED)){
                sgx_dbg(kern, "link_linaddr_with_epc failed"); 
                return false;
            }    
            save_linaddr_epc_info(epc, current->mm, linaddr, PAGE_SHARED);
        }
        //temporary    
#ifdef THREAD_PROTECTION
        if (!add_page_to_epc(tls_page, epc, secs, tcs, pt, linaddr)){
#else
        if (!add_page_to_epc(tls_page, epc, secs, pt, linaddr)){
#endif
            sgx_dbg(kern, "add page_to_epc failed");
            return false;
        }    
    }    
    return true;
}

void kmem_cache_create_sgx_obj(void){
    //cch: kmem_cache by default aligns with the struct

    pageinfo_cache = kmem_cache_create("pageinfoc", 
                                     sizeof(pageinfo_t), 
                                     0, 
                                     SLAB_HWCACHE_ALIGN,
                                     NULL);

    secinfo_cache = kmem_cache_create("secinfoc", 
                                     sizeof(secinfo_t), 
                                     0, 
                                     SLAB_HWCACHE_ALIGN,
                                     NULL);

    pcmd_cache = kmem_cache_create("pcmdc", 
                                     sizeof(pcmd_t), 
                                     0, 
                                     SLAB_HWCACHE_ALIGN,
                                     NULL);

    epc_t_cache = kmem_cache_create("epc_tc", 
                                     sizeof(epc_t), 
                                     0, 
                                     SLAB_HWCACHE_ALIGN,
                                     NULL);
}

asmlinkage int sys_get_enclave_heap(long heap_begin_userp, long heap_end_userp){
    sgx_dbg(trace, "heap_begin_userp is %p, heap_end_userp is %p", heap_begin_userp, heap_end_userp);
    sgx_dbg(trace, "heap_begin is %p, heap_end is %p", heap_begin, heap_end);
    if (copy_to_user(heap_begin_userp, &heap_begin, sizeof(long))) {
         sgx_dbg(trace, "heap_begin is not copied well");
         return -EFAULT;
    }
    if (copy_to_user(heap_end_userp, &heap_end, sizeof(long))) {
         sgx_dbg(trace, "heap_end is not copied well");
         return -EFAULT;
    }
    return 0;
}

int system_sgx_init(void){
    
    int ret = 0; //cch added
    // enclave map
    for (int idx = 0; idx < MAX_ENCLAVES; idx ++) {
        free_keid(idx);
    } 
        
    init_epc(NUM_EPC);
    sgx_dbg(info, "init_epc is completed");

    encls_qemu_init((unsigned long)get_epc_region_beg(),
                    (unsigned long)get_epc_region_end());
    sgx_dbg(info, "encls_qemu_init is completed");

    // Set default cpu svn
    set_cpusvn(CPU_SVN);

    kmem_cache_create_sgx_obj();

    // Initialize an empty page for later use.
    empty_page = (char *)kmem_cache_alloc(epc_t_cache, GFP_KERNEL); //cch modified
    memset(empty_page, 0, PAGE_SIZE);

    return ret;
}

int system_sgx_exit(void){
    free_epc();
    //TODO: free_kmem_cache
}

// allocate keid
static int alloc_keid(void)
{
    static last;
    for (int i = 0; i < MAX_ENCLAVES; i ++) {
        int index = (i + last) % MAX_ENCLAVES;
        if (kenclaves[index].keid == -1) {
            kenclaves[index].keid = index; 
            last = index;
            return index;
        }
    }    
    return -1;
}

static void free_keid(int keid)
{
    WARN_ON(keid < 0 || keid >= MAX_ENCLAVES);
    //memset(&(kenclaves[keid]), 0, sizeof(keid_t));
    kenclaves[keid].keid = -1;
    for(int i = 0 ; i<MAX_THREAD; i++){
       kenclaves[keid].tcs[i] = 0;
    }
    kenclaves[keid].enclave = 0;
    kenclaves[keid].secs = 0;
    kenclaves[keid].kin_n = 0;
    kenclaves[keid].kout_n = 0;
    kenclaves[keid].prealloc_ssa = 0;
    kenclaves[keid].prealloc_stack = 0;
    kenclaves[keid].prealloc_heap = 0;
    kenclaves[keid].augged_heap = 0;
    kenclaves[keid].qstat.mode_switch = 0;
    kenclaves[keid].qstat.tlbflush_n = 0;
    kenclaves[keid].qstat.encls_n = 0;
    kenclaves[keid].qstat.ecreate_n = 0;
    kenclaves[keid].qstat.eadd_n = 0;
    kenclaves[keid].qstat.eextend_n = 0;
    kenclaves[keid].qstat.einit_n = 0;
    kenclaves[keid].qstat.eaug_n = 0;
    kenclaves[keid].qstat.enclu_n = 0;
    kenclaves[keid].qstat.eenter_n = 0;
    kenclaves[keid].qstat.eresume_n = 0;
    kenclaves[keid].qstat.eexit_n = 0;
    kenclaves[keid].qstat.egetkey_n = 0;
    kenclaves[keid].qstat.ereport_n = 0;
    kenclaves[keid].qstat.eaccept_n = 0;
}

asmlinkage int sys_create_enclave(long load_p, unsigned int code_pages, 
                                   long tcs_group_p, long sig_p, long token_p, int intel_flag)
{
    //cch: system call parameter passing
    void *load_addr;
    tcs_group_t *tcs_group;
    tcs_t *tcs;
    sigstruct_t *sig;
    einittoken_t *token; 
    unsigned int ntcs; 
    int tcs_page_offset[MAX_THREAD];
    int ssa_page_offset[MAX_THREAD];
    int tls_page_offset[MAX_THREAD];
    int stack_page_offset[MAX_THREAD];
    int code_page_offset;
    int heap_page_offset;
    unsigned long tcs_linaddr[MAX_THREAD];
#ifdef THREAD_PROTECTION
    unsigned long tcs_epcaddr[MAX_THREAD];
#endif
    unsigned long ssa_linaddr[MAX_THREAD];
    unsigned long tls_linaddr[MAX_THREAD];
    unsigned long stack_linaddr[MAX_THREAD];
    unsigned long code_linaddr;
    unsigned long heap_linaddr;
    int ret = -EPERM;
    int eid;

    load_addr = vmalloc(code_pages * sizeof(epc_t));
    tcs_group = vmalloc(sizeof(tcs_group_t));
    sig = vmalloc(sizeof(sigstruct_t));
    token = vmalloc(sizeof(einittoken_t));

    copy_from_user(load_addr, load_p, code_pages * sizeof(epc_t));
    copy_from_user(tcs_group, tcs_group_p, sizeof(tcs_group_t));
    ntcs = tcs_group->n;
    tcs = vmalloc(sizeof(tcs_t) * ntcs);
    copy_from_user(tcs, tcs_group->tcs_array, sizeof(tcs_t) * ntcs);
    copy_from_user(sig, sig_p, sizeof(sigstruct_t));
    copy_from_user(token, token_p, sizeof(einittoken_t));
    
    //      enclave (@eid) w/ npages
    //      |
    //      v
    // EPC: [SECS]{[TCS][SSA][TLS] x n}+[CODE][DATA]+{[STACK] x n}[HEAP][RESV] 
    //
    // Note, npages must be power of 2.
    int sec_npages  = 1;
    int tcs_npages  = 1;
    int ssa_npages  = SSA_PAGE_FRAMES; // XXX: Temporarily set // 
    int tls_npages  = get_tls_npages(tcs);
    int stack_npages = STACK_PAGE_FRAMES_PER_THREAD;
    int heap_npages = HEAP_PAGE_FRAMES;
    int npages = sec_npages + (tcs_npages + ssa_npages + tls_npages + stack_npages) * ntcs \
        + code_pages + heap_npages;
    sgx_dbg(kern, "code pages is %d", code_pages);
    sgx_dbg(kern, "old npages is %d", npages);
    npages = rop2(npages);
    sgx_dbg(kern, "new npages is %d", npages);

    for(int i = 0 ; i < ntcs ; i++){
        if (i == 0){
            tcs_page_offset[i] = sec_npages;
            ssa_page_offset[i] = sec_npages + tcs_npages;
            tls_page_offset[i] = sec_npages + tcs_npages + ssa_npages;
        }
        else{
            tcs_page_offset[i] = tcs_page_offset[i-1] + tcs_npages + ssa_npages + tls_npages;
            ssa_page_offset[i] = ssa_page_offset[i-1] + ssa_npages + tls_npages + tcs_npages;
            tls_page_offset[i] = tls_page_offset[i-1] + tls_npages + tcs_npages + ssa_npages;
        }
    }
    code_page_offset = tls_page_offset[ntcs-1] + tls_npages;
    for(int i = 0; i < ntcs ; i++){
        if (i == 0){
            stack_page_offset[i] = code_page_offset + code_pages + stack_npages;
        }
        else{
            stack_page_offset[i] = stack_page_offset[i-1] + stack_npages;
        }
    }
    heap_page_offset = stack_page_offset[ntcs-1];
    //cch: consider [HEAP][STACK] order later

    eid = alloc_keid();
    kenclaves[eid].kin_n++; 
 
    // full
    if (eid == -1)
        return -EBUSY; // cch modified.  ENODATA or EUSERS can be candidate
    kenclaves[eid].keid = eid; 

    epc_t **reserved_pages = reserve_epc_pages(npages, eid);
    sgx_dbg(info, "DEBUG eid is %d", eid); //cch added
    if (!reserved_pages){
        sgx_dbg(info, "reserve_epc_pages failed");
        goto err1;
    }

    // allocate secs
    int enclave_size = PAGE_SIZE * npages;
    void *enclave_addr = 0x50000000 - 0x1000 * code_page_offset; //cch changed from epc_to_vaddr(enclave);
    sgx_dbg(kern, "npages is %d enclave size: %x", npages, PAGE_SIZE * npages);

    epc_t *secs = ecreate(eid, (uint64_t)enclave_addr, enclave_size, intel_flag);
    if (!secs)
        goto err;
    kenclaves[eid].secs = secs; //cch: sholud I change this to linaddr?
    sgx_dbg(info, "enclave addr: %p (size: 0x%x w/ secs = %p)",
            enclave_addr, enclave_size, epc_to_vaddr(secs));

    for(int i = 0; i < ntcs ; i++){
        tcs_linaddr[i] = enclave_addr + tcs_page_offset[i] * 0x1000;
        ssa_linaddr[i] = enclave_addr + ssa_page_offset[i] * 0x1000;
        tls_linaddr[i] = enclave_addr + tls_page_offset[i] * 0x1000;
        stack_linaddr[i] = enclave_addr + stack_page_offset[i] * 0x1000;
    }
    code_linaddr = enclave_addr + (code_page_offset) * 0x1000;
    heap_linaddr = enclave_addr + (heap_page_offset) * 0x1000;

    // get epc for TCS
    for(int i = 0; i < ntcs; i++){
        epc_t *tcs_epc = get_epc(eid, TCS_PAGE);
        if (!tcs_epc)
            goto err;
#ifdef THREAD_PROTECTION
        tcs_epcaddr[i] = epc_to_vaddr(tcs_epc);
        sgx_dbg(kern, "tcs_epc is %p while tcs_epcaddr[%d]: %p", tcs_epc, i, tcs_epcaddr[i]); //cch added
#endif

        update_tcs_fields(&tcs[i], tls_page_offset[i], ssa_page_offset[i], code_page_offset);
        sgx_dbg(info, "add tcs %p (@%p)", (void *)&tcs[i], (void *)epc_to_vaddr(tcs_epc));
        if (!link_linaddr_with_epc(tcs_linaddr[i], epc_to_vaddr(tcs_epc), PAGE_SHARED))
            goto err;
        save_linaddr_epc_info(tcs_epc, current->mm, tcs_linaddr[i], PAGE_SHARED);
#ifdef THREAD_PROTECTION
        if (!add_page_to_epc(&tcs[i], epc_to_vaddr(tcs_epc), secs, NULL, PT_TCS, tcs_linaddr[i])) {
#else
        if (!add_page_to_epc(&tcs[i], epc_to_vaddr(tcs_epc), secs, PT_TCS, tcs_linaddr[i])) {
#endif
            goto err;
        }

        // allocate SSA pages
        sgx_dbg(info, "add ssa pages: %p (%d pages)",
                empty_page, ssa_npages);
#ifdef THREAD_PROTECTION
        sgx_dbg(kern, "tcs_epc for ssa of thread %d is %p", i, tcs_epc); //cch added
        if (!add_empty_pages_to_epc(eid, ssa_npages, secs, tcs_epc, REG_PAGE, PT_REG, MT_SSA, ssa_linaddr[i])){
#else
        if (!add_empty_pages_to_epc(eid, ssa_npages, secs, REG_PAGE, PT_REG, MT_SSA, ssa_linaddr[i])){
#endif
            printk("failed to add pages\n");
            goto err;
        }
        kenclaves[eid].prealloc_ssa += ssa_npages * PAGE_SIZE;

        // allocate TLS pages
        sgx_dbg(info, "add tls (fs/gs) pages: %p (%d pages)",
                empty_page, tls_npages);
        sgx_dbg(kern, "stack linaddr before add_tls %d : %p", i, stack_linaddr[i]); 
#ifdef THREAD_PROTECTION
        if (!add_tls_pages_to_epc(eid, tls_npages, secs, tcs_epc, REG_PAGE, PT_REG, tls_linaddr[i], stack_linaddr[i])){
#else
        if (!add_tls_pages_to_epc(eid, tls_npages, secs, REG_PAGE, PT_REG, tls_linaddr[i], stack_linaddr[i])){
#endif
            printk("failed to add pages\n");
            goto err;
        }
    }

    // allocate code pages
    sgx_dbg(info, "add target code/data: %p (%d pages)",
            load_addr, code_pages);
#ifdef THREAD_PROTECTION
    if (!add_pages_to_epc(eid, load_addr, code_pages, secs, NULL, REG_PAGE, PT_REG, code_linaddr)){
#else
    if (!add_pages_to_epc(eid, load_addr, code_pages, secs, REG_PAGE, PT_REG, code_linaddr)){
#endif
        printk("failed to add pages\n");
        goto err;
    }

    // allocate heap pages cch changed the order between heap and stack
    sgx_dbg(info, "add heap pages: %p (%d pages)",
            empty_page, heap_npages);
#ifdef THREAD_PROTECTION
    if (!add_empty_pages_to_epc(eid, heap_npages, secs, NULL, REG_PAGE, PT_REG, MT_HEAP, heap_linaddr)){
#else
    if (!add_empty_pages_to_epc(eid, heap_npages, secs, REG_PAGE, PT_REG, MT_HEAP, heap_linaddr)){
#endif
        printk("failed to add pages");
        goto err;
    }
    kenclaves[eid].prealloc_heap = heap_npages * PAGE_SIZE;

    for(int i = 0 ; i < ntcs ; i++){
        // allocate stack pages
        sgx_dbg(info, "add stack pages: %p (%d pages)",
                empty_page, stack_npages);
#ifdef THREAD_PROTECTION
        sgx_dbg(kern, "tcs_epcaddr[%d]: %p", i, tcs_epcaddr[i]); //cch added
        if (!add_empty_pages_to_epc(eid, stack_npages, secs, tcs_epcaddr[i], REG_PAGE, PT_REG, MT_STACK, stack_linaddr[i])){
#else
        if (!add_empty_pages_to_epc(eid, stack_npages, secs, REG_PAGE, PT_REG, MT_STACK, stack_linaddr[i])){
#endif
            printk("failed to add pages\n");
            goto err;
        }
        kenclaves[eid].prealloc_stack += stack_npages * PAGE_SIZE;
    }

    // dump sig structure
    //{
    //    char *msg = dbg_dump_sigstruct(sig);
    //    sgx_dbg(info, "sigstruct:\n%s", msg);
    //    vfree(msg);
    //}

    if (init_enclave(secs, sig, token))
        goto err;


    // commit
    ret = eid;

    // remove reserved pages
    free_reserved_epc_pages(eid);

    dbg_dump_epc();

    // update per-enclave info
    for(int i = 0 ; i<ntcs ; i++){
        kenclaves[eid].tcs[i] = tcs_linaddr[i]; //cch modified from epc_to_vaddr(tcs_epc); 
    }
    kenclaves[eid].enclave = enclave_addr; //cch: what's the usage for this?

    kenclaves[eid].kout_n++;

    vfree(tcs_group);
    vfree(load_addr);
    vfree(tcs);
    vfree(sig);
    vfree(token);
    kfree(reserved_pages);
    return ret;

 err:
    free_epc_pages(eid);
    kfree(reserved_pages);
 err1:
    vfree(tcs_group);
    vfree(load_addr);
    vfree(tcs);
    vfree(sig);
    vfree(token);
    kenclaves[eid].kout_n++;

    return -ENOMEM;  //cch modified
}

asmlinkage int sys_destroy_enclave(int keid){
    if (keid < 0 || keid >= MAX_ENCLAVES) {
        return -EPERM;  
    }    

    sgx_dbg(kern, "keid to destory is %d", keid);
    int i = 0;
    epc_t *page_to_remove;
    page_to_remove = find_epc(keid);
    while( page_to_remove != NULL ){
        //free EPC pages with EREMOVE
        //sgx_dbg(kern, "page_to_remove is %p", page_to_remove);
        EREMOVE(page_to_remove); 
        //free g_epc_info with put_epc
        put_epc(page_to_remove);
        page_to_remove = find_epc(keid);
        i++;
    }
    sgx_dbg(kern, "The number of removed EPC page is %d", i);

    free_keid(keid);
    return 0; 
}

static
void print_eid_stat(keid_t stat) {
     printk("--------------------------------------------\n");
     printk("kern in count\t: %d\n",stat.kin_n);
     printk("kern out count\t: %d\n",stat.kout_n);
     printk("--------------------------------------------\n");
     printk("encls count\t: %d\n",stat.qstat.encls_n);
     printk("ecreate count\t: %d\n",stat.qstat.ecreate_n);
     printk("eadd count\t: %d\n",stat.qstat.eadd_n);
     printk("eextend count\t: %d\n",stat.qstat.eextend_n);
     printk("einit count\t: %d\n",stat.qstat.einit_n);
     printk("eaug count\t: %d\n",stat.qstat.eaug_n);
     printk("--------------------------------------------\n");
     printk("enclu count\t: %d\n",stat.qstat.enclu_n);
     printk("eenter count\t: %d\n",stat.qstat.eenter_n);
     printk("eresume count\t: %d\n",stat.qstat.eresume_n);
     printk("eexit count\t: %d\n",stat.qstat.eexit_n);
     printk("egetkey count\t: %d\n",stat.qstat.egetkey_n);
     printk("ereport count\t: %d\n",stat.qstat.ereport_n);
     printk("eaccept count\t: %d\n",stat.qstat.eaccept_n);
     printk("--------------------------------------------\n");
     printk("mode switch count : %d\n",stat.qstat.mode_switch);
     printk("tlb flush count\t: %d\n",stat.qstat.tlbflush_n);
     printk("--------------------------------------------\n");
     printk("Pre-allocated EPC SSA region\t: 0x%lx\n",stat.prealloc_ssa);
     printk("Pre-allocated EPC Heap region\t: 0x%lx\n",stat.prealloc_heap);
     printk("Later-Augmented EPC Heap region\t: 0x%lx\n",stat.augged_heap);
     long total_epc_heap = stat.prealloc_heap + stat.augged_heap;
     printk("Total EPC Heap region\t: 0x%lx\n",total_epc_heap);
}



asmlinkage int sys_stat_enclave(int keid, long stat_p)
{
    if (keid < 0 || keid >= MAX_ENCLAVES) {
        return -EPERM;  
    }
    //*stat = kenclaves[keid];
    if (stat_p == NULL) {
        return -EPERM;  
    }

    kenclaves[keid].kin_n++;
    encls_stat(keid, &(kenclaves[keid].qstat));
    //print_eid_stat(kenclaves[keid]); //cch test
    kenclaves[keid].kout_n++;

    copy_to_user(stat_p, &(kenclaves[keid]), sizeof(keid_t));

    return 0; 
}

asmlinkage unsigned long sys_add_epc(int keid) {
    kenclaves[keid].kin_n++;
    unsigned long linaddr = heap_end;
    epc_t *secs = kenclaves[keid].secs;

    epc_t *free_epc_page = alloc_epc_page(keid);
    if (free_epc_page == NULL) {
        kenclaves[keid].kout_n++;
        return 0;
    }   

    epc_t *epc = get_epc(keid, (uint64_t)REG_PAGE);
    if (!epc) {
        sgx_dbg(kern, "get_epc failed"); //cch added
        kenclaves[keid].kout_n++;
        return 0;
    }   
    sgx_dbg(kern, "aug linaddr %p", linaddr);
    if(!link_linaddr_with_epc(linaddr, epc_to_vaddr(epc), PAGE_SHARED)){
        sgx_dbg(kern, "link_linaddr_with_epc failed"); 
        return false;
    }
    save_linaddr_epc_info(epc, current->mm, linaddr, PAGE_SHARED);
#ifdef THREAD_PROTECTION
    if (!aug_page_to_epc(epc, secs, NULL, linaddr)) {
#else
    if (!aug_page_to_epc(epc, secs, linaddr)) {
#endif
        sgx_dbg(kern, "aug_page_to_epc failed"); //cch added
        kenclaves[keid].kout_n++;
        return 0;
    }   
    heap_end = heap_end + 0x1000;
    kenclaves[keid].augged_heap += PAGE_SIZE;
    kenclaves[keid].kout_n++;
    return linaddr;//cch changed. instead of returning epc, I think process virtual address of epc should be returned.
}

asmlinkage unsigned long sys_restrict_epc_perm(int keid, int order, int perm) {

    kenclaves[keid].kin_n++; 

    // epc address 
    epc_t *epc = kenclaves[keid].enclave + (0x1000 *order); 
    if (!epc) {
        sgx_dbg(kern, "get_epc failed"); //cch added
        kenclaves[keid].kout_n++;
        return false;
    } 

    bool rp = (perm >= 4);
    bool wp = ((perm % 4) >= 2) ;
    bool xp = ((perm % 2) == 1) ;

    printk("secinfo permission: %d, %d, %d, %d\n", perm, rp, wp, xp);
    // secinfo 
    secinfo_t *secinfo = alloc_secinfo( rp, wp, xp, PT_SECS ); 
    if (!secinfo ) {
        printk("failed to allocate secinfo\n");
        return false; 
    }
    else {
        printk("successed to allocate secinfo");
    }
 
    // encls 
    EMODPR( secinfo, epc );
   
    kenclaves[keid].kout_n++; 

    return true;
}

asmlinkage unsigned long sys_change_epc_type(int keid, int addr, int type) {

    uint64_t linaddr = 0;
    struct mm_struct *mm;
    pgprot_t pgprot;

    kenclaves[keid].kin_n++; 

    // when epc address is parameter-based 
    epc_t *epc = addr; 
    // when epc address is order-based 
    //epc_t *epc = kenclaves[keid].enclave + (0x1000 *order); 

    if (!epc) {
        sgx_dbg(kern, "get_epc failed"); //cch added
        kenclaves[keid].kout_n++;
        return false;
    } 
    printk("EMODT : epc addr %p\n", epc);

    printk("secinfo EPC type: %d\n", type);
    // secinfo 
    secinfo_t *secinfo = alloc_secinfo( true, true, true, type ); 
    if (!secinfo ) {
        printk("failed to allocate secinfo\n");
        return false; 
    }
    else {
        printk("successed to allocate secinfo");
    }
 
    // encls 
    EMODT( secinfo, epc );
 
    restore_linaddr_epc_info(epc, &mm, &linaddr, &pgprot);
 
    printk("EMODT : pending_page addr %p\n", linaddr);
    kenclaves[keid].kout_n++; 
    
    // when epc address is parameter-based 
    return addr;
    // when epc address is order-based 
    //return linaddr;
}
