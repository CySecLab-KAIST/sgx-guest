#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/sched.h> //cch: for current macro
#include <asm/unistd.h>
#include <asm/page.h>
#include <sgx-module.h>
#include <sgx-dbg.h>
#include <sgx-kern.h>  //cch: for follow_pte
#include <sgx-kern-epc.h>
#include <sgx-shared.h>

//Pointers to re-mapped writable pages
unsigned int** sct;
unsigned long ptr_idt_table;
unsigned long old_page_fault_stub = PAGE_FAULT; //page_fault 
unsigned long old_page_fault_handler = DO_PAGE_FAULT; //do_page_fault
unsigned long fault_address;

static int fault_in_enclave_space(unsigned long address)
{
     return (address >= ENCLAVE_BASE && address <= ENCLAVE_LIMIT);
}

static void disable_page_protection(void)
{
    unsigned long value;
    asm volatile("mov %%cr0,%0":"=r"(value));
    if(value & 0x00010000)
    {
         value &= ~0x00010000;
         asm volatile("mov %0,%%cr0"::"r"(value));
    }
}

static void enable_page_protection(void)
{
    unsigned long value;
    asm volatile("mov %%cr0,%0":"=r"(value));
    if(!(value & 0x00010000))
    {
         value |= 0x00010000;
         asm volatile("mov %0,%%cr0"::"r"(value));
    }
}

int __hook(struct pt_regs *regs, unsigned long error_code){
    pte_t *ptep = NULL;
    spinlock_t *ptl;
    int ret;
    fault_address = read_cr2();
    //printk("cch debug error_code is %d\n", error_code);
    if(fault_in_enclave_space(fault_address)){
        sgx_dbg(kern, "cch debug cr2 address is %p", fault_address);
        ret = follow_pte(current->mm, fault_address, &ptep, &ptl);
        if(ret){
            sgx_dbg(kern, "follow_pte failed, and ret is %d", ret);
            return -1;
        }
        sgx_dbg(kern, "ptep is %p", ptep);
        sgx_dbg(kern, "ptep contents is %p", *ptep);
        va_entry_t va_entry = pte_to_va_entry(*ptep); 
        if(!is_va_entry(va_entry)){
           sgx_dbg(kern, "ptep is not va entry");
           pte_unmap_unlock(ptep, ptl);
           return -1;
        }
        unsigned long va_addr = va_address(va_entry);
        int va_idx = va_index(va_entry);
        unsigned long va_slot_addr = va_addr + va_idx * VA_SLOT_SIZE;
        ret = handle_fault_with_eld(va_slot_addr, &va_info_head, &ptep);
        if (ret == 0){ 
             sgx_dbg(kern, "handle fault with eld failed");
        }
        sgx_dbg(kern, "handle fault with eld succeeded");
        pte_unmap_unlock(ptep, ptl);
        return 1;
    }
    return 0;
}

__attribute__((regparm(2))) hook(struct pt_regs *regs, unsigned long error_code){
    void (*old_fn)(struct pt_regs *, long) = (void *)old_page_fault_handler;
    int ret = __hook(regs, error_code);
    if(ret == 0)
       (*old_fn)(regs, error_code);

    return;
}

extern asmlinkage void our_page_fault_stub(void);

void simple_hexdump(char* p, int len){
    int i;
    for(i=0; i<len; i++){
        printk("%02x", (unsigned char)p[i]);
    }
    printk("\n");
}

unsigned long get_idt( void ) {
   unsigned char idtr[10];
   unsigned long idt;

   __asm__ __volatile__("sidt %0": "=m" (idtr));
   idt = *((unsigned long *)&idtr[2]);
   printk("cch debug idt base is %p\n", idt);
   return(idt);
}

void grab_excep(int n, void *new_fn){
   unsigned long new_addr = (unsigned long)new_fn;
   struct descr_struct *idt = (struct descr_struct *)ptr_idt_table;
   unsigned long old_addr = ((unsigned long)(idt[n].off_hi) << 32) + (idt[n].off_mid << 16)+ idt[n].off_lo;

   int x;
   sgx_dbg(kern, "cch debug new_addr %p contents", new_addr);
   simple_hexdump(new_addr, 70);
   sgx_dbg(kern, "cch debug old_addr %p", old_addr);
   //simple_hexdump(old_addr, 70);

   idt[n].off_hi = (uint32_t)(new_addr >> 32);   //cch temporarily disabled
   idt[n].off_mid = (uint16_t)(new_addr >> 16);
   idt[n].off_lo = (uint16_t)(new_addr & 0x0000FFFF);

   return;
}

static int __init initmodule(void ){
    ptr_idt_table = get_idt();
    char* ptr = &our_page_fault_stub;

    // get SCT
    sct = (unsigned int**)SYS_CALL_TABLE;
    sgx_dbg(kern, "&SCT[NR_SYS_SGXINIT] = %p, SCT[NR_SYS_SGXINIT] = %p", &sct[NR_SYS_SGXINIT], sct[NR_SYS_SGXINIT] );

    //set_page_rw(sct);
    disable_page_protection();
    // hook system call table
    sct[NR_SYS_RESTRICT_EPC_PERM] = sys_restrict_epc_perm;
    sct[NR_SYS_CHANGE_EPC_TYPE] = sys_change_epc_type;
    sct[NR_SYS_CREATE_ENCLAVE] = sys_create_enclave;
    sct[NR_SYS_STAT_ENCLAVE] = sys_stat_enclave;
    sct[NR_SYS_ADD_EPC] = sys_add_epc;
    sct[NR_SYS_GET_ENCLAVE_HEAP] = sys_get_enclave_heap;
    sct[NR_SYS_DESTROY_ENCLAVE] = sys_destroy_enclave;
    // hook page fault handler
    grab_excep(14, ptr);
    enable_page_protection();
    sgx_dbg(kern, "Hook completes.");

    system_sgx_init();
    sgx_dbg(kern, "system_sgx_init completes.");

    return 0;
}

static void __exit exitmodule(void ){
    system_sgx_exit();
    disable_page_protection();
    grab_excep(14, (char *)old_page_fault_stub);
    enable_page_protection();
    sgx_dbg(kern,"system_sgx_exit completes. BYE");
    return;
}

MODULE_LICENSE("GPL");
module_init( initmodule );
module_exit( exitmodule );

/* my Assembly handler */
void my_dummy(void)
{
    __asm__ (
        ".globl our_page_fault_stub    \n\t"
        ".align 4, 0x90     \n\t"
        "our_page_fault_stub:      \n\t"
//    ".byte 0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90\n\t"
//    ".byte 0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90\n\t"
        ".byte 0x66\n\t"
        ".byte 0x66\n\t"
        ".byte 0x90\n\t"
        ".byte 0x66\n\t"
        ".byte 0x0f\n\t"
        ".byte 0x1f\n\t"
        ".byte 0x44\n\t"
        ".byte 0x00\n\t"
        ".byte 0x00\n\t"
        "sub $0x78, %%rsp\n\t"
        "call 0xffffffff8174b640\n\t"  //NOTICE: need to be adjusted for your environment. cat /proc/kallsyms | grep ERROR_ENTRY
        "movq %%rsp, %%rdi\n\t"
        "movq 0x78(%%rsp), %%rsi\n\t"
        "movq $-1, 0x78(%%rsp)\n\t"
        "call hook\n\t"
        "jmp 0xffffffff8174b6f0\n\t"   //NOTICE: need to be adjusted for your environment. cat /proc/kallsyms | grep ERROR_EXIT
        ".byte 0x0f\n\t"
        ".byte 0x1f\n\t"
        ".byte 0x00\n\t"
         ::);
}

