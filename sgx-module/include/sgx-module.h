/*
NOTE: system call address is found by following command
./boot sudo cat System.map-3.13.0-32-generic | grep -e "sys_call_table"
NOTE: exception addresses are found by following commands
root@ubuntu:~/tmp/kernel# cat /proc/kallsyms | T page_fault
root@ubuntu:~/tmp/kernel# cat /proc/kallsyms | T do_page_fault
root@ubuntu:~/tmp/kernel# cat /proc/kallsyms | T error_entry
root@ubuntu:~/tmp/kernel# cat /proc/kallsyms | T error_exit
*/
#define SGX_KERNEL
#define SYS_CALL_TABLE          0xffffffff81801420 
#define PAGE_FAULT              0xffffffff8174b480
#define DO_PAGE_FAULT           0xffffffff8174f350
#define ERROR_ENTRY             0xffffffff8174b640
#define ERROR_EXIT              0xffffffff8174b6f0
/* 
    NOTE : System call entries 180~185 are unused in x64 
*/
#define ENCLAVE_BASE 0x50000000 - 0x1000 * 256  //cch:temporarily set
#define ENCLAVE_LIMIT 0x50000000 + 0x1000 * 512 //cch:temporarily set

struct descr_struct {
   uint16_t off_lo, seg_sel;
   uint8_t reserved,flag;
   uint16_t off_mid;
   uint32_t off_hi;
   uint32_t reserved_big;
};

enum x86_pf_error_code {
        PF_PROT         =               1 << 0,
        PF_WRITE        =               1 << 1,
        PF_USER         =               1 << 2,
        PF_RSVD         =               1 << 3,
        PF_INSTR        =               1 << 4,
};

extern int system_sgx_init(void);
extern int system_sgx_exit(void);
extern asmlinkage int sys_create_enclave(long base_p, unsigned int code_pages,
                                    long tcs_p, long sig_p, long token_p, int intel_flag);
extern asmlinkage int sys_stat_enclave(int keid, long stat_p);
extern asmlinkage unsigned long sys_add_epc(int keid);
extern asmlinkage unsigned long sys_restrict_epc_perm(int keid, int order, int perm);
extern asmlinkage unsigned long sys_change_epc_type(int keid, int order, int type);
extern asmlinkage int sys_get_enclave_heap(long heap_begin_userp, long heap_end_userp);
extern asmlinkage int sys_destroy_enclave(int keid);

