#include <stdio.h>
#include <sys/types.h>
#include <assert.h>
#include <string.h>
#include <malloc.h>
#include <err.h>
#include <errno.h> //cch added
#include <stdint.h>
#include <sgx-user.h>
#include <sgx-shared.h>
#include <sgx-utils.h>
#include <sgx-loader.h>
#include <sgx-signature.h>
#include <polarssl/sha256.h>
#include <signal.h>
#include <fenv.h> //cch added for x87fp exception
#include <pthread.h>

//#define THREAD_ATTACK //harpuia: I think this is NEVER the place to insert such a parameter... moved to sgx-shared.h for now
//#define THREAD_ATTACK2

pthread_t tid[NUMBER_OF_THREADS];

typedef struct {
    int ntcs;
    tcs_t **tcs;    
} threadParam_t;

void *doSomeThing(void *context)
{
    threadParam_t *threadParam = context;
    tcs_t **tcs = threadParam->tcs;
    int ntcs = threadParam->ntcs;
    pthread_t id = pthread_self();
    int i = 0;
    int my_index = 0;

    for (; i < ntcs; i++){
        if(pthread_equal(id, tid[i]))
        {
            my_index = i;
            break;
        }
    }

    if (!tcs[my_index])
        err(1, "failed to run enclave");

    void (*aep)() = exception_handler;

    sgx_enter(tcs[my_index], aep);

    return NULL;
}

static void
sigHandler(int signo)
{
    if (signo == SIGFPE){
        printf("Divided by Zero occurs!\n");
    }
    else if (signo == SIGILL){
        printf("Illegal Instruction occurs!\n");
    }
}

int syscall_template(int syscall_n, int arg0, int arg1, int arg2, int arg3, int arg4, int arg5){
    int ret;
    asm volatile
    (
        "movl %%ebx, %%r10d\n\t"
        "movl %%ecx, %%r8d\n\t"
        "movl %%eax, %%r9d\n\t"
        "movl $0xb6, %%eax\n\t" //NR_SYS_TEMPLATE syscall number 182
        "syscall"
        :"=a"(ret)
        :"0"(arg5), "D"(arg0), "S"(arg1), "d"(arg2), "b"(arg3), "c"(arg4)  
        :"cc","r11","memory"
    );
}

// (ref re:2.13, EINIT/p88)
// Set up sigstruct fields require to be signed.
static
sigstruct_t *alloc_sigstruct(void)
{
    sigstruct_t *s = memalign(PAGE_SIZE, sizeof(sigstruct_t));
    if (!s)
        return NULL;

    // Initializate with 0s
    memset(s, 0, sizeof(sigstruct_t));

    // HEADER(16 bytes)
    uint8_t header[16] = SIG_HEADER1;
    memcpy(s->header, swap_endian(header, 16), 16);

    // VENDOR(4 bytes)
    // Non-Intel Enclave;
    s->vendor = 0x00000000;

    // DATE(4 bytes)
    s->date = 0x20150101;

    // HEADER2(16 bytes)
    uint8_t header2[16] = SIG_HEADER2;
    memcpy(s->header2, swap_endian(header2, 16), 16);

    // SWDEFINTO(4 bytes)
    s->swdefined = 0x00000000;

    // MISCSELECT(4 bytes)
    //s->miscselect = 0x0;

    // MISCMASK(4 bytes)
    //s->miscmask = 0x0;

    // ATTRIBUTES(16 bytes)
    memset(&s->attributes, 0, sizeof(attributes_t));
    s->attributes.mode64bit = true;
    s->attributes.provisionkey = true;
    s->attributes.einittokenkey = false;
    s->attributes.xfrm = 0x03;

    // ATTRIBUTEMAST(16 bytes)
    memset(&s->attributeMask, 0 ,sizeof(attributes_t));
    s->attributeMask.mode64bit = true;
    s->attributeMask.provisionkey = true;
    s->attributeMask.einittokenkey = false;
    s->attributeMask.xfrm = 0x03;

    // ISVPRODID(2 bytes)
    s->isvProdID = 0x0001;

    // ISVSVN(2 bytes)
    s->isvSvn = 0x0001;

    return s;
}

// (ref re:2.13)
// Fill the fields not required for signature after signing.
static
void update_sigstruct(sigstruct_t *sigstruct, rsa_key_t pubkey, rsa_sig_t sig)
{
    // MODULUS (384 bytes)
    memcpy(sigstruct->modulus, pubkey, sizeof(rsa_key_t));

    // EXPONENT (4 bytes)
    sigstruct->exponent = SGX_RSA_EXPONENT;

    // SIGNATURE (384 bytes)
    memcpy(sigstruct->signature, sig, sizeof(rsa_sig_t));

    // TODO: sig->q1 = floor(signature^2 / modulus)
    //       sig->q2 = floor((signature^3 / modulus) / modulus)
}

// Set up einittoken fields require to be signed.
static
einittoken_t *alloc_einittoken(rsa_key_t pubkey, sigstruct_t *sigstruct)
{
    einittoken_t *t = memalign(EINITTOKEN_ALIGN_SIZE, sizeof(einittoken_t));
    if (!t)
        return NULL;

    // Initializate with 0s
    memset(t, 0, sizeof(einittoken_t));

    // VALID(4 bytes)
    t->valid = 0x00000001;

    // ATTRIBUTES(16 bytes)
    memset(&t->attributes, 0, sizeof(attributes_t));
    t->attributes.mode64bit = true;
    t->attributes.provisionkey = true;
    t->attributes.einittokenkey = false;
    t->attributes.xfrm = 0x03;

    // MRENCLAVE(32 bytes)
    memcpy(&t->mrEnclave, &sigstruct->enclaveHash, sizeof(t->mrEnclave));

    // MRSIGNER(32 bytes)
    sha256(pubkey, KEY_LENGTH, (unsigned char *)&t->mrSigner, 0);

    return t;
}

int main(int argc, char **argv){

    char *binary;
    char *conf;
    void *entry;
    void *base_addr;
    size_t npages;
    size_t ntcs;
    unsigned int entry_offset[NUMBER_OF_THREADS];
    int enclave_id;
    int toff;
    extern int errno; //cch added
    int ret = 0;
    int i = 0;

    if (argc < 2) {
        err(1, "Please specifiy binary to load\n");
    }   
    binary = argv[1];

    if (argc > 1) {
        conf = argv[2];
    } else {
        conf = NULL;
    }   

    ret = sgx_init();
    if(ret < 0){
        errno = -ret;
        err(1, "failed to init sgx");
    }

    base_addr = load_elf_enclave(binary, &npages, &entry, &toff);
    printf("baseaddr is %p\n", base_addr); //cch : test for debug
    if (base_addr == NULL) {
        err(1, "Please provide valid binary/configuration files.");
    }

    if(feenableexcept (FE_ALL_EXCEPT) != 0)
        err(1, "feenableexcept not succeeds");
    
    struct sigaction act;
    act.sa_handler = sigHandler;
    sigaction(SIGFPE, &act, 0);
    sigaction(SIGILL, &act, 0);

    ntcs = NUMBER_OF_THREADS;
    for(i = 0 ; i < ntcs ; i++){
        entry_offset[i] = (uint64_t)entry - (uint64_t)base_addr;
        printf("entry_offset[%d]: %p\n", i, entry_offset[i]);
    }
#ifdef THREAD_ATTACK
    entry_offset[1] = 0x10c;
#endif
#ifdef THREAD_ATTACK2
    entry_offset[1] = 0x4a3;
#endif

    tcs_t **tcs = init_enclave(base_addr, entry_offset, npages, ntcs, conf, &enclave_id);

    threadParam_t threadParam;
    threadParam.ntcs = ntcs;
    threadParam.tcs = tcs;

    i = 0;
    while(i < ntcs)
    {
        ret = pthread_create(&(tid[i]), NULL, &doSomeThing, &threadParam);
        if (ret != 0)
            printf("\ncan't create thread :[%s]", strerror(ret));
        else
            printf("\nThread created successfully \n");
        i++;
    } 
    for(i=0 ; i < ntcs ; i++){
        pthread_join(tid[i], NULL);
    }
    //sys_destroy_enclave(enclave_id);
   
    return 0;
}
