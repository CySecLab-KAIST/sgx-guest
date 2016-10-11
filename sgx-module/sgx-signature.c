#include <sgx-utils.h>
#include <sgx-signature.h>

uint8_t get_tls_npages(tcs_t *tcs) {
    return(to_npages(tcs->fslimit + 1) +
           to_npages(tcs->gslimit + 1));
}

// Update the TCS Fields in Kernel module.
void update_tcs_fields(tcs_t *tcs, int tls_page_offset, int ssa_page_offset, int code_page_offset)
{
    uint64_t tls_offset = tls_page_offset * PAGE_SIZE;
    uint64_t ssa_offset = ssa_page_offset * PAGE_SIZE;
    uint64_t code_offset = code_page_offset * PAGE_SIZE;

    tcs->ofsbasgx += tls_offset;
    tcs->ogsbasgx += tls_offset;
    tcs->oentry   += code_offset;

    tcs->ossa = ssa_offset;
}
