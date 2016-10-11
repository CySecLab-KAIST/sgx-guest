#include <sgx-utils.h>
#include <linux/kernel.h>
#include <linux/vmalloc.h>

unsigned char *swap_endian(unsigned char *in, size_t bytes)
{
    unsigned char *out;
    int i;

    out = vmalloc(bytes);
    for (i = 0; i < bytes; i++) {
        out[i] = in[bytes - i - 1];
    }

    return out;
}

char *fmt_bytes(uint8_t *bytes, int size)
{
    char *buf = vmalloc(size*2 + 1);
    if (!buf)
        return NULL;

    for (int i = 0; i < size; i ++)
        snprintf(&buf[i*2], 3, "%02X", *(bytes + i));

    buf[size*2] = '\0';
    return buf;
}

char *dbg_dump_sigstruct(sigstruct_t *s)
{
    char *msg = vmalloc(2048);
    if (!msg)
        return NULL;

    char *hdr           = fmt_bytes(swap_endian(s->header, 16), 16);
    char *vendor        = fmt_bytes(swap_endian((unsigned char *)&s->vendor, 4), 4);
    char *date          = fmt_bytes(swap_endian((unsigned char *)&s->date, 4), 4);
    char *hdr2          = fmt_bytes(swap_endian(s->header2, 16), 16);
    char *swid          = fmt_bytes(swap_endian((unsigned char *)&s->swdefined, 4), 4);
    char *rsv1          = fmt_bytes(s->reserved1, 32);
    char *pub           = fmt_bytes(s->modulus, 32);
    char *ext           = fmt_bytes(swap_endian((unsigned char *)&s->exponent, 4), 4);
    char *sig           = fmt_bytes(s->signature, 32);
    char *mselect_rsv2  = fmt_bytes(s->miscselect.reserved2, 3);
    char *mmasck_rsv2   = fmt_bytes(s->miscmask.reserved2, 3);
    char *rsv2          = fmt_bytes(s->reserved2, 20);
    char *attrs_rsv4    = fmt_bytes(s->attributes.reserved4, 7);
    char *attrs_xfrm    = fmt_bytes(swap_endian((unsigned char *)&s->attributes.xfrm, 8), 8);
    char *attrmask_rsv4 = fmt_bytes(s->attributeMask.reserved4, 7);
    char *attrmask_xfrm = fmt_bytes(swap_endian((unsigned char *)&s->attributeMask.xfrm, 8), 8);
    char *hash          = fmt_bytes(s->enclaveHash, 32);
    char *rsv3          = fmt_bytes(s->reserved3, 32);
    char *prodid        = fmt_bytes(swap_endian((unsigned char *)&s->isvProdID, 2), 2);
    char *svn           = fmt_bytes(swap_endian((unsigned char *)&s->isvSvn, 2), 2);
    char *rsv4          = fmt_bytes(s->reserved4, 12);
    char *q1            = fmt_bytes(s->q1, 32);
    char *q2            = fmt_bytes(s->q2, 32);

    snprintf(msg, 2048,"\
HEADER        : %s\n\
VENDOR        : %s\n\
DATE          : %s\n\
HEADER2       : %s\n\
SWDEFINO      : %s\n\
RESERVED1     : %s..\n\
MODULUS       : %s..\n\
EXPONENT      : %s\n\
SIGNATURE     : %s..\n\
MISCSELECT\n\
.EXINFO       : %d\n\
.RESERVED     : %d%s\n\
MISCMASK\n\
.EXINFO       : %d\n\
.RESERVED     : %d%s\n\
RESERVED2     : %s\n\
ATTRIBUTES\n\
.RESERVED1    : %d\n\
.DEBUG        : %d\n\
.MODE64BIT    : %d\n\
.RESERVED2    : %d\n\
.PROVISIONKEY : %d\n\
.EINITTOKENKEY: %d\n\
.RESERVED3    : %d%s\n\
.XFRM         : %s\n\
ATTRIBUTEMASK\n\
.RESERVED1    : %d\n\
.DEBUG        : %d\n\
.MODE64BIT    : %d\n\
.RESERVED2    : %d\n\
.PROVISIONKEY : %d\n\
.EINITTOKENKEY: %d\n\
.RESERVED3    : %d%s\n\
.XFRM         : %s\n\
ENCLAVEHASH   : %s\n\
RESERVED3     : %s\n\
ISVPRODID     : %s\n\
ISVSVN        : %s\n\
RESERVED4     : %s\n\
Q1            : %s..\n\
Q2            : %s..",
            hdr,
            vendor,
            date,
            hdr2,
            swid,
            rsv1,
            pub,
            ext,
            sig,
            s->miscselect.exinfo,
            s->miscselect.reserved1, mselect_rsv2,
            s->miscmask.exinfo,
            s->miscmask.reserved1, mmasck_rsv2,
            rsv2,
            s->attributes.reserved1,
            s->attributes.debug,
            s->attributes.mode64bit,
            s->attributes.reserved2,
            s->attributes.provisionkey,
            s->attributes.einittokenkey,
            s->attributes.reserved3, attrs_rsv4,
            attrs_xfrm,
            s->attributeMask.reserved1,
            s->attributeMask.debug,
            s->attributeMask.mode64bit,
            s->attributeMask.reserved2,
            s->attributeMask.provisionkey,
            s->attributeMask.einittokenkey,
            s->attributeMask.reserved3, attrmask_rsv4,
            attrmask_xfrm,
            hash,
            rsv3,
            prodid,
            svn,
            rsv4,
            q1,
            q2);

    vfree(hdr);
    vfree(vendor);
    vfree(date);
    vfree(hdr2);
    vfree(rsv1);
    vfree(swid);
    vfree(pub);
    vfree(ext);
    vfree(sig);
    vfree(mselect_rsv2);
    vfree(mmasck_rsv2);
    vfree(rsv2);
    vfree(attrs_rsv4);
    vfree(attrs_xfrm);
    vfree(attrmask_rsv4);
    vfree(attrmask_xfrm);
    vfree(hash);
    vfree(rsv3);
    vfree(prodid);
    vfree(svn);
    vfree(rsv4);
    vfree(q1);
    vfree(q2);

    return msg;
}

void hexdump(void *addr, int len)
{
    int i;
    unsigned char buff[17];
    unsigned char *pc = (unsigned char*)addr;

    // Process every byte in the data.
    for (i = 0; i < len; i++) {
        // Multiple of 16 means new line (with line offset).

        if ((i % 16) == 0) {
            // Just don't print ASCII for the zeroth line.
            if (i != 0)
                printk("  %s\n", buff);

            // Output the offset.
            printk("  %04x ", i);
        }

        // Now the hex code for the specific character.
        printk(" %02x", pc[i]);

        // And store a printable ASCII character for later.
        if ((pc[i] < 0x20) || (pc[i] > 0x7e))
            buff[i % 16] = '.';
        else
            buff[i % 16] = pc[i];
        buff[(i % 16) + 1] = '\0';
    }

    // Pad out last line if not exactly 16 characters.
    while ((i % 16) != 0) {
        printk("   ");
        i++;
    }

    // And print the final ASCII bit.
    printk("  %s\n", buff);
}

// NOTE. arg/ret should be unsigned int, but current code in sgx-*
// don't properly distinguish signed/unsigned
int rop2(int val)
{
    unsigned int n = 1;
    while (n < val)
        n <<= 1;
    return n;
}
