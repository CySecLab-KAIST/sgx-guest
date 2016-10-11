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

#include "test.h"
#include <polarssl/aes.h>

int unhexify(unsigned char *obuf, const char *ibuf)
{
    unsigned char c, c2;
    int len = strlen(ibuf) / 2;
    assert(!(strlen(ibuf) %1)); // must be even number of bytes

    while (*ibuf != 0)
    {
        c = *ibuf++;
        if( c >= '0' && c <= '9' )
            c -= '0';
        else if( c >= 'a' && c <= 'f' )
            c -= 'a' - 10;
        else if( c >= 'A' && c <= 'F' )
            c -= 'A' - 10;
        else
            assert( 0 );

        c2 = *ibuf++;
        if( c2 >= '0' && c2 <= '9' )
            c2 -= '0';
        else if( c2 >= 'a' && c2 <= 'f' )
            c2 -= 'a' - 10;
        else if( c2 >= 'A' && c2 <= 'F' )
            c2 -= 'A' - 10;
        else
            assert( 0 );

        *obuf++ = ( c << 4 ) | c2;
    }

    return len;
}

void hexify(unsigned char *obuf, const unsigned char *ibuf, int len)
{
    unsigned char l, h;

    while (len != 0)
    {
        h = (*ibuf) / 16;
        l = (*ibuf) % 16;

        if( h < 10 )
            *obuf++ = '0' + h;
        else
            *obuf++ = 'a' + h - 10;

        if( l < 10 )
            *obuf++ = '0' + l;
        else
            *obuf++ = 'a' + l - 10;

        ++ibuf;
        len--;
    }
}

unsigned char *encrypt_msg(unsigned char *original_src)
{
    char *error = "error occurs\n";
    unsigned char *hexified_key = "64cf9c7abc50b888af65f49d521944b2";

    unsigned char key_str[32];
    unsigned char iv_str[32];
    unsigned char src_str[32];
    unsigned char *dst_str;
    unsigned char output[32];
    unsigned char temp[32];
    aes_context ctx;
    size_t iv_offset = 0;
    int key_len;
    int src_len = strlen(original_src);

    dst_str = (unsigned char *)malloc(32);
    memset(key_str, 0x00, 32);
    memset(iv_str, 0x00, 32);
    memset(src_str, 0x00, 32);
    memset(dst_str, 0x00, 32);
    memset(output, 0x00, 32);
    strncpy(src_str, original_src, src_len);

    key_len = unhexify( key_str, hexified_key );
    unhexify( iv_str, "00000000000000000000000000000000" );

    if (aes_setkey_enc( &ctx, key_str, key_len * 8 ) != 0){
        puts(error);
        sgx_exit(NULL);
    }
    if (aes_crypt_cfb128( &ctx, AES_ENCRYPT, src_len, &iv_offset, iv_str, src_str, dst_str ) != 0){
        puts(error);
        sgx_exit(NULL);
    }
    hexify( output, dst_str, src_len );
    printf("encrypted str is %s\n", output);

    return dst_str;
}

// one 4k page : enclave page & offset
// Very first page chunk should be 4K aligned
void enclave_main()
{
    int port = 5566;
    char ip[] = "127.0.0.1";
    int srvr_fd;
    int n;
    char buf[32];
    struct sockaddr_in addr;
    unsigned char text_to_encrypt[32] = "hello abc";
    unsigned char *payload;

    srvr_fd = socket(PF_INET, SOCK_STREAM, 0);

    memset(buf, '0', sizeof(buf));
    if (srvr_fd == -1) {
        sgx_exit(NULL);
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (inet_pton(AF_INET, ip, &addr.sin_addr) <= 0) {
        sgx_exit(NULL);
    }

    if (connect(srvr_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(srvr_fd);
        sgx_exit(NULL);
    }

    if (srvr_fd < 0) {
        puts("Cannot connect to server\n");
        sgx_exit(NULL);
    }

    printf("text to encrypt is %s\n", text_to_encrypt);
    payload = encrypt_msg(text_to_encrypt);    
    //unsigned char payload[] = "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x4a\x01\x00\x50";
    printf("payload len is %d\n", strlen(payload));

    n = write(srvr_fd, payload, strlen(payload));
    if (n < 0)
        puts("failed to write\n");

    n = read(srvr_fd, buf, 32);
    if (n < 0)
        puts("failed to read\n");

    puts(buf);

    close(srvr_fd);
    sgx_exit(NULL);
}
