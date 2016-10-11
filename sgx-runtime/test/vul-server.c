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

// test network recv

#include "test.h"
#include <polarssl/aes.h>

char buf[32];
int arrived = 0;
int thread_lock = 0;
unsigned char *key_location;

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

void vul()
{
    char target[10];
    memcpy(target, buf, strlen(buf));
}

void decrypt()
{   
    unsigned char src_str[32];
    unsigned char dst_str[32];
    unsigned char key_str[32];
    unsigned char iv_str[32];
    unsigned char *hexified_key = "64cf9c7abc50b888af65f49d521944b2"; // we assume that this key is pre-shared between the client and the server through the established channel. In this assumption, the key is not accessible in the global data section.

    char *error = "error occurs\n";
    aes_context ctx;
    size_t iv_offset;
    int src_len;

    iv_offset = 0;
    src_len = strlen(buf);

    memset(key_str, 0x00, 32);
    memset(iv_str, 0x00, 32);
    memset(src_str, 0x00, 32);
    memset(dst_str, 0x00, 32);

    unhexify( key_str, hexified_key );
    unhexify( iv_str, "00000000000000000000000000000000" );
    key_location = key_str;

    memcpy(src_str, buf, src_len);  

    if (aes_setkey_enc( &ctx, key_str, 16 * 8 ) != 0 ){ 
        puts(error);
        sgx_exit(NULL);
    }

    if (aes_crypt_cfb128( &ctx, AES_DECRYPT, strlen(buf), &iv_offset, iv_str, src_str, dst_str ) != 0){
        puts(error);
        sgx_exit(NULL);
    }

    printf("%s\n", dst_str); //decrypted text

    arrived = 0;
}

void thread_main()
{
    asm volatile(
      "movq %%fs:(0), %%rsp\n\t"
      "movq %%fs:(0), %%rbp\n\t"
      ::);

    for(;;)
    {
        while(arrived == 0){
        }

        decrypt();
    }
}

void hack()
{
    unsigned char hexified_key[33];

    memset(hexified_key, 0x00, 33);
    hexify(hexified_key, key_location, 16);
    puts("The leaked key is \n");
    printf("%s\n", hexified_key);
}

// one 4k page : enclave page & offset
// Very first page chunk should be 4K aligned
void enclave_main()
{
    int port = 5566;
    int srvr_fd;
    int clnt_fd;
    struct sockaddr_in addr;

    srvr_fd = socket(PF_INET, SOCK_STREAM, 0);

    if (srvr_fd == -1) {
        sgx_exit(NULL);
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(srvr_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        sgx_exit(NULL);
    }

    if (listen(srvr_fd, 10) != 0) {
        sgx_exit(NULL);
    }

    while (1) {
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        clnt_fd = accept(srvr_fd, (struct sockaddr *)&addr, &len);
        if (clnt_fd < 0) {
            puts("ERROR on accept\n");
            continue;
        }

        memset(buf, 0, 32);
        int n = recv(clnt_fd, buf, 31, 0);
        if (n < 0)
            puts("ERROR on read\n");

        arrived = 1;

        while( arrived == 1){
        }

        vul();

        n = send(clnt_fd, "Received Well", 13, 0);
        if (n < 0)
            puts("ERROR on write\n");

        close(clnt_fd);
    }

    close(srvr_fd);

    sgx_exit(NULL);
}
