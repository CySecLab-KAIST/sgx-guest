BASE_CFLAGS = -m64 -g -Iinclude -I../share/include -Wall -pedantic -Wno-unused-function -std=gnu11

# SGX LIB from opensgx
LIBSGXDIR = ./libsgx
SGX_CFLAGS = $(BASE_CFLAGS) -I$(LIBSGXDIR)/include -I$(LIBSGXDIR)/musl-libc/include \
	-fno-stack-protector -static -fvisibility=hidden
SGX_LDFLAGS = -static -nostdlib -nostartfiles\
              -Wl,-T,sgx.lds
SGX_LIBS = $(LIBSGXDIR)/sgx-entry.o $(LIBSGXDIR)/libsgx.a \
	$(LIBSGXDIR)/libpolarssl-sgx.a $(LIBSGXDIR)/libc-sgx.a

SGX_HOST_OBJS := sgx-user.o sgx-trampoline.o sgx-utils.o sgx-crypto.o \
	sgx-loader.o
SGX_TOOL_OBJS := sgx-utils.o sgx-crypto.o sgx-loader.o
POLARSSL_LIB = libpolarssl.a
POLARSSL_OBJS := polarssl/rsa.o polarssl/entropy.o polarssl/ctr_drbg.o \
	polarssl/bignum.o polarssl/md.o polarssl/oid.o polarssl/asn1parse.o polarssl/sha1.o \
	polarssl/sha512.o polarssl/aes.o polarssl/entropy_poll.o polarssl/aesni.o \
	polarssl/timing.o polarssl/md_wrap.o polarssl/sha256.o polarssl/md5.o \
	polarssl/ripemd160.o polarssl/net.o polarssl/aes_cmac128.o

LDLIBS = -L. -lpolarssl -lelf -lm -lpthread

CFLAGS := $(BASE_CFLAGS) -fno-stack-protector -fvisibility=hidden 

BINS := $(patsubst %.c,%,$(wildcard test/*.c))
ALL  := sgx-tool sgx-runtime $(BINS)

all: $(ALL)

sgx-runtime: sgx-runtime.o $(SGX_HOST_OBJS) 
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

libpolarssl.a : $(POLARSSL_OBJS)
	$(AR) rs $@ $^

polarssl/%.o: polarssl/%.c
	$(CC) -c $(CFLAGS) -o $@ $<

sgx-tool: sgx-tool.o $(SGX_TOOL_OBJS) $(POLARSSL_LIB)
	$(CC) $^ $(CFLAGS) -o $@ $(LDLIBS)

test/%.o: test/%.c
	$(CC) -c $(SGX_CFLAGS) -o $@ $<

test/%: test/%.o $(SGX_LIBS)
	$(CC) $(SGX_LDFLAGS) $< -o $@ $(SGX_LIBS) -lgcc

demo/%.o: demo/%.c
	$(CC) -c $(SGX_CFLAGS) -o $@ $<

demo/%.sgx: demo/%.o $(SGX_LIBS)
	$(CC) $(SGX_LDFLAGS) $< -o $@ $(SGX_LIBS) -lgcc

clean:
	rm -f *.o polarssl/*.o test/*.o demo/*.o demo/*.sgx $(ALL)

