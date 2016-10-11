obj-m = sgxmod.o
sgxmod-objs := sgx-module.o sgx-kern.o sgx-kern-epc.o sgx-utils.o sgx-signature.o
KVERSION = $(shell uname -r)
EXTRA_CFLAGS=-I$(PWD)/include -I$(PWD)/../share/include -std=gnu11

all:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) clean 

