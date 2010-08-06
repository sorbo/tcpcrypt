S_SRC	= /lib/modules/$(shell uname -r)/build

obj-m += tcpcrypt.o tcpcrypt_null.o tcpcrypt_aes.o tcpcrypt_hmac.o \
		tcpcrypt_rsa.o tcpcryptumac.o

tcpcrypt-objs := tcp_crypt.o

tcpcryptnull-objs := tcpcrypt_null.o

tcpcryptaes-objs := tcpcrypt_aes.o

tcpcrypthmac-objs := tcpcrypt_hmac.o

tcpcryptrsa-objs := tcpcrypt_rsa.o

tcpcryptumac-objs := tcpcrypt_umac.o umac.o rijndael-alg-fst.o

EXTRA_CFLAGS += -O3

all:
	make -C $(S_SRC) M=$(PWD) modules

clean:
	make -C $(S_SRC) M=$(PWD) clean
