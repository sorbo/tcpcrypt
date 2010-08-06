S_SRC   = /lib/modules/$(shell uname -r)/build

EXTRA_CFLAGS += -I$(PWD) -I$(PWD)/include -I$(PWD)/crypto -I$(PWD)/fake
EXTRA_CFLAGS += -DOPENSSL_NO_FP_API -DOPENSSL_NO_STDIO -O3 \
			-DOPENSSL_BN_ASM_PART_WORDS \
			-DOPENSSL_BN_ASM_MONT

obj-m += openssl.o

openssl-objs := \
	main.o \
        crypto/bn/bn_add.o \
        crypto/bn/bn_const.o \
        crypto/bn/bn_div.o \
        crypto/bn/bn_exp.o \
        crypto/bn/bn_ctx.o \
        crypto/bn/bn_exp2.o \
        crypto/bn/bn_gcd.o \
        crypto/bn/bn_kron.o \
        crypto/bn/bn_lib.o \
        crypto/bn/bn_mod.o \
        crypto/bn/bn_mont.o \
        crypto/bn/bn_mpi.o \
        crypto/bn/bn_mul.o \
        crypto/bn/bn_nist.o \
        crypto/bn/bn_recp.o \
        crypto/bn/bn_shift.o \
        crypto/bn/bn_sqr.o \
        crypto/bn/bn_word.o \
	crypto/bn/bn86-elf.o \
	crypto/bn/co86-elf.o \
	crypto/bn/mo86-elf.o \
	crypto/rsa/rsa_oaep.o \
	crypto/rsa/rsa_eay.o

ifdef IS64
	openssl-objs += crypto/sha/sha1-x86_64.o
else
	openssl-objs += crypto/sha/sx86-elf.o
endif

all:
	make -C $(S_SRC) M=$(PWD) modules

clean:
	make -C $(S_SRC) M=$(PWD) clean
