include ../common.mak

NAME	 = tcpcryptd
CONTRIB  = ../contrib
CFLAGS	+= -I$(CONTRIB) -O3
LDFLAGS	 = -lcrypto

OBJS	= tcpcryptd.o tcpcrypt.o crypto.o crypto_rsa.o crypto_aes.o \
	  crypto_hmac.o crypto_dummy.o profile.o checksum.o \
	  test.o crypto_rc4.o crypto_umac.o \
	  $(CONTRIB)/umac.o $(CONTRIB)/rijndael-alg-fst.o

ifeq ($(OSNAME), FreeBSD)
	OBJS    += freebsd.o
endif

ifeq ($(OSNAME), Darwin)
	OBJS	+= freebsd.o
endif

ifeq ($(OSNAME), Linux)
	OBJS    += linux.o 
	LDFLAGS += -lnetfilter_queue
endif

ifeq ($(OSNAME), Cygwin)
	OBJS    += cygwin.o 
else
	OBJS	+= unix.o
endif

ifndef NO_ASM
	OBJS	+= checksum_32.o
endif

all: $(NAME)

$(NAME): $(OBJS)
	$(CC) $(CFLAGS) -o $(@) $(OBJS) $(LDFLAGS)

clean:
	rm -f $(NAME) *.o *.d core

-include *.d
