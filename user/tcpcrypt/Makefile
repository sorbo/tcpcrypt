include ../common.mak

NAME	 = tcpcryptd$(SUFFIX)
CONTRIB  = ../contrib
CFLAGS	+= -I$(CONTRIB)
LDFLAGS	 = -lcrypto

OBJS	= tcpcryptd.o tcpcrypt.o crypto.o crypto_rsa.o crypto_aes.o \
	  crypto_hmac.o crypto_dummy.o profile.o checksum.o \
	  test.o crypto_rc4.o \
	  crypto_umac.o $(CONTRIB)/umac.o \
	  $(CONTRIB)/rijndael-alg-fst.o

ifeq ($(OSNAME), FreeBSD)
	OBJS    += freebsd.o
endif

ifeq ($(OSNAME), Darwin)
	OBJS	+= freebsd.o
endif

ifeq ($(OSNAME), Linux)
	OBJS    += linux.o 
	LDFLAGS += -lnetfilter_queue -lnfnetlink -lcap
endif

ifneq (,$(filter $(OSNAME),Cygwin Mingw))
	OBJS    += cygwin.o
	LDFLAGS	+= -liphlpapi
else 
	OBJS	+= unix.o
endif

ifeq ($(OSNAME), Mingw)
	OBJS	+= mingw.o res.o
	LDFLAGS += -lwsock32
endif

ifndef NO_ASM
	OBJS	+= checksum_32.o
endif

all: $(NAME)

$(NAME): $(OBJS)
	$(CC) $(CFLAGS) -o $(@) $(OBJS) $(LDFLAGS)

res.o: res.rc resource.h tcpcryptd.exe.manifest
	$(PREFIX)windres $(<) $(@)

clean:
	rm -f $(NAME) *.o *.d core

-include *.d
