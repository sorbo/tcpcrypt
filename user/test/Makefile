include ../common.mak

NAME	 	= tcpcrypt
TCPCRYPT 	= ../lib
CONTRIB		= ../contrib
OPENSSL		= ../../../openssl
PPOLY1305AES 	= $(CONTRIB)/poly1305aes-20050218
CFLAGS	       += -I. -I$(TCPCRYPT) -I../tcpcrypt -O3 \
	   	  -I$(PPOLY1305AES) -I$(CONTRIB) \
		  -I$(OPENSSL)/include

OBJS	 	= tcpcrypt.o ../tcpcrypt/profile.o \
		  $(CONTRIB)/umac.o \
		  $(CONTRIB)/ocb.o \
		  $(CONTRIB)/cmac.o \
		  ../tcpcrypt/checksum.o \
		  pake.o

LDFLAGS	 	= -L$(TCPCRYPT) \
		  -L$(OPENSSL) \
		  -ltcpcrypt -lpthread -lssl -lcrypto -lz

ifneq ($(OSNAME), Darwin)
	LDFLAGS += -lrt
endif

ifneq ($(OSNAME), FreeBSD)
	LDFLAGS += -ldl
endif

ifdef HAVE_NI
	OBJS	+= $(CONTRIB)/rijndael-alg-fst-ni.o
else
	OBJS	+= $(CONTRIB)/rijndael-alg-fst.o
endif

ifdef STATIC
	ifeq ($(OSNAME), Darwin)
		OBJS += ../lib/libtcpcrypt.a
	else
		LDFLAGS += -static
	endif
endif

ifndef NO_ASM
	OBJS	+= ../tcpcrypt/checksum_32.o
endif

ifdef POLY1305AES
	LDFLAGS += $(PPOLY1305AES)/poly1305aes.a
	CFLAGS  += -DPOLY1305AES
endif

all: $(NAME)

$(NAME): $(OBJS)
	$(CC) $(CFLAGS) -o $(@) $(OBJS) $(LDFLAGS) 

clean:
	rm -f *.o *.d core $(NAME)

-include *.d
