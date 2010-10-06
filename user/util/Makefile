include ../common.mak

PRODUCTS	= tcnetstat$(SUFFIX)
TCPCRYPT 	= ../lib
CFLAGS	       += -I. -I$(TCPCRYPT) -I../tcpcrypt -I../contrib -O3
LDFLAGS	 	= -L$(TCPCRYPT) -ltcpcrypt

ifeq ($(OSNAME), Mingw)
	LDFLAGS += -lwsock32
endif


all: $(PRODUCTS)

tcnetstat$(SUFFIX): tcnetstat.o
	$(CC) $(CFLAGS) -o $(@) $(<) $(LDFLAGS) 

clean:
	rm -f *.o *.d core $(PRODUCTS)

-include *.d
