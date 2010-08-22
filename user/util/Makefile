include ../common.mak

PRODUCTS	= tcnetstat
TCPCRYPT 	= ../lib
CFLAGS	       += -I. -I$(TCPCRYPT) -I../tcpcrypt -O3
LDFLAGS	 	= -L$(TCPCRYPT) -ltcpcrypt

all: $(PRODUCTS)

tcnetstat: tcnetstat.o
	$(CC) $(CFLAGS) -o $(@) $(<) $(LDFLAGS) 

clean:
	rm -f *.o *.d core $(PRODUCTS)

-include *.d
