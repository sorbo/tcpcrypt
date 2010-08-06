include ../common.mak

OBJS	= umac.o rijndael-alg-fst-ni.o cmac.o ocb.o rijndael-alg-fst.o
CFLAGS  += -O3

all: $(OBJS)

clean:
	rm -f $(OBJS) *.d
