OBJS	= auth.o auth_dane.o os.o chasetrace.o
CFLAGS	= -Wall -g -MD -I../user/include/tcpcrypt

all: test libauth.so

test: test.o libauth.so
	$(CC) $(CFLAGS) -o test test.o \
		-L. -L../user/lib -lauth -lcrypto -lldns -ltcpcrypt

libauth.so: $(OBJS)
	$(CC) $(CFLAGS) -shared -o libauth.so $(OBJS)

clean:
	rm -f test *.o libauth.so *.d

-include *.d
