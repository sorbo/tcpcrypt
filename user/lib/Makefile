include ../common.mak

N	= libtcpcrypt
NAME	= $(N).$(SO)
CFLAGS += -fPIC -I. -I.. -I../tcpcrypt -I../contrib -O3
OBJS	= tcpcrypt.o
LDFLAGS	= $(SHARED)

ifeq ($(OSNAME), Mingw)
        LIBS += -lwsock32
endif

all: $(NAME)

$(NAME): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(@) $(OBJS) $(LIBS)
	$(AR) cru $(N).a $(OBJS)
	$(RANLIB) $(N).a

clean:
	rm -f *.o *.a *.d core $(NAME)

-include *.d
