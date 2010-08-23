include ../common.mak

N	= libtcpcrypt
NAME	= $(N).$(SO)
CFLAGS += -fPIC -I. -I.. -O3
OBJS	= tcpcrypt.o
LDFLAGS	= $(SHARED)

all: $(NAME)

$(NAME): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(@) $(OBJS)
	$(AR) cru $(N).a $(OBJS)
	$(RANLIB) $(N).a

clean:
	rm -f *.o *.a *.d core $(NAME)

-include *.d
