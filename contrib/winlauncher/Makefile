CC	= $(PREFIX)gcc
CXX	= $(PREFIX)g++

NAME	 = tcpcrypt.exe
CFLAGS	 = -Wall -g -I. -MD
CXXFLAGS = $(CFLAGS)
LDFLAGS  = -lgdi32 -lsetupapi -lws2_32  -lole32 -luuid \
		-Wl,-subsystem,windows

OBJS	 = tcpcrypt.o res.o netcfgapi.o

all: $(NAME)

res.o: res.rc resource.h
	$(PREFIX)windres $(<) $(@)

$(NAME): $(OBJS)
	$(CC) $(CFLAGS) -o $(@) $(OBJS) $(LDFLAGS)

clean:
	rm -f *.o $(NAME) *.d

-include *.d
