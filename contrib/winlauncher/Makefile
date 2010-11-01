CC	= $(PREFIX)gcc
CXX	= $(PREFIX)g++
CC	= $(CXX)

WIX	= wine /root/.wine/drive_c/Program\ Files/Windows\ Installer\ XML\ v3/bin/
CANDLE	= $(WIX)candle
LIGHT	= $(WIX)light

NAME	 = tcpcrypt.exe
CFLAGS	 = -Wall -g -I. -MD
CXXFLAGS = $(CFLAGS)
LDFLAGS  = -lgdi32 -lsetupapi -lws2_32  -lole32 -luuid \
		-Wl,-subsystem,windows

OBJS	 = tcpcrypt.o res.o netcfgapi.o

all: $(NAME)

res.o: res.rc resource.h tcpcrypt.exe.manifest
	$(PREFIX)windres $(<) $(@)

$(NAME): $(OBJS)
	$(CC) $(CFLAGS) -o $(@) $(OBJS) $(LDFLAGS)

tcpcrypt.wixobj: tcpcrypt.wxs tcpcrypt.exe
	$(CANDLE) tcpcrypt.wxs

tcpcrypt.msi: tcpcrypt.wixobj
	$(LIGHT) -sval tcpcrypt.wixobj

clean:
	rm -f *.o $(NAME) *.d

-include *.d
