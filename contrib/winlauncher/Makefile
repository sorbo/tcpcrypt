CC	= $(PREFIX)gcc
CXX	= $(PREFIX)g++

WIX	= wine $(HOME)/.wine/drive_c/Program\ Files\ \(x86\)/Windows\ Installer\ XML\ v3/bin/
CANDLE	= $(WIX)candle
LIGHT	= $(WIX)light

NAME	 = tcpcrypt.exe
CFLAGS	 = -Wall -g -I. -MD
CXXFLAGS = $(CFLAGS)
LDFLAGS  = -lgdi32 -lsetupapi -lws2_32  -lole32 -luuid \
		-Wl,-subsystem,windows

OBJS	 = tcpcrypt.o res.o 

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
