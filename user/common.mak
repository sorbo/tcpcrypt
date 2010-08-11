CFLAGS	= -Wall -g -MD

CC	= $(PREFIX)gcc
AR	= $(PREFIX)ar
RANLIB	= $(PREFIX)ranlib

ifdef GPROF
        CFLAGS += -pg
endif

ifdef OPT
        CFLAGS += -O3 -fomit-frame-pointer
else
ifndef NOOPT
        CFLAGS += -O2
endif
endif

ifndef OSNAME
	OSNAME	= $(shell uname -s)
endif

ifneq ($(findstring $(shell uname -o),"Cygwin"),)
	OSNAME = Cygwin
endif

SHARED = -shared
SO     = so

ifeq ($(OSNAME), Darwin)
	NO_ASM = 1
	SHARED = -dynamiclib
	SO     = dylib
endif

ifeq ($(OSNAME), Cygwin)
	NO_ASM = 1
endif

ifeq ($(shell uname -m), x86_64)
        NO_ASM = 1
endif

ifdef NO_ASM
        CFLAGS  += -DNO_ASM
endif
