bin_PROGRAMS = tcnetstat
tcnetstat_SOURCES = tcnetstat.c
tcnetstat_LDADD = $(top_builddir)/lib/libtcpcrypt.la $(AM_LDFLAGS)
tcnetstat_CFLAGS  = -I$(top_srcdir)/include/
tcnetstat_LDFLAGS = --all-static

if OS_MINGW
tcnetstat_LDADD	  += -lwsock32 -liphlpapi
endif
