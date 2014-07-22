bin_PROGRAMS = tcnetstat tcs
tcnetstat_SOURCES = tcnetstat.c
tcnetstat_LDADD = $(top_builddir)/lib/libtcpcrypt.la $(AM_LDFLAGS)
tcnetstat_CFLAGS  = -I$(top_srcdir)/include/

tcs_SOURCES = tcs.c
tcs_LDADD = $(top_builddir)/lib/libtcpcrypt.la $(AM_LDFLAGS)
tcs_CFLAGS  = -I$(top_srcdir)/include/

if OS_MINGW
tcnetstat_LDADD	  += -lwsock32 -liphlpapi
endif
