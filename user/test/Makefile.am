bin_PROGRAMS = tcpcrypt
tcpcrypt_SOURCES = tcpcrypt.c pake.c     \
	$(top_srcdir)/src/profile.c    \
	$(top_srcdir)/src/checksum.c   \
	$(top_srcdir)/contrib/umac.c   \
	$(top_srcdir)/contrib/ocb.c    \
	$(top_srcdir)/contrib/cmac.c

tcpcrypt_LDADD = $(top_srcdir)/lib/libtcpcrypt.la $(AM_LDFLAGS)
tcpcrypt_LDFLAGS = -lssl -lpthread -lcrypto -lz

if HAVE_NI
tcpcrypt_SOURCES += $(top_srcdir)/contrib/rijndael-alg-fst-ni.c
else
tcpcrypt_SOURCES += $(top_srcdir)/contrib/rijndael-alg-fst.c
endif

if NO_ASM
tcpcrypt_SOURCES += $(top_srcdir)/src/checksum_32.S
endif
