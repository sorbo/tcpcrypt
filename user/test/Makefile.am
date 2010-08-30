check_PROGRAMS     = test_tcpcrypt
test_tcpcrypt_SOURCES = tcpcrypt.c pake.c     \
	$(top_srcdir)/src/profile.c    \
	$(top_srcdir)/src/checksum.c   \
	$(top_srcdir)/contrib/umac.c   \
	$(top_srcdir)/contrib/ocb.c    \
	$(top_srcdir)/contrib/cmac.c
test_tcpcrypt_CFLAGS  = -I$(top_srcdir)/include/
test_tcpcrypt_LDADD   = $(top_srcdir)/lib/libtcpcrypt.la $(AM_LDFLAGS)
test_tcpcrypt_LDFLAGS = -lssl -lpthread -lcrypto -lz

if HAVE_NI
test_tcpcrypt_SOURCES += $(top_srcdir)/contrib/rijndael-alg-fst-ni.c
else
test_tcpcrypt_SOURCES += $(top_srcdir)/contrib/rijndael-alg-fst.c
endif

if !NO_ASM
test_tcpcrypt_SOURCES += $(top_srcdir)/src/checksum_32.S
endif
