#                                               -*- Autoconf -*-

AC_PREREQ([2.65])
AC_INIT([tcpcrypt], [0.2], [tcpcrypt-users@lists.stanford.edu])
AC_CONFIG_SRCDIR([src/tcpcryptd.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_AUX_DIR(config)
AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE([1.9 foreign])
AM_MAINTAINER_MODE([disable])

# Checks for programs.
AC_PROG_CC
AC_PROG_LN_S
AC_PROG_LIBTOOL
AM_PROG_AS

# Check platform
AC_CANONICAL_HOST
AC_MSG_CHECKING(OS)
AM_CONDITIONAL(OS_BSD, [echo $host_os | grep -E 'darwin|freebsd'])
AM_CONDITIONAL(OS_LINUX, [echo $host_os | grep linux])
AM_CONDITIONAL(OS_MINGW, [echo $host_os | grep -E mingw])

CFLAGS="$CFLAGS -Wall -Wno-deprecated-declarations"

# DEBUG
AC_ARG_ENABLE(debug, 
    AS_HELP_STRING([--enable-debug],
                   [enable tracing and debugging flags for all components]),
    [enable_debug="$enableval"],
    [])
if test "${enable_debug}" = yes; then
    CXXFLAGS="$CXXFLAGS -DDEBUG -g"
    CFLAGS="$CFLAGS -DDEBUG -g"

    AC_SUBST(CXXFLAGS)
    AC_SUBST(CFLAGS)
fi

# ASM
AC_MSG_CHECKING(whether to use asm checksum routine)
AC_ARG_ENABLE(asm, 
    AS_HELP_STRING([--enable-asm],
                   [use asm checksum routine]),
    [enable_asm="$enableval"],
    [enable_asm="no"])
if test "${enable_asm}" = yes; then
   AC_MSG_RESULT(yes)
else
   AC_MSG_RESULT(no)
   AC_DEFINE(NO_ASM, 1, [No asm?])
fi
AM_CONDITIONAL(NO_ASM, test x$enable_asm = xno)

AM_CONDITIONAL(HAVE_NI, false)

# libs
AC_CHECK_LIB([cap], [cap_set_flag])
AC_CHECK_LIB([crypto], [EVP_OpenInit])

LDFLAGS="$LDFLAGS -L/usr/local/lib"
AC_CHECK_LIB([netfilter_queue], [nfq_open])

AC_CHECK_LIB([nfnetlink], [nfnl_rcvbufsiz])
AC_CHECK_LIB([pthread], [pthread_create])
AC_CHECK_LIB([rt], [clock_gettime])
AC_CHECK_LIB([ssl], [EC_POINT_new])
AC_CHECK_LIB([z], [compress])
AC_CHECK_LIB([wsock32], [bind]) # TODO: find symbol name
AC_CHECK_LIB([iphlpapi], [GetAdaptersInfo]) # TODO: find symbol name

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h limits.h netinet/in.h stddef.h stdint.h stdlib.h string.h strings.h sys/socket.h sys/time.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_MODE_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T
AC_CHECK_TYPES([ptrdiff_t])

# Checks for library functions.
AC_FUNC_ALLOCA
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_CHECK_FUNCS([bzero clock_gettime gettimeofday inet_ntoa memmove memset select socket strchr strdup strtoul])

AC_CONFIG_FILES([Makefile
                 lib/Makefile
                 src/Makefile
                 test/Makefile
                 util/Makefile])
AC_OUTPUT
