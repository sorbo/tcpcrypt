AC_PREREQ([2.65])
AC_INIT([FULL-PACKAGE-NAME], [VERSION], [BUG-REPORT-ADDRESS])
AC_CONFIG_SRCDIR([tcpcrypt/crypto_umac.c])
AC_CONFIG_HEADERS([config.h])

AC_PROG_CC

# Checks for libraries.
AC_CHECK_LIB([cap], [cap_set_flag])
AC_CHECK_LIB([crypto], [HMAC_cleanup])
#AC_CHECK_LIB([dl], [main])
AC_CHECK_LIB([netfilter_queue], [nfq_get_payload])
AC_CHECK_LIB([pthread], [pthread_create])
#AC_CHECK_LIB([rt], [main])
AC_CHECK_LIB([ssl], [EVP_CIPHER_CTX_init])
AC_CHECK_LIB([z], [main]) # TODO(sqs): still used?

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h limits.h netinet/in.h stddef.h stdint.h stdlib.h string.h strings.h sys/socket.h sys/time.h unistd.h sys/capability.h])

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
                 contrib/Makefile
                 lib/Makefile
                 tcpcrypt/Makefile
                 test/Makefile])
AC_OUTPUT
