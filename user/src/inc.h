#ifndef __WIN32__
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netdb.h>
#define __FAVOR_BSD
#include <netinet/tcp.h>
#include <err.h>
#include <sys/uio.h>
#else /* __WIN32__ */
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include "contrib/win_port.h"
#endif /* ! __WIN32__ */
