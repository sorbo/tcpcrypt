#ifndef __WIN32__
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#define __FAVOR_BSD
#include <netinet/tcp.h>
#include <err.h>
#include <sys/uio.h>
#else /* __WIN32__ */
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <win_port.h>
#endif /* ! __WIN32__ */
