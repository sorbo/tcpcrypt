#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

#include "src/tcpcrypt.h"
#include "src/tcpcrypt_ctl.h"
#include "src/inc.h"

int open_socket()
{
    int s;
    struct sockaddr_in s_in;
#ifdef __WIN32__
    WSADATA wsadata;
    if (WSAStartup(MAKEWORD(1,1), &wsadata) == SOCKET_ERROR)
	errx(1, "WSAStartup()");
#endif  

    memset(&s_in, 0, sizeof(s_in));
    s_in.sin_family = PF_INET;
    s_in.sin_port = 0;
    s_in.sin_addr.s_addr = INADDR_ANY;

    s = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == -1)
        err(1, "socket()");

    if (bind(s, (struct sockaddr*) &s_in, sizeof(s_in)) == -1)
        err(1, "bind()");

    return s;
}

static void do_netstat(void)
{
	unsigned char buf[2048];
	unsigned int len = sizeof(buf);
	int s, sl, i;
	struct tc_netstat *n = (struct tc_netstat*) buf;
	char src[64];
	char dst[64];

	s = open_socket();
	if (tcpcrypt_getsockopt(s, IPPROTO_TCP, TCP_CRYPT_NETSTAT, buf, &len) == -1)
            err(1, "tcpcrypt_getsockopt()");

	printf("Local address\t\tForeign address\t\tSID\n");

	while (len > sizeof(*n)) {
		sl = ntohs(n->tn_len);

		assert(len >= sizeof(*n) + sl);

		sprintf(src, "%s:%d", inet_ntoa(n->tn_sip), ntohs(n->tn_sport));
		sprintf(dst, "%s:%d", inet_ntoa(n->tn_dip), ntohs(n->tn_dport));
		printf("%-21s\t%-21s\t", src, dst);

		for (i = 0; i < sl; i++)
			printf("%.2X", n->tn_sid[i]);

		printf("\n");

		sl  += sizeof(*n);
		n    = (struct tc_netstat*) ((unsigned long) n + sl);
		len -= sl;
	}
	assert(len == 0);
}

int main(int argc, char **argv)
{
    do_netstat();
    return 0;
}
