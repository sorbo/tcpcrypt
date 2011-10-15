#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <unistd.h>

#include "tcpcrypt_divert.h"
#include "tcpcryptd.h"

static int	  _s;
static divert_cb _cb;

int divert_open(int port, divert_cb cb)
{
	struct sockaddr_in s_in;

	memset(&s_in, 0, sizeof(s_in));

	s_in.sin_family = PF_INET;
	s_in.sin_port   = htons(port);

	if ((_s = socket(PF_INET, SOCK_RAW, IPPROTO_DIVERT)) == -1)
		err(1, "socket()");

	if (bind(_s, (struct sockaddr*) &s_in, sizeof(s_in)) == -1)
		err(1, "bind()");

	_cb = cb;

        xprintf(XP_DEFAULT, "Divert packets using ipfw add divert %d\n", port);

	open_raw();

	return _s;
}

void divert_close(void)
{
	close(_s);
}

void divert_next_packet(int s)
{
	unsigned char buf[2048];
	struct sockaddr_in s_in;
	socklen_t len = sizeof(s_in);
	int rc;
	int verdict;
	int flags = 0;

	rc = recvfrom(_s, buf, sizeof(buf), 0, (struct sockaddr*) &s_in, &len);
	if (rc == -1)
		err(1, "recvfrom()");

	if (rc == 0)
		errx(1, "EOF");

	if (s_in.sin_addr.s_addr != INADDR_ANY)
		flags |= DF_IN;

	verdict = _cb(buf, rc, flags);

	switch (verdict) {
	case DIVERT_MODIFY:
		rc = ntohs(((struct ip*) buf)->ip_len);
		/* fallthrough */
	case DIVERT_ACCEPT:
		flags = sendto(_s, buf, rc, 0, (struct sockaddr*)  &s_in, len);
		if (flags == -1)
			err(1, "sendto()");

		if (flags != rc)
			errx(1, "sent %d/%d", flags, rc);
		break;

	case DIVERT_DROP:
		break;

	default:
		abort();
		break;
	}
}
