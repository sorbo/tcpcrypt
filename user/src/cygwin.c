#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>

#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>

#include "inc.h"
#include "tcpcrypt_divert.h"
#include "tcpcryptd.h"

#include <windivert.h>

#define MAC_SIZE 14

static int	  _s;
static divert_cb _cb;

struct packet {
	unsigned char p_buf[2048];
	int	      p_len;
	struct packet *p_next;
} _outbound;

extern int do_divert_open(void);
extern int do_divert_read(int s, void *buf, int len);
extern int do_divert_write(int s, void *buf, int len);
extern void do_divert_close(int s);

int divert_open(int port, divert_cb cb)
{
	_s  = do_divert_open();
	_cb = cb;

	return _s;
}

void divert_close(void)
{
	do_divert_close(_s);
}

static void do_divert_next_packet(unsigned char *buf, int rc)
{
	int verdict;
	int flags = 0;
	struct ip *iph = (struct ip*) &buf[MAC_SIZE];
	int len;
	PDIVERT_ADDRESS addr = (PDIVERT_ADDRESS)buf;

	if (rc < MAC_SIZE)
		errx(1, "short read %d", rc);

	if (addr->Direction == WINDIVERT_DIRECTION_INBOUND)
		flags |= DF_IN;

	// XXX ethernet padding on short packets?  (46 byte minimum)
	len = rc - MAC_SIZE;
	if (len > ntohs(iph->ip_len)) {
		xprintf(XP_ALWAYS, "Trimming from %d to %d\n",
			len, ntohs(iph->ip_len));

		len = ntohs(iph->ip_len);
	}

	verdict = _cb(iph, len, flags);

	switch (verdict) {
	case DIVERT_MODIFY:
		rc = ntohs(iph->ip_len) + MAC_SIZE;
		/* fallthrough */
	case DIVERT_ACCEPT:
		flags = do_divert_write(_s, buf, rc);
		if (flags == -1)
			err(1, "write()");

		if (flags != rc)
			errx(1, "wrote %d/%d", flags, rc);
		break;

	case DIVERT_DROP:
		break;

	default:
		abort();
		break;
	}
}

void divert_next_packet(int s)
{
	unsigned char buf[2048];
	int rc;

	rc = do_divert_read(_s, buf, sizeof(buf));
	if (rc == -1)
		err(1, "read()");

	if (rc == 0)
		errx(1, "EOF");

	do_divert_next_packet(buf, rc);
}

void divert_inject(void *data, int len)
{
	struct packet *p, *p2;
	unsigned short *et;
	struct ip *iph = (struct ip*) data;

	p = malloc(sizeof(*p));
	if (!p)
		err(1, "malloc()");

	memset(p, 0, sizeof(*p));

	// XXX: for divert, we can just zero the ethhdr, which contains the
	//      DIVERT_ADDRESS.  A zeroed address usually gives the desired
	//      result.
	
	/* payload */
	p->p_len = len + MAC_SIZE;

	if (p->p_len > sizeof(p->p_buf))
		errx(1, "too big (divert_inject)");

	memcpy(&p->p_buf[MAC_SIZE], data, len);

	/* add to list */
	p2 = &_outbound;

	if (p2->p_next)
		p2 = p2->p_next;

	p2->p_next = p;
}

void divert_cycle(void)
{
	struct packet *p = _outbound.p_next;

	while (p) {
		struct packet *next = p->p_next;

		do_divert_next_packet(p->p_buf, p->p_len);

		free(p);

		p = next;
	}

	_outbound.p_next = NULL;
}

void drop_privs(void)
{
}
