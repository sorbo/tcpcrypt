#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <stdint.h>

#include "src/inc.h"
#include "src/tcpcryptd.h"
#include "src/tcpcrypt.h"
#include "src/tcpcrypt_ctl.h"
#include "src/tcpcrypt_strings.h"

static const char *_bind_ip = "0.0.0.0";

enum {
	TYPE_CLIENT = 0,
	TYPE_SERVER,
	TYPE_RAW,
};

enum {
	FLAG_HELLO = 1,
};

struct sock {
	int			s;
	int			type;
	int			dead;
	time_t			added;
	struct sockaddr_in	peer;
	int			port;
	int			flags;
	struct sock  		*next;
} _socks;

struct client {
	int		sport;
	int		dport;
	int		flags;
	struct in_addr	ip;
	time_t		added;
	struct client	*next;
} _clients;

static struct sock *add_sock(int s)
{
	struct sock *sock = malloc(sizeof(*sock));

	if (!sock)
		err(1, "malloc()");

	memset(sock, 0, sizeof(*sock));

	sock->s     = s;
	sock->added = time(NULL);

	sock->next  = _socks.next;
	_socks.next = sock;

	return sock;
}

static void add_server(int port)
{
	int s;
	struct sockaddr_in s_in;
	struct sock *sock;
	int one = 1;

	if ((s = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1)
		err(1, "socket()");

	if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) == -1)
		err(1, "setsockopt()");

	memset(&s_in, 0, sizeof(s_in));

	s_in.sin_addr.s_addr = inet_addr(_bind_ip);
	s_in.sin_port        = htons(port);

	if (bind(s, (struct sockaddr*) &s_in, sizeof(s_in)) == -1)
		err(1, "bind()");

	if (listen(s, 5) == -1)
		err(1, "listen()");

	sock = add_sock(s);
	sock->type = TYPE_SERVER;
	sock->port = port;
}

static void add_sniffer(void)
{
	int s;
	struct sock *sock;

	if ((s = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
		err(1, "socket()");

	sock = add_sock(s);
	sock->type = TYPE_RAW;
}

static void find_client(struct sock *s)
{
	struct client *c = &_clients;

	while (c->next) {
		struct client *next = c->next;
		struct client *del  = NULL;

		if (next->dport == s->port
		    && next->sport == ntohs(s->peer.sin_port)) {
		    	s->flags = next->flags;
			del = next;
		}

		if ((time(NULL) - next->added) > 10)
			del = next;

		if (del) {
			c->next = next->next;
			free(del);
		} else
			c = next;
	}
}

static void handle_server(struct sock *s)
{
	struct sockaddr_in s_in;
	socklen_t len = sizeof(s_in);
	int dude;
	struct sock *d;
	
	dude = accept(s->s, (struct sockaddr*) &s_in, &len);

	if (dude == -1) {
		perror("accept()");
		return;
	}

	d = add_sock(dude);

	memcpy(&d->peer, &s_in, sizeof(d->peer));
	d->port = s->port;

	find_client(d);
}

static void handle_client(struct sock *s)
{
	char buf[1024];
	int rc;
	int got = -1;
	int i;
	int crypt = 0;
	unsigned int len;
	struct tm *tm;
	time_t t;

	len = sizeof(buf);
	rc = tcpcrypt_getsockopt(s->s, IPPROTO_TCP, TCP_CRYPT_SESSID, buf,
				 &len);
	crypt = rc != -1;

	rc = read(s->s, buf, sizeof(buf) - 1);
	if (rc <= 0) {
		s->dead = 1;
		return;
	}

	buf[rc] = 0;

	s->dead = 1;

	for (i = 0; i < sizeof(REQS) / sizeof(*REQS); i++) {
		if (strcmp(buf, REQS[i]) == 0) {
			got = i;
			break;
		}
	}

	if (got == -1)
		return;

	snprintf(buf, sizeof(buf), "%s%d", TEST_REPLY, s->flags);
	rc = strlen(buf);

	if (write(s->s, buf, rc) != rc)
		return;

	t = time(NULL);
	tm = localtime(&t);
	strftime(buf, sizeof(buf), "%m/%d/%y %H:%M:%S", tm);

	printf("[%s] GOT %s:%d - %4d [MSG %d] crypt %d flags %d\n",
	       buf,
	       inet_ntoa(s->peer.sin_addr),
	       ntohs(s->peer.sin_port),
	       s->port,
	       got,
	       crypt,
	       s->flags);

	s->dead = 1;
}

static void found_crypt(struct ip *ip, struct tcphdr *th)
{
	struct client *c = malloc(sizeof(*c));

	if (!c)
		err(1, "malloc()");

	memset(c, 0, sizeof(*c));

	c->ip    = ip->ip_src;
	c->sport = ntohs(th->th_sport);
	c->dport = ntohs(th->th_dport);
	c->added = time(NULL);
	c->flags = FLAG_HELLO;
	c->next  = _clients.next;

	_clients.next = c;
}

static void handle_raw(struct sock *s)
{
	unsigned char buf[2048];
	int rc;
	struct ip *ip = (struct ip*) buf;
	struct tcphdr *th;
	unsigned char *end, *p;

	if ((rc = read(s->s, buf, sizeof(buf))) <= 0)
		err(1, "read()");

	if (ip->ip_v != 4)
		return;

	if (ip->ip_p != IPPROTO_TCP)
		return;

	th = (struct tcphdr*) (((unsigned long) ip) + (ip->ip_hl << 2));

	if ((unsigned long) th >= (unsigned long) (&buf[rc] - sizeof(*th)))
		return;

	p   = (unsigned char*) (th + 1);
	end = (unsigned char*) (((unsigned long) th) + (th->th_off << 2));

	if ((unsigned long) end > (unsigned long) &buf[rc])
		return;

	if (th->th_flags != TH_SYN)
		return;

	while (p < end) {
		int opt = *p++;
		int len;

		switch (opt) {
		case TCPOPT_EOL:
		case TCPOPT_NOP:
			continue;
		}

		if (p >= end)
			break;

		len = *p++ - 2;

		if ((p + len) >= end)
			break;

		switch (opt) {
		case TCPOPT_CRYPT:
			found_crypt(ip, th);
			break;
		}

		p += len;
	}
}

static void process_socket(struct sock *s)
{

	switch (s->type) {
	case TYPE_SERVER:
		handle_server(s);
		break;

	case TYPE_RAW:
		handle_raw(s);
		break;

	case TYPE_CLIENT:
		handle_client(s);
		break;

	default:
		printf("WTF %d\n", s->type);
		abort();
		break;
	}
}

static void check_sockets(void)
{
	struct sock *s = _socks.next;
	fd_set fds;
	int max = 0;
	struct timeval tv;

	FD_ZERO(&fds);

	while (s) {
		FD_SET(s->s, &fds);

		if (s->s > max)
			max = s->s;

		s = s->next;
	}

	tv.tv_sec  = 5;
	tv.tv_usec = 0;

	if (select(max + 1, &fds, NULL, NULL, &tv) == -1)
		err(1, "select()");

	s = &_socks;

	while ((s = s->next)) {
		if (FD_ISSET(s->s, &fds))
			process_socket(s);
	}

	s = &_socks;

	while (s->next) {
		struct sock *next = s->next;

		if (next->type == TYPE_CLIENT 
		    && (time(NULL) - next->added > 10))
			next->dead = 1;

		if (next->dead) {
			close(next->s);
			s->next = next->next;
			free(next);
		} else
			s = next;
	}
}

static void pwn(void)
{
	add_sniffer();
	add_server(80);
	add_server(7777);

	tzset();

#ifndef __WIN32__
	chroot("/tmp");
	setgid(666);
	setuid(666);
#endif

	while (1)
		check_sockets();
}

int main(int argc, const char *argv[])
{
	if (argc > 1) {
		_bind_ip = argv[1];

		printf("Binding to %s\n", _bind_ip);
	}

	pwn();
	exit(0);
}
