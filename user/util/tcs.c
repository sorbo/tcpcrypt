#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/select.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "src/tcpcryptd.h"
#include "src/tcpcrypt.h"
#include "src/tcpcrypt_ctl.h"

static char *_bind_ip = "0.0.0.0";

enum {
	TYPE_CLIENT = 0,
	TYPE_SERVER,
};

struct sock {
	int			s;
	int			type;
	int			dead;
	time_t			added;
	struct sockaddr_in	peer;
	int			port;
	struct sock  		*next;
} _socks;

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

static void process_socket(struct sock *s)
{
	char buf[1024];
	int rc;
	int got = -1;
	int i;
	int crypt = 0;
	unsigned int len;
	struct tm *tm;
	time_t t;

	if (s->type == TYPE_SERVER) {
		struct sockaddr_in s_in;
		socklen_t len = sizeof(s_in);

		int dude = accept(s->s, (struct sockaddr*) &s_in, &len);

		if (dude == -1)
			perror("accept()");
		else {
			struct sock *d = add_sock(dude);

			memcpy(&d->peer, &s_in, sizeof(d->peer));
			d->port = s->port;
		}

		return;
	}

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

	if (write(s->s, TEST_REPLY, rc) != rc)
		return;

	t = time(NULL);
	tm = localtime(&t);
	strftime(buf, sizeof(buf), "%m/%d/%y %H:%M:%S", tm);

	printf("[%s] GOT %s:%d - %d\t[MSG %d] crypt %d\n",
	       buf,
	       inet_ntoa(s->peer.sin_addr),
	       ntohs(s->peer.sin_port),
	       s->port,
	       got,
	       crypt);

	s->dead = 1;
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
	add_server(80);
	add_server(7777);

	tzset();
	chroot("/tmp");
	setgid(666);
	setuid(666);

	while (1)
		check_sockets();
}

int main(int argc, char *argv[])
{
	if (argc > 1) {
		_bind_ip = argv[1];

		printf("Binding to %s\n", _bind_ip);
	}

	pwn();
	exit(0);
}
