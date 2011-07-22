#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <err.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "auth.h"
#include "auth_dane.h"

static char	*_cert_file;
static char	*_key_file;
static int	_port = 666;
static int	_listen = 0;
static char	*_host = "localhost";
static int	_connect_by_name = 0;

static int do_pipe(int in, int out)
{
	unsigned char buf[1024];
	int len;

	len = read(in, buf, sizeof(buf));
	if (len <= 0)
		return -1;

	if (write(out, buf, len) != len)
		return -1;

	return len;
}

static void telnet(int s)
{
	fd_set fds;

	while (1) {
		FD_ZERO(&fds);
		FD_SET(0, &fds);
		FD_SET(s, &fds);

		if (select(s + 1, &fds, NULL, NULL, NULL) == -1)
			break;

		if (FD_ISSET(0, &fds)) {
			if (do_pipe(0, s) == -1)
				break;
		}

		if (FD_ISSET(s, &fds)) {
			if (do_pipe(s, 0) == -1)
				break;
		}
	}

	close(s);
}

static void do_server(void)
{
	int s, dude, rc;
	struct auth_info_dane ai;
	X509 *cert;
	FILE *f;
	EVP_PKEY *key;
	struct sockaddr_in s_in;
	int one = 1;

	memset(&ai, 0, sizeof(ai));
	ai.ai_type = AUTH_DANE;

	if (!_cert_file || !_key_file)
		errx(1, "Need cert & key file");

	f = fopen(_cert_file, "r");
	if (!f)
		err(1, "fopen()");

	cert = PEM_read_X509(f, NULL, NULL, NULL);
	if (!cert)
		errx(1, "PEM_read_X509()");

	fclose(f);

	f = fopen(_key_file, "r");
	if (!f)
		err(1, "fopen()");

	key = PEM_read_PrivateKey(f, NULL, NULL, NULL);
	if (!key)
		errx(1, "PEM_read_PrivateKey()");

	fclose(f);

	ai.ai_cert = cert;
	ai.ai_key  = key;

	if ((s = socket(PF_INET, SOCK_STREAM, 0)) == -1)
		err(1, "socket()");

	if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) == -1)
		err(1, "setsockopt()");

	memset(&s_in, 0, sizeof(s_in));
	s_in.sin_family	     = PF_INET;
	s_in.sin_addr.s_addr = INADDR_ANY;
	s_in.sin_port        = htons(_port);

	if (bind(s, (struct sockaddr*) &s_in, sizeof(s_in)) == -1)
		err(1, "bind()");

	if (listen(s, 5) == -1)
		err(1, "listen()");

	if (auth_enable(s) == -1)
		errx(1, "auth_enable()");

	do {
		printf("Listening...\n");

		if ((dude = accept(s, NULL, NULL)) == -1)
			err(1, "accept()");

		rc = auth_accept(dude, (struct auth_info*) &ai);

		if (rc == 0) {
			printf("Got connection\n");
			telnet(dude);
		} else
			printf("auth_accept() error\n");

		close(dude);
	} while (_listen > 1);
}

static void do_client(void)
{
	int s;
	struct sockaddr_in s_in;
	int rc = -1;
	struct auth_info_dane ai;

	if (_connect_by_name) {
		s = connectbyname(_host, _port);
		if (s != -1)
			rc = 0;
	} else {
		if ((s = socket(PF_INET, SOCK_STREAM, 0)) == -1)
			err(1, "socket()");

		memset(&s_in, 0, sizeof(s_in));
		s_in.sin_family = PF_INET;
		s_in.sin_addr.s_addr = inet_addr("127.0.0.1");
		s_in.sin_port = htons(_port);

		if (auth_enable(s) == -1)
			errx(1, "auth_enable()");

		if (connect(s, (struct sockaddr*) &s_in, sizeof(s_in)) == -1)
			err(1, "connect()");

		memset(&ai, 0, sizeof(ai));

		ai.ai_type     = AUTH_DANE;
		ai.ai_hostname = _host;
		ai.ai_port     = _port;

		rc = auth_connect(s, (struct auth_info*) &ai);
	}

	if (rc == 0) {
		printf("Connected\n");
		telnet(s);
	} else
		printf("auth_connect() error\n");

	close(s);
}

static void help(char *name)
{
	printf("Usage: %s [opts]\n"
	       "-h\thelp\n"
	       "-l\tlisten\n"
	       "-c\t<cert>\n"
	       "-k\t<key>\n"
	       "-d\t<hostname>\n"
	       "-p\t<port>\n"
	       "-C\tconnectbyname()\n"
	       , name);

	exit(1);
}

int main(int argc, char *argv[])
{
	int ch;

	while ((ch = getopt(argc, argv, "hlc:k:d:p:C")) != -1) {
		switch (ch) {
		case 'C':
			_connect_by_name = 1;
			break;

		case 'p':
			_port = atoi(optarg);
			break;

		case 'd':
			_host = optarg;
			break;

		case 'c':
			_cert_file = optarg;
			break;
		
		case 'k':
			_key_file = optarg;
			break;

		case 'h':
			help(argv[1]);
			exit(1);

		case 'l':
			_listen++;
			break;
		}
	}

	if (_listen)
		do_server();
	else
		do_client();

	exit(0);
}
