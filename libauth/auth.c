#include <err.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <tcpcrypt.h>
#include <string.h>
#include <netdb.h>
#include <unistd.h>

#include "auth.h"
#include "auth_dane.h"
#include "os.h"

struct auth_module {
	int		am_type;
	accept_cb	am_accept;
	connect_cb	am_connect;
};

static struct auth_module _modules[24];

static struct auth_module *auth_get(int type)
{
	if (type >= (sizeof(_modules) / sizeof(*_modules)))
		errx(1, "auth_register()");

	return &_modules[type];
}

static struct auth_module *auth_getx(int type)
{
	struct auth_module *m = auth_get(type);

	if (!m->am_accept)
		errx(1, "auth_getx()");

	return m;
}

void auth_register(int type, accept_cb a, connect_cb c)
{
	struct auth_module *m = auth_get(type);

	m->am_type    = type;
	m->am_accept  = a;
	m->am_connect = c;
}

int auth_connect(int s, struct auth_info *ai)
{
	struct auth_module *m = auth_getx(ai->ai_type);

	if (!tcpcrypt_get_app_support(s))
		return -1;

	return m->am_connect(s, ai);
}

int auth_accept(int s, struct auth_info *ai)
{
	struct auth_module *m = auth_getx(ai->ai_type);

	if (!tcpcrypt_get_app_support(s))
		return -1;

	return m->am_accept(s, ai);
}

int auth_enable(int s)
{
	return tcpcrypt_set_app_support(s, 1);
}

int connectbyname(char *host, int port)
{
	int s;
	struct sockaddr_in s_in;
	struct hostent *he;
        struct auth_info_dane ai;

	memset(&s_in, 0, sizeof(s_in));
	s_in.sin_family = PF_INET;
	s_in.sin_port   = htons(port);

	he = gethostbyname(host);
	if (!he)
		return -1;

	if (!he->h_addr_list[0])
		return -1;

	memcpy(&s_in.sin_addr.s_addr, he->h_addr_list[0],
	       sizeof(s_in.sin_addr.s_addr));

	if ((s = socket(PF_INET, SOCK_STREAM, 0)) == -1)
		return -1;

	if (auth_enable(s) == -1)
		goto __bad;

	if (connect(s, (struct sockaddr*) &s_in, sizeof(s_in)) == -1)
		goto __bad;

	memset(&ai, 0, sizeof(ai));

	ai.ai_type     = AUTH_DANE;
	ai.ai_hostname = host;
	ai.ai_port     = port;

	if (auth_connect(s, (struct auth_info*) &ai) != 0)
		goto __bad;

	return s;
__bad:
	close(s);
	return -1;
}
