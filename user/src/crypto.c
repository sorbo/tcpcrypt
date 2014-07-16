#include <sys/time.h>
#include <time.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "inc.h"
#include "tcpcrypt_ctl.h"
#include "tcpcrypt.h"
#include "tcpcryptd.h"
#include "crypto.h"

static struct cipher_list _ciphers;

struct cipher_list *crypt_cipher_list(void)
{
	return _ciphers.c_next;
}

struct crypt *crypt_init(int sz)
{
	struct crypt *c = xmalloc(sizeof(*c));
	memset(c, 0, sizeof(*c));

	if (sz) {
		c->c_priv = xmalloc(sz);
		memset(c->c_priv, 0, sz);
	}

	return c;
}

void crypt_register(int type, unsigned int id, crypt_ctr ctr)
{
	struct cipher_list *c = xmalloc(sizeof(*c));

	c->c_type	= type;
	c->c_id		= id;
	c->c_ctr	= ctr;
	c->c_next       = _ciphers.c_next;
	_ciphers.c_next = c;
}

struct cipher_list *crypt_find_cipher(int type, unsigned int id)
{
	struct cipher_list *c = _ciphers.c_next;

	while (c) {
		if (c->c_type == type && c->c_id == id)
			return c;

		c = c->c_next;
	}

	return NULL;
}
