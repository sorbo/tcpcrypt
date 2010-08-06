#include <sys/uio.h>
#include <sys/time.h>
#include <time.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <netinet/in.h>
#include <assert.h>

#include "tcpcrypt_ctl.h"
#include "tcpcrypt.h"
#include "tcpcryptd.h"
#include "crypto.h"

static struct cipher_list _ciphers;

void crypto_init(struct tc *tc)
{
	assert(tc->tc_crypt_ops);
	tc->tc_crypt_ops->co_init(tc);
}

void crypto_finish(struct tc *tc)
{
	if (tc->tc_crypt_ops->co_finish) {
		tc->tc_crypt_ops->co_finish(tc);

		return;
	}

	if (tc->tc_crypt)
		free(tc->tc_crypt);

	tc->tc_crypt = 0;
}

void crypto_next_iv(struct tc *tc, void *out, int *outlen)
{
	tc->tc_crypt_ops->co_next_iv(tc, out, outlen);
}

void crypto_mac(struct tc *tc, struct iovec *iov, int num, void *iv, void *out,
		int *outlen)
{
	tc->tc_crypt_ops->co_mac(tc, iov, num, iv, out, outlen);
}

void crypto_encrypt(struct tc *tc, void *iv, void *data, int len)
{
	tc->tc_crypt_ops->co_encrypt(tc, iv, data, len);
}

int crypto_decrypt(struct tc *tc, void *iv, void *data, int len)
{
	return tc->tc_crypt_ops->co_decrypt(tc, iv, data, len);
}

int crypto_get_key(struct tc *tc, void **out)
{
	return tc->tc_crypt_ops->co_get_key(tc, out);
}

int crypto_set_key(struct tc *tc, void *key, int len)
{
	return tc->tc_crypt_ops->co_set_key(tc, key, len);
}

void crypto_mac_set_key(struct tc *tc, void *key, int len)
{
	tc->tc_crypt_ops->co_mac_set_key(tc, key, len);
}

void *crypto_priv(struct tc *tc)
{
	return tc->tc_crypt;
}

void *crypto_priv_init(struct tc *tc, int sz)
{
	void *priv;

	tc->tc_crypt = xmalloc(sz);

	priv = crypto_priv(tc);
	memset(priv, 0, sz);

	return priv;
}

struct crypt_prop *crypto_prop(struct tc *tc)
{
	return tc->tc_crypt_ops->co_crypt_prop(tc);
}

void crypto_register(struct crypt_ops *ops)
{
	struct cipher_list *c = xmalloc(sizeof(*c));

	c->c_cipher     = ops;
	c->c_next       = _ciphers.c_next;
	_ciphers.c_next = c;
}

struct cipher_list *crypto_cipher_list(void)
{
	return _ciphers.c_next;
}

static int get_id(struct crypt_ops *o)
{
	struct tc_cipher_spec *pkey;
	struct tc_scipher *sym;

	switch (o->co_type()) {
	case TYPE_PKEY:
		pkey = o->co_spec();
		return pkey->tcs_algo;

	case TYPE_SYM:
		sym = o->co_spec();
		return sym->sc_cipher;

	case TYPE_MAC:
		sym = o->co_spec();
		return sym->sc_mac;

	default:
		abort();
	}
}

struct crypt_ops *crypto_find_cipher(int type, int id)
{
	struct cipher_list *c = _ciphers.c_next;
	struct crypt_ops *o;

	while (c) {
		o = c->c_cipher;

		if (o->co_type() == type && get_id(o) == id)
			return o;

		c = c->c_next;
	}

	return NULL;
}
