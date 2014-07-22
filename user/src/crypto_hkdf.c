#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <openssl/hmac.h>

#include "inc.h"
#include "tcpcrypt_ctl.h"
#include "tcpcrypt.h"
#include "tcpcryptd.h"
#include "crypto.h"
#include "profile.h"

#define MAC_LEN 32

struct hkdf_priv {
	struct crypt *hk_hmac;
};

static void hkdf_destroy(struct crypt *c)
{
	struct hkdf_priv *hk = crypt_priv(c);

	if (!hk)
		return;

	crypt_destroy(hk->hk_hmac);
	free(hk);
	free(c);
}

static int hkdf_set_key(struct crypt *c, void *data, int len)
{
	struct hkdf_priv *hk = crypt_priv(c);

	crypt_set_key(hk->hk_hmac, data, len);

	return 0;
}

static void hkdf_extract(struct crypt *c, struct iovec *iov, int num,
			 void *out, int *outlen)
{
	struct hkdf_priv *hk = crypt_priv(c);

	crypt_mac(hk->hk_hmac, iov, num, out, outlen);
}

static void hkdf_expand(struct crypt *c, void *tag, int taglen, void *out,
			int len)
{
	struct hkdf_priv *hk = crypt_priv(c);
	unsigned char *p = out;
	uint8_t ctr = 1;
	struct iovec iov[2];
	int outlen = MAC_LEN;

	iov[0].iov_base = tag;
	iov[0].iov_len  = taglen;

	iov[1].iov_base = &ctr;
	iov[1].iov_len  = sizeof(ctr);

	while (len >= MAC_LEN) {
		crypt_mac(hk->hk_hmac, iov, sizeof(iov) / sizeof(*iov),
			  p, &outlen);

		ctr++;

		assert(outlen == MAC_LEN);
		assert(ctr != 0);

		p   += MAC_LEN;
		len -= MAC_LEN;
	}

	if (len) {
		assert(!"implement remainder");
		abort();
	}
}

struct crypt *crypt_HKDF_SHA256_new(void)
{
	struct hkdf_priv *hk;
	struct crypt *c;

	c = crypt_init(sizeof(*hk));
	c->c_destroy = hkdf_destroy;
	c->c_set_key = hkdf_set_key;
	c->c_extract = hkdf_extract;
	c->c_expand  = hkdf_expand;

	hk = crypt_priv(c);
	hk->hk_hmac = crypt_HMAC_SHA256_new();

	return c;
}
