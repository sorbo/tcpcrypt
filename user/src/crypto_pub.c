#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/err.h>

#include "inc.h"
#include "tcpcrypt_ctl.h"
#include "tcpcrypt.h"
#include "tcpcryptd.h"
#include "crypto.h"
#include "profile.h"

#define NONCE_LEN	32
#define NONCE_LEN_S	48
#define KEYLEN		4096
#define LENM		(KEYLEN / 8)
#define RSA_EXPONENT	3

static struct tc_cipher_spec _rsa_spec = 
	{ 0, TC_CIPHER_OAEP_RSA_3 };

static struct crypt_prop _rsa_prop;

struct tc_priv {
	struct crypt		*tp_hkdf;
	struct crypt		*tp_pub;
	struct crypt_prop	tp_prop;
};

static void pub_init_priv(struct tc *tc)
{
	struct tc_priv *tp = crypto_priv_init(tc, sizeof(*tp));

	tp->tp_hkdf = crypt_HKDF_SHA256_new();
	tp->tp_pub  = crypt_RSA_new();
}

static void pub_init(struct tc *tc)
{
	pub_init_priv(tc);
}

static void pub_finish(struct tc *tc)
{
	struct tc_priv *tp = crypto_priv(tc);

	if (!tp)
		return;

	if (tp->tp_pub)
		crypt_destroy(tp->tp_pub);

	if (tp->tp_hkdf)
		crypt_destroy(tp->tp_hkdf);

	free(tp);
}

static void pub_encrypt(struct tc *tc, void *iv, void *data, int len)
{
	struct tc_priv *tp = crypto_priv(tc);

	crypt_encrypt(tp->tp_pub, iv, data, len);
}

static int pub_decrypt(struct tc *tc, void *iv, void *data, int len)
{
	struct tc_priv *tp = crypto_priv(tc);

	return crypt_decrypt(tp->tp_pub, iv, data, len);
}

static void *pub_spec(void)
{
	static int init = 0;

	if (!init) {
		_rsa_spec.tcs_algo = htons(_rsa_spec.tcs_algo);
		init = 1;
	}

	return &_rsa_spec;
}

static int pub_type(void)
{
	return TYPE_PKEY;
}

static int pub_get_key(struct tc *tc, void **out)
{
	struct tc_priv *tp = crypto_priv(tc);

	return crypt_get_key(tp->tp_pub, out);
}

static int pub_set_key(struct tc *tc, void *key, int len)
{
	struct tc_priv *tp;
	int rc;

	pub_init_priv(tc);
	tp = crypto_priv(tc);
	rc = crypt_set_key(tp->tp_pub, key, len);
	if (rc == -1)
		crypto_finish(tc);

	return rc;
}

static void pub_mac_set_key(struct tc *tc, void *key, int len)
{
	struct tc_priv *tp = crypto_priv(tc);

	crypt_set_key(tp->tp_hkdf, key, len);
}

static void pub_extract(struct tc *tc, struct iovec *iov, int num, void *out,
		 int *outlen)
{
	struct tc_priv *tp = crypto_priv(tc);

	crypt_extract(tp->tp_hkdf, iov, num, out, outlen);
}

static void pub_expand(struct tc *tc, uint8_t tag, int len, void *out)
{
	struct tc_priv *tp = crypto_priv(tc);

	crypt_expand(tp->tp_hkdf, tag, len, out);
}

static struct crypt_prop *pub_prop(struct tc *tc)
{
	struct tc_priv *tp;
	struct crypt_prop *cp;

	if (!tc)
		return &_rsa_prop;

	tp = crypto_priv(tc);
	cp = &tp->tp_prop;

	cp->cp_noncelen   = NONCE_LEN;
	cp->cp_noncelen_s = NONCE_LEN_S;
	cp->cp_keylen     = (KEYLEN / 8);

	if (tp->tp_pub)
		cp->cp_cipherlen = 512; /* XXX */

	return cp;
}

static struct crypt_ops _pub_ops = {
	.co_init	= pub_init,
	.co_finish	= pub_finish,
	.co_encrypt	= pub_encrypt,
	.co_decrypt	= pub_decrypt,
	.co_get_key	= pub_get_key,
	.co_spec	= pub_spec,
	.co_type	= pub_type,
	.co_set_key	= pub_set_key,
	.co_mac_set_key	= pub_mac_set_key,
	.co_extract	= pub_extract,
	.co_expand	= pub_expand,
	.co_crypt_prop	= pub_prop,
};

static void __pub_init(void) __attribute__ ((constructor));

static void __pub_init(void)
{
	crypto_register(&_pub_ops);
}
