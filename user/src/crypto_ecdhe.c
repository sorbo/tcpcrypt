#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/err.h>

#include "inc.h"
#include "tcpcrypt_ctl.h"
#include "tcpcrypt.h"
#include "tcpcryptd.h"
#include "crypto.h"
#include "profile.h"

struct ecdhe_priv {
	EC_KEY	*ec_key;
	EC_KEY	*ec_peer;
	void	*ec_bin;
	int	ec_bin_len;
	int	ec_nid;
};

static int set_peer_key(struct crypt *c, void *key, int len)
{
        struct ecdhe_priv *p = crypt_priv(c);

	EC_KEY *k;
	const unsigned char *kk = key;

	k = EC_KEY_new_by_curve_name(p->ec_nid);
	assert(k);

	k = o2i_ECPublicKey(&k, &kk, len);
	if (!k)
		return -1;

	p->ec_peer = k;

	return 0;
}

static void ecdhe_destroy(struct crypt *c)
{
	struct ecdhe_priv *tp = crypt_priv(c);

	if (!tp)
		return;

	if (tp->ec_key)
		EC_KEY_free(tp->ec_key);

	if (tp->ec_peer)
		EC_KEY_free(tp->ec_peer);

	if (tp->ec_bin)
		free(tp->ec_bin);

	free(tp);
	free(c);
}

static int ecdhe_compute_key(struct crypt *c, void *out)
{
        struct ecdhe_priv *ec = crypt_priv(c);

	return ECDH_compute_key(out, 1024,
			        EC_KEY_get0_public_key(ec->ec_peer),
			        ec->ec_key, NULL);
}

/* XXX - factor out in tcpcrypt.c?  call this kxs?  */
static int ecdhe_encrypt(struct crypt *c, void *iv, void *data, int len)
{
	struct ecdhe_priv *tp = crypt_priv(c);
	unsigned char *p = data;

	memmove(data + 1, data, len);
	*p = (uint8_t) len;

	p += 1 + len;

	memcpy(p, tp->ec_bin, tp->ec_bin_len);

	p += tp->ec_bin_len;

	return (unsigned long) p - (unsigned long) data;
}

/* XXX same as above */
static int ecdhe_decrypt(struct crypt *c, void *iv, void *data, int len)
{
	unsigned char *p = data;
	int nonce_len = 32;

	if (*p++ != nonce_len)
		return -1;

	p += nonce_len;

	len -= (unsigned long) p - (unsigned long) data;
	if (len <= 0)
		return -1;

	if (set_peer_key(c, p, len) == -1)
		return -1;

	return ecdhe_compute_key(c, data);
}

static int ecdhe_get_key(struct crypt *c, void **out)
{
        struct ecdhe_priv *p = crypt_priv(c);

	*out = p->ec_bin;

	return p->ec_bin_len;
}

static int ecdhe_set_key(struct crypt *c, void *key, int len)
{
	return set_peer_key(c, key, len);
}

static struct crypt *crypt_ECDHE_new(int nid)
{
        struct ecdhe_priv *r;
        struct crypt *c;
	unsigned char *p;

        c = crypt_init(sizeof(*r));
	c->c_destroy     = ecdhe_destroy;
	c->c_get_key     = ecdhe_get_key;
	c->c_set_key     = ecdhe_set_key;
	c->c_encrypt     = ecdhe_encrypt;
	c->c_decrypt     = ecdhe_decrypt;
	c->c_compute_key = ecdhe_compute_key;

        r = crypt_priv(c);

	r->ec_nid = nid;

	if (!(r->ec_key = EC_KEY_new_by_curve_name(r->ec_nid)))
		errx(1, "unknown curve nid %d", nid);

	if (EC_KEY_generate_key(r->ec_key) != 1)
		errx(1, "EC_KEY_generate_key()");

	r->ec_bin_len = i2o_ECPublicKey(r->ec_key, NULL);
	assert(r->ec_bin_len > 0);

	r->ec_bin = xmalloc(r->ec_bin_len);
	p = r->ec_bin;
	i2o_ECPublicKey(r->ec_key, &p);

        return c;
}

struct crypt *crypt_ECDHE256_new(void)
{
	return crypt_ECDHE_new(NID_X9_62_prime256v1);
}

struct crypt *crypt_ECDHE521_new(void)
{
	return crypt_ECDHE_new(NID_secp521r1);
}
