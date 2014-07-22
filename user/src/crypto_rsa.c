#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <openssl/rsa.h>
#include <openssl/err.h>

#include "inc.h"
#include "tcpcrypt_ctl.h"
#include "tcpcrypt.h"
#include "tcpcryptd.h"
#include "crypto.h"
#include "profile.h"

#define KEYLEN		4096
#define LENM		(KEYLEN / 8)
#define RSA_EXPONENT	3

struct key {
	RSA	*k_rsa;
	int	k_len;
	int	k_blen;
	void	*k_bin;
};

static struct state {
	struct key	s_key;
} _state;

struct rsa_priv {
	struct key		*r_key;
	RSA			*r_rsa;
};

static RSA* generate_key(int bits)
{
	RSA* r;

	xprintf(XP_DEFAULT, "Generating RSA key: %d bits\n", bits);
	r = RSA_generate_key(bits, RSA_EXPONENT, NULL, NULL);
	if (!r)
		errssl(1, "RSA_generate_key()");

	return r;
}

static void generate_keys(void)
{
	struct key *k = &_state.s_key;

	xprintf(XP_DEFAULT, "Generating RSA key\n");

	if (k->k_rsa) { 
		RSA_free(k->k_rsa);
		free(k->k_bin);
	}

	k->k_len  = KEYLEN;
	k->k_rsa  = generate_key(k->k_len);
	k->k_blen = BN_num_bytes(k->k_rsa->n);
	k->k_bin  = xmalloc(k->k_blen);
	BN_bn2bin(k->k_rsa->n, k->k_bin);

	xprintf(XP_DEFAULT, "Done generating RSA key\n");
}

static struct key *get_key(void)
{
	return &_state.s_key;
}

static void rsa_destroy(struct crypt *c)
{
	struct rsa_priv *tp = crypt_priv(c);

	if (!tp)
		return;

	if (tp->r_rsa) {
		tp->r_rsa->e = NULL;
		RSA_free(tp->r_rsa);
	}

	free(tp);
	free(c);
}

static int rsa_encrypt(struct crypt *c, void *iv, void *data, int len)
{
	struct rsa_priv *tp = crypt_priv(c);
	int sz = RSA_size(tp->r_rsa);
	void *out = alloca(sz);

	profile_add(1, "pre pkey encrypt");

	if (RSA_public_encrypt(len, data, out, tp->r_rsa,
			       RSA_PKCS1_OAEP_PADDING) == -1)
		errssl(1, "RSA_public_encrypt()");

	profile_add(1, "post pkey encrypt");

	memcpy(data, out, sz);

	return sz;
}

static int rsa_decrypt(struct crypt *c, void *iv, void *data, int len)
{
	struct rsa_priv *tp = crypt_priv(c);
	void *out = alloca(len);
	int rc;

	if (_conf.cf_rsa_client_hack)
		assert(!"not implemented");

	profile_add(1, "pre pkey decrypt");

	rc = RSA_private_decrypt(len, data, out, tp->r_key->k_rsa,
				 RSA_PKCS1_OAEP_PADDING);
	if (rc == -1)
		errssl(1, "RSA_private_decrypt()");

	profile_add(1, "post pkey decrypt");

	memcpy(data, out, rc);

	return rc;
}

static int rsa_get_key(struct crypt *c, void **out)
{
	struct rsa_priv *tp = crypt_priv(c);
	struct key *k;

	k = tp->r_key = get_key();
	*out = k->k_bin;

	return k->k_blen;
}

static int rsa_set_key(struct crypt *c, void *key, int len)
{
	struct rsa_priv *tp = crypt_priv(c);
	BIGNUM *pub;
	int plen;
	RSA* r;

	tp->r_rsa = r = RSA_new();
	if (!r)
		return -1;

	r->n = pub = BN_bin2bn(key, len, NULL);
	if (!pub)
		return -1;

	plen = BN_num_bits(pub);
	if (plen % LENM)
		return -1;

	r->e = get_key()->k_rsa->e;

	return 0;
}

struct crypt *crypt_RSA_new(void)
{
        struct rsa_priv *r;
        struct crypt *c;
	static int init = 0;

        c = crypt_init(sizeof(*r));
	c->c_destroy = rsa_destroy;
	c->c_set_key = rsa_set_key;
	c->c_get_key = rsa_get_key;
	c->c_encrypt = rsa_encrypt;
	c->c_decrypt = rsa_decrypt;

        r = crypt_priv(c);

	/* XXX have tcpcrypt call this and renew keys */
	if (!init) {
		generate_keys();
		init = 1;
	}

        return c;
}
