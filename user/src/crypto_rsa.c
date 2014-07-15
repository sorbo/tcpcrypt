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

struct key {
	RSA	*k_rsa;
	int	k_len;
	int	k_blen;
	void	*k_bin;
};

static struct state {
	struct key	s_key;
} _state;

struct tc_priv {
	struct key		*tp_key;
	RSA			*tp_rsa;
	struct tc		*tp_hmac;
	struct crypt_prop	tp_prop;
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

static struct tc_priv *rsa_init_priv(struct tc *tc)
{
	struct tc_priv *tp = crypto_priv_init(tc, sizeof(*tp));

	/* init MAC */
	tp->tp_hmac = xmalloc(sizeof(*tp->tp_hmac));
	tp->tp_hmac->tc_crypt_ops = &_hmac_ops;
	crypto_init(tp->tp_hmac);

	return tp;
}
static void rsa_init(struct tc *tc)
{
	static int init = 0;

	/* XXX have tcpcrypt call this and renew keys */
	if (!init) {
		generate_keys(); 
		init = 1;
	}

	rsa_init_priv(tc);
}

static void rsa_finish(struct tc *tc)
{
	struct tc_priv *tp = crypto_priv(tc);

	if (!tp)
		return;

	if (tp->tp_rsa) {
		tp->tp_rsa->e = NULL;
		RSA_free(tp->tp_rsa);
	}

	if (tp->tp_hmac) {
		crypto_finish(tp->tp_hmac);
		free(tp->tp_hmac);
	}

	free(tp);
}

static void rsa_encrypt(struct tc *tc, void *iv, void *data, int len)
{
	struct tc_priv *tp = crypto_priv(tc);
	int sz = RSA_size(tp->tp_rsa);
	void *out = alloca(sz);

	profile_add(1, "pre pkey encrypt");

	if (RSA_public_encrypt(len, data, out, tp->tp_rsa,
			       RSA_PKCS1_OAEP_PADDING) == -1)
		errssl(1, "RSA_public_encrypt()");

	profile_add(1, "post pkey encrypt");

	memcpy(data, out, sz);
}

static int rsa_decrypt(struct tc *tc, void *iv, void *data, int len)
{
	struct tc_priv *tp = crypto_priv(tc);
	void *out = alloca(len);
	int rc;

	if (_conf.cf_rsa_client_hack)
		return sizeof(tc->tc_nonce);

	profile_add(1, "pre pkey decrypt");

	rc = RSA_private_decrypt(len, data, out, tp->tp_key->k_rsa,
				 RSA_PKCS1_OAEP_PADDING);
	if (rc == -1)
		errssl(1, "RSA_private_decrypt()");

	profile_add(1, "post pkey decrypt");

	memcpy(data, out, rc);

	return rc;
}

static void *rsa_spec(void)
{
	static int init = 0;

	if (!init) {
		_rsa_spec.tcs_algo = htons(_rsa_spec.tcs_algo);
		init = 1;
	}

	return &_rsa_spec;
}

static int rsa_type(void)
{
	return TYPE_PKEY;
}

static int rsa_get_key(struct tc *tc, void **out)
{
	struct tc_priv *tp = crypto_priv(tc);
	struct key *k;

	k = tp->tp_key = get_key();
	*out = k->k_bin;

	return k->k_blen;
}

static int rsa_set_key(struct tc *tc, void *key, int len)
{
	struct tc_priv *tp;
	BIGNUM *pub;
	int plen;
	RSA* r;

	tp = rsa_init_priv(tc);
	tp->tp_rsa = r = RSA_new();
	if (!r)
		goto __err;

	r->n = pub = BN_bin2bn(key, len, NULL);
	if (!pub)
		goto __err;

	plen = BN_num_bits(pub);
	if (plen % LENM)
		goto __err;

	r->e = get_key()->k_rsa->e;

	return 0;
__err:
	crypto_finish(tc);
	return -1;
}

void rsa_mac(struct tc *tc, struct iovec *iov, int num, void *iv,
	     void *out, int *outlen)
{
	struct tc_priv *tp = crypto_priv(tc);

	crypto_mac(tp->tp_hmac, iov, num, iv, out, outlen);
}

void rsa_mac_set_key(struct tc *tc, void *key, int len)
{
	struct tc_priv *tp = crypto_priv(tc);

	crypto_set_key(tp->tp_hmac, key, len);
}

struct crypt_prop *rsa_prop(struct tc *tc)
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

	if (tp->tp_rsa)
		cp->cp_cipherlen = RSA_size(tp->tp_rsa);

	return cp;
}

static struct crypt_ops _rsa_ops = {
	.co_init	= rsa_init,
	.co_finish	= rsa_finish,
	.co_encrypt	= rsa_encrypt,
	.co_decrypt	= rsa_decrypt,
	.co_get_key	= rsa_get_key,
	.co_spec	= rsa_spec,
	.co_type	= rsa_type,
	.co_set_key	= rsa_set_key,
	.co_mac_set_key	= rsa_mac_set_key,
	.co_mac		= rsa_mac,
	.co_crypt_prop	= rsa_prop,
};

static void __rsa_init(void) __attribute__ ((constructor));

static void __rsa_init(void)
{
	crypto_register(&_rsa_ops);
}
