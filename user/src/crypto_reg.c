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

static struct crypt_pub *RSA_HKDF_new(void)
{
	struct crypt_pub *cp = xmalloc(sizeof(*cp));

	memset(cp, 0, sizeof(*cp));

	cp->cp_hkdf       = crypt_HKDF_SHA256_new();
	cp->cp_pub        = crypt_RSA_new();
	cp->cp_n_c        = 32;
	cp->cp_n_s        = 48;
	cp->cp_k_len      = 32;
	cp->cp_min_key    = (2048 / 8);
	cp->cp_max_key    = (4096 / 8);
	cp->cp_cipher_len = (4096 / 8);

	return cp;
}

static struct crypt_pub *ECDHE_HKDF_new(struct crypt*(*ctr)(void), int klen)
{
	struct crypt_pub *cp = xmalloc(sizeof(*cp));

	memset(cp, 0, sizeof(*cp));

	cp->cp_hkdf          = crypt_HKDF_SHA256_new();
	cp->cp_pub           = ctr();
	cp->cp_n_c           = 32;
	cp->cp_n_s           = 32;
	cp->cp_k_len         = 32;
	cp->cp_max_key       = (4096 / 8);
	cp->cp_cipher_len    = 1 + cp->cp_n_s + klen;
	cp->cp_key_agreement = 1;

	return cp;
}

static struct crypt_pub *ECDHE256_HKDF_new(void)
{
	return ECDHE_HKDF_new(crypt_ECDHE256_new, 65);
}

static struct crypt_pub *ECDHE521_HKDF_new(void)
{
	return ECDHE_HKDF_new(crypt_ECDHE521_new, 133);
}

static struct crypt_sym *AES_HMAC_new(void)
{
	struct crypt_sym *cs = xmalloc(sizeof(*cs));

	memset(cs, 0, sizeof(*cs));

	cs->cs_cipher  = crypt_AES_new();
	cs->cs_mac     = crypt_HMAC_SHA256_new();
	cs->cs_ack_mac = crypt_AES_new();
	cs->cs_mac_len = (128 / 8);

	return cs;
}

static void register_pub(unsigned int id, struct crypt_pub *(*ctr)(void))
{
	crypt_register(TYPE_PKEY, id, (crypt_ctr) ctr);
}

static void register_sym(unsigned int id, struct crypt_sym *(*ctr)(void))
{
	crypt_register(TYPE_SYM, id, (crypt_ctr) ctr);
}

static void __register_ciphers(void) __attribute__ ((constructor));

static void __register_ciphers(void)
{
	register_pub(TC_CIPHER_OAEP_RSA_3, RSA_HKDF_new);
	register_pub(TC_CIPHER_ECDHE_P256, ECDHE256_HKDF_new);
	register_pub(TC_CIPHER_ECDHE_P521, ECDHE521_HKDF_new);

	register_sym(TC_AES128_HMAC_SHA2, AES_HMAC_new);
}
