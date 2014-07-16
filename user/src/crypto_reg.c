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
	cp->cp_max_key    = (4096 / 8);
	cp->cp_cipher_len = (4096 / 8);

	return cp;
}

static void register_pub(int id, struct crypt_pub *(*ctr)(void))
{
	crypt_register(TYPE_PKEY, id, (crypt_ctr) ctr);
}

static void __register_ciphers(void) __attribute__ ((constructor));

static void __register_ciphers(void)
{
	register_pub(TC_CIPHER_OAEP_RSA_3, RSA_HKDF_new);
}
