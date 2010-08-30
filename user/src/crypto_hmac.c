#include <sys/uio.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <openssl/hmac.h>

#include "tcpcrypt.h"
#include "tcpcryptd.h"
#include "crypto.h"
#include "profile.h"

#define MAC_SIZE	20

static struct tc_scipher _hmac_spec =
	{ 0, TC_ANY, 0, TC_HMAC_SHA1_128 };

struct hmac_priv {
	HMAC_CTX hp_ctx;
	int	 hp_fresh;
};

static void hmac_init(struct tc *tc)
{
	struct hmac_priv *hp;

	hp = crypto_priv_init(tc, sizeof(*hp));
	HMAC_CTX_init(&hp->hp_ctx);
	HMAC_Init_ex(&hp->hp_ctx, "a", 1, EVP_sha1(), NULL);
}

static void hmac_finish(struct tc *tc)
{
	struct hmac_priv *hp = crypto_priv(tc);

	if (!hp)
		return;

	HMAC_cleanup(&hp->hp_ctx);
	free(hp);
}

static void hmac_mac(struct tc *tc, struct iovec *iov, int num, void *iv,
	             void *out, int *outlen)
{
	struct hmac_priv *hp = crypto_priv(tc);

	if (*outlen < MAC_SIZE) {
		*outlen = MAC_SIZE;
		return;
	}

	profile_add(3, "hmac_mac in");
	
	if (!hp->hp_fresh)
		HMAC_Init_ex(&hp->hp_ctx, NULL, 0, NULL, NULL);
	else
		hp->hp_fresh = 0;

	while (num--) {
		HMAC_Update(&hp->hp_ctx, iov->iov_base, iov->iov_len);
		profile_add(3, "hmac_mac update");
		iov++;
	}

	HMAC_Final(&hp->hp_ctx, out, (unsigned int*) outlen);
	profile_add(3, "hmac_mac final");
}

static void *hmac_spec(void)
{
	return &_hmac_spec;
}

static int hmac_type(void)
{
	return TYPE_MAC;
}

static int hmac_set_key(struct tc *tc, void *key, int len)
{
	struct hmac_priv *hp = crypto_priv(tc);

	HMAC_Init_ex(&hp->hp_ctx, key, len, NULL, NULL);
	hp->hp_fresh = 1;

	return 0;
}

struct crypt_ops _hmac_ops = {
	.co_init	= hmac_init,
	.co_finish	= hmac_finish,
	.co_mac		= hmac_mac,
	.co_spec	= hmac_spec,
	.co_type	= hmac_type,
	.co_set_key	= hmac_set_key,
};

static void __hmac_init(void) __attribute__ ((constructor));

static void __hmac_init(void)
{
	crypto_register(&_hmac_ops);
}
