#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

#include "contrib/umac.h"
#include "inc.h"
#include "tcpcrypt_ctl.h"
#include "tcpcrypt.h"
#include "tcpcryptd.h"
#include "crypto.h"
#include "profile.h"

#if 0
#define MAC_SIZE	8

static struct tc_scipher _umac_spec =
	{ 0x0 };

static struct crypt_prop _umac_prop = {
        .cp_ivlen       = 0,
        .cp_ivmode      = IVMODE_NONE,
        .cp_maclen      = MAC_SIZE,
        .cp_cipherlen   = 0,
        .cp_preference  = -1,
};

struct umac_priv {
	umac_ctx_t	hp_ctx;
};

static void umac_init(struct tc *tc)
{
	struct umac_priv *hp;

	hp = crypto_priv_init(tc, sizeof(*hp));
}

static void umac_finish(struct tc *tc)
{
	struct umac_priv *hp = crypto_priv(tc);

	if (!hp)
		return;

	if (hp->hp_ctx)
		umac_delete(hp->hp_ctx);

	free(hp);
}

static void umac_mac(struct tc *tc, struct iovec *iov, int num, void *iv,
	             void *out, int *outlen)
{
	struct umac_priv *hp = crypto_priv(tc);
	char nonce[8];

	if (*outlen < MAC_SIZE) {
		*outlen = MAC_SIZE;
		return;
	}

	memset(nonce, 0, sizeof(nonce));

	umac_reset(hp->hp_ctx);
	while (num--) {
		umac_update(hp->hp_ctx, iov->iov_base, iov->iov_len);
		iov++;
	}

	umac_final(hp->hp_ctx, out, nonce);
	*outlen = MAC_SIZE;
}

static void *umac_spec(void)
{
	return &_umac_spec;
}

static int umac_type(void)
{
	return TYPE_MAC;
}

static int umac_set_key(struct tc *tc, void *key, int len)
{
	struct umac_priv *hp = crypto_priv(tc);

	if (hp->hp_ctx)
		umac_delete(hp->hp_ctx);

	hp->hp_ctx = umac_new(key);
	assert(hp->hp_ctx);

	return 0;
}

static struct crypt_prop *umac_prop(struct tc *tc)
{       
        return &_umac_prop;
}

struct crypt_ops _umac_ops = {
	.co_init	= umac_init,
	.co_finish	= umac_finish,
	.co_mac		= umac_mac,
	.co_spec	= umac_spec,
	.co_type	= umac_type,
	.co_set_key	= umac_set_key,
	.co_crypt_prop	= umac_prop,
};

static void __umac_init(void) __attribute__ ((constructor));

static void __umac_init(void)
{
//	crypto_register(&_umac_ops);
}
#endif
