#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <openssl/hmac.h>

#include "inc.h"
#include "tcpcrypt_ctl.h"
#include "tcpcrypt.h"
#include "tcpcryptd.h"
#include "crypto.h"
#include "profile.h"

#define MAC_SIZE	32

struct hmac_priv {
	HMAC_CTX hp_ctx;
	int	 hp_fresh;
};

static void hmac_destroy(struct crypt *c)
{
	struct hmac_priv *hp = crypt_priv(c);

	if (!hp)
		return;

	HMAC_cleanup(&hp->hp_ctx);
	free(hp);
	free(c);
}

static void hmac_mac(struct crypt *c, struct iovec *iov, int num,
	             void *out, int *outlen)
{
	struct hmac_priv *hp = crypt_priv(c);
	void *o = out;
	unsigned int olen = MAC_SIZE;

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

	if (*outlen < MAC_SIZE)
		o = alloca(MAC_SIZE);

	HMAC_Final(&hp->hp_ctx, o, &olen);
	profile_add(3, "hmac_mac final");

	if (*outlen < MAC_SIZE)
		memcpy(out, o, *outlen);
	else
		*outlen = olen;
}

static int hmac_set_key(struct crypt *c, void *key, int len)
{
	struct hmac_priv *hp = crypt_priv(c);

	HMAC_Init_ex(&hp->hp_ctx, key, len, NULL, NULL);
	hp->hp_fresh = 1;

	return 0;
}

struct crypt *crypt_HMAC_SHA256_new(void)
{
	struct hmac_priv *hp;
	struct crypt *c;

	c = crypt_init(sizeof(*hp));
	c->c_destroy = hmac_destroy;
	c->c_set_key = hmac_set_key;
	c->c_mac     = hmac_mac;

	hp = crypt_priv(c);

	HMAC_CTX_init(&hp->hp_ctx);
	HMAC_Init_ex(&hp->hp_ctx, "a", 1, EVP_sha256(), NULL);

	return c;
}
