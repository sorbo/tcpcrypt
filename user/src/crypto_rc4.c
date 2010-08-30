#include <sys/uio.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <openssl/evp.h>
#include <err.h>

#include "tcpcrypt.h"
#include "tcpcryptd.h"
#include "crypto.h"
#include "profile.h"

#define WINSIZE		(10 * 1024 * 1024)

static struct tc_scipher _rc4_spec =
	{ 0, TC_RC4, 0, TC_ANY };

static struct crypt_prop _rc4_prop = {
	.cp_ivlen	= 0,
	.cp_ivmode	= IVMODE_SEQ,
	.cp_maclen	= 0,
	.cp_cipherlen	= 0,
	.cp_preference  = -1,
	.cp_rekey	= 0, // 666 * 1024 * 1024,
};

struct keystream {
	uint64_t	k_start;
	uint64_t	k_end;
	uint8_t		k_buf[WINSIZE];
	uint8_t		*k_head;
	uint8_t		*k_tail;
};

struct rc4_priv {
	EVP_CIPHER_CTX		ap_ctx;
	struct keystream	ap_rx;
	struct keystream	ap_tx;
	uint8_t			ap_one[2048];
};

static void rc4_init(struct tc *tc)
{
	struct rc4_priv *ap = crypto_priv_init(tc, sizeof(*ap));

	EVP_CIPHER_CTX_init(&ap->ap_ctx);
	if (!EVP_CipherInit_ex(&ap->ap_ctx, EVP_rc4(), NULL, NULL, NULL, 1))
		errssl(1, "EVP_CipherInit_ex()");

	memset(ap->ap_one, 0xff, sizeof(ap->ap_one));
}

static void rc4_finish(struct tc *tc)
{
	struct rc4_priv *ap = crypto_priv(tc);

	if (!ap)
		return;

	EVP_CIPHER_CTX_cleanup(&ap->ap_ctx);

	free(ap);
}

static void xor(void *out, void *in, int len)
{
	uint32_t *o = out, *i = in;
	uint8_t *o2, *i2;

	while (len > 4) {
		*o++ ^= *i++;
		len -= 4;
	}

	o2 = (uint8_t*) o;
	i2 = (uint8_t*) i;

	while (len--)
		*o2++ ^= *i2++;
}

static void do_rc4(struct tc *tc, void *iv, void *data, int len, int enc)
{
	struct rc4_priv *ap = crypto_priv(tc);
	uint64_t seq = xbe64toh(*((uint64_t*) iv));
	struct keystream *k = enc ? &ap->ap_tx : &ap->ap_rx;
	int need;
	uint8_t *p;

	/* XXX all of this should be implemented in a "stream-cipher layer" */

	/* init */
	if (!k->k_head) {
		k->k_head  = k->k_tail = k->k_buf;
		k->k_start = k->k_end = seq;
	}

	/* expand keystream.  XXX seqno wraps */
	need = seq + len - k->k_end;
	while (need > 0) {
		int left = sizeof(k->k_buf) - (k->k_end - k->k_start);
		int tail = &k->k_buf[sizeof(k->k_buf)] - k->k_tail;
		int sz   = need;

		assert(left >= 0);
		assert(k->k_head >= k->k_buf 
		       && k->k_head < &k->k_buf[sizeof(k->k_buf)]);
		assert(k->k_tail >= k->k_buf 
		       && k->k_tail <= &k->k_buf[sizeof(k->k_buf)]);
		assert(left || (k->k_head == k->k_tail));

		if (sz > tail)
			sz = tail;

		if (sz > sizeof(ap->ap_one))
			sz = sizeof(ap->ap_one);

		if (!EVP_EncryptUpdate(&ap->ap_ctx, k->k_tail, &sz, ap->ap_one,
				       sz))
			errssl(1, "EVP_EncryptUpdate()");

		k->k_end  += sz;
		k->k_tail += sz;
		need      -= sz;

		if (sz == tail)
			k->k_tail = k->k_buf;

		if (sz > left) {
			sz -= left;
			k->k_head  += sz;
			k->k_start += sz;
			if (k->k_head == &k->k_buf[sizeof(k->k_buf)])
				k->k_head = k->k_buf;
		}
	}

	if (seq < k->k_start) {
		printf("seq %llx start %llx end %llx\n",
		       seq, k->k_start, k->k_end);
	}

	assert(seq >= k->k_start);
	assert((seq + len) <= k->k_end);

	/* XOR */
	p = k->k_head + (seq - k->k_start);
	if (p >= &k->k_buf[sizeof(k->k_buf)])
		p = k->k_buf + (p - &k->k_buf[sizeof(k->k_buf)]);

	need = &k->k_buf[sizeof(k->k_buf)] - p;
	assert(need > 0);

	if (len < need)
		need = len;

	xor(data, p, need);
	len -= need;
	xor(data, k->k_buf, len);
}

static void rc4_encrypt(struct tc *tc, void *iv, void *data, int len)
{
	do_rc4(tc, iv, data, len, 1);
}

static int rc4_decrypt(struct tc *tc, void *iv, void *data, int len)
{
	do_rc4(tc, iv, data, len, 0);

	return len;
}

static void *rc4_spec(void)
{
	return &_rc4_spec;
}

static int rc4_type(void)
{
	return TYPE_SYM;
}

static int rc4_set_key(struct tc *tc, void *key, int len)
{
	struct rc4_priv *ap = crypto_priv(tc);

	assert(len >= EVP_CIPHER_CTX_key_length(&ap->ap_ctx));

	if (!EVP_CipherInit_ex(&ap->ap_ctx, NULL, NULL, key, NULL, 1))
		errssl(1, "EVP_CipherInit_ex()");

	return 0;
}

static void rc4_next_iv(struct tc *tc, void *out, int *outlen)
{
	assert(*outlen == 0);

	*outlen = -IVMODE_SEQ;
}

static struct crypt_prop *rc4_crypt_prop(struct tc *tc)
{
	return &_rc4_prop;
}

static struct crypt_ops _rc4_ops = {
	.co_init	= rc4_init,
	.co_finish	= rc4_finish,
	.co_encrypt	= rc4_encrypt,
	.co_decrypt	= rc4_decrypt,
	.co_spec	= rc4_spec,
	.co_type	= rc4_type,
	.co_set_key	= rc4_set_key,
	.co_next_iv	= rc4_next_iv,
	.co_crypt_prop	= rc4_crypt_prop,
};

static void __rc4_init(void) __attribute__ ((constructor));

static void __rc4_init(void)
{
	crypto_register(&_rc4_ops);
}
