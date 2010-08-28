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

#include "tcpcrypt_ctl.h"
#include "tcpcrypt.h"
#include "tcpcryptd.h"
#include "crypto.h"
#include "profile.h"

#define BLEN	16

static struct tc_scipher _aes_spec =
	{ 0, TC_AES128_CTR_SEQIV, 0, TC_ANY };

struct aes_priv {
	EVP_CIPHER_CTX ap_ctx;
};

static void aes_init(struct tc *tc)
{
	struct aes_priv *ap = crypto_priv_init(tc, sizeof(*ap));

	EVP_CIPHER_CTX_init(&ap->ap_ctx);
}

static void aes_finish(struct tc *tc)
{
	struct aes_priv *ap = crypto_priv(tc);

	if (!ap)
		return;

	EVP_CIPHER_CTX_cleanup(&ap->ap_ctx);

	free(ap);
}

static void do_aes(struct tc *tc, void *iv, void *data, int len, int enc)
{
	struct aes_priv *ap = crypto_priv(tc);
	int blen;
	uint8_t *blocks;
	uint64_t ctr;
	uint64_t inc = xhtobe64(1);
	int rem, drem;
	uint64_t *ctrp;
	int i;
	uint32_t *pb, *pd;
	uint8_t *pb2, *pd2;
	uint16_t* csum = data;

	profile_add(3, "do_aes in");
	assert(len);

	/* figure out counter value and remainder (use of previous block) */
	ctr  = xbe64toh(*((uint64_t*) iv));
	rem  = ctr & 0xf;
	ctr &= ~0xf;
	xhtobe64(ctr);

	/* figure out how many blocks we need */
	blen = (len & ~0xf);
	if (rem)
		blen += BLEN;

	drem = len & 0xf;
	if (drem && ((drem > (16 - rem)) || !rem))
		blen += BLEN;

	blocks = alloca(blen);
	assert(blocks);

	profile_add(3, "do_aes setup");

	/* fill blocks with counter values */
	ctrp = (uint64_t*) blocks;
	for (i = 0; i < (blen >> 4); i++) {
		*ctrp++ = 0;
		*ctrp++ = ctr;
		ctr    += inc;
	}

	profile_add(3, "do_aes fill blocks");

	/* do AES */
	i = blen;
	if (!EVP_EncryptUpdate(&ap->ap_ctx, blocks, &i, blocks, blen))
		errssl(1, "EVP_EncryptUpdate()");

	assert(i == blen);

	profile_add(3, "do_aes AES");

	/* XOR data (and checksum) */
	pb = (uint32_t*) &blocks[rem];
	pd = (uint32_t*) data;
	while (len >= 4) {
		*pd++ ^= *pb++;
		len   -= 4;

		tc->tc_csum += *csum++;
		tc->tc_csum += *csum++;
	}

	profile_add(3, "do_aes XOR words");

	/* XOR any remainder (< 4 bytes) */
	i   = 0; /* unsummed */
	pb2 = (uint8_t*) pb;
	pd2 = (uint8_t*) pd;
	while (len > 0) {
		*pd2++ ^= *pb2++;
		len--;
		
		if (i == 1) {
			tc->tc_csum += *csum++;
			i = 0;
		} else
			i++;
	}

	profile_add(3, "do_aes XOR remainder");

	assert(pb2 - blocks <= blen);
	assert(blen - (pb2 - blocks) < 16); /* efficiency */

	/* sum odd byte */
	if (i) {
		i = 0;
		*((uint8_t*) &i) = *((uint8_t*) csum);
		tc->tc_csum += i;
	}
}

static void aes_encrypt(struct tc *tc, void *iv, void *data, int len)
{
	do_aes(tc, iv, data, len, 1);
}

static int aes_decrypt(struct tc *tc, void *iv, void *data, int len)
{
	do_aes(tc, iv, data, len, 0);

	return len;
}

static void *aes_spec(void)
{
	return &_aes_spec;
}

static int aes_type(void)
{
	return TYPE_SYM;
}

static int aes_set_key(struct tc *tc, void *key, int len)
{
	struct aes_priv *ap = crypto_priv(tc);

	assert(len >= 16);
	if (!EVP_EncryptInit(&ap->ap_ctx, EVP_aes_128_ecb(), key, NULL))
		errssl(1, "EVP_EncryptInit()");

	return 0;
}

static void aes_next_iv(struct tc *tc, void *out, int *outlen)
{
	assert(*outlen == 0);

	*outlen = -IVMODE_SEQ;
}

static struct crypt_ops _aes_ops = {
	.co_init	= aes_init,
	.co_finish	= aes_finish,
	.co_encrypt	= aes_encrypt,
	.co_decrypt	= aes_decrypt,
	.co_spec	= aes_spec,
	.co_type	= aes_type,
	.co_set_key	= aes_set_key,
	.co_next_iv	= aes_next_iv,
};

static void __aes_init(void) __attribute__ ((constructor));

static void __aes_init(void)
{
	crypto_register(&_aes_ops);
}
