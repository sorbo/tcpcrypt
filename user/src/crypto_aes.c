#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <openssl/evp.h>

#include "inc.h"
#include "tcpcrypt_ctl.h"
#include "tcpcrypt.h"
#include "tcpcryptd.h"
#include "crypto.h"
#include "profile.h"

#define BLEN	16

struct aes_priv {
	EVP_CIPHER_CTX		ap_ctx;
};

/* XXX move CTR / ASM mode outside of AES-specific implementation */
static void do_aes(struct crypt *c, void *iv, void *data, int len, int enc)
{
	struct aes_priv *ap = crypt_priv(c);
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

//		tc->tc_csum += *csum++;
//		tc->tc_csum += *csum++;
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
//			tc->tc_csum += *csum++;
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
//		tc->tc_csum += i;
	}
}

static int aes_encrypt(struct crypt *c, void *iv, void *data, int len)
{
	do_aes(c, iv, data, len, 1);

	return len;
}

static int aes_decrypt(struct crypt *c, void *iv, void *data, int len)
{
	do_aes(c, iv, data, len, 0);

	return len;
}

static int aes_set_key(struct crypt *c, void *key, int len)
{
	struct aes_priv *ap = crypt_priv(c);

	assert(len >= 16);
	if (!EVP_EncryptInit(&ap->ap_ctx, EVP_aes_128_ecb(), key, NULL))
		errssl(1, "EVP_EncryptInit()");

	return 0;
}

static void aes_ack_mac(struct crypt *c, struct iovec *iov, int num, void *out,
                        int *outlen)
{
	struct aes_priv *ap = crypt_priv(c);
	unsigned char block[BLEN];

	assert(num == 1);
	assert(iov->iov_len <= sizeof(block));

	memset(block, 0, sizeof(block));
	memcpy(block, iov->iov_base, iov->iov_len);

	if (!EVP_EncryptUpdate(&ap->ap_ctx, out, outlen, block, sizeof(block)))
		errssl(1, "EVP_EncryptUpdate()");
}

static void aes_destroy(struct crypt *c)
{
	struct aes_priv *p = crypt_priv(c);

	EVP_CIPHER_CTX_cleanup(&p->ap_ctx);

	free(p);
	free(c);
}

struct crypt *crypt_AES_new(void)
{
        struct aes_priv *p;
        struct crypt *c;

        c = crypt_init(sizeof(*p));
        c->c_destroy = aes_destroy;
	c->c_set_key = aes_set_key;
	c->c_mac     = aes_ack_mac;
	c->c_encrypt = aes_encrypt;
	c->c_decrypt = aes_decrypt;

        p = crypt_priv(c);

	EVP_CIPHER_CTX_init(&p->ap_ctx);

        return c;
}
