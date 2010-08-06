#include <linux/module.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <crypto/algapi.h>
#include <crypto/sha.h>
#include <linux/cryptohash.h>
#include <crypto/internal/hash.h>

#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

#undef  SHA_0
#define SHA_1
#define SHA1_ASM
#include <crypto/sha/sha_locl.h>

static unsigned char key[] =
	/* public */
    "\x00\x00\x01\x01\x00\xa5\x48\x1b\x90\xca\xcf\x8d\x06\x3b\xc0\x47\xca\xf3\x00"
    "\xa6\xfe\x00\xee\x7d\x77\x69\x09\xd5\xf8\x15\x9b\x09\x91\xaf"
    "\x30\x9a\x8c\x46\x0f\x21\x28\x96\x68\x6a\x60\xaf\xab\xbf\x5f"
    "\x99\xb8\x56\x6d\xd9\x81\x4c\xc1\xcf\xc5\x5a\x1f\xeb\xc7\x20"
    "\x0a\x5e\x9a\xf8\x05\x6e\x3a\x0c\x09\x59\x8d\x0f\x29\x6c\xf5"
    "\xc9\x0f\xcd\xb1\xaa\x89\x7d\xc9\xf9\x3d\x37\xf2\x52\xe6\x9f"
    "\x56\x38\xa0\x44\x3a\x8d\x14\xac\xd5\xc7\x03\x35\x83\x88\x38"
    "\x73\xa5\xba\x76\xde\xe6\x87\xc4\xf8\x0e\xf5\xec\x1c\xbc\xf8"
    "\xfe\xf5\xf6\xb7\x6d\x4d\x9a\x6c\x6e\xb0\x03\x60\x53\x86\x5e"
    "\xd6\xa0\x04\xb7\x84\x71\x0d\x32\xd4\xf5\x2f\x7d\x0a\xda\x11"
    "\x53\xc8\x9c\x1f\x23\x0a\x82\xec\xf3\xc7\x16\x98\x95\x7a\x81"
    "\xc9\xdf\x95\x55\x62\xf2\x77\x86\x14\x64\xa5\x54\x0a\xc1\x49"
    "\xd1\x2a\xfb\x53\xac\x02\xd4\xcc\xad\xa9\x11\x5e\x51\x62\x79"
    "\x1e\xf5\x2e\xb2\xa2\x26\xc6\x8a\x90\x3d\x3f\xb6\x4b\x2f\xf0"
    "\xc4\x6f\xce\x0f\x2e\xb5\xff\x64\xd7\x81\xac\xb9\xd0\xd8\x30"
    "\xec\x9b\x41\x29\xab\x28\x8a\xd8\x72\x92\x56\xc3\x02\x99\x16"
    "\x70\x00\x47\x09\x99\x99\x7b\x86\x11\x56\x8e\xc7\x24\xac\xeb"
    "\x96\x25"

	/* exp */
	"\x00\x00\x00\x01\x03"

	/* private */
    "\x00\x00\x01\x00\x6e\x30\x12\x60\x87\x35\x08\xae\xd2\x80\x2f\xdc\xa2\x00\x6f"
    "\x54\x00\x9e\xfe\x4f\x9b\x5b\xe3\xfa\xb9\x12\x06\x61\x1f\x75"
    "\xbc\x5d\x84\x0a\x16\x1b\x0e\xf0\x46\xeb\x1f\xc7\xd4\xea\x66"
    "\x7a\xe4\x49\x3b\xab\x88\x81\x35\x2e\x3c\x15\x47\xda\x15\x5c"
    "\x3f\x11\xfa\xae\x49\x7c\x08\x06\x3b\xb3\x5f\x70\xf3\x4e\x86"
    "\x0a\x89\x21\x1c\x5b\xa9\x31\x50\xd3\x7a\xa1\x8c\x99\xbf\x8e"
    "\xd0\x6a\xd8\x27\x08\xb8\x73\x39\x2f\x57\x79\x02\x5a\xd0\x4d"
    "\x19\x26\xf9\xe9\xef\x05\x2d\xfa\xb4\xa3\xf2\xbd\xd3\x50\xa9"
    "\xf9\x4f\x24\xf3\x89\x11\x9d\x9e\x0d\xbe\x47\xa5\x25\xe3\xf9"
    "\x1f\xe4\xfe\x60\x24\x02\x09\xd3\x9f\x15\xd7\x2d\x85\x4b\x94"
    "\x10\x19\xd4\x02\x18\xce\xd0\xe8\x9e\xf9\xbc\x0f\x31\x96\xf1"
    "\x1a\x1f\xb7\xf8\x8f\x36\xec\xbd\x76\x7e\xa0\xbe\x15\xf9\xbe"
    "\xe8\x8c\x0c\x25\xeb\x61\x88\x5d\x70\x10\x26\x53\x86\xad\x39"
    "\x0b\x18\xc8\xf6\x27\x10\xc7\x3c\x83\x47\xc5\x86\xc9\x30\x7b"
    "\x96\xcf\x66\x87\xe9\xd8\x2c\x8d\xbf\xa6\xa1\x38\xe9\x9d\x93"
    "\x1d\x76\x01\x14\xb9\x50\x3c\xf0\x40\xb7\xf4\x81\xad\x0d\xef"
    "\xe8\x7d\xb7\x55\x74\xaf\xba\x89\x32\x68\x91\xe8\xe7\x74\x3d"
    "\xf3";

struct crypto_rsa_ctx {
	RSA			crr_rsa;
	struct crypto_hash	*crr_sha1_tfm;
	struct hash_desc	crr_sha1_desc;
};

struct openssl_sha1_ctx {
	SHA_CTX	sha_sha1;
};

void assert(int x)
{
	BUG_ON(!x);
}

void ERR_put_error(int lib, int func, int reason,
		   const char *file, int line)
{
	printk(KERN_INFO "ERR_put_error(%d, %d, %d, %s, %d)\n",
	       lib, func, reason, file, line);
}

void *CRYPTO_malloc(int num, const char *file, int line)
{
	return kmalloc(num, GFP_ATOMIC);
}

void CRYPTO_free(void *x)
{
	kfree(x);
}

void OPENSSL_cleanse(void *ptr, size_t len)
{
	memset(ptr, 0, len);
}

void CRYPTO_lock(int mode, int type, const char *file, int line)
{
	printk(KERN_INFO "need lock\n");
}

int RAND_bytes(unsigned char *buf, int num)
{
	memset(buf, 'R', sizeof(num));

	return 1;
}

void sha1_init(void *c)
{
	struct hash_desc *d = c;

	if (crypto_hash_init(d))
		printk(KERN_INFO "crypto_hash_init()\n");
}

void sha1_update(void *c, const void *crap, int len)
{
	struct hash_desc *d = c;
	struct scatterlist sg;

	sg_init_table(&sg, 1);
	sg_set_buf(&sg, crap, len);

	if (crypto_hash_update(d, &sg, len))
		printk(KERN_INFO "crypto_hash_update()\n");
}

void sha1_final(void *c, void *out)
{
	struct hash_desc *d = c;

	if (crypto_hash_final(d, out))
		printk(KERN_INFO "crypto_hash_final()\n");
}

int RSA_eay_public_encrypt(int flen, const unsigned char *from,
                unsigned char *to, RSA *rsa,int padding);
int RSA_eay_private_decrypt(int flen, const unsigned char *from,
                unsigned char *to, RSA *rsa,int padding);

static int crypto_rsa_init(struct crypto_tfm *tfm)
{
	struct crypto_rsa_ctx *ctx = crypto_tfm_ctx(tfm);
	RSA *rsa;

	memset(ctx, 0, sizeof(*ctx));

	ctx->crr_sha1_tfm = crypto_alloc_hash("sha1", 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(ctx->crr_sha1_tfm))
		return -1;

	ctx->crr_sha1_desc.tfm   = ctx->crr_sha1_tfm;
	ctx->crr_sha1_desc.flags = 0;

	rsa = &ctx->crr_rsa;
	rsa->meth = (void*) &ctx->crr_sha1_desc; /* XXX */
	rsa->flags = RSA_FLAG_NO_CONSTTIME;

	return 0;
}

static void cleanup_rsa(struct crypto_rsa_ctx *ctx)
{
	BIGNUM **c[] = { &ctx->crr_rsa.n,
			 &ctx->crr_rsa.e,
			 &ctx->crr_rsa.d,
			 &ctx->crr_rsa.p,
			 &ctx->crr_rsa.q,
			 &ctx->crr_rsa.dmp1,
			 &ctx->crr_rsa.dmq1,
			 &ctx->crr_rsa.iqmp
			};
	int i;

	for (i = 0; i < sizeof(c) / sizeof(*c); i++) {
		BIGNUM **x = c[i];
		if (*x) {
			BN_free(*x);
			*x = NULL;
		}
	}
}

static void crypto_rsa_exit(struct crypto_tfm *tfm)
{
	struct crypto_rsa_ctx *ctx = crypto_tfm_ctx(tfm);

	cleanup_rsa(ctx);
	crypto_free_hash(ctx->crr_sha1_tfm);
}

/* public key, exponent, private key */
static int crypto_rsa_set_key(struct crypto_tfm *tfm, const u8 *in_key,
		              unsigned int key_len)
{
	struct crypto_rsa_ctx *ctx = crypto_tfm_ctx(tfm);
	int l;
	int part = 0;
	BIGNUM *x;
	RSA *rsa = &ctx->crr_rsa;

	cleanup_rsa(ctx);

	while (key_len >= 4) {
		l = ntohl(*((uint32_t*) in_key));

		l += 4;

		if (l > key_len)
			return -1;

		x = BN_mpi2bn(in_key, l, NULL);
		if (!x)
			return -1;

//		printk(KERN_INFO "PART %d\n", part);
		switch (part++) {
		case 0:
			rsa->n = x;
			break;

		case 1:
			rsa->e = x;
			break;

		case 2:
			rsa->d = x;
			break;

		case 3:
			rsa->p = x;
			break;

		case 4:
			rsa->q = x;
			break;

		case 5:
			rsa->dmp1 = x;
			break;

		case 6:
			rsa->dmq1 = x;
			break;

		case 7:
			rsa->iqmp = x;
			break;

		default:
			return -1;
		}

		key_len -= l;
		in_key  += l;
	}

	return 0;
}

static int rsa_encrypt(struct blkcipher_desc *desc,
	               struct scatterlist *dst,
		       struct scatterlist *src,
                       unsigned int nbytes)
{
	struct crypto_blkcipher *tfm = desc->tfm;
	struct crypto_rsa_ctx *ctx = crypto_blkcipher_ctx(tfm);
	void *in = sg_virt(src), *out = sg_virt(dst);
	int rc;

	rc = RSA_eay_public_encrypt(nbytes, in, out, &ctx->crr_rsa,
				    RSA_PKCS1_OAEP_PADDING);

	return rc;
}

static int rsa_decrypt(struct blkcipher_desc *desc,
	               struct scatterlist *dst,
		       struct scatterlist *src,
                       unsigned int nbytes)
{
	struct crypto_blkcipher *tfm = desc->tfm;
	struct crypto_rsa_ctx *ctx = crypto_blkcipher_ctx(tfm);
	void *in = sg_virt(src), *out = sg_virt(dst);
	int rc;

	rc = RSA_eay_private_decrypt(nbytes, in, out, &ctx->crr_rsa,
				     RSA_PKCS1_OAEP_PADDING);

	return rc;
}

static struct crypto_alg alg = {
        .cra_name           =   "rsa",
        .cra_driver_name    =   "openssl",
        .cra_priority       =   100,
        .cra_flags          =   CRYPTO_ALG_TYPE_BLKCIPHER,
        .cra_type           =   &crypto_blkcipher_type,
        .cra_blocksize      =   1,
        .cra_ctxsize        =   sizeof(struct crypto_rsa_ctx),
        .cra_alignmask      =   3,
        .cra_module         =   THIS_MODULE,
        .cra_list           =   LIST_HEAD_INIT(alg.cra_list),
        .cra_u              =   {
                .blkcipher = {
                        .setkey         =   crypto_rsa_set_key,
                        .encrypt        =   rsa_encrypt,
                        .decrypt        =   rsa_decrypt,
                        .min_keysize    =   4,
                        .max_keysize    =   4096,
                        .ivsize         =   0,
                }
        },
        .cra_init           = crypto_rsa_init,
        .cra_exit           = crypto_rsa_exit,
};

static inline void test2(void)
{
	struct crypto_blkcipher *tfm;
	int rc;
	unsigned char *crap;
	struct blkcipher_desc desc;
	struct scatterlist in, out;

	printk(KERN_INFO "test in\n");

	crap = kmalloc(4096, GFP_KERNEL);

	tfm = crypto_alloc_blkcipher("rsa", 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(tfm)) {
		printk(KERN_INFO "crypto_alloc_blkcipher()\n");
		return;
	}

	rc = crypto_blkcipher_setkey(tfm, key, sizeof(key) - 1);
	printk(KERN_INFO "crypto_blkcipher_setkey = %d\n", rc);

	strcpy(crap, "AABC");
	desc.tfm   = tfm;
	desc.flags = 0;

	sg_init_table(&in, 1);
	sg_set_buf(&in, crap, 4);

	sg_init_table(&out, 1);
	sg_set_buf(&out, crap, 4096);

	rc = crypto_blkcipher_encrypt(&desc, &out, &in, 4);
	printk(KERN_INFO "crypto_blkcipher_encrypt RC %d %x %x %x\n",
	       rc, crap[0], crap[1], crap[2]);

	sg_init_one(&in, crap, rc);
	sg_init_one(&out, crap, 4096);
	rc = crypto_blkcipher_decrypt(&desc, &out, &in, rc);
	printk(KERN_INFO "crypto_blkcipher_decrypt RC %d %x %x %x\n",
	       rc, crap[0], crap[1], crap[2]);

	crypto_free_blkcipher(tfm);

	kfree(crap);

	printk(KERN_INFO "test out\n");
}

static int sha1_openssl_init(struct shash_desc *desc)
{       
        struct openssl_sha1_ctx *sctx = shash_desc_ctx(desc);

	SHA1_Init(&sctx->sha_sha1);

        return 0;
}


static int sha1_openssl_update(struct shash_desc *desc, const u8 *data,
                               unsigned int len)
{
	struct openssl_sha1_ctx *sctx = shash_desc_ctx(desc);

	SHA1_Update(&sctx->sha_sha1, data, len);

	return 0;
}

static int sha1_openssl_final(struct shash_desc *desc, u8 *out)
{       
        struct openssl_sha1_ctx *sctx = shash_desc_ctx(desc);

	SHA1_Final(out, &sctx->sha_sha1);

	return 0;
}

static int sha1_openssl_export(struct shash_desc *desc, void *out)
{               
        struct openssl_sha1_ctx *sctx = shash_desc_ctx(desc);
                
        memcpy(out, sctx, sizeof(*sctx));
        return 0;
}

static int sha1_openssl_import(struct shash_desc *desc, const void *in)
{
        struct openssl_sha1_ctx *sctx = shash_desc_ctx(desc);

        memcpy(sctx, in, sizeof(*sctx));
        return 0;
}

static struct shash_alg shaalg = {
        .digestsize     =       SHA1_DIGEST_SIZE,
        .init           =       sha1_openssl_init,
        .update         =       sha1_openssl_update,
        .final          =       sha1_openssl_final,
        .export         =       sha1_openssl_export,
        .import         =       sha1_openssl_import,
        .descsize       =       sizeof(struct openssl_sha1_ctx),
        .statesize      =       sizeof(struct openssl_sha1_ctx),
        .base           =       {
                .cra_name       =       "sha1-openssl",
                .cra_driver_name=       "sha1-openssl",
                .cra_flags      =       CRYPTO_ALG_TYPE_SHASH,
                .cra_blocksize  =       SHA1_BLOCK_SIZE,
                .cra_module     =       THIS_MODULE,
        }
};

static int __init openssl_module_init(void)
{
	int rc;

	if ((rc = crypto_register_shash(&shaalg)))
		return rc;

	if ((rc = crypto_register_alg(&alg)))
		return rc;

	if (0)
		test2();

	printk(KERN_INFO "OpenSSL loaded\n");

	return 0;
}

static void __exit openssl_module_exit(void)
{
	crypto_unregister_shash(&shaalg);
	crypto_unregister_alg(&alg);
}

module_init(openssl_module_init);
module_exit(openssl_module_exit);

MODULE_LICENSE("GPL");
