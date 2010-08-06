#include <linux/module.h>
#include <linux/highmem.h>
#include <net/sock.h>
#include <net/tcp.h>

#include "tcp_crypt.h"

struct rsa_pool {
	struct list_head	rp_node;
	struct crypto_hash	*rp_hmac;
	struct crypto_blkcipher	*rp_rsa;
} rsa_pool;

struct tcrypto_priv {
	struct sock		*rp_sk;
	struct rsa_pool		*rp_pool;
	struct hash_desc	rp_hmac_desc;
	struct blkcipher_desc	rp_rsa_desc;
	unsigned char		rp_rsa_public[1024];
	int			rp_rsa_public_len;
	int			rp_key_size;
};

DEFINE_SPINLOCK(rsa_pool_lock);

static struct tcp_crypt_ops *tcpcrypt_ops;

static struct tcrypto_priv *rsa_init(struct sock *sk)
{
	struct tcrypto_priv *p;
	struct rsa_pool *cur, *next;

	p = kzalloc(sizeof(*p), GFP_ATOMIC);
	if (!p)
		return NULL;

	p->rp_sk  = sk;

	spin_lock(&rsa_pool_lock);
        list_for_each_entry_safe(cur, next, &rsa_pool.rp_node, rp_node) {
		p->rp_pool = cur;
		list_del(&cur->rp_node);
		break;
	}
	spin_unlock(&rsa_pool_lock);

	if (!p->rp_pool)
		goto __free;

	p->rp_hmac_desc.tfm   = cur->rp_hmac;
	p->rp_hmac_desc.flags = 0;

	p->rp_rsa_desc.tfm    = cur->rp_rsa;
	p->rp_rsa_desc.flags  = 0;

	return p;

__free:
	printk(KERN_INFO "rsa_init()");
	kfree(p);

	return NULL;
}

static void rsa_destroy(struct tcrypto_priv *priv)
{
	spin_lock(&rsa_pool_lock);
	list_add(&priv->rp_pool->rp_node, &rsa_pool.rp_node);
	spin_unlock(&rsa_pool_lock);

	kfree(priv);
}

static int rsa_prf(struct tcrypto_priv *priv, void *out, void *k, int klen,
                   void *in, int len)
{
	struct scatterlist sg;

	if (k) {
		unsigned char key[16];

		memset(key, 0, sizeof(key));

		if (klen > sizeof(key))
			klen = sizeof(key);

		memcpy(key, k, klen);

		if (crypto_hash_setkey(priv->rp_hmac_desc.tfm,
				       key, sizeof(key))) {
			printk(KERN_INFO "crypto_hash_setkey()\n");
			return -1;
		}
	}

	if (crypto_hash_init(&priv->rp_hmac_desc)) {
		printk(KERN_INFO "crypto_hash_init()\n");
		return -1;
	}

	sg_init_table(&sg, 1);
	sg_set_buf(&sg, in, len);

	if (crypto_hash_update(&priv->rp_hmac_desc, &sg, len))
		printk(KERN_INFO "crypto_hash_update()\n");

	if (crypto_hash_final(&priv->rp_hmac_desc, out)) {
		printk(KERN_INFO "crypto_hash_final()\n");
		return -1;
	}

	return 20;	
}

static int rsa_set_key(struct tcrypto_priv *priv, void *p, int len)
{
	uint32_t *plen   = p;
	unsigned char *x = p;

	if (crypto_blkcipher_setkey(priv->rp_rsa_desc.tfm, p, len))
		return -1;

	len = priv->rp_key_size = ntohl(*plen);
	if (x[4] == 0)
		priv->rp_key_size--;

	/* we want pub + exponent */
	len += 4;
	x   += len;

	plen = (uint32_t*) x;
	len += ntohl(*plen) + 4;

	priv->rp_rsa_public_len = len;
	memcpy(priv->rp_rsa_public, p, priv->rp_rsa_public_len);

	return priv->rp_key_size / 32;
}

static int rsa_fill_key(struct tcrypto_priv *priv, void *p, int keylen)
{
	/* XXX */
	memcpy(p, priv->rp_rsa_public, priv->rp_rsa_public_len);

	return priv->rp_rsa_public_len;
}

static int do_encdec(struct tcrypto_priv *priv, void *out, void *in, int len,
		     int enc)
{
        struct scatterlist inl, outl;
	int rc;

        sg_init_table(&inl, 1);
	sg_set_buf(&inl, in, len);

	sg_init_table(&outl, 1);
	sg_set_buf(&outl, out,  priv->rp_key_size);

	if (enc) {
		rc = crypto_blkcipher_encrypt(&priv->rp_rsa_desc, &outl, &inl,
					      len);
	} else {
		rc = crypto_blkcipher_decrypt(&priv->rp_rsa_desc, &outl, &inl,
					      len);
	}

	return rc;
}

static int rsa_encrypt(struct tcrypto_priv *priv, void *out, void *in, int len)
{
	return do_encdec(priv, out, in, len, 1);
}

static int rsa_decrypt(struct tcrypto_priv *priv, void *out, void *in, int len)
{
	return do_encdec(priv, out, in, len, 0);
}

static struct tcpcrypt_crypto_ops rsa_ops = {
	.tco_init       = rsa_init,
	.tco_destroy    = rsa_destroy,
	.tco_fill_key	= rsa_fill_key,
	.tco_set_key    = rsa_set_key,
	.tco_encrypt	= rsa_encrypt,
	.tco_decrypt	= rsa_decrypt,
	.tco_prf	= rsa_prf,
};

static struct tcpcrypt_crypto rsa_info = {
	.tcc_type	= TCPCRYPT_PKEY,
	.tcc_id		= 0x02,
	.tcc_min_key	= 8,
	.tcc_max_key	= 8,
	.tcc_prf_len	= 20,
	.tcc_ops	= &rsa_ops,
};

static int __init tcpcrypt_rsa_module_init(void)
{
	int i;

	INIT_LIST_HEAD(&rsa_pool.rp_node);

	for (i = 0; i < TCPCRYPT_CRYPTO_POOL; i++) {
		struct rsa_pool *pool;

		pool = kmalloc(sizeof(*pool), GFP_KERNEL);
		if (!pool)
			return -1;

		pool->rp_hmac = crypto_alloc_hash("hmac(sha1-openssl)", 
						  0, CRYPTO_ALG_ASYNC);
		if (IS_ERR(pool->rp_hmac)) {
			printk(KERN_INFO "Can't alloc hmac\n");
			return -1;
		}

		pool->rp_rsa = crypto_alloc_blkcipher("rsa",
						      0, CRYPTO_ALG_ASYNC);
		if (IS_ERR(pool->rp_rsa)) {
			printk(KERN_INFO "Can't alloc rsa\n");
			return -1;
		}

		list_add(&pool->rp_node, &rsa_pool.rp_node);
	}

	printk(KERN_INFO "in\n");

	tcpcrypt_ops = tcp_get_tcpcrypt();

	if (tcpcrypt_ops->tc_register_crypto(&rsa_info))
		return -1;

	return 0;
}

static void __exit tcpcrypt_rsa_module_exit(void)
{
	struct rsa_pool *cur, *next;

	printk(KERN_INFO "out\n");

	if (tcpcrypt_ops->tc_unregister_crypto(&rsa_info))
		printk(KERN_INFO "fuck\n");

        list_for_each_entry_safe(cur, next, &rsa_pool.rp_node, rp_node) {
		crypto_free_hash(cur->rp_hmac);
		crypto_free_blkcipher(cur->rp_rsa);
		kfree(cur);
	}
}

module_init(tcpcrypt_rsa_module_init);
module_exit(tcpcrypt_rsa_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Andrea Bittau <bittau@stanford.edu>");
MODULE_DESCRIPTION("TCP crypt RSA");
