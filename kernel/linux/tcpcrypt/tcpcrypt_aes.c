#include <linux/module.h>
#include <linux/highmem.h>
#include <net/sock.h>
#include <net/tcp.h>

#include "tcp_crypt.h"

static int ni = 0;

struct aes_pool {
	struct list_head	ap_node;
	struct crypto_blkcipher	*ap_tfm;
} aes_pool;

struct tcrypto_priv {
	struct sock		*ap_sk;
	struct crypto_blkcipher	*ap_tfm;
	struct aes_pool		*ap_pool;
};

DEFINE_SPINLOCK(aes_pool_lock);

static struct tcp_crypt_ops *tcpcrypt_ops;

static struct tcrypto_priv *aes_init(struct sock *sk)
{
	struct tcrypto_priv *p;
	struct aes_pool *cur, *next;

	p = kzalloc(sizeof(*p), GFP_ATOMIC);
	if (!p)
		return NULL;

	p->ap_sk  = sk;

	spin_lock(&aes_pool_lock);
        list_for_each_entry_safe(cur, next, &aes_pool.ap_node, ap_node) {
		p->ap_pool = cur;
		p->ap_tfm  = cur->ap_tfm;
		list_del(&cur->ap_node);
		break;
	}
	spin_unlock(&aes_pool_lock);

	if (!p->ap_tfm)
		goto __free;

	return p;

__free:
	printk(KERN_INFO "aes_init()");
	kfree(p);

	return NULL;
}

static int aes_set_key(struct tcrypto_priv *priv, void *p, int len)
{
	unsigned char key[16];

	memset(key, 0, sizeof(key));

	if (len > sizeof(key))
		len = sizeof(key);

	memcpy(key, p, len);

	if (crypto_blkcipher_setkey(priv->ap_tfm, key, sizeof(key))) {
		printk(KERN_INFO "crypto_blkcipher_setkey()");
		return -1;
	}

	return len;
}

static void aes_destroy(struct tcrypto_priv *priv)
{
	spin_lock(&aes_pool_lock);
	list_add(&priv->ap_pool->ap_node, &aes_pool.ap_node);
	spin_unlock(&aes_pool_lock);

	kfree(priv);
}

static int do_skb(struct tcrypto_priv *priv, struct sk_buff *skb, int enc)
{
        struct tcphdr *th = tcp_hdr(skb);
        int off = th->doff * 4;
        int len = 0;
	unsigned char iv[16];
	uint64_t *s = (uint64_t*) &iv[8];
	struct scatterlist sg[24];
	int frags = 0;
	struct skb_shared_info *shi = skb_shinfo(skb);
	struct blkcipher_desc desc;
	int rc;
	int i = 0, j = 0;
	int headlen = skb_headlen(skb) - off - (skb->len
		      - ((skb->tail - skb->transport_header) + skb->data_len));

	BUG_ON(!th);
	BUG_ON(!priv);

	/* IV */
	memset(iv, 0, sizeof(iv));
	*s = th->seq;
	crypto_blkcipher_set_iv(priv->ap_tfm, iv, sizeof(iv));

	/* sglist */
	if (headlen > 0)
		frags++;

	if (!shi)
		return 0;

	frags += shi->nr_frags;

	BUG_ON(frags > (sizeof(sg) / sizeof(*sg)));

	if (frags == 0)
		return 0;

	sg_init_table(sg, frags);

	if (headlen > 0) {
		sg_set_buf(&sg[i], (unsigned char *) th + off, headlen);
		i++;
		len += headlen;
	}

	for (; i < frags; i++) {
		const struct skb_frag_struct *f = &shi->frags[j];

		sg_set_buf(&sg[i], (unsigned char*) pfn_to_kaddr(page_to_pfn(f->page)) 
				   + f->page_offset, f->size);
		j++;
		len += f->size;
	}

	/* enc */
	desc.tfm   = priv->ap_tfm;
	desc.flags = 0;

	if (enc)
		rc = crypto_blkcipher_encrypt(&desc, sg, sg, len);
	else
		rc = crypto_blkcipher_decrypt(&desc, sg, sg, len);

	if (rc)
		return -1;

	return len;
}

static int do_encdec(struct tcrypto_priv *priv, void *out, void *in, int len,
		     int enc)
{
	if (len == -1)
		return do_skb(priv, in, enc);

	BUG_ON(1);

	return len;
}

static int aes_encrypt(struct tcrypto_priv *priv, void *out, void *in, int len)
{
	return do_encdec(priv, out, in, len, 1);
}

static int aes_decrypt(struct tcrypto_priv *priv, void *out, void *in, int len)
{
	return do_encdec(priv, out, in, len, 0);
}

static struct tcpcrypt_crypto_ops aes_ops = {
	.tco_init       = aes_init,
	.tco_destroy    = aes_destroy,
	.tco_set_key    = aes_set_key,
	.tco_encrypt    = aes_encrypt,
	.tco_decrypt    = aes_decrypt,
};

static struct tcpcrypt_crypto aes_info = {
	.tcc_type	= TCPCRYPT_SYMMETRIC,
	.tcc_id		= 0x01,
	.tcc_companion  = 0x00,
	.tcc_ops	= &aes_ops,
};

static int __init tcpcrypt_aes_module_init(void)
{
	int i;

	INIT_LIST_HEAD(&aes_pool.ap_node);

	for (i = 0; i < TCPCRYPT_CRYPTO_POOL; i++) {
		struct aes_pool *pool;
		char *a = "ctr(aes)";

		if (ni)
			a = "__cbc-aes-aesni";

		pool = kmalloc(sizeof(*pool), GFP_KERNEL);
		if (!pool)
			return -1;

		pool->ap_tfm = crypto_alloc_blkcipher(a, 0, CRYPTO_ALG_ASYNC);
		if (IS_ERR(pool->ap_tfm)) {
			printk(KERN_INFO "Can't alloc aes\n");
			return -1;
		}

		if (i == 0) {
			struct crypto_alg *alg = pool->ap_tfm->base.__crt_alg;

			printk(KERN_INFO "Got driver: %s\n",
			       alg->cra_driver_name);
		}

		list_add(&pool->ap_node, &aes_pool.ap_node);
	}

	printk(KERN_INFO "in\n");

	tcpcrypt_ops = tcp_get_tcpcrypt();

	if (tcpcrypt_ops->tc_register_crypto(&aes_info))
		return -1;

	return 0;
}

static void __exit tcpcrypt_aes_module_exit(void)
{
	struct aes_pool *cur, *next;

	printk(KERN_INFO "out\n");

	if (tcpcrypt_ops->tc_unregister_crypto(&aes_info))
		printk(KERN_INFO "fuck\n");

        list_for_each_entry_safe(cur, next, &aes_pool.ap_node, ap_node) {
		crypto_free_blkcipher(cur->ap_tfm);
		kfree(cur);
	}
}

module_init(tcpcrypt_aes_module_init);
module_exit(tcpcrypt_aes_module_exit);

module_param(ni, int, 0);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Andrea Bittau <bittau@stanford.edu>");
MODULE_DESCRIPTION("TCP crypt AES");
