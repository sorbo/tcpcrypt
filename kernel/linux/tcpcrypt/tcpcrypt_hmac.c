#include <linux/module.h>
#include <linux/highmem.h>
#include <net/sock.h>
#include <net/tcp.h>

#include "tcp_crypt.h"

struct hmac_pool {
	struct list_head	hp_node;
	struct crypto_hash	*hp_tfm;
} hmac_pool;

struct tcrypto_priv {
	struct sock		*hp_sk;
	struct crypto_hash	*hp_tfm;
	struct hmac_pool	*hp_pool;
	struct hash_desc	hp_desc;
};

DEFINE_SPINLOCK(hmac_pool_lock);

static struct tcp_crypt_ops *tcpcrypt_ops;

static struct tcrypto_priv *hmac_init(struct sock *sk)
{
	struct tcrypto_priv *p;
	struct hmac_pool *cur, *next;

	p = kzalloc(sizeof(*p), GFP_ATOMIC);
	if (!p)
		return NULL;

	p->hp_sk  = sk;

	spin_lock(&hmac_pool_lock);
        list_for_each_entry_safe(cur, next, &hmac_pool.hp_node, hp_node) {
		p->hp_pool = cur;
		p->hp_tfm  = cur->hp_tfm;
		list_del(&cur->hp_node);
		break;
	}
	spin_unlock(&hmac_pool_lock);

	if (!p->hp_tfm)
		goto __free;

	p->hp_desc.tfm   = p->hp_tfm;
	p->hp_desc.flags = 0;

	return p;

__free:
	printk(KERN_INFO "hmac_init()");
	kfree(p);

	return NULL;
}

static void hmac_destroy(struct tcrypto_priv *priv)
{
	spin_lock(&hmac_pool_lock);
	list_add(&priv->hp_pool->hp_node, &hmac_pool.hp_node);
	spin_unlock(&hmac_pool_lock);

	kfree(priv);
}

static int hmac_set_key(struct tcrypto_priv *priv, void *p, int len)
{
	unsigned char key[16];

	memset(key, 0, sizeof(key));

	if (len > sizeof(key))
		len = sizeof(key);

	memcpy(key, p, len);

	if (crypto_hash_setkey(priv->hp_tfm, key, sizeof(key))) {
		printk(KERN_INFO "crypto_hash_setkey()\n");
		return -1;
	}

	if (crypto_hash_init(&priv->hp_desc)) {
		printk(KERN_INFO "crypto_hash_init()\n");
		return -1;
	}

	return len;
}

static int hmac_mac_final(struct tcrypto_priv *priv, void *out)
{
	if (crypto_hash_final(&priv->hp_desc, out)) {
		printk(KERN_INFO "crypto_hash_final()\n");
		return -1;
	}

	if (crypto_hash_init(&priv->hp_desc)) {
		printk(KERN_INFO "crypto_hash_init()\n");
		return -1;
	}

	return 20;
}

static void hmac_mac_update(struct tcrypto_priv *priv, void *in, int len)
{
	struct scatterlist sg;

	sg_init_table(&sg, 1);
	sg_set_buf(&sg, in, len);

	if (crypto_hash_update(&priv->hp_desc, &sg, len))
		printk(KERN_INFO "crypto_hash_update()\n");
}

static struct tcpcrypt_crypto_ops hmac_ops = {
	.tco_init       = hmac_init,
	.tco_destroy    = hmac_destroy,
	.tco_set_key    = hmac_set_key,
	.tco_mac_update = hmac_mac_update,
	.tco_mac_final  = hmac_mac_final,
};

static struct tcpcrypt_crypto hmac_info = {
	.tcc_type	= TCPCRYPT_MAC,
	.tcc_id		= 0x01,
	.tcc_companion  = 0x00,
	.tcc_mac_len	= 20,
	.tcc_ops	= &hmac_ops,
};

static int __init tcpcrypt_hmac_module_init(void)
{
	int i;

	INIT_LIST_HEAD(&hmac_pool.hp_node);

	for (i = 0; i < TCPCRYPT_CRYPTO_POOL; i++) {
		struct hmac_pool *pool;

		pool = kmalloc(sizeof(*pool), GFP_KERNEL);
		if (!pool)
			return -1;

		pool->hp_tfm = crypto_alloc_hash("hmac(sha1-openssl)",
						 0, CRYPTO_ALG_ASYNC);
		if (IS_ERR(pool->hp_tfm)) {
			printk(KERN_INFO "Can't alloc hmac\n");
			return -1;
		}

		list_add(&pool->hp_node, &hmac_pool.hp_node);
	}

	printk(KERN_INFO "in\n");

	tcpcrypt_ops = tcp_get_tcpcrypt();

	if (tcpcrypt_ops->tc_register_crypto(&hmac_info))
		return -1;

	return 0;
}

static void __exit tcpcrypt_hmac_module_exit(void)
{
	struct hmac_pool *cur, *next;

	printk(KERN_INFO "out\n");

	if (tcpcrypt_ops->tc_unregister_crypto(&hmac_info))
		printk(KERN_INFO "fuck\n");

        list_for_each_entry_safe(cur, next, &hmac_pool.hp_node, hp_node) {
		crypto_free_hash(cur->hp_tfm);
		kfree(cur);
	}
}

module_init(tcpcrypt_hmac_module_init);
module_exit(tcpcrypt_hmac_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Andrea Bittau <bittau@stanford.edu>");
MODULE_DESCRIPTION("TCP crypt HMAC-SHA1");
