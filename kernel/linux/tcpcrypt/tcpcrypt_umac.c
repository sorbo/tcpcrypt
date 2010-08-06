#include <linux/module.h>
#include <linux/highmem.h>
#include <net/sock.h>
#include <net/tcp.h>

#include "tcp_crypt.h"
#include "umac.h"

struct tcrypto_priv {
	struct sock		*hp_sk;
	umac_ctx_t		hp_umac;
};

DEFINE_SPINLOCK(umac_pool_lock);

static struct tcp_crypt_ops *tcpcrypt_ops;

static struct tcrypto_priv *umac_init(struct sock *sk)
{
	struct tcrypto_priv *p;

	p = kzalloc(sizeof(*p), GFP_ATOMIC);
	if (!p)
		return NULL;

	p->hp_sk   = sk;

	return p;
}

static void umac_destroy(struct tcrypto_priv *priv)
{
	if (priv->hp_umac)
		umac_delete(priv->hp_umac);

	kfree(priv);
}

static int umac_set_key(struct tcrypto_priv *priv, void *p, int len)
{
	unsigned char key[16];

	memset(key, 0, sizeof(key));

	if (len > sizeof(key))
		len = sizeof(key);

	memcpy(key, p, len);

	priv->hp_umac = umac_new(key);

	return len;
}

static int umac_mac_final(struct tcrypto_priv *priv, void *out)
{
	unsigned char *p = out;

	memset(p, 0, 8); /* nonce */

	umac_final(priv->hp_umac, &p[8], out);
	umac_reset(priv->hp_umac);

	return 16;
}

static void umac_mac_update(struct tcrypto_priv *priv, void *in, int len)
{
	umac_update(priv->hp_umac, in, len);
}

static struct tcpcrypt_crypto_ops umac_ops = {
	.tco_init       = umac_init,
	.tco_destroy    = umac_destroy,
	.tco_set_key    = umac_set_key,
	.tco_mac_update = umac_mac_update,
	.tco_mac_final  = umac_mac_final,
};

static struct tcpcrypt_crypto umac_info = {
	.tcc_type	= TCPCRYPT_MAC,
	.tcc_id		= 0x01,
	.tcc_companion  = 0x00,
	.tcc_mac_len	= 16, /* XXX IV */
	.tcc_ops	= &umac_ops,
};

static int __init tcpcrypt_umac_module_init(void)
{
	printk(KERN_INFO "in\n");

	tcpcrypt_ops = tcp_get_tcpcrypt();

	if (tcpcrypt_ops->tc_register_crypto(&umac_info))
		return -1;

	return 0;
}

static void __exit tcpcrypt_umac_module_exit(void)
{
	printk(KERN_INFO "out\n");

	if (tcpcrypt_ops->tc_unregister_crypto(&umac_info))
		printk(KERN_INFO "fuck\n");
}

module_init(tcpcrypt_umac_module_init);
module_exit(tcpcrypt_umac_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Andrea Bittau <bittau@stanford.edu>");
MODULE_DESCRIPTION("TCP crypt UMAC");
