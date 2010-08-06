#include <linux/module.h>
#include <linux/highmem.h>
#include <net/sock.h>
#include <net/tcp.h>

#include "tcp_crypt.h"

struct tcrypto_priv {
	struct sock	*np_sk;
	unsigned char	np_crap[1500];
	unsigned int	np_len;
	unsigned char	np_key;
	unsigned int	np_mac;
};

static struct tcp_crypt_ops *tcpcrypt_ops;

static struct tcrypto_priv *null_init(struct sock *sk)
{
	struct tcrypto_priv *p;

	p = kzalloc(sizeof(*p), GFP_ATOMIC);
	if (!p)
		return NULL;

	p->np_sk  = sk;

	return p;
}

static int null_fill_key(struct tcrypto_priv *priv, void *p, int keylen)
{
	int i;
	unsigned char *x = p;
	int k = 'K';

	for (i = 0; i < keylen; i++) {
		*x++ = k;
		priv->np_key += k;
	}

	return keylen;
}

static int null_set_key(struct tcrypto_priv *priv, void *p, int len)
{
	unsigned char *x = p;
	int l = len;

	priv->np_key = 0;

	while (len--)
		priv->np_key += *x++;

	return l;
}

static void null_destroy(struct tcrypto_priv *priv)
{
	kfree(priv);
}

static void enc(void *p, void *data, int len)
{
	unsigned char *x = data;
	struct tcrypto_priv *priv = p;

	while (len--)
		*x++ ^= priv->np_key;
}

static int encrypt_skb(struct tcrypto_priv *priv, struct sk_buff *skb)
{
        struct tcphdr *th = tcp_hdr(skb);
        int off = th->doff * 4;
        int len = skb->len - off;

	skb_for_each_data(priv, skb, enc);

	return len;
}

static int do_encrypt(struct tcrypto_priv *priv, void *out, void *in, int len)
{
	int x = len;
	unsigned char *pin = in, *pout = out;

	if (len == -1)
		return encrypt_skb(priv, in);

	while (len--)
		*pout++ = *pin++ ^ priv->np_key;

	return x;
}

static int null_encrypt(struct tcrypto_priv *priv, void *out, void *in, int len)
{
	return do_encrypt(priv, out, in, len);
}

static int null_decrypt(struct tcrypto_priv *priv, void *out, void *in, int len)
{
	return do_encrypt(priv, out, in, len);
}

static int null_prf(struct tcrypto_priv *priv, void *out, void *k, int klen,
		    void *in, int len)
{
	unsigned int sum = 0;
	unsigned char *p = k;

	if (k) {
		priv->np_len = klen;
		memcpy(priv->np_crap, k, klen);
	} else {
		klen = priv->np_len;
		p    = priv->np_crap;
	}

	while (klen--)
		sum += *p++;

	p = in;

	while (len--)
		sum += *p++;

	*((unsigned int*) out) = htonl(sum);

	return sizeof(sum);
}

static int null_mac_final(struct tcrypto_priv *priv, void *out)
{
	*((unsigned int*) out) = htonl(priv->np_mac ^ priv->np_key);

	priv->np_mac = 0;

	return sizeof(priv->np_mac);
}

static void null_mac_update(struct tcrypto_priv *priv, void *in, int len)
{
	unsigned char *x = in;

	while (len--)
		priv->np_mac += *x++;

}

static struct tcpcrypt_crypto_ops null_pkey_ops = {
	.tco_init       = null_init,
	.tco_destroy    = null_destroy,
	.tco_fill_key   = null_fill_key,
	.tco_set_key    = null_set_key,
	.tco_encrypt    = null_encrypt,
	.tco_decrypt    = null_decrypt,
	.tco_prf        = null_prf,
	.tco_mac_update = null_mac_update,
	.tco_mac_final  = null_mac_final,
};

static struct tcpcrypt_crypto null_pkey = {
	.tcc_type	= TCPCRYPT_PKEY,
	.tcc_id		= 7,
	.tcc_min_key	= 8,
	.tcc_max_key	= 8,
	.tcc_prf_len    = 4,
	.tcc_ops	= &null_pkey_ops,
};

static struct tcpcrypt_crypto null_sym = {
	.tcc_type	= TCPCRYPT_SYMMETRIC,
	.tcc_id		= 7,
	.tcc_companion  = 0,
	.tcc_ops	= &null_pkey_ops,
};

static struct tcpcrypt_crypto null_mac = {
	.tcc_type	= TCPCRYPT_MAC,
	.tcc_id		= 7,
	.tcc_companion  = 0,
	.tcc_mac_len	= 4,
	.tcc_ops	= &null_pkey_ops,
};

static struct tcpcrypt_crypto *algos[] = { &null_pkey, &null_sym, &null_mac };

static int __init tcpcrypt_null_module_init(void)
{
	int i;

	printk(KERN_INFO "in\n");

	tcpcrypt_ops = tcp_get_tcpcrypt();

	for (i = 0; i < sizeof(algos) / sizeof(*algos); i++) {
		if (tcpcrypt_ops->tc_register_crypto(algos[i]))
			return -1;
	}

	return 0;
}

static void __exit tcpcrypt_null_module_exit(void)
{
	int i;

	printk(KERN_INFO "out\n");

	for (i = 0; i < sizeof(algos) / sizeof(*algos); i++) {
		if (tcpcrypt_ops->tc_unregister_crypto(algos[i]))
			printk(KERN_INFO "fuck\n");
	}
}

module_init(tcpcrypt_null_module_init);
module_exit(tcpcrypt_null_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Andrea Bittau <bittau@stanford.edu>");
MODULE_DESCRIPTION("TCP crypt null ciphers");
