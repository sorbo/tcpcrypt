#ifndef __NET_TCP_CRYPT_H__
#define __NET_TCP_CRYPT_H__

#define TCPOPT_CRYPT            	69
#define TCPOPT_MAC			70
#define TCPOLEN_CRYPT_HELLO_ALIGNED	 4

#define TCPCRYPT_MAX_PRF		32

#define TCPCRYPT_CRYPTO_POOL	8000

#define TCPCRYPT_SUPPORT_LOCAL	0x01
#define TCPCRYPT_SUPPORT_REMOTE	0x02
#define TCPCRYPT_SUPPORT_ON	0x04

enum {
	TCPCRYPT_CLOSED		=  0,
	TCPCRYPT_HELLO_SENT,
	TCPCRYPT_PKCONF_RCVD,
	TCPCRYPT_INIT1_SENT,

	TCPCRYPT_LISTEN,
	TCPCRYPT_PKCONF_SENT	=  5,
	TCPCRYPT_INIT1_RCVD,

	TCPCRYPT_NEXTK1_SENT,
	TCPCRYPT_NEXTK2_SENT,

	TCPCRYPT_ENCRYPTING,
	TCPCRYPT_DISABLED	= 10,
};

enum {
	TCPCRYPT_HELLO	= 0x01,
	TCPCRYPT_HELLO_SUPPORT,
	TCPCRYPT_NEXTK2 = 0x04,
	TCPCRYPT_NEXTK2_SUPPORT,
	TCPCRYPT_INIT1	= 0x06,
	TCPCRYPT_INIT2,
	TCPCRYPT_PKCONF = 0x41,
	TCPCRYPT_PKCONF_SUPPORT,
	TCPCRYPT_NEXTK1 = 0x84,
	TCPCRYPT_NEXTK1_SUPPORT,
};

enum {
	TCPCRYPT_PKEY = 0,
	TCPCRYPT_SYMMETRIC,
	TCPCRYPT_MAC,
	TCPCRYPT_SYMMETRIC2,
	TCPCRYPT_MAC2,

	TCPCRYPT_CRYPT_MAX
};

enum {
	TCPCRYPT_MK = 0,
	TCPCRYPT_KEC = TCPCRYPT_SYMMETRIC,
	TCPCRYPT_KAC,
	TCPCRYPT_KES,
	TCPCRYPT_KAS,
	TCPCRYPT_SS,
	TCPCRYPT_SID,

	TCPCRYPT_KEYS_MAX
};

enum {
	TCPCRYPT_TAG_SID = 1,
	TCPCRYPT_TAG_MK,
	TCPCRYPT_TAG_C_ENC,
	TCPCRYPT_TAG_C_MAC,
	TCPCRYPT_TAG_S_ENC,
	TCPCRYPT_TAG_S_MAC,
	TCPCRYPT_TAG_NEXTK,
};

enum {
	TCPCRYPT_CLIENT = TCPCRYPT_KEC,
	TCPCRYPT_SERVER = TCPCRYPT_KES,
};

enum {
	TCPCRYPT_SO_APP_SUPPORT = 15,
	TCPCRYPT_SO_RSA_KEY	= 3,
	TCPCRYPT_SO_SESSID	= 2,
	TCPCRYPT_SO_NETSTAT	= 102,
};

struct tcrypto_priv;

struct tcpcrypt_crypto_ops {
	struct tcrypto_priv *(*tco_init)(struct sock *sk);
	void	(*tco_destroy)(struct tcrypto_priv *p);
	int	(*tco_fill_key)(struct tcrypto_priv *p, void *key, int keylen);
	int	(*tco_set_key)(struct tcrypto_priv *p, void *key, int len);
	int	(*tco_encrypt)(struct tcrypto_priv *p, void *out, void *in,
			       int len);
	int	(*tco_decrypt)(struct tcrypto_priv *p, void *out, void *in,
			       int len);
	void	(*tco_mac_update)(struct tcrypto_priv *p, void *in, int len);
	int	(*tco_mac_final)(struct tcrypto_priv *p, void *out);
	int	(*tco_prf)(struct tcrypto_priv *p, void *out, void *k, int klen,
			   void *in, int len);
};

struct tcpcrypt_crypto {
	int				tcc_type;
	int				tcc_id;
	int				tcc_companion;
	unsigned char			tcc_min_key;
	unsigned char			tcc_max_key;
	int				tcc_prf_len;
	int				tcc_mac_len;
	struct tcpcrypt_crypto_ops	*tcc_ops;
};

struct tcpcrypt_cache {
	struct list_head	tca_node;
	int			tca_role;
	unsigned char		tca_ss[TCPCRYPT_MAX_PRF];
	unsigned char		tca_sid[TCPCRYPT_MAX_PRF];
	struct tcpcrypt_crypto	*tca_crypto[TCPCRYPT_CRYPT_MAX];
	struct in_addr		tca_dst;
};

struct tcp_crypt_info {
	int			tci_state;
	unsigned char		tci_hashbuf[1500];
	int			tci_hashbuf_len;
	unsigned char		*tci_hashbuf_sym;
	unsigned char		tci_crap[1500];
	int			tci_role;
	unsigned char		tci_keys[TCPCRYPT_KEYS_MAX][TCPCRYPT_MAX_PRF];
	struct tcpcrypt_crypto	*tci_crypto[TCPCRYPT_CRYPT_MAX];
	struct tcrypto_priv	*tci_crypto_priv[TCPCRYPT_CRYPT_MAX];
	struct tcpcrypt_cache	*tci_cached;
	int			tci_support;
	spinlock_t		tci_rxlock;
	spinlock_t		tci_txlock;
};

struct tcpcrypt_rsk {
	struct tcpcrypt_cache	*tr_cached;
	u8			tr_support;
};

struct tcpcrypt_suboption {
	unsigned char	tcs_opt;
	unsigned char	tcs_len;
	unsigned char	tcs_subopt;
	unsigned char	tcs_sublen;
	unsigned char	tcs_data[0];
};

struct tcpcrypt_pkconf {
	unsigned char	pk_id;
	unsigned char	pk_min;
	unsigned char	pk_max;
} __attribute__((packed));

struct tcpcrypt_algo {
	struct list_head	tcc_node;
	struct tcpcrypt_crypto	*tcc_crypto;
};

static inline struct tcp_crypt_info *tci_sk(struct sock *sk)
{       
        return tcp_sk(sk)->tc_info;
}

static inline void skb_for_each_data(void *priv, struct sk_buff *skb,
			             void (*cb)(void *p, void *data, int l))
{
        struct tcphdr *th = tcp_hdr(skb);
        int off = th->doff * 4;
        int len;
        struct skb_shared_info *shi = skb_shinfo(skb);
        int i;

        len = skb_headlen(skb) - off - (skb->len
	      - ((skb->tail - skb->transport_header) + skb->data_len));
	BUG_ON(len < 0);
        if (len) {
                void *m;
                unsigned char *p;

                p = (unsigned char*) th + off;
                m = kmap_atomic(virt_to_page(p), 0);
                p = (unsigned char*) m + offset_in_page(p);

		cb(priv, p, len);

                kunmap_atomic(m, 0);
        }

        for (i = 0; i < shi->nr_frags; ++i) {
                struct skb_frag_struct *f = &shi->frags[i];
                void *m;
                unsigned char *p;

                p = m = kmap_atomic(f->page, 0);
                p += f->page_offset;

		cb(priv, p, f->size);

                kunmap_atomic(m, 0);
        }
}

#endif /* __NET_TCP_CRYPT_H__ */
