#include <linux/module.h>
#include <linux/highmem.h>
#include <net/sock.h>
#include <net/tcp.h>

#include "tcp_crypt.h"
#include "rsa_key.h"

struct mac_arg {
	struct tcp_crypt_info *ma_tci;
	int		      ma_off;
};

static DEFINE_MUTEX(tcpcrypt_algos_mutex);
static struct tcpcrypt_algo tcpcrypt_algos;

static DEFINE_SPINLOCK(tcpcrypt_cache_lock);
static struct tcpcrypt_cache tcpcrypt_cache;

/* sysctl */
static unsigned long conf_session_cache = 2;
static unsigned long conf_client_hack	= 0;
static unsigned long conf_no_enc	= 0;
static unsigned long conf_no_mac	= 0;

static struct ctl_table_header *sysctl_table;

static struct proc_dir_entry *proc_tcpcrypt;

static struct tcpcrypt_rsk *tcpcrypt_rsk(struct request_sock *req)
{
	return (struct tcpcrypt_rsk*) tcp_rsk(req)->tcpcrypt_data;
}

static int do_tcpcrypt_init(struct sock *sk, const gfp_t priority)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_crypt_info *tci;

	if (!try_module_get(THIS_MODULE))
		WARN_ON(1);

	tp->tc_info = tci = kzalloc(sizeof(*tci), priority);
	if (!tci)
		goto __put_module;

	spin_lock_init(&tci->tci_txlock);
	spin_lock_init(&tci->tci_rxlock);

	return 0;

__put_module:
	module_put(THIS_MODULE);
	return -1;
}

static int tcpcrypt_init(struct sock *sk)
{
	return do_tcpcrypt_init(sk, GFP_KERNEL);
}

static void tcpcrypt_destroy(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_crypt_info *tci = tci_sk(sk);
	int i;

	for (i = 0; i < TCPCRYPT_CRYPT_MAX; i++) {
		struct tcrypto_priv *p = tci->tci_crypto_priv[i];

		if (p)
			tci->tci_crypto[i]->tcc_ops->tco_destroy(p);
	}

	if (tci->tci_cached) {
		if (conf_session_cache == 2) {
			printk(KERN_INFO "Lost a sesison cache sk %p"
			       " state %d cache %p\n",
			       sk, tci->tci_state, tci->tci_cached);
		}

		kfree(tci->tci_cached);
	}

	kfree(tci);
	tp->tc_info = NULL;
	tp->tc_ops  = NULL;

	module_put(THIS_MODULE);
}

static void *tcpcrypt_option_ptr(struct sk_buff *skb, int len)
{
	unsigned char *p;
	struct tcphdr *th;

	if (!skb)
		return NULL;

	th = tcp_hdr(skb);

	p  = (u8*) th;
	p += th->doff * 4;
	p -= len;

	return p;
}

static uint32_t get_addr(struct sock *sk)
{
	struct inet_sock *inet = inet_sk(sk);

	return inet->daddr;
}

static int do_try_session_cache(struct sock *sk, struct sk_buff *skb)
{
	struct tcpcrypt_cache *cur, *next;
	uint32_t addr = get_addr(sk);
	struct tcp_crypt_info *tci = tci_sk(sk);

	list_for_each_entry_safe(cur, next, &tcpcrypt_cache.tca_node,
				 tca_node) {
		if (addr == cur->tca_dst.s_addr) {
			BUG_ON(tci->tci_cached);

			list_del(&cur->tca_node);
			tci->tci_cached = cur;
			return 1;
		}
	}

	if (conf_session_cache == 2)
		printk(KERN_INFO "not cached %p\n", sk);

	return 0;
}

static int try_session_cache(struct sock *sk, struct sk_buff *skb)
{
	int i;
	int sidl = 9;
	int len = sidl + 3;
	struct tcp_crypt_info *tci = tci_sk(sk);
	u8 *p;
	struct tcpcrypt_cache *cache;
	unsigned long flags;

	/* first round, find */
	if (!tci->tci_cached && !skb) {
		spin_lock_irqsave(&tcpcrypt_cache_lock, flags);
		do_try_session_cache(sk, skb);
		spin_unlock_irqrestore(&tcpcrypt_cache_lock, flags);
	}

	if (!(cache = tci->tci_cached))
		return -1;

	BUG_ON(!conf_session_cache); /* XXX */

	p = tcpcrypt_option_ptr(skb, len);
	if (!p)
		return len;

	*p++ = TCPOPT_CRYPT;
	*p++ = len;
	*p++ = tci->tci_support ? TCPCRYPT_NEXTK1_SUPPORT : TCPCRYPT_NEXTK1;

	for (i = 0; i < sidl; i++)
		*p++ = cache->tca_sid[i];

	tci->tci_state = TCPCRYPT_NEXTK1_SENT;

	return len;
}

static int tcpcrypt_send_hello(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_crypt_info *tci = tci_sk(sk);
	int len = TCPOLEN_CRYPT_HELLO_ALIGNED;
	unsigned char *ptr = tcpcrypt_option_ptr(skb, len);

	if (!ptr)
		return len;

	*ptr++ = TCPOPT_CRYPT;

	if (tci->tci_support & TCPCRYPT_SUPPORT_LOCAL) {
		*ptr++ = 3;
		*ptr++ = TCPCRYPT_HELLO_SUPPORT;
	} else {
		*ptr++ = 2;
		*ptr++ = TCPOPT_NOP;
	}

	*ptr++ = TCPOPT_NOP;

	tci->tci_state = TCPCRYPT_HELLO_SENT;

	return len;
}

static int tcpcrypt_send_closed(struct sock *sk, struct sk_buff *skb)
{
	int rc;

	if ((rc = try_session_cache(sk, skb)) != -1)
		return rc;

	return tcpcrypt_send_hello(sk, skb);
}

static int send_pkconf(struct sock *sk, struct request_sock *req,
		       struct sk_buff *skb)
{
	int pkconflen, pad = 0, len;
	u8 *p;
	struct tcpcrypt_algo *algo;
	int algos = 0;
	struct tcp_crypt_info *tci = tci_sk(sk);
	unsigned char *pk;

	list_for_each_entry(algo, &tcpcrypt_algos.tcc_node, tcc_node) {
		if (algo->tcc_crypto->tcc_type == TCPCRYPT_PKEY)
			algos++;
	}

	pkconflen = 2 + algos * 3;
	len = 2 + pkconflen;

	if (len % 4)
		pad = 4 - (len % 4);

	p = tcpcrypt_option_ptr(skb, len + pad);

	if (!p)
		return len + pad;

	*p++ = TCPOPT_CRYPT;
	*p++ = len;
	*p++ = tci->tci_support ? TCPCRYPT_PKCONF_SUPPORT : TCPCRYPT_PKCONF;
	*p++ = pkconflen;

	pk = p;

	list_for_each_entry(algo, &tcpcrypt_algos.tcc_node, tcc_node) {
		struct tcpcrypt_crypto *crypto = algo->tcc_crypto;

		if (crypto->tcc_type != TCPCRYPT_PKEY)
			continue;

		*p++ = crypto->tcc_id;
		*p++ = crypto->tcc_min_key;
		*p++ = crypto->tcc_max_key;
	}

	while (pad--)
		*p++ = TCPOPT_NOP;

	if (tci->tci_hashbuf_len == 0) {
		tci->tci_hashbuf_len = pkconflen - 2;
		BUG_ON(tci->tci_hashbuf_len < 0);
		memcpy(tci->tci_hashbuf, pk, tci->tci_hashbuf_len);
	}

	return len + pad;
}

static int send_nextk2(struct sock *sk, struct request_sock *req,
		       struct sk_buff *skb)
{
	struct tcp_crypt_info *tci = tci_sk(sk);
	int len = 4;
	u8 *p = tcpcrypt_option_ptr(skb, len);

	if (!p)
		return len;

	BUG_ON(!conf_session_cache); /* XXX */

	*p++ = TCPOPT_CRYPT;
	*p++ = 3;
	*p++ = tci->tci_support ? TCPCRYPT_NEXTK2_SUPPORT : TCPCRYPT_NEXTK2;

	*p++ = TCPOPT_NOP;

	return len;
}

static int tcpcrypt_send_listen(struct sock *sk,
			        struct request_sock *req,
			        struct sk_buff *skb)
{
	struct tcpcrypt_rsk *trsk = tcpcrypt_rsk(req);

	if (trsk->tr_cached)
		return send_nextk2(sk, req, skb);
	else if (trsk->tr_support)
		return send_pkconf(sk, req, skb);
	else
		return 0;
}

static int inject_data(struct sock *sk, void *data, int len)
{
	struct sk_buff *skb;
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_skb_cb *tcb;
	int size = len;
	void *p;

	size = ALIGN(size, 4);
	skb  = alloc_skb_fclone(size + sk->sk_prot->max_header, GFP_ATOMIC);

	if (!skb)
		return -1;

        if (sk->sk_route_caps & NETIF_F_ALL_CSUM)
                skb->ip_summed = CHECKSUM_PARTIAL;

	skb_reserve(skb, skb_tailroom(skb) - size);

	tcb = TCP_SKB_CB(skb);
        skb->csum    = 0;
        tcb->seq     = tcb->end_seq = tp->write_seq;
        tcb->flags   = TCPCB_FLAG_ACK;
        tcb->sacked  = 0;
        skb_header_release(skb);
        tcp_add_write_queue_tail(sk, skb);
        sk->sk_wmem_queued += skb->truesize;
        sk_mem_charge(sk, skb->truesize);

	tp->write_seq += len;
	TCP_SKB_CB(skb)->end_seq += len;
	skb_shinfo(skb)->gso_segs = 0;

	p = skb_put(skb, len);
	memcpy(p, data, len);

	if (skb->ip_summed == CHECKSUM_NONE)
		skb->csum = csum_partial(data, len, 0);

	return 0;
}

static int tcpcrypt_send_pkconf_rcvd(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_crypt_info *tci = tci_sk(sk);
	int len = 4;
	__be32 *ptr = tcpcrypt_option_ptr(skb, len);
	u8 *p = (u8*) ptr;

	if (!p)
		return len;
#if 1
	/* XXX */
	if (skb->len == 36)
		return -1;
#endif

	*p++ = TCPOPT_NOP;
	*p++ = TCPOPT_CRYPT;
	*p++ = 3;
	*p++ = TCPCRYPT_INIT1;

	tci->tci_state = TCPCRYPT_INIT1_SENT;

	return len;
}

static int tcpcrypt_send_init1_rcvd(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_crypt_info *tci = tci_sk(sk);
	int len = 4;
	__be32 *ptr = tcpcrypt_option_ptr(skb, len);
	u8 *p = (u8*) ptr;

	if (!p)
		return len;

	*p++ = TCPOPT_NOP;
	*p++ = TCPOPT_CRYPT;
	*p++ = 3;
	*p++ = TCPCRYPT_INIT2;

	tci->tci_state = TCPCRYPT_ENCRYPTING;

	return len;
}

static void do_csum(void *p, void *data, int len)
{
	struct sk_buff *skb = p;

	skb->csum = csum_partial(data, len, skb->csum);
}

static void fix_checksum(struct sk_buff *skb)
{
	if (skb->ip_summed != CHECKSUM_NONE)
		return;

	skb->csum = 0;

	skb_for_each_data(skb, skb, do_csum);
}

static int prepare_m(struct sock *sk, struct sk_buff *skb, void *out)
{
	unsigned short *m = out;
	struct tcphdr *th = tcp_hdr(skb);
	unsigned char *p;
	unsigned char *o;
	int optlen, ol = 0, copy = 0;
	int tcplen = (skb->tail - skb->transport_header) + skb->data_len;

	*m++ = htons(0x8000);
	*m++ = htons(tcplen);
	*m++ = htons((th->doff << 8) | ((unsigned char*) th)[13]);
	*m++ = th->urg_ptr;
	*m++ = 0; /* XXX */
	*m++ = th->seq;

	p = (unsigned char*) m;
	o = (unsigned char*) (th + 1);

	optlen = th->doff * 4 - sizeof(*th);

	while (optlen--) {
		if (ol == 0) {
			copy = 1;

			switch (*o) {
			case TCPOPT_EOL:
			case TCPOPT_NOP:
				ol = 1;
				break;

			default:
				copy = ol = o[1];
				/* fallthrough */
			case TCPOPT_TIMESTAMP:
			case 16: /* skeeter */
			case 17: /* bubba */
			case TCPOPT_MD5SIG:
			case TCPOPT_MAC:
				copy = 2;
				break;
			}
		}

		if (copy) {
			*p++ = *o;
			copy--;
		} else
			*p++ = 0;

		o++;
		ol--;
	}

	return p - (unsigned char*) out;
}

static uint64_t prepare_a(struct sock *sk, struct sk_buff *skb)
{
	unsigned int a[2];
	struct tcphdr *th = tcp_hdr(skb);

	a[0] = 0;
	a[1] = th->ack;

	return *((uint64_t*) a);
}

static void mac_update(struct tcp_crypt_info *tci, int off, void *data, int len)
{
	tci->tci_crypto[off]->tcc_ops->tco_mac_update(
				tci->tci_crypto_priv[off], data, len);
}

static void mac(void *arg, void *data, int len)
{
	struct mac_arg *ma = arg;

	mac_update(ma->ma_tci, ma->ma_off, data, len);
}

static void do_mac(struct sock *sk, struct sk_buff *skb, int off, void *out)
{
	unsigned char m[60];
	int mlen;
	uint64_t a;
	struct tcp_crypt_info *tci = tci_sk(sk);
	struct mac_arg ma = { tci, off };

	if (conf_no_mac == 1) {
		int maclen = tci->tci_crypto[TCPCRYPT_MAC]->tcc_mac_len;

		memset(out, 0, maclen);
		return;
	}

	mlen = prepare_m(sk, skb, m);
	a    = prepare_a(sk, skb);

	mac_update(tci, off, m, mlen);
	skb_for_each_data(&ma, skb, mac);
	mac_update(tci, off, &a, sizeof(a));

	tci->tci_crypto[off]->tcc_ops->tco_mac_final(
			tci->tci_crypto_priv[off], out);
}

static int tcpcrypt_send_encrypting(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_crypt_info *tci = tci_sk(sk);
	u8 *p;
	int maclen = tci->tci_crypto[TCPCRYPT_MAC]->tcc_mac_len;
	int len = 2 + maclen;
	int pad = 0;
	int off;
	unsigned long flags;

	/* figure out length */
	pad = len % 4;
	if (pad)
		pad = 4 - pad;

	len += pad;

	p = tcpcrypt_option_ptr(skb, len);
	if (!p)
		return len;

	/* XXX */
	if (skb->len > 1514)
		return len;

	off = tci->tci_role;

	if (!tci->tci_crypto_priv[off]) {
		printk(KERN_INFO "NULL off %d off state %d\n",
		       off, sk->sk_state);
		BUG_ON(1);
	}

	if (!conf_no_enc || (conf_no_mac != 1))
		spin_lock_irqsave(&tci->tci_txlock, flags);

	/* encrypt */
	if (!conf_no_enc) {
		tci->tci_crypto[off]->tcc_ops->tco_encrypt(
			tci->tci_crypto_priv[off],
			NULL,
			skb,
			-1);

		fix_checksum(skb);
	}

	/* MAC */
	*p++ = TCPOPT_MAC;
	*p++ = 2 + maclen;

	off++;
	do_mac(sk, skb, off, p);
	p += maclen;

	if (!conf_no_enc || (conf_no_mac != 1))
		spin_unlock_irqrestore(&tci->tci_txlock, flags);

	while (pad--)
		*p++ = TCPOPT_NOP;

	return len;
}

static int tcpcrypt_send(struct sock *sk,
			 struct request_sock *rsk,
			 struct sk_buff *skb)
{
	struct tcp_crypt_info *tci = tci_sk(sk);

	switch (tci->tci_state) {
	case TCPCRYPT_CLOSED:
		return tcpcrypt_send_closed(sk, skb);

	case TCPCRYPT_LISTEN:
		return tcpcrypt_send_listen(sk, rsk, skb);

	case TCPCRYPT_PKCONF_RCVD:
	case TCPCRYPT_INIT1_SENT:
		return tcpcrypt_send_pkconf_rcvd(sk, skb);

	case TCPCRYPT_INIT1_RCVD:
		return tcpcrypt_send_init1_rcvd(sk, skb);

	case TCPCRYPT_ENCRYPTING:
		return tcpcrypt_send_encrypting(sk, skb);

	case TCPCRYPT_DISABLED:
		return 0;

	case TCPCRYPT_NEXTK1_SENT:
		return try_session_cache(sk, skb);

	case TCPCRYPT_HELLO_SENT:
		return tcpcrypt_send_hello(sk, skb);

	default:
		printk(KERN_INFO "Unhandled send state: %d\n", tci->tci_state);
		break;
	}

	return 0;
}

static u8 *tcpcrypt_find_option(struct sk_buff *skb, int option)
{       
	struct tcphdr *th = tcp_hdr(skb);
        int length = (th->doff << 2) - sizeof (*th);
        u8 *ptr = (u8*)(th + 1);

        while (length > 0) {
                int opcode = *ptr++;
                int opsize;
                
                switch(opcode) {
                case TCPOPT_EOL:
                        return NULL;
                case TCPOPT_NOP:
                        length--;
                        continue;
                default:
                        opsize = *ptr++;
                        if (opsize < 2 || opsize > length)
                                return NULL;
                        if (opcode == option)
                                return ptr - 2;
                }
                ptr += opsize - 2;
                length -= opsize;
        }
        return NULL;
}

static unsigned char tcpcrypt_opcode(u8 *p)
{
	if (p[1] == 2)
		return TCPCRYPT_HELLO;
	else {
		BUG_ON(p[1] < 3);
		return p[2];
	}
}

static void do_process_nextk1(struct sock *sk, struct request_sock *req,
			      struct sk_buff *skb, u8 *p)
{
	struct tcpcrypt_cache *cur, *next;
	struct tcpcrypt_rsk *trsk = tcpcrypt_rsk(req);

	BUG_ON(!conf_session_cache); /* XXX */

	if (p[1] != 12) {
		printk(KERN_INFO "Bad nextk1\n");
		return;
	}

	p += 3;

	list_for_each_entry_safe(cur, next, &tcpcrypt_cache.tca_node,
				 tca_node) {
		if (memcmp(cur->tca_sid, p, 9) == 0) {
			/* XXX leak if connection doesn't complete */
			list_del(&cur->tca_node);
			if (trsk->tr_cached) {
        			struct tcphdr *th = tcp_hdr(skb);

				printk(KERN_INFO "DATA %p %p rsk %p %d %d\n",
				       trsk->tr_cached, cur,
				       req, th->syn, th->ack);
				       
			}
			trsk->tr_cached = cur;
			return;
		}
	}

	printk(KERN_INFO "Unknown SID %p %x:%x:%x:... [data %p]\n",
	       sk, p[0], p[1], p[2], trsk->tr_cached);

	trsk->tr_cached = NULL;
}

static void process_nextk1(struct sock *sk, struct request_sock *req,
			   struct sk_buff *skb, u8 *p)
{
	unsigned long flags;

	spin_lock_irqsave(&tcpcrypt_cache_lock, flags);
	do_process_nextk1(sk, req, skb, p);
	spin_unlock_irqrestore(&tcpcrypt_cache_lock, flags);
}

static int tcpcrypt_recv_listen(struct sock *sk, struct request_sock *req,
				struct sk_buff *skb)
{
	u8 *p;
	struct tcpcrypt_rsk *trsk = tcpcrypt_rsk(req);

	BUG_ON(!req);

	p = tcpcrypt_find_option(skb, TCPOPT_CRYPT);
	if (!p) {
        	struct tcphdr *th = tcp_hdr(skb);

		printk(KERN_INFO "recv_listen: CRYPT not found"
		       " S %d A %d R %d len %d doff %d data %p support %x\n",
		       th->syn, th->ack, th->rst, skb->len, th->doff * 4,
		       trsk->tr_cached, trsk->tr_support);

		goto __disable;
	}

	/* XXX who the fuck inits this? */
	trsk->tr_support = 0;

	switch (tcpcrypt_opcode(p)) {
	case TCPCRYPT_HELLO_SUPPORT:
		trsk->tr_support |= TCPCRYPT_SUPPORT_REMOTE;
	case TCPCRYPT_HELLO:
		trsk->tr_support |= TCPCRYPT_SUPPORT_ON;
		trsk->tr_cached   = NULL;
		break;

	case TCPCRYPT_NEXTK1_SUPPORT:
		trsk->tr_support |= TCPCRYPT_SUPPORT_REMOTE;
	case TCPCRYPT_NEXTK1:
		trsk->tr_support |= TCPCRYPT_SUPPORT_ON;
		process_nextk1(sk, req, skb, p);
		break;

	default:
		printk(KERN_INFO "recv_listen opcode %x\n", tcpcrypt_opcode(p));
		goto __disable;
	}

	return 0;

__disable:
	printk(KERN_INFO "Disabling tcpcrypt %p\n", sk);
	trsk->tr_support = 0;
	trsk->tr_cached  = NULL; /* XXX */
	return 0;
}

static void fill_nonce(void *x, int len)
{
	unsigned char *p = x;

	if (!conf_client_hack) {
		get_random_bytes(x, len);
		return;
	}

	while (len--)
		*p++ = 'X';
}

static struct tcpcrypt_crypto_ops *pkey_op(struct sock *sk)
{
	return tci_sk(sk)->tci_crypto[TCPCRYPT_PKEY]->tcc_ops;
}

static struct tcrypto_priv *pkey_priv(struct sock *sk)
{
	return tci_sk(sk)->tci_crypto_priv[TCPCRYPT_PKEY];
}

static void add_hashbuf(struct sock *sk, void *data, int len)
{
	struct tcp_crypt_info *tci = tci_sk(sk);

	BUG_ON(len >= (sizeof(tci->tci_hashbuf) - tci->tci_hashbuf_len));

	memcpy(&tci->tci_hashbuf[tci->tci_hashbuf_len], data, len);
	tci->tci_hashbuf_len += len;
}

static int send_init1(struct sock *sk, int mink, int maxk, int keylen,
		      void *pk, int pkl)
{
	struct tcp_crypt_info *tci = tci_sk(sk);
	unsigned short *s = (unsigned short*) tci->tci_crap;
	unsigned short *syml, *keyl;
	int nonce_len = 32;
	struct tcpcrypt_algo *algo;
	struct tcpcrypt_crypto *crypto;
	unsigned char *p;
	int symlen = 0;
	void *sym;
	void *nonce;

	*s++ = htons(0x0001);
	syml = s++;
	*s++ = htons(nonce_len);
	keyl = s++;
	sym  = s;
	list_for_each_entry(algo, &tcpcrypt_algos.tcc_node, tcc_node) {
		crypto = algo->tcc_crypto;

		if (crypto->tcc_type == TCPCRYPT_SYMMETRIC) {
			*s++ = htons(crypto->tcc_id);
			*s++ = htons(crypto->tcc_companion);
			symlen++;
		} else if (crypto->tcc_type == TCPCRYPT_MAC) {
			*s++ = htons(crypto->tcc_companion);
			*s++ = htons(crypto->tcc_id);
			symlen++;
		}
	}
	*syml = htons(symlen);

	fill_nonce(s, nonce_len);
	nonce = p = (unsigned char*) s;
	p += nonce_len;

	*p++ = 0;

	*p++ = tci->tci_crypto[TCPCRYPT_PKEY]->tcc_id;
	*p++ = mink;
	*p++ = maxk;

	tci->tci_crypto_priv[TCPCRYPT_PKEY] = pkey_op(sk)->tco_init(sk);
	if (!tci->tci_crypto_priv[TCPCRYPT_PKEY])
		return -1;

	/* XXX cache */
	if (pkey_op(sk)->tco_set_key(pkey_priv(sk), rsa_key2,
				     rsa_key2_size) < 0)
		return -1;

	keylen = pkey_op(sk)->tco_fill_key(pkey_priv(sk), p, keylen);
	*keyl  = htons(keylen);

	tci->tci_hashbuf_len = 0;
	add_hashbuf(sk, p, keylen);
	add_hashbuf(sk, pk, pkl);
	add_hashbuf(sk, sym, symlen * 4);

	/* place holder */
	tci->tci_hashbuf_sym = &tci->tci_hashbuf[tci->tci_hashbuf_len];
	add_hashbuf(sk, "aaaa", 4);

	add_hashbuf(sk, nonce, nonce_len);

	p += keylen;

	return inject_data(sk, tci->tci_crap, p - tci->tci_crap);
}

static int tcpcrypt_recv_hello_sent(struct sock *sk, struct sk_buff *skb)
{
	u8 *p;
	struct tcp_crypt_info *tci = tci_sk(sk);
	int opcode;
	int algos;
	struct tcpcrypt_suboption *sub;
	struct tcpcrypt_pkconf *pkconf;
	struct tcpcrypt_algo *algo;
	struct tcpcrypt_crypto *crypto;
	unsigned char mink, maxk;
	void *pk;
	int pkl;

	p = tcpcrypt_find_option(skb, TCPOPT_CRYPT);
	if (!p) {
		printk(KERN_INFO "sent hello - can't find CRYPT\n");
		tci->tci_state = TCPCRYPT_DISABLED;
		return 0;
	}

	opcode = tcpcrypt_opcode(p);
	if (opcode == TCPCRYPT_PKCONF_SUPPORT) {
		tci->tci_support |= TCPCRYPT_SUPPORT_REMOTE;
	} else if (opcode != TCPCRYPT_PKCONF)
		goto __bad;

	/* figure out which public key algo to use */

	sub    = (struct tcpcrypt_suboption*) p;
	pkl    = sub->tcs_sublen - 2;
	algos  = pkl / 3;
	pk = pkconf = (struct tcpcrypt_pkconf*) sub->tcs_data;

	BUG_ON(pkl < 0 || pkl % 3);

	while (algos--) {
		list_for_each_entry(algo, &tcpcrypt_algos.tcc_node, tcc_node) {
			crypto = algo->tcc_crypto;

			if ((crypto->tcc_type == TCPCRYPT_PKEY)
			    && (crypto->tcc_id == pkconf->pk_id)
			    && (crypto->tcc_min_key <= pkconf->pk_max)
			    && (crypto->tcc_max_key <= pkconf->pk_min))
				break;
			else
				crypto = NULL;
		}

		if (crypto)
			break;

		crypto = NULL;
		pkconf++;
	}

	if (!crypto) {
		printk(KERN_INFO "no algo found\n");
		goto __disable;
	}

	tci->tci_crypto[TCPCRYPT_PKEY] = crypto;

	mink = max(pkconf->pk_min, crypto->tcc_min_key);
	maxk = min(pkconf->pk_max, crypto->tcc_max_key);

	/* send init1 */
	if (send_init1(sk, mink, maxk, mink, pk, pkl)) {
		printk(KERN_INFO "can't send init1\n");
		goto __disable;
	}

	tci_sk(sk)->tci_state = TCPCRYPT_PKCONF_RCVD;
	tci->tci_role	      = TCPCRYPT_CLIENT;

	return 0;

__bad:
	printk(KERN_INFO "bad pkconf\n");
__disable:
	tci->tci_state = TCPCRYPT_DISABLED;

	return 0;
}

static int send_init2(struct sock *sk, void *nonces, int nonces_len)
{
	struct tcp_crypt_info *tci = tci_sk(sk);
	unsigned short *s = (unsigned short*) tci->tci_crap;
	unsigned short *lenp;
	int len;

	*s++ = htons(0x0002);
	lenp = s++;
	*s++ = htons(tci->tci_crypto[TCPCRYPT_SYMMETRIC]->tcc_id);
	*s++ = htons(tci->tci_crypto[TCPCRYPT_MAC]->tcc_id);

	len   = pkey_op(sk)->tco_encrypt(pkey_priv(sk), s, nonces, nonces_len);
	*lenp = htons(len);

	return inject_data(sk, tci->tci_crap,
			   (unsigned char*) s - tci->tci_crap + len);
}

static int linearize(void *out, int outlen, struct iovec *iov, int count)
{
	int len = 0;
	unsigned char *p = out;

	while (count--) {
		if (iov->iov_len + len >= outlen) {
			WARN_ON(1);
			return len;
		}

		memcpy(p, iov->iov_base, iov->iov_len);
		p   += iov->iov_len;
		len += iov->iov_len;
		iov++;
	}

	return len;
}

static void setup_ciphers(struct sock *sk)
{
	struct tcp_crypt_info *tci = tci_sk(sk);
	int prfl = tci->tci_crypto[TCPCRYPT_PKEY]->tcc_prf_len;
	int i;

	for (i = TCPCRYPT_SYMMETRIC; i <= TCPCRYPT_MAC2; i++) {
		struct tcrypto_priv *p;

		p = tci->tci_crypto[i]->tcc_ops->tco_init(sk);
		if (!p) {
			printk(KERN_INFO "Fuck can't init key %d\n", i);
			BUG_ON(1);
			return;
		}

		tci->tci_crypto_priv[i] = p;

		if (tci->tci_crypto[i]->tcc_ops->tco_set_key(
				p, tci->tci_keys[i], prfl) == -1) {
			printk(KERN_INFO "can't set key %d\n", i);
			return;
		}
	}
}

static void compute_keys(struct sock *sk)
{
	struct tcp_crypt_info *tci = tci_sk(sk);
	int prfl = tci->tci_crypto[TCPCRYPT_PKEY]->tcc_prf_len;
	unsigned char tag[] = { TCPCRYPT_TAG_SID, 1 };

	/* MK */
	tag[0] = TCPCRYPT_TAG_MK;
	pkey_op(sk)->tco_prf(pkey_priv(sk), tci->tci_keys[TCPCRYPT_MK],
			     NULL, 0, tag, 1);

	/* keys */
	tag[0] = TCPCRYPT_TAG_C_ENC;
	pkey_op(sk)->tco_prf(pkey_priv(sk), tci->tci_keys[TCPCRYPT_KEC],
			     tci->tci_keys[TCPCRYPT_MK], prfl, tag, 2);

	tag[0] = TCPCRYPT_TAG_C_MAC;
	pkey_op(sk)->tco_prf(pkey_priv(sk), tci->tci_keys[TCPCRYPT_KAC], NULL,
			     0, tag, 2);

	tag[0] = TCPCRYPT_TAG_S_ENC;
	pkey_op(sk)->tco_prf(pkey_priv(sk), tci->tci_keys[TCPCRYPT_KES], NULL,
			     0, tag, 2);

	tag[0] = TCPCRYPT_TAG_S_MAC;
	pkey_op(sk)->tco_prf(pkey_priv(sk), tci->tci_keys[TCPCRYPT_KAS], NULL,
			     0, tag, 2);

	setup_ciphers(sk);
}

static void inline dump_keys(struct sock *sk)
{
	struct tcp_crypt_info *tci = tci_sk(sk);
	int prfl = tci->tci_crypto[TCPCRYPT_PKEY]->tcc_prf_len;
	unsigned char *x = tci->tci_keys[TCPCRYPT_SS];

	printk(KERN_INFO "sock %p SS", sk);

	while (prfl--)
		printk(KERN_INFO " %x", *x++);

	printk(KERN_INFO "\n");
}

static inline void hexdump(void *x, int len)
{
	unsigned char *p = x;

	while (len--)
		printk(KERN_INFO " %x", *p++);
}

static void session_cache(struct sock *sk, struct tcpcrypt_cache *cache)
{
	struct tcp_crypt_info *tci = tci_sk(sk);
	unsigned char tag = TCPCRYPT_TAG_NEXTK;
	int prfl = tci->tci_crypto[TCPCRYPT_PKEY]->tcc_prf_len;
	void *k = NULL;
	int klen = 0;

	if (!conf_session_cache)
		return;

	/* fresh */
	if (!cache) {
		cache = kzalloc(sizeof(*cache), GFP_ATOMIC);
		if (!cache)
			return;
	} else {
		/* steal cache struct, but need to reinit prf */
		k    = tci->tci_keys[TCPCRYPT_SS];
		klen = prfl;
	}

	cache->tca_role       = tci->tci_role;
	cache->tca_dst.s_addr = get_addr(sk);

	/* SS */
	pkey_op(sk)->tco_prf(pkey_priv(sk), cache->tca_ss, k, klen,
			     &tag, sizeof(tag));

	/* SID */
	tag = TCPCRYPT_TAG_NEXTK;
	pkey_op(sk)->tco_prf(pkey_priv(sk), cache->tca_sid, cache->tca_ss, prfl,
			     &tag, sizeof(tag));

	memcpy(cache->tca_crypto, tci->tci_crypto, sizeof(cache->tca_crypto));

	tci->tci_cached = cache;
}

static void add_session_cache(struct sock *sk)
{
	struct tcp_crypt_info *tci = tci_sk(sk);
	unsigned long flags;

	if (!tci->tci_cached)
		return;

	spin_lock_irqsave(&tcpcrypt_cache_lock, flags);
	list_add(&tci->tci_cached->tca_node, &tcpcrypt_cache.tca_node);
	spin_unlock_irqrestore(&tcpcrypt_cache_lock, flags);

	tci->tci_cached = NULL;
}

static void session_resume(struct sock *sk)
{
	struct tcp_crypt_info *tci = tci_sk(sk);
	struct tcpcrypt_cache *ca  = tci->tci_cached;
	int prfl;

	tci->tci_state = TCPCRYPT_ENCRYPTING;
	tci->tci_role  = ca->tca_role;

	/* setup prf */
	memcpy(tci->tci_crypto, ca->tca_crypto, sizeof(tci->tci_crypto));

	prfl = tci->tci_crypto[TCPCRYPT_PKEY]->tcc_prf_len;

	tci->tci_crypto_priv[TCPCRYPT_PKEY] = pkey_op(sk)->tco_init(sk);

	/* ss & sid */
	memcpy(tci->tci_keys[TCPCRYPT_SS], ca->tca_ss, prfl);
	memcpy(tci->tci_keys[TCPCRYPT_SID], ca->tca_sid, prfl);

	/* recache */
	session_cache(sk, ca);

	compute_keys(sk);
}

static void compute_crypto(struct sock *sk, void *nonce, int nonce_len,
			   struct iovec *iov, int iovc)
{
	int len;
	struct tcp_crypt_info *tci = tci_sk(sk);
	unsigned char tag[] = { TCPCRYPT_TAG_SID, 1 };
	int prfl = tci->tci_crypto[TCPCRYPT_PKEY]->tcc_prf_len;

	BUG_ON(!tci->tci_crypto[TCPCRYPT_PKEY]);
	BUG_ON(!tci->tci_crypto[TCPCRYPT_SYMMETRIC]);
	BUG_ON(!tci->tci_crypto[TCPCRYPT_MAC]);

	tci->tci_crypto[TCPCRYPT_SYMMETRIC2] = 
				tci->tci_crypto[TCPCRYPT_SYMMETRIC];

	tci->tci_crypto[TCPCRYPT_MAC2] = 
				tci->tci_crypto[TCPCRYPT_MAC];

	len = linearize(tci->tci_crap, sizeof(tci->tci_crap), iov, iovc);

	/* SS */
	pkey_op(sk)->tco_prf(pkey_priv(sk), tci->tci_keys[TCPCRYPT_SS],
			     nonce, nonce_len, tci->tci_crap, len);

#if 0
	dump_keys(sk);
#endif

	/* SID */
	pkey_op(sk)->tco_prf(pkey_priv(sk), tci->tci_keys[TCPCRYPT_SID],
			     tci->tci_keys[TCPCRYPT_SS], prfl, tag, 1);

	session_cache(sk, NULL);
	add_session_cache(sk);

	compute_keys(sk);
}

static int tcpcrypt_recv_nextk1_sent(struct sock *sk, struct sk_buff *skb)
{
	u8 *p;
	struct tcp_crypt_info *tci = tci_sk(sk);

	p = tcpcrypt_find_option(skb, TCPOPT_CRYPT);
	if (!p) {
        	struct tcphdr *th = tcp_hdr(skb);

		printk(KERN_INFO "nextk1 sent - crypt not found %p flags %x"
		       " state %d\n", 
		       sk, ((unsigned char*) th)[13], sk->sk_state);

		tci->tci_state = TCPCRYPT_DISABLED;
		return 0;
	}

	switch (tcpcrypt_opcode(p)) {
	case TCPCRYPT_PKCONF:
	case TCPCRYPT_PKCONF_SUPPORT:
		if (conf_session_cache == 2) {
			printk(KERN_INFO "Server refused session caching\n");
		}

		return tcpcrypt_recv_hello_sent(sk, skb);

	case TCPCRYPT_NEXTK2_SUPPORT:
		tci->tci_support |= TCPCRYPT_SUPPORT_REMOTE;
	case TCPCRYPT_NEXTK2:
		break;

	default:
		printk(KERN_INFO "Bad subopt\n");
		goto __disable;
		
	}

	if (p[1] != 3) {
		printk(KERN_INFO "bad nextk2\n");
		goto __disable;
	}

	BUG_ON(!conf_session_cache); /* XXX */

	session_resume(sk);

	return 0;

__disable:
	tci->tci_state = TCPCRYPT_DISABLED;

	return 0;
}

static void process_init1(struct sock *sk, struct sk_buff *skb)
{
	u8 *p;
	u16 *s;
	struct tcp_crypt_info *tci = tci_sk(sk);
	int nums;
	int nc, kc;
	struct tcpcrypt_algo *algo;
	u8 *noncec;
	int len;
	unsigned char nonce[32];
	int ns = sizeof(nonce);
	int found = 0;
	unsigned short *sym, symlen;
	struct iovec iov[5];
	unsigned short symc[2];
        struct tcphdr *th = tcp_hdr(skb);
	struct skb_shared_info *shi = skb_shinfo(skb);

	p = tcpcrypt_find_option(skb, TCPOPT_CRYPT);
	BUG_ON(!p);
	BUG_ON(tcpcrypt_opcode(p) != TCPCRYPT_INIT1);

	/* XXX check lengths */

	s = (u16*) ((u8*) th + th->doff * 4);

	/* XXX */
	if (shi->nr_frags == 1) {
		const struct skb_frag_struct *f = &shi->frags[0];

		s = (u16*) ((unsigned char*) pfn_to_kaddr(page_to_pfn(f->page))
		                             + f->page_offset);
	}

	if (ntohs(*s++) != 0x0001) {
		printk(KERN_INFO "Bad magic %x frags %d headlen %d\n",
		       ntohs(s[-1]), shi->nr_frags, skb_headlen(skb));
		goto __bad;
	}

	nums = ntohs(*s++);
	nc   = ntohs(*s++);
	kc   = ntohs(*s++);

	symlen = nums * 4;
	sym    = s;

	while (nums--) {
		int wants[TCPCRYPT_CRYPT_MAX];
		int i;

		wants[TCPCRYPT_SYMMETRIC] = ntohs(*s++);
		wants[TCPCRYPT_MAC]       = ntohs(*s++);

		list_for_each_entry(algo, &tcpcrypt_algos.tcc_node, tcc_node) {
			struct tcpcrypt_crypto *crypto = algo->tcc_crypto;

			for (i = TCPCRYPT_SYMMETRIC; 
			     i <= TCPCRYPT_MAC; i++) {
				if (!tci->tci_crypto[i]
				    && (crypto->tcc_type == i)
				    && (crypto->tcc_id == wants[i] 
				    	|| wants[i] == 0)) {
					tci->tci_crypto[i] = crypto;
				}
			}
			
			if (tci->tci_crypto[TCPCRYPT_SYMMETRIC]
			    && tci->tci_crypto[TCPCRYPT_MAC]) {
			    	found = 1;
				break;
			}
		}

		if (found)
			break;
		else {
			tci->tci_crypto[TCPCRYPT_SYMMETRIC] 
				= tci->tci_crypto[TCPCRYPT_MAC] = NULL;
		}
	}

	if (!found) {
		printk(KERN_INFO "Can't negotiate symmetric and mac\n");
		goto __bad;
	}

	p  = noncec = (u8*) sym + symlen;
	p += nc;

	if (*p++ != 0) {
		printk(KERN_INFO "Zero not found\n");
		goto __bad;
	}

	list_for_each_entry(algo, &tcpcrypt_algos.tcc_node, tcc_node) {
		struct tcpcrypt_crypto *crypto = algo->tcc_crypto;

		if (crypto->tcc_type == TCPCRYPT_PKEY
		    && crypto->tcc_id == p[0]
		    && p[1] <= crypto->tcc_max_key
		    && p[2] <= crypto->tcc_min_key) {
			tci->tci_crypto[TCPCRYPT_PKEY] = crypto;
			break;
		}
	}

	if (!tci->tci_crypto[TCPCRYPT_PKEY]) {
		printk(KERN_INFO "Can't negotiate pkey\n");
		goto __bad;
	}

	p += 3;

	tci->tci_crypto_priv[TCPCRYPT_PKEY] = pkey_op(sk)->tco_init(sk);
	if (!tci->tci_crypto_priv[TCPCRYPT_PKEY]) {
		printk(KERN_INFO "Can't init pkey\n");
		goto __bad;
	}

	len = pkey_op(sk)->tco_set_key(pkey_priv(sk), p, kc);
	if (len == -1) {
		printk(KERN_INFO "Can't parse key\n");
		goto __bad;
	}

	if (len > tci->tci_crypto[TCPCRYPT_PKEY]->tcc_max_key ||
	    len < tci->tci_crypto[TCPCRYPT_PKEY]->tcc_min_key) {
		printk(KERN_INFO "bad key len\n");
		goto __bad;
	}

	fill_nonce(nonce, ns);

	symc[0] = htons(tci->tci_crypto[TCPCRYPT_SYMMETRIC]->tcc_id);
	symc[1] = htons(tci->tci_crypto[TCPCRYPT_MAC]->tcc_id);

	if (send_init2(sk, nonce, ns)) {
		printk(KERN_INFO "Can't send INIT2\n");
		goto __disable;
	}

	tci->tci_state = TCPCRYPT_INIT1_RCVD;
	tci->tci_role  = TCPCRYPT_SERVER;

	iov[0].iov_base = p;
	iov[0].iov_len  = kc;
	iov[1].iov_base = tci->tci_hashbuf;
	iov[1].iov_len  = tci->tci_hashbuf_len;
	iov[2].iov_base = sym;
	iov[2].iov_len  = symlen;
	iov[3].iov_base = symc;
	iov[3].iov_len  = sizeof(symc);
	iov[4].iov_base = noncec;
	iov[4].iov_len  = nc;

	compute_crypto(sk, nonce, ns, iov, sizeof(iov) / sizeof(*iov));

	return;

__bad:
	printk(KERN_INFO "Bad INIT1\n");
__disable:
	tci->tci_state = TCPCRYPT_DISABLED;
}

static int tcpcrypt_recv_pkconf_sent(struct sock *sk, struct sk_buff *skb)
{
	u8 *p;
	struct tcp_crypt_info *tci = tci_sk(sk);

	p = tcpcrypt_find_option(skb, TCPOPT_CRYPT);
	if (!p)
		goto __disable;

	if (tcpcrypt_opcode(p) != TCPCRYPT_INIT1)
		goto __disable;

	TCP_SKB_CB(skb)->tcpcrypt_option = 1;

	process_init1(sk, skb);

	return 0;

__disable:
	tci->tci_state = TCPCRYPT_DISABLED;

	return 0;
}

static void process_init2(struct sock *sk, struct sk_buff *skb)
{
	u16 *s;
	struct tcp_crypt_info *tci = tci_sk(sk);
        struct tcphdr *th = tcp_hdr(skb);
	int clen;
	int wants[TCPCRYPT_CRYPT_MAX];
	unsigned char *sym;
	unsigned char nonce[32];
	struct tcpcrypt_algo *algo;
	int found = 0;
	int noncel;
	struct iovec iov[1];
	struct skb_shared_info *shi = skb_shinfo(skb);

	/* XXX check lengths */

	s = (u16*) ((u8*) th + th->doff * 4);

	/* XXX */
	if (shi->nr_frags == 1) {
		const struct skb_frag_struct *f = &shi->frags[0];

		s = (u16*) ((unsigned char*) pfn_to_kaddr(page_to_pfn(f->page))
		                             + f->page_offset);
	}

	if (ntohs(*s++) != 0x0002) {
		printk(KERN_INFO "Bad magic\n");
		goto __bad;
	}

	clen = ntohs(*s++);
	sym  = (u8*) s;

	wants[TCPCRYPT_SYMMETRIC] = ntohs(*s++);
	wants[TCPCRYPT_MAC]       = ntohs(*s++);

	list_for_each_entry(algo, &tcpcrypt_algos.tcc_node, tcc_node) {
		struct tcpcrypt_crypto *crypto = algo->tcc_crypto;
		int i;

		for (i = TCPCRYPT_SYMMETRIC; i <= TCPCRYPT_MAC; i++) {
			int comp = i == TCPCRYPT_SYMMETRIC ? TCPCRYPT_MAC
							   : TCPCRYPT_SYMMETRIC;

			if (!tci->tci_crypto[i] 
			    && (crypto->tcc_type == i)
			    && (crypto->tcc_id == wants[i])
			    && ((crypto->tcc_companion == 0
			        || crypto->tcc_companion == wants[comp]))) {

				tci->tci_crypto[i] = crypto;
				found++;
			}
		}

		if (found == 2)
			break;
	}

	if (found != 2) {
		printk(KERN_INFO "Can't find sym\n");
		goto __bad;
	}

	BUG_ON(!tci->tci_crypto[TCPCRYPT_SYMMETRIC]);
	BUG_ON(!tci->tci_crypto[TCPCRYPT_MAC]);

	if (conf_client_hack) {
		noncel = 32;
		fill_nonce(nonce, noncel);
	} else {
		noncel = pkey_op(sk)->tco_decrypt(pkey_priv(sk), nonce, s,
						  clen);
	}
	BUG_ON(noncel > sizeof(nonce));

	if (noncel == -1) {
		printk(KERN_INFO "can't decrypt nonce\n");
		goto __bad;
	}

	iov[0].iov_base = tci->tci_hashbuf;
	iov[0].iov_len  = tci->tci_hashbuf_len;

	memcpy(tci->tci_hashbuf_sym, sym, 4);

	compute_crypto(sk, nonce, noncel, iov, sizeof(iov) / sizeof(*iov));

	tci->tci_state = TCPCRYPT_ENCRYPTING;

	return;

__bad:
	printk(KERN_INFO "Bad INIT2\n");
	tci->tci_state = TCPCRYPT_DISABLED;
}

static int tcpcrypt_recv_init1_sent(struct sock *sk, struct sk_buff *skb)
{
	u8 *p;
	struct tcp_crypt_info *tci = tci_sk(sk);

	p = tcpcrypt_find_option(skb, TCPOPT_CRYPT);
	if (!p)
		goto __disable;

	if (tcpcrypt_opcode(p) != TCPCRYPT_INIT2)
		goto __disable;

	TCP_SKB_CB(skb)->tcpcrypt_option = 1;

	process_init2(sk, skb);

	return 0;

__disable:
	printk(KERN_INFO "can't find init2\n");
	tci->tci_state = TCPCRYPT_DISABLED;

	return 0;
}

static int tcpcrypt_recv_encrypting(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_crypt_info *tci = tci_sk(sk);
	u8 *p;
	int maclen = tci->tci_crypto[TCPCRYPT_MAC]->tcc_mac_len;
	int len = 2 + maclen;
	int off;
	unsigned char mac[64];
	unsigned long flags = 0;

	off = tci->tci_role == TCPCRYPT_CLIENT ? TCPCRYPT_KAS
					       : TCPCRYPT_KAC;

	p = tcpcrypt_find_option(skb, TCPOPT_MAC);
	if (!p) {
		struct tcphdr *th = tcp_hdr(skb);

		printk(KERN_INFO "no mac %p flags %x len %d state %d\n",
		       sk, ((unsigned char*) th)[13], skb->len, sk->sk_state);

		return -1;
	}

	if (p[1] != len) {
		printk(KERN_INFO "bad MAC len\n");
		return -1;
	}

	if ((conf_no_mac != 1) || !conf_no_enc)
		spin_lock_irqsave(&tci->tci_rxlock, flags);

	/* check mac */
	do_mac(sk, skb, off, mac);

	if (memcmp(mac, &p[2], maclen) != 0 && conf_no_mac == 0) {
		printk(KERN_INFO "MAC mismatch\n");
		spin_unlock_irqrestore(&tci->tci_rxlock, flags);
		return -1;
	}

	/* decrypt */
	off--;
	if (!conf_no_enc) {
		tci->tci_crypto[off]->tcc_ops->tco_decrypt(
			tci->tci_crypto_priv[off],
			NULL,
			skb,
			-1);
	}

	if ((conf_no_mac != 1) || !conf_no_enc)
		spin_unlock_irqrestore(&tci->tci_rxlock, flags);

	/* wait for first encrypted packet from server before adding to session
	 * cache.  This way we're sure server got a chance to cache session.
	 * */
	if (tci->tci_cached)
		add_session_cache(sk);

	return 0;
}

static int tcpcrypt_recv_nextk2_sent(struct sock *sk, struct sk_buff *skb)
{
	BUG_ON(!conf_session_cache);
	session_resume(sk);
	add_session_cache(sk);

	return tcpcrypt_recv_encrypting(sk, skb);
}

static int tcpcrypt_recv(struct sock *sk, struct request_sock *rsk,
			 struct sk_buff *skb)
{
	struct tcp_crypt_info *tci = tci_sk(sk);
	struct tcphdr *th = tcp_hdr(skb);

	if (sk->sk_state == TCP_LISTEN)
		tci->tci_state = TCPCRYPT_LISTEN;

	/* XXX cleanup */
	if (th->rst)
		return 0;

	if ((sk->sk_state == TCP_SYN_SENT) && !th->syn)
		return 0;

	if (sk->sk_state == TCP_LAST_ACK)
		return 0;

	if ((tci->tci_state == TCPCRYPT_LISTEN) && !rsk)
		return 0;

	/* XXX end of cleanup */

	switch (tci->tci_state) {
	case TCPCRYPT_LISTEN:
		return tcpcrypt_recv_listen(sk, rsk, skb);

	case TCPCRYPT_PKCONF_SENT:
		return tcpcrypt_recv_pkconf_sent(sk, skb);

	case TCPCRYPT_HELLO_SENT:
		return tcpcrypt_recv_hello_sent(sk, skb);

	case TCPCRYPT_INIT1_SENT:
		return tcpcrypt_recv_init1_sent(sk, skb);

	case TCPCRYPT_ENCRYPTING:
		return tcpcrypt_recv_encrypting(sk, skb);

	case TCPCRYPT_DISABLED:
		return 0;

	case TCPCRYPT_NEXTK1_SENT:
		return tcpcrypt_recv_nextk1_sent(sk, skb);

	case TCPCRYPT_NEXTK2_SENT:
		return tcpcrypt_recv_nextk2_sent(sk, skb);

	default:
		printk(KERN_INFO "Unhandled recv state: %d\n",tci->tci_state);
		break;
	}

	return 0;
}

static int tcpcrypt_create_openreq_child(struct sock *parent,
                                         struct sock *newsk,
                                         struct request_sock *req)
{
	struct tcp_crypt_info *tci;
	struct tcpcrypt_rsk *trsk = tcpcrypt_rsk(req);

	if (do_tcpcrypt_init(newsk, GFP_ATOMIC))
		return -1;

	tci = tci_sk(newsk);

	tci->tci_cached  = trsk->tr_cached;
	tci->tci_support = trsk->tr_support;

	if (tci->tci_cached)
		tci->tci_state = TCPCRYPT_NEXTK2_SENT;
	else if (tci->tci_support)
		tci->tci_state = TCPCRYPT_PKCONF_SENT;
	else
		tci->tci_state = TCPCRYPT_DISABLED;

	/* XXX can probably avoid copy */
	tci->tci_hashbuf_len = tci_sk(parent)->tci_hashbuf_len;
	memcpy(tci->tci_hashbuf, tci_sk(parent)->tci_hashbuf,
	       tci->tci_hashbuf_len);

	memset(trsk, 0, sizeof(*trsk));

	return 0;
}

static int tcpcrypt_register_crypto(struct tcpcrypt_crypto *crypto)
{
	struct tcpcrypt_algo *algo;

	algo = kmalloc(sizeof(*algo), GFP_KERNEL);
	if (!algo)
		return -1;

	algo->tcc_crypto = crypto;

	mutex_lock(&tcpcrypt_algos_mutex);
	list_add(&algo->tcc_node, &tcpcrypt_algos.tcc_node);
	mutex_unlock(&tcpcrypt_algos_mutex);

        return 0;
}

static int do_unregister_crypto(struct tcpcrypt_crypto *crypto)
{
	struct tcpcrypt_algo *algo, *next;
	int rc = -1;

	mutex_lock(&tcpcrypt_algos_mutex);
	list_for_each_entry_safe(algo, next, &tcpcrypt_algos.tcc_node,
				 tcc_node) {
		if (crypto == NULL || crypto == algo->tcc_crypto) {
			list_del(&algo->tcc_node);
			kfree(algo);
			rc = 0;
		}
	}
	mutex_unlock(&tcpcrypt_algos_mutex);

	return rc;
}

static char *xinet_ntoa(struct in_addr *in, char *ip)
{
	unsigned char *i = (unsigned char*) &in->s_addr;

	sprintf(ip, "%d.%d.%d.%d", i[0], i[1], i[2], i[3]);

	return ip;
}

static int read_session_cache(char *page, char **start,
                              off_t off, int count,
                              int *eof, void *data)
{
	int rc = -1;
	char *stuff, *p;
	int stufflen = 4096 * 5;
	struct tcpcrypt_cache *cur;
	int i = 0;
	int len;
	char ip[18];
	unsigned long flags;

	p = stuff = kmalloc(stufflen, GFP_KERNEL);
	if (!stuff)
		return -1;

	spin_lock_irqsave(&tcpcrypt_cache_lock, flags);

	list_for_each_entry(cur, &tcpcrypt_cache.tca_node, tca_node) {
		i++;

		if (stufflen < 64) {
			printk(KERN_INFO "need more stufflen\n");
			spin_unlock_irqrestore(&tcpcrypt_cache_lock, flags);
			goto __free;
		}

		len = sprintf(p, "%d) %s R %d [%x:%x:%x:...]\n",
			      i, 
			      xinet_ntoa(&cur->tca_dst, ip),
			      cur->tca_role,
			      cur->tca_sid[0],
			      cur->tca_sid[1],
			      cur->tca_sid[2]);

		stufflen -= len;
		p        += len;
	}

	spin_unlock_irqrestore(&tcpcrypt_cache_lock, flags);

	len = strlen(stuff) - off;
	if (len < 0)
		goto __free;

	if (count < len)
		len = count;

	memcpy(page, &stuff[off], len);

	rc = len;
__free:
	kfree(stuff);

	return rc;
}

static int tcpcrypt_unregister_crypto(struct tcpcrypt_crypto *crypto)
{
	return do_unregister_crypto(crypto);
}

static int tcpcrypt_setsockopt(struct sock *sk, void *optval, int len)
{
	struct tcp_crypt_info *tci = tci_sk(sk);
	int optname;
	int *x = optval;

	if (len < sizeof(optname))
		return -EINVAL;

	/* XXX */
	if (get_user(optname, x))
		return -EFAULT;

	len -= sizeof(optname);
	optval = (void*) ((unsigned long) optval + sizeof(optname));

	switch (optname) {
	case TCPCRYPT_SO_APP_SUPPORT:
		tci->tci_support |= TCPCRYPT_SUPPORT_LOCAL;
		break;

	case TCPCRYPT_SO_RSA_KEY:
		/* XXX var len, lock */
		if (len > sizeof(rsa_key2)) {
			printk(KERN_INFO "size got %d want %d\n",
			       len, sizeof(rsa_key2));
			return -EINVAL;
		}

		if (copy_from_user(rsa_key2, optval, len))
			return -EFAULT;

		rsa_key2_size = len;

		break;

	default:
		return -EINVAL;
	}

        return 0;
}

static int tcpcrypt_netstat(struct sock *sk, void *out, int len)
{
	return 0;
}

static int tcpcrypt_getsockopt(struct sock *sk, void *optval, int *len)
{
	struct tcp_crypt_info *tci = tci_sk(sk);
	int l;
	unsigned char *p = optval;
	int sidlen = 20;
	int olen = 1 + sidlen;
	int *x = optval;
	int opt;

	if (get_user(l, len))
		return -EFAULT;

	if (l < sizeof(int))
		return -EINVAL;
	
	if (get_user(opt, x))
		return -EFAULT;

	switch (opt) {
	case TCPCRYPT_SO_APP_SUPPORT:
		if (l < olen)
			return -1;

		if (put_user(tci->tci_support & TCPCRYPT_SUPPORT_REMOTE, p))
			return -EFAULT;

		p++;

		if (copy_to_user(p, tci->tci_keys[TCPCRYPT_SID], sidlen))
			return -EFAULT;

		break;

	case TCPCRYPT_SO_SESSID:
		if (l < sidlen)
			return -EINVAL;

		if (copy_to_user(p, tci->tci_keys[TCPCRYPT_SID], sidlen))
			return -EFAULT;

		olen = sidlen;
		break;

	case TCPCRYPT_SO_NETSTAT:
		olen = tcpcrypt_netstat(sk, p, l);

		if (olen == -1)
			return -1;
		break;

	default:
		return -EINVAL;
	}

	if (put_user(olen, len))
		return -EFAULT;

	return 0;
}

static void do_session_clear(void)
{
	struct tcpcrypt_cache *cur, *next;

	list_for_each_entry_safe(cur, next, &tcpcrypt_cache.tca_node,
				 tca_node) {
		list_del(&cur->tca_node);
		kfree(cur);
	}
}

static void session_clear(void)
{
	unsigned long flags;

	spin_lock_irqsave(&tcpcrypt_cache_lock, flags);
	do_session_clear();
	spin_unlock_irqrestore(&tcpcrypt_cache_lock, flags);
}

struct tcp_crypt_ops tcp_crypt_ops = {
	.tc_init		 = tcpcrypt_init,
	.tc_destroy		 = tcpcrypt_destroy,
	.tc_create_openreq_child = tcpcrypt_create_openreq_child,
	.tc_send		 = tcpcrypt_send,
	.tc_recv		 = tcpcrypt_recv,
	.tc_register_crypto	 = tcpcrypt_register_crypto,
	.tc_unregister_crypto	 = tcpcrypt_unregister_crypto,
        .tc_setsockopt           = tcpcrypt_setsockopt,
        .tc_getsockopt           = tcpcrypt_getsockopt,
};

static struct ctl_table tcpcrypt_sysctl[] = {
	{
		.procname    = "session_cache",
		.data         = &conf_session_cache,
		.maxlen	      = sizeof(conf_session_cache),
		.mode	      = 0644,
		.proc_handler = proc_dointvec,
	},
	{
		.procname    = "client_hack",
		.data         = &conf_client_hack,
		.maxlen	      = sizeof(conf_client_hack),
		.mode	      = 0644,
		.proc_handler = proc_dointvec,
	},
	{
		.procname    = "no_enc",
		.data         = &conf_no_enc,
		.maxlen	      = sizeof(conf_no_enc),
		.mode	      = 0644,
		.proc_handler = proc_dointvec,
	},
	{
		.procname    = "no_mac",
		.data         = &conf_no_mac,
		.maxlen	      = sizeof(conf_no_mac),
		.mode	      = 0644,
		.proc_handler = proc_dointvec,
	},

	{ .ctl_name = 0, }
};

static struct ctl_path tcpcrypt_sysctl_path[] = {
	{ .procname = "net", .ctl_name = CTL_NET, },
	{ .procname = "tcpcrypt", .ctl_name = NET_TCPCRYPT, },
	{ }
};

static int __init tcpcrypt_module_init(void)
{
	struct tcp_request_sock dummy;
	
	BUILD_BUG_ON(sizeof(struct tcpcrypt_rsk) > sizeof(dummy.tcpcrypt_data));

	printk(KERN_INFO "in\n");

	INIT_LIST_HEAD(&tcpcrypt_algos.tcc_node);
	INIT_LIST_HEAD(&tcpcrypt_cache.tca_node);

	sysctl_table = register_sysctl_paths(tcpcrypt_sysctl_path,
					     tcpcrypt_sysctl);
	if (!sysctl_table)
		return -1;

	proc_tcpcrypt = proc_mkdir("tcpcrypt", init_net.proc_net);
	if (!proc_tcpcrypt)
		return -1;

	if (!create_proc_read_entry("session_cache", 0644, proc_tcpcrypt,
				    read_session_cache, NULL))
		return -1;

	if (tcp_set_tcpcrypt(&tcp_crypt_ops)) {
		printk(KERN_INFO "Can't setup tcpcrypt");
		return -1;
	}

	printk(KERN_INFO "ready to rock\n");

	return 0;
}

static void __exit tcpcrypt_module_exit(void)
{
	printk(KERN_INFO "out\n");

	tcp_set_tcpcrypt(NULL);

	do_unregister_crypto(NULL);

	session_clear();

	unregister_sysctl_table(sysctl_table);

	remove_proc_entry("session_cache", proc_tcpcrypt);
	remove_proc_entry("tcpcrypt", init_net.proc_net);
}

module_init(tcpcrypt_module_init);
module_exit(tcpcrypt_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Andrea Bittau <bittau@stanford.edu>");
MODULE_DESCRIPTION("TCP crypt option");
