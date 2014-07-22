#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <time.h>

#include "inc.h"
#include "tcpcrypt.h"
#include "tcpcrypt_divert.h"
#include "tcpcryptd.h"
#include "crypto.h"
#include "profile.h"
#include "checksum.h"
#include "test.h"

struct conn {
	struct sockaddr_in	c_addr[2];
	struct tc		*c_tc;
	struct conn		*c_next;
};

/* XXX someone that knows what they're doing code a proper hash table */
static struct conn *_connection_map[65536];

struct freelist {
	void		*f_obj;
	struct freelist	*f_next;
};

struct retransmit {
	void	*r_timer;
	int	r_num;
	uint8_t	r_packet[0];
};

struct ciphers {
	struct cipher_list	*c_cipher;
	unsigned char		c_spec[4];
	int			c_speclen;
	struct ciphers	 	*c_next;
};

static struct tc		*_sockopts[65536];
static struct tc_sess		_sessions;
static struct ciphers		_ciphers_pkey;
static struct ciphers		_ciphers_sym;
static struct freelist		_free_free;
static struct freelist		_free_tc;
static struct freelist		_free_conn;
static struct tc_cipher_spec	_pkey[MAX_CIPHERS];
static int			_pkey_len;
static struct tc_scipher	_sym[MAX_CIPHERS];
static int			_sym_len;

typedef int (*opt_cb)(struct tc *tc, int tcpop, int subop, int len, void *data);

static void *get_free(struct freelist *f, unsigned int sz)
{
	struct freelist *x = f->f_next;
	void *o;

	if (x) {
		o = x->f_obj;
		f->f_next = x->f_next;

		if (f != &_free_free) {
			x->f_next         = _free_free.f_next;
			_free_free.f_next = x;
			x->f_obj	  = x;
		}
	} else {
		xprintf(XP_DEBUG, "Gotta malloc %u\n", sz);
		o = xmalloc(sz);
	}

	return o;
}

static void put_free(struct freelist *f, void *obj)
{
	struct freelist *x = get_free(&_free_free, sizeof(*f));

	x->f_obj  = obj;
	x->f_next = f->f_next;
	f->f_next = x;
}

static struct tc *get_tc(void)
{
	return get_free(&_free_tc, sizeof(struct tc));
}

static void put_tc(struct tc *tc)
{
	put_free(&_free_tc, tc);
}

static struct conn *get_connection(void)
{
	return get_free(&_free_conn, sizeof(struct conn));
}

static void put_connection(struct conn *c)
{
	put_free(&_free_conn, c);
}

static void do_add_ciphers(struct ciphers *c, void *spec, int *speclen, int sz,
			   void *specend)
{
	uint8_t *p = (uint8_t*) spec + *speclen;

	c = c->c_next;

	while (c) {
		unsigned char *sp = c->c_spec;

		assert(p + sz <= (uint8_t*) specend);

		memcpy(p, sp, sz);
		p        += sz;
		*speclen += sz;

		c = c->c_next;
	}
}

static int bad_packet(char *msg)
{
	xprintf(XP_ALWAYS, "%s\n", msg);

	return 0;
}

static void tc_init(struct tc *tc)
{
	memset(tc, 0, sizeof(*tc));

	tc->tc_state        = _conf.cf_disable ? STATE_DISABLED : STATE_CLOSED;
	tc->tc_mtu	    = TC_MTU;
	tc->tc_mss_clamp    = 40; /* XXX */
	tc->tc_sack_disable = 1;
	tc->tc_rto	    = 100 * 1000; /* XXX */
	tc->tc_nocache	    = _conf.cf_nocache;

	tc->tc_ciphers_pkey     = _pkey;
	tc->tc_ciphers_pkey_len = _pkey_len;
	tc->tc_ciphers_sym      = _sym;
	tc->tc_ciphers_sym_len  = _sym_len;
}

/* XXX */
static void tc_reset(struct tc *tc)
{
	struct conn *c = tc->tc_conn;

	assert(c);
	tc_init(tc);
	tc->tc_conn = c;
}

static void kill_retransmit(struct tc *tc)
{
	if (!tc->tc_retransmit)
		return;

	clear_timer(tc->tc_retransmit->r_timer);
	free(tc->tc_retransmit);
	tc->tc_retransmit = NULL;
}

static void crypto_free_keyset(struct tc *tc, struct tc_keyset *ks)
{
	if (ks->tc_alg_tx)
		crypt_sym_destroy(ks->tc_alg_tx);

	if (ks->tc_alg_rx)
		crypt_sym_destroy(ks->tc_alg_rx);
}

static void tc_finish(struct tc *tc)
{
	if (tc->tc_crypt_pub)
		crypt_pub_destroy(tc->tc_crypt_pub);

	if (tc->tc_crypt_sym)
		crypt_sym_destroy(tc->tc_crypt_sym);

	crypto_free_keyset(tc, &tc->tc_key_current);
	crypto_free_keyset(tc, &tc->tc_key_next);

	kill_retransmit(tc);

	if (tc->tc_last_ack_timer)
		clear_timer(tc->tc_last_ack_timer);

	if (tc->tc_sess)
		tc->tc_sess->ts_used = 0;
}

static struct tc *tc_dup(struct tc *tc)
{
	struct tc *x = get_tc();

	assert(x);

	*x = *tc;

	assert(!x->tc_crypt);
	assert(!x->tc_crypt_ops);

	return x;
}

static void do_expand(struct tc *tc, uint8_t tag, struct stuff *out)
{
	int len = tc->tc_crypt_pub->cp_k_len;

	assert(len <= sizeof(out->s_data));

	crypt_expand(tc->tc_crypt_pub->cp_hkdf, &tag, sizeof(tag), out->s_data,
		     len);

	out->s_len = len;
}

static void compute_nextk(struct tc *tc, struct stuff *out)
{
	do_expand(tc, CONST_NEXTK, out);
}

static void compute_mk(struct tc *tc, struct stuff *out)
{
	int len = tc->tc_crypt_pub->cp_k_len;
	unsigned char tag[2];
	unsigned char app_support = 0;
	int pos = tc->tc_role == ROLE_SERVER ? 1 : 0;

	assert(len <= sizeof(out->s_data));

	app_support |= (tc->tc_app_support & 1)	<< pos;
	app_support |= (tc->tc_app_support >> 1) << (!pos);

	tag[0] = CONST_REKEY;
	tag[1] = app_support;

	crypt_expand(tc->tc_crypt_pub->cp_hkdf, tag, sizeof(tag), out->s_data,
		     len);

	out->s_len = len;
}

static void compute_sid(struct tc *tc, struct stuff *out)
{
	do_expand(tc, CONST_SESSID, out);
}

static void set_expand_key(struct tc *tc, struct stuff *s)
{
	crypt_set_key(tc->tc_crypt_pub->cp_hkdf, s->s_data, s->s_len);
}

static void session_cache(struct tc *tc)
{
	struct tc_sess *s = tc->tc_sess;

	if (tc->tc_nocache)
		return;

	if (!s) {
		s = xmalloc(sizeof(*s));
		if (!s)
			err(1, "malloc()");

		memset(s, 0, sizeof(*s));
		s->ts_next	  = _sessions.ts_next;
		_sessions.ts_next = s;
		tc->tc_sess	  = s;

		s->ts_dir	 = tc->tc_dir;
		s->ts_role 	 = tc->tc_role;
		s->ts_ip   	 = tc->tc_dst_ip;
		s->ts_port 	 = tc->tc_dst_port;
		s->ts_pub	 = crypt_new(tc->tc_crypt_pub->cp_ctr);
		s->ts_sym	 = crypt_new(tc->tc_crypt_sym->cs_ctr);
	}

	set_expand_key(tc, &tc->tc_nk);
	profile_add(1, "session_cache crypto_mac_set_key");

	compute_sid(tc, &s->ts_sid);
	profile_add(1, "session_cache compute_sid");

	compute_mk(tc, &s->ts_mk);
	profile_add(1, "session_cache compute_mk");

	compute_nextk(tc, &s->ts_nk);
	profile_add(1, "session_cache compute_nk");
}

static void init_algo(struct tc *tc, struct crypt_sym *cs,
		      struct crypt_sym **algo, struct tc_keys *keys)
{
	*algo = crypt_new(cs->cs_ctr);

	cs = *algo;

	crypt_set_key(cs->cs_cipher, keys->tk_enc.s_data, keys->tk_enc.s_len);
	crypt_set_key(cs->cs_mac, keys->tk_mac.s_data, keys->tk_mac.s_len);
	crypt_set_key(cs->cs_ack_mac, keys->tk_ack.s_data, keys->tk_ack.s_len);
}

static void compute_asm_keys(struct tc *tc, struct tc_keys *tk)
{
	set_expand_key(tc, &tk->tk_prk);

	do_expand(tc, CONST_KEY_ENC, &tk->tk_enc);
	do_expand(tc, CONST_KEY_MAC, &tk->tk_mac);
	do_expand(tc, CONST_KEY_ACK, &tk->tk_ack);
}

static void compute_keys(struct tc *tc, struct tc_keyset *out)
{
	struct crypt_sym **tx, **rx;

	set_expand_key(tc, &tc->tc_mk);

	profile_add(1, "compute keys mac set key");

	do_expand(tc, CONST_KEY_C, &out->tc_client.tk_prk);
	do_expand(tc, CONST_KEY_S, &out->tc_server.tk_prk);

	profile_add(1, "compute keys calculated keys");

	compute_asm_keys(tc, &out->tc_client);
	compute_asm_keys(tc, &out->tc_server);

	switch (tc->tc_role) {
	case ROLE_CLIENT:
		tx = &out->tc_alg_tx;
		rx = &out->tc_alg_rx;
		break;

	case ROLE_SERVER:
		tx = &out->tc_alg_rx;
		rx = &out->tc_alg_tx;
		break;

	default:
		assert(!"Unknown role");
		abort();
		break;
	}

	init_algo(tc, tc->tc_crypt_sym, tx, &out->tc_client);
	init_algo(tc, tc->tc_crypt_sym, rx, &out->tc_server);
	profile_add(1, "initialized algos");
}

static void get_algo_info(struct tc *tc)
{
	tc->tc_mac_size = tc->tc_crypt_sym->cs_mac_len;
	tc->tc_sym_ivmode = IVMODE_SEQ; /* XXX */
}

static void scrub_sensitive(struct tc *tc)
{
}

static void copy_stuff(struct stuff *dst, struct stuff *src)
{
	memcpy(dst, src, sizeof(*dst));
}

static int session_resume(struct tc *tc)
{
	struct tc_sess *s = tc->tc_sess;

	if (!s)
		return 0;

	copy_stuff(&tc->tc_sid, &s->ts_sid);
	copy_stuff(&tc->tc_mk, &s->ts_mk);
	copy_stuff(&tc->tc_nk, &s->ts_nk);

	tc->tc_role	 = s->ts_role;
	tc->tc_crypt_sym = crypt_new(s->ts_sym->cs_ctr);
	tc->tc_crypt_pub = crypt_new(s->ts_pub->cp_ctr);

	return 1;
}

static void enable_encryption(struct tc *tc)
{
	profile_add(1, "enable_encryption in");

	tc->tc_state = STATE_ENCRYPTING;

	if (!session_resume(tc)) {
		set_expand_key(tc, &tc->tc_ss);

		profile_add(1, "enable_encryption mac set key");

		compute_sid(tc, &tc->tc_sid);
		profile_add(1, "enable_encryption compute SID");

		compute_mk(tc, &tc->tc_mk);
		profile_add(1, "enable_encryption compute mk");

		compute_nextk(tc, &tc->tc_nk);
		profile_add(1, "enable_encryption did compute_nextk");
	}

	compute_keys(tc, &tc->tc_key_current);
	profile_add(1, "enable_encryption compute keys");

	get_algo_info(tc);

	session_cache(tc);
	profile_add(1, "enable_encryption session cache");

	scrub_sensitive(tc);
}

static int conn_hash(uint16_t src, uint16_t dst)
{
	return (src + dst) % 
		(sizeof(_connection_map) / sizeof(*_connection_map));
}

static struct conn *get_head(uint16_t src, uint16_t dst)
{
	return _connection_map[conn_hash(src, dst)];
}

static struct tc *do_lookup_connection_prev(struct sockaddr_in *src,
					    struct sockaddr_in *dst,
					    struct conn **prev)
{
	struct conn *head;
	struct conn *c;

	head = get_head(src->sin_port, dst->sin_port);
	if (!head)
		return NULL;

	c     = head->c_next;
	*prev = head;

	while (c) {
		if (   src->sin_addr.s_addr == c->c_addr[0].sin_addr.s_addr
		    && dst->sin_addr.s_addr == c->c_addr[1].sin_addr.s_addr
		    && src->sin_port == c->c_addr[0].sin_port
		    && dst->sin_port == c->c_addr[1].sin_port)
			return c->c_tc;

		*prev = c;
		c = c->c_next;
	}

	return NULL;
}

static struct tc *lookup_connection_prev(struct ip *ip, struct tcphdr *tcp,
				    	 int flags, struct conn **prev)
{
	struct sockaddr_in addr[2];
	int idx = flags & DF_IN ? 1 : 0;

	addr[idx].sin_addr.s_addr  = ip->ip_src.s_addr;
	addr[idx].sin_port         = tcp->th_sport;
	addr[!idx].sin_addr.s_addr = ip->ip_dst.s_addr;
	addr[!idx].sin_port        = tcp->th_dport;

	return do_lookup_connection_prev(&addr[0], &addr[1], prev);
}

static struct tc *lookup_connection(struct ip *ip, struct tcphdr *tcp,
				    int flags)
{
	struct conn *prev;

	return lookup_connection_prev(ip, tcp, flags, &prev);
}

static struct tc *sockopt_find_port(int port)
{
	return _sockopts[port];
}

static struct tc *sockopt_find(struct tcpcrypt_ctl *ctl)
{
	struct ip ip;
	struct tcphdr tcp;

	if (!ctl->tcc_dport)
		return sockopt_find_port(ctl->tcc_sport);

	/* XXX */
	ip.ip_src = ctl->tcc_src;
	ip.ip_dst = ctl->tcc_dst;

	tcp.th_sport = ctl->tcc_sport;
	tcp.th_dport = ctl->tcc_dport;

	return lookup_connection(&ip, &tcp, 0);
}

static void sockopt_clear(unsigned short port)
{
	_sockopts[port] = NULL;
}

static void retransmit(void *a)
{
	struct tc *tc = a;
	struct ip *ip;

	xprintf(XP_DEBUG, "Retransmitting %p\n", tc);

	assert(tc->tc_retransmit);

	if (tc->tc_retransmit->r_num++ >= 10) {
		xprintf(XP_DEFAULT, "Retransmit timeout\n");
		tc->tc_tcp_state = TCPSTATE_DEAD; /* XXX remove connection */
	}

	ip = (struct ip*) tc->tc_retransmit->r_packet;

	divert_inject(ip, ntohs(ip->ip_len));

	/* XXX decay */
	tc->tc_retransmit->r_timer = add_timer(tc->tc_rto, retransmit, tc);
}

static void add_connection(struct conn *c)
{
	int idx = c->c_addr[0].sin_port;
	struct conn *head;

	idx = conn_hash(c->c_addr[0].sin_port, c->c_addr[1].sin_port);
	if (!_connection_map[idx]) {
		_connection_map[idx] = xmalloc(sizeof(*c));
		memset(_connection_map[idx], 0, sizeof(*c));
	}

	head = _connection_map[idx];

	c->c_next    = head->c_next;
	head->c_next = c;
}

static struct tc *new_connection(struct ip *ip, struct tcphdr *tcp, int flags)
{
	struct tc *tc;
	struct conn *c;
	int idx = flags & DF_IN ? 1 : 0;

	c = get_connection();
	assert(c);
	profile_add(2, "alloc connection");

	memset(c, 0, sizeof(*c));
	c->c_addr[idx].sin_addr.s_addr  = ip->ip_src.s_addr;
	c->c_addr[idx].sin_port         = tcp->th_sport;
	c->c_addr[!idx].sin_addr.s_addr = ip->ip_dst.s_addr;
	c->c_addr[!idx].sin_port        = tcp->th_dport;
	profile_add(2, "setup connection");

	tc = sockopt_find_port(c->c_addr[0].sin_port);
	if (!tc) {
		tc = get_tc();
		assert(tc);

		profile_add(2, "TC malloc");

		tc_init(tc);

		profile_add(2, "TC init");
	} else {
		/* For servers, we gotta duplicate options on child sockets.
		 * For clients, we just steal it.
		 */
		if (flags & DF_IN)
			tc = tc_dup(tc);
		else
			sockopt_clear(c->c_addr[0].sin_port);
	}

	tc->tc_dst_ip.s_addr = c->c_addr[1].sin_addr.s_addr;
	tc->tc_dst_port	     = c->c_addr[1].sin_port;
	tc->tc_conn	     = c;

	c->c_tc	= tc;

	add_connection(c);	

	return tc;
}

static void do_remove_connection(struct tc *tc, struct conn *prev)
{
	struct conn *item;

	assert(tc);
	assert(prev);

	item = prev->c_next;
	assert(item);

	tc_finish(tc);
	put_tc(tc);

	prev->c_next = item->c_next;
	put_connection(item);
}

static void remove_connection(struct ip *ip, struct tcphdr *tcp, int flags)
{
	struct conn *prev = NULL;
	struct tc *tc;

	tc = lookup_connection_prev(ip, tcp, flags, &prev);

	do_remove_connection(tc, prev);
}

static void kill_connection(struct tc *tc)
{
	struct conn *c = tc->tc_conn;
	struct conn *prev;
	struct tc *found;

	assert(c);
	found = do_lookup_connection_prev(&c->c_addr[0], &c->c_addr[1], &prev);
	assert(found);
	assert(found == tc);

	do_remove_connection(tc, prev);
}

static void last_ack(void *a)
{
	struct tc *tc = a;

	tc->tc_last_ack_timer = NULL;
	xprintf(XP_NOISY, "Last ack for %p\n");
	kill_connection(tc);
}

static void *tcp_data(struct tcphdr *tcp)
{
	return (char*) tcp + (tcp->th_off << 2);
}

static int tcp_data_len(struct ip *ip, struct tcphdr *tcp)
{
	int hl = (ip->ip_hl << 2) + (tcp->th_off << 2);

	return ntohs(ip->ip_len) - hl;
}

static void *find_opt(struct tcphdr *tcp, unsigned char opt)
{
	unsigned char *p = (unsigned char*) (tcp + 1);
	int len = (tcp->th_off << 2) - sizeof(*tcp);
	int o, l;

	assert(len >= 0);

	while (len > 0) {
		if (*p == opt) {
			if (*(p + 1) > len) {
				xprintf(XP_ALWAYS, "fek\n");
				return NULL;
			}

			return p;
		}

		o = *p++;
		len--;

		switch (o) {
		case TCPOPT_EOL:
		case TCPOPT_NOP:
			continue;
		}

		if (!len) {
			xprintf(XP_ALWAYS, "fuck\n");
			return NULL;
		}

		l = *p++;
		len--;
		if (l > (len + 2) || l < 2) {
			xprintf(XP_ALWAYS, "fuck2 %d %d\n", l, len);
			return NULL;
		}

		p += l - 2;
		len -= l - 2;
	}
	assert(len == 0);

	return NULL;
}

static struct tc_subopt *find_subopt(struct tcphdr *tcp, unsigned char op)
{
	struct tcpopt_crypt *toc;
	struct tc_subopt *tcs;
	int len;
	int optlen;

	toc = find_opt(tcp, TCPOPT_CRYPT);
	if (!toc)
		return NULL;

	len = toc->toc_len - sizeof(*toc);
	assert(len >= 0);

	if (len == 0 && op == TCOP_HELLO)
		return (struct tc_subopt*) 0xbad;

	tcs = &toc->toc_opts[0];
	while (len > 0) {
		if (len < 1)
			return NULL;

		if (tcs->tcs_op <= 0x3f)
			optlen = 1;
		else if (tcs->tcs_op >= 0x80) {
			switch (tcs->tcs_op) {
			case TCOP_NEXTK1:
			case TCOP_NEXTK1_SUPPORT:
				optlen = 10;
				break;

			case TCOP_REKEY:
				/* XXX depends on cipher */
				optlen = sizeof(struct tco_rekeystream);
				break;

			default:
				errx(1, "Unknown option %d", tcs->tcs_op);
				break;
			}
		} else
			optlen = tcs->tcs_len;

		if (optlen > len)
			return NULL;

		if (tcs->tcs_op == op)
			return tcs;

		len -= optlen;
		tcs = (struct tc_subopt*) ((unsigned long) tcs + optlen);
	}
	assert(len == 0);

	return NULL;
}

static void checksum_packet(struct tc *tc, struct ip *ip, struct tcphdr *tcp)
{
	checksum_ip(ip);
	checksum_tcp(tc, ip, tcp);
}

static void set_ip_len(struct ip *ip, unsigned short len)
{
	unsigned short old = ntohs(ip->ip_len);
	int diff;
	int sum;

	ip->ip_len = htons(len);

	diff	   = len - old;
	sum  	   = ntohs(~ip->ip_sum);
	sum 	  += diff;
	sum	   = (sum >> 16) + (sum & 0xffff);
	sum	  += (sum >> 16);
	ip->ip_sum = htons(~sum);
}

static int foreach_subopt(struct tc *tc, int len, void *data, opt_cb cb)
{
	struct tc_subopt *tcs = (struct tc_subopt*) data;
	int optlen = 0;
	unsigned char *d;

	assert(len >= 0);

	if (len == 0)
		return cb(tc, -1, TCOP_HELLO, optlen, tcs);

	while (len > 0) {
		d = (unsigned char *) tcs;

		if (len < 1)
			goto __bad;

		if (tcs->tcs_op <= 0x3f)
			optlen = 1;
		else if (tcs->tcs_op >= 0x80) {
			d++;
			switch (tcs->tcs_op) {
			case TCOP_NEXTK1:
			case TCOP_NEXTK1_SUPPORT:
				optlen = 10;
				break;

			case TCOP_REKEY:
				/* XXX depends on cipher */
				optlen = sizeof(struct tco_rekeystream);
				break;

			default:
				errx(1, "Unknown option %d", tcs->tcs_op);
				break;
			}
		} else {
			if (len < 2)
				goto __bad;
			optlen = tcs->tcs_len;
			d = tcs->tcs_data;
		}

		if (optlen > len)
			goto __bad;

		if (cb(tc, -1, tcs->tcs_op, optlen, d))
			return 1;

		len -= optlen;
		tcs  = (struct tc_subopt*) ((unsigned long) tcs + optlen);
	}

	assert(len == 0);

	return 0;
__bad:
	xprintf(XP_ALWAYS, "bad\n");
	return 1;
}

static void foreach_opt(struct tc *tc, struct tcphdr *tcp, opt_cb cb)
{
	unsigned char *p = (unsigned char*) (tcp + 1);
	int len = (tcp->th_off << 2) - sizeof(*tcp);
	int o, l;

	assert(len >= 0);

	while (len > 0) {
		o = *p++;
		len--;

		switch (o) {
		case TCPOPT_EOL:
		case TCPOPT_NOP:
			continue; /* XXX optimize */
			l = 0;
			break;

		default:
			if (!len) {
				xprintf(XP_ALWAYS, "fuck\n");
				return;
			}
			l = *p++;
			len--;
			if (l < 2 || l > (len + 2)) {
				xprintf(XP_ALWAYS, "fuck2 %d %d\n", l, len);
				return;
			}
			l -= 2;
			break;
		}

		if (o == TCPOPT_CRYPT) {
			if (foreach_subopt(tc, l, p, cb))
				return;
		} else {
			if (cb(tc, o, -1, l, p))
				return;
		}

		p   += l;
		len -= l;
	}
	assert(len == 0);
}

static int do_ops_len(struct tc *tc, int tcpop, int subop, int len, void *data)
{
	tc->tc_optlen += len + 2;

	return 0;
}

static int tcp_ops_len(struct tc *tc, struct tcphdr *tcp)
{
	int nops   = 40;
	uint8_t *p = (uint8_t*) (tcp + 1);

	tc->tc_optlen = 0;

	foreach_opt(tc, tcp, do_ops_len);

	nops -= tc->tc_optlen;
	p    += tc->tc_optlen;

	assert(nops >= 0);

	while (nops--) {
		if (*p != TCPOPT_NOP && *p != TCPOPT_EOL)
			return (tcp->th_off << 2) - 20;

		p++;
	}

	return tc->tc_optlen;
}

static void *tcp_opts_alloc(struct tc *tc, struct ip *ip, struct tcphdr *tcp,
			    int len)
{
	int opslen = (tcp->th_off << 2) + len;
	int pad = opslen % 4;
	char *p;
	int dlen = ntohs(ip->ip_len) - (ip->ip_hl << 2) - (tcp->th_off << 2);
	int ol = (tcp->th_off << 2) - sizeof(*tcp);

	assert(len);

	/* find space in tail if full of nops */
	if (ol == 40) {
		ol = tcp_ops_len(tc, tcp);
		assert(ol <= 40);

		if (40 - ol >= len)
			return (uint8_t*) (tcp + 1) + ol;
	}

	if (pad)
		len += 4 - pad;

	if (ntohs(ip->ip_len) + len > tc->tc_mtu)
		return NULL;

	p = (char*) tcp + (tcp->th_off << 2);
	memmove(p + len, p, dlen);
	memset(p, 0, len);

	assert(((tcp->th_off << 2) + len) <= 60);

	set_ip_len(ip, ntohs(ip->ip_len) + len);
	tcp->th_off += len >> 2;

	return p;
}

static struct tc_subopt *subopt_alloc(struct tc *tc, struct ip *ip,
				      struct tcphdr *tcp, int len)
{
	struct tcpopt_crypt *toc;

	len += sizeof(*toc);
	toc = tcp_opts_alloc(tc, ip, tcp, len);
	if (!toc)
		return NULL;

	toc->toc_kind = TCPOPT_CRYPT;
	toc->toc_len  = len;

	return toc->toc_opts;
}

static struct tc_sess *session_find_host(struct tc *tc, struct in_addr *in,
					 int port)
{
	struct tc_sess *s = _sessions.ts_next;

	while (s) {
		/* we're liberal - lets only check host */
		if (!s->ts_used 
		    && (s->ts_dir == tc->tc_dir)
		    && (s->ts_ip.s_addr == in->s_addr))
			return s;

		s = s->ts_next;
	}

	return NULL;
}

static int do_output_closed(struct tc *tc, struct ip *ip, struct tcphdr *tcp)
{
	struct tc_sess *ts = tc->tc_sess;

	tc->tc_dir = DIR_OUT;

	if (tcp->th_flags != TH_SYN)
		return DIVERT_ACCEPT;

	if (!ts && !tc->tc_nocache)
		ts = session_find_host(tc, &ip->ip_dst, tcp->th_dport);

	if (!ts) {
		struct tcpopt_crypt *toc;
		int len = sizeof(*toc);

		if (tc->tc_app_support)
			len++;

		toc = tcp_opts_alloc(tc, ip, tcp, len);
		if (!toc) {
			xprintf(XP_ALWAYS, "No space for hello\n");
			tc->tc_state = STATE_DISABLED;

			return DIVERT_ACCEPT;
		}

		toc->toc_kind = TCPOPT_CRYPT;
		toc->toc_len  = len;

		if (tc->tc_app_support)
			toc->toc_opts[0].tcs_op = TCOP_HELLO_SUPPORT;

		tc->tc_state = STATE_HELLO_SENT;

		if (!_conf.cf_nocache)
			xprintf(XP_DEBUG, "Can't find session for host\n");
	} else {
		/* session caching */
		struct tc_subopt *tcs;
		int len = 1 + sizeof(struct tc_sid);

		tcs = subopt_alloc(tc, ip, tcp, len);
		if (!tcs) {
			xprintf(XP_ALWAYS, "No space for NEXTK1\n");
			tc->tc_state = STATE_DISABLED;

			return DIVERT_ACCEPT;
		}

		tcs->tcs_op = tc->tc_app_support ? TCOP_NEXTK1_SUPPORT
						 : TCOP_NEXTK1;

		assert(ts->ts_sid.s_len >= sizeof(struct tc_sid));
		memcpy(&tcs->tcs_len, &ts->ts_sid.s_data,
		       sizeof(struct tc_sid));

		tc->tc_state = STATE_NEXTK1_SENT;
		assert(!ts->ts_used || ts == tc->tc_sess);
		tc->tc_sess  = ts;
		ts->ts_used  = 1;
	}

	return DIVERT_MODIFY;
}

static int do_output_hello_rcvd(struct tc *tc, struct ip *ip,
				struct tcphdr *tcp)
{
	struct tc_subopt *tcs;
	int len;

	if (tc->tc_cmode == CMODE_ALWAYS) {
		tcs = subopt_alloc(tc, ip, tcp, 1);
		if (!tcs) {
			xprintf(XP_ALWAYS, "No space for HELLO\n");
			tc->tc_state = STATE_DISABLED;

			return DIVERT_ACCEPT;
		}

		tcs->tcs_op = TCOP_HELLO;

		tc->tc_state = STATE_HELLO_SENT;

		return DIVERT_MODIFY;
	}

	len = sizeof(*tcs) + tc->tc_ciphers_pkey_len;
	tcs = subopt_alloc(tc, ip, tcp, len);
	if (!tcs) {
		xprintf(XP_ALWAYS, "No space for PKCONF\n");
		tc->tc_state = STATE_DISABLED;
		return DIVERT_ACCEPT;
	}

	tcs->tcs_op  = (tc->tc_app_support & 1) ? TCOP_PKCONF_SUPPORT
						: TCOP_PKCONF;
	tcs->tcs_len = len;

	memcpy(tcs->tcs_data, tc->tc_ciphers_pkey, tc->tc_ciphers_pkey_len);

	memcpy(tc->tc_pub_cipher_list, tc->tc_ciphers_pkey,
	       tc->tc_ciphers_pkey_len);
	tc->tc_pub_cipher_list_len = tc->tc_ciphers_pkey_len;

	tc->tc_state = STATE_PKCONF_SENT;

	return DIVERT_MODIFY;
}

static void *data_alloc(struct tc *tc, struct ip *ip, struct tcphdr *tcp,
			int len, int retx)
{
	int totlen = ntohs(ip->ip_len);
	int hl     = (ip->ip_hl << 2) + (tcp->th_off << 2);
	void *p;

	assert(totlen == hl);
	p = (char*) tcp + (tcp->th_off << 2);

	totlen += len;
	assert(totlen <= 1500);
	set_ip_len(ip, totlen);

	if (!retx)
		tc->tc_seq_off = len;

	return p;
}

static void do_random(void *p, int len)
{
	uint8_t *x = p;

	while (len--)
		*x++ = rand() & 0xff;
}

static void generate_nonce(struct tc *tc, int len)
{
	profile_add(1, "generated nonce in");

	assert(tc->tc_nonce_len == 0);

	tc->tc_nonce_len = len;

	do_random(tc->tc_nonce, tc->tc_nonce_len);

	profile_add(1, "generated nonce out");
}

static int do_output_pkconf_rcvd(struct tc *tc, struct ip *ip,
				 struct tcphdr *tcp, int retx)
{
	struct tc_subopt *tcs;
	int len, klen;
	struct tc_init1 *init1;
	void *key;
	uint8_t *p;

	if (!retx)
		generate_nonce(tc, tc->tc_crypt_pub->cp_n_c);

	tcs = subopt_alloc(tc, ip, tcp, 1);
	assert(tcs);
	tcs->tcs_op = TCOP_INIT1;

	klen = crypt_get_key(tc->tc_crypt_pub->cp_pub, &key);
	len  = sizeof(*init1) 
	       + tc->tc_ciphers_sym_len 
	       + tc->tc_nonce_len
	       + klen;

	init1 = data_alloc(tc, ip, tcp, len, retx);

	init1->i1_magic       = htonl(TC_INIT1);
	init1->i1_len	      = htonl(len);
	init1->i1_pub	      = tc->tc_cipher_pkey;
	init1->i1_num_ciphers = htons(tc->tc_ciphers_sym_len /
				      sizeof(*tc->tc_ciphers_sym));

	p = (uint8_t*) init1->i1_ciphers;
	memcpy(p, tc->tc_ciphers_sym, tc->tc_ciphers_sym_len);
	p += tc->tc_ciphers_sym_len;

	memcpy(tc->tc_sym_cipher_list, tc->tc_ciphers_sym,
	       tc->tc_ciphers_sym_len);
	tc->tc_sym_cipher_list_len = tc->tc_ciphers_sym_len;

	memcpy(p, tc->tc_nonce, tc->tc_nonce_len);
	p += tc->tc_nonce_len;

	memcpy(p, key, klen);

	tc->tc_state = STATE_INIT1_SENT;
	tc->tc_role  = ROLE_CLIENT;

	assert(len <= sizeof(tc->tc_init1));

	memcpy(tc->tc_init1, init1, len);
	tc->tc_init1_len = len;

	return DIVERT_MODIFY;
}

static int do_output_init1_rcvd(struct tc *tc, struct ip *ip,
				struct tcphdr *tcp)
{
	return DIVERT_ACCEPT;
}

static int do_output_init2_sent(struct tc *tc, struct ip *ip,
				struct tcphdr *tcp)
{
	/* we generated this packet */
	struct tc_subopt *opt = find_subopt(tcp, TCOP_INIT2);

	/* kernel is getting pissed off and is resending SYN ack (because we're
	 * delaying his connect setup)
	 */
	if (!opt) {
		/* we could piggy back / retx init2 */

		assert(tcp_data_len(ip, tcp) == 0);
		assert(tcp->th_flags == (TH_SYN | TH_ACK));
		assert(tc->tc_retransmit);

		/* XXX */
		tcp = (struct tcphdr*) &tc->tc_retransmit->r_packet[20];
		assert(find_subopt(tcp, TCOP_INIT2));

		return DIVERT_DROP;
	} else {
#if 1
		enable_encryption(tc);
#endif
	}

	return DIVERT_ACCEPT;
}

static void compute_mac_opts(struct tc *tc, struct tcphdr *tcp,
			     struct iovec *iov, int *nump)
{
	int optlen, ol, optlen2;
	uint8_t *p = (uint8_t*) (tcp + 1);
	int num = *nump;

	optlen2 = optlen = (tcp->th_off << 2) - sizeof(*tcp);
	assert(optlen >= 0);

	if (optlen == tc->tc_mac_opt_cache[tc->tc_dir_packet])
		return;

	iov[num].iov_base = NULL;

	while (optlen > 0) {
		ol = 0;

		switch (*p) {
		case TCPOPT_EOL:
		case TCPOPT_NOP:
			ol = 1;
			ol = 1;
			break;

		default:
			if (optlen < 2) {
				xprintf(XP_ALWAYS, "death\n");
				abort();
			}

			ol = *(p + 1);
			if (ol > optlen) {
				xprintf(XP_ALWAYS, "fuck off\n");
				abort();
			}
		}

		switch (*p) {
		case TCPOPT_TIMESTAMP:
		case TCPOPT_SKEETER:
		case TCPOPT_BUBBA:
		case TCPOPT_MD5:
		case TCPOPT_MAC:
		case TCPOPT_EOL:
		case TCPOPT_NOP:
			if (iov[num].iov_base) {
				num++;
				iov[num].iov_base = NULL;
			}
			break;

		default:
			if (!iov[num].iov_base) {
				iov[num].iov_base = p;
				iov[num].iov_len  = 0;
			}
			iov[num].iov_len += ol;
			break;
		}

		optlen -= ol;
		p += ol;
	}

	if (iov[num].iov_base)
		num++;

	if (*nump == num)
		tc->tc_mac_opt_cache[tc->tc_dir_packet] = optlen2;

	*nump = num;
}

static void compute_mac(struct tc *tc, struct ip *ip, struct tcphdr *tcp,
			void *iv, void *out, int dir_in)
{
	struct mac_m m;
	struct iovec iov[32];
	int num = 0;
	struct mac_a a;
	uint8_t *outp;
	int maca_len = tc->tc_mac_size;
	uint8_t *mac = alloca(maca_len);
	int maclen;
	uint32_t *p1, *p2;
	uint64_t seq = tc->tc_seq + ntohl(tcp->th_seq);
	uint64_t ack = tc->tc_ack + ntohl(tcp->th_ack);
	struct crypt_sym *cs = dir_in ? tc->tc_key_active->tc_alg_rx
				      : tc->tc_key_active->tc_alg_tx;

	seq -= dir_in ? tc->tc_isn_peer : tc->tc_isn;
	ack -= dir_in ? tc->tc_isn : tc->tc_isn_peer;

	assert(mac);
	p2 = (uint32_t*) mac;

	/* M struct */
	m.mm_magic = htons(MACM_MAGIC);
	m.mm_len   = htons(ntohs(ip->ip_len) - (ip->ip_hl << 2));
	m.mm_off   = tcp->th_off;
	m.mm_flags = tcp->th_flags;
	m.mm_urg   = tcp->th_urp;
	m.mm_seqhi = htonl(seq >> 32);
	m.mm_seq   = htonl(seq & 0xFFFFFFFF);

	iov[num].iov_base   = &m;
	iov[num++].iov_len  = sizeof(m);

	/* options */
	compute_mac_opts(tc, tcp, iov, &num);
	assert(num < sizeof(iov) / sizeof(*iov));

	/* IV */
	if (tc->tc_mac_ivlen) {
		if (!iv) {
			assert(!"implement");
//			crypto_next_iv(tc, out, &tc->tc_mac_ivlen);
			iv = out;
			out = (void*) ((unsigned long) out + tc->tc_mac_ivlen);
		}

		iov[num].iov_base  = iv;
		iov[num++].iov_len = tc->tc_mac_ivlen;
	} else
		assert(!iv);

	/* payload */
	assert(num < sizeof(iov) / sizeof(*iov));
	iov[num].iov_len = tcp_data_len(ip, tcp);
	if (iov[num].iov_len)
		iov[num++].iov_base = tcp_data(tcp);

	maclen = tc->tc_mac_size;

	profile_add(2, "compute_mac pre M");
	crypt_mac(cs->cs_mac, iov, num, out, &maclen);
	profile_add(2, "compute_mac MACed M");

	/* A struct */
	a.ma_ackhi = htonl(ack >> 32);
	a.ma_ack   = htonl(ack & 0xFFFFFFFF);

	memset(mac, 0, maca_len);

	iov[0].iov_base = &a;
	iov[0].iov_len  = sizeof(a);

	crypt_mac(cs->cs_ack_mac, iov, 1, mac, &maca_len);
	assert(maca_len == tc->tc_mac_size);
	profile_add(2, "compute_mac MACed A");

	/* XOR the two */
	p1     = (uint32_t*) out;
	maclen = tc->tc_mac_size;

	while (maclen >= 4) {
		*p1++  ^= *p2++;
		maclen -= 4;
	}

	if (maclen == 0)
		return;

	outp = (uint8_t*) p1;
	mac  = (uint8_t*) p2;

	while (maclen--) 
		*outp++ ^= *mac++;
}

static void *get_iv(struct tc *tc, struct ip *ip, struct tcphdr *tcp)
{
	static uint64_t seq;
	void *iv = NULL;

	switch (tc->tc_sym_ivmode) {
	case IVMODE_CRYPT:
		assert(!"codeme");
		break;

	case IVMODE_SEQ:
		seq   = htonl(tc->tc_seq >> 32);
		seq <<= 32;
		seq  |= tcp->th_seq;
		iv = &seq;
		break;

	case IVMODE_NONE:
		break;

	default:
		assert(!"sdfsfd");
		break;
	}

	return iv;
}

static void encrypt(struct tc *tc, struct ip *ip, struct tcphdr *tcp)
{
	uint8_t *data = tcp_data(tcp);
	int dlen = tcp_data_len(ip, tcp);
	void *iv = NULL;
	struct crypt *c = tc->tc_key_active->tc_alg_tx->cs_cipher;

	iv = get_iv(tc, ip, tcp);

	if (dlen)
		crypt_encrypt(c, iv, data, dlen);
}

static int add_mac(struct tc *tc, struct ip *ip, struct tcphdr *tcp)
{
	struct tcpopt_mac *tom;
	int len = sizeof(*tom) + tc->tc_mac_size + tc->tc_mac_ivlen;

	/* add MAC option */
	tom = tcp_opts_alloc(tc, ip, tcp, len);
	if (!tom)
		return -1;

	tom->tom_kind = TCPOPT_MAC;
	tom->tom_len  = len;

	compute_mac(tc, ip, tcp, NULL, tom->tom_data, 0);

	return 0;
}

static int fixup_seq(struct tc *tc, struct tcphdr *tcp, int in)
{
	if (!tc->tc_seq_off)
		return 0;

	if (in) {
		tcp->th_ack = htonl(ntohl(tcp->th_ack) - tc->tc_seq_off);
		tcp->th_seq = htonl(ntohl(tcp->th_seq) - tc->tc_rseq_off);
	} else {
		tcp->th_seq = htonl(ntohl(tcp->th_seq) + tc->tc_seq_off);
		tcp->th_ack = htonl(ntohl(tcp->th_ack) + tc->tc_rseq_off);
	}

	return 1;
}

static int connected(struct tc *tc)
{
	return tc->tc_state == STATE_ENCRYPTING 
	       || tc->tc_state == STATE_REKEY_SENT
	       || tc->tc_state == STATE_REKEY_RCVD;
}

static int do_compress(struct tc *tc, int tcpop, int subop, int len, void *data)
{
	uint8_t *p = data;

	len += 2;
	p   -= 2;

	memcpy(&tc->tc_opt[tc->tc_optlen], p, len);

	tc->tc_optlen += len;
	assert(tc->tc_optlen <= sizeof(tc->tc_opt));

	return 0;
}

static void compress_options(struct tc *tc, struct ip *ip, struct tcphdr *tcp)
{
	int len;
	int max = 60;
	void *p;

	memset(tc->tc_opt, TCPOPT_EOL, sizeof(tc->tc_opt));
	tc->tc_optlen = 0;
	foreach_opt(tc, tcp, do_compress);

	len = max - (tcp->th_off << 2);
	assert(len >= 0);
	if (len) {
		p = tcp_opts_alloc(tc, ip, tcp, len);
		assert(p);
	}

	memcpy(tcp + 1, tc->tc_opt, sizeof(tc->tc_opt));
}

static void do_rekey(struct tc *tc)
{
	assert(!tc->tc_key_next.tc_alg_rx);

	tc->tc_keygen++;
	
	assert(!"implement");
//	crypto_mac_set_key(tc, tc->tc_mk.s_data, tc->tc_mk.s_len);

	compute_mk(tc, &tc->tc_mk);
	compute_keys(tc, &tc->tc_key_next);

	xprintf(XP_DEFAULT, "Rekeying, keygen %d [%p]\n", tc->tc_keygen, tc);
}

static int rekey_complete(struct tc *tc)
{
	if (tc->tc_keygenrx != tc->tc_keygen) {
		assert((uint8_t)(tc->tc_keygenrx + 1) == tc->tc_keygen);

		return 0;
	}

	if (tc->tc_keygentx != tc->tc_keygen) {
		assert((uint8_t)(tc->tc_keygentx + 1) == tc->tc_keygen);

		return 0;
	}

	assert(tc->tc_key_current.tc_alg_tx);
	assert(tc->tc_key_next.tc_alg_tx);

	crypto_free_keyset(tc, &tc->tc_key_current);
	memcpy(&tc->tc_key_current, &tc->tc_key_next,
	       sizeof(tc->tc_key_current));
	memset(&tc->tc_key_next, 0, sizeof(tc->tc_key_next));

	tc->tc_state = STATE_ENCRYPTING;

	xprintf(XP_DEBUG, "Rekey complete %d [%p]\n", tc->tc_keygen, tc);

	return 1;
}

static void rekey_output(struct tc *tc, struct ip *ip, struct tcphdr *tcp)
{
	int rk = 0;
	struct tco_rekeystream *tr;

	/* got all old packets from the other dude, lets rekey our side */
	if (tc->tc_state == STATE_REKEY_RCVD
	    && ntohl(tcp->th_ack) >= tc->tc_rekey_seq) {
	    	xprintf(XP_DEBUG, "RX rekey done %d %p\n", tc->tc_keygen, tc);
		tc->tc_keygenrx++;
		assert(tc->tc_keygenrx == tc->tc_keygen);
		if (rekey_complete(tc))
			return;

		tc->tc_state	  = STATE_REKEY_SENT;
		tc->tc_rekey_seq  = ntohl(tcp->th_seq);
		tc->tc_sent_bytes = 0;
	}

	/* half way through rekey - figure out current key */
	if (tc->tc_keygentx != tc->tc_keygenrx
	    && tc->tc_keygentx == tc->tc_keygen)
		tc->tc_key_active = &tc->tc_key_next;

	/* XXX check if proto supports rekey */

	if (!rk)
		return;

	/* initiate rekey */
	if (tc->tc_sent_bytes > rk && tc->tc_state != STATE_REKEY_RCVD) {
		do_rekey(tc);

		tc->tc_sent_bytes = 0;
		tc->tc_rekey_seq  = ntohl(tcp->th_seq);
		tc->tc_state      = STATE_REKEY_SENT;
	}

	if (tc->tc_state != STATE_REKEY_SENT)
		return;

	/* old shit - send with old key */
	if (ntohl(tcp->th_seq) < tc->tc_rekey_seq) {
		assert(ntohl(tcp->th_seq) + tcp_data_len(ip, tcp)
		       <= tc->tc_rekey_seq);

		return;
	}

	/* send rekeys */
	compress_options(tc, ip, tcp);

	tr = (struct tco_rekeystream*) subopt_alloc(tc, ip, tcp, sizeof(*tr));
	assert(tr);

	tr->tr_op  	  = TCOP_REKEY;
	tr->tr_key	  = tc->tc_keygen;
	tr->tr_seq	  = htonl(tc->tc_rekey_seq);
	tc->tc_key_active = &tc->tc_key_next;
}

static int do_output_encrypting(struct tc *tc, struct ip *ip,
				struct tcphdr *tcp)
{
	if (tcp->th_flags == (TH_SYN | TH_ACK)) {
		/* XXX I assume we just sent ACK to dude but he didn't get it
		 * yet 
		 */
		return DIVERT_DROP;
	}

	assert(!(tcp->th_flags & TH_SYN));

	fixup_seq(tc, tcp, 0);

	tc->tc_key_active = &tc->tc_key_current;
	rekey_output(tc, ip, tcp);

	profile_add(1, "do_output pre sym encrypt");
	encrypt(tc, ip, tcp);
	profile_add(1, "do_output post sym encrypt");

	if (add_mac(tc, ip, tcp)) { 
		/* hopefully pmtu disc works */
		xprintf(XP_ALWAYS, "No space for MAC - dropping\n");

		return DIVERT_DROP;
	}
	profile_add(1, "post add mac");

	/* XXX retransmissions.  approx. */
	tc->tc_sent_bytes += tcp_data_len(ip, tcp);

	return DIVERT_MODIFY;
}

static int sack_disable(struct tc *tc, struct tcphdr *tcp)
{
	struct {
		uint8_t	kind;
		uint8_t len;
	} *sack;

	sack = find_opt(tcp, TCPOPT_SACK_PERMITTED);
	if (!sack)
		return DIVERT_ACCEPT;

	memset(sack, TCPOPT_NOP, sizeof(*sack));

	return DIVERT_MODIFY;
}

static int do_tcp_output(struct tc *tc, struct ip *ip, struct tcphdr *tcp)
{
	int rc = DIVERT_ACCEPT;

	if (tcp->th_flags & TH_SYN)
		tc->tc_isn = ntohl(tcp->th_seq);

	if (tcp->th_flags == TH_SYN) {
		if (tc->tc_tcp_state == TCPSTATE_LASTACK) {
			tc_finish(tc);
			tc_reset(tc);
		}

		rc = sack_disable(tc, tcp);
	}

	if (tcp->th_flags & TH_FIN) {
		switch (tc->tc_tcp_state) {
		case TCPSTATE_FIN1_RCVD:
			tc->tc_tcp_state = TCPSTATE_FIN2_SENT;
			break;

		case TCPSTATE_FIN2_SENT:
			break;

		default:
			tc->tc_tcp_state = TCPSTATE_FIN1_SENT;
		}

		return rc;
	}

	if (tcp->th_flags & TH_RST) {
		tc->tc_tcp_state = TCPSTATE_DEAD;
		return rc;
	}

	if (!(tcp->th_flags & TH_ACK))
		return rc;

	switch (tc->tc_tcp_state) {
	case TCPSTATE_FIN2_RCVD:
		tc->tc_tcp_state = TCPSTATE_LASTACK;
		if (!tc->tc_last_ack_timer)
			tc->tc_last_ack_timer = add_timer(10 * 1000 * 1000,
							  last_ack, tc);
		else
			xprintf(XP_DEFAULT, "uarning\n");
		break;
	}

	return rc;
}

static int do_output_nextk1_rcvd(struct tc *tc, struct ip *ip,
				 struct tcphdr *tcp)
{
	struct tc_subopt *tcs;

	if (!tc->tc_sess)
		return do_output_hello_rcvd(tc, ip, tcp);

	tcs = subopt_alloc(tc, ip, tcp, 1);
	if (!tcs) {
		xprintf(XP_ALWAYS, "No space for NEXTK2\n");
		tc->tc_state = STATE_DISABLED;
		return DIVERT_ACCEPT;
	}

	tcs->tcs_op = (tc->tc_app_support & 1) ? TCOP_NEXTK2_SUPPORT
					       : TCOP_NEXTK2;

	tc->tc_state = STATE_NEXTK2_SENT;

	return DIVERT_MODIFY;
}

static int do_output(struct tc *tc, struct ip *ip, struct tcphdr *tcp)
{
	int rc = DIVERT_ACCEPT;
	int tcp_rc;

	tcp_rc = do_tcp_output(tc, ip, tcp);	

	/* an RST half way through the handshake */
	if (tc->tc_tcp_state == TCPSTATE_DEAD 
	    && !connected(tc))
		return tcp_rc;

	switch (tc->tc_state) {
	case STATE_HELLO_SENT:
	case STATE_NEXTK1_SENT:
		/* syn re-TX.  fallthrough */
		assert(tcp->th_flags & TH_SYN);
	case STATE_CLOSED:
		rc = do_output_closed(tc, ip, tcp);
		break;

	case STATE_PKCONF_SENT:
		/* reTX of syn ack, or ACK (role switch) */
	case STATE_HELLO_RCVD:
		rc = do_output_hello_rcvd(tc, ip, tcp);
		break;

	case STATE_NEXTK2_SENT:
		/* syn ack rtx */
		assert(tc->tc_sess);
		assert(tcp->th_flags == (TH_SYN | TH_ACK));
	case STATE_NEXTK1_RCVD:
		rc = do_output_nextk1_rcvd(tc, ip, tcp);
		break;

	case STATE_PKCONF_RCVD:
		rc = do_output_pkconf_rcvd(tc, ip, tcp, 0);
		break;

	case STATE_INIT1_RCVD:
		rc = do_output_init1_rcvd(tc, ip, tcp);
		break;

	case STATE_INIT1_SENT:
		if (!find_subopt(tcp, TCOP_INIT1))
			rc = do_output_pkconf_rcvd(tc, ip, tcp, 1);
		break;

	case STATE_INIT2_SENT:
		rc = do_output_init2_sent(tc, ip, tcp);
		break;

	case STATE_ENCRYPTING:
	case STATE_REKEY_SENT:
	case STATE_REKEY_RCVD:
		rc = do_output_encrypting(tc, ip, tcp);
		break;

	case STATE_DISABLED:
		rc = DIVERT_ACCEPT;
		break;

	default:
		xprintf(XP_ALWAYS, "Unknown state %d\n", tc->tc_state);
		abort();
	}

	if (rc == DIVERT_ACCEPT)
		return tcp_rc;

	return rc;
}

static struct tc_sess *session_find(struct tc *tc, struct tc_sid *sid)
{
	struct tc_sess *s = _sessions.ts_next;

	while (s) {
		if (tc->tc_dir == s->ts_dir 
		    && memcmp(sid, s->ts_sid.s_data, sizeof(*sid)) == 0)
			return s;

		s = s->ts_next;
	}

	return NULL;
}

static int do_clamp_mss(struct tc *tc, uint16_t *mss)
{
	int len;

	len = ntohs(*mss) - tc->tc_mss_clamp;
	assert(len > 0);

	*mss = htons(len);

	xprintf(XP_NOISY, "Clamping MSS to %d\n", len);

	return DIVERT_MODIFY;
}

static int opt_input_closed(struct tc *tc, int tcpop, int subop, int len,
			    void *data)
{
	uint8_t *p;

	profile_add(2, "opt_input_closed in");

	switch (subop) {
	case TCOP_HELLO_SUPPORT:
		tc->tc_app_support |= 2;
		/* fallthrough */
	case TCOP_HELLO:
		tc->tc_state = STATE_HELLO_RCVD;
		break;

	case TCOP_NEXTK1_SUPPORT:
		tc->tc_app_support |= 2;
		/* fallthrough */
	case TCOP_NEXTK1:
		tc->tc_state = STATE_NEXTK1_RCVD;
		tc->tc_sess  = session_find(tc, data);
		profile_add(2, "found session");
		break;
	}

	switch (tcpop) {
	case TCPOPT_SACK_PERMITTED:
		p     = data;
		p[-2] = TCPOPT_NOP;
		p[-1] = TCPOPT_NOP;
		tc->tc_verdict = DIVERT_MODIFY;
		break;

	case TCPOPT_MAXSEG:
		if (do_clamp_mss(tc, data) == DIVERT_MODIFY)
			tc->tc_verdict = DIVERT_MODIFY;

		tc->tc_mss_clamp = -1;
		break;
	}

	profile_add(2, "opt_input_closed out");

	return 0;
}

static int do_input_closed(struct tc *tc, struct ip *ip, struct tcphdr *tcp)
{
	tc->tc_dir = DIR_IN;

	if (tcp->th_flags != TH_SYN)
		return DIVERT_ACCEPT;

	tc->tc_verdict = DIVERT_ACCEPT;
	tc->tc_state   = STATE_DISABLED;

	profile_add(1, "do_input_closed pre option parse");
	foreach_opt(tc, tcp, opt_input_closed);
	profile_add(1, "do_input_closed options parsed");

	return tc->tc_verdict;
}

static int negotiate_cipher(struct tc *tc, struct tc_cipher_spec *a, int an)
{
	struct tc_cipher_spec *b = tc->tc_ciphers_pkey;
	int bn = tc->tc_ciphers_pkey_len / sizeof(*tc->tc_ciphers_pkey);
	struct tc_cipher_spec *out = &tc->tc_cipher_pkey;

	tc->tc_pub_cipher_list_len = an * sizeof(*a);
	memcpy(tc->tc_pub_cipher_list, a, tc->tc_pub_cipher_list_len);

	while (an--) {
		while (bn--) {
			if (a->tcs_algo == b->tcs_algo) {
				out->tcs_algo    = a->tcs_algo;
				return 1;
			}

			b++;
		}

		a++;
	}

	return 0;
}

static void make_reply(void *buf, struct ip *ip, struct tcphdr *tcp)
{
	struct ip *ip2 = buf;
	struct tcphdr *tcp2;
	int dlen = ntohs(ip->ip_len) - (ip->ip_hl << 2) - (tcp->th_off << 2);

	ip2->ip_v   = 4;
	ip2->ip_hl  = sizeof(*ip2) >> 2;
	ip2->ip_tos = 0;
	ip2->ip_len = htons(sizeof(*ip2) + sizeof(*tcp2));
	ip2->ip_id  = 0;
	ip2->ip_off = 0;
	ip2->ip_ttl = 128;
	ip2->ip_p   = IPPROTO_TCP;
	ip2->ip_sum = 0;
	ip2->ip_src = ip->ip_dst;
	ip2->ip_dst = ip->ip_src;

	tcp2 = (struct tcphdr*) (ip2 + 1);
	tcp2->th_sport = tcp->th_dport;
	tcp2->th_dport = tcp->th_sport;
	tcp2->th_seq   = tcp->th_ack;
	tcp2->th_ack   = htonl(ntohl(tcp->th_seq) + dlen);
	tcp2->th_x2    = 0;
	tcp2->th_off   = sizeof(*tcp2) >> 2;
	tcp2->th_flags = TH_ACK;
	tcp2->th_win   = tcp->th_win;
	tcp2->th_sum   = 0;
	tcp2->th_urp   = 0;
}

static void *alloc_retransmit(struct tc *tc)
{
	struct retransmit *r;
	int len;

	assert(!tc->tc_retransmit);

	len = sizeof(*r) + tc->tc_mtu;
	r = xmalloc(len);
	memset(r, 0, len);

	r->r_timer = add_timer(tc->tc_rto, retransmit, tc);

	tc->tc_retransmit = r;

	return r->r_packet;
}

static void init_pkey(struct tc *tc)
{
	struct ciphers *c = _ciphers_pkey.c_next;
	struct tc_cipher_spec *s;

	assert(tc->tc_cipher_pkey.tcs_algo);

	while (c) {
		s = (struct tc_cipher_spec*) c->c_spec;

		if (s->tcs_algo == tc->tc_cipher_pkey.tcs_algo) {
			tc->tc_crypt_pub = crypt_new(c->c_cipher->c_ctr);
			return;
		}

		c = c->c_next;
	}

	assert(!"Can't init cipher");
}

static int do_input_hello_sent(struct tc *tc, struct ip *ip, struct tcphdr *tcp)
{
	struct tc_subopt *tcs;
	struct tc_cipher_spec *cipher;

	tcs = find_subopt(tcp, TCOP_HELLO);
	if (tcs) {
		if (tc->tc_cmode == CMODE_ALWAYS) {
			tc->tc_state = STATE_DISABLED;

			return DIVERT_ACCEPT;
		}

		tc->tc_state = STATE_HELLO_RCVD;

		return DIVERT_ACCEPT;
	}

	if ((tcs = find_subopt(tcp, TCOP_PKCONF_SUPPORT)))
		tc->tc_app_support |= 2;
	else {
		tcs = find_subopt(tcp, TCOP_PKCONF);
		if (!tcs) {
			tc->tc_state = STATE_DISABLED;

			return DIVERT_ACCEPT;
		}
	}

	assert((tcs->tcs_len - 2) % sizeof(*cipher) == 0);
	cipher = (struct tc_cipher_spec*) tcs->tcs_data;

	if (!negotiate_cipher(tc, cipher,
			      (tcs->tcs_len - 2) / sizeof(*cipher))) {
		xprintf(XP_ALWAYS, "No cipher\n");
		tc->tc_state = STATE_DISABLED;

		return DIVERT_ACCEPT;
	}

	init_pkey(tc);

	tc->tc_state = STATE_PKCONF_RCVD;

	/* we switched roles, we gotta inject the INIT1 */
	if (tcp->th_flags != (TH_SYN | TH_ACK)) {
		void *buf;
		struct ip *ip2;
		struct tcphdr *tcp2;

		buf = alloc_retransmit(tc);
		make_reply(buf, ip, tcp);

		ip2 = (struct ip*) buf;
		tcp2 = (struct tcphdr*) (ip2 + 1);
		do_output_pkconf_rcvd(tc, ip2, tcp2, 0);

		checksum_packet(tc, ip2, tcp2);
		divert_inject(ip2, ntohs(ip2->ip_len));

		tc->tc_state = STATE_INIT1_SENT;
	}

	return DIVERT_ACCEPT;
}

static void do_neg_sym(struct tc *tc, struct ciphers *c, struct tc_scipher *a)
{
	struct tc_scipher *b;

	c = c->c_next;

	while (c) {
		b = (struct tc_scipher*) c->c_spec;

		if (b->sc_algo == a->sc_algo) {
			tc->tc_crypt_sym = crypt_new(c->c_cipher->c_ctr);
			tc->tc_cipher_sym.sc_algo = a->sc_algo;
			break;
		}

		c = c->c_next;
	}
}

static int negotiate_sym_cipher(struct tc *tc, struct tc_scipher *a, int alen)
{
	int rc = 0;

	tc->tc_sym_cipher_list_len = alen * sizeof(*a);
	memcpy(tc->tc_sym_cipher_list, a, tc->tc_sym_cipher_list_len);

	while (alen--) {
		do_neg_sym(tc, &_ciphers_sym, a);

		if (tc->tc_crypt_sym) {
			rc = 1;
			break;
		}

		a++;
	}

	return rc;
}

static int select_pkey(struct tc *tc, struct tc_cipher_spec *pkey)
{
	struct tc_cipher_spec *spec;
	struct ciphers *c = _ciphers_pkey.c_next;
	int i;

	/* check whether we know about the cipher */
	while (c) {
		spec = (struct tc_cipher_spec*) c->c_spec;

		if (spec->tcs_algo == pkey->tcs_algo) {
			tc->tc_crypt_pub = crypt_new(c->c_cipher->c_ctr);
			break;
		}

		c = c->c_next;
	}
	if (!c)
		return 0;

	/* check whether we were willing to accept this cipher */
	for (i = 0; i < tc->tc_ciphers_pkey_len / sizeof(*tc->tc_ciphers_pkey);
	     i++) {
		spec = &tc->tc_ciphers_pkey[i];

		if (spec->tcs_algo == pkey->tcs_algo) {
			tc->tc_cipher_pkey = *pkey;
			return 1;
		}
	}

	/* XXX cleanup */

	return 0;
}

static void compute_ss(struct tc *tc)
{
	struct iovec iov[5];
	unsigned char num;

	profile_add(1, "compute ss in");

	assert((tc->tc_pub_cipher_list_len % 3) == 0);

	num = tc->tc_pub_cipher_list_len / 3;

	iov[0].iov_base = &num;
	iov[0].iov_len  = 1;

	iov[1].iov_base = tc->tc_pub_cipher_list;
	iov[1].iov_len  = tc->tc_pub_cipher_list_len;

	iov[2].iov_base = tc->tc_init1;
	iov[2].iov_len  = tc->tc_init1_len;

	iov[3].iov_base = tc->tc_init2;
	iov[3].iov_len  = tc->tc_init2_len;

	iov[4].iov_base = tc->tc_pms;
	iov[4].iov_len  = tc->tc_pms_len;

	crypt_set_key(tc->tc_crypt_pub->cp_hkdf,
		      tc->tc_nonce, tc->tc_nonce_len);

	profile_add(1, "compute ss mac set key");

	tc->tc_ss.s_len = sizeof(tc->tc_ss.s_data);

	crypt_extract(tc->tc_crypt_pub->cp_hkdf, iov,
		      sizeof(iov) / sizeof(*iov), tc->tc_ss.s_data,
	              &tc->tc_ss.s_len);

	assert(tc->tc_ss.s_len <= sizeof(tc->tc_ss.s_data));

	profile_add(1, "compute ss did MAC");
}

static int process_init1(struct tc *tc, struct ip *ip, struct tcphdr *tcp,
			 uint8_t *kxs, int kxs_len)
{
	struct tc_subopt *tcs;
	struct tc_init1 *i1;
	int dlen;
	uint8_t *nonce;
	int nonce_len;
	int num_ciphers;
	void *key;
	int klen;
	int cl;
	void *pms;
	int pmsl;

	tcs = find_subopt(tcp, TCOP_INIT1);
	if (!tcs)
		return bad_packet("can't find init1");

	dlen = tcp_data_len(ip, tcp);
	i1   = tcp_data(tcp);

	if (dlen < sizeof(*i1))
		return bad_packet("short init1");

	if (ntohl(i1->i1_magic) != TC_INIT1)
		return bad_packet("bad magic");

	if (dlen != ntohl(i1->i1_len))
		return bad_packet("bad init1 lenn");

	if (!select_pkey(tc, &i1->i1_pub))
		return bad_packet("init1: bad public key");

	nonce_len   = tc->tc_crypt_pub->cp_n_c;
	num_ciphers = ntohs(i1->i1_num_ciphers);

	klen = dlen 
	       - sizeof(*i1)
	       - num_ciphers * sizeof(*i1->i1_ciphers)
	       - nonce_len;

	if (klen <= 0)
	    	return bad_packet("bad init1 len");

	if (tc->tc_crypt_pub->cp_max_key && klen > tc->tc_crypt_pub->cp_max_key)
		return bad_packet("init1: key length disagreement");

	if (tc->tc_crypt_pub->cp_min_key && klen < tc->tc_crypt_pub->cp_min_key)
		return bad_packet("init2: key length too short");

	if (!negotiate_sym_cipher(tc, i1->i1_ciphers, num_ciphers))
		return bad_packet("init1: can't negotiate");

	nonce = (uint8_t*) &i1->i1_ciphers[num_ciphers];
	key   = nonce + nonce_len;

	profile_add(1, "pre pkey set key");

	/* figure out key len */
	if (crypt_set_key(tc->tc_crypt_pub->cp_pub, key, klen) == -1)
		return 0;

	profile_add(1, "pkey set key");

	generate_nonce(tc, tc->tc_crypt_pub->cp_n_s);

	/* XXX fix crypto api to have from to args */
	memcpy(kxs, tc->tc_nonce, tc->tc_nonce_len);
	cl = crypt_encrypt(tc->tc_crypt_pub->cp_pub,
			   NULL, kxs, tc->tc_nonce_len);

	assert(cl <= kxs_len); /* XXX too late to check */

	pms  = tc->tc_nonce;
	pmsl = tc->tc_nonce_len;

	if (tc->tc_crypt_pub->cp_key_agreement) {
		pms = alloca(1024);
		pmsl = crypt_compute_key(tc->tc_crypt_pub->cp_pub, pms);

		assert(pmsl < 1024); /* XXX */
	}

	assert(dlen <= sizeof(tc->tc_init1));

	memcpy(tc->tc_init1, i1, dlen);
	tc->tc_init1_len = dlen;

	assert(pmsl <= sizeof(tc->tc_pms));
	memcpy(tc->tc_pms, pms, pmsl);
	tc->tc_pms_len = pmsl;

	assert(nonce_len <= sizeof(tc->tc_nonce));
	memcpy(tc->tc_nonce, nonce, nonce_len);
	tc->tc_nonce_len = nonce_len;

	tc->tc_state = STATE_INIT1_RCVD;

	return 1;
}

static int swallow_data(struct ip *ip, struct tcphdr *tcp)
{
	int len, dlen;

	len  = (ip->ip_hl << 2) + (tcp->th_off << 2);
	dlen = ntohs(ip->ip_len) - len;
	set_ip_len(ip, len);

	return dlen;
}

static int do_input_pkconf_sent(struct tc *tc, struct ip *ip,
				struct tcphdr *tcp)
{
	struct tc_subopt *tcs;
	int len, dlen;
	void *buf;
	struct ip *ip2;
	struct tcphdr *tcp2;
	struct tc_init2 *i2;
	uint8_t kxs[1024];
	int cipherlen;

	/* syn retransmission */
	if (tcp->th_flags == TH_SYN)
		return do_input_closed(tc, ip, tcp);

	if (!process_init1(tc, ip, tcp, kxs, sizeof(kxs))) {
		tc->tc_state = STATE_DISABLED;

		return DIVERT_ACCEPT;
	}

	cipherlen = tc->tc_crypt_pub->cp_cipher_len;

	/* send init2 */
	buf = alloc_retransmit(tc);
	make_reply(buf, ip, tcp);
	ip2 = (struct ip*) buf;
	tcp2 = (struct tcphdr*) (ip2 + 1);

	tcs = subopt_alloc(tc, ip2, tcp2, 1);
	assert(tcs);
	tcs->tcs_op = TCOP_INIT2;

	len = sizeof(*i2) + cipherlen;
	i2  = data_alloc(tc, ip2, tcp2, len, 0);

	i2->i2_magic   = htonl(TC_INIT2);
	i2->i2_len     = htonl(len);
	i2->i2_scipher = tc->tc_cipher_sym;

	memcpy(i2->i2_data, kxs, cipherlen);

	if (_conf.cf_rsa_client_hack)
		memcpy(i2->i2_data, tc->tc_nonce, tc->tc_nonce_len);

	assert(len <= sizeof(tc->tc_init2));

	memcpy(tc->tc_init2, i2, len);
	tc->tc_init2_len = len;

	checksum_packet(tc, ip2, tcp2);
	divert_inject(ip2, ntohs(ip2->ip_len));

	tc->tc_state = STATE_INIT2_SENT;

	/* swallow data - ewwww */
	dlen = swallow_data(ip, tcp);

	tc->tc_rseq_off = dlen;
	tc->tc_role     = ROLE_SERVER;

	compute_ss(tc);

#if 1
	return DIVERT_MODIFY;
#else
	/* we let the ACK of INIT2 through to complete the handshake */
	return DIVERT_DROP;
#endif
}

static int select_sym(struct tc *tc, struct tc_scipher *s)
{
	struct tc_scipher *me = tc->tc_ciphers_sym;
	int len = tc->tc_ciphers_sym_len;
	int sym = 0;
	struct ciphers *c;

	/* check if we approve it */
	while (len) {
		if (memcmp(me, s, sizeof(*s)) == 0) {
			sym = 1;
			break;
		}

		me++;
		len -= sizeof(*me);
		assert(len >= 0);
	}

	if (!sym)
		return 0;

	/* select ciphers */
	c = _ciphers_sym.c_next;
	while (c) {
		me = (struct tc_scipher*) c->c_spec;

		if (me->sc_algo == s->sc_algo) {
			tc->tc_crypt_sym = crypt_new(c->c_cipher->c_ctr);
			break;
		}

		c = c->c_next;
	}

	assert(tc->tc_crypt_sym);

	memcpy(&tc->tc_cipher_sym, s, sizeof(*s));

	return 1;
}

static int process_init2(struct tc *tc, struct ip *ip, struct tcphdr *tcp)
{
	struct tc_subopt *tcs;
	struct tc_init2 *i2;
	int len;
	int nlen;
	void *nonce;
	void *key;
	int klen;
	uint8_t kxs[1024];
	int kxs_len;

	tcs = find_subopt(tcp, TCOP_INIT2);
	if (!tcs)
		return bad_packet("init2: can't find opt");

	i2  = tcp_data(tcp);
	len = tcp_data_len(ip, tcp);

	if (len < sizeof(*i2))
		return bad_packet("init2: short packet");

	if (len != ntohl(i2->i2_len))
		return bad_packet("init2: bad lenn");

	nlen = len - sizeof(*i2);
	if (nlen <= 0)
		return bad_packet("init2: bad len");

	if (ntohl(i2->i2_magic) != TC_INIT2)
		return bad_packet("init2: bad magic");

	if (!select_sym(tc, &i2->i2_scipher))
		return bad_packet("init2: select_sym()");

	if (nlen > sizeof(kxs))
		return bad_packet("init2: big nonce kxs");

	assert(len <= sizeof(tc->tc_init2));

	memcpy(tc->tc_init2, i2, len);
	tc->tc_init2_len = len;

	/* XXX fix crypto api to use to / from */
	kxs_len = nlen;
	memcpy(kxs, i2->i2_data, nlen);

	nonce = i2->i2_data;
	nlen  = crypt_decrypt(tc->tc_crypt_pub->cp_pub, NULL, nonce, nlen);

	klen = crypt_get_key(tc->tc_crypt_pub->cp_pub, &key);

	assert(nlen <= sizeof(tc->tc_pms));
	memcpy(tc->tc_pms, nonce, nlen);
	tc->tc_pms_len = nlen;

	compute_ss(tc);

	return 1;
}

static void ack(struct tc *tc, struct ip *ip, struct tcphdr *tcp)
{
	char buf[2048];
	struct ip *ip2;
	struct tcphdr *tcp2;

	ip2  = (struct ip*) buf;
	tcp2 = (struct tcphdr*) (ip2 + 1);

	make_reply(buf, ip, tcp);

	/* XXX */
	tcp2->th_seq = htonl(ntohl(tcp2->th_seq) - tc->tc_seq_off);
	tcp2->th_ack = htonl(ntohl(tcp2->th_ack) - tc->tc_rseq_off);

	checksum_packet(tc, ip2, tcp2);
	divert_inject(ip2, ntohs(ip2->ip_len));
}

static int do_input_init1_sent(struct tc *tc, struct ip *ip, struct tcphdr *tcp)
{
	int dlen;

	/* XXX syn ack re-TX - check pkconf */
	if (tcp->th_flags == (TH_SYN | TH_ACK))
		return DIVERT_ACCEPT;

	if (!process_init2(tc, ip, tcp)) {
		tc->tc_state = STATE_DISABLED;
		return DIVERT_ACCEPT;
	}

	dlen = ntohs(ip->ip_len) - (ip->ip_hl << 2) - (tcp->th_off << 2);
	tc->tc_rseq_off = dlen;

	ack(tc, ip, tcp);

	enable_encryption(tc);

	/* we let this packet through to reopen window */
	swallow_data(ip, tcp);
	tcp->th_ack = htonl(ntohl(tcp->th_ack) - tc->tc_seq_off);

	return DIVERT_MODIFY;
}

static int check_mac(struct tc *tc, struct ip *ip, struct tcphdr *tcp)
{
	struct tcpopt_mac *tom;
	void *mac = alloca(tc->tc_mac_size);

	assert(mac);

	tom = find_opt(tcp, TCPOPT_MAC);
	if (!tom) {
		if (!tc->tc_mac_rst && (tcp->th_flags & TH_RST))
			return 0;

		return -1;
	}

	compute_mac(tc, ip, tcp, tc->tc_mac_ivlen ? tom->tom_data : NULL,
		    mac, 1);

	if (memcmp(&tom->tom_data[tc->tc_mac_ivlen], mac, tc->tc_mac_size) != 0)
		return -2;

	return 0;
}

static int decrypt(struct tc *tc, struct ip *ip, struct tcphdr *tcp)
{
	uint8_t *data = tcp_data(tcp);
	int dlen = tcp_data_len(ip, tcp);
	void *iv = NULL;
	struct crypt *c = tc->tc_key_active->tc_alg_rx->cs_cipher;

	iv = get_iv(tc, ip, tcp);

	if (dlen)
		crypt_decrypt(c, iv, data, dlen);

	return dlen;
}

static struct tco_rekeystream *rekey_input(struct tc *tc, struct ip *ip,
					   struct tcphdr *tcp)
{
	struct tco_rekeystream *tr;

	/* half way through rekey - figure out current key */
	if (tc->tc_keygentx != tc->tc_keygenrx
	    && tc->tc_keygenrx == tc->tc_keygen)
		tc->tc_key_active = &tc->tc_key_next;

	tr = (struct tco_rekeystream *) find_subopt(tcp, TCOP_REKEY);
	if (!tr)
		return NULL;

	if (tr->tr_key == (uint8_t) ((tc->tc_keygen + 1))) {
		do_rekey(tc);
		tc->tc_state     = STATE_REKEY_RCVD;
		tc->tc_rekey_seq = ntohl(tr->tr_seq);

		if (tc->tc_rekey_seq != ntohl(tcp->th_seq)) {
			assert(!"implement");
//			unsigned char dummy[] = "a";
//			void *iv = &tr->tr_seq;

			/* XXX assuming stream, and seq as IV */
//			crypto_decrypt(tc, iv, dummy, sizeof(dummy));
		}

		/* XXX assert that MAC checks out, else revert */
	}

	assert(tr->tr_key == tc->tc_keygen);

	if (tr->tr_key == tc->tc_keygen) {
		/* old news - we've finished rekeying */
		if (tc->tc_state == STATE_ENCRYPTING) {
			assert(tc->tc_keygen == tc->tc_keygenrx
			       && tc->tc_keygen == tc->tc_keygentx);
			return NULL;
		}

		tc->tc_key_active = &tc->tc_key_next;
	}

	return tr;
}

static void rekey_input_post(struct tc *tc, struct ip *ip, struct tcphdr *tcp,
			     struct tco_rekeystream *tr)
{
	/* XXX seqno wrap */
	if (tc->tc_state == STATE_REKEY_SENT
	    && ntohl(tcp->th_ack) >= tc->tc_rekey_seq) {
	    	xprintf(XP_DEBUG, "TX rekey done %d %p\n", tc->tc_keygen, tc);
		tc->tc_keygentx++;
		assert(tc->tc_keygentx == tc->tc_keygen);
		if (rekey_complete(tc))
			return;

		tc->tc_state = STATE_ENCRYPTING;
	}

	if (tr && (tc->tc_state = STATE_ENCRYPTING)) {
		tc->tc_state     = STATE_REKEY_RCVD;
		tc->tc_rekey_seq = ntohl(tr->tr_seq);
	}
}

static int do_input_encrypting(struct tc *tc, struct ip *ip, struct tcphdr *tcp)
{
	int rc;
	int v = DIVERT_ACCEPT;
	struct tco_rekeystream *tr;

	tc->tc_key_active = &tc->tc_key_current;
	tr = rekey_input(tc, ip, tcp);

	profile_add(1, "do_input pre check_mac");
	if ((rc = check_mac(tc, ip, tcp))) {
		/* XXX gross */
		if (rc == -1) {
			/* session caching */
			if (tcp->th_flags == (TH_SYN | TH_ACK))
				return DIVERT_ACCEPT;

			/* pkey */
			else if (find_subopt(tcp, TCOP_INIT2)) {
				ack(tc, ip, tcp);
				return DIVERT_DROP;
			}
		}

		xprintf(XP_ALWAYS, "MAC failed %d\n", rc);

		if (_conf.cf_debug)
			abort();

		return DIVERT_DROP;
	} else if (tc->tc_sess) {
		/* When we receive the first MACed packet, we know the other
		 * side is setup so we can cache this session.
		 */
		tc->tc_sess->ts_used = 0;
		tc->tc_sess	     = NULL;
	}

	profile_add(1, "do_input post check_mac");

	if (decrypt(tc, ip, tcp))
		v = DIVERT_MODIFY;

	profile_add(1, "do_input post decrypt");

	rekey_input_post(tc, ip, tcp, tr);

	if (fixup_seq(tc, tcp, 1))
		v = DIVERT_MODIFY;

	return v;
}

static int do_input_init2_sent(struct tc *tc, struct ip *ip, struct tcphdr *tcp)
{
	int rc;

	if (tc->tc_retransmit) {
		assert(find_subopt(tcp, TCOP_INIT1));
		return DIVERT_DROP;
	}

	/* XXX check ACK */

	enable_encryption(tc);

	rc = do_input_encrypting(tc, ip, tcp);
	assert(rc != DIVERT_DROP);

	return rc;
}

static int clamp_mss(struct tc *tc, struct ip *ip, struct tcphdr *tcp)
{
	struct {
		uint8_t	 kind;
		uint8_t	 len;
		uint16_t mss;
	} *mss;

	if (tc->tc_mss_clamp == -1)
		return DIVERT_ACCEPT;

	if (!(tcp->th_flags & TH_SYN))
		return DIVERT_ACCEPT;

	if (tc->tc_state == STATE_DISABLED)
		return DIVERT_ACCEPT;

	mss = find_opt(tcp, TCPOPT_MAXSEG);
	if (!mss) {
		mss = tcp_opts_alloc(tc, ip, tcp, sizeof(*mss));
		if (!mss) {
			tc->tc_state = STATE_DISABLED;

			xprintf(XP_ALWAYS, "Can't clamp MSS\n");

			return DIVERT_ACCEPT;
		}

		mss->kind = TCPOPT_MAXSEG;
		mss->len  = sizeof(*mss);
		mss->mss  = htons(tc->tc_mtu - sizeof(*ip) - sizeof(*tcp));
	}

	return do_clamp_mss(tc, &mss->mss);
}

static void check_retransmit(struct tc *tc, struct ip *ip, struct tcphdr *tcp)
{
	struct ip *ip2;
	struct tcphdr *tcp2;
	int seq;

	if (!tc->tc_retransmit)
		return;

	if (!(tcp->th_flags & TH_ACK))
		return;

	ip2  = (struct ip*) tc->tc_retransmit->r_packet;
	tcp2 = (struct tcphdr*) ((unsigned long) ip2 + (ip2->ip_hl << 2));
	seq  = ntohl(tcp2->th_seq) + tcp_data_len(ip2, tcp2);

	if (ntohl(tcp->th_ack) < seq)
		return;

	kill_retransmit(tc);
}

static int tcp_input_pre(struct tc *tc, struct ip *ip, struct tcphdr *tcp)
{
	int rc = DIVERT_ACCEPT;

	if (tcp->th_flags & TH_SYN)
		tc->tc_isn_peer = ntohl(tcp->th_seq);

	if (tcp->th_flags == TH_SYN && tc->tc_tcp_state == TCPSTATE_LASTACK) {
		tc_finish(tc);
		tc_reset(tc);
	}

	/* XXX check seq numbers, etc. */

	check_retransmit(tc, ip, tcp);

	if (tcp->th_flags & TH_RST) {
		tc->tc_tcp_state = TCPSTATE_DEAD;
		return rc;
	}

	return rc;
}

static int tcp_input_post(struct tc *tc, struct ip *ip, struct tcphdr *tcp)
{
	int rc = DIVERT_ACCEPT;

	if (clamp_mss(tc, ip, tcp) == DIVERT_MODIFY)
		rc = DIVERT_MODIFY;

	profile_add(2, "did clamp MSS");

	/* Make sure kernel doesn't send shit until we connect */
	switch (tc->tc_state) {
	case STATE_ENCRYPTING:
	case STATE_REKEY_SENT:
	case STATE_REKEY_RCVD:
	case STATE_DISABLED:
	case STATE_INIT2_SENT:
		break;

	default:
		tcp->th_win = htons(0);
		rc = DIVERT_MODIFY;
		break;
	}

	if (tcp->th_flags & TH_FIN) {
		switch (tc->tc_tcp_state) {
		case TCPSTATE_FIN1_SENT:
			tc->tc_tcp_state = TCPSTATE_FIN2_RCVD;
			break;

		case TCPSTATE_LASTACK:
		case TCPSTATE_FIN2_RCVD:
			break;

		default:
			tc->tc_tcp_state = TCPSTATE_FIN1_RCVD;
			break;
		}

		return rc;
	}

	if (tcp->th_flags & TH_RST) {
		tc->tc_tcp_state = TCPSTATE_DEAD;
		return rc;
	}

	switch (tc->tc_tcp_state) {
	case TCPSTATE_FIN2_SENT:
		if (tcp->th_flags & TH_ACK)
			tc->tc_tcp_state = TCPSTATE_DEAD;
		break;
	}

	return rc;
}

static int do_input_nextk1_sent(struct tc *tc, struct ip *ip,
				struct tcphdr *tcp)
{
	struct tc_subopt *sub;

	if (find_subopt(tcp, TCOP_NEXTK2_SUPPORT))
		tc->tc_app_support |= 2;
	else {
		sub = find_subopt(tcp, TCOP_NEXTK2);
		if (!sub) {
			assert(tc->tc_sess->ts_used);
			tc->tc_sess->ts_used = 0;
			tc->tc_sess = NULL;

			if (!_conf.cf_nocache)
				xprintf(XP_DEFAULT, "Session caching failed\n");

			return do_input_hello_sent(tc, ip, tcp);
		}
	}

	enable_encryption(tc);

	return DIVERT_ACCEPT;
}

static int do_input_nextk2_sent(struct tc *tc, struct ip *ip,
				struct tcphdr *tcp)
{
	int rc;

	if (tcp->th_flags & TH_SYN)
		return DIVERT_ACCEPT;

	assert(tcp->th_flags & TH_ACK);

	enable_encryption(tc);

	rc = do_input_encrypting(tc, ip, tcp);
	assert(rc != DIVERT_DROP);

	return rc;
}

static int do_input(struct tc *tc, struct ip *ip, struct tcphdr *tcp)
{
	int rc = DIVERT_DROP;
	int tcp_rc, tcp_rc2;

	tcp_rc = tcp_input_pre(tc, ip, tcp);

	/* an RST half way through the handshake */
	if (tc->tc_tcp_state == TCPSTATE_DEAD 
	    && !connected(tc))
		return tcp_rc;

	if (tcp_rc == DIVERT_DROP)
		return DIVERT_ACCEPT; /* kernel will deal with it */

	switch (tc->tc_state) {
	case STATE_NEXTK1_RCVD:
		/* XXX check same SID */
	case STATE_HELLO_RCVD:
		tc_reset(tc); /* XXX */
	case STATE_CLOSED:
		rc = do_input_closed(tc, ip, tcp);
		break;

	case STATE_HELLO_SENT:
		rc = do_input_hello_sent(tc, ip, tcp);
		break;

	case STATE_PKCONF_RCVD:
		/* XXX syn ack re-TX check that we're getting the same shit */
		assert(tcp->th_flags == (TH_SYN | TH_ACK));
		rc = DIVERT_ACCEPT;
		break;

	case STATE_NEXTK1_SENT:
		rc = do_input_nextk1_sent(tc, ip, tcp);
		break;

	case STATE_NEXTK2_SENT:
		rc = do_input_nextk2_sent(tc, ip, tcp);
		break;

	case STATE_PKCONF_SENT:
		rc = do_input_pkconf_sent(tc, ip, tcp);
		break;

	case STATE_INIT1_SENT:
		rc = do_input_init1_sent(tc, ip, tcp);
		break;

	case STATE_INIT2_SENT:
		rc = do_input_init2_sent(tc, ip, tcp);
		break;

	case STATE_ENCRYPTING:
	case STATE_REKEY_SENT:
	case STATE_REKEY_RCVD:
		rc = do_input_encrypting(tc, ip, tcp);
		break;

	case STATE_DISABLED:
		rc = DIVERT_ACCEPT;
		break;

	default:
		xprintf(XP_ALWAYS, "Unknown state %d\n", tc->tc_state);
		abort();
	}

	tcp_rc2 = tcp_input_post(tc, ip, tcp);

	if (tcp_rc == DIVERT_ACCEPT)
		tcp_rc = tcp_rc2;

	if (rc == DIVERT_ACCEPT)
		return tcp_rc;

	return rc;
}

int tcpcrypt_packet(void *packet, int len, int flags)
{
	struct ip *ip = packet;
	struct tc *tc;
	struct tcphdr *tcp;
	int rc;

	profile_add(1, "tcpcrypt_packet in");

	if (ntohs(ip->ip_len) != len)
		goto __bad_packet;

	if (ip->ip_p != IPPROTO_TCP)
		return DIVERT_ACCEPT;

	tcp = (struct tcphdr*) ((unsigned long) ip + (ip->ip_hl << 2));
	if ((unsigned long) tcp - (unsigned long) ip + (tcp->th_off << 2) > len)
		goto __bad_packet;

	tc = lookup_connection(ip, tcp, flags);

	/* new connection */
	if (!tc) {
		profile_add(1, "tcpcrypt_packet found no connection");

		if (_conf.cf_disable)
			return DIVERT_ACCEPT;

		if (tcp->th_flags != TH_SYN) {
			xprintf(XP_NOISY, "Ignoring established connection: ");
			print_packet(ip, tcp, flags, tc);

			return DIVERT_ACCEPT;
		}

		tc = new_connection(ip, tcp, flags);
		profile_add(1, "tcpcrypt_packet new connection");
	} else
		profile_add(1, "tcpcrypt_packet found connection");

	print_packet(ip, tcp, flags, tc);

	tc->tc_dir_packet = (flags & DF_IN) ? DIR_IN : DIR_OUT;
	tc->tc_csum       = 0;

	if (flags & DF_IN)
		rc = do_input(tc, ip, tcp);
	else
		rc = do_output(tc, ip, tcp);

	/* XXX for performance measuring - ensure sane results */
	assert(!_conf.cf_debug || (tc->tc_state != STATE_DISABLED));

	profile_add(1, "tcpcrypt_packet did processing");

	if (rc == DIVERT_MODIFY) {
		checksum_tcp(tc, ip, tcp);
		profile_add(1, "tcpcrypt_packet did checksum");
	}

	if (tc->tc_tcp_state == TCPSTATE_DEAD
	    || tc->tc_state  == STATE_DISABLED)
		remove_connection(ip, tcp, flags);

	profile_print();

	return rc;

__bad_packet:
	xprintf(XP_ALWAYS, "Bad packet\n");
	return DIVERT_ACCEPT; /* kernel will drop / deal with it */
}

static struct tc *sockopt_get(struct tcpcrypt_ctl *ctl)
{
	struct tc *tc = sockopt_find(ctl);

	if (tc)
		return tc;

	if (ctl->tcc_sport == 0)
		return NULL;

	tc = get_tc();
	assert(tc);

	_sockopts[ctl->tcc_sport] = tc;
	tc_init(tc);

	return tc;
}

static int do_opt(int set, void *p, int len, void *val, unsigned int *vallen)
{
	if (set) {
		if (*vallen > len)
			return -1;

		memcpy(p, val, *vallen);
		return 0;
	}

	/* get */
	if (len > *vallen)
		len = *vallen;

	memcpy(val, p, len);
	*vallen = len;

	return 0;
}

static int do_sockopt(int set, struct tc *tc, int opt, void *val,
		      unsigned int *len)
{
	int v;
	int rc;

	/* do not allow options during connection */
	switch (tc->tc_state) {
	case STATE_CLOSED:
	case STATE_ENCRYPTING:
	case STATE_DISABLED:
	case STATE_REKEY_SENT:
	case STATE_REKEY_RCVD:
		break;

	default:
		return EBUSY;
	}

	switch (opt) {
	case TCP_CRYPT_ENABLE:
		if (tc->tc_state == STATE_DISABLED)
			v = 0;
		else
			v = 1;

		rc = do_opt(set, &v, sizeof(v), val, len);
		if (rc)
			return rc;

		/* XXX can't re-enable */
		if (tc->tc_state == STATE_CLOSED && !v)
			tc->tc_state = STATE_DISABLED;

		break;

	case TCP_CRYPT_APP_SUPPORT:
		if (set) {
			if (tc->tc_state != STATE_CLOSED)
				return -1;

			return do_opt(set, &tc->tc_app_support,
				      sizeof(tc->tc_app_support), val, len);
		} else {
			unsigned char *p = val;

			if (!connected(tc))
				return -1;

			if (*len < (tc->tc_sid.s_len + 1))
				return -1;

			*p++ = (char) tc->tc_app_support;
			memcpy(p, tc->tc_sid.s_data, tc->tc_sid.s_len);

			*len = tc->tc_sid.s_len + 1;

			return 0;
		}

	case TCP_CRYPT_NOCACHE:
		if (tc->tc_state != STATE_CLOSED)
			return -1;

		return do_opt(set, &tc->tc_nocache, sizeof(tc->tc_nocache),
			      val, len);

	case TCP_CRYPT_CMODE:
		if (tc->tc_state != STATE_CLOSED)
			return -1;

		switch (tc->tc_cmode) {
		case CMODE_ALWAYS:
		case CMODE_ALWAYS_NK:
			v = 1;
			break;

		default:
			v = 0;
			break;
		}

		rc = do_opt(set, &v, sizeof(v), val, len);
		if (rc)
			return rc;

		if (!set)
			break;

		if (v)
			tc->tc_cmode = CMODE_ALWAYS;
		else
			tc->tc_cmode = CMODE_DEFAULT;

		break;

	case TCP_CRYPT_SESSID:
		if (set)
			return -1;

		if (!connected(tc))
			return -1;

		return do_opt(set, tc->tc_sid.s_data, tc->tc_sid.s_len,
			      val, len);

	default:
		return -1;
	}

	return 0;
}

int tcpcryptd_setsockopt(struct tcpcrypt_ctl *s, int opt, void *val,
			 unsigned int len)
{
	struct tc *tc;

	switch (opt) {
	case TCP_CRYPT_RESET:
		tc = sockopt_find(s);
		if (!tc)
			return -1;

		tc_finish(tc);
		put_tc(tc);
		sockopt_clear(s->tcc_sport);

		return 0;
	}

	tc = sockopt_get(s);
	if (!tc)
		return -1;

	return do_sockopt(1, tc, opt, val, &len);
}

static int do_tcpcrypt_netstat(struct conn *c, void *val, unsigned int *len)
{
	struct tc_netstat *n = val;
	int l = *len;
	int copied = 0;
	struct tc *tc;
	int tl;

	while (c) {
		tc = c->c_tc;

		if (!connected(tc))
			goto __next;

		if (tc->tc_tcp_state == TCPSTATE_LASTACK)
			goto __next;

		tl = sizeof(*n) + tc->tc_sid.s_len;
		if (l < tl)
			break;

		n->tn_sip.s_addr = c->c_addr[0].sin_addr.s_addr;
		n->tn_dip.s_addr = c->c_addr[1].sin_addr.s_addr;
		n->tn_sport	 = c->c_addr[0].sin_port;
		n->tn_dport	 = c->c_addr[1].sin_port;
		n->tn_len	 = htons(tc->tc_sid.s_len);

		memcpy(n->tn_sid, tc->tc_sid.s_data, tc->tc_sid.s_len);
		n = (struct tc_netstat*) ((unsigned long) n + tl);
		copied += tl;
		l -= tl;
__next:
		c = c->c_next;
	}

	*len -= copied;

	return copied;
}

/* XXX slow */
static int tcpcrypt_netstat(void *val, unsigned int *len)
{
	int i;
	int num = sizeof(_connection_map) / sizeof(*_connection_map);
	struct conn *c;
	int copied = 0;
	unsigned char *v = val;

	for (i = 0; i < num; i++) {
		c = _connection_map[i];

		if (!c)
			continue;

		copied += do_tcpcrypt_netstat(c->c_next, &v[copied], len);
	}

	*len = copied;

	return 0;
}

int tcpcryptd_getsockopt(struct tcpcrypt_ctl *s, int opt, void *val,
			 unsigned int *len)
{
	struct tc *tc;

	switch (opt) {
	case TCP_CRYPT_NETSTAT:
		return tcpcrypt_netstat(val, len);
	}

	tc = sockopt_get(s);
	if (!tc)
		return -1;

	return do_sockopt(0, tc, opt, val, len);
}

static int get_pref(struct crypt_ops *ops)
{
	int pref = 0;

	/* XXX implement */

	return pref;
}

static void do_register_cipher(struct ciphers *c, struct cipher_list *cl)
{
	struct ciphers *x;
	int pref = 0;

	x = xmalloc(sizeof(*x));
	memset(x, 0, sizeof(*x));
	x->c_cipher = cl;

	while (c->c_next) {
		if (pref >= get_pref(NULL))
			break;

		c = c->c_next;
	}

	x->c_next  = c->c_next;
	c->c_next  = x;
}

void tcpcrypt_register_cipher(struct cipher_list *c)
{
	int type = c->c_type;

	switch (type) {
	case TYPE_PKEY:
		do_register_cipher(&_ciphers_pkey, c);
		break;

	case TYPE_SYM:
		do_register_cipher(&_ciphers_sym, c);
		break;

	default:
		assert(!"Unknown type");
		break;
	}
}

static void init_cipher(struct ciphers *c)
{
	struct crypt_pub *cp;
	struct crypt_sym *cs;
	unsigned int spec = htonl(c->c_cipher->c_id);

	switch (c->c_cipher->c_type) {
	case TYPE_PKEY:
		c->c_speclen = 3;

		cp = c->c_cipher->c_ctr();
		crypt_pub_destroy(cp);
		break;
	
	case TYPE_SYM:
		c->c_speclen = 4;

		cs = crypt_new(c->c_cipher->c_ctr);
		crypt_sym_destroy(cs);
		break;

	default:
		assert(!"unknown type");
		abort();
	}

	memcpy(c->c_spec,
	       ((unsigned char*) &spec) + sizeof(spec) - c->c_speclen,
	       c->c_speclen);
}

static void do_init_ciphers(struct ciphers *c)
{
	struct tc *tc = get_tc();
	struct ciphers *prev = c;
	struct ciphers *head = c;

	c = c->c_next;

	while (c) {
		/* XXX */
		if (TC_DUMMY != TC_DUMMY) {
			if (!_conf.cf_dummy) {
				/* kill dummy */
				prev->c_next = c->c_next;
				free(c);
				c = prev->c_next;
				continue;
			} else {
				/* leave all but dummy */
				head->c_next = c;
				c->c_next = NULL;
				return;
			}
		} else if (!_conf.cf_dummy) {
			/* standard path */
			init_cipher(c);
		}

		prev = c;
		c = c->c_next;
	}

	put_tc(tc);
}

static void init_ciphers(void)
{
	do_init_ciphers(&_ciphers_pkey);
	do_init_ciphers(&_ciphers_sym);

	do_add_ciphers(&_ciphers_pkey, &_pkey, &_pkey_len, sizeof(*_pkey),
		       (uint8_t*) _pkey + sizeof(_pkey));
	do_add_ciphers(&_ciphers_sym, &_sym, &_sym_len, sizeof(*_sym),
                       (uint8_t*) _sym + sizeof(_sym));
}

void tcpcrypt_init(void)
{
	srand(time(NULL)); /* XXX */
	init_ciphers();
}
