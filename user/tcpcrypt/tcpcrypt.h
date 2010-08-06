#ifndef __TCPCRYPT_TCPCRYPT_H__
#define __TCPCRYPT_TCPCRYPT_H__

#define TC_DUMMY	0x69

enum {
	TC_CIPHER_RABIN_WILLIAMS = 0x01,
	TC_CIPHER_OAEP_RSA_3,
};

enum {
	TC_ANY			= 0x00,
	TC_AES128_CTR_SEQIV,
	TC_RC4,
};

enum {
	TC_HMAC_SHA1_128	= 0x01,
	TC_UMAC,
};

typedef uint32_t tag_t;

enum {
	TAG_SESSID	= 0x00,
	TAG_NEXTK,
	TAG_REKEY,
	TAG_KEY_C_ENC,
	TAG_KEY_C_MAC,
	TAG_KEY_S_ENC,
	TAG_KEY_S_MAC,
};

struct tc_cipher_spec {
        uint8_t tcs_algo;
        uint8_t tcs_key_min;
        uint8_t tcs_key_max;
};

struct tc_scipher {
	uint8_t	sc_z1;
	uint8_t sc_cipher;
	uint8_t sc_z2;
	uint8_t	sc_mac;
};

enum {
	STATE_CLOSED		=  0,
	STATE_HELLO_SENT,
	STATE_HELLO_RCVD,
	STATE_PKCONF_SENT,
	STATE_PKCONF_RCVD,
	STATE_INIT1_SENT	=  5,
	STATE_INIT1_RCVD,
	STATE_INIT2_SENT,
	STATE_ENCRYPTING,
	STATE_DISABLED,
	STATE_NEXTK1_SENT	= 10,
	STATE_NEXTK1_RCVD,
	STATE_NEXTK2_SENT,
	STATE_REKEY_SENT,
	STATE_REKEY_RCVD,
};

enum {
	CMODE_DEFAULT	= 0,
	CMODE_ALWAYS,
	CMODE_ALWAYS_NK,
	CMODE_NEVER,
	CMODE_NEVER_NK,
};

enum {
	ROLE_CLIENT	= 1,
	ROLE_SERVER,
};

enum {
	TCPSTATE_CLOSED	= 0,
	TCPSTATE_FIN1_SENT,
	TCPSTATE_FIN1_RCVD,
	TCPSTATE_FIN2_SENT,
	TCPSTATE_FIN2_RCVD,
	TCPSTATE_LASTACK,
	TCPSTATE_DEAD,
};

struct crypt_alg {
	struct crypt_ops	*ca_ops;
	void			*ca_priv;
};

#define MAX_SS		32

struct stuff {
	uint8_t	s_data[MAX_SS * 2];
	int	s_len;
};

struct tc_sess {
	struct crypt_alg	ts_prf;
	struct crypt_alg	ts_sym;
	struct crypt_alg	ts_mac;
	struct stuff		ts_sid;
	struct stuff		ts_nk;
	struct stuff		ts_mk;
	int			ts_role;
	struct in_addr		ts_ip;
	int			ts_port;
	int			ts_dir;
	struct tc_sess		*ts_next;
	int			ts_used;
};

struct tc_sid {
        uint8_t ts_sid[9];
} __attribute__ ((__packed__));

#define TC_MTU		1500
#define MAX_CIPHERS	8
#define MAX_NONCE	16

struct crypt_sym_mac {
	struct crypt_alg	csm_sym;
	struct crypt_alg	csm_mac;
};

enum {
	IVMODE_NONE	= 0,
	IVMODE_SEQ,
	IVMODE_CRYPT,
};

enum {
	DIR_IN	= 1,
	DIR_OUT,
};

struct tc_keyset {
	struct stuff		tc_kec;
	struct stuff		tc_kac;
	struct stuff		tc_kes;
	struct stuff		tc_kas;
	struct crypt_sym_mac	tc_alg_tx;
	struct crypt_sym_mac	tc_alg_rx;
};

struct conn;

struct tc {
	int			tc_state;
	struct tc_cipher_spec	*tc_ciphers_pkey;
	int			tc_ciphers_pkey_len;
	struct tc_scipher	*tc_ciphers_sym;
	int			tc_ciphers_sym_len;
	struct tc_cipher_spec	tc_cipher_pkey;
	struct tc_scipher	tc_cipher_sym;
	struct crypt_ops	*tc_crypt_pkey;
	struct crypt_ops	*tc_crypt_sym;
	struct crypt_ops	*tc_crypt_mac;
	int			tc_mac_size;
	int			tc_mac_ivlen;
	int			tc_mac_ivmode;
	uint64_t		tc_seq;
	uint64_t		tc_ack;
	void			*tc_crypt;
	struct crypt_ops	*tc_crypt_ops;
	int			tc_mac_rst;
	int			tc_cmode;
	int			tc_tcp_state;
	int			tc_mtu;
	struct tc_sess		*tc_sess;
	int			tc_mss_clamp;
	int			tc_seq_off;
	int			tc_rseq_off;
	int			tc_sack_disable;
	int			tc_rto;
	void			*tc_timer;
	struct retransmit	*tc_retransmit;
	struct in_addr		tc_dst_ip;
	int			tc_dst_port;
	uint8_t			tc_nonce[MAX_NONCE];
	int			tc_nonce_len;
	struct tc_cipher_spec	tc_pub_cipher_list[MAX_CIPHERS];
	int			tc_pub_cipher_list_len;
	struct tc_scipher	tc_sym_cipher_list[MAX_CIPHERS];
	int                     tc_sym_cipher_list_len;
	struct stuff		tc_ss;
	struct stuff		tc_sid;
	struct stuff		tc_mk;
	struct stuff		tc_nk;
	struct tc_keyset	tc_key_current;
	struct tc_keyset	tc_key_next;
	struct tc_keyset	*tc_key_active;
	int			tc_role;
	struct crypt_alg	tc_alg_pkey;
	struct crypt_alg	*tc_prf;
	int			tc_sym_ivlen;
	int			tc_sym_ivmode;
	int			tc_dir;
	int			tc_nocache;
	int			tc_dir_packet;
	int			tc_mac_opt_cache[DIR_OUT + 1];
	int			tc_csum;
	int			tc_verdict;
	void			*tc_last_ack_timer;
	unsigned int		tc_sent_bytes;
	unsigned char		tc_keygen;
	unsigned char		tc_keygentx;
	unsigned char		tc_keygenrx;
	unsigned int		tc_rekey_seq;
	unsigned char		tc_opt[40];
	int			tc_optlen;
	struct conn		*tc_conn;
	int			tc_app_support;
};

enum {  
        TCOP_NONE               = 0x0,
        TCOP_HELLO,
	TCOP_HELLO_SUPPORT,
	TCOP_NEXTK2		= 0x04,
	TCOP_NEXTK2_SUPPORT,
	TCOP_INIT1		= 0x06,
	TCOP_INIT2,
        TCOP_PKCONF             = 0x41,
        TCOP_PKCONF_SUPPORT,
	TCOP_REKEY		= 0x83,
        TCOP_NEXTK1		= 0x84,
        TCOP_NEXTK1_SUPPORT,
};

struct tc_subopt {
	uint8_t	tcs_op;
	uint8_t	tcs_len;
	uint8_t	tcs_data[0];
};

struct tco_rekeystream {
	uint8_t  tr_op;
	uint8_t  tr_key;
	uint32_t tr_seq;
} __attribute__ ((__packed__));

#define TCPOPT_SKEETER	16
#define TCPOPT_BUBBA	17
#define TCPOPT_MD5	19
#define TCPOPT_CRYPT	69
#define TCPOPT_MAC	70

struct tcpopt_crypt {
	uint8_t		 toc_kind;
	uint8_t		 toc_len;
	struct tc_subopt toc_opts[0];
};

struct tcpopt_mac {
	uint8_t		tom_kind;
	uint8_t		tom_len;
	uint8_t		tom_data[0];
};

#define MACM_MAGIC 0x8000

struct mac_m {
        uint16_t        mm_magic;
        uint16_t        mm_len;
        uint8_t         mm_off;
        uint8_t         mm_flags;
        uint16_t        mm_urg;
        uint32_t        mm_seqhi;
        uint32_t        mm_seq;
};

struct mac_a {
        uint32_t        ma_ackhi;
        uint32_t        ma_ack;
};

enum {
	TC_INIT1 = 0x0001,
	TC_INIT2,
};

struct tc_init1 {
	uint16_t		i1_op;
	uint16_t		i1_num_ciphers;
	uint16_t		i1_nonce_len;
	uint16_t		i1_pkey_len;
	struct tc_scipher	i1_ciphers[0];
};

struct tc_init2 {
	uint16_t		i2_op;
	uint16_t		i2_clen;
	struct tc_scipher	i2_scipher;
	uint8_t			i2_data[0];
};

extern int  tcpcrypt_packet(void *packet, int len, int flags);
extern int  tcpcrypt_setsockopt(struct tcpcrypt_ctl *s, int opt, void *val,
			        unsigned int len);
extern int  tcpcrypt_getsockopt(struct tcpcrypt_ctl *s, int opt, void *val,
			        unsigned int *len);
extern void tcpcrypt_register_cipher(struct crypt_ops *ops);
extern void tcpcrypt_init(void);

#endif /* __TCPCRYPT_TCPCRYPT_H__ */
