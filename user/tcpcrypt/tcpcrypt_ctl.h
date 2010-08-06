#ifndef __TCPCRYPT_TCPCRYPT_CTL_H__
#define __TCPCRYPT_TCPCRYPT_CTL_H__

#define TCPCRYPT_CTLPATH "/tmp/tcpcrypt"

#define TCC_IN	0x00000001
#define TCC_SET	0x00000002

enum {
        TCP_CRYPT_ENABLE	= 0,
        TCP_CRYPT_CMODE,
	TCP_CRYPT_SESSID,
	TCP_CRYPT_RSA_KEY	= 3,

	TCP_CRYPT_APP_SUPPORT	= 15,

	/* non standard options */
	TCP_CRYPT_RESET		= 100,
	TCP_CRYPT_NOCACHE,
	TCP_CRYPT_NETSTAT,
};

struct tc_netstat {
	struct in_addr	tn_sip;
	uint16_t	tn_sport;
	struct in_addr	tn_dip;
	uint16_t	tn_dport;
	uint16_t	tn_len;
	uint8_t		tn_sid[0];
};

struct tcpcrypt_ctl {
	uint32_t	tcc_seq;
	struct in_addr	tcc_src;
	uint16_t	tcc_sport;
	struct in_addr	tcc_dst;
	uint16_t	tcc_dport;
	uint32_t	tcc_flags;
	uint32_t	tcc_err;
	uint32_t	tcc_opt;
	uint32_t	tcc_dlen;
	uint8_t		tcc_data[0];
};

#endif /* __TCPCRYPT_TCPCRYPT_CTL_H__ */
