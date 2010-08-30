#ifndef __TCPCRYPT_TCPCRYPT_H__
#define __TCPCRYPT_TCPCRYPT_H__

#ifdef __cplusplus
extern "C" {
#pragma GCC visibility push(default)
#endif

/* tcpcrypt get/setsockopt optnames */
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

enum {
	TCPCRYPT_PARAM_CTLPATH	= 0,
};

extern void tcpcrypt_setparam(int param, void *val);

extern int tcpcrypt_getsockopt(int s, int level, int optname, void *optval,
			       socklen_t *optlen);
extern int tcpcrypt_setsockopt(int s, int level, int optname,
			       const void *optval, socklen_t optlen);

#ifdef __cplusplus
}
#pragma GCC visibility pop
#endif


#endif // __TCPCRYPT_TCPCRYPT_H__
