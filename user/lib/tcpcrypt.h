#ifndef __TCPCRYPT_TCPCRYPT_H__
#define __TCPCRYPT_TCPCRYPT_H__

#include <tcpcrypt_ctl.h>

#ifdef __cplusplus
extern "C" {
#pragma GCC visibility push(default)
#endif

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

#endif /* __TCPCRYPT_TCPCRYPT_H__ */
