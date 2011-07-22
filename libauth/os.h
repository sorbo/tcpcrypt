#ifndef __AUTH_OS__
#define __AUTH_OS__

extern int os_read(int s, void *buf, int len);
extern int os_write(int s, void *buf, int len);
extern int os_getsockopt(int s, int level, int opt, void *buf, socklen_t *len);
extern int tcpcrypt_get_sid(int s, unsigned char *sid);
extern int tcpcrypt_get_app_support(int s);
extern int tcpcrypt_set_app_support(int s, int val);

#endif /* __AUTH_OS__ */
