#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <tcpcrypt.h>
#include <arpa/inet.h>

#include "os.h"

int os_read(int s, void *buf, int len)
{
	return read(s, buf, len);
}

int os_write(int s, void *buf, int len)
{
	return write(s, buf, len);
}

int os_getsockopt(int s, int level, int opt, void *buf, socklen_t *len)
{
	return tcpcrypt_getsockopt(s, level, opt, buf, len);
}

int tcpcrypt_get_sid(int s, unsigned char *sid)
{
	int sidl = TCPCRYPT_SID_MAXLEN;

        if (os_getsockopt(s, IPPROTO_TCP, TCP_CRYPT_SESSID, sid,
                          (socklen_t*) &sidl) == -1) {
                return -1;
        }

	if (sidl <= 0)
		return -1;

	return sidl;
}

int tcpcrypt_get_app_support(int s)
{
	unsigned char morte[TCPCRYPT_SID_MAXLEN + 1];
	int len = sizeof(morte);

        if (os_getsockopt(s, IPPROTO_TCP, TCP_CRYPT_APP_SUPPORT, morte,
                          (socklen_t*) &len) == -1) {
                return 0;
	}

	if (morte[0] == 3)
		return 1;

	return 0;
}

int tcpcrypt_set_app_support(int s, int val)
{
        if (tcpcrypt_setsockopt(s, IPPROTO_TCP, TCP_CRYPT_APP_SUPPORT, &val,
			        sizeof(val)) == -1) {
		return -1;
	}

	return 0;
}
