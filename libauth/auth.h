#ifndef __TCPCRYPT_AUTH__
#define __TCPCRYPT_AUTH__

#include <stdint.h>

#define AUTH_MAGIC	0x69

struct auth_hdr {
	uint8_t		ah_magic;
	uint8_t		ah_type;
	uint16_t	ah_len;
	uint8_t		ah_data[0];
} __attribute__ ((packed));

struct auth_info {
	unsigned int	ai_type;
	unsigned char	ai_data[64];
};

extern int auth_connect(int s, struct auth_info *ai);
extern int auth_accept(int s, struct auth_info *ai);
extern int auth_enable(int s);

extern int connectbyname(char *host, int port);

/* auth modules APIs */
typedef int (*accept_cb)(int s, struct auth_info *ai);
typedef int (*connect_cb)(int s, struct auth_info *ai);

extern void auth_register(int type, accept_cb accept, connect_cb connect);

#endif /* __TCPCRYPT_AUTH__ */
