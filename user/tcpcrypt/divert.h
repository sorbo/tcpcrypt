#ifndef __TCPCRYPT_DIVERT_H__
#define __TCPCRYPT_DIVERT_H__

enum {
	DIVERT_ACCEPT = 0,
	DIVERT_DROP,
	DIVERT_MODIFY,
};

#define DF_IN	0x1

typedef int (*divert_cb)(void *data, int len, int flags);

extern int  divert_open(int port, divert_cb cb);
extern void divert_next_packet(int s);
extern void divert_close(void);
extern void divert_inject(void *data, int len);
extern void divert_cycle(void);
extern void open_raw(void);

#endif /* __TCPCRYPT_DIVERT_H__ */
