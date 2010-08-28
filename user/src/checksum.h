#ifndef __TCPCRYPT_CHECKSUM_H__
#define __TCPCRYPT_CHECKSUM_H__

extern void     checksum_ip(struct ip *ip);
extern void     checksum_tcp(struct tc *tc, struct ip *ip, struct tcphdr *tcp);
extern uint16_t checksum(void *data, int len);

#endif /* __TCPCRYPT_CHECKSUM_H__ */
