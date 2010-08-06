#ifndef __TCPCRYPT_TEST_H__
#define __TCPCRYPT_TEST_H__

extern void test_sym_throughput(void);
extern void test_mac_throughput(void);
extern void test_dropper(void);
extern void print_packet(struct ip *ip, struct tcphdr *tcp, int flags,
			 struct tc *tc);

#endif /* __TCPCRYPT_TEST_H__ */
