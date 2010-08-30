#include <sys/types.h> 
#include <arpa/inet.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#define __FAVOR_BSD
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>

#include "tcpcrypt.h"
#include "tcpcryptd.h"
#include "checksum.h"
#include "config.h"

typedef __signed__ char __s8;
typedef unsigned char __u8;

typedef __signed__ short __s16;
typedef unsigned short __u16;

typedef __signed__ int __s32;
typedef unsigned int __u32;

typedef __u16 __sum16;
typedef __u32 __wsum;

typedef __u32 u32;
typedef u32 __be32;

# define __force

extern unsigned int csum_partial(const unsigned char * buff, int len,
				 unsigned int sum);

#ifdef NO_ASM
static int _use_linux = 0;

unsigned int csum_partial(const unsigned char * buff, int len, unsigned int sum)
{
	abort();
}
#else
static int _use_linux = 1;
#endif /* ! NO_ASM */

struct tcp_ph {
        struct in_addr  ph_src;
        struct in_addr  ph_dst; 
        uint8_t         ph_zero;
        uint8_t         ph_proto;
        uint16_t        ph_len;
};                              


static unsigned short in_cksum(struct tcp_ph *ph, unsigned short *ptr,
                               int nbytes, int s)
{ 
  register long sum;
  u_short oddbyte;
  register u_short answer;
  
  sum = s;
  
  if (ph) {
        unsigned short *p = (unsigned short*) ph;
        int i;
        
        for (i = 0; i < sizeof(*ph) >> 1; i++)
                sum += *p++;
  }
  
  while (nbytes > 1)
    {
      sum += *ptr++;
      nbytes -= 2;
    }
  
  if (nbytes == 1)
    { 
      oddbyte = 0;
      *((u_char *) & oddbyte) = *(u_char *) ptr;
      sum += oddbyte;
    }

  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  answer = ~sum;
  return (answer);
}

static void checksum_ip_generic(struct ip *ip)
{       
        ip->ip_sum = 0;
        ip->ip_sum = in_cksum(NULL, (unsigned short*) ip, sizeof(*ip), 0);
}

static void checksum_tcp_generic(struct ip *ip, struct tcphdr *tcp, int sum)
{ 
        struct tcp_ph ph;
	int len;

	len = ntohs(ip->ip_len) - (ip->ip_hl << 2);

        ph.ph_src   = ip->ip_src;
        ph.ph_dst   = ip->ip_dst;
        ph.ph_zero  = 0;
        ph.ph_proto = ip->ip_p;
        ph.ph_len   = htons(len);

	if (sum != 0)
		len = tcp->th_off << 2;

        tcp->th_sum = 0;
        tcp->th_sum = in_cksum(&ph, (unsigned short*) tcp, len, sum);
}

static inline __sum16 csum_fold(__wsum sum)
{       
        asm("addl %1, %0                ;\n"
            "adcl $0xffff, %0   ;\n"
            : "=r" (sum)
            : "r" ((__force u32)sum << 16),
              "0" ((__force u32)sum & 0xffff0000));
        return (__force __sum16)(~(__force u32)sum >> 16);
}

static inline __wsum csum_tcpudp_nofold(__be32 saddr, __be32 daddr,
                                        unsigned short len,
                                        unsigned short proto,
                                        __wsum sum)
{
        asm("addl %1, %0        ;\n"
            "adcl %2, %0        ;\n"
            "adcl %3, %0        ;\n"
            "adcl $0, %0        ;\n"
            : "=r" (sum)
            : "g" (daddr), "g"(saddr),
              "g" ((len + proto) << 8), "0" (sum));
        return sum;
}

/*
 * computes the checksum of the TCP/UDP pseudo-header
 * returns a 16-bit checksum, already complemented
 */
static inline __sum16 csum_tcpudp_magic(__be32 saddr, __be32 daddr,
                                        unsigned short len,
                                        unsigned short proto,
                                        __wsum sum)
{       
        return csum_fold(csum_tcpudp_nofold(saddr, daddr, len, proto, sum));
}

static void checksum_tcp_linux(struct tc *tc, struct ip *ip, struct tcphdr *tcp)
{
	int len = ntohs(ip->ip_len) - (ip->ip_hl << 2);
	int p;
	int sum = tc->tc_csum;

	tcp->th_sum = 0;

	if (sum) {
  		sum  = (sum >> 16) + (sum & 0xffff);
  		sum += (sum >> 16);
		sum &= 0xffff;
		
		p = csum_partial((unsigned char*) tcp, tcp->th_off << 2, sum);
	} else
		p = csum_partial((unsigned char*) tcp, len, 0);

	tcp->th_sum = csum_tcpudp_magic(ip->ip_src.s_addr,
					ip->ip_dst.s_addr,
					len,
					IPPROTO_TCP,
					p);
}

void checksum_tcp(struct tc *tc, struct ip *ip, struct tcphdr *tcp)
{
	if (tc->tc_csum && 0)
		checksum_tcp_generic(ip, tcp, tc->tc_csum);
	else if (_use_linux)
		checksum_tcp_linux(tc, ip, tcp);
	else
		checksum_tcp_generic(ip, tcp, 0);
}

static inline __sum16 ip_compute_csum(const void *buff, int len)
{   
    return csum_fold(csum_partial(buff, len, 0));
}

static void checksum_ip_linux(struct ip *ip)
{
	ip->ip_sum = 0;
	ip->ip_sum = ip_compute_csum(ip, ip->ip_hl << 2);
}

void checksum_ip(struct ip *ip)
{
	if (_use_linux)
		checksum_ip_linux(ip);
	else
		checksum_ip_generic(ip);
}

uint16_t checksum(void *data, int len)
{
	if (_use_linux)
		return ip_compute_csum(data, len);
	else
		return in_cksum(NULL, data, len, 0);
}
