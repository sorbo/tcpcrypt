/*
 * Copyright (c) 1982, 1986, 1993
 *      The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *      @(#)tcp.h       8.1 (Berkeley) 6/10/93
 */

#ifndef WIN_PORT_H
#define WIN_PORT_H

#include <assert.h>

#define __LITTLE_ENDIAN 666
#define __BYTE_ORDER 666

typedef int socklen_t;

typedef unsigned int u_int32_t;
typedef unsigned short u_int16_t;
typedef unsigned char u_int8_t;

typedef unsigned int in_addr_t;

struct msghdr
  {
    void *msg_name;             /* Address to send to/receive from.  */
    socklen_t msg_namelen;      /* Length of address data.  */

    struct iovec *msg_iov;      /* Vector of data to send/receive into.  */
    size_t msg_iovlen;          /* Number of elements in the vector.  */

    void *msg_control;          /* Ancillary data (eg BSD filedesc passing). */
    size_t msg_controllen;      /* Ancillary data buffer length.
                                   !! The type should be socklen_t but the
                                   definition of the kernel is incompatible
                                   with this.  */

    int msg_flags;              /* Flags on received message.  */
  };

typedef u_int32_t tcp_seq;
/*
 * TCP header.
 * Per RFC 793, September, 1981.
 */
struct tcphdr
  { 
    u_int16_t th_sport;         /* source port */
    u_int16_t th_dport;         /* destination port */
    tcp_seq th_seq;             /* sequence number */
    tcp_seq th_ack;             /* acknowledgement number */
#  if __BYTE_ORDER == __LITTLE_ENDIAN
    u_int8_t th_x2:4;           /* (unused) */
    u_int8_t th_off:4;          /* data offset */
#  endif
#  if __BYTE_ORDER == __BIG_ENDIAN
    u_int8_t th_off:4;          /* data offset */
    u_int8_t th_x2:4;           /* (unused) */
#  endif
    u_int8_t th_flags;
#  define TH_FIN        0x01
#  define TH_SYN        0x02
#  define TH_RST        0x04
#  define TH_PUSH       0x08
#  define TH_ACK        0x10
#  define TH_URG        0x20
    u_int16_t th_win;           /* window */
    u_int16_t th_sum;           /* checksum */
    u_int16_t th_urp;           /* urgent pointer */
} __attribute__ ((gcc_struct));

# define TCPOPT_EOL             0
# define TCPOPT_NOP             1
# define TCPOPT_MAXSEG          2
# define TCPOLEN_MAXSEG         4
# define TCPOPT_WINDOW          3
# define TCPOLEN_WINDOW         3
# define TCPOPT_SACK_PERMITTED  4               /* Experimental */
# define TCPOLEN_SACK_PERMITTED 2
# define TCPOPT_SACK            5               /* Experimental */
# define TCPOPT_TIMESTAMP       8
# define TCPOLEN_TIMESTAMP      10
# define TCPOLEN_TSTAMP_APPA    (TCPOLEN_TIMESTAMP+2) /* appendix A */

# define TCPOPT_TSTAMP_HDR      \
    (TCPOPT_NOP<<24|TCPOPT_NOP<<16|TCPOPT_TIMESTAMP<<8|TCPOLEN_TIMESTAMP)

struct ip
  {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int ip_hl:4;               /* header length */
    unsigned int ip_v:4;                /* version */
#endif
#if __BYTE_ORDER == __BIG_ENDIAN
    unsigned int ip_v:4;                /* version */
    unsigned int ip_hl:4;               /* header length */
#endif
    u_int8_t ip_tos;                    /* type of service */
    u_short ip_len;                     /* total length */
    u_short ip_id;                      /* identification */
    u_short ip_off;                     /* fragment offset field */
#define IP_RF 0x8000                    /* reserved fragment flag */
#define IP_DF 0x4000                    /* dont fragment flag */
#define IP_MF 0x2000                    /* more fragments flag */
#define IP_OFFMASK 0x1fff               /* mask for fragmenting bits */
    u_int8_t ip_ttl;                    /* time to live */
    u_int8_t ip_p;                      /* protocol */
    u_short ip_sum;                     /* checksum */
    struct in_addr ip_src, ip_dst;      /* source and dest address */
  } __attribute__ ((gcc_struct));

struct iovec
  {
    void *iov_base;     /* Pointer to data.  */
    size_t iov_len;     /* Length of data.  */
  };

static void errx(int eval, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);

	printf("\n");

	exit(eval);
}

static void err(int eval, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);

	printf(": ");
	perror("");

	exit(eval);
}

#endif // WIN_PORT_H
