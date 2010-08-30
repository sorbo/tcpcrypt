#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <unistd.h>
#include <sys/uio.h>

#include <tcpcrypt/tcpcrypt.h>
#include "src/tcpcrypt_ctl.h"

#define MAX_LEN	1200

#define TCP_CRYPT 15

#ifndef SOL_TCP
#define SOL_TCP IPPROTO_TCP
#endif

enum {
	IMP_UNKNOWN = 0,
	IMP_USER,
	IMP_KERNEL,
};

struct conf {
	char			*cf_path;
	int			cf_s;
	uint32_t		cf_seq;
	struct sockaddr_un	cf_sun;
	int			cf_imp;
};

static struct conf _conf = {
	.cf_path = TCPCRYPT_CTLPATH,
};

union sockaddr_u {
  struct sockaddr addr;
  struct sockaddr_in in;
  struct sockaddr_in6 in6;
  struct sockaddr_storage storage;
};

static void set_addr()
{
	struct sockaddr_un *addr = &_conf.cf_sun;
	memset(addr, 0, sizeof(*addr));

	addr->sun_family = PF_UNIX;
	snprintf(addr->sun_path, sizeof(addr->sun_path), "%s", _conf.cf_path);
}

void tcpcrypt_setparam(int param, void *val)
{
	switch (param) {
	case TCPCRYPT_PARAM_CTLPATH:
		_conf.cf_path = strdup(val);
		set_addr();
		break;

	default:
		printf("Unknown param %d\n", param);
		break;
	}
}

static void bind_local(void)
{
	struct sockaddr_un s_un;

	memset(&s_un, 0, sizeof(s_un));
	s_un.sun_family = PF_UNIX;

	snprintf(s_un.sun_path, sizeof(s_un.sun_path), "/tmp/%d", getpid());
#ifdef linux
	s_un.sun_path[0] = 0;
#endif

	if (bind(_conf.cf_s, (struct sockaddr*) &s_un, sizeof(s_un)) == -1)
		err(1, "bind()");
}

static void open_socket(void)
{
	if (_conf.cf_s)
		return;

	_conf.cf_s = socket(PF_UNIX, SOCK_DGRAM, 0);
	if (_conf.cf_s == -1)
		err(1, "socket()");

	set_addr();

	bind_local();
}

/* Sets fields in `struct tcpcrypt_ctl` given in the pointers `ctl_addr` and
   `ctl_port` from the sockaddr in `ss`. If `ss` is IPv6, attempts a
   rudimentary IPv6->IPv4 "conversion" for IPv4-compatible/mapped
   addresses. This will fail on real (non-IPv4-compatible/mapped) IPv6
   addresses. Currently, tcpcrypt is *not* IPv6 compatible. */
static void set_ctl_sockaddr(union sockaddr_u *ss,
			     in_addr_t *ctl_addr,
			     uint16_t *ctl_port)
{
	if (ss->storage.ss_family == AF_INET) {
		*ctl_addr = ss->in.sin_addr.s_addr;
		*ctl_port = ss->in.sin_port;
	} else { // AF_INET6
		if (IN6_IS_ADDR_V4COMPAT(&ss->in6.sin6_addr) ||
		    IN6_IS_ADDR_V4MAPPED(&ss->in6.sin6_addr)) {
#if !defined s6_addr32
# define s6_addr32 __u6_addr.__u6_addr32
#endif
			*ctl_addr = ss->in6.sin6_addr.s6_addr32[3];
			*ctl_port = ss->in6.sin6_port;
		} else {
			/* TODO: add IPv6 support */
			warn("Non-IPv4-compatible IPv6 addresses not supported."
			     "Behavior of get/set_sockopt call is unreliable.");
	    }
	}

#ifdef DEBUG_IPV6
	fprintf(stderr, "* set_ctl_sockaddr: %s:%d\n",
		inet_ntoa(*ctl_addr), ntohs(*ctl_port));
#endif
}

static int do_sockopt(uint32_t flags, int s, int level, int optname,
		      void *optval, socklen_t *optlen)
{
	struct tcpcrypt_ctl ctl;
	union sockaddr_u ss;
	socklen_t sl = sizeof ss;
	struct iovec iov[2];
	struct msghdr mh;
	int rc, len, i, port;
	unsigned char buf[2048];
	int set = flags & TCC_SET;

	if (level != IPPROTO_TCP)
		errx(1, "bad level");

	/* XXX */
	if (*optlen > MAX_LEN) {
		if (flags & TCC_SET)
			errx(1, "setsockopt too long %d", *optlen);
		
		*optlen = MAX_LEN;
	}

	memset(&ctl, 0, sizeof(ctl));
	ctl.tcc_seq = _conf.cf_seq++;

	for (i = 0; i < 2; i++) {
		memset(&ss, 0, sizeof(ss));

		if (getsockname(s, (struct sockaddr*) &ss, &sl) == -1)
			err(1, "getsockname()");

                if (ss.storage.ss_family == AF_INET)
                        port = ntohs(ss.in.sin_port);
                else
                        port = ntohs(ss.in6.sin6_port);

		if (i == 1) {
			printf("forced bind to %d\n", port);
			break;
		}

		if (port)
			break;

		/* let's just home the app doesn't call bind again */
		ss.in.sin_family      = PF_INET;
		ss.in.sin_port        = 0;
		ss.in.sin_addr.s_addr = INADDR_ANY;

		if (bind(s, &ss.addr, sizeof(ss)) == -1)
			err(1, "bind()");
	}

	set_ctl_sockaddr(&ss, &ctl.tcc_src.s_addr, &ctl.tcc_sport);

	memset(&ss, 0, sl);
	if (getpeername(s, (struct sockaddr*) &ss, &sl) == 0) {
		set_ctl_sockaddr(&ss, &ctl.tcc_dst.s_addr, &ctl.tcc_dport);
	}

	ctl.tcc_flags = flags;
	ctl.tcc_opt   = optname;
	ctl.tcc_dlen  = *optlen;

	iov[0].iov_base = &ctl;
	iov[0].iov_len  = sizeof(ctl);
	iov[1].iov_base = optval;
	iov[1].iov_len  = *optlen;

	memset(&mh, 0, sizeof(mh));
	mh.msg_name    = &_conf.cf_sun;
	mh.msg_namelen = sizeof(_conf.cf_sun);
	mh.msg_iov     = iov;
	mh.msg_iovlen  = *optlen ? 2 : 1;

	len = 0;
	for (i = 0; i < mh.msg_iovlen; i++)
		len += mh.msg_iov[i].iov_len;

	open_socket();

#if defined(__CYGWIN__)
	if (connect(_conf.cf_s, (struct sockaddr*) &_conf.cf_sun,
		    sizeof(&_conf.cf_sun)) == -1)
		err(1, "connect()");

	if ((rc = writev(_conf.cf_s, iov, 2)) == -1)
		return -1;
#else
	if ((rc = sendmsg(_conf.cf_s, &mh, 0)) == -1)
		return -1;
#endif

	if (rc != len)
		errx(1, "short write %d/%d", rc, len);

	if (set) {
		iov[1].iov_base = buf;
		assert(sizeof(buf) >= iov[1].iov_len);
	}

	rc = recvmsg(_conf.cf_s, &mh, 0);
	if (rc == -1)
		err(1, "recvmsg()");

	if (rc == 0)
		errx(1, "EOF");

	if (rc < sizeof(ctl) || (rc != sizeof(ctl) + ctl.tcc_dlen))
		errx(1, "short read");

	*optlen = ctl.tcc_dlen;

	if (ctl.tcc_err) {
		errno = ctl.tcc_err;
		ctl.tcc_err = -1;
	}

	return ctl.tcc_err;
}

static void probe_imp()
{
	int s;
	int opt = TCP_CRYPT_APP_SUPPORT;

	if (_conf.cf_imp != IMP_UNKNOWN)
		return;

	s = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (s == -1)
		err(1, "socket()");

	if (setsockopt(s, SOL_TCP, TCP_CRYPT, &opt, sizeof(opt)) != -1)
		_conf.cf_imp = IMP_KERNEL;
	else
		_conf.cf_imp = IMP_USER;

	printf("Using %d implementation\n", _conf.cf_imp);

	close(s);
}

static int setsockopt_kernel(int s, int level, int optname, const void *optval,
			     socklen_t optlen)
{
	unsigned char lame[2048];

	if ((optlen + 4) > sizeof(lame))
		return -1;

	*((int*) lame) = optname;

	memcpy(&lame[sizeof(int)], optval, optlen);

	optlen += sizeof(int);

	return setsockopt(s, SOL_TCP, TCP_CRYPT, lame, optlen);
}

static int getsockopt_kernel(int s, int level, int optname, void *optval,
			     socklen_t *optlen)
{
	unsigned char lame[2048];
	int rc;

	if (*optlen > sizeof(lame))
		return -1;

	*((int*) lame) = optname;

	rc = getsockopt(s, SOL_TCP, TCP_CRYPT, lame, optlen);

	if (rc == -1)
		return rc;

	memcpy(optval, lame, *optlen);

	return 0;
}

int tcpcrypt_getsockopt(int s, int level, int optname, void *optval,
			socklen_t *optlen)
{
	probe_imp();

	if (_conf.cf_imp == IMP_KERNEL)
		return getsockopt_kernel(s, level, optname, optval, optlen);

	return do_sockopt(0, s, level, optname, optval, optlen);
}

int tcpcrypt_setsockopt(int s, int level, int optname, const void *optval,
                        socklen_t optlen)
{
	probe_imp();

	if (_conf.cf_imp == IMP_KERNEL)
		return setsockopt_kernel(s, level, optname, optval, optlen);

	return do_sockopt(TCC_SET, s, level, optname, (void*) optval, &optlen);
}
