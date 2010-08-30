#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#define __FAVOR_BSD
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <err.h>
#include <stdarg.h>
#include <errno.h>
#include <assert.h>
#include <signal.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#include <openssl/engine.h>
#include <ctype.h>

struct tc;
#include <tcpcrypt/tcpcrypt.h>
#include "src/profile.h"
#include "src/checksum.h"
#include "contrib/umac.h"
#include "contrib/ocb.h"
#include "contrib/cmac.h"
#include "pake.h"

#define TEST_ASSERT(n)					                     \
	do {								     \
		if (!(n)) 						     \
			errx(1, "Test FAILED at %s:%d", __FILE__, __LINE__); \
	} while (0)

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))

#define TCP_CRYPT 15

struct opt {
	int		o_num;
	int		o_len;
	void		*o_data;
	struct opt	*o_next;
};

typedef void (*server_cb)(int);
typedef void (*crypto_cb)(int len);
typedef void (*client_cb)(int);

#define MAX_PARAM	16

static struct conf {
	int		cf_listen;
	struct in_addr	cf_srcip;
	int		cf_sport;
	struct in_addr	cf_dstip;
	int		cf_dport;
	int		cf_verbose;
	int		cf_test;
	struct opt	cf_ops;
	int		cf_nocache;
	int		cf_paramn;
	char		*cf_params[MAX_PARAM];
	int		cf_ssl;
	char		*cf_ssl_file;
	char		*cf_ssl_cipher;
	int		cf_notcpcrypt;
	int		cf_discard;
	int		cf_port_spacing;
	int		cf_backlog;
	int		cf_stats_amortize;
	int		cf_data_collector;
	int		cf_auth_cache;
	int		cf_ports;
	int		cf_kernel;
	int		cf_app_support;
	int		cf_latency;
} _conf;

struct sem {
	pthread_mutex_t	s_mtx;
	pthread_cond_t	s_sem;
	int		s_state;
};

struct batch {
	unsigned char	b_data[4096];
	int		b_len;
	int		b_ref;
	struct sem	b_ready;
	pthread_mutex_t	b_mtx;
	struct batch	*b_next;
};

static struct state {
	int		s_ss;
	pthread_mutex_t	s_mtx;
	int		s_do_lock;
	pthread_key_t	s_tls_key;
	SSL_CTX		*s_ssl_sessions;
	EVP_CIPHER_CTX	s_test_cipher;
	EVP_MD_CTX	s_test_md;
	const EVP_MD	*s_test_mdp;
	HMAC_CTX	s_test_hmac;
	umac_ctx_t	s_test_umac;
	unsigned char	s_test_poly1305aes[32];
	crypto_cb	s_mac;
	crypto_cb	s_cipher;
	unsigned char	s_sid[9];
	struct sem	s_signer_wait;
	struct batch	s_batch_queue;
	struct batch	s_batch_active;
	struct batch	s_batch_free;
	unsigned char	s_batch_sig[2048];
	int		s_batch_siglen;
	int		s_batch_num;
	SHA_CTX		s_batch_sha;
	pthread_mutex_t	s_batch_mtx;
	RSA		*s_batch_rsa;
	void		*s_batch_cert;
	int		s_batch_cert_len;
	pthread_mutex_t	s_accept_mtx;
	pthread_mutex_t	*s_ssl_locks;
	int		s_batch_cmac;
	int		s_latency_samples;
	int		s_latency_count;
} _state;

typedef struct {
	void		*pi_priv;
	HMAC_CTX	pi_hmac;
} PAKE;

struct tls {
	SSL		*t_ssl;
	SSL_SESSION	*t_ssl_session;
	SSL_CTX		*t_ssl_ctx;
	int		t_sport;
	int		t_sport_off;
	CMAC_CTX	*t_cmac;
	int		t_stat_count;
	int		t_stat_samples;
	PAKE		*t_pake;
	struct timeval	t_latency_start;
	int		t_latency_count;
	int		t_latency_samples;
};

struct CRYPTO_dynlock_value {
	pthread_mutex_t mutex;
};

static char *_mac_label[] = { "server", "client" };

static pthread_once_t key_once = PTHREAD_ONCE_INIT;

static char *_data_collector = "/tmp/datacollector";

struct test {
	void	(*t_cb)(void);
	char	*t_desc;
};

struct crypto {
	void		(*c_setup)(void);
	crypto_cb	c_do;
	char		*c_name;
};

struct st_arg {
	server_cb	sta_cb;
	int		sta_s;
};

void aesni_encrypt(const unsigned char *in, unsigned char *out,
                       const AES_KEY *key);

int aesni_set_encrypt_key(const unsigned char *userKey, int bits,
                              AES_KEY *key);

void aesni_cbc_encrypt(const unsigned char *in,
                           unsigned char *out,
                           size_t length,
                           const AES_KEY *key,
                           unsigned char *ivec, int enc);

static void xprintf(char *fmt, ...)
{
	va_list ap;

	if (!_conf.cf_verbose)
		return;

	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
}

static inline void hexdump(void *p, int len)
{
	int i = 0;
	unsigned char *x = p;

	while (len--) {
		printf("%.2x ", *x++);

		if (++i == 16) {
			printf("\n");
			i = 0;
		}
	}

	if (i)
		printf("\n");
}

static void* xmalloc(size_t len)
{
	void *a = malloc(len);

	if (!a)
		err(1, "malloc()");

	return a;
}

void errssl(int x, char *fmt, ...)
{       
        va_list ap;

        va_start(ap, fmt);
        vprintf(fmt, ap);
        va_end(ap);

        printf(": %s\n", ERR_error_string(ERR_get_error(), NULL));
        exit(1);
}

static void make_key(void)
{
	pthread_key_create(&_state.s_tls_key, NULL);
}

static struct tls *get_tls(void)
{
	struct tls *t;

	pthread_once(&key_once, make_key);

	if ((t = pthread_getspecific(_state.s_tls_key)) == NULL) {
		t = malloc(sizeof(*t));
		if (!t)
			err(1, "malloc()");

		memset(t, 0, sizeof(*t));

		pthread_setspecific(_state.s_tls_key, t);
	}

	return t;
}

static void do_lock(pthread_mutex_t *mtx)
{
	if (pthread_mutex_lock(mtx))
		err(1, "pthread_mutex_lock()");
}

static void do_unlock(pthread_mutex_t *mtx)
{
	if (pthread_mutex_unlock(mtx))
		err(1, "pthread_mutex_unlock()");
}

static void lock(void)
{
	if (!_state.s_do_lock)
		return;

	do_lock(&_state.s_mtx);
}

static void unlock(void)
{
	if (!_state.s_do_lock)
		return;
	
	do_unlock(&_state.s_mtx);
}

static SSL *get_ssl(void)
{
	struct tls *t = get_tls();

	return t->t_ssl;
}

static void xgetsockopt(int s, int optname, void *optval, socklen_t *optlen)
{
	if (_conf.cf_notcpcrypt)
		return;

	if (tcpcrypt_getsockopt(s, IPPROTO_TCP, optname, optval, optlen) == -1)
		err(1, "tcpcrypt_getsockopt()");
}

static void xsetsockopt(int s, int optname, const void *optval, socklen_t len)
{
	if (_conf.cf_notcpcrypt)
		return;

	if (tcpcrypt_setsockopt(s, IPPROTO_TCP, optname, optval, len) == -1)
		err(1, "tcpcrypt_setsockopt()");
}

static void cleanup(void)
{
	if (_state.s_ss > 0) {
		if (!_conf.cf_notcpcrypt)
			tcpcrypt_setsockopt(_state.s_ss, IPPROTO_TCP,
					    TCP_CRYPT_RESET, NULL, 0);

		close(_state.s_ss);
	}
}

static void sig(int x)
{
	printf("\n");

	profile_end();

	cleanup();
	exit(0);
}

static int do_open_socket(int port)
{
	int s;
	struct sockaddr_in s_in;
	struct opt *o = _conf.cf_ops.o_next;
	int one = 1;

	s = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (s == -1)
		err(1, "socket()");

	memset(&s_in, 0, sizeof(s_in));
	s_in.sin_family      = PF_INET;
	s_in.sin_port        = htons(port);
	s_in.sin_addr.s_addr = _conf.cf_srcip.s_addr;

	if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) == -1)
		err(1, "setsockopt()");

	if (bind(s, (struct sockaddr*) &s_in, sizeof(s_in)) == -1)
		err(1, "bind(%d)", port);

	while (o) {
		xsetsockopt(s, o->o_num, o->o_data, o->o_len);
		o = o->o_next;
	}

	if (_conf.cf_nocache)
		xsetsockopt(s, TCP_CRYPT_NOCACHE, &one, sizeof(one));

	if (_conf.cf_app_support) {
		if (tcpcrypt_setsockopt(s, IPPROTO_TCP, TCP_CRYPT,
					&_conf.cf_app_support,
		            		sizeof(_conf.cf_app_support)) == -1)
			err(1, "tcpcrypt_setsockopt()");
	}

	if (0)	{
		struct linger ling;

		ling.l_onoff = 1;
		ling.l_linger = 0;

		if (setsockopt(s, SOL_SOCKET, SO_LINGER, &ling, sizeof(ling)) 
		    == -1)
			err(1, "setsockopt()");
	}

	return s;
}

static int open_socket(void)
{
	return do_open_socket(_conf.cf_sport);
}

static void print_sid(uint8_t *sid, int len)
{
	xprintf("Session ID: ");

	while (len--)
		xprintf("%.2X", *sid++);

	xprintf("\n");
}

static void print_session(int s)
{
	unsigned char buf[1024];
	unsigned char *sid = buf;
	int rc;
	unsigned int len = sizeof(buf);

	if (!_conf.cf_verbose || _conf.cf_notcpcrypt)
		return;

	if (_conf.cf_kernel) {
		if (getsockopt(s, IPPROTO_TCP, TCP_CRYPT, sid, &len) == -1)
			err(1, "getsockopt()\n");

		assert(len > 0);
		xprintf("App support %d ", sid[0]);
		sid++;
		len--;
	} else {
		rc = tcpcrypt_getsockopt(s, IPPROTO_TCP, TCP_CRYPT_SESSID, sid,
					 &len);
		if (rc) {
			xprintf("No session id\n");
			return;
		}
	}

	print_sid(sid, len);
}

static void close_socket(int s)
{
	struct tls *tls;
	SSL* ssl;

	close(s);

	if (!_conf.cf_ssl)
		return;

	tls = get_tls();
	ssl = tls->t_ssl;
	
	if (!_conf.cf_nocache && !_conf.cf_listen) {
		if (!tls->t_ssl_session) {
			tls->t_ssl_session = SSL_get1_session(ssl);
			if (!tls->t_ssl_session)
				errssl(1, "SSL_get_session()");

			lock();
			if (!SSL_CTX_sess_number(_state.s_ssl_sessions)) {
				if (!SSL_CTX_add_session(_state.s_ssl_sessions,
							 tls->t_ssl_session))
					errssl(1, "SSL_CTX_add_session()");

				assert(SSL_CTX_sess_number(
						_state.s_ssl_sessions));
			}
			unlock();
		} else if (!SSL_session_reused(ssl))
			printf("Warning - session NOT reused\n");
	}

	SSL_set_shutdown(ssl, SSL_SENT_SHUTDOWN);
	SSL_free(ssl);
}

static int do_write(int s, void *data, int len)
{
	if (_conf.cf_ssl)
		return SSL_write(get_ssl(), data, len);

	return write(s, data, len);
}

static int do_read(int s, void *data, int len)
{
	if (_conf.cf_ssl)
		return SSL_read(get_ssl(), data, len);

	return read(s, data, len);
}

static void pipe_io(int s)
{
	unsigned char buf[1024];
	int rc, rc2;
	int max = s;
	fd_set fds;
	int fdz[2];
	int i;
	int done = 0;


	fdz[0] = 0;
	fdz[1] = s;

	while (!done) {
		FD_ZERO(&fds);
		FD_SET(0, &fds);
		FD_SET(s, &fds);

		rc = select(max + 1, &fds, NULL, NULL, NULL);
		if (rc == -1) {
			if (errno == EINTR)
				continue;

			err(1, "select()");
		}

		for (i = 0; i < 2; i++) {
			if (!FD_ISSET(fdz[i], &fds))
				continue;

			if (fdz[i] == 0)
				rc = read(fdz[i], buf, sizeof(buf));
			else
				rc = do_read(fdz[i], buf, sizeof(buf));

			if (rc == -1)
				perror("read()");

			if (rc <= 0) {
				done = 1;
				break;
			}

			if (fdz[!i] == 0)		
				rc2 = write(1, buf, rc);
			else
				rc2 = do_write(fdz[!i], buf, rc);

			if (rc2 == -1)
				perror("write()");

			if (rc2 != rc) {
				done = 1;
				break;
			}
		}
	}
	xprintf("Connection terminated\n");
}

static void server_handle(int s)
{
	pipe_io(s);
}

static SSL_SESSION *ssl_lookup_session(SSL *ssl, unsigned char *data, int len,
				       int *copy)
{
	SSL_SESSION *s = NULL, r;

	memset(&r, 0, sizeof(r));
	r.ssl_version	    = ssl->version;
	r.session_id_length = len;
	memcpy(r.session_id, data, len);

	printf("SSL cache miss\n");
	lock();
	s = lh_retrieve(SSL_CTX_sessions(_state.s_ssl_sessions), &r);
	unlock();

	assert(s);
	*copy = 0;

	return s;
}

static int ssl_new_session(SSL *ssl, SSL_SESSION *sess)
{
	printf("New SSL session\n");
	lock();
	if (!SSL_CTX_add_session(_state.s_ssl_sessions, sess))
		errssl(1, "SSL_CTX_add_session()");
	unlock();

	return 1;
}

static void init_ssl_ctx()
{
	SSL_CTX *ctx;
	char *file = _conf.cf_ssl_file;
	struct tls *tls = get_tls();
	SSL_METHOD *m;

	if (_conf.cf_listen)
		m = TLSv1_server_method();
	else
		m = TLSv1_client_method();

	ctx = SSL_CTX_new(m);
	if (!ctx)
		errssl(1, "SSL_CTX_new()");

	if (!SSL_CTX_set_cipher_list(ctx, _conf.cf_ssl_cipher))
		errssl(1, "SSL_CTX_set_cipher_list()");

	if (!SSL_CTX_use_certificate_file(ctx, file, SSL_FILETYPE_PEM))
		errssl(1, "SSL_CTX_use_certificate_file()");

	if (!SSL_CTX_use_RSAPrivateKey_file(ctx, file, SSL_FILETYPE_PEM))
		errssl(1, "SSL_CTX_use_RSAPrivateKey_file()");

	/* XXX */
        ctx->comp_methods = NULL;

	SSL_CTX_sess_set_get_cb(ctx, ssl_lookup_session);

	if (!_conf.cf_nocache)
		SSL_CTX_sess_set_new_cb(ctx, ssl_new_session);

	tls->t_ssl_ctx = ctx;
}

static void get_session(void *item, void *arg)
{
	SSL_SESSION *s = item, **sp = arg;

	assert(!(*sp));
	*sp = s;
}

static void bind_ssl(int s)
{
	struct tls *tls = get_tls();

	if (!tls->t_ssl_ctx)
		init_ssl_ctx();

	SSL *ssl = SSL_new(tls->t_ssl_ctx);

	if (!ssl)
		errssl(1, "SSL_new()");

	if (!SSL_set_fd(ssl, s))
		errssl(1, "SSL_set_fd()");

	if (!_conf.cf_nocache && !_conf.cf_listen && !tls->t_ssl_session) {
		lock();
		lh_doall_arg(SSL_CTX_sessions(_state.s_ssl_sessions),
			     (LHASH_DOALL_ARG_FN_TYPE) get_session,
			     &tls->t_ssl_session);
		unlock();
	}

	if (tls->t_ssl_session) {
		if (!SSL_set_session(ssl, tls->t_ssl_session))
			errssl(1, "SSL_set_session()");
	}

	tls->t_ssl = ssl;
}

static int do_accept(int s, struct sockaddr* s_in, socklen_t *slen)
{
	int dude;
	int rc;

#ifdef ACCEPT_LOCK
	if (_state.s_do_lock)
		do_lock(&_state.s_accept_mtx);
#endif

	dude = accept(s, s_in, slen);

#ifdef ACCEPT_LOCK
	if (_state.s_do_lock)
		do_unlock(&_state.s_accept_mtx);
#endif

	if (dude == -1)
		return dude;

	if (!_conf.cf_ssl)
		return dude;

	bind_ssl(dude);

	rc = SSL_accept(get_ssl());

	if (!rc) {
		close_socket(dude);
		return -1;
	}

	return dude;
}

static void *server_thread(void *arg)
{
	struct st_arg *sta = arg;
	server_cb cb = sta->sta_cb;
	struct sockaddr_in s_in;
	socklen_t slen = sizeof(s_in);
	int dude;

	do {
		slen = sizeof(s_in);
		dude = do_accept(sta->sta_s, (struct sockaddr*) &s_in, &slen);

		if (dude == -1) {
			printf("Bad accept\n");
			continue;
		}	

		xprintf("Connection from %s:%d\n",
			inet_ntoa(s_in.sin_addr), ntohs(s_in.sin_port));

		print_session(dude);

		cb(dude);
		close_socket(dude);

	} while (_conf.cf_listen > 1);

	free(sta);

	return NULL;
}

static char *get_param(int idx)
{
	if (idx >= _conf.cf_paramn)
		return NULL;

	return _conf.cf_params[idx];
}

static int get_param_num(int idx, int def)
{
	char *p = get_param(idx);

	if (p)
		return atoi(p);

	return def;
}

static void init_lock(pthread_mutex_t *x)
{
	if (pthread_mutex_init(x, NULL))
		err(1, "pthread_mutex_init()");
}

static void ssl_lock(int mode, int n, const char *file, int line)
{
	pthread_mutex_t *t = &_state.s_ssl_locks[n];

	if (mode & CRYPTO_LOCK)
		do_lock(t);
	else
		do_unlock(t);
}

static struct CRYPTO_dynlock_value *ssl_lock_dyn_create(const char *file,
							int line)
{
	struct CRYPTO_dynlock_value *value = xmalloc(sizeof(*value));

	printf("w00t\n");
	pthread_mutex_init(&value->mutex, NULL);

	return value;
}

static void ssl_lock_dyn_lock(int mode, struct CRYPTO_dynlock_value *l,
                              const char *file, int line)
{                               
	if (mode & CRYPTO_LOCK)
		do_lock(&l->mutex);                 
	else
		do_unlock(&l->mutex);
}      

static void ssl_lock_dyn_destroy(struct CRYPTO_dynlock_value *l,
                                 const char *file, int line)             
{
	if (pthread_mutex_destroy(&l->mutex))
		err(1, "pthread_mutex_destroy()");

	free(l);
}                                                                                      

static void init_locks(void)
{
	pthread_mutex_t *t;
	int i;

	init_lock(&_state.s_mtx);
	init_lock(&_state.s_accept_mtx);
	_state.s_do_lock = 1;

	t = xmalloc(sizeof(*t) * CRYPTO_num_locks());

	for (i = 0; i < CRYPTO_num_locks(); i++)
		init_lock(&t[i]);

	_state.s_ssl_locks = t;

	CRYPTO_set_locking_callback(ssl_lock);

	CRYPTO_set_dynlock_create_callback(ssl_lock_dyn_create);
	CRYPTO_set_dynlock_lock_callback(ssl_lock_dyn_lock);
	CRYPTO_set_dynlock_destroy_callback(ssl_lock_dyn_destroy);
}

static void do_test_server(server_cb cb, int port, int more)
{
	pthread_t pt;
	int s;
	struct sockaddr_in s_in;
	socklen_t slen = sizeof(s_in);
	int tc = get_param_num(0, 1);
	struct st_arg *a;

	s = do_open_socket(port);
	_state.s_ss = s;

	if (listen(s, _conf.cf_backlog) == -1)
		err(1, "listen()");

	if (getsockname(s, (struct sockaddr*) &s_in, &slen) == -1)
		err(1, "getsockname()");

	xprintf("Listening on %s:%d\n",
		inet_ntoa(s_in.sin_addr), ntohs(s_in.sin_port));

	a = xmalloc(sizeof(*a));
	memset(a, 0, sizeof(*a));
	a->sta_cb = cb;
	a->sta_s  = s;

	if (more)
		tc++;

	while (--tc) {
		if (pthread_create(&pt, NULL, server_thread, a))
			err(1, "pthread_create()");
	}

	if (!more)
		server_thread(a);
}

static void test_server(server_cb cb)
{
	int tc = get_param_num(0, 1);
	int ports = _conf.cf_ports;
	int i;
	int more = 1;

	if (tc > 1 || ports > 1)
		init_locks();

	for (i = 0; i < ports; i++) {
		more = i + 1 < ports;
		do_test_server(cb, _conf.cf_sport + i, more);
	}
}

static void do_server()
{
	test_server(server_handle);
}

static void client_handle(int s)
{
	pipe_io(s);
}

static int try_connect(int s)
{
	struct sockaddr_in s_in;
	int flags;
	struct timeval tv;

	memset(&s_in, 0, sizeof(s_in));
	s_in.sin_family      = PF_INET;
	s_in.sin_port        = htons(_conf.cf_dport);
	s_in.sin_addr.s_addr = _conf.cf_dstip.s_addr;

	flags = fcntl(s, F_GETFL);
	if (fcntl(s, F_SETFL, flags | O_NONBLOCK) == -1)
		err(1, "fnctl()");

	tv.tv_usec = 0;
	tv.tv_sec  = 5;

	while (connect(s, (struct sockaddr*) &s_in, sizeof(s_in)) == -1) {
		if (errno == EINPROGRESS) {
			fd_set fds;

			FD_ZERO(&fds);
			FD_SET(s, &fds);

			if (select(s + 1, NULL, &fds, NULL, &tv) == -1)
				err(1, "select()");

			if (FD_ISSET(s, &fds))
				break;

			printf("Connect timeout\n");
			close(s);
			return -1;
		}

		if (errno == EADDRNOTAVAIL) {
			struct sockaddr_in s_in2;
			socklen_t len = sizeof(s_in2);

			if (getsockname(s, (struct sockaddr*) &s_in2, &len)
			    == -1)
				err(1, "getsockname()");

			printf("Addr in use %d\n", ntohs(s_in2.sin_port));
			usleep(100000);
			continue;
		}
		err(1, "connect() [%d]", errno);
	}

	if (fcntl(s, F_SETFL, flags) == -1)
		err(1, "fnctl()");

	if (!_conf.cf_ssl)
		return 0;

	bind_ssl(s);

	if (!SSL_connect(get_ssl()))
		errssl(1, "SSL_connect()");

	return 0;
}

static void do_connect(int s)
{
	if (try_connect(s) == -1)
		err(1, "connect()");
}

static void do_client(void)
{
	int s;
	struct sockaddr_in s_in;
	socklen_t slen = sizeof(s_in);

	s = open_socket();
	do_connect(s);

	if (getsockname(s, (struct sockaddr*) &s_in, &slen) == -1)
		err(1, "getsockname()");

	xprintf("Connected from %s:%d",
		inet_ntoa(s_in.sin_addr), ntohs(s_in.sin_port));

	xprintf(" to %s:%d\n",
		inet_ntoa(_conf.cf_dstip), _conf.cf_dport);

	print_session(s);

	client_handle(s);
}


static void pwn(void)
{
	if (_conf.cf_listen)
		do_server();
	else
		do_client();
}

static void test_enable(void)
{
	int s;
	int val;
	unsigned int len;

	s = open_socket();

	len = sizeof(val);
	xgetsockopt(s, TCP_CRYPT_ENABLE, &val, &len);

	xprintf("Enable = %d\n", val);
	TEST_ASSERT(val == 1);

	len = sizeof(val);
	val = 0;
	xsetsockopt(s, TCP_CRYPT_ENABLE, &val, len);

	xprintf("Set to %d\n", val);

	len = sizeof(val);
	xgetsockopt(s, TCP_CRYPT_ENABLE, &val, &len);

	xprintf("Enable is now %d\n", val);
	TEST_ASSERT(val == 0);

	xprintf("Connecting...\n");
	do_connect(s);
	close_socket(s);
}

static void writex(int s, void *p, int len)
{
	int rc = do_write(s, p, len);

	if (rc == -1)
		err(1, "write()");

	if (rc != len)
		errx(1, "wrote %d/%d", rc, len);
}

static int readx(int s, void *p, int len)
{
	int rc = do_read(s, p, len);

	if (rc == -1)
		err(1, "read()");

	if (rc == 0)
		errx(1, "EOF");

	return rc;
}

static void do_latency(struct tls *tls)
{
	struct timeval now;
	int diff;

	if (!_conf.cf_latency)
		return;

	/* init */
	if (tls->t_latency_start.tv_sec == 0) {
		gettimeofday(&tls->t_latency_start, NULL);
		return;
	}

	gettimeofday(&now, NULL);

	if (now.tv_sec == tls->t_latency_start.tv_sec)
		diff = now.tv_usec - tls->t_latency_start.tv_usec;
	else {
		diff  = 1000 * 1000 - tls->t_latency_start.tv_usec;
		diff += now.tv_usec;
		diff += (now.tv_sec - tls->t_latency_start.tv_sec - 1) 
		        * 1000 * 1000;
	}

	assert(diff >= 0);

	tls->t_latency_samples += diff;
	assert(tls->t_latency_samples >= 0);

	tls->t_latency_count++;

//	printf("Latency %d us (%p)\n", diff, tls);

	lock();	
	_state.s_latency_samples += diff;
	assert(_state.s_latency_samples >= 0);
	if (_state.s_latency_count++ >= 1000) {
		printf("LAT %.0f\n", (double) _state.s_latency_samples
				     / (double) _state.s_latency_count);

		_state.s_latency_samples = 0;
		_state.s_latency_count = 0;
	}
	unlock();

	if (tls->t_latency_count == 20) {
		printf("Latency AVG %.0f us (%p)\n",
		       (double) tls->t_latency_samples /
		       (double) tls->t_latency_count,
		       tls);

		tls->t_latency_samples = tls->t_latency_count = 0;
	}

	memcpy(&tls->t_latency_start, &now, sizeof(tls->t_latency_start));
}

static void do_speed_add(unsigned int sample)
{
	struct tls *tls;

	if (_conf.cf_stats_amortize == 0)
		return;

	tls = get_tls();

	tls->t_stat_samples += sample;
	assert(tls->t_stat_samples >= 0);
	tls->t_stat_count++;

	do_latency(tls);

	if (tls->t_stat_count < _conf.cf_stats_amortize)
		return;

	lock();
	speed_add(tls->t_stat_samples);
	unlock();

	if (_conf.cf_data_collector) {
		unsigned char sample = tls->t_stat_samples;

		assert(sample == tls->t_stat_samples);

		if (write(_conf.cf_data_collector, &sample, 1) != 1)
			err(1, "write()");
	}

	tls->t_stat_samples = 0;
	tls->t_stat_count   = 0;
}

static void delay_server(int s)
{
	unsigned char x = 0x69;

	writex(s, &x, sizeof(x));

	/* wait for remote disconnect */
	do_read(s, &x, sizeof(x));
}

static void throughput_server(int s)
{
	unsigned char buf[4096 * 5];
	int rc;
	int len = sizeof(buf);
	unsigned char buf2[sizeof(buf)];
        unsigned char *key = (unsigned char*) "aaaaaaaaaaaaaaaa";
        unsigned char iv[16];
        AES_KEY aes_key;
        int enc = get_param_num(1, 0);
        umac_ctx_t umac_ctx;

	memset(buf, 0x69, len);
#ifdef HAVE_NI
        aesni_set_encrypt_key(key, 128, &aes_key);
#endif
        umac_ctx = umac_new(key);
        printf("Will encrypt: %d\n", enc);

	while (1) {
		if (enc) {
			int x = len;

#ifdef HAVE_NI
                       aesni_cbc_encrypt(buf, buf2, len, &aes_key, iv, 1);
#endif
#if 0
			while (x > 0) {	
				int y = x;

				if (y > 1400)
					y = 1400;

                       		umac_reset(umac_ctx);
                       		umac_update(umac_ctx, buf, y);
                       		umac_final(umac_ctx, buf, iv);

				x -= y;
			}
#endif
               }

		rc = do_write(s, buf, len);
		if (rc == -1)
			break;

		if (rc != len)
			break;

		do_speed_add(len);
	}
}

static void echo_server(int s)
{
	unsigned char buf[4096];
	int rc;

	while (1) {
		rc = do_read(s, buf, sizeof(buf));
		if (rc <= 0)
			break;

		writex(s, buf, rc);
	}
}

static void test_delay_server(void)
{
	test_server(delay_server);
}

static void test_echo_server(void)
{
	test_server(echo_server);
}

static void test_delay_client(void)
{
	int s;
	unsigned char x;
	struct timeval a, b, c;
	unsigned int diff;

	while (1) {
		s = open_socket();

		gettimeofday(&a, NULL);

		do_connect(s);
		gettimeofday(&b, NULL);

		x = readx(s, &x, sizeof(x));
		assert(x == sizeof(x));
		gettimeofday(&c, NULL);

		close_socket(s);

		diff = time_diff(&a, &c);
		printf("Connect %u us first byte %u us\n",
		       time_diff(&a, &b), diff);

		sample_add(diff);
		usleep(100000);
	}
}

static unsigned int throughput_client_cb(float speed, unsigned int avg)
{
	unsigned int rate;

	speed *= 8.0;
	rate = (unsigned int) speed;

	printf("%u Mbit/s [%u]\n", rate, avg);

	return rate;
}

static void test_throughput_server(void)
{
	speed_start(throughput_client_cb);
	test_server(throughput_server);
}

static void test_throughput_client(void)
{
	int s;
	char buf[4096 * 10];
	int rc;

	s = open_socket();
	do_connect(s);

	speed_start(throughput_client_cb);

	while (1) {
		rc = readx(s, buf, sizeof(buf));
		assert(rc > 0);
		do_speed_add(rc);
	}
}

static void test_rtt_client(void)
{
	int s;
	struct timeval a, b;
	unsigned int diff;
	int rc;

	s = open_socket();
	do_connect(s);

	while (1) {
		gettimeofday(&a, NULL);
		writex(s, &a, sizeof(a));

		rc = readx(s, &a, sizeof(a));
		gettimeofday(&b, NULL);

		assert(rc == sizeof(b));

		diff = time_diff(&a, &b);

		printf("RTT %u\n", diff);
		sample_add(diff);
		usleep(100000);
	}
}

static void set_nonblocking(int s)
{
	int flagz = fcntl(s, F_GETFL);

	if (flagz == -1)
		err(1, "fcntl(F_GETFL)");

	if (fcntl(s, F_SETFL, flagz | O_NONBLOCK) == -1)
		err(1, "fcntl(F_SETFL)");
}

static void test_send_race(void)
{
	int s;
	char x[] = "FUCK";

	s = open_socket();

	if (0)
		set_nonblocking(s);

	do_connect(s);
	writex(s, x, sizeof(x) - 1);
	close_socket(s);
}

static void do_1b_server(int s)
{
	unsigned char x = 0x69;

        if (do_write(s, &x, sizeof(x)) != sizeof(x)) {
                perror("do_write()");
                return;
        }

	do_speed_add(1);
}

static void cmac(void *out, void *in, int len)
{
	struct tls *tls = get_tls();
	CMAC_CTX* ctx = tls->t_cmac;
	int l = len;

	if (!tls->t_cmac) {
		unsigned char key[16];

		ctx = CMAC_CTX_new();
		assert(ctx);

		memset(key, 0, sizeof(key));

		if (!CMAC_Init(ctx, key, sizeof(key),
			       EVP_get_cipherbyname("AES128"), NULL))
			errx(1, "CMAC_Init()");

		tls->t_cmac = ctx;
	}

	if (!CMAC_Init(ctx, NULL, 0, NULL, NULL))
		errx(1, "CMAC_Init()");

	CMAC_Update(ctx, in, len);
	if (!CMAC_Final(ctx, out, &l))
		errx(1, "CMAC_Final()");
}

static void send_cmac(int s, unsigned char *crap, unsigned char *out, int idx,
		      int sc, int so)
{
	memcpy(crap, _mac_label[idx], 6);
	memcpy(&crap[6], _state.s_sid, sizeof(_state.s_sid));
	crap[15] = 0;

	cmac(out, crap, sc);

	writex(s, out, so);
}

static void do_cmac(int s, int idx)
{
	unsigned char crap[sizeof(_state.s_sid) + 6 + 1];
	unsigned char out[sizeof(crap)];
	int rc;

	send_cmac(s, crap, out, idx, sizeof(crap), sizeof(out));

	memcpy(crap, _mac_label[!idx], 6);
	cmac(out, crap, sizeof(crap));

	rc = readx(s, crap, sizeof(crap));
	if (rc != sizeof(crap))
		errx(1, "readx()");

	if (memcmp(out, crap, sizeof(out)) != 0)
		errx(1, "CMAC mismatch");

	if (idx == 0)
		do_speed_add(1);
}

static void readxx(int s, void *buf, int len)
{
	int rc;
	unsigned char *p = buf;

	while (len > 0) {
		rc   = readx(s, p, len);
		len -= rc;
		p   += rc;
	}
	assert(len == 0);
}

static void verify_cmac(int s, unsigned char *crap, unsigned char *in,
			unsigned char *out, int sc, int si, int so)
{
	memcpy(crap, _mac_label[1], 6);
	memcpy(&crap[6], _state.s_sid, sizeof(_state.s_sid));
	crap[15] = 0;

	cmac(out, crap, sc);

	readxx(s, in, si);

	if (memcmp(out, in, so) != 0) {
//		errx(1, "CMAC mismatch");
		printf("CMAC mismatch\n");
	}
}

static void do_mac_server(int s)
{
	unsigned char crap[sizeof(_state.s_sid) + 6 + 1];
	unsigned char in[sizeof(crap)];
	unsigned char out[sizeof(crap)];

	verify_cmac(s, crap, in, out, sizeof(crap), sizeof(in), sizeof(out));

	memcpy(crap, _mac_label[0], 6);
	cmac(out, crap, sizeof(crap));

	writex(s, out, sizeof(out));

	do_speed_add(1);

//	do_cmac(s, 0);
}

static struct batch *get_batch(void)
{
	struct batch *b;

//	do_lock(&_state.s_batch_mtx);
	b = _state.s_batch_free.b_next;
	assert(b);
	_state.s_batch_free.b_next = b->b_next;
	b->b_next = NULL;
//	do_unlock(&_state.s_batch_mtx);

	return b;
}

static void put_batch(struct batch *b)
{
	struct batch *active;

	do_lock(&_state.s_batch_mtx);

	b->b_ready.s_state = 0;
	assert(b->b_ref == 0);
//	memset(b->b_data, 0, sizeof(b->b_data));
	b->b_len = 0;

	active = &_state.s_batch_active;
	while (1) {
		assert(active->b_next);
		if (active->b_next == b) {
			active->b_next = b->b_next;
			break;
		}

		active = active->b_next;
	}

	b->b_next = _state.s_batch_free.b_next;
	_state.s_batch_free.b_next = b;
	
	do_unlock(&_state.s_batch_mtx);
}

static void do_sem_notify(struct sem *s, int all)
{
	do_lock(&s->s_mtx);

	if (s->s_state == 1)
		goto __out;

	s->s_state = 1;

	if (all) {
		s->s_state++;
		if (pthread_cond_broadcast(&s->s_sem))
			err(1, "pthread_cond_signal()");
	} else if (pthread_cond_signal(&s->s_sem))
		err(1, "pthread_cond_signal()");

__out:
	do_unlock(&s->s_mtx);
}

static void sem_notify(struct sem *s)
{
	do_sem_notify(s, 0);
}

static int do_sem_wait(struct sem *s, struct timespec *ts)
{
	int rc = 0;

	do_lock(&s->s_mtx);

	if (s->s_state == 0) {
		if (ts) {
			rc = pthread_cond_timedwait(&s->s_sem, &s->s_mtx, ts);
			if (rc) {
				if (rc != ETIMEDOUT)
					errx(1, "pthread_cond_timedwait()");
			}
		} else if (pthread_cond_wait(&s->s_sem, &s->s_mtx))
			err(1, "pthread_cond_wait()");
	} else if (s->s_state == 1)
		s->s_state = 0;

	do_unlock(&s->s_mtx);

	return rc;
}

static void sem_wait(struct sem *s)
{
	do_sem_wait(s, NULL);
}

static struct batch *get_sig(void **sig, int *siglen)
{
	struct batch *b;
	int id;

	if (_conf.cf_auth_cache) {
		// XXX lock
		if (_state.s_batch_siglen) {
			*sig    = _state.s_batch_sig;
			*siglen = _state.s_batch_siglen;
			return NULL;
		}
	}

	/* queue work */
	xprintf("SERVER: queue work\n");
	do_lock(&_state.s_batch_mtx);
	b = _state.s_batch_queue.b_next;

	while (b) {
		if (b->b_ref < _state.s_batch_num)
			break;

		b = b->b_next;
	}
	assert(b);

	id = b->b_ref++;
	memcpy(&b->b_data[b->b_len], _state.s_sid,
	       sizeof(_state.s_sid));

	b->b_len += sizeof(_state.s_sid);

	if (b->b_ref == _state.s_batch_num) {
		assert(b->b_next == NULL);
		b->b_next = get_batch();
		do_unlock(&_state.s_batch_mtx);
		sem_notify(&_state.s_signer_wait);
	} else
		do_unlock(&_state.s_batch_mtx);

	/* wait for batch to complete */
	xprintf("SERVER: waiting for ready\n");
	sem_wait(&b->b_ready);

	*sig    = b->b_data;
	*siglen = b->b_len;

	return b;
}

static void do_sign_server(int s)
{
	struct batch *b;
	int id;
	uint32_t *len;
	void *sig;
	int slen = sizeof(b->b_data);

	b = get_sig(&sig, &slen);

	/* write cert */
	len = (uint32_t*) _state.s_batch_cert;
	*len++ = htonl(_state.s_batch_cert_len);
	*len++ = htonl(slen);

	writex(s, _state.s_batch_cert, _state.s_batch_cert_len + 8);

	/* write sig */
	writex(s, sig, slen);

	if (b) {
		/* drop batch */
		do_lock(&b->b_mtx);
		b->b_ref--;
		assert(b->b_ref >= 0);
		id = b->b_ref;
		do_unlock(&b->b_mtx);

		xprintf("SERVER: done\n");

		if (id == 0) {
			xprintf("SERVER: releasing batch\n");
			put_batch(b);
		}
	}

	if (_state.s_batch_cmac) {
		unsigned char crap[sizeof(_state.s_sid) + 6 + 1];
		unsigned char in[sizeof(crap)];
		unsigned char out[sizeof(crap)];

		verify_cmac(s, crap, in, out, sizeof(crap), sizeof(in),
			    sizeof(out));
	}

	do_speed_add(1);
}

static unsigned int throughput_connect_cb(float sample, unsigned int avg)
{
	unsigned int rate = (unsigned int) (sample * 1000.0 * 1000.0);

	printf("%u connect/s [avg %u]\n", rate, avg);

	return rate;
}

static void test_1b_server(void)
{
	speed_start(throughput_connect_cb);
	test_server(do_1b_server);
}

static void test_mac_server(void)
{
	speed_start(throughput_connect_cb);
	test_server(do_mac_server);
}

static PAKE *get_pake(void)
{
	struct tls *tls = get_tls();
	PAKE *pi = tls->t_pake;

	if (!pi) {
		tls->t_pake = pi = xmalloc(sizeof(*pi));

		pi->pi_priv = pake_setup();
		if (!pi->pi_priv)
			errx(1, "pake_setup()");

		HMAC_CTX_init(&pi->pi_hmac);
		HMAC_Init_ex(&pi->pi_hmac, "ao", 2, EVP_sha1(), NULL);
	}

	assert(pi);

	return pi;
}

static void do_pake(int s, int client)
{
	unsigned char *key;
	PAKE *pi = get_pake();
	unsigned char sid[21];
	unsigned char out[20];
	unsigned int len = sizeof(out);

	if (client)
		key = pake_client(pi->pi_priv, s);
	else
		key = pake_server(pi->pi_priv, s);

	if (!key)
		errx(1, "pake()");

	memset(sid, 0, sizeof(sid));
	sid[20] = client;
	HMAC_Init_ex(&pi->pi_hmac, key, SHA256_DIGEST_LENGTH, NULL, NULL);
	HMAC_Update(&pi->pi_hmac, sid, sizeof(sid));
	HMAC_Final(&pi->pi_hmac, out, &len);
	assert(len == sizeof(out));

	writex(s, out, sizeof(out));

	/* verify */
	readxx(s, out, sizeof(out));
	sid[20] = !client;
	HMAC_Init_ex(&pi->pi_hmac, NULL, 0, NULL, NULL);
	HMAC_Update(&pi->pi_hmac, sid, sizeof(sid));
	HMAC_Final(&pi->pi_hmac, sid, &len);

	if (memcmp(out, sid, sizeof(out)) != 0)
		errx(1, "pake mismatch");
}

static void do_pake_server(int s)
{
	do_pake(s, 0);
	do_speed_add(1);
}

static void test_pake_server(void)
{
	speed_start(throughput_connect_cb);
	test_server(do_pake_server);
}

static void do_signer(void)
{
	struct batch *b;
	int rc = -1;
	struct timespec ts;
	struct timespec *t;
	int to = 0;
	static int first = 0;
	int excess;
	void *p;
	int plen;

	/* wait for work */
	while (1) {
		do_lock(&_state.s_batch_mtx);
		b = _state.s_batch_queue.b_next;
		assert(b);

		xprintf("SIGNER: waiting for work %d %d\n",
			b->b_ref, _state.s_batch_num);

		if (b->b_ref < _state.s_batch_num) {
			if (to && b->b_ref)
				break;

			do_unlock(&_state.s_batch_mtx);

			if (!first) {
				printf("Fuck calling clock\n");
#if _POSIX_TIMERS > 0
				clock_gettime(CLOCK_REALTIME, &ts);
#else
				struct timeval tv;
				gettimeofday(&tv, NULL);
				ts.tv_sec = tv.tv_sec;
				ts.tv_nsec = tv.tv_usec*1000;
#endif
				ts.tv_sec += 5;
				t = &ts;
			} else
				t = NULL;

			if (!_conf.cf_auth_cache)
				printf("I don't have a queue\n");

			to = do_sem_wait(&_state.s_signer_wait, t);
			if (to)
				printf("Timeout\n");
			continue;
		}

		assert(b->b_ref == _state.s_batch_num);
		break;
	}

	first = 1;

	/* dequeue */
	xprintf("SIGNER: dequeue\n");
	_state.s_batch_queue.b_next = b->b_next;
	if (!_state.s_batch_queue.b_next)
		_state.s_batch_queue.b_next = get_batch();

	/* set active */
	b->b_next = _state.s_batch_active.b_next;
	_state.s_batch_active.b_next = b;
	do_unlock(&_state.s_batch_mtx);

	/* work on batch */
	if (_conf.cf_auth_cache && _state.s_batch_siglen) {
		assert(sizeof(b->b_data) >= _state.s_batch_siglen);
		memcpy(b->b_data, _state.s_batch_sig, _state.s_batch_siglen);
		b->b_len = _state.s_batch_siglen;
		goto __done;
	}

	excess = b->b_len - ((RSA_size(_state.s_batch_rsa) - 11));
	if (excess > 0) {
		assert(sizeof(b->b_data) 
		       >= (b->b_len + SHA_DIGEST_LENGTH + 11));

		excess += SHA_DIGEST_LENGTH;

		if (!SHA1_Init(&_state.s_batch_sha))
			errssl(1, "SHA1_Init()");

		if (!SHA1_Update(&_state.s_batch_sha, b->b_data, excess))
			errssl(1, "SHA1_Update()");

		if (!SHA1_Final(b->b_data + b->b_len, &_state.s_batch_sha))
			err(1, "SHA1_Final()");

		b->b_len += SHA_DIGEST_LENGTH + 11;
		plen      = RSA_size(_state.s_batch_rsa) - 11;
		p         = &b->b_data[b->b_len - RSA_size(_state.s_batch_rsa)];
	} else {
		p        = b->b_data;
		plen     = b->b_len;
		b->b_len = RSA_size(_state.s_batch_rsa);
	}

	rc = RSA_private_encrypt(plen, p, p, _state.s_batch_rsa,
				 RSA_PKCS1_PADDING);
	if (rc == -1)
		errssl(1, "RSA_private_encrypt()");

__done:
	if (_conf.cf_auth_cache && (_state.s_batch_siglen == 0)) {
		assert(b->b_len <= sizeof(_state.s_batch_sig));
		memcpy(_state.s_batch_sig, b->b_data, b->b_len);

		lock();
		_state.s_batch_siglen = b->b_len;
		unlock();
	}

	/* tell the world we're done */
	xprintf("SIGNER: done\n");
	do_sem_notify(&b->b_ready, 1);
}

static void *signer(void *arg)
{
	while (1) {
		do_signer();

		if (_state.s_batch_siglen)
			break;
	}

	return NULL;
}

static void sem_init(struct sem *s)
{
	memset(s, 0, sizeof(*s));

	if (pthread_mutex_init(&s->s_mtx, NULL))
		err(1, "pthread_mutex_init()");

	if (pthread_cond_init(&s->s_sem, NULL))
		err(1, "pthread_cond_init()");
}

static void launch_signer(void)
{
	pthread_t x;
	int i;
	FILE *f;
	X509 *cert;
	unsigned char *out;
	struct batch *b;

	sem_init(&_state.s_signer_wait);
	_state.s_batch_num = get_param_num(1, 1);
	xprintf("Batch num: %d\n", _state.s_batch_num);

	if (pthread_mutex_init(&_state.s_batch_mtx, NULL))
		err(1, "pthread_mutex_init()");

	for (i = 0; i < 100; i++) {
		b = xmalloc(sizeof(*b));

		memset(b, 0, sizeof(*b));
		sem_init(&b->b_ready);

		if (pthread_mutex_init(&b->b_mtx, NULL))
			err(1, "pthread_mutex_init()");

		b->b_next = _state.s_batch_free.b_next;
		_state.s_batch_free.b_next = b;
	}

	_state.s_batch_queue.b_next = get_batch();

	f = fopen(_conf.cf_ssl_file, "r");
	if (!f)
		err(1, "fopen()");

	_state.s_batch_rsa = PEM_read_RSAPrivateKey(f, NULL, NULL, NULL);
	if (!_state.s_batch_rsa)
		err(1, "PEM_read_RSAPrivateKey()");

	fseek(f, 0L, SEEK_SET);

	cert = PEM_read_X509(f, NULL, NULL, NULL);
	if (!cert)
		err(1, "PEM_read_X509()");

	fclose(f);

	out = NULL;
	_state.s_batch_cert_len = i2d_X509(cert, &out);
	if (_state.s_batch_cert_len < 0)
		err(1, "i2d_X509()");

	OPENSSL_free(out);

	/* leave 8 bytes for length header */
	out = xmalloc(_state.s_batch_cert_len + 8);
	_state.s_batch_cert = out;

	out += 8;

	if (i2d_X509(cert, &out) != _state.s_batch_cert_len)
		err(1, "i2d_X509()");

	assert((unsigned long) out == 
	       ((unsigned long) _state.s_batch_cert 
	        + _state.s_batch_cert_len + 8));

	printf("Cert len %d\n", _state.s_batch_cert_len);

	if (pthread_create(&x, NULL, signer, NULL))
		err(1, "pthread_create()");
}

static void test_sign_server(void)
{
	_state.s_batch_cmac = get_param_num(2, 0);

	launch_signer();
	speed_start(throughput_connect_cb);
	test_server(do_sign_server);
}

static void client1b(int s)
{
	unsigned char x;

	readx(s, &x, 1);
}

static void do_tp_client(client_cb cb)
{
	int s;
	struct tls *tls = get_tls();
	int port;

	if (!tls->t_sport) {
		lock();
		tls->t_sport    = _conf.cf_sport;
		_conf.cf_sport += _conf.cf_port_spacing;
		unlock();
	}

	port = tls->t_sport + tls->t_sport_off++;
	if (tls->t_sport_off == _conf.cf_port_spacing)
		tls->t_sport_off = 0;

	do {
		s = do_open_socket(port);
	} while (try_connect(s) != 0);

	cb(s);
	close_socket(s);
}

static void *connect_tp_thread(void *arg)
{
	while (1) {
		do_tp_client((client_cb) arg);
		do_speed_add(1);
	}
}

static void do_test_tp_client(client_cb cb)
{
	int tc;
	pthread_t pt;

	tc = get_param_num(0, 1);

	/* XXX */
	if (!_conf.cf_sport)
		_conf.cf_sport = 10666;

	if (tc > 1) {
		init_locks();
		do_tp_client(cb); /* Get a session ID */
	}

	speed_start(throughput_connect_cb);

	while (--tc) {
		if (pthread_create(&pt, NULL, connect_tp_thread, (void*) cb))
			err(1, "pthread_create()");
	}

	connect_tp_thread((void*) cb);
}

static void test_connect_tp_client(void)
{
	do_test_tp_client(client1b);
}

static void client_web(int s)
{
	char buf[1024];
	static char req[1024];
	static int len = 0;
	int rc;

	if (!len) {
		char *url = get_param(1);

		strcpy(req, "GET / HTTP/1.0\n\n");

		if (url)
			snprintf(req, sizeof(req), "GET %s HTTP/1.0\n\n", url);

		len = strlen(req);
	}

	writex(s, req, len);

	while (1) {
		rc = do_read(s, buf, sizeof(buf));
		if (rc == -1)
			err(1, "read()");

		if (rc == 0)
			break;

		if (_conf.cf_verbose) {
			buf[rc] = 0;
			printf("%s", buf);
		}
	}
}

static void client_mac(int s)
{
	do_cmac(s, 1);
}

static void client_pake(int s)
{
	do_pake(s, 1);
}

static void test_web_client(void)
{
	do_test_tp_client(client_web);
}

static void test_mac_client(void)
{
	do_test_tp_client(client_mac);
}

static void test_pake_client(void)
{
	do_test_tp_client(client_pake);
}

static void client_sign(int s)
{
	unsigned char crap[4096];
	uint32_t lena, lenb;
#ifdef VERIFY_SIGN
	int rc;
	const unsigned char *in;
	X509 *cert;
	EVP_PKEY *key;
	RSA *rsa;
	unsigned char *sid;
#endif

	readxx(s, &lena, sizeof(lena));
	readxx(s, &lenb, sizeof(lenb));

	lena = ntohl(lena);
	lenb = ntohl(lenb);

	assert(lena <= sizeof(crap));
	readxx(s, crap, lena);

#ifdef VERIFY_SIGN
	in = crap;
	cert = d2i_X509(NULL, &in, lena);
	if (!cert)
		errssl(1, "d2i_X509()");
#endif

	assert(lenb <= sizeof(crap));
	readxx(s, crap, lenb);

#ifdef VERIFY_SIGN
	key = X509_get_pubkey(cert);
	assert(key);

	rsa = key->pkey.rsa;

	lena = RSA_public_decrypt(lenb, crap, crap, rsa, RSA_PKCS1_PADDING);
	if (lena < 0)
		errssl(1, "RSA_public_decrypt()");

	sid = crap;
	while (lena >= sizeof(_state.s_sid)) {
		if (memcmp(sid, _state.s_sid, sizeof(_state.s_sid)) == 0)
			break;

		lena -= sizeof(_state.s_sid);
		sid  += sizeof(_state.s_sid);
	}
	assert(lena >= sizeof(_state.s_sid));

	EVP_PKEY_free(key);
	X509_free(cert);
#endif

	if (_state.s_batch_cmac) {
		unsigned char crap[sizeof(_state.s_sid) + 6 + 1];
		unsigned char out[sizeof(crap)];

		send_cmac(s, crap, out, 1, sizeof(crap), sizeof(out));
	}
}

static void test_sign_client(void)
{
	_state.s_batch_cmac = get_param_num(1, 0);

	do_test_tp_client(client_sign);
}

static void print_ciphers(const OBJ_NAME *o, void *a)
{
	static char x = 0;
	char f;

	f = o->name[0];

	if (isupper(f))
		return;

	if (x && (f != x))
		printf("\n");

	x = f;

	printf("%s ", o->name);
}

static struct crypto *find_builtin(struct crypto *c, int num, char *name)
{
	while (num--) {
		if (strcmp(c->c_name, name) == 0)
			return c;

		c++;
	}

	return NULL;
}

static void print_builtin(struct crypto *c, int num)
{
	while (num--) {
		printf("%s\n", c->c_name);

		c++;
	}
}

static void setup_null(void)
{
}

static void do_null(int len)
{
}

static struct crypto _ciphers[] = {
	{ setup_null, do_null,			"null" },
};

static void do_cipher_ssl(int len)
{
	unsigned char buf[1024];
	int x = sizeof(buf);

	assert(len <= sizeof(buf));

	if (!EVP_EncryptUpdate(&_state.s_test_cipher, buf, &x, buf, len))
		errssl(1, "EVP_EncryptUpdate()");

	assert(len == x);
}

static void setup_cipher(char *name)
{
	const EVP_CIPHER *c;
	unsigned char buf[1024];
	int len = sizeof(buf);
	struct crypto *cr;

	cr = find_builtin(_ciphers, ARRAY_SIZE(_ciphers), name);
	if (cr) {
		cr->c_setup();
		_state.s_cipher = cr->c_do;
		return;
	}

	c = EVP_get_cipherbyname(name);
	if (!c) {
		printf("Unknown cipher %s.  Possible values:\n", name);

		print_builtin(_ciphers, ARRAY_SIZE(_ciphers));

		OBJ_NAME_do_all_sorted(OBJ_NAME_TYPE_CIPHER_METH,
				       print_ciphers, NULL);

		printf("\n");
		exit(1);
	}

	memset(buf, 0, sizeof(buf));

//	assert(EVP_CIPHER_iv_length(c) == 0);
	assert(EVP_CIPHER_key_length(c) <= sizeof(buf));
	assert(len % EVP_CIPHER_block_size(c) == 0);

	EVP_CIPHER_CTX_init(&_state.s_test_cipher);
	if (!EVP_EncryptInit_ex(&_state.s_test_cipher, c, NULL, buf, NULL))
		errssl(1, "EVP_EncryptInit_ex()");

	_state.s_cipher = do_cipher_ssl;
}

static void do_cipher(int len)
{
	assert(_state.s_cipher);
	_state.s_cipher(len);
}

static void test_cipher(void)
{
	char *name = get_param(0);
	int len = 1024;

	if (!name)
		errx(1, "need cipher name [-x]");

	setup_cipher(name);

	speed_start(throughput_client_cb);

	while (1) {
		do_cipher(len);
		speed_add(len);
	}
}

static void do_umac(int len)
{
	static char nonce[8];
	static char out[1024];
	static char *buf = NULL;

	if (!buf) {
		buf = malloc(len * 2);
		assert(buf);
		buf += 16 - ((unsigned long) buf % 16);
		assert((unsigned long) buf % 16 == 0);
	}

	umac_reset(_state.s_test_umac);
	umac_update(_state.s_test_umac, buf, len);
	umac_final(_state.s_test_umac, out, nonce);
}

static void setup_umac(void)
{
	char buf[1024];

	_state.s_test_umac = umac_new(buf);
	assert(_state.s_test_umac);
}

#ifdef POLY1305AES
#include "poly1305aes.h"

static void setup_poly1305aes(void)
{
	poly1305aes_clamp(_state.s_test_poly1305aes);
}

static void do_poly1305aes(int len)
{
	unsigned char buf[1024];
	unsigned char out[16];
	unsigned char nonce[16];

	assert(len <= sizeof(buf));

	poly1305aes_authenticate(out, _state.s_test_poly1305aes, nonce, buf,
				 len);
}
#endif /* POLY1305AES */

static struct crypto _macs[] = {
	{ setup_umac, do_umac,			"umac" },
	{ setup_null, do_null,			"null" },
#ifdef POLY1305AES
	{ setup_poly1305aes, do_poly1305aes,	"poly1305aes" },
#endif
};

static void do_mac(int len)
{
	assert(_state.s_mac);
	_state.s_mac(len);
}

static void do_hmac(int len)
{
	unsigned char buf[1024];
	unsigned int out = sizeof(buf);

	assert(len <= sizeof(buf));

	HMAC_Init_ex(&_state.s_test_hmac, NULL, 0, NULL, NULL);
	HMAC_Update(&_state.s_test_hmac, buf, len);
	HMAC_Final(&_state.s_test_hmac, buf, &out);
}

static void do_md(int len)
{
	unsigned char buf[1024];
	unsigned int out = sizeof(buf);

	assert(len <= sizeof(buf));

	if (!EVP_DigestInit_ex(&_state.s_test_md, _state.s_test_mdp, NULL))
		errssl(1, "EVP_DigestInit_ex()");

	if (!EVP_DigestUpdate(&_state.s_test_md, buf, len))
		errssl(1, "EVP_DigestUpdate()");

	if (!EVP_DigestFinal_ex(&_state.s_test_md, buf, &out))
		errssl(1, "EVP_DigestFinal_ex()");
}

static void setup_mac(char *name)
{
	const EVP_MD *c;
	unsigned char buf[1024];
	int len = sizeof(buf);
	char *hmac = "hmac-";
	struct crypto *cr;

	cr = find_builtin(_macs, ARRAY_SIZE(_macs), name);
	if (cr) {
		cr->c_setup();
		_state.s_mac = cr->c_do;
		return;
	}

	if (strncmp(name, hmac, strlen(hmac)) == 0) {
		name += strlen(hmac);
	} else
		hmac = NULL;

	c = EVP_get_digestbyname(name);
	if (!c) {
		printf("Unknown digest %s.  Possible values:\n", name);

		print_builtin(_macs, ARRAY_SIZE(_macs));

		OBJ_NAME_do_all_sorted(OBJ_NAME_TYPE_MD_METH,
				       print_ciphers, NULL);

		printf("\n");
		exit(1);
	}

	memset(buf, 0, sizeof(buf));

	if (hmac) {
		HMAC_CTX_init(&_state.s_test_hmac);
		HMAC_Init_ex(&_state.s_test_hmac, buf, len, c, NULL);
		_state.s_mac = do_hmac;
	} else {
		EVP_MD_CTX_init(&_state.s_test_md);
		_state.s_test_mdp = c;
		_state.s_mac	  = do_md;
	}
}

static void test_mac(void)
{
	char *name = get_param(0);
	int len = 1024;

	if (!name)
		errx(1, "need mac or digest name [-x]");

	setup_mac(name);

	speed_start(throughput_client_cb);

	while (1) {
		do_mac(len);
		speed_add(len);
	}
}

static void do_checksum(int len)
{
	unsigned char buf[1024];

	assert(len <= sizeof(buf));
	checksum(buf, len);
}

static void test_checksum(void)
{
	int len = 1024;

	speed_start(throughput_client_cb);

	while (1) {
		do_checksum(len);
		speed_add(len);
	}	
}

static void test_enc_mac_check(void)
{
	int len      = 1024;
	char *mac    = get_param(0);
	char *cipher = get_param(1);

	if (!mac || !cipher)
		errx(1, "select mac + cipher [-x -x]");

	setup_cipher(cipher);
	setup_mac(mac);

	printf("MAC: %s Cipher: %s\n", mac, cipher);

	speed_start(throughput_client_cb);

	while (1) {
		do_cipher(len);
		do_mac(len);
		do_checksum(len);
		speed_add(len);
	}
}

static void fork_child()
{
	int dude;

	while (1) {
		dude = do_accept(_state.s_ss, NULL, NULL);
		writex(dude, "i", 1);
		close(dude);
	}

	exit(0);
}

static void test_fork_server(void)
{
	int children = get_param_num(0, 1);
	int i;
	int pid;

	_state.s_ss = open_socket();

	if (listen(_state.s_ss, _conf.cf_backlog) == -1)
		err(1, "listen()");

	for (i = 0; i < children; i++) {
		pid = fork();
		if (pid == -1)
			err(1, "fork()");

		if (pid == 0)
			fork_child();
	}

	wait(NULL);
}

static void *do_udp_sink(void *x)
{
	int s = (int) (unsigned long) x;
	char buf[1024];
	uint64_t a, b;
	int count = 0;
	int samples = 0;
	int diff;
	int first = 1;

	while (1) {
		a = get_tsc();
		readxx(s, buf, 1);
		b = get_tsc();

		if (first) {
			first = 0;
			continue;
		}

		diff = b - a;
		if (diff <= 0)
			printf("wtf %d %llu %llu\n",
			       diff, b, a);

		assert(diff >= 0);
		samples += diff;
		assert(samples >= 0);

		if (++count == 10000) {
			printf("avg %d\n", 
			       (int) ((double) samples / (double) count));
			samples = 0;
			count = 0;
		}

		do_speed_add(1);
	}
}

static void test_udp_sink(void)
{
	int s;
	struct sockaddr_in s_in;
	int t = get_param_num(0, 1);
	pthread_t pt;

	if (t > 1)
		init_locks();

	memset(&s_in, 0, sizeof(s_in));
	s_in.sin_family = PF_INET;
	s_in.sin_port   = htons(_conf.cf_sport);

	if ((s = socket(s_in.sin_family, SOCK_DGRAM, IPPROTO_UDP)) == -1)
		err(1, "socket()");

	if (bind(s, (struct sockaddr*) &s_in, sizeof(s_in)) == -1)
		err(1, "bind()");

	speed_start(throughput_connect_cb);

	while (--t) {
		if (pthread_create(&pt, NULL, do_udp_sink, (void*) (long) s) 
		    == -1)
			err(1, "pthread_create()");
	}

	do_udp_sink((void*) (long) s);
}

static void test_udp_client(void)
{
	int s;
	struct sockaddr_in s_in;
	char buf[1024];

	memset(&s_in, 0, sizeof(s_in));
	s_in.sin_family = PF_INET;
	s_in.sin_port   = htons(_conf.cf_dport);
	s_in.sin_addr.s_addr = _conf.cf_dstip.s_addr;

	if ((s = socket(s_in.sin_family, SOCK_DGRAM, IPPROTO_UDP)) == -1)
		err(1, "socket()");

	if (connect(s, (struct sockaddr*) &s_in, sizeof(s_in)) == -1)
		err(1, "connect9)");

	speed_start(throughput_connect_cb);
	while (1) {
		writex(s, buf, 1);
		do_speed_add(1);
	}
}

static void test_data_collector(void)
{
	int fd;
	unsigned char buf[1024];
	int rc;
	unsigned char *p;

	unlink(_data_collector);

	if (mknod(_data_collector, 0666 | S_IFIFO, 0) == -1)
		err(1, "mknod()");

	if ((fd = open(_data_collector, O_RDONLY)) == -1)
		err(1, "open()");

	speed_start(throughput_connect_cb);

	while (1) {
		rc = read(fd, buf, sizeof(buf));
		if (rc == -1)
			err(1, "read()");

		if (rc == 0) {
			printf("EOF\n");
			sleep(1);
			continue;
		}

		p = buf;
		while (rc--)
			do_speed_add(*p++);
	}

	close(fd);
}

static void init_ssl()
{
	struct tls *tls;

	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();

	if (!_conf.cf_ssl)
		return;

	init_ssl_ctx();
	tls = get_tls();
	_state.s_ssl_sessions = tls->t_ssl_ctx;
	tls->t_ssl_ctx = NULL;
}

static void test_rsa_encrypt(void)
{
	FILE *f;
	RSA *rsa;
	unsigned char in[4096];
	unsigned char out[4096];
	int len  = 128;
	int test = get_param_num(0, 1);
	int dec = 0;

	init_ssl();

	f = fopen(_conf.cf_ssl_file, "r");
	if (!f)
		err(1, "fopen()");

	rsa = PEM_read_RSAPrivateKey(f, NULL, NULL, NULL);
	if (!rsa)
		err(1, "PEM_read_RSAPrivateKey()");

	speed_start(throughput_connect_cb);

	switch (test) {
		case 2:
			dec = 1;
		case 1:
			goto __1;

		case 4:
			dec = 1;
		case 3:
			goto __3;


		default:
			errx(1, "dunno\n");
			break;

	}

__1:
	printf("RSA_private_encrypt(RSA_PKCS1_PADDING) - i.e., sign\n");
	while (1) {
		if (RSA_private_encrypt(len, in, out, rsa, RSA_PKCS1_PADDING)
		    == -1)
			errssl(1, "RSA_private_encrypt()");

		if (dec)
			break;

		do_speed_add(1);
	}

	printf("RSA_public_decrypt(RSA_PKCS1_PADDING) - i.e., verify\n");
	while (1) {
		if (RSA_public_decrypt(RSA_size(rsa), out, in, rsa,
				       RSA_PKCS1_PADDING) == -1)
			errssl(1, "RSA_public_decrypt()");

		do_speed_add(1);
	}

__3:
	printf("RSA_public_encrypt(RSA_PKCS1_OAEP_PADDING) - i.e., encrypt\n");
	while (1) {
		if (RSA_public_encrypt(len, in, out, rsa,
				       RSA_PKCS1_PADDING) == -1)
			errssl(1, "RSA_public_encrypt()");

		if (dec)
			break;

		do_speed_add(1);
	}

	printf("RSA_private_decrypt(RSA_PKCS1_OAEP_PADDING) - i.e., decrypt\n");
	while (1) {
		if (RSA_private_decrypt(RSA_size(rsa), out, in, rsa,
				       RSA_PKCS1_PADDING) == -1)
			errssl(1, "RSA_private_decrypt()");

		do_speed_add(1);
	}

}

static void shutdown_ssl(SSL *s)
{
	if (SSL_shutdown(s) == 0) {
		if (SSL_shutdown(s) == -1)
			errssl(1, "SSL_shutdown()");
	}
}

static void test_ssl_server(void)
{
	BIO *bio, *dude;
	char url[64];
	SSL *s;
	int rc;
	struct tls *tls = get_tls();

	if (!tls->t_ssl_ctx)
		init_ssl_ctx();

	if (!(s = SSL_new(tls->t_ssl_ctx)))
		errssl(1, "SSL_new()");

	snprintf(url, sizeof(url), "%d", _conf.cf_sport);

	if (!(bio = BIO_new_accept(url)))
		errssl(1, "BIO_new_accept()");

	if (BIO_do_accept(bio) <= 0)
		errssl(1, "BIO_do_accept() - setup");

	/* no wonder nobody uses this API... it fucking sucks */
	if (BIO_do_accept(bio) <= 0)
		errssl(1, "BIO_do_accept() - accept");

	dude = BIO_pop(bio);
	assert(dude);

	SSL_set_bio(s, dude, dude);

	if (SSL_accept(s) <= 0)
		errssl(1, "SSL_accept()");

	strcpy(url, "hi from server");

	if (SSL_write(s, url, strlen(url)) != strlen(url))
		errssl(1, "SSL_write()");

	rc = SSL_read(s, url, sizeof(url) - 1);
	if (rc <= 0)
		errssl(1, "SSL_read()");

	url[rc] = 0;

	printf("Server got [%s]\n", url);

	shutdown_ssl(s);

	BIO_free(dude);
	BIO_free(bio);
}

static void test_ssl_client(void)
{
	BIO *bio;
	char url[64];
	struct tls *tls = get_tls();
	SSL *s;
	int rc;

	if (!tls->t_ssl_ctx)
		init_ssl_ctx();

	if (!(s = SSL_new(tls->t_ssl_ctx)))
		errssl(1, "SSL_new()");

	snprintf(url, sizeof(url), "%s:%d",
		 inet_ntoa(_conf.cf_srcip), _conf.cf_dport);

	if (!(bio = BIO_new_connect(url)))
		errssl(1, "BIO_s_connect()");

	if (BIO_do_connect(bio) <= 0)
		errssl(1, "BIO_do_connect()");

	SSL_set_bio(s, bio, bio);

	if (SSL_connect(s) <= 0)
		errssl(1, "SSL_connect()");

	if ((rc = SSL_read(s, url, sizeof(url) - 1)) <= 0)
		errssl(1, "SSL_read()");

	url[rc] = 0;

	printf("Client got [%s]\n", url);

	strcpy(url, "hi from client");

	if (SSL_write(s, url, strlen(url)) != strlen(url))
		errssl(1, "SSL_write()");

	shutdown_ssl(s);

	BIO_free(bio);
}

static void test_aes_ni(void)
{
	int len   = 1400;
	unsigned char *buf;
	unsigned char *key = (unsigned char*) "aaaaaaaaaaaaaaaa";
	AES_KEY aes_key;
	unsigned char iv[16];

	buf = xmalloc(len);
#ifdef HAVE_NI
	aesni_set_encrypt_key(key, 128, &aes_key);
#endif
	speed_start(throughput_client_cb);

	while (1) {
#ifdef HAVE_NI
		aesni_cbc_encrypt(buf, buf, len, &aes_key, iv, 1);
#endif
		do_speed_add(len);
	}
}

static void test_cmac(void)
{
	int len   = 1400;
	unsigned char *buf;
	unsigned char key[16];
	CMAC_CTX* ctx;
	const EVP_CIPHER *evp;
	size_t x;
	ENGINE *e;

	buf = xmalloc(len);

	ctx = CMAC_CTX_new();
	assert(ctx);

	ENGINE_load_builtin_engines();

	evp = EVP_get_cipherbyname("AES128");
	e   = ENGINE_by_id("aesni");

	assert(evp);
	assert(e);

	if (!CMAC_Init(ctx, key, sizeof(key), evp, e))
		errx(1, "CMAC_Init()");

	speed_start(throughput_client_cb);

	while (1) {
		if (!CMAC_Init(ctx, NULL, 0, NULL, NULL))
			errx(1, "CMAC_Init()");

		CMAC_Update(ctx, buf, len);

		x = len;

		if (!CMAC_Final(ctx, buf, &x))
			errx(1, "CMAC_Final()");

		do_speed_add(len);
	}
}

static void test_aes_umac_throughput(void)
{
        int len   = 1400;
        unsigned char *buf;
        unsigned char key[16];
        unsigned char iv[16];
        umac_ctx_t umac_ctx;
        AES_KEY aes_key, aes_key2;

        buf = xmalloc(len);

#ifdef HAVE_NI
        aesni_set_encrypt_key(key, 128, &aes_key);
#endif
	AES_set_encrypt_key(key, 128, &aes_key2);

        umac_ctx = umac_new(key);

        speed_start(throughput_client_cb);

        while (1) {                                                                
#ifdef HAVE_NI
                aesni_cbc_encrypt(buf, buf, len, &aes_key, iv, 1);                 
#endif
//		AES_cbc_encrypt(buf, buf, len, &aes_key2, iv, 1);
                umac_reset(umac_ctx);
                umac_update(umac_ctx, buf, len);
                umac_final(umac_ctx, buf, iv);

                do_speed_add(len);
        }
}

static void test_pmac(void)
{
	int len = 1400;
	unsigned char *buf;
	unsigned char key[16];
	unsigned char out[16];
	keystruct *keys = NULL;
	int do_ocb = get_param_num(0, 0);

	buf = xmalloc(len);

	keys = ocb_aes_init(key, 16, NULL);

	if (do_ocb)
		printf("doing ocb\n");
	else
		printf("doing pmac\n");

	speed_start(throughput_client_cb);

	while (1) {
		if (do_ocb)
			ocb_aes_encrypt(keys, out, buf, len, buf, out);
		else
			pmac_aes(keys, buf, len, out);

		do_speed_add(len);
	}
}

static void test_udp_server(void)
{
	int s;
	struct sockaddr_in s_in;
	unsigned char buf[4096];
	int rc;

	if ((s = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
		err(1, "sockt()");

	memset(&s_in, 0, sizeof(s_in));
	s_in.sin_family	     = PF_INET;
	s_in.sin_addr.s_addr = INADDR_ANY;
	s_in.sin_port	     = htons(_conf.cf_sport);

	if (bind(s, (struct sockaddr*) &s_in, sizeof(s_in)) == -1)
		err(1, "bind()");

	speed_start(throughput_client_cb);

	while (1) {
		rc = recv(s, buf, sizeof(buf), 0);
		if (rc == 0)
			break;

		if (rc == -1)
			err(1, "recv()");

		do_speed_add(rc);
	}
}

static void test_udp_throughput_client(void)
{
	int s;
	struct sockaddr_in s_in;
	unsigned char buf[4096];
	int rc;
	int len = 1400;

	if ((s = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
		err(1, "sockt()");

	memset(&s_in, 0, sizeof(s_in));
	s_in.sin_family	     = PF_INET;
	s_in.sin_addr.s_addr = _conf.cf_dstip.s_addr;
	s_in.sin_port	     = htons(_conf.cf_dport);

	speed_start(throughput_client_cb);

	while (1) {
		rc = sendto(s, buf, len, 0,
			    (struct sockaddr*) &s_in,
			    sizeof(s_in));

		if (rc == -1)
			err(1, "sendto()");

		if (rc != len)
			errx(1, "short send!");

		do_speed_add(rc);
	}
}

static void test_set_key(void)
{
	RSA* r;
	int i, s;
	unsigned char stuff[4096];
	int len = 0;

	printf("Generating key...\n");

        r = RSA_generate_key(2048, 3, NULL, NULL);
        if (!r) 
                errssl(1, "RSA_generate_key()");

	do {
		BIGNUM* bn[] = { r->n,
				 r->e,
				 r->d,
				 r->p,
				 r->q,
				 r->dmp1,
				 r->dmq1,
				 r->iqmp };

		for (i = 0; i < sizeof(bn) / sizeof(*bn); i++) {
			len += BN_bn2mpi(bn[i], &stuff[len]);
			assert(len <= sizeof(stuff));
		}
	} while (0);

	RSA_free(r);

//	printf("KEY %d\n", len);
//	hexdump(stuff, len);

	printf("Setting\n");

	s = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (s == -1)
		err(1, "socket()");

	xsetsockopt(s, TCP_CRYPT_RSA_KEY, stuff, len);

	close(s);

	printf("DONE!\n");
}

static struct test _tests[] = {
	{ test_enable,			"ENABLE sockopt" },
	{ test_delay_server,		"Delay server" },
	{ test_delay_client,		"Delay client" },
	{ test_throughput_server,	"Throughput server" },
	{ test_throughput_client,	"Throughput client" },
	{ test_send_race,		"Send race" },
	{ test_echo_server,		"Echo server" },
	{ test_rtt_client,		"RTT client" },
	{ test_1b_server,		"Send 1 byte server" },
	{ test_connect_tp_client,	"Connect throughput client" },
	{ test_cipher,			"Cipher throughput" },
	{ test_mac,			"MAC throughput" },
	{ test_checksum,		"Checksum throughput" },
	{ test_enc_mac_check,		"Encrypt, MAC, checksum" },
	{ test_web_client,		"web client" },
	{ test_mac_server,		"MAC server" },
	{ test_mac_client,		"MAC client" },
	{ test_sign_server,		"sign server" },
	{ test_sign_client,		"sign client" },
	{ test_fork_server,		"fork server" },
	{ test_udp_sink,		"udp sink" },
	{ test_udp_client,		"udp client" },
	{ test_data_collector,		"data collector" },
	{ test_rsa_encrypt,		"RSA performance" },
	{ test_ssl_server,		"SSL tcpcrypt-enabled server" },
	{ test_ssl_client,		"SSL tcpcrypt-enabled client" },
	{ test_pake_server,		"pake server" },
	{ test_pake_client,		"pake client" },
	{ test_aes_ni,			"AES NI throughput" },
	{ test_cmac,			"CMAC throughput" },
	{ test_pmac,			"PMAC or OCB throughput" },
	{ test_udp_server,		"UDP throughput server" },
	{ test_udp_throughput_client,	"UDP throughput client" },
        { test_aes_umac_throughput,     "AES + UMAC throughput" },
	{ test_set_key,			"tcpcrypt kernel set rsa key" },
};

static void do_test()
{
	struct test* t;

	if (_conf.cf_test >= sizeof(_tests) / sizeof(*_tests))
		errx(1, "Test out of range");

	t = &_tests[_conf.cf_test];

	printf("Running test %d: %s\n",
	       _conf.cf_test, t->t_desc);

	t->t_cb();

	printf("Test PASSED\n");
}

static void set_opt_len(struct opt *o, int len)
{
	o->o_len = len;

	o->o_data = malloc(o->o_len);
	if (!o->o_data)
		err(1, "malloc()");
}

static void do_hex_option(struct opt *o, char *p)
{
	int len = strlen(p);
	int x;
	uint8_t *data;

	if (len & 1)
		errx(1, "odd hex data %s", p);

	set_opt_len(o, len >> 1);
	data = o->o_data;

	while (len > 1) {
		char tmp[3];

		snprintf(tmp, sizeof(tmp), "%s", p);

		if (sscanf(tmp, "%x", &x) != 1)
			err(1, "bad hex data %s", tmp);

		*data++ = x & 0xff;

		p += 2;
		len -= 2;
	}
	assert(len == 0);
}

static void add_opt(char *opt)
{
	char optnum[16];
	char *p;
	struct opt *o;

	p = strchr(opt, ':');
	if (!p)
		errx(1, "bad opt %s - lookin for :", opt);

	assert(p - opt < sizeof(optnum));
	snprintf(optnum, p - opt + 1, "%s", opt);
	p++;

	o = malloc(sizeof(*o));
	memset(o, 0, sizeof(*o));

	o->o_num = atoi(optnum);

	switch (o->o_num) {
	case TCP_CRYPT_ENABLE:
	case TCP_CRYPT_CMODE:
	case TCP_CRYPT_NOCACHE:
		set_opt_len(o, 4);
		*((int*) o->o_data) = atoi(p);
		break;

	default:
		do_hex_option(o, p);
		break;
	}

	o->o_next = _conf.cf_ops.o_next;
	_conf.cf_ops.o_next = o;
}

static void usage(char *progname)
{
	int i;

	printf("Usage: %s <opts> <ip> <port>\n"
	       "-h\thelp\n"
	       "-u\t<ctl unix socket path>\n"
	       "-l\tlisten\n"
	       "-p\t<local port>\n"
	       "-v\tverbose\n"
	       "-t\t<test num>\n"
	       "-o\t<setsockopt opt:val>\n"
	       "-c\tno session cache\n"
	       "-x\t<param>\n"
	       "-s\tSSL\n"
	       "-S\t<SSL certificate + key file>\n"
	       "-C\t<SSL cipher suite>\n"
	       "-n\tnotcpcrypt\n"
	       "-d\t<samples to discard>\n"
	       "-b\t<backlog>\n"
	       "-a\t<stats amortize>\n"
	       "-D\tdata collector\n"
	       "-A\tauth cache\n"
	       "-P\t<num ports>\n"
	       "-B\ttcpcrypt app support on\n"
	       "-k\tkernel version\n"
	       "-L\tmeasure latency\n"
	       , progname);

	printf("\nTests:\n");

	for (i = 0; i < sizeof(_tests) / sizeof(*_tests); i++)
		printf("%d) %s\n", i, _tests[i].t_desc);
}

static void add_param(char *p)
{
	if (_conf.cf_paramn 
	    >= sizeof(_conf.cf_params) / sizeof(*_conf.cf_params))
		err(1, "too many params");

	_conf.cf_params[_conf.cf_paramn++] = p;
}

int main(int argc, char *argv[])
{
	int ch;
	int t = 0;

	memset(&_state, 0, sizeof(_state));

	_conf.cf_ssl_file	= "server.pem";
	_conf.cf_ssl_cipher   	= "AES128-SHA";
	_conf.cf_discard      	= 3;
	_conf.cf_dport	      	= 666;
	_conf.cf_port_spacing 	= 10;
	_conf.cf_backlog      	= 128;
	_conf.cf_stats_amortize = 1;
	_conf.cf_ports		= 1;

	inet_aton("127.0.0.1", &_conf.cf_dstip);
        umask(0);

	while ((ch = getopt(argc, argv, "hu:lp:vt:o:cx:snS:d:NC:b:a:DAP:kBL"))
		!= -1) {
		switch (ch) {
		case 'L':
			_conf.cf_latency = 1;
			break;

		case 'B':
			_conf.cf_app_support = 1;
			break;

		case 'k':
			_conf.cf_kernel = 1;
			break;

		case 'P':
			_conf.cf_ports = atoi(optarg);
			break;

		case 'A':
			_conf.cf_auth_cache = 1;
			break;

		case 'D':
			_conf.cf_data_collector = open(_data_collector,
						       O_WRONLY);

			if (_conf.cf_data_collector == -1)
				err(1, "open()");

			break;

		case 'a':
			_conf.cf_stats_amortize = atoi(optarg);
			break;

		case 'b':
			_conf.cf_backlog = atoi(optarg);
			break;

		case 'C':
			_conf.cf_ssl_cipher = optarg;
			break;

		case 'd':
			_conf.cf_discard = atoi(optarg);
			break;

		case 'S':
			_conf.cf_ssl_file = optarg;
			/* fall through */
		case 's':
			_conf.cf_ssl = 1;
			/* fallthrough */
		case 'n':
			_conf.cf_notcpcrypt = 1;
			break;

		case 'x':
			add_param(optarg);
			break;

		case 'c':
			_conf.cf_nocache = 1;
			break;

		case 'o':
			add_opt(optarg);
			break;

		case 'l':
			_conf.cf_listen++;
			break;

		case 'v':
			_conf.cf_verbose++;
			break;

		case 'p':
			_conf.cf_sport = atoi(optarg);
			break;

		case 'u':
			tcpcrypt_setparam(TCPCRYPT_PARAM_CTLPATH, optarg);
			break;

		case 't':
			t = 1;
			_conf.cf_test = atoi(optarg);
			break;

		case 'h':
		default:
			usage(argv[0]);
			exit(1);
		}
	}

	if ((optind + 2) <= argc) {
		inet_aton(argv[optind], &_conf.cf_dstip);
		_conf.cf_dport = atoi(argv[optind + 1]);
	}

	if (_conf.cf_listen && !_conf.cf_sport)
		_conf.cf_sport = _conf.cf_dport;

	if (signal(SIGINT, sig) == SIG_ERR)
		err(1, "signal()");

	if (signal(SIGTERM, sig) == SIG_ERR)
		err(1, "signal()");

	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR)
		err(1, "signal()");

	init_ssl();

	profile_setopt(PROFILE_DISCARD, _conf.cf_discard);
	profile_setopt(PROFILE_ENABLE, 1);

	if (t)
		do_test();
	else
		pwn();

	cleanup();
	exit(0);
}
