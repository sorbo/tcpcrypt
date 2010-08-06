#include <net/tcp.h>
                
#include <linux/compiler.h>
#include <linux/module.h>

/* null tcpcrypt implementation */
static int tcp_crypt_init(struct sock *sk)
{
	return 0;
}

static void tcp_crypt_destroy(struct sock *sk)
{
}

static int tcp_crypt_create_openreq_child(struct sock *parent,
                                          struct sock *newsk,
                                          struct request_sock *req)
{
	return 0;
}

static int tcp_crypt_send(struct sock *sk,
			  struct request_sock *rsk,
			  struct sk_buff *skb)
{
	return 0;
}

static int tcp_crypt_recv(struct sock *sk,
			  struct request_sock *req,
			  struct sk_buff *skb)
{
	return 0;
}

static int tcp_crypt_register_crypto(struct tcpcrypt_crypto *crypto)
{
	return -1;
}

static int tcp_crypt_unregister_crypto(struct tcpcrypt_crypto *crypto)
{
	return -1;
}

static int tcp_crypt_setsockopt(struct sock *sk, void *optval, int len)
{
	return -1;
}

static int tcp_crypt_getsockopt(struct sock *sk, void *optval, int *len)
{
	return -1;
}

static struct tcp_crypt_ops tcp_crypt_null = {
	.tc_init		 = tcp_crypt_init,
	.tc_destroy		 = tcp_crypt_destroy,
	.tc_create_openreq_child = tcp_crypt_create_openreq_child,
	.tc_send		 = tcp_crypt_send,
	.tc_recv		 = tcp_crypt_recv,
	.tc_register_crypto	 = tcp_crypt_register_crypto,
	.tc_unregister_crypto	 = tcp_crypt_unregister_crypto,
	.tc_setsockopt		 = tcp_crypt_setsockopt,
	.tc_getsockopt		 = tcp_crypt_getsockopt,
};

static struct tcp_crypt_ops *tcp_crypt_ops;
static DEFINE_MUTEX(tcp_crypt_ops_mutex);

int tcp_set_tcpcrypt(struct tcp_crypt_ops *ops)
{
	mutex_lock(&tcp_crypt_ops_mutex);
	tcp_crypt_ops = ops;
	mutex_unlock(&tcp_crypt_ops_mutex);

	return 0;
}

struct tcp_crypt_ops *tcp_get_tcpcrypt(void)
{
	struct tcp_crypt_ops *ops;

	mutex_lock(&tcp_crypt_ops_mutex);
	ops = tcp_crypt_ops;
	mutex_unlock(&tcp_crypt_ops_mutex);

	return ops ? ops : &tcp_crypt_null;
}

EXPORT_SYMBOL(tcp_set_tcpcrypt);
EXPORT_SYMBOL(tcp_get_tcpcrypt);
