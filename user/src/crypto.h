#ifndef __TCPCRYPT_CRYPTO_H__
#define __TCPCRYPT_CRYPTO_H__

enum {
	TYPE_PKEY = 0,
	TYPE_SYM,
	TYPE_MAC,
};

struct crypt_prop {
	int	cp_ivlen;
	int	cp_ivmode;
	int	cp_maclen;
	int	cp_cipherlen;
	int	cp_noncelen;
	int	cp_noncelen_s;
	int	cp_preference;
	int	cp_rekey;
	int	cp_keylen;
};

struct crypt_ops {
	void		  (*co_init)(struct tc *tc);
	void		  (*co_finish)(struct tc *tc);
	void		  (*co_next_iv)(struct tc *tc, void *out, int *outlen);
	void		  (*co_mac)(struct tc *tc, struct iovec *iov, int num,
				    void *iv, void *out, int *outlen);
	void		  (*co_encrypt)(struct tc *tc, void *iv, void *data,
					int len);
	int		  (*co_decrypt)(struct tc *tc, void *iv, void *data,
					int len);
	int		  (*co_get_key)(struct tc *tc, void **out);
	int		  (*co_set_key)(struct tc *tc, void *key, int len);
	void		  *(*co_spec)(void);
	int		  (*co_type)(void);
	void		  (*co_mac_set_key)(struct tc *tc, void *key, int len);
	void		  (*co_set_keys)(struct tc *tc, struct tc_keys *keys);
	struct crypt_prop *(*co_crypt_prop)(struct tc *tc);
};

struct cipher_list {
	struct crypt_ops	*c_cipher;
	struct cipher_list	*c_next;
};

extern struct crypt_ops _hmac_ops;

extern void crypto_init(struct tc *tc);
extern void crypto_finish(struct tc *tc);
extern void crypto_next_iv(struct tc *tc, void *out, int *outlen);
extern void crypto_mac(struct tc *tc, struct iovec *iov, int num,
		       void *iv, void *out, int *outlen);
extern void crypto_encrypt(struct tc *tc, void *iv, void *data, int len);
extern int  crypto_decrypt(struct tc *tc, void *iv, void *data, int len);
extern void crypto_register(struct crypt_ops *ops);
extern int  crypto_get_key(struct tc *tc, void **out);
extern int  crypto_set_key(struct tc *tc, void *key, int len);
extern void crypto_mac_set_key(struct tc *tc, void *key, int len);
extern void crypto_set_keys(struct tc *tc, struct tc_keys *keys);
extern void *crypto_priv(struct tc *tc);
extern void *crypto_priv_init(struct tc *tc, int sz);

extern struct crypt_prop  *crypto_prop(struct tc *tc);
extern struct cipher_list *crypto_cipher_list(void);
extern struct crypt_ops	  *crypto_find_cipher(int type, int id);

#endif /* __TCPCRYPT_CRYPTO_H__ */
