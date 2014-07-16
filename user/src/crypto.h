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
	void		  (*co_mac_ack)(struct tc *tc, void *data, int len, void
					*out, int *olen);
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
	void	(*co_extract)(struct tc *c, struct iovec *iov, int num, void
			     *out, int *outlen);
	void	(*co_expand)(struct tc *c, uint8_t tag, int len, void *out);
};

struct cipher_list {
	struct crypt_ops	*c_cipher;
	struct cipher_list	*c_next;
};

extern void crypto_init(struct tc *tc);
extern void crypto_finish(struct tc *tc);
extern void crypto_next_iv(struct tc *tc, void *out, int *outlen);
extern void crypto_mac(struct tc *tc, struct iovec *iov, int num,
		       void *iv, void *out, int *outlen);
extern void crypto_mac_ack(struct tc *tc, void *data, int len, void *out,
			   int *olen);
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

/* low-level interface */

struct crypt {
	void	*c_priv;
	void	(*c_destroy)(struct crypt *c);
	int	(*c_set_key)(struct crypt *c, void *key, int len);
	int	(*c_get_key)(struct crypt *c, void **out);
	void	(*c_mac)(struct crypt *, struct iovec *iov, int num, void *out,
		         int *outlen);
	void	(*c_extract)(struct crypt *c, struct iovec *iov, int num,
			     void *out, int *outlen);
	void	(*c_expand)(struct crypt *c, uint8_t tag, int len, void *out);
	void	(*c_encrypt)(struct crypt *c, void *iv, void *data, int len);
	int	(*c_decrypt)(struct crypt *c, void *iv, void *data, int len);
};

extern struct crypt *crypt_HMAC_SHA256_new(void);
extern struct crypt *crypt_HKDF_SHA256_new(void);
extern struct crypt *crypt_RSA_new(void);

extern struct crypt *crypt_init(int sz);

static inline void crypt_destroy(struct crypt *c)
{
	c->c_destroy(c);
}

static inline int crypt_set_key(struct crypt *c, void *key, int len)
{
	return c->c_set_key(c, key, len);
}

static inline int crypt_get_key(struct crypt *c, void **out)
{
	return c->c_get_key(c, out);
}

static inline void crypt_mac(struct crypt *c, struct iovec *iov, int num,
			     void *out, int *outlen)
{
	c->c_mac(c, iov, num, out, outlen);
}

static inline void *crypt_priv(struct crypt *c)
{
	return c->c_priv;
}

static inline void crypt_extract(struct crypt *c, struct iovec *iov, int num,
				 void *out, int *outlen)
{
	c->c_extract(c, iov, num, out, outlen);
}

static inline void crypt_expand(struct crypt *c, uint8_t tag, int len,
				void *out)
{
	c->c_expand(c, tag, len, out);
}

static inline void crypt_encrypt(struct crypt *c, void *iv, void *data, int len)
{
	c->c_encrypt(c, iv, data, len);
}

static inline int crypt_decrypt(struct crypt *c, void *iv, void *data, int len)
{
	return c->c_decrypt(c, iv, data, len);
}

#endif /* __TCPCRYPT_CRYPTO_H__ */
