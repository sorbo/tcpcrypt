#ifndef __TCPCRYPT_CRYPTO_H__
#define __TCPCRYPT_CRYPTO_H__

typedef void *(*crypt_ctr)(void);

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
};

struct cipher_list {
	unsigned int		c_id;
	int			c_type;
	crypt_ctr		c_ctr;
	struct cipher_list	*c_next;

	struct crypt_ops	*c_cipher;
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
	int     (*c_encrypt)(struct crypt *c, void *iv, void *data, int len);
	int	(*c_decrypt)(struct crypt *c, void *iv, void *data, int len);
};

extern struct crypt *crypt_HMAC_SHA256_new(void);
extern struct crypt *crypt_HKDF_SHA256_new(void);
extern struct crypt *crypt_RSA_new(void);

extern struct crypt *crypt_init(int sz);
extern void crypt_register(int type, unsigned int id, crypt_ctr ctr);

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

static inline int crypt_encrypt(struct crypt *c, void *iv, void *data, int len)
{
	return c->c_encrypt(c, iv, data, len);
}

static inline int crypt_decrypt(struct crypt *c, void *iv, void *data, int len)
{
	return c->c_decrypt(c, iv, data, len);
}

static inline void *crypt_new(crypt_ctr ctr)
{
	crypt_ctr *r = ctr();

	*r = ctr;

	return r;
}

/* pub crypto */

struct crypt_pub {
	crypt_ctr    cp_ctr;		/* must be first */
	struct crypt *cp_hkdf;
	struct crypt *cp_pub;
	int	     cp_n_c;
	int	     cp_n_s;
	int	     cp_k_len;
	int	     cp_max_key;
	int	     cp_cipher_len;
};

static inline void crypt_pub_destroy(struct crypt_pub *cp)
{
	crypt_destroy(cp->cp_hkdf);
	crypt_destroy(cp->cp_pub);
	free(cp);
}

#endif /* __TCPCRYPT_CRYPTO_H__ */
