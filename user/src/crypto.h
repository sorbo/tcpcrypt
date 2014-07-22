#ifndef __TCPCRYPT_CRYPTO_H__
#define __TCPCRYPT_CRYPTO_H__

typedef void *(*crypt_ctr)(void);

enum {
	TYPE_PKEY = 0,
	TYPE_SYM,
};

struct cipher_list {
	unsigned int		c_id;
	int			c_type;
	crypt_ctr		c_ctr;
	struct cipher_list	*c_next;
};

extern struct cipher_list *crypt_cipher_list(void);

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
	void	(*c_expand)(struct crypt *c, void *tag, int taglen,
			    void *out, int outlen);
	int     (*c_encrypt)(struct crypt *c, void *iv, void *data, int len);
	int	(*c_decrypt)(struct crypt *c, void *iv, void *data, int len);
	int	(*c_compute_key)(struct crypt *c, void *out);
};

extern struct crypt *crypt_HMAC_SHA256_new(void);
extern struct crypt *crypt_HKDF_SHA256_new(void);
extern struct crypt *crypt_AES_new(void);
extern struct crypt *crypt_RSA_new(void);
extern struct crypt *crypt_ECDHE256_new(void);
extern struct crypt *crypt_ECDHE521_new(void);

extern struct crypt *crypt_init(int sz);
extern void crypt_register(int type, unsigned int id, crypt_ctr ctr);
extern struct cipher_list *crypt_find_cipher(int type, unsigned int id);

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

static inline void crypt_expand(struct crypt *c, void *tag, int taglen,
				void *out, int outlen)
{
	c->c_expand(c, tag, taglen, out, outlen);
}

static inline int crypt_encrypt(struct crypt *c, void *iv, void *data, int len)
{
	return c->c_encrypt(c, iv, data, len);
}

static inline int crypt_decrypt(struct crypt *c, void *iv, void *data, int len)
{
	return c->c_decrypt(c, iv, data, len);
}

static inline int crypt_compute_key(struct crypt *c, void *out)
{
	return c->c_compute_key(c, out);
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
	int	     cp_min_key;
	int	     cp_max_key;
	int	     cp_cipher_len;
	int	     cp_key_agreement;
};

static inline void crypt_pub_destroy(struct crypt_pub *cp)
{
	crypt_destroy(cp->cp_hkdf);
	crypt_destroy(cp->cp_pub);
	free(cp);
}

/* sym crypto */

struct crypt_sym {
	crypt_ctr	cs_ctr;		/* must be first */
	struct crypt	*cs_cipher;
	struct crypt	*cs_mac;
	struct crypt	*cs_ack_mac;
	int		cs_mac_len;
	int		cs_iv_len;
};

static inline void crypt_sym_destroy(struct crypt_sym *cs)
{
	crypt_destroy(cs->cs_cipher);
	crypt_destroy(cs->cs_mac);
	crypt_destroy(cs->cs_ack_mac);
	free(cs);
}

#endif /* __TCPCRYPT_CRYPTO_H__ */
