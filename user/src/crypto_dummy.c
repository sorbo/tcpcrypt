#include <time.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "inc.h"
#include "tcpcrypt_ctl.h"
#include "tcpcrypt.h"
#include "tcpcryptd.h"
#include "crypto.h"

#if 0
#define MAC_SIZE	20

static struct tc_cipher_spec _dummy_pkey_spec =
        { 0, TC_DUMMY };

static struct crypt_prop _dummy_pkey_prop =
	{ 0, IVMODE_NONE, MAC_SIZE, 256 };

static struct tc_scipher _dummy_mac_spec =
        { TC_DUMMY };

static struct tc_scipher _dummy_sym_spec =
        { TC_DUMMY };

static void dummy_init(struct tc *tc)
{
}

static void dummy_finish(struct tc *tc)
{
}

static void dummy_mac(struct tc *tc, struct iovec *iov, int num, void *iv,
		      void *out, int *outlen)
{
	if (*outlen >= MAC_SIZE)
		memset(out, 0, MAC_SIZE);

	*outlen = MAC_SIZE;
}

static uint32_t *get_len(void *data)
{
	uint32_t* x = (uint32_t*) ((unsigned long) data 
				   + _dummy_pkey_prop.cp_cipherlen);

	return --x;
}

static void dummy_pkey_encrypt(struct tc *tc, void *iv, void *data, int len)
{
	uint32_t *l = get_len(data);

	assert(len + 4 <= _dummy_pkey_prop.cp_cipherlen);

	*l = htonl(len);
}

static int dummy_pkey_decrypt(struct tc *tc, void *iv, void *data, int len)
{
	uint32_t *l = get_len(data);

	assert(len == _dummy_pkey_prop.cp_cipherlen);

	return htonl(*l);
}

static void dummy_encrypt(struct tc *tc, void *iv, void *data, int len)
{
}

static int dummy_decrypt(struct tc *tc, void *iv, void *data, int len)
{
	return len;
}

static int dummy_get_key(struct tc *tc, void **out)
{
	static int len = 128;
	static void *key;

	if (!key)
		key = xmalloc(len);

	*out = key;

	return len;
}

static void *dummy_pkey_spec(void)
{       
        return &_dummy_pkey_spec;
}

static int dummy_pkey_type(void)
{
	return TYPE_PKEY;
}

static int dummy_set_key(struct tc *tc, void *key, int len)
{
	return 4;
}

static void dummy_mac_set_key(struct tc *tc, void *key, int len)
{
}

struct crypt_prop *dummy_pkey_prop(struct tc *tc)
{
	return &_dummy_pkey_prop;
}

static int dummy_mac_type(void)
{
	return TYPE_MAC;
}

static int dummy_sym_type(void)
{
	return TYPE_SYM;
}

static void *dummy_mac_spec(void)
{
	return &_dummy_mac_spec;
}

static void *dummy_sym_spec(void)
{
	return &_dummy_sym_spec;
}

static void dummy_next_iv(struct tc *tc, void *out, int *outlen)
{
        assert(*outlen == 0);

        *outlen = 0;
}

static struct crypt_ops _dummy_pkey = {
        .co_init        = dummy_init,
        .co_finish      = dummy_finish,
        .co_encrypt     = dummy_pkey_encrypt,
        .co_decrypt     = dummy_pkey_decrypt,
        .co_get_key     = dummy_get_key,
        .co_spec        = dummy_pkey_spec,
        .co_type        = dummy_pkey_type,
        .co_set_key     = dummy_set_key,
        .co_mac_set_key = dummy_mac_set_key,
        .co_mac         = dummy_mac,
        .co_crypt_prop  = dummy_pkey_prop,
};

static struct crypt_ops _dummy_sym = {
	.co_init        = dummy_init,
	.co_finish      = dummy_finish,
	.co_encrypt	= dummy_encrypt,
	.co_decrypt	= dummy_decrypt,
        .co_spec        = dummy_sym_spec,
        .co_type        = dummy_sym_type,
        .co_set_key     = dummy_set_key,
        .co_next_iv     = dummy_next_iv,
};

static struct crypt_ops _dummy_mac = {
	.co_init        = dummy_init,
	.co_finish      = dummy_finish,
	.co_mac		= dummy_mac,
        .co_spec        = dummy_mac_spec,
        .co_type        = dummy_mac_type,
        .co_set_key     = dummy_set_key,
};

static void __dummy_init(void) __attribute__ ((constructor));

static void __dummy_init(void)
{
	crypto_register(&_dummy_pkey);
	crypto_register(&_dummy_sym);
	if (0) crypto_register(&_dummy_mac);
}
#endif
