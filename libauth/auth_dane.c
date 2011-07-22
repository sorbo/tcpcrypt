#include <string.h>
#include <arpa/inet.h>
#include <tcpcrypt.h>
#include <assert.h>
#include <err.h>
#include <ldns/ldns.h>

#include "auth.h"
#include "auth_dane.h"
#include "os.h"

ldns_status
do_chase(ldns_resolver *res,
            ldns_rdf *name,
            ldns_rr_type type,
            ldns_rr_class c,
            ldns_rr_list *trusted_keys,
            ldns_pkt *pkt_o,
            uint16_t qflags,
            ldns_rr_list *prev_key_list,
            int verbosity);

ldns_status
read_key_file(const char *filename, ldns_rr_list *key_list);

static ldns_rr_list *_key_list;

static inline void hexdump(void *p, int len)
{
	unsigned char *x = p;

	while (len--)
		printf("%.2x ", *x++);

	printf("\n");
}

static int dane_accept(int s, struct auth_info *ai)
{
	unsigned char buf[4096];
	struct auth_hdr *ah = (struct auth_hdr*) buf;
	struct auth_info_dane *ad = (struct auth_info_dane*) ai;
	unsigned char *out = NULL;
	int len, rc;
	uint16_t *lp;
	unsigned char *p;
	unsigned char sid[TCPCRYPT_SID_MAXLEN];
	int sidl = sizeof(sid);
	EVP_MD_CTX ctx;

	sidl = tcpcrypt_get_sid(s, sid);

	memset(ah, 0, sizeof(*ah));

	ah->ah_magic = AUTH_MAGIC;
	ah->ah_type  = AUTH_DANE;

	/* stick in cert */
	len = i2d_X509(ad->ai_cert, &out);
	if (len < 0)
		return -1;

	lp    = (uint16_t*) ah->ah_data;
	*lp++ = htons(len);

	p = (unsigned char*) lp;
	memcpy(p, out, len);
	p += len;

	OPENSSL_free(out);

	/* do signature */
	lp = (uint16_t*) p;
	p  = (unsigned char*) (lp + 1);

	if (!EVP_SignInit(&ctx, EVP_sha1()))
		return -1;

	EVP_SignUpdate(&ctx, sid, sidl);

	if (!EVP_SignFinal(&ctx, p, (unsigned int*) &len, ad->ai_key))
		return -1;

	EVP_MD_CTX_cleanup(&ctx);

	*lp = htons(len);
	p  += len;

	len = p - ah->ah_data;

	ah->ah_len = htons(len);

	len += sizeof(ah);

	assert(len <= sizeof(buf));

	rc = os_write(s, buf, len);
	if (rc == -1)
		return -1;

	if (rc != len)
		return -1;

	return 0;
}

static int verify_cert_cn(X509 *cert, struct auth_info_dane *ad)
{
	X509_NAME *name;
	X509_NAME_ENTRY *entry;
	int lastpos = -1;
	int rc = -1;
	char *cn = NULL;

	if (!(name = X509_get_subject_name(cert)))
		return -1;

	while (1) {
		lastpos = X509_NAME_get_index_by_NID(name, NID_commonName,
						     lastpos);

		if (lastpos == -1)
			break;

		entry = X509_NAME_get_entry(name, lastpos);
		if (!entry)
			continue;

		ASN1_STRING_to_UTF8((unsigned char**) &cn,
				    X509_NAME_ENTRY_get_data(entry));

		if (!cn)
			continue;

//		printf ("CN [%s]\n", cn);

		OPENSSL_free(cn);
	}

	rc = 1;

	return rc;
}

static int get_dane(char *name, void *out, int len)
{
	ldns_resolver *res;
	ldns_rdf *domain;
	ldns_pkt *p;
	ldns_rr_list *txt;
	ldns_rr *rr;
	ldns_rdf *tlsa;
	int rc = -1;
	int l;
	unsigned char *x;
	int result;

	domain = ldns_dname_new_frm_str(name);
	if (!domain)
		return -1;

	if (ldns_resolver_new_frm_file(&res, NULL) != LDNS_STATUS_OK);

	ldns_resolver_set_dnssec(res, true);
	ldns_resolver_set_dnssec_cd(res, true);
	ldns_resolver_set_edns_udp_size(res, 4096);

        p = ldns_resolver_query(res,
                                domain,
                                LDNS_RR_TYPE_TXT,
                                LDNS_RR_CLASS_IN,
                                LDNS_RD);

	if (!p)
		goto __out3;

	txt = ldns_pkt_rr_list_by_type(p,
                                       LDNS_RR_TYPE_TXT,
                                       LDNS_SECTION_ANSWER);
	if (!txt)
		goto __out;

	ldns_rr_list_sort(txt);

	rr = ldns_rr_list_rr(txt, 0);
	if (!rr)
		goto __out2;

	tlsa = ldns_rr_rdf(rr, 0);
	if (!tlsa)
		goto __out2;

	l = ldns_rdf_size(tlsa);
	if (l < 5 && l >= len)
		goto __out2;

	l -= 6;
	x = ldns_rdf_data(tlsa);
	memcpy(out, &x[6], l);

	x = out;
	x[l] = 0;	

	/* DNSSEC */
	result = do_chase(res,
			  domain, 
			  LDNS_RR_TYPE_TXT,
			  LDNS_RR_CLASS_IN,
			  _key_list,
			  p, LDNS_RD, NULL, -1);

	if (result != LDNS_STATUS_OK)
		goto __out2;

	rc = 0;

__out2:
	ldns_rr_list_deep_free(txt);
__out:
	ldns_pkt_free(p);
	ldns_resolver_deep_free(res);
__out3:
	ldns_rdf_deep_free(domain);
	return rc;
}

static int hex2bin(char *in, unsigned char *out)
{
	int len = strlen(in);
	int l = 0;

	while (len >= 2) {
		char tmp[3];
		int x;

		tmp[0] = in[0];
		tmp[1] = in[1];
		tmp[2] = 0;

		if (sscanf(tmp, "%x", &x) != 1)
			return -1;

		*out++ = (unsigned char) x;

		in += 2;
		l++;

		len -= 2;
	}

	return l;
}

static int verify_cert_dane(X509 *cert, struct auth_info_dane *ad,
			    unsigned char *der, int derlen)
{
	unsigned char sig[1024];
	unsigned char fp[1024];
	char *p, *p2;
	int type, ref, len;
	EVP_MD_CTX ctx;

	snprintf((char*) fp, sizeof(fp), "_%d._tcp.%s",
	 	 ad->ai_port, ad->ai_hostname);

	if (get_dane((char*) fp, sig, sizeof(sig)) == -1)
		return -1;

//	printf("SIG [%s]\n", sig);

	p = (char*) sig;
	p2 = strchr(p, ' ');
	if (!p2)
		return -1;

	*p2++ = 0;

	type = atoi(p);

	p = strchr(p2, ' ');
	if (!p)
		return -1;
	*p++ = 0;

	ref = atoi(p2);

	len = hex2bin(p, fp);	
	if (len == -1)
		return -1;

	/* XXX */
	if (type == 1 && ref == 1) {
		int l = sizeof(sig);

		if (!EVP_DigestInit(&ctx, EVP_sha256()))
			return -1;

		EVP_DigestUpdate(&ctx, der, derlen);
		EVP_DigestFinal(&ctx, sig, (unsigned int*) &l);
		EVP_MD_CTX_cleanup(&ctx);

		if (l != len)
			return -1;

		if (memcmp(sig, fp, l) != 0)
			return -1;
	} else
		return -1; /* XXX */

	return 1;
}

static int verify_cert(X509* cert, struct auth_info_dane *ad, unsigned char *der,
		       int derlen)
{
	int rc;
	
	rc = verify_cert_dane(cert, ad, der, derlen);
	if (rc == -1)
		return -1;

	if (verify_cert_cn(cert, ad) != 1)
		return -1;

	return 1;
}

static int dane_connect(int s, struct auth_info *ai)
{
	unsigned char buf[4096];
	struct auth_hdr *ah = (struct auth_hdr*) buf;
	struct auth_info_dane *ad = (struct auth_info_dane*) ai;
	uint16_t *lp;
	int rc, len;
	unsigned char *p;
	unsigned char sid[TCPCRYPT_SID_MAXLEN];
	int sidl = sizeof(sid);
	EVP_MD_CTX ctx;
	X509 *cert;

	sidl = tcpcrypt_get_sid(s, sid);

	rc = os_read(s, ah, sizeof(*ah));
	if (rc != sizeof(*ah))
		return -1;

	if (ah->ah_magic != AUTH_MAGIC)
		return -1;

	len = ntohs(ah->ah_len);

	if (len >= (sizeof(buf) - sizeof(*ah)))
		return -1;

	rc = os_read(s, ah->ah_data, len);
	if (rc != len)
		return -1;

	/* get cert */
	lp  = (uint16_t*) ah->ah_data;
	len = ntohs(*lp++);
	p   = (unsigned char*) lp;

	cert = d2i_X509(NULL, (const unsigned char**) &p, len);
	if (!cert)
		return -1;

	if (verify_cert(cert, ad, (unsigned char*) lp, len) != 1) {
		X509_free(cert);
		return -1;
	}

	/* get signature */
	lp  = (uint16_t*) p;
	len = ntohs(*lp++);
	p   = (unsigned char*) lp;

	if (EVP_VerifyInit(&ctx, EVP_sha1()) == -1)
		return -1;

	EVP_VerifyUpdate(&ctx, sid, sidl);

	rc = EVP_VerifyFinal(&ctx, p, len, X509_get_pubkey(cert));

        EVP_MD_CTX_cleanup(&ctx);
	X509_free(cert);

	if (rc != 1)
		return -1;

	return 0;
}

static void __dane_init(void) __attribute__ ((constructor));

static void __dane_init(void)
{
	char *keyfile = getenv("LIBAUTH_DNSSEC_KEYFILE");

	_key_list = ldns_rr_list_new();

	if (keyfile) {
		if (read_key_file(keyfile, _key_list) != LDNS_STATUS_OK)
			errx(1, "Can't load keyfile: %s", keyfile);
	}

	auth_register(AUTH_DANE, dane_accept, dane_connect);
}                                                                                                            
