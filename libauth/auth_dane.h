#ifndef __AUTH_DANE__
#define __AUTH_DANE__

#include <openssl/pem.h>

#define AUTH_DANE 1

struct auth_info_dane {
        unsigned int    ai_type;
        X509            *ai_cert;
        EVP_PKEY        *ai_key;
	char		*ai_hostname;
	int		ai_port;
};

#endif /* __AUTH_DANE__ */
