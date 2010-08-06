#include <sys/types.h>
#include <string.h>
#include <strings.h>

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h> 

#include <pthread.h>

#include <sys/socket.h>
#include <sys/un.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/sha.h>
#include <openssl/obj_mac.h>

#include "pake.h"

static int get_affine_coordinates(const EC_GROUP *G,
				  const EC_POINT *P,
				  BIGNUM *x,
				  BIGNUM *y,
				  BN_CTX *ctx) {
  if (EC_METHOD_get_field_type(EC_GROUP_method_of(G))
      == NID_X9_62_prime_field) {
    return EC_POINT_get_affine_coordinates_GFp (G, P, x, y, ctx);
  } else { /* NID_X9_62_characteristic_two_field */
    return EC_POINT_get_affine_coordinates_GF2m(G, P, x, y, ctx);
  }
}

static int set_affine_coordinates(const EC_GROUP *G,
				  EC_POINT *P,
				  const BIGNUM *x,
				  const BIGNUM *y,
				  BN_CTX *ctx) {
  if (EC_METHOD_get_field_type(EC_GROUP_method_of(G))
      == NID_X9_62_prime_field) {
    return EC_POINT_set_affine_coordinates_GFp (G, P, x, y, ctx);
  } else { /* NID_X9_62_characteristic_two_field */
    return EC_POINT_set_affine_coordinates_GF2m(G, P, x, y, ctx);
  }
}

static int hash_bn(SHA256_CTX *sha, const BIGNUM *x) {
  /* allocate space */
  int size = BN_num_bytes(x), ret = 0;
  if (size <= 0 || size >= 256) return 0;
  unsigned char *tmp = (unsigned char *) alloca(size+1);

  /* first byte is size to ensure parseability */
  *tmp = (unsigned char) size;

  /* convert to bytes and hash it */
  if (!BN_bn2bin(x, tmp+1)) goto err;
  ret = SHA256_Update(sha, (const void *) tmp, size+1);

 err:
  bzero(tmp, size+1);
  return ret;
}

static int hash_point(SHA256_CTX *sha,
		      const EC_GROUP *G,
		      const EC_POINT *P,
		      BIGNUM *P_x,
		      BIGNUM *P_y,
		      BN_CTX *ctx) {
  int ret = get_affine_coordinates(G, P, P_x, P_y, ctx);
  if (ret) ret = hash_bn(sha, P_x);
  if (ret) ret = hash_bn(sha, P_y);
  return ret;
}

pthread_mutex_t debug_mutex;
#ifdef PAKE_DEBUG
static void debug_point(const EC_GROUP *G,
			const char *message,
			const EC_POINT *P,
			BN_CTX *ctx) {
  BIGNUM *x = BN_new(), *y = BN_new();
  int sx, sy;
  unsigned char *out_x = NULL, *out_y = NULL;
  if (!x || !y) goto err;
  if (!get_affine_coordinates(G, P, x, y, ctx)) goto err;
  sx = BN_num_bytes(x);
  sy = BN_num_bytes(y);

  out_x = alloca(sx);
  out_y = alloca(sy);
  if (!BN_bn2bin(x, out_x)) goto err;
  if (!BN_bn2bin(y, out_y)) goto err;
  
  if (pthread_mutex_lock(&debug_mutex)) goto err;
  int i;
  printf("***DEBUG*** %s:\n*** x = ", message);
  for (i=0; i<sx; i++) {
    if (i && i % 8 == 0) printf(" ");
    printf("%02hhX", out_x[i]);
  }
  printf("\n*** y = ");
  for (i=0; i<sy; i++) {
    if (i && i % 8 == 0) printf(" ");
    printf("%02hhX", out_y[i]);
  }
  printf("\n\n");
  pthread_mutex_unlock(&debug_mutex);

  goto done;

 err:
  printf("***DEBUG*** %s: FAIL\n", message);

 done:
  if (out_x) bzero(out_x, sx);
  if (out_y) bzero(out_y, sy);
  if (x) BN_clear_free(x);
  if (y) BN_clear_free(y);
}
#else
#define debug_point(a,b,c,d)
#endif

int send_bn(int socket, const BIGNUM *x) {
  /* allocate space */
  int size = BN_num_bytes(x), ret = 0;
  if (size <= 0 || size >= 256) return 0;
  unsigned char *tmp = (unsigned char *) alloca(size+1);

  /* first byte is size to ensure parseability */
  *tmp = (unsigned char) size;
  if (!BN_bn2bin(x, tmp+1)) goto err;
  ssize_t written = 0;
  do {
    ssize_t wr = send(socket, (const void *)(tmp+written), size+1-written, 0);
    if (wr < 0) goto err;
    written += wr;
  } while (written < size+1);
  ret = 1;
 err:
  bzero(tmp, size+1);
  return ret;
}

static int recv_bn(int socket, BIGNUM *y) {
  unsigned char size = 0;
  int ret = 0;

  /* get the size */
  ssize_t rc = recv(socket, &size, 1, 0);
  if (rc != 1 || size == 0) return 0;
  
  /* allocate space */
  unsigned char *tmp = (unsigned char *) alloca(size);
  ssize_t red = 0;
  
  /* read it in */
  do {
    rc = recv(socket, (void *)(tmp + red), size-red, 0);
    if (rc < 0) goto err;
    red += rc;
  } while (red < size);
  if (!BN_bin2bn(tmp, size, y)) goto err;
  ret = 1;

 err:
  bzero(tmp, size+1);
  return ret;
}

int PAKE_setup(const EC_GROUP *group,
	       const EC_POINT *U,
	       const EC_POINT *V,
	       const char *password,
	       const char *server_name,
	       const char *client_name,
	       BIGNUM *pi_0,
	       BIGNUM *pi_1,
	       EC_POINT *L,
	       EC_POINT *U_minus_pi_0,
	       EC_POINT *V_pi_0) {
  int ret = 0;
  unsigned char side = 0;

  SHA512_CTX sha;
  unsigned char md[SHA512_DIGEST_LENGTH];

  BIGNUM *order = NULL, *tmp = NULL;

  /* fire up the engines */
  BN_CTX *ctx = NULL;
  if (!(ctx = BN_CTX_new())) goto err;
  BN_CTX_start(ctx);
  order = BN_new();
  tmp = BN_new();
  if (!order || !tmp) goto err;
  if (!EC_GROUP_get_order(group, order, ctx)) goto err;
  
  /* HACK: make sure we can get ~uniform distribution */
  if (BN_num_bits(order) > 512 - 64) goto err;

  /* get pi_0 */
  if (!SHA512_Init(&sha)) goto err;
  if (!SHA512_Update(&sha, &side, 1)) goto err;
  if (!SHA512_Update(&sha, server_name, 1+strlen(server_name))) goto err;
  if (!SHA512_Update(&sha, client_name, 1+strlen(client_name))) goto err;
  if (!SHA512_Update(&sha, password, 1+strlen(password))) goto err;
  if (!SHA512_Final(md, &sha)) goto err;
  if (!BN_bin2bn(md, sizeof(md), tmp)) goto err;
  if (!BN_nnmod(pi_0, tmp, order, ctx)) goto err;

  /* get pi_1 */
  side = 1;
  if (!SHA512_Init(&sha)) goto err;
  if (!SHA512_Update(&sha, &side, 1)) goto err;
  if (!SHA512_Update(&sha, server_name, 1+strlen(server_name))) goto err;
  if (!SHA512_Update(&sha, client_name, 1+strlen(client_name))) goto err;
  if (!SHA512_Update(&sha, password, 1+strlen(password))) goto err;
  if (!SHA512_Final(md, &sha)) goto err;
  if (!BN_bin2bn(md, sizeof(md), tmp)) goto err;
  if (!BN_nnmod(pi_1, tmp, order, ctx)) goto err;

  /* get L, etc */
  if (V_pi_0 && !EC_POINT_mul(group, V_pi_0, NULL, V, pi_0, ctx)) goto err;
  if (U_minus_pi_0 &&
      (!EC_POINT_mul(group, U_minus_pi_0, NULL, U, pi_0, ctx)
       || !EC_POINT_invert(group, U_minus_pi_0, ctx))) goto err;
  if (L && !EC_POINT_mul(group, L, pi_1, NULL, NULL, ctx)) goto err;

  ret = 1;

 err:
  if (!ret) {
    BN_clear(pi_0);
    BN_clear(pi_1);
    // hm, no clear function ...
    // if (L) EC_POINT_clear(L);
    // if (U_minus_pi_0) EC_POINT_clear(U_minus_pi_0);
    // if (V_pi_0) EC_POINT_clear(V_pi_0);
  }
  bzero(md, sizeof(md));
  bzero(&sha, sizeof(sha));
  if (order) BN_free(order);
  if (tmp) BN_clear_free(tmp);
  if (ctx) { BN_CTX_end(ctx); BN_CTX_free(ctx); }
  return ret;
}

int PAKE_client(const EC_GROUP *group,
		const EC_POINT *U,
		const EC_POINT *V,
		const BIGNUM *pi_0,
		const BIGNUM *pi_1,
		const EC_POINT *U_minus_pi_0,
		const EC_POINT *V_pi_0,
		unsigned char output[SHA256_DIGEST_LENGTH],
		int socket) {
  int ret = 0;
  BN_CTX *ctx = NULL;
  BIGNUM *order = NULL, *alpha = NULL, *P_x = NULL, *P_y = NULL;
  EC_POINT *X = NULL, *Y = NULL, *Y2 = NULL, *V2 = NULL, *Z = NULL, *N = NULL,
    *U2 = NULL, *X2 = NULL;
  SHA256_CTX sha;

  /* fire up the engines */
  if (!(ctx = BN_CTX_new())) goto err;
  BN_CTX_start(ctx);
  order = BN_new();
  alpha = BN_new();
  P_x = BN_new();
  P_y = BN_new();
  X = Y = EC_POINT_new(group);
  Y2 = X2 = EC_POINT_new(group);
  N = Z = V2 = U2 = EC_POINT_new(group);
  if (!order || !alpha || !P_x || !P_y || !X || !Y2 || !N) goto err;
  if (!EC_GROUP_get_order(group, order, ctx)) goto err;
  if (!SHA256_Init(&sha)) goto err;

  /* choose X */
  if (!EC_POINT_copy(U2, U_minus_pi_0)) goto err;
  if (!EC_POINT_invert(group, U2, ctx)) goto err;
  do {
    if (!BN_rand_range(alpha, order)) goto err;
  } while (BN_is_zero(alpha));
  if (!EC_POINT_mul(group, X2, alpha, NULL, NULL, ctx)) goto err;
  if (!EC_POINT_add(group, X, X2, U2, ctx)) goto err;
  if (!hash_bn(&sha, pi_0)) goto err;
  if (!hash_point(&sha, group, X, P_x, P_y, ctx)) goto err;

  debug_point(group, "client X", X, ctx);

  /*** output X ***/
  if (!send_bn(socket, P_x)) goto err;
  if (!send_bn(socket, P_y)) goto err;
  

  /*** input Y ***/
  if (!recv_bn(socket, P_x)) goto err;
  if (!recv_bn(socket, P_y)) goto err;
  if (!set_affine_coordinates(group, Y, P_x, P_y, ctx)) goto err;
  debug_point(group, "client Y", Y, ctx);
  //if (EC_POINT_is_at_infinity(group, Y)) goto err;

  /* compute Z, N */
  if (!hash_bn(&sha, P_x)) goto err;
  if (!hash_bn(&sha, P_y)) goto err;
  if (!EC_POINT_copy(V2, V_pi_0)) goto err;
  if (!EC_POINT_invert(group, V2, ctx)) goto err;
  if (!EC_POINT_add(group, Y2, Y, V2, ctx)) goto err;
  debug_point(group, "client Y2", Y2, ctx);
  if (!EC_POINT_mul(group, Z, NULL, Y2, alpha, ctx)) goto err;
  debug_point(group, "client Z", Z, ctx);
  if (!hash_point(&sha, group, Z, P_x, P_y, ctx)) goto err;
  if (!EC_POINT_mul(group, N, NULL, Y2, pi_1,  ctx)) goto err;
  debug_point(group, "client N", N, ctx);
  if (!hash_point(&sha, group, N, P_x, P_y, ctx)) goto err;
  if (!SHA256_Final(output, &sha)) goto err;

  /* yay */
  ret = 1;

 err:
  if (ctx) { BN_CTX_end(ctx); BN_CTX_free(ctx); }

  if (P_x) BN_clear_free(P_x);
  if (P_y) BN_clear_free(P_y);
  if (alpha) BN_clear_free(alpha);
  if (order) BN_free(order);

  if (X) EC_POINT_clear_free(X);
  if (N) EC_POINT_clear_free(N);
  if (Y2) EC_POINT_clear_free(Y2);
  /* Y = X and N = Z = V2  already free*/

  bzero(&sha, sizeof(sha));

  return ret;
}

int PAKE_server(const EC_GROUP *group,
		const EC_POINT *U,
		const EC_POINT *V,
		const BIGNUM *pi_0,
		const EC_POINT *U_minus_pi_0,
		const EC_POINT *V_pi_0,
		const EC_POINT *L,
		unsigned char output[SHA256_DIGEST_LENGTH],
		int socket) {
  int ret = 0;
  BN_CTX *ctx = NULL;
  BIGNUM *order = NULL, *beta = NULL, *P_x = NULL, *P_y = NULL;
  EC_POINT *X = NULL, *Y = NULL, *X2 = NULL, *Y2 = NULL, *Z = NULL, *N = NULL;
  SHA256_CTX sha;

  /* fire up the engines */
  if (!(ctx = BN_CTX_new())) goto err;
  BN_CTX_start(ctx);
  order = BN_new();
  beta = BN_new();
  P_x = BN_new();
  P_y = BN_new();
  X = N = Z = Y2 = EC_POINT_new(group);
  Y = X2 = EC_POINT_new(group);
  if (!order || !beta || !P_x || !P_y || !X || !Y2 || !N) goto err;
  if (!EC_GROUP_get_order(group, order, ctx)) goto err;
  if (!SHA256_Init(&sha)) goto err;
  if (!hash_bn(&sha, pi_0)) goto err;

  /* choose Y */
  do {
    if (!BN_rand_range(beta, order)) goto err;
  } while (BN_is_zero(beta));
  if (!EC_POINT_mul(group, Y2, beta, NULL, NULL, ctx)) goto err;
  debug_point(group, "server Y2", Y2, ctx);
  if (!EC_POINT_add(group, Y, Y2, V_pi_0, ctx)) goto err;
  debug_point(group, "server Y", Y, ctx);

  /*** input X ***/
  if (!recv_bn(socket, P_x)) goto err;
  if (!recv_bn(socket, P_y)) goto err;
  if (!set_affine_coordinates(group, X, P_x, P_y, ctx)) goto err;
  if (!hash_bn(&sha, P_x)) goto err;
  if (!hash_bn(&sha, P_y)) goto err;
  debug_point(group, "server X", X, ctx);
  //if (EC_POINT_is_at_infinity(group, X)) goto err;

  /*** output Y ***/
  if (!hash_point(&sha, group, Y, P_x, P_y, ctx)) goto err;
  if (!send_bn(socket, P_x)) goto err;
  if (!send_bn(socket, P_y)) goto err;
  
  /* compute Z, N */
  if (!EC_POINT_add(group, X2, X, U_minus_pi_0, ctx)) goto err;
  if (!EC_POINT_mul(group, Z, NULL, X2, beta, ctx)) goto err;
  debug_point(group, "server Z", Z, ctx);
  if (!hash_point(&sha, group, Z, P_x, P_y, ctx)) goto err;
  if (!EC_POINT_mul(group, N, NULL, L, beta, ctx)) goto err;
  debug_point(group, "server N", N, ctx);
  if (!hash_point(&sha, group, N, P_x, P_y, ctx)) goto err;
  if (!SHA256_Final(output, &sha)) goto err;

  /* yay */
  ret = 1;

 err:
  if (ctx) { BN_CTX_end(ctx); BN_CTX_free(ctx); }

  if (P_x) BN_clear_free(P_x);
  if (P_y) BN_clear_free(P_y);
  if (beta) BN_clear_free(beta);
  if (order) BN_free(order);

  if (X) EC_POINT_clear_free(X);
  if (Y) EC_POINT_clear_free(Y);
  /* others already free */

  bzero(&sha, sizeof(sha));

  return ret;
}

typedef struct {
  const EC_GROUP *group;
  const EC_POINT *U;
  const EC_POINT *V;
  const BIGNUM *pi_0;
  const EC_POINT *U_minus_pi_0;
  const EC_POINT *V_pi_0;
  const EC_POINT *L;
  unsigned char output[SHA256_DIGEST_LENGTH];
  int socket;
} PAKE_server_params;

typedef struct {
  const EC_GROUP *group;
  const EC_POINT *U;
  const EC_POINT *V;
  const BIGNUM *pi_0;
  const BIGNUM *pi_1;
  const EC_POINT *U_minus_pi_0;
  const EC_POINT *V_pi_0;
  unsigned char output[SHA256_DIGEST_LENGTH];
  int socket;
} PAKE_client_params;

typedef struct {
  PAKE_server_params server;
  PAKE_client_params client;
} PAKE_params;

void *PAKE_client_thread(void *args) {
  PAKE_client_params *p = (PAKE_client_params *) args;
  return PAKE_client(p->group, p->U, p->V,
		     p->pi_0, p->pi_1, p->U_minus_pi_0, p->V_pi_0,
		     p->output,
		     p->socket)
    ? "success" : "failure";
}

void *pake_client(void *priv, int s) {
  PAKE_params *pp = priv;
  PAKE_client_params *p = &pp->client;
  return PAKE_client(p->group, p->U, p->V,
		     p->pi_0, p->pi_1, p->U_minus_pi_0, p->V_pi_0,
		     p->output,
		     s)
    ? p->output : NULL;
}

void *PAKE_server_thread(void *args) {
  PAKE_server_params *p = (PAKE_server_params *) args;
  return PAKE_server(p->group, p->U, p->V,
		     p->pi_0, p->U_minus_pi_0, p->V_pi_0, p->L,
		     p->output,
		     p->socket)
    ? "success" : "failure";
}

void *pake_server(void *priv, int s) {
  PAKE_params *pp = priv;
  PAKE_server_params *p = &pp->server;
  return PAKE_server(p->group, p->U, p->V,
		     p->pi_0, p->U_minus_pi_0, p->V_pi_0, p->L,
		     p->output,
		     s)
    ? p->output : NULL;
}

void *pake_setup(void) {
  PAKE_params *p;

  if (!(p = malloc(sizeof(*p))))
    return NULL;

  memset(p, 0, sizeof(*p));

  const char *password = "not a very good password";
  const char *client_name = "John Smith";
  const char *server_name = "catameringue";

  BN_CTX *ctx = NULL;
  BIGNUM *tmp = NULL, *order = NULL, *pi_0 = NULL, *pi_1 = NULL;
  EC_POINT *U = NULL, *V = NULL, *L = NULL,
    *U_minus_pi_0 = NULL, *V_pi_0 = NULL;
  

  /* fire up the engines */
  if (!(ctx = BN_CTX_new())) goto err;
  BN_CTX_start(ctx);
  tmp = BN_new();
  order = BN_new();
  pi_0 = BN_new();
  pi_1 = BN_new();
  if (!tmp || !order || !pi_0 || !pi_1) goto err;

  const EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
  if (!group) goto err;
  if (!EC_GROUP_get_order(group, order, ctx)) goto err;
  U = EC_POINT_new(group);
  V = EC_POINT_new(group);
  L = EC_POINT_new(group);
  U_minus_pi_0 = EC_POINT_new(group);
  V_pi_0 = EC_POINT_new(group);
  if (!U || !V || !L || !U_minus_pi_0 || !V_pi_0) goto err;

  /* HACK: choose U, V */
  do {
    if (!BN_rand_range(tmp, order)) goto err;
  } while (BN_is_zero(tmp));
  if (!BN_hex2bn(&tmp, "799ABC951C32825396D5EEA12C527308ECC0393621EEFC82B5B2C6AB4BA895B6"))
    goto err;
  if (!EC_POINT_mul(group, U, tmp, NULL, NULL, ctx)) goto err;

  do {
    if (!BN_rand_range(tmp, order)) goto err;
  } while (BN_is_zero(tmp));
  if (!BN_hex2bn(&tmp, "7417A0F2C5824875508F1524CAFA2521F49562B89D86D15530BFF792EBBB8BDD"))
    goto err;
  if (!EC_POINT_mul(group, V, tmp, NULL, NULL, ctx)) goto err;

  /* initialize */
  if (!PAKE_setup(group, U, V,
		  password, server_name, client_name,
		  pi_0, pi_1,
		  L, U_minus_pi_0, V_pi_0))
    goto err;

  /* set up communications */
  int socks[2] = { 0, 0 };
//  if (socketpair(AF_UNIX, SOCK_STREAM, 0, socks)) goto err;

  PAKE_client_params cp = {
    group, U, V, pi_0, pi_1, U_minus_pi_0, V_pi_0, {}, socks[0]
  };

  PAKE_server_params sp = {
    group, U, V, pi_0, U_minus_pi_0, V_pi_0, L, {}, socks[1]
  };

  memcpy(&p->client, &cp, sizeof(p->client));
  memcpy(&p->server, &sp, sizeof(p->server));

  return p;

 err:
  printf("YOU FAIL! (booooooo....)\n");
  return NULL;
}

#if 0
int main(int argc, char **argv) {

  pthread_t cth, sth;
  pthread_attr_t attr;

  if (pthread_mutex_init(&debug_mutex, NULL)) goto err;
  if (pthread_attr_init(&attr)) goto err;
  if (pthread_create(&cth, &attr, PAKE_client_thread, (void *)&cp)) goto err;
  if (pthread_create(&sth, &attr, PAKE_server_thread, (void *)&sp)) goto err;

  const char *server_ret, *client_ret;
  if (pthread_join(cth, (void **) &client_ret)) goto err;
  if (pthread_join(sth, (void **) &server_ret)) goto err;

  /* report back */
  printf("Client: %s\n", client_ret);
  int i;
  for (i=0; i<SHA256_DIGEST_LENGTH; i++) {
    if (i && i % 8 == 0) printf(" ");
    printf("%02hhX", cp.output[i]);
  }
  printf("\n\n");

  printf("Server: %s\n", server_ret);
  for (i=0; i<SHA256_DIGEST_LENGTH; i++) {
    if (i && i % 8 == 0) printf(" ");
    printf("%02hhX", sp.output[i]);
  }
  printf("\n\n");

  return 0;

}
#endif
