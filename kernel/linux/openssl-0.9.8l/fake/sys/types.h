#include <linux/module.h>

extern void assert(int);
extern void sha1_init(void *c);
extern void sha1_update(void *c, const void *crap, int len);
extern void sha1_final(void *c, void *out);
