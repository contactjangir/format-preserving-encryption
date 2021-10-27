#ifndef HEADER_FPE_H
# define HEADER_FPE_H

# include <openssl/bn.h>
# include <openssl/aes.h>

# ifdef __cplusplus
extern "C" {
# endif

# define FPE_ENCRYPT 1
# define FPE_DECRYPT 0

# define FF1_ROUNDS 10
// ceil and floor for x / (2 ^ bit)
# define ceil2(x, bit) ( ((x) >> (bit)) + ( ((x) & ((1 << (bit)) - 1)) > 0 ) )
# define floor2(x, bit) ( (x) >> (bit) )

struct fpe_key {
    unsigned int radix;
    unsigned int tweaklen;
    unsigned char *tweak;
    AES_KEY aes_enc_ctx;
};


/*** FF1 FPE Functions ***/
int FPE_set_ff1_key(const unsigned char *userKey, const int bits, const unsigned char *tweak, const unsigned int tweaklen, const int radix, struct fpe_key *key);

void FPE_unset_ff1_key(struct fpe_key *key);

void FPE_ff1_encrypt(unsigned int *in, unsigned int *out, unsigned int inlen, struct fpe_key *key, const int enc);

void pow_uv(BIGNUM *pow_u, BIGNUM *pow_v, unsigned int x, int u, int v, BN_CTX *ctx);
# ifdef __cplusplus
}
# endif

#endif
