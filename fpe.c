#include <stdint.h>
#include <math.h>
#include <string.h>
#include <assert.h>
#include <openssl/aes.h>
#include <openssl/crypto.h>
#include <openssl/bn.h>
#include "fpe.h"

/* This implementation is based on openssl's BIGNUM and AES, so you need to install openssl first */
// Converts hex number to char
void
hex2chars (unsigned char hex[], unsigned char result[])
{
  int len = strlen (hex);
  unsigned char temp[3];
  temp[2] = 0x00;

  int j = 0;
  for (int i = 0; i < len; i += 2)
    {
      temp[0] = hex[i];
      temp[1] = hex[i + 1];
      result[j] = (char) strtol (temp, NULL, 16);
      ++j;
    }
}

void
inverse_map_chars (unsigned result[], unsigned char str[], int len)
{
  for (int i = 0; i < len; ++i)
    if (result[i] < 10)
      str[i] = result[i] + '0';
    else
      str[i] = result[i] - 10 + 'a';

  str[len] = 0x00;
}

void
map_chars (unsigned char str[], unsigned int result[])
{
  int len = strlen (str);

  for (int i = 0; i < len; ++i)
    if (str[i] >= 'a')
      result[i] = str[i] - 'a' + 10;
    else
      result[i] = str[i] - '0';
}

// quick power: result = x ^ e
void
pow_uv (BIGNUM * pow_u, BIGNUM * pow_v, unsigned int x, int u, int v,
	BN_CTX * ctx)
{
  BN_CTX_start (ctx);
  BIGNUM *base = BN_CTX_get (ctx), *e = BN_CTX_get (ctx);

  BN_set_word (base, x);
  if (u > v)
    {
      BN_set_word (e, v);
      BN_exp (pow_v, base, e, ctx);
      BN_mul (pow_u, pow_v, base, ctx);
    }
  else
    {
      BN_set_word (e, u);
      BN_exp (pow_u, base, e, ctx);
      if (u == v)
	BN_copy (pow_v, pow_u);
      else
	BN_mul (pow_v, pow_u, base, ctx);
    }

  BN_CTX_end (ctx);
  return;
}

// convert numeral string to number
void
str2num (BIGNUM * Y, const unsigned int *X, unsigned long long radix,
	 unsigned int len, BN_CTX * ctx)
{
  BN_CTX_start (ctx);
  BIGNUM *r = BN_CTX_get (ctx), *x = BN_CTX_get (ctx);

  BN_set_word (Y, 0);
  BN_set_word (r, radix);
  for (int i = 0; i < len; ++i)
    {
      // Y = Y * radix + X[i]
      BN_set_word (x, X[i]);
      BN_mul (Y, Y, r, ctx);
      BN_add (Y, Y, x);
    }

  BN_CTX_end (ctx);
  return;
}

// convert number to numeral string
void
num2str (const BIGNUM * X, unsigned int *Y, unsigned int radix, int len,
	 BN_CTX * ctx)
{
  BN_CTX_start (ctx);
  BIGNUM *dv = BN_CTX_get (ctx),
    *rem = BN_CTX_get (ctx), *r = BN_CTX_get (ctx), *XX = BN_CTX_get (ctx);

  BN_copy (XX, X);
  BN_set_word (r, radix);
  memset (Y, 0, len << 2);

  for (int i = len - 1; i >= 0; --i)
    {
      // XX / r = dv ... rem
      BN_div (dv, rem, XX, r, ctx);
      // Y[i] = XX % r
      Y[i] = BN_get_word (rem);
      // XX = XX / r
      BN_copy (XX, dv);
    }

  BN_CTX_end (ctx);
  return;
}

// This is our FF1 FPE encryption function
void
FF1_encrypt (const unsigned int *in, unsigned int *out, AES_KEY * aes_enc_ctx,
	     const unsigned char *tweak, const unsigned int radix,
	     size_t inlen, size_t tweaklen)
{
  BIGNUM *bnum = BN_new (),
    *y = BN_new (),
    *c = BN_new (),
    *anum = BN_new (), *qpow_u = BN_new (), *qpow_v = BN_new ();
  BN_CTX *ctx = BN_CTX_new ();

  union
  {
    long one;
    char little;
  } is_endian =
  {
  1};

  memcpy (out, in, inlen << 2);
  printf ("\nFF1_encrypt()\n");
  printf ("--------------\n");
  printf ("\nX is ");
  for (int i = 0; i < inlen; ++i)
    printf ("%d ", in[i]);
  if (!tweaklen)
    printf ("\nTweak is <empty>\n");
  else
    {
      printf ("\nTweak is ");
      for (int i = 0; i < tweaklen; ++i)
	printf (" %02x", tweak[i]);
    }
  printf ("\n");
  // Calculate split point
  int u = floor2 (inlen, 1);
  int v = inlen - u;

  printf ("\nStep 1:\n");
  printf ("\tu is %d, v is %d\n", u, v);
  // Split the message
  unsigned int *A = out, *B = out + u;
  pow_uv (qpow_u, qpow_v, radix, u, v, ctx);


  printf ("Step 2:");
  printf ("\n\t A is \t ");
  for (int i = 0; i < u; i++)
    printf ("%d ", A[i]);
  printf ("\n");
  printf ("\t B is \t ");
  for (int i = 0; i < v; i++)
    printf ("%d ", B[i]);
  printf ("\n");
  unsigned int temp = (unsigned int) ceil (v * log2 (radix));
  // Byte lengths
  const int b = ceil2 (temp, 3);
  const int d = 4 * ceil2 (b, 2) + 4;

  printf ("Step 3:");
  printf ("\n\t b is\t %d \n", b);
  printf ("Step 4:");
  printf ("\n\t d is \t %d \n", d);
  int numpad = ((-tweaklen - b - 1) % 16 + 16) % 16;

  // Q's length is known to always be tweaklength +byte length + 1 +numPad, to be multiple of 16
  int lenQ = tweaklen + numpad + 1 + b;
  unsigned char P[16];
  unsigned char *Q = (unsigned char *) OPENSSL_malloc (lenQ), *Bytes =
    (unsigned char *) OPENSSL_malloc (b);

  // initialize P
  P[0] = 0x1;
  P[1] = 0x2;
  P[2] = 0x1;
  P[7] = u % 256;
  if (is_endian.little)
    {
      temp = (radix << 8) | 10;
      P[3] = (temp >> 24) & 0xff;
      P[4] = (temp >> 16) & 0xff;
      P[5] = (temp >> 8) & 0xff;
      P[6] = temp & 0xff;
      P[8] = (inlen >> 24) & 0xff;
      P[9] = (inlen >> 16) & 0xff;
      P[10] = (inlen >> 8) & 0xff;
      P[11] = inlen & 0xff;
      P[12] = (tweaklen >> 24) & 0xff;
      P[13] = (tweaklen >> 16) & 0xff;
      P[14] = (tweaklen >> 8) & 0xff;
      P[15] = tweaklen & 0xff;
    }
  else
    {
      *((unsigned int *) (P + 3)) = (radix << 8) | 10;
      *((unsigned int *) (P + 8)) = inlen;
      *((unsigned int *) (P + 12)) = tweaklen;
    }

  printf ("Step 5:");
  printf ("\n\t P is \t [ ");
  for (int i = 0; i < 16; i++)
    printf ("%d ", P[i]);
  printf ("]\n");
  // initialize Q
  memcpy (Q, tweak, tweaklen);
  memset (Q + tweaklen, 0x00, numpad);
  assert (tweaklen + numpad - 1 <= lenQ);

  unsigned char R[16];
  int maxJ = ceil2 (d, 4) - 1;
  int Slen = 16 + maxJ * 16;
  unsigned char *S = (unsigned char *) OPENSSL_malloc (Slen);
  for (int i = 0; i < FF1_ROUNDS; ++i)
    {
      // v
      int m = (i & 1) ? v : u;

      printf ("\nRound #%d\n", i);
      // i
      // Calculate the dynamic parts of Q
      Q[tweaklen + numpad] = i & 0xff;
      str2num (bnum, B, radix, inlen - m, ctx);
      int BytesLen = BN_bn2bin (bnum, Bytes);
      memset (Q + lenQ - b, 0x00, b);

      int qtmp = lenQ - BytesLen;
      memcpy (Q + qtmp, Bytes, BytesLen);

      printf ("\tStep 6.i\n");
      printf ("\t\t Q is \t[ ");
      for (int i = 0; i < lenQ; i++)
	printf ("%d ", Q[i]);
      printf ("]\n");

      // ii PRF(P || Q), P is always 16 bytes long
      // Since prf/ciph will operate in place, P and Q have to be copied into PQ,
      // for each iteration to reset the contents
      AES_encrypt (P, R, aes_enc_ctx);
      int count = lenQ / 16;
      unsigned char Ri[16];
      unsigned char *Qi = Q;
      for (int cc = 0; cc < count; ++cc)
	{
	  for (int j = 0; j < 16; ++j)
	    Ri[j] = Qi[j] ^ R[j];
	  AES_encrypt (Ri, R, aes_enc_ctx);
	  Qi += 16;
	}

      printf ("\tStep 6.ii\n");
      printf ("\t\t R is \t [");
      for (int i = 0; i < 16; i++)
	printf ("%d ", R[i]);
      printf ("]\n");

      // 6 iii 
      unsigned char tmp[16], SS[16];
      memset (S, 0x00, Slen);
      assert (Slen >= 16);
      memcpy (S, R, 16);


      for (int j = 1; j <= maxJ; ++j)
	{
	  memset (tmp, 0x00, 16);

	  if (is_endian.little)
	    {
	      // convert to big endian
	      // full unroll
	      tmp[15] = j & 0xff;
	      tmp[14] = (j >> 8) & 0xff;
	      tmp[13] = (j >> 16) & 0xff;
	      tmp[12] = (j >> 24) & 0xff;
	    }
	  else
	    *((unsigned int *) tmp + 3) = j;

	  for (int k = 0; k < 16; ++k)
	    tmp[k] ^= R[k];
	  AES_encrypt (tmp, SS, aes_enc_ctx);
	  assert ((S + 16 * j)[0] == 0x00);
	  assert (16 + 16 * j <= Slen);
	  memcpy (S + 16 * j, SS, 16);
	}

      printf ("\tStep 6.iii\n");
      printf ("\t\t S is \t");
      for (int i = 0; i < 8; i++)
	printf ("%x", S[i]);
      printf ("\n");

      // iv
      BN_bin2bn (S, d, y);

      printf ("\tStep 6.iv\n");
      printf ("\t\t y is \t ");
      BN_print_fp (stdout, y);
      printf ("\n");


      printf ("\tStep 6.v\n");
      printf ("\t\t m is \t %d\n", m);
      // vi
      // (num(A, radix, m) + y) % qpow(radix, m);
      str2num (anum, A, radix, m, ctx);
      // anum = (anum + y) mod qpow_uv
      if (m == u)
	BN_mod_add (c, anum, y, qpow_u, ctx);
      else
	BN_mod_add (c, anum, y, qpow_v, ctx);

      // swap A and B
      assert (A != B);
      A = (unsigned int *) ((uintptr_t) A ^ (uintptr_t) B);
      B = (unsigned int *) ((uintptr_t) B ^ (uintptr_t) A);
      A = (unsigned int *) ((uintptr_t) A ^ (uintptr_t) B);
      num2str (c, B, radix, m, ctx);

      printf ("\tStep 6.vi\n");
      printf ("\t\t c is \t");
      for (int i = 0; i < v; i++)
	printf ("%d", B[i]);
      printf ("\n");

      printf ("\tStep 6.vii\n");
      printf ("\t\t C is \t");
      for (int i = 0; i < v; i++)
	printf ("%d ", B[i]);
      printf ("\n");

      printf ("\tStep 6.viii\n");
      printf ("\t\t A is \t");
      for (int i = 0; i < u; i++)
	printf ("%d ", A[i]);
      printf ("\n");

      printf ("\tStep 6.ix\n");
      printf ("\t\t B is \t");
      for (int i = 0; i < v; i++)
	printf ("%d ", B[i]);
      printf ("\n");
    }

  printf ("\tStep 7\n");
  printf ("\n\nCIPHERTEXT ( A||B ) is ");
  for (int i = 0; i < inlen; ++i)
    printf (" %d", out[i]);
  printf ("\n");

  // free the space
  BN_clear_free (anum);
  BN_clear_free (bnum);
  BN_clear_free (c);
  BN_clear_free (y);
  BN_clear_free (qpow_u);
  BN_clear_free (qpow_v);
  BN_CTX_free (ctx);
  OPENSSL_free (Bytes);
  OPENSSL_free (Q);
  OPENSSL_free (S);
  return;
}

// This is our FF1 FPE decryption function
void
FF1_decrypt (const unsigned int *in, unsigned int *out, AES_KEY * aes_enc_ctx,
	     const unsigned char *tweak, const unsigned int radix,
	     size_t inlen, size_t tweaklen)
{
  BIGNUM *bnum = BN_new (),
    *y = BN_new (),
    *c = BN_new (),
    *anum = BN_new (), *qpow_u = BN_new (), *qpow_v = BN_new ();
  BN_CTX *ctx = BN_CTX_new ();

  union
  {
    long one;
    char little;
  } is_endian =
  {
  1};
  memcpy (out, in, inlen << 2);
  printf ("\nFF1_decrypt()\n");
  printf ("--------------\n");
  printf ("\nX is ");
  for (int i = 0; i < inlen; ++i)
    printf ("%d ", in[i]);
  if (!tweaklen)
    printf ("\nTweak is <empty>\n");
  else
    {
      printf ("\nTweak is ");
      for (int i = 0; i < tweaklen; ++i)
	printf (" %02x", tweak[i]);
    }
  printf ("\n");
  // Calculate split point
  int u = floor2 (inlen, 1);
  int v = inlen - u;

  printf ("\nStep 1:\n");
  printf ("\tu is %d, v is %d\n", u, v);
  // Split the message
  unsigned int *A = out, *B = out + u;
  pow_uv (qpow_u, qpow_v, radix, u, v, ctx);

  printf ("Step 2:");
  printf ("\n\t A is \t ");
  for (int i = 0; i < u; i++)
    printf ("%d ", A[i]);
  printf ("\n");
  printf ("\t B is \t ");
  for (int i = 0; i < v; i++)
    printf ("%d ", B[i]);
  printf ("\n");
  unsigned int temp = (unsigned int) ceil (v * log2 (radix));
  // Byte lengths
  const int b = ceil2 (temp, 3);
  const int d = 4 * ceil2 (b, 2) + 4;

  printf ("Step 3:");
  printf ("\n\t b is\t %d \n", b);
  printf ("Step 4:");
  printf ("\n\t d is \t %d \n", d);
  int numpad = ((-tweaklen - b - 1) % 16 + 16) % 16;
  int lenQ = tweaklen + numpad + 1 + b;
  unsigned char P[16];
  unsigned char *Q = (unsigned char *) OPENSSL_malloc (lenQ), *Bytes =
    (unsigned char *) OPENSSL_malloc (b);
  // initialize P
  P[0] = 0x1;
  P[1] = 0x2;
  P[2] = 0x1;
  P[7] = u % 256;
  if (is_endian.little)
    {
      temp = (radix << 8) | 10;
      P[3] = (temp >> 24) & 0xff;
      P[4] = (temp >> 16) & 0xff;
      P[5] = (temp >> 8) & 0xff;
      P[6] = temp & 0xff;
      P[8] = (inlen >> 24) & 0xff;
      P[9] = (inlen >> 16) & 0xff;
      P[10] = (inlen >> 8) & 0xff;
      P[11] = inlen & 0xff;
      P[12] = (tweaklen >> 24) & 0xff;
      P[13] = (tweaklen >> 16) & 0xff;
      P[14] = (tweaklen >> 8) & 0xff;
      P[15] = tweaklen & 0xff;
    }
  else
    {
      *((unsigned int *) (P + 3)) = (radix << 8) | 10;
      *((unsigned int *) (P + 8)) = inlen;
      *((unsigned int *) (P + 12)) = tweaklen;
    }

  printf ("Step 5:");
  printf ("\n\t P is \t [ ");
  for (int i = 0; i < 16; i++)
    printf ("%d ", P[i]);
  printf ("]\n");
  // initialize Q
  memcpy (Q, tweak, tweaklen);
  memset (Q + tweaklen, 0x00, numpad);
  assert (tweaklen + numpad - 1 <= lenQ);

  unsigned char R[16];
  int maxJ = ceil2 (d, 4) - 1;
  int Slen = 16 + maxJ * 16;
  unsigned char *S = (unsigned char *) OPENSSL_malloc (Slen);
  for (int i = FF1_ROUNDS - 1; i >= 0; --i)
    {
      // v
      int m = (i & 1) ? v : u;

      printf ("\nRound #%d\n", i);
      // i
      // Calculate the dynamic parts of Q
      Q[tweaklen + numpad] = i & 0xff;
      str2num (anum, A, radix, inlen - m, ctx);
      memset (Q + lenQ - b, 0x00, b);
      int BytesLen = BN_bn2bin (anum, Bytes);
      int qtmp = lenQ - BytesLen;
      memcpy (Q + qtmp, Bytes, BytesLen);

      printf ("\tStep 6.i\n");
      printf ("\t\t Q is \t[ ");
      for (int i = 0; i < lenQ; i++)
	printf ("%d ", Q[i]);
      printf ("]\n");
      // ii PRF(P || Q)
      // Since prf/ciph will operate in place, P and Q have to be copied into PQ,
      // for each iteration to reset the contents
      memset (R, 0x00, sizeof (R));
      AES_encrypt (P, R, aes_enc_ctx);
      int count = lenQ / 16;

      // R is guaranteed to be of length 16
      unsigned char Ri[16];
      unsigned char *Qi = Q;
      for (int cc = 0; cc < count; ++cc)
	{
	  for (int j = 0; j < 16; ++j)
	    Ri[j] = Qi[j] ^ R[j];
	  AES_encrypt (Ri, R, aes_enc_ctx);
	  Qi += 16;
	}

      printf ("\tStep 6.ii\n");
      printf ("\t\t R is \t [");
      for (int i = 0; i < 16; i++)
	printf ("%d ", R[i]);
      printf ("]\n");

      // 6 iii 
      unsigned char tmp[16], SS[16];
      memset (S, 0x00, Slen);
      memcpy (S, R, 16);
      for (int j = 1; j <= maxJ; ++j)
	{
	  memset (tmp, 0x00, 16);

	  if (is_endian.little)
	    {
	      // convert to big endian
	      // full unroll
	      tmp[15] = j & 0xff;
	      tmp[14] = (j >> 8) & 0xff;
	      tmp[13] = (j >> 16) & 0xff;
	      tmp[12] = (j >> 24) & 0xff;
	    }
	  else
	    *((unsigned int *) tmp + 3) = j;

	  for (int k = 0; k < 16; ++k)
	    tmp[k] ^= R[k];
	  AES_encrypt (tmp, SS, aes_enc_ctx);
	  assert ((S + 16 * j)[0] == 0x00);
	  memcpy (S + 16 * j, SS, 16);
	}

      printf ("\tStep 6.iii\n");
      printf ("\t\t S is \t");
      for (int i = 0; i < 8; i++)
	printf ("%x", S[i]);
      printf ("\n");
      // iv
      BN_bin2bn (S, d, y);

      printf ("\tStep 6.iv\n");
      printf ("\t\t y is \t ");
      BN_print_fp (stdout, y);
      printf ("\n");

      printf ("\tStep 6.v\n");
      printf ("\t\t m is \t %d\n", m);
      // vi
      // (num(B, radix, m) - y) % qpow(radix, m);
      str2num (bnum, B, radix, m, ctx);
      if (m == u)
	BN_mod_sub (c, bnum, y, qpow_u, ctx);
      else
	BN_mod_sub (c, bnum, y, qpow_v, ctx);

      // swap A and B
      assert (A != B);
      A = (unsigned int *) ((uintptr_t) A ^ (uintptr_t) B);
      B = (unsigned int *) ((uintptr_t) B ^ (uintptr_t) A);
      A = (unsigned int *) ((uintptr_t) A ^ (uintptr_t) B);
      num2str (c, A, radix, m, ctx);

      printf ("\tStep 6.vi\n");
      printf ("\t\t c is \t");
      for (int i = 0; i < v; i++)
	printf ("%d", B[i]);
      printf ("\n");

      printf ("\tStep 6.vii\n");
      printf ("\t\t C is \t");
      for (int i = 0; i < v; i++)
	printf ("%d ", B[i]);
      printf ("\n");

      printf ("\tStep 6.viii\n");
      printf ("\t\t A is \t");
      for (int i = 0; i < u; i++)
	printf ("%d ", A[i]);
      printf ("\n");

      printf ("\tStep 6.ix\n");
      printf ("\t\t B is \t");
      for (int i = 0; i < v; i++)
	printf ("%d ", B[i]);
      printf ("\n");
    }

  // free the space
  BN_clear_free (anum);
  BN_clear_free (bnum);
  BN_clear_free (y);
  BN_clear_free (c);
  BN_clear_free (qpow_u);
  BN_clear_free (qpow_v);
  BN_CTX_free (ctx);
  OPENSSL_free (Bytes);
  OPENSSL_free (Q);
  OPENSSL_free (S);
  return;
}

int
FPE_set_ff1_key (const unsigned char *userKey, const int bits,
		 const unsigned char *tweak, const unsigned int tweaklen,
		 const int radix, struct fpe_key *key)
{
  int ret;
  if (bits != 128 && bits != 192 && bits != 256)
    {
      ret = -1;
      return ret;
    }
  key->radix = radix;
  key->tweaklen = tweaklen;
  key->tweak = (unsigned char *) OPENSSL_malloc (tweaklen);
  memcpy (key->tweak, tweak, tweaklen);
  ret = AES_set_encrypt_key (userKey, bits, &key->aes_enc_ctx);
  return ret;
}

void
FPE_unset_ff1_key (struct fpe_key *key)
{
  OPENSSL_free (key->tweak);
}

void
FPE_ff1_encrypt (unsigned int *in, unsigned int *out, unsigned int inlen,
		 struct fpe_key *key, const int enc)
{
  if (enc)
    FF1_encrypt (in, out, &key->aes_enc_ctx, key->tweak,
		 key->radix, inlen, key->tweaklen);

  else
    FF1_decrypt (in, out, &key->aes_enc_ctx, key->tweak,
		 key->radix, inlen, key->tweaklen);
}

// main function
int
main (int argc, char *argv[])
{
  if (argc != 3)
    {
      printf ("Usage: %s <key> <credit card number (16digits)>\n", argv[0]);
      return 0;
    }

  unsigned char k[100], t[100], result[100],t1[10];
  int xlen = strlen (argv[2]),
    klen = strlen (argv[1]) / 2,
    tlen, radix = 10;
  unsigned int x[100], y[xlen], iin[6], tin[4], ntbe[6], ntbd[6], enccard[16];
  unsigned int tmp;

  strncpy(t1,argv[2],6);
  strncpy(t1+6,argv[2]+12,4);
 tlen=strlen(t1)/2;
  
  hex2chars (argv[1], k);
  hex2chars (t1, t);
  map_chars (argv[2], x);


  for (int i = 0; i < xlen; ++i)
    assert (x[i] < radix);

  struct fpe_key ff1;
  printf
    ("\n##############################################################\n");
  printf ("\n    Block Cipher Modes of Operation\n");
  printf ("\t Format-Preserving Encryption\n");
  printf
    ("\n##############################################################\n");
  printf ("\nFF1-Based on AES with Block Size as 128\n\n");
  printf ("Key is ");
  for (int i = 0; i < klen; ++i)
    printf (" %02x", k[i]);
  puts ("");
  printf ("Radix = %d\n", radix);
  printf
    ("--------------------------------------------------------------\n\n");
  printf ("Credit Card Number is <");
  for (int i = 0; i < xlen; ++i)
    printf (" %d", x[i]);
  printf (">\n");

  for (int i = 0; i < 6; ++i) {
    iin[i] = x[i];
  }

  printf ("\nTweak is ");
  for (int i = 0; i < tlen; ++i)
	printf (" %02x", t[i]);

  for (int i = 0; i < 4; ++i) {
    tin[i] = x[i+12];
  }

  for (int i = 0; i < 6; ++i)
    ntbe[i] = x[i+6];

  printf("\nIssuer Identification Number is ");
  for (int i = 0; i < 6; ++i) {
    printf ("%d ", iin[i]);
  }
  printf (">\n");

  printf("\nTransaction Identification Number is ");
  for (int i = 0; i < 4; ++i)
    printf ("%d ", tin[i]);
  printf (">\n");

  printf ("\nPlaintext is <");
  for (int i = 0; i < 6; ++i)
    printf (" %d", ntbe[i]);
  printf (">\n");
  FPE_set_ff1_key (k, klen * 8, t, tlen, radix, &ff1);

  FPE_ff1_encrypt (ntbe, y +6 , 6, &ff1, FPE_ENCRYPT);

  for (int i = 0; i < 16; ++i)
    enccard[i] = x[i];

  // Add cipher to Credit Card Number
  for (int i = 0; i < 6; ++i)
    enccard[i+6] = y[i+6];

  inverse_map_chars(y + 6, result, 6);
  printf("ciphertext: %s\n\n", result);

  printf("\n ********************************************************");
  inverse_map_chars(y + 6, result, 6);
  printf("\n\nciphertext: %s\n\n", result);
  printf ("Encrypted Credit Card Number : ");
  for (int i = 0; i < 16; ++i)
    printf (" %d", enccard[i]);
  printf ("\n\n");
  printf("\n ********************************************************");

  printf("\n\n We start Decrypting the cipher back \n");
  memset (ntbd, 0, sizeof (ntbd));
  FPE_ff1_encrypt (enccard+6, ntbd, 6, &ff1, FPE_DECRYPT);

  // Add plaintext back instead of cipher to Credit Card Number
  for (int i = 0; i < 6; ++i)
    enccard[i+6] = ntbd[i];

  printf("\n--------------------------------------------------------------\n\n");
  printf("Decrypted Card Number \n\n");
  printf ("Plaintext: <");
  for (int i = 0; i < 16; ++i)
    printf (" %d", enccard[i]);
  printf (" >\n\n");

  FPE_unset_ff1_key (&ff1);

  return 0;
}
