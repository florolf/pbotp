#include <stdint.h>
#include <assert.h>

#include "utils.h"

#include "sha256.h"

// derived from public domain libtomcrypt

#define RORc(x, y) (((((uint32_t)(x)&0xFFFFFFFFUL)>>(uint32_t)((y)&31)) | ((uint32_t)(x)<<(uint32_t)((32-((y)&31))&31))) & 0xFFFFFFFFUL)

/* the K array */
static const uint32_t K[64] = {
	0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL, 0x3956c25bUL,
	0x59f111f1UL, 0x923f82a4UL, 0xab1c5ed5UL, 0xd807aa98UL, 0x12835b01UL,
	0x243185beUL, 0x550c7dc3UL, 0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL,
	0xc19bf174UL, 0xe49b69c1UL, 0xefbe4786UL, 0x0fc19dc6UL, 0x240ca1ccUL,
	0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL, 0x983e5152UL,
	0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL, 0xc6e00bf3UL, 0xd5a79147UL,
	0x06ca6351UL, 0x14292967UL, 0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL,
	0x53380d13UL, 0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL,
	0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL, 0xc76c51a3UL, 0xd192e819UL,
	0xd6990624UL, 0xf40e3585UL, 0x106aa070UL, 0x19a4c116UL, 0x1e376c08UL,
	0x2748774cUL, 0x34b0bcb5UL, 0x391c0cb3UL, 0x4ed8aa4aUL, 0x5b9cca4fUL,
	0x682e6ff3UL, 0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL,
	0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL
};

/* Various logical functions */
#define Ch(x,y,z)       (z ^ (x & (y ^ z)))
#define Maj(x,y,z)      (((x | y) & z) | (x & y))
#define S(x, n)         RORc((x),(n))
#define R(x, n)         (((x)&0xFFFFFFFFUL)>>(n))
#define Sigma0(x)       (S(x, 2) ^ S(x, 13) ^ S(x, 22))
#define Sigma1(x)       (S(x, 6) ^ S(x, 11) ^ S(x, 25))
#define Gamma0(x)       (S(x, 7) ^ S(x, 18) ^ R(x, 3))
#define Gamma1(x)       (S(x, 17) ^ S(x, 19) ^ R(x, 10))

/* compress 512-bits */
static void sha256_compress(struct sha256_state *md, const unsigned char *buf)
{
	uint32_t S[8], W[64], t0, t1;
	uint32_t t;
	int i;

	/* copy state into S */
	for (i = 0; i < 8; i++) {
		S[i] = md->state[i];
	}

	/* copy the state into 512-bits into W[0..15] */
	for (i = 0; i < 16; i++) {
		W[i] = unp32be(buf + (4*i));
	}

	/* fill W[16..63] */
	for (i = 16; i < 64; i++) {
		W[i] = Gamma1(W[i - 2]) + W[i - 7] + Gamma0(W[i - 15]) + W[i - 16];
	}

	/* Compress */
#define RND(a,b,c,d,e,f,g,h,i) \
	t0 = h + Sigma1(e) + Ch(e, f, g) + K[i] + W[i]; \
	t1 = Sigma0(a) + Maj(a, b, c); \
	d += t0; \
	h  = t0 + t1;

	for (i = 0; i < 64; ++i) {
		RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],i);
		t = S[7]; S[7] = S[6]; S[6] = S[5]; S[5] = S[4];
		S[4] = S[3]; S[3] = S[2]; S[2] = S[1]; S[1] = S[0]; S[0] = t;
	}
#undef RND

	/* feedback */
	for (i = 0; i < 8; i++) {
		md->state[i] = md->state[i] + S[i];
	}
}

void sha256_init(struct sha256_state *md)
{
	md->curlen = 0;
	md->length = 0;
	md->state[0] = 0x6A09E667UL;
	md->state[1] = 0xBB67AE85UL;
	md->state[2] = 0x3C6EF372UL;
	md->state[3] = 0xA54FF53AUL;
	md->state[4] = 0x510E527FUL;
	md->state[5] = 0x9B05688CUL;
	md->state[6] = 0x1F83D9ABUL;
	md->state[7] = 0x5BE0CD19UL;
}

void sha256_process(struct sha256_state *md, const unsigned char *in, unsigned long inlen)
{
	unsigned long n;

	assert(md->curlen <= sizeof(md->buf));
	assert((md->length + inlen * 8) >= md->length);

	while (inlen > 0) {
		if (md->curlen == 0 && inlen >= SHA256_BLOCK_SIZE) {
			sha256_compress(md, in);
			md->length += SHA256_BLOCK_SIZE * 8;
			in += SHA256_BLOCK_SIZE;
			inlen -= SHA256_BLOCK_SIZE;
		} else {
			n = MIN(inlen, (SHA256_BLOCK_SIZE - md->curlen));
			memcpy(md->buf + md->curlen, in, n);
			md->curlen += n;
			in += n;
			inlen -= n;
			if (md->curlen == SHA256_BLOCK_SIZE) {
				sha256_compress(md, md->buf);
				md->length += 8*SHA256_BLOCK_SIZE;
				md->curlen = 0;
			}
		}
	}
}

void sha256_finish(struct sha256_state *md, unsigned char *out)
{
	int i;

	assert(md->curlen < sizeof(md->buf));

	/* increase the length of the message */
	md->length += md->curlen * 8;

	/* append the '1' bit */
	md->buf[md->curlen++] = (unsigned char)0x80;

	/* if the length is currently above 56 bytes we append zeros
	 * then compress.  Then we can fall back to padding zeros and length
	 * encoding like normal.
	 */
	if (md->curlen > 56) {
		while (md->curlen < 64) {
			md->buf[md->curlen++] = (unsigned char)0;
		}
		sha256_compress(md, md->buf);
		md->curlen = 0;
	}

	/* pad upto 56 bytes of zeroes */
	while (md->curlen < 56) {
		md->buf[md->curlen++] = (unsigned char)0;
	}

	/* store length */
	p64be(md->buf+56, md->length);
	sha256_compress(md, md->buf);

	/* copy output */
	for (i = 0; i < 8; i++) {
		p32be(out+(4*i), md->state[i]);
	}
}

void sha256(unsigned char *out, const unsigned char *in, unsigned long inlen)
{
	struct sha256_state md;

	sha256_init(&md);
	sha256_process(&md, in, inlen);
	sha256_finish(&md, out);
}
