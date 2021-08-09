#pragma once

#include <stdint.h>

#define SHA256_BLOCK_SIZE 64
#define SHA256_SIZE 32

struct sha256_state {
	uint64_t length;
	uint32_t state[8], curlen;
	uint8_t buf[SHA256_BLOCK_SIZE];
};

void sha256_init(struct sha256_state *md);
void sha256_process(struct sha256_state *md, const unsigned char *in,
                   unsigned long inlen);
void sha256_finish(struct sha256_state *md, unsigned char *out);
void sha256(unsigned char *out, const unsigned char *in, unsigned long inlen);
