#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <sys/random.h>

#include "tweetnacl.h"
#include "hmac.h"
#include "base64.h"
#include "utils.h"

#include "challenge.h"

#include "wordlist.h"

char *response_to_code(uint8_t response[static 32], size_t digits)
{
	if (digits > 19)
		return NULL;

	uint64_t code = unp64le(response);

	char *out = malloc(digits + 1);
	if (!out)
		return NULL;

	out[digits] = 0;
	while (digits--) {
		out[digits] = '0' + (code % 10);
		code /= 10;
	}

	return out;
}

char *response_to_phrase(uint8_t response[static 32], size_t words)
{
	if (words * BITS_PER_WORD > 32 * 8)
		return NULL;

	if (words == 0)
		return NULL;

	uint32_t buffer, buffer_fill;
	buffer = 0;
	buffer_fill = 0;

	char *out = malloc(words * (WORD_LEN_MAX + 1));
	if (!out)
		return NULL;

	char *p = out;

	for (size_t i = 0; i < words; i++) {
		while (buffer_fill < BITS_PER_WORD) {
			buffer |= ((uint32_t)*response) << buffer_fill;

			response++;
			buffer_fill += 8;
		}

		size_t word_idx = buffer & ((1ull << BITS_PER_WORD) - 1);
		buffer >>= BITS_PER_WORD;
		buffer_fill -= BITS_PER_WORD;

		const char *word = wordlist[word_idx];
		size_t word_len = strlen(word);

		memcpy(p, word, word_len);
		p[word_len] = ' ';

		p += word_len + 1;
	}

	*(p - 1) = 0;

	return out;
}

int make_challenge(const uint8_t pubkey[static 32],
                   const char **payload,
                   uint8_t challenge_out[static 32], uint8_t response_out[static 32])
{
	uint8_t secret[32];
	if (randombytes(secret, sizeof(secret)) < 0)
		return -1;

	crypto_scalarmult_base(challenge_out, secret);

	uint8_t dh_shared[32];
	crypto_scalarmult(dh_shared, secret, pubkey);

	struct hmac_state hmac;
	hmac_init(&hmac, dh_shared, sizeof(dh_shared));

	while (*payload) {
		const char *p = *payload;

		hmac_process(&hmac, (const uint8_t*)p, strlen(p) + 1);

		payload++;
	}

	hmac_finish(&hmac, response_out);

	wipe_sized(dh_shared);
	wipe_sized(secret);

	return 0;
}
