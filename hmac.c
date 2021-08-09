#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "utils.h"

#include "hmac.h"

void hmac_init(struct hmac_state *hmac,
               const uint8_t *key, size_t key_len)
{
	memset(&hmac->key_exp, 0, SHA256_BLOCK_SIZE);

	if (key_len <= SHA256_BLOCK_SIZE)
		memcpy(hmac->key_exp, key, key_len);
	else
		sha256(hmac->key_exp, key, key_len);

	uint8_t key_pad[SHA256_BLOCK_SIZE];
	for (size_t i = 0; i < SHA256_BLOCK_SIZE; i++)
		key_pad[i] = hmac->key_exp[i] ^ 0x36;

	sha256_init(&hmac->md);
	sha256_process(&hmac->md, key_pad, sizeof(key_pad));

	wipe_sized(key_pad);
}

void hmac_process(struct hmac_state *hmac,
                  const uint8_t *data, size_t data_len)
{
	sha256_process(&hmac->md, data, data_len);
}

void hmac_finish(struct hmac_state *hmac, uint8_t *hmac_out)
{
	uint8_t hash_inner[SHA256_SIZE];

	sha256_finish(&hmac->md, hash_inner);

	uint8_t key_pad[SHA256_BLOCK_SIZE];
	for (size_t i = 0; i < SHA256_BLOCK_SIZE; i++)
		key_pad[i] = hmac->key_exp[i] ^ 0x5c;

	sha256_init(&hmac->md);
	sha256_process(&hmac->md, key_pad, sizeof(key_pad));
	sha256_process(&hmac->md, hash_inner, sizeof(hash_inner));
	sha256_finish(&hmac->md, hmac_out);

	wipe_sized(hash_inner);
	wipe_sized(key_pad);
	wipe_ref(hmac);
}

void hmac(uint8_t *hmac_out,
          const uint8_t *key, size_t key_len,
          const uint8_t *data, size_t data_len)
{
	struct hmac_state hmac;

	hmac_init(&hmac, key, key_len);
	hmac_process(&hmac, data, data_len);
	hmac_finish(&hmac, hmac_out); // wipes &hmac
}
