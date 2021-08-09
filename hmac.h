#pragma once

#include <stdint.h>
#include <stddef.h>

#include "sha256.h"

struct hmac_state {
	uint8_t key_exp[SHA256_BLOCK_SIZE];
	struct sha256_state md;
};

void hmac_init(struct hmac_state *hmac,
               const uint8_t *key, size_t key_len);
void hmac_process(struct hmac_state *hmac,
                  const uint8_t *data, size_t data_len);
void hmac_finish(struct hmac_state *hmac, uint8_t *hmac_out);

void hmac(uint8_t *hmac_out,
          const uint8_t *key, size_t key_len,
          const uint8_t *data, size_t data_len);
