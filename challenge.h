#pragma once

#include <stdint.h>
#include <stddef.h>

char *response_to_phrase(uint8_t response[static 32], size_t words);
char *response_to_code(uint8_t response[static 32], size_t digits);

int make_challenge(const uint8_t pubkey[static 32],
                   const char **payload,
                   uint8_t challenge_out[static 32], uint8_t response_out[static 32]);
