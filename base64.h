#pragma once

#include <unistd.h>
#include <stddef.h>
#include <stdint.h>

void b64url_enc(char *out, const uint8_t *in, size_t in_len);
ssize_t b64url_dec(uint8_t *out, size_t out_space, const char *in);
