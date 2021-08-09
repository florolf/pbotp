#pragma once

#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

__attribute__((format(printf, 3, 4)))
ssize_t xsnprintf(char *str, size_t size, const char *fmt, ...);

#define streq(a, b) (strcmp((a), (b)) == 0)
#define strneq(a, b, n) (strncmp((a), (b), (n)) == 0)

bool streq_isgraph(const char *a, const char *b);
char *join(const char **data, char c);

static inline char *startswith(const char *a, const char *b)
{
	size_t n = strlen(b);

	if (strneq(a, b, n))
		return (char*) (a + n);

	return NULL;
}

void wipe(void *p, size_t size);
#define wipe_ref(x) wipe((x), sizeof(*(x)))
#define wipe_sized(x) wipe(&(x), sizeof(x))

int randombytes(uint8_t *out, size_t len);

int memcmp_ctime(const void *x, const void *y, size_t n);

static inline uint32_t unp32le(const uint8_t *data) {
	return ((uint32_t)data[3] << 24) |
	       ((uint32_t)data[2] << 16) |
	       ((uint32_t)data[1] <<  8) |
	       ((uint32_t)data[0] <<  0);
}

static inline uint32_t unp32be(const uint8_t *data) {
	return ((uint32_t)data[0] << 24) |
	       ((uint32_t)data[1] << 16) |
	       ((uint32_t)data[2] <<  8) |
	       ((uint32_t)data[3] <<  0);
}

static inline uint64_t unp64le(const uint8_t *data) {
	return ((uint64_t)data[7] << 56) |
	       ((uint64_t)data[6] << 48) |
	       ((uint64_t)data[5] << 40) |
	       ((uint64_t)data[4] << 32) |
	       ((uint64_t)data[3] << 24) |
	       ((uint64_t)data[2] << 16) |
	       ((uint64_t)data[1] <<  8) |
	       ((uint64_t)data[0] <<  0);
}

static inline void p32be(uint8_t *out, uint32_t val)
{
	for (int i = 0; i < 4; i++) {
		out[3 - i] = val & 0xff;
		val >>= 8;
	}
}

static inline void p64be(uint8_t *out, uint64_t val)
{
	for (int i = 0; i < 8; i++) {
		out[7 - i] = val & 0xff;
		val >>= 8;
	}
}

void free_indirect(void *p);
#define AUTOFREE_PTR(type, name) __attribute__((cleanup(free_indirect))) type *name = NULL
#define AUTOFREE_BUF(type, name, nmemb) __attribute__((cleanup(free_indirect))) type *name = calloc((nmemb), sizeof(type))

#ifndef MIN
#define MIN(x, y) (((x) < (y)) ? (x) : (y))
#endif

#define ARRAY_SIZE(x) (sizeof((x))/sizeof((x)[0]))
