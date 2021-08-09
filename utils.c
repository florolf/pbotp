#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>
#include <ctype.h>
#include <errno.h>
#include <sys/random.h>

#include "utils.h"

ssize_t xsnprintf(char *str, size_t size, const char *format, ...)
{
	int ret;
	va_list args;

	va_start(args, format);
	ret = vsnprintf(str, size, format, args);
	va_end(args);

	if (ret < 0)
		return -1;

	if ((size_t)ret >= size)
		return -1;

	return ret;
}

bool streq_isgraph(const char *a, const char *b)
{
	while (1) {
		while (isspace(*a))
			a++;

		while (isspace(*b))
			b++;

		if (*a == 0 && *b == 0)
			return true;

		if (*a != *b)
			return false;

		a++;
		b++;
	}
}

char *join(const char **data, char c)
{
	size_t len = 0;
	for (const char **elem = data; *elem; elem++) {
		len += strlen(*elem);
		len++;
	}

	char *out = malloc(len + 1);
	if (!out)
		return NULL;

	char *p = out;
	for (const char **elem = data; *elem; elem++) {
		p = stpcpy(p, *elem);
		*p++ = c;
	}

	*(p-1) = 0;

	return out;
}

void wipe(void *p, size_t size)
{
	volatile uint8_t *p8 = (volatile uint8_t *)p;

	for (size_t i = 0; i < size; i++)
		*p8 = 0;

	asm volatile ("" ::: "memory");
}

void free_indirect(void *p)
{
	free(*(void**)p);
}

#ifndef TESTING
int randombytes(uint8_t *out, size_t len)
{
	while (len) {
		ssize_t ret;

		ret = getrandom(out, len, 0);
		if (ret < 0) {
			if (errno == EINTR)
				continue;

			perror("could not get randomness");
			return -1;
		}

		out += ret;
		len -= ret;
	}

	return 0;
}
#endif
