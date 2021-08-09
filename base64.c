// based on public domain base64 implementation written by WEI Zhicheng
// https://github.com/zhicheng/base64/blob/master/base64.c

#include "base64.h"

static const char b64url_chr[] = {
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
	'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
	'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
	'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
	'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
	'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
	'w', 'x', 'y', 'z', '0', '1', '2', '3',
	'4', '5', '6', '7', '8', '9', '-', '_',
};

/* ASCII order for BASE 64 decode, 255 in unused character */
static const uint8_t b64url_rev[] = {
	/* nul, soh, stx, etx, eot, enq, ack, bel, */
	   255, 255, 255, 255, 255, 255, 255, 255,

	/*  bs,  ht,  nl,  vt,  np,  cr,  so,  si, */
	   255, 255, 255, 255, 255, 255, 255, 255,

	/* dle, dc1, dc2, dc3, dc4, nak, syn, etb, */
	   255, 255, 255, 255, 255, 255, 255, 255,

	/* can,  em, sub, esc,  fs,  gs,  rs,  us, */
	   255, 255, 255, 255, 255, 255, 255, 255,

	/*  sp, '!', '"', '#', '$', '%', '&', ''', */
	   255, 255, 255, 255, 255, 255, 255, 255,

	/* '(', ')', '*', '+', ',', '-', '.', '/', */
	   255, 255, 255, 255, 255,  62, 255, 255,

	/* '0', '1', '2', '3', '4', '5', '6', '7', */
	    52,  53,  54,  55,  56,  57,  58,  59,

	/* '8', '9', ':', ';', '<', '=', '>', '?', */
	    60,  61, 255, 255, 255, 255, 255, 255,

	/* '@', 'A', 'B', 'C', 'D', 'E', 'F', 'G', */
	   255,   0,   1,  2,   3,   4,   5,    6,

	/* 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', */
	     7,   8,   9,  10,  11,  12,  13,  14,

	/* 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', */
	    15,  16,  17,  18,  19,  20,  21,  22,

	/* 'X', 'Y', 'Z', '[', '\', ']', '^', '_', */
	    23,  24,  25, 255, 255, 255, 255,  63,

	/* '`', 'a', 'b', 'c', 'd', 'e', 'f', 'g', */
	   255,  26,  27,  28,  29,  30,  31,  32,

	/* 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', */
	    33,  34,  35,  36,  37,  38,  39,  40,

	/* 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', */
	    41,  42,  43,  44,  45,  46,  47,  48,

	/* 'x', 'y', 'z', '{', '|', '}', '~', del, */
	    49,  50,  51, 255, 255, 255, 255, 255
};

void b64url_enc(char *out, const uint8_t *in, size_t in_len)
{
	int s;
	size_t i,j ;
	uint8_t l;

	s = 0;
	l = 0;
	j = 0;
	for (i = 0; i < in_len; i++) {
		uint8_t c = in[i];

		switch (s) {
			case 0:
				s = 1;
				out[j++] = b64url_chr[(c >> 2) & 0x3F];
				break;
			case 1:
				s = 2;
				out[j++] = b64url_chr[((l & 0x3) << 4) | ((c >> 4) & 0xF)];
				break;
			case 2:
				s = 0;
				out[j++] = b64url_chr[((l & 0xF) << 2) | ((c >> 6) & 0x3)];
				out[j++] = b64url_chr[c & 0x3F];
				break;
		}

		l = c;
	}

	switch (s) {
		case 1:
			out[j++] = b64url_chr[(l & 0x3) << 4];
			break;
		case 2:
			out[j++] = b64url_chr[(l & 0xF) << 2];
			break;
	}

	out[j] = 0;
}

ssize_t b64url_dec(uint8_t *out, size_t out_space, const char *in)
{
	int s = 0;
	size_t j = 0;

	while (1) {
		char c = *in++;
		if (!c) {
			// only residual lengths of 0, 2 and 3 constitute valid encodings
			if (s == 1)
				return -1;

			break;
		}

		uint8_t x;
		x = b64url_rev[(unsigned char)c];
		if (x == 255)
			return -1;

		if (j == out_space)
			return -1;

		uint8_t next;
		switch (s) {
		case 0:
			out[j] = (x << 2) & 0xFF;
			break;
		case 1:
			out[j++] |= (x >> 4) & 0x3;

			next = (x & 0xF) << 4;
			if (j == out_space)
				return (next == 0) ? (ssize_t)j : -1;

			out[j] = next;
			break;
		case 2:
			out[j++] |= (x >> 2) & 0xF;

			next = (x & 0x3) << 6;
			if (j == out_space)
				return (next == 0) ? (ssize_t)j : -1;

			out[j] = next;
			break;
		case 3:
			out[j++] |= x;
			break;
		}

		s = (s + 1) % 4;
	}

	return j;
}
