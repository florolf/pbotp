#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <qrencode.h>

#include "utils.h"

#include "qr.h"

#define ANSI_RESET "\033[0m"
#define ANSI_WHITE_ON_BLACK "\033[40;97;1m"
#define ANSI_WHITE_BG "\033[107;1m"
#define ANSI_BLACK_BG "\033[40;1m"

#define UTF8_BLOCK_UPPER "\xe2\x96\x80" // U+2580
#define UTF8_BLOCK_LOWER "\xe2\x96\x84" // U+2584
#define UTF8_BLOCK_FULL  "\xe2\x96\x88" // U+2588

#define QUIET_SIZE 4

static char *memset_p(char *s, char c, size_t n)
{
	memset(s, c, n);
	s += n;
	*s = 0;

	return s;
}

static int write_qrcode_utf8(QRcode *qr, void (*print)(const char *line, void *arg), void *arg)
{
	AUTOFREE_BUF(char, buf, strlen(ANSI_WHITE_ON_BLACK) + (qr->width + 2 * QUIET_SIZE) * 3 + strlen(ANSI_RESET) + 1);
	if (!buf)
		return -1;

	_Static_assert(QUIET_SIZE % 2 == 0, "QUIET_SIZE needs to be even");

	char *p = buf;
	p = stpcpy(p, ANSI_WHITE_ON_BLACK);
	for (size_t x = 0; x < QUIET_SIZE; x++)
		p = stpcpy(p, UTF8_BLOCK_FULL);

	char *start = p;

	for (size_t x = 0; x < (size_t)qr->width + QUIET_SIZE; x++)
		p = stpcpy(p, UTF8_BLOCK_FULL);

	stpcpy(p, ANSI_RESET);

	for (size_t y = 0; y < QUIET_SIZE / 2; y++)
		print(buf, arg);

	for (size_t y = 0; y < (size_t)qr->width; y += 2) {
		const uint8_t *row1 = qr->data + qr->width * y;
		const uint8_t *row2 = row1 + qr->width;

		p = start;
		for (size_t x = 0; x < (size_t)qr->width; x++) {
			bool upper = row1[x] & 1;
			bool lower = (y+1) < (size_t)qr->width ? (row2[x] & 1) : false;

			if (upper && lower)
				p = stpcpy(p, " ");
			else if (upper)
				p = stpcpy(p, UTF8_BLOCK_LOWER);
			else if (lower)
				p = stpcpy(p, UTF8_BLOCK_UPPER);
			else
				p = stpcpy(p, UTF8_BLOCK_FULL);
		}

		for (size_t x = 0; x < QUIET_SIZE; x++)
			p = stpcpy(p, UTF8_BLOCK_FULL);

		strcat(buf, ANSI_RESET);

		print(buf, arg);
	}

	p = start;
	for (size_t x = 0; x < (size_t)qr->width + QUIET_SIZE; x++)
		p = stpcpy(p, UTF8_BLOCK_FULL);

	stpcpy(p, ANSI_RESET);

	for (size_t y = 0; y < QUIET_SIZE / 2; y++)
		print(buf, arg);

	return 0;
}

static int write_qrcode_ascii(QRcode *qr, void (*print)(const char *line, void *arg), void *arg)
{
	AUTOFREE_BUF(char, buf, 2 * (qr->width + 2 * QUIET_SIZE) + 1);
	if (!buf)
		return -1;

	memset(buf, '#', 2 * (qr->width + 2 * QUIET_SIZE));
	buf[2 * (qr->width + 2 * QUIET_SIZE)] = 0;

	for (size_t i = 0; i < QUIET_SIZE; i++)
		print(buf, arg);

	unsigned char *qr_p = qr->data;
	for (size_t y = 0; y < (size_t) qr->width; y++) {
		char *p = &buf[2 * QUIET_SIZE];

		for (size_t x = 0; x < (size_t) qr->width; x++) {
			char c = (*qr_p++ & 1) ? ' ' : '#';

			*p++ = c;
			*p++ = c;
		}

		print(buf, arg);
	}

	memset(buf, '#', 2 * (qr->width + 2 * QUIET_SIZE));
	for (size_t i = 0; i < QUIET_SIZE; i++)
		print(buf, arg);

	return 0;
}

static int write_qrcode_ansi(QRcode *qr, void (*print)(const char *line, void *arg), void *arg)
{
	/* worst case: one toggle every pixel -> one color sequence + two spaces
	 * every pixel + final reset */
	AUTOFREE_BUF(char, buf, (qr->width + 2 * QUIET_SIZE) * (strlen(ANSI_WHITE_BG) + 2) + strlen(ANSI_RESET) + 1);
	if (!buf)
		return -1;

	*buf = 0;

	char *p = buf;
	p = stpcpy(p, ANSI_WHITE_BG);
	p = memset_p(p, ' ', 2 * QUIET_SIZE);

	char *start = p;

	p = memset_p(start, ' ', 2 * (qr->width + QUIET_SIZE));
	stpcpy(p, ANSI_RESET);

	for (size_t i = 0; i < QUIET_SIZE; i++)
		print(buf, arg);

	unsigned char *qr_p = qr->data;
	for (size_t y = 0; y < (size_t) qr->width; y++) {
		bool white = true;

		p = start;
		for (size_t x = 0; x < (size_t) qr->width; x++) {
			bool next_white = !(*qr_p++ & 1);

			if (!white && next_white)
				p = stpcpy(p, ANSI_WHITE_BG);
			else if (white && !next_white)
				p = stpcpy(p, ANSI_BLACK_BG);

			p = stpcpy(p, "  ");

			white = next_white;
		}

		if (!white)
			p = stpcpy(p, ANSI_WHITE_BG);

		p = memset_p(p, ' ', 2 * QUIET_SIZE);
		stpcpy(p, ANSI_RESET);

		print(buf, arg);
	}

	p = memset_p(start, ' ', 2 * (qr->width + QUIET_SIZE));
	stpcpy(p, ANSI_RESET);

	for (size_t i = 0; i < QUIET_SIZE; i++)
		print(buf, arg);

	return 0;
}

int print_qr(const char *str, enum qr_mode mode, void (*print)(const char *line, void *arg), void *arg)
{
	QRcode *qr;
	qr = QRcode_encodeString(str, 0, QR_ECLEVEL_L, QR_MODE_8, 1);
	if (!qr) {
		perror("generating QR code failed");
		return -1;
	}

	int ret = -1;
	switch (mode) {
		case QR_MODE_UTF8:
			ret = write_qrcode_utf8(qr, print, arg);
			break;
		case QR_MODE_ANSI:
			ret = write_qrcode_ansi(qr, print, arg);
			break;
		case QR_MODE_ASCII:
			ret = write_qrcode_ascii(qr, print, arg);
			break;
	}

	QRcode_free(qr);
	return ret;
}
