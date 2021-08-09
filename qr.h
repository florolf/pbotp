#pragma once

enum qr_mode {
	QR_MODE_UTF8,
	QR_MODE_ANSI,
	QR_MODE_ASCII,
};

int print_qr(const char *str, enum qr_mode mode, void (*print)(const char *line, void *arg), void *arg);
