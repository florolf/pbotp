#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

#include "tweetnacl.h"
#include "utils.h"
#include "base64.h"

static __attribute__((noreturn)) void help(const char *progname, int code)
{
	fprintf(stderr,
		"usage: %s [privkey|pubkey]\n"
		"\n"
		"    privkey: Generates a new private key and writes it to stdout\n"
		"    pubkey: Reads a private key from stdin and writes a public key to stdout\n",
		progname);

	exit(code);
}

static int privkey(void)
{
	uint8_t raw[32];

	if (randombytes(raw, 32) < 0) {
		fprintf(stderr, "could not generate private key\n");
		return EXIT_FAILURE;
	}

	char b64[44];
	b64url_enc(b64, raw, 32);
	puts(b64);

	return EXIT_SUCCESS;
}

static int read_key(uint8_t out[static 32])
{
	char line[64];
	if (fgets(line, sizeof(line), stdin) == NULL) {
		perror("reading from stdin failed");
		return -1;
	}

	char *p = line + strlen(line) - 1;
	while (p >= line && isspace(*p))
		*p-- = 0;

	size_t keylen = strlen(line);
	if (keylen != 43) {
		fprintf(stderr, "invalid pubkey length, expected 43, got %zu\n", keylen);
		return -1;
	}

	if (b64url_dec(out, 32, line) < 0) {
		fprintf(stderr, "decoding pubkey failed\n");
		return -1;
	}

	return 0;
}

static int pubkey(void)
{
	uint8_t privkey_raw[32];
	uint8_t pubkey_raw[32];

	if (read_key(privkey_raw) < 0)
		return EXIT_FAILURE;

	crypto_scalarmult_base(pubkey_raw, privkey_raw);

	char b64[44];
	b64url_enc(b64, pubkey_raw, 32);
	puts(b64);

	return EXIT_SUCCESS;
}

int main(int argc, char **argv)
{
	(void) argc;
	(void) argv;

	if (argc < 2)
		help(argv[0], EXIT_FAILURE);

	if (streq(argv[1], "privkey"))
		return privkey();
	else if(streq(argv[1], "pubkey"))
		return pubkey();
	else if(streq(argv[1], "--help") || streq(argv[1], "-h"))
		help(argv[0], EXIT_SUCCESS);

	help(argv[0], EXIT_FAILURE);
}
