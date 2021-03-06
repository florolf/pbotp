#include <stdlib.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <string.h>

#include <cmocka.h>

#include "challenge.h"
#include "utils.h"

static size_t randombytes_len = 0;
static uint8_t *randombytes_data = NULL;

int randombytes(uint8_t *out, size_t len)
{
	assert_true(len == randombytes_len);
	assert_non_null(randombytes_data);

	memcpy(out, randombytes_data, len);

	randombytes_data = NULL;
	randombytes_len = 0;

	return 0;
}

static void randombytes_set(uint8_t *data, size_t len)
{
	assert_null(randombytes_data);

	randombytes_data = data;
	randombytes_len = len;
}

static void test_challenge(void **state)
{
	(void) state;
	int _;

	// this is the example from the documentation

	uint8_t pubkey[] = {
		0x66, 0x78, 0x36, 0xf0, 0xb2, 0x18, 0xa6, 0x1a, 0x9b, 0x6f, 0x0a, 0x84, 0x7e, 0xf7, 0x13, 0xe2,
		0x70, 0x2c, 0x87, 0x36, 0xb3, 0x34, 0x4e, 0x65, 0x0e, 0xe4, 0xaf, 0x44, 0x98, 0xeb, 0x4a, 0x04
	};

	uint8_t nonce[] = {
		0x3e, 0x2a, 0x27, 0xbe, 0xc0, 0x47, 0x58, 0x54, 0x6b, 0x5c, 0xd2, 0x93, 0x1b, 0x80, 0x9d, 0x56,
		0xf3, 0x82, 0xe8, 0x10, 0x52, 0x6c, 0x3a, 0xe1, 0xcc, 0x61, 0xf8, 0x61, 0xe5, 0x86, 0x93, 0x5f
	};

	randombytes_set(nonce, sizeof(nonce));

	uint8_t challenge[32];
	uint8_t response[32];
	const char *payload[] = {
		"dev", "SSSN7PBXFG6DY", "root", NULL
	};

	_ = make_challenge(pubkey, payload, challenge, response);
	assert_int_equal(_, 0);

	uint8_t expected_challenge[] = {
		0x73, 0x60, 0xda, 0xa5, 0x23, 0xa5, 0x68, 0x14, 0xfd, 0x97, 0x43, 0x8c, 0xa1, 0x83, 0xe4, 0xe0,
		0xf8, 0x57, 0xc1, 0xde, 0x7f, 0x92, 0xcc, 0x5a, 0xd7, 0x4f, 0x6a, 0xf9, 0xec, 0x23, 0xed, 0x5a
	};
	assert_memory_equal(challenge, expected_challenge, 32);

	uint8_t expected_response[] = {
		0x84, 0x71, 0xdb, 0x51, 0x79, 0x58, 0x38, 0x49, 0x70, 0xbc, 0x72, 0x29, 0x48, 0xca, 0x60, 0xe4,
		0x0a, 0x98, 0xb3, 0x7f, 0x5b, 0x99, 0xd2, 0x18, 0x9d, 0xb7, 0xae, 0xb3, 0xd4, 0x36, 0xde, 0x50
	};
	assert_memory_equal(response, expected_response, 32);
}

static void test_code(void **state)
{
	(void) state;

	// this is the example from the documentation

	uint8_t response[] = {
		0x84, 0x71, 0xdb, 0x51, 0x79, 0x58, 0x38, 0x49, 0x70, 0xbc, 0x72, 0x29, 0x48, 0xca, 0x60, 0xe4,
		0x0a, 0x98, 0xb3, 0x7f, 0x5b, 0x99, 0xd2, 0x18, 0x9d, 0xb7, 0xae, 0xb3, 0xd4, 0x36, 0xde, 0x50
	};

	AUTOFREE_PTR(char, code);
	code = response_to_code(response, 9);
	assert_string_equal(code, "552159108");
}

static void test_phrase(void **state)
{
	(void) state;

	// this is the example from the documentation

	uint8_t response[] = {
		0x84, 0x71, 0xdb, 0x51, 0x79, 0x58, 0x38, 0x49, 0x70, 0xbc, 0x72, 0x29, 0x48, 0xca, 0x60, 0xe4,
		0x0a, 0x98, 0xb3, 0x7f, 0x5b, 0x99, 0xd2, 0x18, 0x9d, 0xb7, 0xae, 0xb3, 0xd4, 0x36, 0xde, 0x50
	};

	AUTOFREE_PTR(char, phrase);
	phrase = response_to_phrase(response, 5);
	assert_string_equal(phrase, "correct horse pottery maple idle");
}

int main(int argc, char **argv)
{
	(void) argc;
	(void) argv;

	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_challenge),
		cmocka_unit_test(test_code),
		cmocka_unit_test(test_phrase),
	};

	return cmocka_run_group_tests_name("challenge", tests, NULL, NULL);
}
