#include <stdlib.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <string.h>

#include <cmocka.h>

#include "base64.h"

static void test_encode(void **state)
{
	(void) state;

	static const char *input = "foobar";
	static const char *prefix_out[] = {
		"",
		"Zg",
		"Zm8",
		"Zm9v",
		"Zm9vYg",
		"Zm9vYmE",
		"Zm9vYmFy",
	};

	for (size_t i = 0; i < strlen(input); i++) {
		char out[16];

		b64url_enc(out, (uint8_t*)input, i);

		assert_string_equal(out, prefix_out[i]);
	}
}

static void test_decode(void **state)
{
	(void) state;

	static const struct {
		const char *input, *output;
		int fake_space;
	} vectors[] = {
		{"", "", -1},

		/// valid inputs
		{"Zg",       "f",      -1},
		{"Zm8",      "fo",     -1},
		{"Zm9v",     "foo",    -1},
		{"Zm9vYg",   "foob",   -1},
		{"Zm9vYmE",  "fooba",  -1},
		{"Zm9vYmFy", "foobar", -1},

		// exact space match
		{"Zg",       "f",      1},
		{"Zm8",      "fo",     2},
		{"Zm9v",     "foo",    3},
		{"Zm9vYg",   "foob",   4},
		{"Zm9vYmE",  "fooba",  5},
		{"Zm9vYmFy", "foobar", 6},

		/// invalid inputs
		// length == 1 mod 4 is not valid
		{"Z", NULL, -1},
		{"Zm9vY", NULL, -1},

		// overflow
		{"Zg",       NULL, 0},
		{"Zm8",      NULL, 1},
		{"Zm9v",     NULL, 2},
		{"Zm9vYg",   NULL, 3},
		{"Zm9vYmE",  NULL, 4},
		{"Zm9vYmFy", NULL, 5},

		{NULL, NULL, 0}
	};

	for (size_t i = 0; vectors[i].input; i++) {
		char out[16];
		ssize_t ret;

		size_t space = sizeof(out);

		if (vectors[i].fake_space != -1)
			space = vectors[i].fake_space;

		ret = b64url_dec((uint8_t*)out, space, vectors[i].input);
		if (vectors[i].output == NULL) {
			assert_true(ret == -1);
			continue;
		}

		assert_true(ret >= 0);
		assert_int_equal(ret, strlen(vectors[i].output));

		assert_memory_equal(out, vectors[i].output, ret);
	}
}

int main(int argc, char **argv)
{
	(void) argc;
	(void) argv;

	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_encode),
		cmocka_unit_test(test_decode),
	};

	return cmocka_run_group_tests_name("base64", tests, NULL, NULL);
}
