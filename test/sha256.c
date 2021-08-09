#include <stdlib.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <string.h>

#include <cmocka.h>

#include "sha256.h"

static void test_vectors(void **state)
{
	(void) state;

	struct test_vector {
		const uint8_t *data;
		size_t data_len;

		uint8_t result[SHA256_SIZE];
	};

#define SIZED_STR(x) (const uint8_t*)x, sizeof(x)-1

	static const struct test_vector vecs[] = {
		{
			SIZED_STR(""),
			{
				0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
				0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
			}
		},
		{
			SIZED_STR("abc"),
			{
				0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
				0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
			}
		},
		{
			SIZED_STR("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
			{
				0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8, 0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39,
				0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67, 0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1
			}
		},
		{
			SIZED_STR("db94592b6838823588e9958724b72372c2c8168cd257eb7ffa26fc756cc3727b0ef2d9acbdcafb359794a99fd611f998ff1c5234b5754c271bd47efdb61594d8"),
			{
				0xc6, 0x89, 0xb0, 0x10, 0x55, 0x96, 0xd9, 0x69, 0x88, 0xaf, 0x89, 0x68, 0xc6, 0x18, 0xfa, 0x62,
				0x1f, 0x38, 0x85, 0x1b, 0x2c, 0xdd, 0x31, 0xcf, 0x79, 0x97, 0xeb, 0x65, 0x4f, 0x74, 0x2f, 0x0c
			}
		},
		{ 0 }
	};
#undef SIZED_STR

	for (size_t i = 0; vecs[i].data; i++) {
		uint8_t out[SHA256_SIZE];

		sha256(out, vecs[i].data, vecs[i].data_len);
		assert_memory_equal(vecs[i].result, out, SHA256_SIZE);
	}
}

static void test_partial_feed(void **state)
{
	(void) state;

	const char *in = "db94592b6838823588e9958724b72372c2c8168cd257eb7ffa26fc756cc3727b0ef2d9acbdcafb359794a99fd611f998ff1c5234b5754c271bd47efdb61594d8";
	size_t inlen = strlen(in);

	uint8_t ref_out[SHA256_SIZE];
	sha256(ref_out, (uint8_t*)in, strlen(in));

	struct sha256_state s;
	for (size_t i = 0; i < inlen; i++) {
		uint8_t out[SHA256_SIZE];

		sha256_init(&s);
		sha256_process(&s, (uint8_t*)&in[0], i);
		sha256_process(&s, (uint8_t*)&in[i], inlen - i);
		sha256_finish(&s, out);

		assert_memory_equal(out, ref_out, SHA256_SIZE);
	}
}

int main(int argc, char **argv)
{
	(void) argc;
	(void) argv;

	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_vectors),
		cmocka_unit_test(test_partial_feed)
	};

	return cmocka_run_group_tests_name("sha256", tests, NULL, NULL);
}
