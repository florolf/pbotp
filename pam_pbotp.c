#define _GNU_SOURCE
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <sys/utsname.h>
#include <limits.h>
#include <errno.h>
#include <syslog.h>

#include <security/_pam_macros.h>
#include <security/pam_ext.h>
#include <security/pam_misc.h>
#include <security/pam_modutil.h>
#include <security/pam_modules.h>

#include "base64.h"
#include "challenge.h"
#include "utils.h"

#ifdef HAVE_QR
#include "qr.h"
#endif

#define EXPORT_SYMBOL __attribute__((visibility("default")))

enum response_mode {
	RESPONSE_CODE,
	RESPONSE_PHRASE
};

static const char *response_mode_name[] = {
	[RESPONSE_CODE] = "code",
	[RESPONSE_PHRASE] = "phrase"
};

struct context {
	struct pam_handle *pamh;

	const char *baseurl;
	const char *group;
	char hostname[HOST_NAME_MAX];
	const char *user;

	uint8_t pubkey[32];

#ifdef HAVE_QR
	bool qr_enabled;
	enum qr_mode qr_mode;
#endif

	enum response_mode response_mode;
	unsigned int length;
};

static int parse_args(struct context *ctx, int argc, const char **argv)
{
	bool pubkey_set = false;

	char *p;
	for (int i = 0; i < argc; i++) {
		if ((p = startswith(argv[i], "pubkey="))) {
			size_t keylen = strlen(p);
			if (keylen != 43) {
				pam_syslog(ctx->pamh, LOG_ERR, "invalid pubkey length, expected 43, got %zu", keylen);
				return -1;
			}

			if (b64url_dec(ctx->pubkey, 32, p) < 0) {
				pam_syslog(ctx->pamh, LOG_ERR, "could not decode pubkey");
				return -1;
			}

			pubkey_set = true;
		} else if ((p = startswith(argv[i], "group="))) {
			ctx->group= p;
		} else if ((p = startswith(argv[i], "baseurl="))) {
			ctx->baseurl = p;
		} else if ((p = startswith(argv[i], "response_mode="))) {
			if (streq(p, "code")) {
				ctx->response_mode = RESPONSE_CODE;
			} else if (streq(p, "phrase")) {
				ctx->response_mode = RESPONSE_PHRASE;
			} else {
				pam_syslog(ctx->pamh, LOG_ERR, "unknown response mode: '%s'", p);
				return -1;
			}
#ifdef HAVE_QR
		} else if ((p = startswith(argv[i], "qr="))) {
			if (streq(p, "utf8")) {
				ctx->qr_mode = QR_MODE_UTF8;
			} else if (streq(p, "ansi")) {
				ctx->qr_mode = QR_MODE_ANSI;
			} else if (streq(p, "ascii")) {
				ctx->qr_mode = QR_MODE_ASCII;
			} else if (streq(p, "none")) {
				ctx->qr_enabled = false;
			} else {
				pam_syslog(ctx->pamh, LOG_ERR, "unknown QR code mode: '%s'", p);
				return -1;
			}
#endif
		} else if ((p = startswith(argv[i], "length="))) {
			int tmp;

			errno = 0;
			tmp = strtol(p, NULL, 10);
			if (errno) {
				pam_syslog(ctx->pamh, LOG_ERR, "converting length value failed: %s", strerror(errno));
				return -1;
			}

			if (tmp <= 0) {
				pam_syslog(ctx->pamh, LOG_ERR, "length must be > 1");
				return -1;
			}

			ctx->length = tmp;
		} else {
			pam_syslog(ctx->pamh, LOG_WARNING, "unknown option: %s", argv[i]);
		}
	}

	if (!pubkey_set) {
		pam_syslog(ctx->pamh, LOG_ERR, "no pubkey given");
		return -1;
	}

	if (!ctx->baseurl) {
		pam_syslog(ctx->pamh, LOG_ERR, "no baseurl given");
		return -1;
	}

	if (!ctx->group) {
		pam_syslog(ctx->pamh, LOG_ERR, "no group given");
		return -1;
	}

	unsigned int default_length, max_length;
	switch (ctx->response_mode) {
		case RESPONSE_CODE:
			default_length = 9;
			max_length = 19;
			break;
		case RESPONSE_PHRASE:
			default_length = 5;
			max_length = 23;
			break;
	}

	if (!ctx->length)
		ctx->length = default_length;

	if (ctx->length > max_length) {
		pam_syslog(ctx->pamh, LOG_ERR, "length (%u) too long for response mode %s (%u allowed)",
		           ctx->length, response_mode_name[ctx->response_mode], max_length);
		return -1;
	}

	return 0;
}

#ifdef HAVE_QR
static void print_wrapper(const char *str, void *arg)
{
	struct context *ctx = (struct context *) arg;

	pam_info(ctx->pamh, "%s", str);
}
#endif

static char *format_response(struct context *ctx, uint8_t response_raw[static 32])
{
	switch (ctx->response_mode) {
		case RESPONSE_CODE:
			return response_to_code(response_raw, ctx->length);
		case RESPONSE_PHRASE:
			return response_to_phrase(response_raw, ctx->length);
	}

	return NULL;
}

static int output_challenge(struct context *ctx, char **expected_response)
{
	const char *elements[] = {
		ctx->baseurl,
		ctx->group,
		ctx->hostname,
		ctx->user,
		NULL,
		NULL
	};

	uint8_t challenge_raw[32];
	uint8_t response_raw[32];
	if (make_challenge(ctx->pubkey, &elements[1], challenge_raw, response_raw) < 0) {
		pam_syslog(ctx->pamh, LOG_ERR, "generating challenge failed");
		return -1;
	}

	char challenge[44];
	b64url_enc(challenge, challenge_raw, 32);

	elements[ARRAY_SIZE(elements)-2] = challenge;

	*expected_response = format_response(ctx, response_raw);
	if (!*expected_response) {
		pam_syslog(ctx->pamh, LOG_ERR, "formatting response failed");
		return -1;
	}

	AUTOFREE_PTR(char, url);
	url = join(elements, '/');
	if (!url) {
		pam_syslog(ctx->pamh, LOG_ERR, "generating URL failed");

		free(*expected_response);
		return -1;
	}

#ifdef HAVE_QR
	if (ctx->qr_enabled) {
		pam_info(ctx->pamh, "Scan this QR code to get a login token\n");
		if (print_qr(url, ctx->qr_mode, print_wrapper, ctx) < 0)
			pam_info(ctx->pamh, "Could not generate QR code\n");

		pam_info(ctx->pamh, "\nOr go to this URL: %s", url);
	} else
#endif
	{
		pam_info(ctx->pamh, "Go to this URL to get a login token: %s", url);
	}

	return 0;
}

EXPORT_SYMBOL int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	(void) flags;

	int _;
	struct context ctx;

	memset(&ctx, 0, sizeof(ctx));

	ctx.pamh = pamh;
	ctx.response_mode = RESPONSE_CODE;

#ifdef HAVE_QR
	ctx.qr_enabled = true;
	ctx.qr_mode = QR_MODE_UTF8;
#endif

	if (parse_args(&ctx, argc, argv) < 0)
		return PAM_AUTHINFO_UNAVAIL;

	if (!ctx.hostname[0]) {
		if (gethostname(ctx.hostname, sizeof(ctx.hostname)) < 0) {
			pam_syslog(pamh, LOG_ERR, "could not get hostname: %s", strerror(errno));
			return PAM_AUTHINFO_UNAVAIL;
		}
	}

	_ = pam_get_user(ctx.pamh, &ctx.user, NULL);
	if (_ != PAM_SUCCESS) {
		pam_syslog(ctx.pamh, LOG_ERR, "could not get user name: %s", pam_strerror(ctx.pamh, _));
		return PAM_USER_UNKNOWN;
	}

	AUTOFREE_PTR(char, expected_response);
	if (output_challenge(&ctx, &expected_response) < 0) {
		pam_syslog(pamh, LOG_ERR, "could not generate challenge");
		return PAM_AUTHINFO_UNAVAIL;
	}

	char *response;
	_ = pam_prompt(ctx.pamh, PAM_PROMPT_ECHO_ON, &response,
	               "Enter login %s: ", response_mode_name[ctx.response_mode]);
	if (_ != PAM_SUCCESS) {
		pam_syslog(ctx.pamh, LOG_ERR, "could not get token response: %s", pam_strerror(ctx.pamh, _));
		return PAM_AUTHINFO_UNAVAIL;
	}

	/* We can do a non-constant-time compare here since the attacker
	 * doesn't learn anything about future expected responses from the time
	 * the comparison took.
	 *
	 * Furthermore, in the case of the "phrase" mode, we allow the user to
	 * enter a longer phrase as long as the prefix we want to see matches.
	 * This does not reduce security as an attacker would still have to
	 * guess the prefix correctly, but allows for some resilience in case
	 * of length mismatches between the server and ourselves: A user can
	 * always enter the full phrase as a fallback.
	 *
	 * In the case of the "code" mode, we ignore whitespace in the
	 * comparison. This allows grouping numbers for readability. */

	bool equal = false;

	switch (ctx.response_mode) {
		case RESPONSE_CODE:
			equal = streq_isgraph(response, expected_response);
			break;
		case RESPONSE_PHRASE:
			equal = strneq(response, expected_response, strlen(expected_response));
			break;
	}

	free(response);

	return equal ? PAM_SUCCESS : PAM_AUTH_ERR;
}

EXPORT_SYMBOL int pam_sm_setcred (pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	(void) pamh;
	(void) flags;
	(void) argc;
	(void) argv;

	return PAM_SUCCESS;
}
