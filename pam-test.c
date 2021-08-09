#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>

#include <security/_pam_macros.h>
#include <security/pam_ext.h>
#include <security/pam_misc.h>
#include <security/pam_modutil.h>
#include <security/pam_modules.h>

extern int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv);

struct pam_handle {}; // allow making a pam_handle instance later;

const char *login_user;

void pam_syslog(const pam_handle_t *pamh, int priority, const char *fmt, ...)
{
	(void) pamh;

	va_list args;
	va_start(args, fmt);

	printf("syslog %d: ", priority);
	vprintf(fmt, args);
	printf("\n");
	fflush(stdout);

	va_end(args);
}

const char *pam_strerror(pam_handle_t *pamh, int errnum)
{
	(void) pamh;
	(void) errnum;

	static char buf[64];

	snprintf(buf, sizeof(buf), "mock, errno=%d", errnum);

	return buf;
}

int pam_prompt(pam_handle_t *pamh, int style, char **response, const char *fmt, ...)
{
	(void) pamh;
	(void) style;

	va_list args;
	va_start(args, fmt);

	vprintf(fmt, args);
	fflush(stdout);

	va_end(args);

	if (style == PAM_PROMPT_ECHO_ON || style == PAM_PROMPT_ECHO_OFF) {
		char *buf;
		buf = calloc(256, sizeof(char));
		if (!buf)
			return PAM_SYSTEM_ERR;

		fgets(buf, 256, stdin);
		size_t len = strlen(buf);
		if (len == 0 || buf[len-1] != '\n') {
			free(buf);
			return PAM_SYSTEM_ERR;
		}

		buf[len-1] = 0;
		*response = buf;
	} else {
		putchar('\n');
	}

	return PAM_SUCCESS;
}

int pam_get_user(pam_handle_t *pamh, const char **user, const char *prompt)
{
	(void) pamh;
	(void) prompt;

	*user = login_user;
	return 0;
}

int main(int argc, char **argv)
{
	int _;

	if (argc < 2) {
		fprintf(stderr, "usage: %s user [pam module args]\n", argv[0]);
		return EXIT_FAILURE;
	}

	login_user = argv[1];

	struct pam_handle handle; // make ubsan happy by not passing NULL

	_ = pam_sm_authenticate(&handle, 0, argc - 2, (const char**)(argv + 2));
	if (_ == PAM_SUCCESS) {
		printf("success\n");
		return EXIT_SUCCESS;
	} else {
		printf("failed with return code %d\n", _);
		return EXIT_FAILURE;
	}
}
