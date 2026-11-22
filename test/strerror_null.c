// Regression test: pam_strerror() must work without a pam_handle_t.
//
// libpam ignores the handle here (libpam/pam_strerror.c declares it UNUSED),
// so applications legitimately pass NULL - for example after a failed
// pam_start() left them without a handle, or when the PAM transaction runs in
// a separate process. pam_shim used to dereference the handle unconditionally
// and crash the caller.

#include <stdio.h>

#include <security/pam_appl.h>

static int failures;

static void check(int errnum, const char *what)
{
	const char *message = pam_strerror(NULL, errnum);

	if (message == NULL) {
		fprintf(stderr, "FAIL: pam_strerror(NULL, %s) returned NULL\n", what);
		failures++;
		return;
	}
	if (message[0] == '\0') {
		fprintf(stderr, "FAIL: pam_strerror(NULL, %s) returned an empty string\n", what);
		failures++;
		return;
	}
	printf("ok: pam_strerror(NULL, %s) = \"%s\"\n", what, message);
}

int main(void)
{
	check(PAM_SUCCESS, "PAM_SUCCESS");
	check(PAM_AUTH_ERR, "PAM_AUTH_ERR");
	check(PAM_OPEN_ERR, "PAM_OPEN_ERR");
	check(PAM_BAD_ITEM, "PAM_BAD_ITEM");
	/* Unknown codes must still yield a string, like libpam does. */
	check(12345, "unknown code");

	if (failures != 0) {
		fprintf(stderr, "%d check(s) failed\n", failures);
		return 1;
	}
	printf("all checks passed\n");
	return 0;
}
