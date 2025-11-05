// Simple PAM authentication test program
// Usage: ./pam_auth_test <username> [service]

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#include <security/pam_appl.h>

// Read a line from tty/stdin, optionally disabling echo (for passwords).
// Returns 0 on success and allocates *out with malloc; caller must free.
static int read_line_with_echo(const char *prompt, bool echo, char **out)
{
	FILE *tty = fopen("/dev/tty", "r+");
	FILE *in = stdin;
	FILE *outf = stderr;
	int fd = fileno(in);
	struct termios oldt, newt;
	bool changed = false;
	char *line = NULL;
	size_t cap = 0;
	ssize_t len;

	if (tty) {
		in = tty;
		outf = tty;
		fd = fileno(tty);
	}

	if (prompt) {
		fputs(prompt, outf);
		fflush(outf);
	}

	if (!echo && isatty(fd)) {
		if (tcgetattr(fd, &oldt) == 0) {
			newt = oldt;
			newt.c_lflag &= ~(ECHO);
			if (tcsetattr(fd, TCSAFLUSH, &newt) == 0) {
				changed = true;
			}
		}
	}

	len = getline(&line, &cap, in);

	if (changed) {
		// Restore echo and print a newline to mimic getpass behavior
		(void)tcsetattr(fd, TCSAFLUSH, &oldt);
		fputc('\n', outf);
		fflush(outf);
	}

	if (tty) {
		fclose(tty);
	}

	if (len < 0) {
		free(line);
		return -1;
	}

	// Strip trailing newline
	if (len > 0 && line[len - 1] == '\n') {
		line[len - 1] = '\0';
	}

	*out = line; // transfer ownership
	return 0;
}

static int pam_conv_func(int num_msg, const struct pam_message **msg,
						 struct pam_response **resp, void *appdata_ptr)
{
	(void)appdata_ptr;

	if (num_msg <= 0 || msg == NULL || resp == NULL) {
		return PAM_CONV_ERR;
	}

	struct pam_response *aresp = calloc((size_t)num_msg, sizeof(struct pam_response));
	if (!aresp) {
		return PAM_CONV_ERR;
	}

	for (int i = 0; i < num_msg; i++) {
		const struct pam_message *m = msg[i];
		if (!m) {
			free(aresp);
			return PAM_CONV_ERR;
		}

		switch (m->msg_style) {
			case PAM_PROMPT_ECHO_OFF: {
				char *input = NULL;
				if (read_line_with_echo(m->msg ? m->msg : "Password: ", false, &input) != 0) {
					free(aresp);
					return PAM_CONV_ERR;
				}
				aresp[i].resp = input; // PAM will free
				aresp[i].resp_retcode = 0;
				break;
			}
			case PAM_PROMPT_ECHO_ON: {
				char *input = NULL;
				if (read_line_with_echo(m->msg ? m->msg : "Input: ", true, &input) != 0) {
					free(aresp);
					return PAM_CONV_ERR;
				}
				aresp[i].resp = input; // PAM will free
				aresp[i].resp_retcode = 0;
				break;
			}
			case PAM_ERROR_MSG:
				if (m->msg) {
					fprintf(stderr, "%s\n", m->msg);
				}
				aresp[i].resp = NULL;
				aresp[i].resp_retcode = 0;
				break;
			case PAM_TEXT_INFO:
				if (m->msg) {
					fprintf(stdout, "%s\n", m->msg);
				}
				aresp[i].resp = NULL;
				aresp[i].resp_retcode = 0;
				break;
			default:
				// Unsupported prompt style
				for (int j = 0; j <= i; j++) {
					if (aresp[j].resp) {
						// PAM expects allocated via malloc, so free safely
						free(aresp[j].resp);
					}
				}
				free(aresp);
				return PAM_CONV_ERR;
		}
	}

	*resp = aresp;
	return PAM_SUCCESS;
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		fprintf(stderr, "Usage: %s <username> [service]\n", argv[0]);
		return 2;
	}

	const char *user = argv[1];
	const char *service = (argc >= 3) ? argv[2] : "login";

	struct pam_conv conv = { .conv = pam_conv_func, .appdata_ptr = NULL };
	pam_handle_t *pamh = NULL;

	int ret = pam_start(service, user, &conv, &pamh);
	if (ret != PAM_SUCCESS) {
		fprintf(stderr, "pam_start failed (code %d)\n", ret);
		return 1;
	}

	ret = pam_authenticate(pamh, 0);
	if (ret == PAM_SUCCESS) {
		fprintf(stdout, "Authentication success for user '%s' (service '%s')\n", user, service);
	} else {
		fprintf(stderr, "Authentication failed for user '%s' (service '%s'), code %d\n", user, service, ret);
	}

	// End the PAM transaction; pass the last status
	int end_ret = pam_end(pamh, ret);
	if (end_ret != PAM_SUCCESS) {
		fprintf(stderr, "pam_end returned code %d\n", end_ret);
	}

	return ret == PAM_SUCCESS ? 0 : 1;
}

