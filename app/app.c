// Example extended from libpam documentation

#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <stdbool.h>
#include <termios.h>

// See http://stackoverflow.com/questions/1413445/read-a-password-from-stdcin
void set_echo(bool enable)
{
	struct termios tty;
	tcgetattr(STDIN_FILENO, &tty);
	if (enable == false) {
		tty.c_lflag &= ~ECHO;
	}
	else {
		tty.c_lflag |= ECHO;
	}
	(void) tcsetattr(STDIN_FILENO, TCSANOW, &tty);
}

int text_conv (int num_msg, const struct pam_message ** msg, struct pam_response ** resp, void *appdata_ptr) {
	int msg_count;
	struct pam_message const * current_msg;
	struct pam_response * current_resp;
	char * inputline;
	size_t read;
	int result;

	result = PAM_SUCCESS;
	*resp = calloc(sizeof(struct pam_response), num_msg);

	for (msg_count = 0; msg_count < num_msg; msg_count++) {
		current_msg = msg[msg_count];
		current_resp = & (*resp[msg_count]);

		current_resp->resp_retcode = 0;

		switch (current_msg->msg_style) {
			case PAM_PROMPT_ECHO_OFF:
				printf("%s (no echo) \n", current_msg->msg);
				set_echo(false);
				inputline = NULL;
				read = 0;
				read = getline(&inputline, &read, stdin);
				// Remove final \n delimiter
				if (inputline && (read > 0) && (inputline[read - 1] == '\n')) {
					inputline[read - 1] = 0;
				}
				current_resp->resp = inputline;
				set_echo(true);
				break;
			case PAM_PROMPT_ECHO_ON:
				printf("%s (echo) \n", current_msg->msg);
				inputline = NULL;
				read = 0;
				read = getline(&inputline, &read, stdin);
				// Remove final \n delimiter
				if (inputline && (read > 0) && (inputline[read - 1] == '\n')) {
					inputline[read - 1] = 0;
				}
				current_resp->resp = inputline;
				break;
			case PAM_ERROR_MSG:
				printf("Error: %s\n", current_msg->msg);
				break;
			case PAM_TEXT_INFO:
				printf("Message: %s\n", current_msg->msg);
				break;
			default:
				printf("Unknown PAM message type.\n");
				result = PAM_CONV_ERR;
				break;
		}
	}
	
	return result;
}

static struct pam_conv conv = {
	text_conv,
	NULL
};

int main(int argc, char *argv[])
{
	pam_handle_t *pamh=NULL;
	int retval;
	const char *user=NULL;

	if(argc == 2) {
		user = argv[1];
	}

	if(argc > 2) {
		fprintf(stderr, "Usage: check_user [username]\n");
		exit(1);
	}

	printf("pam_start\n");
	retval = pam_start("check_user", user, &conv, &pamh);
	printf("Done\n");

	if (retval == PAM_SUCCESS) {
		printf("pam_authenticate\n");
		retval = pam_authenticate(pamh, 0);	/* is user really user? */
		printf("Done\n");
	}

	if (retval == PAM_SUCCESS) {
		printf("pam_acct_mgmt\n");
		retval = pam_acct_mgmt(pamh, 0);	   /* permitted access? */
		printf("Done\n");
	}

	/* This is where we have been authorized or not. */

	if (retval == PAM_SUCCESS) {
		fprintf(stdout, "Authenticated\n");
	} else {
		fprintf(stdout, "Not Authenticated\n");
	}

	printf("pam_end\n");
	retval = pam_end(pamh,retval);
	printf("Done\n");
	if (retval != PAM_SUCCESS) {	 /* close Linux-PAM */
		pamh = NULL;
		fprintf(stderr, "check_user: failed to release authenticator\n");
		exit(1);
	}

	return ( retval == PAM_SUCCESS ? 0:1 );	   /* indicate success */
}
