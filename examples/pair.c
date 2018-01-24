// Example code for performing Pico client-side authentication

#include "pico/pico.h"
#include "pico/auth.h"
#include "pico/displayqr.h"

// Display a QR code on the console
bool display_qr(char * qrtext, void * localdata) {
	DisplayQR * displayqr = displayqr_new();

	printf("\nPlease scan the barcode with your Pico app to pair.\n\n");
	displayqr_generate(displayqr, qrtext);
	displayqr_output(displayqr);
	displayqr_delete(displayqr);

	return true;
}

// Program entry point: Pico server-side pairing protocol
int main(int argc, char **argv) {
	char const * username = "testuser";
	char const * hostname = "testhost";
	Shared * shared = shared_new();
	Users * users = users_new();
	bool result = true;

	// Load in the service's identity keys if they exist, or generate new ones
	shared_load_or_generate_keys(shared, "./pico_pub_key.der", "pico_priv_key.der");

	// Load in the user list
	USERFILE userresult = users_load(users, "./users.txt");
	if ((userresult != USERFILE_SUCCESS) && (userresult != USERFILE_IOERROR)) {
		printf("Error reading users file: %d\n", userresult);
		result = false;
	}

	// Perfrom the pairing
	if (result == true) {
		result = pair_send_username_loop(shared, hostname, "", username, NULL, display_qr, NULL, 45);
	}

	// Export the resulting user list
	if (result == true) {
		users_add_user(users, username, shared_get_pico_identity_public_key(shared), NULL);
		userresult = users_export(users, "./users.txt");
		if (userresult != USERFILE_SUCCESS) {
			printf("Error saving users file: %d\n", userresult);
			result = false;
		}
	}

	printf ("User %s pairing with %s result: %d\n", username, hostname, result);

	// Tidy things up
	shared_delete(shared);
	users_delete(users);

	return 0;
}

