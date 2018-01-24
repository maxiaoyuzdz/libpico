// Example code for performing Pico server-side authentication

#include "pico/pico.h"
#include "pico/auth.h"
#include "pico/displayqr.h"

// Display a QR code on the console
bool display_qr(char * qrtext, void * localdata) {
	DisplayQR * displayqr = displayqr_new();

	printf("\nPlease scan the barcode with your Pico app to authenticate.\n\n");
	displayqr_generate(displayqr, qrtext);
	displayqr_output(displayqr);
	displayqr_delete(displayqr);

	return true;
}

// Program entry point: Pico server-side authentication protocol
int main(int argc, char **argv) {
	Shared * shared = shared_new();
	Users * users = users_new();
	bool result = true;

	// Load in the service's identity keys
	result = shared_load_service_keys(shared, "./pico_pub_key.der", "./pico_priv_key.der");
	if (result == false) {
		printf("Failed to load service keys.\n");
	}

	// Load in the user list
	USERFILE userresult = users_load(users, "./users.txt");
	if ((userresult != USERFILE_SUCCESS) && (userresult != USERFILE_IOERROR)) {
		printf("Error reading users file: %d\n", userresult);
		result = false;
	}

	// Perform the authentication
	if (result == true) {
		result = auth(shared, users, NULL, display_qr, NULL, NULL);
	}

	printf ("Authentication result: %d\n", result);

	// Tidy things up
	shared_delete(shared);
	users_delete(users);

	return 0;
}

