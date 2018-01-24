// Example code for performing Pico server-side authentication

#include "pico/pico.h"
#include "pico/auth.h"
#include "pico/displayqr.h"
#include "pico/keyauth.h"
#include "pico/debug.h"
#include "pico/sigmaverifier.h"
#include "pico/continuous.h"
#include "pico/channel.h"
#include "pico/channel_bt.h"
#include "pico/log.h"

bool auth_auth(Shared * shared, Users * authorizedUsers, Buffer * returnedStoredData, QrCallbackFunction qrCallback, void * data, Buffer * localSymmetricKey, RVPChannel * channel) {
	KeyPair * serviceIdentityKey;
	bool result;
	size_t size;
	char * qrtext;
	Buffer * buffer;
	KeyAuth * keyauth;

	buffer = buffer_new(0);

	channel_get_url(channel, buffer);
	result = (buffer_get_pos(buffer) > 0);

	if (result) {
		serviceIdentityKey = shared_get_service_identity_key(shared);

		// SEND
		// Generate a visual QR code for Key Pairing
		// {"sn":"NAME","spk":"PUB-KEY","sig":"B64-SIG","ed":"","sa":"URL","td":{},"t":"KP"}
		keyauth = keyauth_new();
		keyauth_set(keyauth, buffer, "", NULL, serviceIdentityKey);

		size = keyauth_serialize_size(keyauth);
		qrtext = MALLOC(size + 1);
		keyauth_serialize(keyauth, qrtext, size + 1);
		keyauth_delete(keyauth);

		result = qrCallback(qrtext, data);
		FREE(qrtext);
	}
	
	if (result) {
		//result = sigmaverifier(shared, channel, authorizedUsers, NULL, returnedStoredData, localSymmetricKey);
		result = sigmaverifier_session(shared, channel, authorizedUsers, "", returnedStoredData, localSymmetricKey, true, 0);
	}
	
	buffer_delete(buffer);

	return result;
}

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
	Buffer * extra_data;
	Continuous * continuous;
	RVPChannel * channel;
	bool auth_result;
	int count;

	// Load in the service's identity keys
	result = shared_load_service_keys(shared, "./pico_pub_key.der", "./pico_priv_key.der");
	if (result == false) {
		printf("Failed to load service keys.\n");
	}

	// Load in the user list
	extra_data = buffer_new(0);
	USERFILE userresult = users_load(users, "./users.txt");
	if ((userresult != USERFILE_SUCCESS) && (userresult != USERFILE_IOERROR)) {
		printf("Error reading users file: %d\n", userresult);
		result = false;
	}

	// Perform the authentication
	if (result == true) {
		// Request a new rendezvous channel
		channel = channel_new();
		//channel_set_bt(channel);

		result = auth_auth(shared, users, extra_data, display_qr, NULL, NULL, channel);
		buffer_print(extra_data);
	}

	buffer_delete(extra_data);
	printf ("Authentication result: %d\n", result);

	// Tidy things up
	users_delete(users);



	continuous = continuous_new();
	continuous_set_shared_key(continuous, shared_get_shared_key(shared));
	continuous_set_channel(continuous, channel);
	shared_delete(shared);


	printf("Starting continuous\n");
	continuous_cycle_start(continuous);

	auth_result = true;
	// Continuous authentication
	count = 0;
	while (auth_result == true) {
		printf("Authenticating cycle %d\n", count);
		auth_result = continuous_continue(continuous, NULL);
		printf("Result: %d\n", auth_result);
		count++;
	}

	// Close continuous connection
	continuous_finish(continuous);
	channel_delete(channel);
	continuous_delete(continuous);

	return 0;
}

