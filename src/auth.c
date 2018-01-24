/** \ingroup Protocol
 * @file
 * @author  David Llewellyn-Jones <David.Llewellyn-Jones@cl.cam.ac.uk>
 * @version $(VERSION)
 *
 * @section LICENSE
 *
 * (C) Copyright Cambridge Authentication Ltd, 2017
 *
 * This file is part of libpico.
 *
 * Libpico is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * Libpico is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public
 * License along with libpico. If not, see
 * <http://www.gnu.org/licenses/>.
 *
 *
 * @brief Performs the server authentication and pairing protocols
 * @section DESCRIPTION
 *
 * The Auth class encapsulates the Pico server authentication and pairing
 * protocol into single call. 
 *
 */

/** \addtogroup Protocol
 *  @{
 */

#include <stdio.h>
#include "pico/debug.h"
#include "pico/buffer.h"
#include "pico/channel.h"
#include "pico/keypair.h"
#include "pico/keyauth.h"
#include "pico/shared.h"
#include "pico/sigmaverifier.h"
#include "pico/users.h"
#include "pico/log.h"
#include "pico/auth.h"
#include "pico/keypairing.h"
#include "pico/json.h"

// Defines

// Structure definitions

// Function prototypes

// Function definitions

/**
* Basically the same function as pair_loop, but the data sent to the phone is sent in a Json string as:
* {"data": extraData, "name": username}
* Newer version of the App will be able to save extraData and use username as the pairing name
*/
bool pair_send_username_loop(Shared * shared, char const * servicename, char const * extraData, char const * username, Buffer * returnedStoredData, QrCallbackFunction qrCallback, void * data, int loop_verifier) {
	Json * extraDataJson = json_new();
	Buffer * buffer = buffer_new(0);

	json_add_string(extraDataJson, "data", extraData);
	json_add_string(extraDataJson, "name", username);
	
	json_serialize_buffer(extraDataJson, buffer);
	buffer_append(buffer, "", 1);

	bool result = pair_loop(shared, servicename, buffer_get_buffer(buffer), returnedStoredData, qrCallback, data, loop_verifier);

	json_delete(extraDataJson);
	buffer_delete(buffer);

	return result;
}

/**
 * Server code for performing the pairing stage Pico protocol.
 * Basically the same as pair_loop, but looping only once, i.e.
 * returning directly if the first pairing failed
 *
 * @param shared Structure for managing shared secrets.
 * @param servicename The name of the service the Pico will pair with
 * @param extraData Extra data to be saved with the pairing
 * @param returnedStoredData bluetooth address sent as extra data
 * @param qrCallback Function to be called in with the qrcode text 
 * @param data Pointer to be sent to qrCallback 
 * @return true if pairing completed successfully. false o/w.
 */
bool pair(Shared * shared, char const * servicename, char const * extraData, Buffer * returnedStoredData, QrCallbackFunction qrCallback, void * data) {
	return pair_loop(shared, servicename, extraData, returnedStoredData, qrCallback, data, 1);
}

/**
 * Server code for performing the pairing stage Pico protocol.
 *
 * @param shared Structure for managing shared secrets.
 * @param servicename The name of the service the Pico will pair with
 * @param extraData Extra data to be saved with the pairing
 * @param returnedStoredData bluetooth address sent as extra data
 * @param qrCallback Function to be called in with the qrcode text 
 * @param data Pointer to be sent to qrCallback 
 * @param loopVerifier How many time to try the sigma verifier before returning false
 * @return true if pairing completed successfully. false o/w.
 */
bool pair_loop(Shared * shared, char const * servicename, char const * extraData, Buffer * returnedStoredData, QrCallbackFunction qrCallback, void * data, int loopVerifier) {
	RVPChannel * channel;
	KeyPair * serviceIdentityKey;
	bool result;
	size_t size;
	char * qrtext;
	Buffer * buffer;
	KeyPairing * keypairing;
	int i;

	// Request a new rendezvous channel
	channel = channel_new();
	buffer = buffer_new(0);

	channel_get_url(channel, buffer);
	result = (buffer_get_pos(buffer) > 0);

	if (result) {
		serviceIdentityKey = shared_get_service_identity_key(shared);

		// SEND
		// Generate a visual QR code for Key Pairing
		// {"sn":"NAME","spk":"PUB-KEY","sig":"B64-SIG","ed":"","sa":"URL","td":{},"t":"KP"}
		keypairing = keypairing_new();
		keypairing_set(keypairing, buffer, "", NULL, servicename, serviceIdentityKey);

		size = keypairing_serialize_size(keypairing);
		qrtext = MALLOC(size + 1);
		keypairing_serialize(keypairing, qrtext, size + 1);
		keypairing_delete(keypairing);

		result = qrCallback(qrtext, data);
		
		FREE(qrtext);
	}
	
	if (result) {
		result = false;
		for (i = 0; i < loopVerifier && !result; i++) {
			result = sigmaverifier(shared, channel, NULL, extraData, returnedStoredData, NULL);
		}
	}
	
	buffer_delete(buffer);
	channel_delete(channel);

	return result;
}

/**
 * Server code for performing the authorisation stage Pico protocol.
 *
 * @param shared Structure for managing shared secrets.
 * @param authorizedUsers List of users authorized to complete successfully.
 * @param returnedStoredData If not NULL, is appended with a string
 *                          containing data returned from Pico.
 *                          This data was sent when paired.
 * @param qrCallback Function to be called in with the qrcode text 
 * @param data Pointer to be sent to qrCallback 
 * @param localSymmetricKey User's locally stored symmetric key
 * @return true if authentication completed successfully. false o/w.
 */
bool auth(Shared * shared, Users * authorizedUsers, Buffer * returnedStoredData, QrCallbackFunction qrCallback, void * data, Buffer * localSymmetricKey) {
	RVPChannel * channel;
	KeyPair * serviceIdentityKey;
	bool result;
	size_t size;
	char * qrtext;
	Buffer * buffer;
	KeyAuth * keyauth;

	// Request a new rendezvous channel
	channel = channel_new();
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
		result = sigmaverifier(shared, channel, authorizedUsers, NULL, returnedStoredData, localSymmetricKey);
	}

	buffer_delete(buffer);
	channel_delete(channel);

	return result;
}

/** @} addtogroup Protocol */

