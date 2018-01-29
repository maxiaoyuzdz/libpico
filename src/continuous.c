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
 * @brief Continuous authentication protocol support
 * @section DESCRIPTION
 *
 * Once a device has been authenticated, it can offer to remain authenticated
 * on a continuous basis. In this case the verifier and prover will perform a
 * ping-pong message exchange on a regular basis (e.g. once every ten seconds).
 * In the event that the messages fail to arrive or can't be correctly decoded
 * (e.g. the decryption fails) then the authenticated session closes. In this
 * way the user can be continuously authenticated based on some characteristic
 * such as being within communication range.
 * 
 * The continuous class provides support for these continuous authentication
 * activities.
 *
 */

/** \addtogroup Protocol
 *  @{
 */

#include <stdio.h>
#include <malloc.h>
#include "pico/debug.h"
#include "pico/buffer.h"
#include "pico/keypair.h"
#include "pico/keyauth.h"
#include "pico/sigmaverifier.h"
#include "pico/messagepicoreauth.h"
#include "pico/messageservicereauth.h"
#include "pico/messagestatus.h"
#include "pico/sequencenumber.h"
#include "pico/continuous.h"
#include "pico/log.h"

// Defines
#define DEFAULT_CONTINUOUS_TIMEOUT_ACTIVE (10000)
#define DEFAULT_CONTINUOUS_TIMEOUT_PAUSED (50000)
#define DEFAULT_CONTINUOUS_TIMEOUT_LEEWAY (5000)
#define MAX(x,y) ((x) > (y) ? (x) : (y))


// Structure definitions

/**
 * @brief Structure used for continuous authentication
 *
 * Opaque structure containing the private fields of the Continuous class.
 *
 * This is provided as the first parameter of every non-static function and 
 * stores the operation's context.
 *
 * The structure typedef is in continuous.h
 */
struct _Continuous {
	RVPChannel * channel;
	Buffer * sharedKey;
	REAUTHSTATE currentState;
	SequenceNumber * picoSeqNumber;
	SequenceNumber * serviceSeqNumber;
	int timeoutActive;
	int timeoutPaused;
	int timeoutLeeway;
	int currentTimeout;
};

// Function prototypes

static REAUTHSTATE continuous_transition(REAUTHSTATE oldState, REAUTHSTATE newState);

// Function definitions

/**
 * Perform a state transition if this is allowed by the continuous
 * authentication state machine. If the transition isn't allowed, will return
 * an error state.
 *
 * See messagepicoreauth.h for the possible REAUTHSTATE values.
 *
 * @param oldState The state to transition from.
 * @param newState The state to transition to.
 * @return The state transition to: newState if the transition is valid,
 *         REAUTHSTATE_ERROR otherwise.
 */
static REAUTHSTATE continuous_transition(REAUTHSTATE oldState, REAUTHSTATE newState) {
	REAUTHSTATE ret = REAUTHSTATE_ERROR;

	switch (oldState) {
		case REAUTHSTATE_CONTINUE:
			if (newState == REAUTHSTATE_CONTINUE || newState == REAUTHSTATE_PAUSE || newState == REAUTHSTATE_STOP) {
				ret = newState;
			} else {
				LOG(LOG_ERR, "Invalid transition: %d %d\n", oldState, newState);
				ret = REAUTHSTATE_ERROR;
			}
			break;
		case REAUTHSTATE_PAUSE:
			if (newState == REAUTHSTATE_CONTINUE || newState == REAUTHSTATE_PAUSE || newState == REAUTHSTATE_STOP) {
				ret = newState;
			}
			else {
				LOG(LOG_ERR, "Invalid transition: %d %d\n", oldState, newState);
				ret = REAUTHSTATE_ERROR;
			}
			break;
		case REAUTHSTATE_STOP:
			if (newState == REAUTHSTATE_STOP) {
				ret = newState;
			}
			else {
				LOG(LOG_ERR, "Invalid transition: %d %d\n", oldState, newState);
				ret = REAUTHSTATE_ERROR;
			}
			break;
		case REAUTHSTATE_ERROR:
		default:
			ret = REAUTHSTATE_ERROR;
			break;
	}

	return ret;
}

/**
 * Create a new instance of the class.
 *
 * @return The newly created object.
 */
Continuous * continuous_new() {
	Continuous * continuous;

	continuous = CALLOC(sizeof(Continuous), 1);
	continuous->channel = NULL;
	continuous->sharedKey = buffer_new(0);
	continuous->currentState = REAUTHSTATE_INVALID;
	continuous->picoSeqNumber = sequencenumber_new();
	continuous->serviceSeqNumber = sequencenumber_new();
	continuous->timeoutActive = DEFAULT_CONTINUOUS_TIMEOUT_ACTIVE;
	continuous->timeoutPaused = DEFAULT_CONTINUOUS_TIMEOUT_PAUSED;
	continuous->timeoutLeeway = DEFAULT_CONTINUOUS_TIMEOUT_LEEWAY;
	continuous->currentTimeout = continuous->timeoutActive;

	return continuous;
}

/**
 * Sets a new continuous state and update the timeout corresponding
 * Important: This is an internal function and should not be called from outside.
 *
 * @param continuous The continuous object
 * @param state The new state
 */
void continuous_set_current_state(Continuous* continuous, REAUTHSTATE state) {
	continuous->currentState = state;
	if (continuous->currentState == REAUTHSTATE_CONTINUE) {
		continuous->currentTimeout = continuous->timeoutActive;
	} else if (continuous->currentState == REAUTHSTATE_PAUSE) {
		continuous->currentTimeout = continuous->timeoutPaused;
	} else {
		// If the state if different than continuous and pause, then no more read
		// will be called. Anyway, we set the timeout as 0 so if a read is attempted
		// the timeout will be the shortest possible.
		continuous->currentTimeout = 0;
	}
}

/**
 * Set the timeout for next read
 *
 * @param timeout_active Time to wait for Pico when in active state
 * @param timeout_paused Time to wait for Pico when in paused state
 */
void continuous_set_custom_timeout(Continuous * continuous, int timeout_active, int timeout_paused) {
	continuous->timeoutActive = timeout_active;
	continuous->timeoutPaused = timeout_paused;

	// Update state to force updating the currentTimeout variable
	continuous_set_current_state(continuous, continuous->currentState);
}

/**
 * Set the leeway that's allowed beyond the next timeout before the
 * authentication is considered to have failed.
 *
 * The default value is DEFAULT_CONTINUOUS_TIMEOUT_LEEWAY (5 seconds).
 *
 * @param timeout_leeway Time to wait beyond the time out before authentication
 *                       is considered to have failed
 */
void continuous_set_custom_timeout_leeway(Continuous * continuous, int timeout_leeway) {
	continuous->timeoutLeeway = timeout_leeway;
}

/**
 * Delete an instance of the class, freeing up the memory allocated to it.
 *
 * @param continuous The object to free.
 */
void continuous_delete(Continuous * continuous) {
	if (continuous) {
		if (continuous->sharedKey) {
			buffer_delete(continuous->sharedKey);
		}

		if (continuous->picoSeqNumber) {
			sequencenumber_delete(continuous->picoSeqNumber);
		}
		if (continuous->serviceSeqNumber) {
			sequencenumber_delete(continuous->serviceSeqNumber);
		}

		FREE(continuous);
	}
}

/**
 * Sets the current sequence number for the Pico.
 * This is used by continuous_cycle_start and should not be used
 * by a third-party in normal conditions.
 *
 * @parm continuous The object to set the Pico sequence number of.
 * @param seqNumber The sequence number to set. This value will be copied (s0
 *        can be safely freed after this call).
 */
void continuous_set_pico_sequence_number(Continuous * continuous, SequenceNumber * seqNumber) {
	sequencenumber_copy(continuous->picoSeqNumber, seqNumber);
}

/**
 * Sets the current sequence number for the Service.
 * This is used by continuous_cycle_start_pico and should not be used
 * by a third-party in normal conditions.
 *
 * @parm continuous The object to set the service sequence number of.
 * @param seqNumber The sequence number to set. This value will be copied (s0
 *        can be safely freed after this call).
 */
void continuous_set_service_sequence_number(Continuous * continuous, SequenceNumber * seqNumber) {
	sequencenumber_copy(continuous->serviceSeqNumber, seqNumber);
}

/**
 * Returns the current state.
 *
 * @param continuous The object to get the state from.
 * @return The current state as stored by the object.
 */
REAUTHSTATE continuous_get_state(Continuous * continuous) {
	return continuous->currentState;
}

/**
 * Set the shared key to be used by the continuous authentication process
 * (the continuous_continue() part). Usually this would be set automatically
 * during the continuous_start() stage, but sometimes a service may want to
 * perform it's own initial authentication step, rather than using the standard
 * version in continuous_start(). In this case, it should set the key itself
 * using this function.
 * This will make a copy of the shared key, so it's safe to destroy the
 * original buffer independent of the continuous structure.
 *
 * @param continuous The object to set the shared key for.
 * @param sharedKey Buffer containing the key data to copy into the 
 *        continuous structure.
 */
void continuous_set_shared_key(Continuous * continuous, Buffer * sharedKey) {
	if (continuous) {
		buffer_clear(continuous->sharedKey);
		buffer_append_buffer(continuous->sharedKey, sharedKey);
	}
}

/**
 * Get the shared key being used by the continuous authentication process
 * (the continuous_continue() part).
 * This will make a copy of the shared key, so it's safe to destroy the
 * output buffer independent of the continuous structure.
 *
 * @param continuous The object to get the shared key from.
 * @param sharedKey Buffer to copy the key data into from the 
 *        continuous structure.
 */
void continuous_get_shared_key(Continuous * continuous, Buffer * sharedKey) {
	if (continuous && sharedKey) {
		buffer_clear(sharedKey);
		buffer_append_buffer(sharedKey, continuous->sharedKey);
	}
}

/**
 * Set the channel for the continuous prover.
 * The channel won't be destroyed when the continuous object is destroyed. 
 * Its lifecycle must be managed independent of the continuous lifecycle.
 *
 * @param continuous The object to set the channel for.
 * @param channel The channel to set it to.
 */
void continuous_set_channel(Continuous * continuous, RVPChannel * channel) {
	continuous->channel = channel;
}

/**
 * Get the channel of the continuous prover.
 * The channel won't be destroyed when the continuous object is destroyed. 
 * Its lifecycle must be managed independent of the continuous lifecycle.
 *
 * @param continuous The object to get the channel from.
 * @return The channel currently being used.
 */
RVPChannel * continuous_get_channel(Continuous * continuous) {
	return continuous->channel;
}

/**
 * Server code for performing the start of a Pico continuous authorisation 
 * protocol.
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
bool continuous_start(Continuous * continuous, Shared * shared, Users * authorizedUsers, Buffer * returnedStoredData, QrCallbackFunction qrCallback, void * data, Buffer * localSymmetricKey) {
	RVPChannel * channel;
	KeyPair * serviceIdentityKey;
	bool result;
	size_t size;
	char * qrtext;
	Buffer * buffer;
	KeyAuth * keyauth;
	Buffer * sharedKey;

	// Request a new rendezvous channel
	channel = continuous->channel;
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
		channel_open(channel);
		result = sigmaverifier_session(shared, channel, authorizedUsers, NULL, returnedStoredData, localSymmetricKey, true, 0);
		channel_close(channel);
	}

	if (result) {
		sharedKey = shared_get_shared_key(shared);
		buffer_clear(continuous->sharedKey);
		buffer_append_buffer(continuous->sharedKey, sharedKey);
		continuous_set_current_state(continuous, REAUTHSTATE_CONTINUE);
	}

	buffer_delete(buffer);

	return result;
}

/**
 * Initialise the continuous part of the continuous authentication process
 * on the service.
 * This should be called after continuous_start(), but before the first
 * call to continuous_continue().
 *
 * @param continuous The continuous prover object.
 * @return true if everything was successfully set up.
 */
bool continuous_cycle_start(Continuous * continuous) {
	bool result;
	SequenceNumber * sequenceNum;
	REAUTHSTATE receivedState = REAUTHSTATE_INVALID;

	sequenceNum = sequencenumber_new();

	result = channel_open(continuous->channel);
	
	if (result) {
		LOG(LOG_INFO, "First read, allowing default timeout");
		channel_set_timeout(continuous->channel, DEFAULT_CONTINUOUS_TIMEOUT_ACTIVE);
		result = continuous_read_pico_reauth(continuous, sequenceNum, NULL);
		receivedState = continuous->currentState;
	}

	if (receivedState != REAUTHSTATE_INVALID && receivedState != REAUTHSTATE_ERROR) {
		// To avoid replay attacks, we *must* initialise the service sequence
		// number to a good random number
		sequencenumber_random(continuous->serviceSeqNumber);

		// Increment and store the sequence number received from the Pico
		sequencenumber_increment(sequenceNum);
		continuous_set_pico_sequence_number(continuous, sequenceNum);
		continuous_set_current_state(continuous, receivedState);
		result = continuous_write_service_reauth(continuous);
	}

	sequencenumber_delete(sequenceNum);

	return result;
}

/**
 * Initialise the continuous part of the continuous authentication process
 * on the Pico.
 * This should be called after continuous_start(), but before the first
 * call to continuous_continue_pico().
 *
 * @param continuous The continuous prover object.
 * @return true if everything was successfully set up.
 */
bool continuous_cycle_start_pico(Continuous * continuous, Buffer * extraData) {
	bool result;
	SequenceNumber * sequenceNum;

	result = channel_open(continuous->channel);
	
	if (result) {
		// To avoid replay attacks, we *must* initialise the Pico sequence
		// number to a good random number
		sequencenumber_random(continuous->picoSeqNumber);

		continuous_set_current_state(continuous, REAUTHSTATE_CONTINUE);
		result = continuous_write_pico_reauth(continuous, extraData);
	}

	if (result) {
		sequenceNum = sequencenumber_new();

		result = continuous_read_service_reauth(continuous, sequenceNum, NULL);

		// Increment and store the sequence number received from the Service
		sequencenumber_increment(sequenceNum);
		continuous_set_service_sequence_number(continuous, sequenceNum);

		sequencenumber_delete(sequenceNum);
	}

	return result;
}

/**
 * Waits for a Pico reauth message, deserializes the result and checks for
 * consistency.
 *
 * This function will block until the channel can be read from, or until
 * the channel times out. The continuous state will be updated
 *
 * If successful, the sequence number in the continuous struct will be
 * incremented.
 *
 * If sequenceNumber is NULL, the sequence number verification will be
 * performed. Otherwise, the number returned from the Pico will be written.
 *
 * @param continuous The continuous structure holding the context.
 * @param sequenceNumber The sequence number to set, or NULL to check the
          received number against the internal state.
 * @param returnedStoredData A buffer to store any returned extraData into.
 * @return True if the message was read correctly.
*/
bool continuous_read_pico_reauth(Continuous * continuous, SequenceNumber * sequenceNumber, Buffer * returnedStoredData) {
	bool result;
	bool sequencenumber_match;
	Buffer * buffer;
	MessagePicoReAuth * messagepicoreauth;
	SequenceNumber * sequenceNum;

	buffer = buffer_new(0);
	sequenceNum = sequencenumber_new();
	sequencenumber_match = true;

	// RECEIVE
	// Read PicoReAuthMessage from client
	// {"encryptedData":"B64-ENC","iv":"B64","sessionId":0}
	buffer_clear(buffer);
	result = channel_read(continuous->channel, buffer);
	LOG(LOG_INFO, "PicoReauth received\n");

	if (result) {
		// Deserialize the message
		messagepicoreauth = messagepicoreauth_new();
		messagepicoreauth_set(messagepicoreauth, continuous->sharedKey, NULL);
		result = messagepicoreauth_deserialize(messagepicoreauth, buffer);
	}

	if (result) {
		messagepicoreauth_get_sequencenum(messagepicoreauth, sequenceNum);
		continuous_set_current_state(continuous, messagepicoreauth_get_reauthstate(messagepicoreauth));
		messagepicoreauth_delete(messagepicoreauth);

		if (sequenceNumber != NULL) {
			// This is an initialisation message, so store the receied sequence
			// number for future use
			sequencenumber_copy(sequenceNumber, sequenceNum);
		} else {
			// This is a subsequence message, so check that the sequence number
			// has been incremented by the Pico. If it's all good, store the result
			sequencenumber_match = sequencenumber_equals(continuous->picoSeqNumber, sequenceNum);
			if (!sequencenumber_match) {
				LOG(LOG_INFO, "Sequence number from Pico didn't match stored value.\n");
			}
		}
	}

	if (result && sequencenumber_match) {
		sequencenumber_increment(continuous->picoSeqNumber);
	} else {
		continuous_set_current_state(continuous, REAUTHSTATE_ERROR);
	}

	buffer_delete(buffer);
	sequencenumber_delete(sequenceNum);
	
	return result;
}

/**
 * Writes a Pico reauth message. The function will block until the message
 * has been sent or the channel times out.
 *
 * If successful, the sequence number will be incremented
 *
 * @param continuous The continuous structure holding the context.
 * @param extraData The extra data to send to the service (or NULL for none).
 * @return True if we could send the message correctly
*/
bool continuous_write_pico_reauth(Continuous * continuous, Buffer * extraData) {
	bool result;
	Buffer * buffer;
	MessagePicoReAuth * messagepicoreauth;

	buffer = buffer_new(0);

	// SEND
	// Send PicoReAuthMessage from client
	// {"encryptedData":"B64-ENC","iv":"B64","sessionId":0}
	// Where encryptedData contains the following sections
	// char reauthState | length | char sequenceNumber[length] | length | char extraData[length]
	messagepicoreauth = messagepicoreauth_new();
	messagepicoreauth_set(messagepicoreauth, continuous->sharedKey, continuous->picoSeqNumber);
	messagepicoreauth_set_reauthstate(messagepicoreauth, continuous->currentState);

	messagepicoreauth_serialize(messagepicoreauth, extraData, buffer);

	// Send the message
	result = channel_write_buffer(continuous->channel, buffer);
	LOG(LOG_INFO, "PicoReauth sent\n");

	// Increment the sequence number ready for the next message
	if (result) {
		sequencenumber_increment(continuous->picoSeqNumber);
	}

	messagepicoreauth_delete(messagepicoreauth);
	buffer_delete(buffer);

	return result;
}

/**
 * Waits for a Service reauth message, deserializes the result and checks for
 * consistency.
 *
 * This function will block until the channel can be read from, or until
 * the channel times out. The continuous state will be updated
 *
 * If successful, the sequence number in the continuous struct will be
 * incremented.
 *
 * If sequenceNumber is NULL, the sequence number verification will be
 * performed. Otherwise, the number returned from the Service will be written.
 *
 * @param continuous The continuous structure holding the context.
 * @param sequenceNumber The sequence number to set, or NULL to check the
          received number against the internal state.
 * @param returnedStoredData A buffer to store any returned extraData into.
 * @return True if the message was read correctly.
*/
bool continuous_read_service_reauth(Continuous * continuous, SequenceNumber * sequenceNumber, int * timeout) {
	bool result;
	bool sequencenumber_match;
	Buffer * buffer;
	MessageServiceReAuth * messageservicereauth;
	SequenceNumber * sequenceNum;

	buffer = buffer_new(0);
	sequenceNum = sequencenumber_new();
	sequencenumber_match = true;

	// RECEIVE
	// Read with ServiceReAuthMessage
	// {"encryptedData":"B64-ENC","iv":"B64","sessionId":0}
	// Where encryptedData contains the following sections
	// char reauthState | int timeout | length | char sequenceNumber[length]
	buffer_clear(buffer);
	channel_set_timeout(continuous->channel, continuous->currentTimeout + continuous->timeoutLeeway);
	result = channel_read(continuous->channel, buffer);
	LOG(LOG_INFO, "ServiceReauth received\n");

	if (result) {
		// Deserialize the message
		messageservicereauth = messageservicereauth_new();
		messageservicereauth_set(messageservicereauth, continuous->sharedKey, 0, REAUTHSTATE_CONTINUE, NULL);
		result = messageservicereauth_deserialize(messageservicereauth, buffer);
	}

	if (result) {
		messageservicereauth_get_sequencenum(messageservicereauth, sequenceNum);
		continuous_set_current_state(continuous, messageservicereauth_get_reauthstate(messageservicereauth));
		if (timeout != NULL) {
			*timeout = MAX(messageservicereauth_get_timeout(messageservicereauth) - continuous->timeoutLeeway, 0);
		}
		messageservicereauth_delete(messageservicereauth);

		if (sequenceNumber != NULL) {
			// This is an initialisation message, so store the receied sequence
			// number for future use
			sequencenumber_copy(sequenceNumber, sequenceNum);
		} else {
			// This is a subsequence message, so check that the sequence number
			// has been incremented by the Service. If it's all good, store the result
			sequencenumber_match = sequencenumber_equals(continuous->serviceSeqNumber, sequenceNum);
			if (!sequencenumber_match) {
				LOG(LOG_INFO, "Sequence number from server didn't match stored value.\n");
			}
		}
	}

	if (result && sequencenumber_match) {
		sequencenumber_increment(continuous->serviceSeqNumber);
	} else {
		continuous_set_current_state(continuous, REAUTHSTATE_ERROR);
	}

	buffer_delete(buffer);
	sequencenumber_delete(sequenceNum);

	return result;
}

/**
 * Writes a service reauth message. The function will block until the message
 * has been sent or the channel times out.
 *
 * If successful, the sequence number will be incremented.
 *
 * @param continuous The continuous structure holding the context.
 * @return True if we could send the message correctly.
*/
bool continuous_write_service_reauth(Continuous * continuous) {
	bool result;
	Buffer * buffer;
	MessageServiceReAuth * messageservicereauth;
	
	buffer = buffer_new(0);

	// SEND
	// Reply with ServiceReAuthMessage
	// {"encryptedData":"B64-ENC","iv":"B64","sessionId":0}
	messageservicereauth = messageservicereauth_new();
	messageservicereauth_set(messageservicereauth, continuous->sharedKey, continuous->currentTimeout, continuous->currentState, continuous->serviceSeqNumber);

	messageservicereauth_serialize(messageservicereauth, buffer);

	// Send the message
	result = channel_write_buffer(continuous->channel, buffer);
	LOG(LOG_INFO, "ServiceReauth sent. Timeout: %d\n", continuous->currentTimeout);

	// Increment the sequence number ready for the next message
	if (result) {
		sequencenumber_increment(continuous->serviceSeqNumber);
	}

	messageservicereauth_delete(messageservicereauth);
	buffer_delete(buffer);
	
	return result;
}

/**
 * Updates the internal state and sends a message to the Pico. This should
 * be used on the server side of the protocol to keep track of the current
 * state of the protocol state machine.
 *
 * See messagepicoreauth.h for the possible REAUTHSTATE values.
 *
 * WARNING: This will cause the method continuous_write_service_reauth to be 
 * called if the state is different from current.
 *
 * Be careful in multithread environments.
 *
 * @param continuous The continuous structure holding the context.
 * @param newState The new state to attempt to transition to (if different
 *        from the current state).
 * @return True if we could send the message correctly.
 */
bool continuous_update_state(Continuous * continuous, REAUTHSTATE newState) {
	bool result = true; 

	newState = continuous_transition(continuous->currentState, newState);

	if (continuous->currentState != newState) {
		continuous_set_current_state(continuous, newState);
		result = continuous_write_service_reauth(continuous);
	}

	return result;
}

/**
 * Server code for performing the cyclic part of the continuous authentication
 * protocol. This should be called repeatedly until authentication fails.
 *
 * It will return the current status, as returned by Pico.
 *
 * @param continuous The continuous prover object.
 * @param returnedStoredData If not NULL, is appended with a string
 *        containing data returned from Pico.
 * @return True if the authentication was successful.
 */
bool continuous_reauth(Continuous * continuous, Buffer * returnedStoredData) {
	bool result;

	LOG(LOG_INFO, "Starting read %d", continuous->currentTimeout);
	channel_set_timeout(continuous->channel, continuous->currentTimeout);
	result = continuous_read_pico_reauth(continuous, NULL, returnedStoredData);

	if (result) {
		result = continuous->currentState != REAUTHSTATE_ERROR;
	}
	
	if (result) {
		result = continuous_write_service_reauth(continuous);
	}

	return result;
}

/**
 * Pico code for performing the cyclic part of the continuous authentication
 * protocol. This should be called repeatedly until authentication fails.
 *
 * It will return the current status, as returned by the service.
 *
 * @param continuous The continuous prover object.
 * @param returnedStoredData If not NULL, is appended with a string
 *        containing data returned from Pico.
 * @return True if the authentication was successful.
 */
bool continuous_reauth_pico(Continuous * continuous, Buffer * extraData, int * timeout) {
	bool result;

	result = continuous_write_pico_reauth(continuous, extraData);

	if (result) {
		result = continuous->currentState != REAUTHSTATE_ERROR;
	}

	if (result) {
		result = continuous_read_service_reauth(continuous, NULL, timeout);
	}

	return result;
}

/**
 * Server code for performing the cyclic part of the continuous authentication
 * protocol. This should be called repeatedly until authentication fails. In
 * case authentication fails, this means either the connection was closed
 * (e.g. the Pico went out of range), or the Pico was unable to authenticate
 * successfully (e.g. someone tried unsuccessfully to imitate the Pico).
 *
 * @param continuous The continuous prover object.
 * @param returnedStoredData If not NULL, is appended with a string
 *        containing data returned from Pico.
 * @return true if authentication completed successfully, false o/w.
 */
bool continuous_continue(Continuous * continuous, Buffer * returnedStoredData) {
	bool result;
	REAUTHSTATE receivedState = REAUTHSTATE_INVALID;

	result = continuous_reauth(continuous, returnedStoredData);
	if (result) {
		receivedState = continuous->currentState;
	}

	return (receivedState == REAUTHSTATE_CONTINUE);
}

/**
 * Tidy up at the end of the continuous authentication process. This should
 * be called after the lasts call to continuous_continue() and before the
 * continuous structure is deleted.
 *
 * @param continuous The continuous prover object.
 * @return true if everything was successfully titied up, false o/w.
 */
bool continuous_finish(Continuous * continuous) {
	bool result;

	result = channel_close(continuous->channel);

	return result;
}

/**
 * Pico code for performing the cyclic part of the continuous authentication
 * protocol. This should be called repeatedly until authentication fails. In
 * case authentication fails, this means either the connection was closed
 * (e.g. the Server went out of range), or the Server was unable to
 * authenticate successfully (e.g. someone tried unsuccessfully to imitate
 * the Server).
 *
 * @param continuous The continuous prover object.
 * @param extraData If not NULL, is sent to the server.
 * @param timeout returns the timeout value sent by the server, measured in
 *        milliseconds. The server value defaults toCONTINUOUS_TIMEOUT_ACTIVE
 *        (set in messageservicereauth.h to 10000ms = 10s).
 * @return true if authentication completed successfully. false o/w.
 */
bool continuous_continue_pico(Continuous * continuous, Buffer * extraData, int * timeout) {
	bool result;
	REAUTHSTATE receivedState = REAUTHSTATE_INVALID;

	result = continuous_reauth_pico(continuous, extraData, timeout);

	if (result) {
		receivedState = continuous->currentState;
	}

	return (receivedState == REAUTHSTATE_CONTINUE);
}

/** @} addtogroup Protocol */

