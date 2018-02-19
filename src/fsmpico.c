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
 * @section DESCRIPTION
 *
 * Provides a Finite State Machine implementation of the sigma prover half of
 * the SIGMA-I protocol. This is useful for event based network APIs.
 *
 * To get this to work, the developer must implement the following functions:
 *
 * 1. write(data, length, user_data): send data to the server.
 * 2. timeout(time, user_data): wait for the specified time.
 * 3. reconnect(user_data): reconnect to the service.
 * 4. disconnect(user_data): disconnect from the service.
 *
 * Optionally the developer should also implement the following functions:
 *
 * 5. error(user_data): act on the fact an error occurred.
 * 6. authenticated(status, user_data): act on a successful authentication.
 * 7. sessionEnded(user_data): act on the continuous auth session ending.
 * 8. statusUpdate(state, user_data): notification that the state machine state
 *                                    has changed.
 * The write(), disconnect() and listen() functions relate to network activity.
 * In addition to these, the developer must also *call* the following functions
 * at when the following events occur:
 *
 * 9. fsmpico_read(): when data arrives on the network.
 * 10. fsmpico_connected(): when a new Pico connects.
 * 11. fsmpicp_disconnected(): when the Pico disconnects.
 * 12. fsmpico_timeout(): when a previously requested the timeout occurs.
 *
 * The semantics for most of these should be obvious. One subtlety is that only
 * one timeout should be in play at a time. If the FSM requests a timeout when
 * another is already active, the FSM expects the previous timeout to be
 * overridden (that is, it should either be cancelled, or extended based on the
 * new timeout request).
 *
 * To use the FSM, and having established the above, the developer can then
 * perform an authentication by first connecting to a service on the channel
 * the service requested (e.g. established by scanning a QR code) then call
 * fsmpico_start(). If the authentication is to be aborted after having been
 * started (and assuming it didn't already fininsh naturally as part of the
 * process), a call to fsmpico_stop() will abort it.
 *
 */

/** \addtogroup Protocol
 *  @{
 */

#include <stdio.h>
//#include <malloc.h>
#include "pico/debug.h"
#include "pico/log.h"
#include "pico/messagestart.h"
#include "pico/messageserviceauth.h"
#include "pico/messageservicereauth.h"
#include "pico/messagestatus.h"
#include "pico/messagepicoreauth.h"
#include "pico/messagepicoauth.h"

#include "pico/fsmpico.h"

// Defines

#define RECONNECT_DELAY (10000)
#define CONTAUTH_LEEWAY (1000)
#define MAX(x,y) ((x) > (y) ? (x) : (y))

// Structure definitions

/**
 * @brief Pico finite state machine callbacks
 *
 * Provides a strucure for storing the callbacks (virtual functions) used
 * to tie an external communication provider to the state machine.
 *
 * In practice these functions should be set using fsmpico_set_functions()
 *
 */
typedef struct _AuthFsmComms {
	FsmWrite write;
	FsmSetTimeout setTimeout;
	FsmError error;
	FsmReconnect reconnect;
	FsmDisconnect disconnect;
	FsmAuthenticated authenticated;
	FsmSessionEnded sessionEnded;
	FsmStatusUpdate statusUpdate;
} AuthFsmComms;

/**
 * @brief Pico finite state machine internal data
 *
 * Stores the data needed to handle Pico authentication using the finite
 * state machine.
 *
 */
struct _FsmPico {
	REAUTHSTATE currentState;
	SequenceNumber * picoSeqNumber;
	SequenceNumber * serviceSeqNumber;
	Buffer * sharedKey;
	Shared * shared;
	Buffer * extraData;

	FSMPICOSTATE state;
	AuthFsmComms * comms;
	void * user_data;
};

// Function prototypes

static void createMessageStart(FsmPico * fsmpico, Buffer * message);
static bool readMessageServiceAuth(FsmPico * fsmpico, Buffer const * message);
static void createMessagePicoAuth(FsmPico * fsmpico, Buffer * message, Buffer const * sendExtraData);
static bool readMessageStatus(FsmPico * fsmpico, Buffer const * message, Buffer * returnedExtraData, char *status);
static void createMessagePicoReauth(FsmPico * fsmpico, Buffer * message, Buffer const * sendExtraData);
static bool readMessageServiceReauth(FsmPico * fsmpico, Buffer const * message, int * timeout);
static void stateTransition(FsmPico* fsmpico, FSMPICOSTATE newState);

static void FsmWriteNull(char const * data, size_t length, void * user_data);
static void FsmSetTimeoutNull(int timeout, void * user_data);
static void FsmErrorNull(void * user_data);
static void FsmReconnectNull(void * user_data);
static void FsmDisconnectNull(void * user_data);
static void FsmAuthenticatedNull(int status, void * user_data);
static void FsmSessionEndedNull(void * user_data);
static void FsmStatusUpdateNull(FSMPICOSTATE state, void * user_data);

// Function definitions

/**
 * Create a new instance of the class.
 *
 * @return The newly created object.
 */
FsmPico * fsmpico_new() {
	FsmPico * fsmpico;

	fsmpico = CALLOC(sizeof(FsmPico), 1);

	fsmpico->shared = shared_new();
	fsmpico->extraData = buffer_new(0);

	fsmpico->currentState = REAUTHSTATE_INVALID;
	fsmpico->picoSeqNumber = sequencenumber_new();
	fsmpico->serviceSeqNumber = sequencenumber_new();
	fsmpico->sharedKey = buffer_new(0);

	fsmpico->state = FSMPICOSTATE_INVALID;

	fsmpico->comms = CALLOC(sizeof(AuthFsmComms), 1);

	fsmpico->comms->write = FsmWriteNull;
	fsmpico->comms->setTimeout = FsmSetTimeoutNull;
	fsmpico->comms->error = FsmErrorNull;
	fsmpico->comms->reconnect = FsmReconnectNull;
	fsmpico->comms->disconnect = FsmDisconnectNull;
	fsmpico->comms->authenticated = FsmAuthenticatedNull;
	fsmpico->comms->sessionEnded = FsmSessionEndedNull;
	fsmpico->comms->statusUpdate = FsmStatusUpdateNull;

	return fsmpico;
}

/**
 * Delete an instance of the class, freeing up the memory allocated to it.
 *
 * @param fsmpico The object to free.
 */
void fsmpico_delete(FsmPico * fsmpico) {
	if (fsmpico) {
		if (fsmpico->shared) {
			shared_delete(fsmpico->shared);
			fsmpico->shared = NULL;
		}

		if (fsmpico->picoSeqNumber) {
			sequencenumber_delete(fsmpico->picoSeqNumber);
			fsmpico->picoSeqNumber = NULL;
		}
		
		if (fsmpico->serviceSeqNumber) {
			sequencenumber_delete(fsmpico->serviceSeqNumber);
			fsmpico->serviceSeqNumber = NULL;
		}

		if (fsmpico->sharedKey) {
			buffer_delete(fsmpico->sharedKey);
			fsmpico->sharedKey = NULL;
		}
		
		FREE(fsmpico->comms);

		FREE(fsmpico);
	}
}

/**
 * Set the callbacks that should be used to provide communication.
 *
 * Setting any function to NULL will cause the default handler for that
 * function to be used instead. However, for a working system, at least
 * write(), setTimeout(), reconnect() and disconnect() must be properly
 * assigned.
 *
 * @param fsmpico The object to assign callbacks to.
 * @param write Callback used by the state machine when it wants to write
 *        data to the channel.
 * @param setTimeout Callback used by the state machine when it wants to set
 *        a timer, after which the timeout() function should be called.
 * @param error Callback used by the state machine to signal that an error has
 *        occured.
 * @param reconnect Callback used by the state machine to trigger a reconnect
 *        attempt.
 * @param disconnect Callback used by the state machine to trigger a disconnect.
 * @param authenticated Callback called by the state machine once authentication
 *        completes (either successfully or unsuccessfully).
 * @param sessionEnded Callback called by the state machine when the continuous
 *        authentication session has finished.
 * @param statusUpdate Callback called by the state machine to indicate that
 *        its state has changed.
 */
void fsmpico_set_functions(FsmPico * fsmpico, FsmWrite write, FsmSetTimeout setTimeout, FsmError error, FsmReconnect reconnect, FsmDisconnect disconnect, FsmAuthenticated authenticated, FsmSessionEnded sessionEnded, FsmStatusUpdate statusUpdate) {
	fsmpico->comms->write = write ? write : FsmWriteNull;
	fsmpico->comms->setTimeout = setTimeout ? setTimeout : FsmSetTimeoutNull;
	fsmpico->comms->error = error ? error : FsmErrorNull;
	fsmpico->comms->reconnect = reconnect ? reconnect : FsmReconnectNull;
	fsmpico->comms->disconnect = disconnect ? disconnect : FsmDisconnectNull;
	fsmpico->comms->authenticated = authenticated ? authenticated : FsmAuthenticatedNull;
	fsmpico->comms->sessionEnded = sessionEnded ? sessionEnded : FsmSessionEndedNull;
	fsmpico->comms->statusUpdate = statusUpdate ? statusUpdate : FsmStatusUpdateNull;
}

/**
 * Set the user data that will be passed back to the callbacks. This should be
 * used to provide context for the callbacks.
 *
 * @param fsmpico The object to apply to.
 * @param user_data A pointer to the user data to pass to the callback
 *        functions.
 */
void fsmpico_set_userdata(FsmPico * fsmpico, void * user_data) {
	fsmpico->user_data = user_data;
}

/**
 * The default (dummy) function used as a write callback if the user doesn't
 * specify an alternative.
 *
 * @param data The data to send.
 * @param length The length of the data to send.
 * @param user_data Context data set using fsmpico_set_userdata().
 */
static void FsmWriteNull(char const * data, size_t length, void * user_data) {
	LOG(LOG_DEBUG, "FsmiPico Write function not set");
}

/**
 * The default (dummy) function used as a setTimeout callback if the user
 * doesn't specify an alternative.
 *
 * @param timeout The timeout to use.
 * @param user_data Context data set using fsmpico_set_userdata().
 */
static void FsmSetTimeoutNull(int timeout, void * user_data) {
	LOG(LOG_DEBUG, "FsmiPico SetTimeout function not set");
}

/**
 * The default (dummy) function used as an error callback if the user
 * doesn't specify an alternative.
 *
 * @param user_data Context data set using fsmpico_set_userdata().
 */
static void FsmErrorNull(void * user_data) {
	LOG(LOG_DEBUG, "FsmiPico Error function not set");
}

/**
 * The default (dummy) function used as a reconnect callback if the user
 * doesn't specify an alternative.
 *
 * @param user_data Context data set using fsmpico_set_userdata().
 */
static void FsmReconnectNull(void * user_data) {
	LOG(LOG_DEBUG, "FsmiPico Reconnect function not set");
}

/**
 * The default (dummy) function used as a disconnect callback if the user
 * doesn't specify an alternative.
 *
 * @param user_data Context data set using fsmpico_set_userdata().
 */
static void FsmDisconnectNull(void * user_data) {
	LOG(LOG_DEBUG, "FsmiPico Disconnect function not set");
}

/**
 * The default (dummy) function used as an authenticated callback if the user
 * doesn't specify an alternative.
 *
 * @param user_data Context data set using fsmpico_set_userdata().
 */
static void FsmAuthenticatedNull(int status, void * user_data) {
	LOG(LOG_DEBUG, "FsmiPico Authenticated function not set");
}

/**
 * The default (dummy) function used as a sessionEnded callback if the user
 * doesn't specify an alternative.
 *
 * @param user_data Context data set using fsmpico_set_userdata().
 */
static void FsmSessionEndedNull(void * user_data) {
	LOG(LOG_DEBUG, "FsmiPico SessionEnded function not set");
}

/**
 * The default (dummy) function used as a statusUpdate callback if the user
 * doesn't specify an alternative.
 *
 * @param state The new state the state machine just moved to.
 * @param user_data Context data set using fsmpico_set_userdata().
 */
static void FsmStatusUpdateNull(FSMPICOSTATE state, void * user_data) {
	LOG(LOG_DEBUG, "FsmiPico StatusUpdate function not set");
}

/**
 * This function should be called when a read event occurs on the channel. A
 * buffer containing the data read should be passed in to it.
 *
 * @param fsmpico The object to apply to.
 * @param data The data read on the channel that should be processed.
 */
void fsmpico_read(FsmPico * fsmpico, char const * data, size_t length) {
	LOG(LOG_DEBUG, "Read");

	bool result;
	Buffer * receivedExtraData;
	int timeout;
	Buffer * message;
	Buffer * dataread;
	char status;
    
	receivedExtraData = buffer_new(0);
	message = buffer_new(0);
	dataread = buffer_new(length);
	buffer_append(dataread, data, length);

	// TODO: If the reads fail, should move to an error state
	switch (fsmpico->state) {
	case FSMPICOSTATE_SERVICEAUTH:
		result = readMessageServiceAuth(fsmpico, dataread);
		if (result) {
			stateTransition(fsmpico, FSMPICOSTATE_PICOAUTH);
			createMessagePicoAuth(fsmpico, message, fsmpico->extraData);
			fsmpico->comms->write(buffer_get_buffer(message), buffer_get_pos(message), fsmpico->user_data);
			stateTransition(fsmpico, FSMPICOSTATE_STATUS);
		}
		break;
	case FSMPICOSTATE_STATUS:
		result = readMessageStatus(fsmpico, dataread, receivedExtraData, &status);
		if (result) {
			fsmpico->comms->authenticated((int) status, fsmpico->user_data);
			fsmpico->comms->disconnect(fsmpico->user_data);
            
			switch (status) {
			case MESSAGESTATUS_OK_DONE:
				stateTransition(fsmpico, FSMPICOSTATE_FIN);
				break;
			case MESSAGESTATUS_OK_CONTINUE:
				stateTransition(fsmpico, FSMPICOSTATE_AUTHENTICATED);
				break;
			default:
				stateTransition(fsmpico, FSMPICOSTATE_ERROR);
				break;
			}
		}
		break;
	case FSMPICOSTATE_CONTSTARTSERVICE:
	case FSMPICOSTATE_SERVICEREAUTH:
		result = readMessageServiceReauth(fsmpico, dataread, &timeout);
		if (result) {
			stateTransition(fsmpico, FSMPICOSTATE_PICOREAUTH);
			LOG(LOG_DEBUG, "Timeout set to: %d", timeout);
			// Wait for timeout
			fsmpico->comms->setTimeout(MAX((timeout - CONTAUTH_LEEWAY), 0), fsmpico->user_data);
		}
		break;
	default:
		stateTransition(fsmpico, FSMPICOSTATE_ERROR);
		fsmpico->comms->error(fsmpico->user_data);
		break;
	}

	buffer_delete(receivedExtraData);
	buffer_delete(message);
	buffer_delete(dataread);
}

/**
 * This function should be called when a connection event occurs on the channel.
 *
 * @param fsmpico The object to apply to.
 */
void fsmpico_connected(FsmPico * fsmpico) {
	Buffer * extraData;
	Buffer * message;

	LOG(LOG_DEBUG, "Connected");

	extraData = buffer_new(0);
	message = buffer_new(0);

	switch (fsmpico->state) {
	case FSMPICOSTATE_START:
		createMessageStart(fsmpico, message);
		fsmpico->comms->write(buffer_get_buffer(message), buffer_get_pos(message), fsmpico->user_data);
		stateTransition(fsmpico, FSMPICOSTATE_SERVICEAUTH);
		break;
	case FSMPICOSTATE_CONTSTARTPICO:
		fsmpico->currentState = REAUTHSTATE_CONTINUE;
		buffer_clear(fsmpico->sharedKey);
		buffer_append_buffer(fsmpico->sharedKey, shared_get_shared_key(fsmpico->shared));
		sequencenumber_random(fsmpico->picoSeqNumber);
		createMessagePicoReauth(fsmpico, message, extraData);
		fsmpico->comms->write(buffer_get_buffer(message), buffer_get_pos(message), fsmpico->user_data);
		stateTransition(fsmpico, FSMPICOSTATE_CONTSTARTSERVICE);
		break;
	default:
		stateTransition(fsmpico, FSMPICOSTATE_ERROR);
		fsmpico->comms->error(fsmpico->user_data);
		break;
	}

	buffer_delete(extraData);
	buffer_delete(message);
}

/**
 * This function should be called when a disconnection event occurs on the
 * channel.
 *
 * @param fsmpico The object to apply to.
 */
void fsmpico_disconnected(FsmPico * fsmpico) {
	LOG(LOG_DEBUG, "Disconnected");

	switch (fsmpico->state) {
	case FSMPICOSTATE_AUTHENTICATED:
		stateTransition(fsmpico, FSMPICOSTATE_CONTSTARTPICO);
		// Wait for a second
		fsmpico->comms->setTimeout(RECONNECT_DELAY, fsmpico->user_data);
		break;
	case FSMPICOSTATE_CONTSTARTPICO:
	case FSMPICOSTATE_CONTSTARTSERVICE:
	case FSMPICOSTATE_FIN:
		stateTransition(fsmpico, FSMPICOSTATE_FIN);
		fsmpico->comms->sessionEnded(fsmpico->user_data);
		break;
	default:
		stateTransition(fsmpico, FSMPICOSTATE_ERROR);
		fsmpico->comms->error(fsmpico->user_data);
		break;
	}
}

/**
 * This function should be called when a timeout event occurs on the channel.
 * a Timeout only occurs in response to a setTimeout() call that requested it.
 *
 * @param fsmpico The object to apply to.
 */
void fsmpico_timeout(FsmPico * fsmpico) {
	Buffer * extraData;
	Buffer * message;

	LOG(LOG_DEBUG, "Timeout");

	extraData = buffer_new(0);
	message = buffer_new(0);

	switch (fsmpico->state) {
		case FSMPICOSTATE_CONTSTARTPICO:
		LOG(LOG_DEBUG, "Reconnecting for continuous authentication");
		fsmpico->comms->reconnect(fsmpico->user_data);
		break;
	case FSMPICOSTATE_PICOREAUTH:
		createMessagePicoReauth(fsmpico, message, extraData);
		fsmpico->comms->write(buffer_get_buffer(message), buffer_get_pos(message), fsmpico->user_data);
		stateTransition(fsmpico, FSMPICOSTATE_SERVICEREAUTH);
		break;
	default:
		LOG(LOG_DEBUG, "Timer fired during an invalid state");
		break;
	}

	buffer_delete(extraData);
	buffer_delete(message);
}


void stateTransition(FsmPico* fsmpico, FSMPICOSTATE newState) {
	fsmpico->state = newState;
	fsmpico->comms->statusUpdate(newState, fsmpico->user_data);
}

/**
 * An internal function used to construct a MessageStart data item.
 *
 * @param fsmpico The object to apply to.
 * @param message A buffer to store the resulting message in.
 */
static void createMessageStart(FsmPico * fsmpico, Buffer * message) {
	MessageStart * messagestart;

	LOG(LOG_DEBUG, "Send MessageStart");

	buffer_clear(message);
	messagestart = messagestart_new();
	messagestart_set(messagestart, fsmpico->shared);
	messagestart_serialize(messagestart, message);
	messagestart_delete(messagestart);
}

static bool readMessageServiceAuth(FsmPico * fsmpico, Buffer const * message) {
	MessageServiceAuth * messageserviceauth;
	bool result;

	LOG(LOG_DEBUG, "Read MessageServiceAuth");

	messageserviceauth = messageserviceauth_new();
	messageserviceauth_set(messageserviceauth, fsmpico->shared, 0);

	result = messageserviceauth_deserialize(messageserviceauth, message);

	// TODO: Check that the Service identity public key matches with the
	// key expected. The received key can be retrieved using
	// EC_KEY * shared_get_service_identity_public_key(Shared const * shared)
	messageserviceauth_delete(messageserviceauth);

	return result;
}

/**
 * An internal function used to construct a MessagePicoAuth data item.
 *
 * @param fsmpico The object to apply to.
 * @param message A buffer to store the resulting message in.
 * @param sendExtraData Any extra data that should be sent with the message.
 */
static void createMessagePicoAuth(FsmPico * fsmpico, Buffer * message, Buffer const * sendExtraData) {
	MessagePicoAuth * messagepicoauth;

	LOG(LOG_DEBUG, "Send MessagePicoAuth");

	messagepicoauth = messagepicoauth_new();
	messagepicoauth_set(messagepicoauth, fsmpico->shared);
	messagepicoauth_set_extra_data(messagepicoauth, sendExtraData);

	buffer_clear(message);
	messagepicoauth_serialize(messagepicoauth, message);
}

/**
 * An internal function used to interpret a MessageStatus message.
 *
 * @param fsmpico The object to apply to.
 * @param message The message data to interpret.
 * @param returnedExtraData A buffer to store any extra data that was extracted
 *        from the message.
 * @param status A char that will contain the status code sent by the service.
 */
static bool readMessageStatus(FsmPico * fsmpico, Buffer const * message, Buffer * returnedExtraData, char *status) {
	MessageStatus * messagestatus;
	bool result;
	Buffer * extradata;

	LOG(LOG_DEBUG, "Read MessageStatus");

	messagestatus = messagestatus_new();
	messagestatus_set(messagestatus, fsmpico->shared, NULL, 0);

	result = messagestatus_deserialize(messagestatus, message);

	buffer_clear(returnedExtraData);
	if (result) {
		extradata = messagestatus_get_extra_data(messagestatus);
		buffer_append_buffer(returnedExtraData, extradata);
	}

	// TODO: Check the status to establish whether continuous authentication should be used
	if (status != NULL) {
		*status = messagestatus_get_status(messagestatus);
	}

	messagestatus_delete(messagestatus);

	return result;
}

/**
 * An internal function used to construct a MessagePicoReauth data item.
 *
 * @param fsmpico The object to apply to.
 * @param message A buffer to store the resulting message in.
 * @param sendExtraData Any extra data that should be sent with the message.
 */
static void createMessagePicoReauth(FsmPico * fsmpico, Buffer * message, Buffer const * sendExtraData) {
	MessagePicoReAuth * messagepicoreauth;

	LOG(LOG_DEBUG, "Send MessagePicoReauth with state %d", fsmpico->currentState);

	messagepicoreauth = messagepicoreauth_new();
	messagepicoreauth_set(messagepicoreauth, fsmpico->sharedKey, fsmpico->picoSeqNumber);
	messagepicoreauth_set_reauthstate(messagepicoreauth, fsmpico->currentState);

	messagepicoreauth_serialize(messagepicoreauth, sendExtraData, message);

	// Increment the sequence number ready for the next message
	sequencenumber_increment(fsmpico->picoSeqNumber);

	messagepicoreauth_delete(messagepicoreauth);
}

/**
 * An internal function used to interpret a MessageServiceReauth message.
 *
 * @param fsmpico The object to apply to.
 * @param message The message data to interpret.
 * @param timeout A pointer to an integer to return the timeout value in.
 */
static bool readMessageServiceReauth(FsmPico * fsmpico, Buffer const * message, int * timeout) {
	MessageServiceReAuth * messageservicereauth;
	bool result;
	bool sequencenumber_match;
	SequenceNumber * sequenceNum;

	sequenceNum = sequencenumber_new();
	sequencenumber_match = true;
	*timeout = 0;

	// Deserialize the message
	messageservicereauth = messageservicereauth_new();
	messageservicereauth_set(messageservicereauth, fsmpico->sharedKey, 0, REAUTHSTATE_CONTINUE, NULL);
	result = messageservicereauth_deserialize(messageservicereauth, message);

	LOG(LOG_DEBUG, "Read MessageServiceReauth with status %d", messageservicereauth_get_reauthstate(messageservicereauth));
    
	if (result) {
		messageservicereauth_get_sequencenum(messageservicereauth, sequenceNum);
		fsmpico->currentState = messageservicereauth_get_reauthstate(messageservicereauth);
		*timeout = messageservicereauth_get_timeout(messageservicereauth);

		if (fsmpico->state == FSMPICOSTATE_CONTSTARTSERVICE) {
			// This is an initialisation message, so store the receied sequence number for future use
			sequencenumber_copy(fsmpico->serviceSeqNumber, sequenceNum);
		}
		else {
			// This is a subsequent message, so check that the sequence number has been incremented by the Service. If it's all good, store the result
			sequencenumber_match = sequencenumber_equals(fsmpico->serviceSeqNumber, sequenceNum);
			LOG(LOG_DEBUG, "Sequence number match: %d", sequencenumber_match);
		}
	}

	if (result && sequencenumber_match) {
		sequencenumber_increment(fsmpico->serviceSeqNumber);
	}
	else {
		fsmpico->currentState = REAUTHSTATE_ERROR;
		fsmpico->comms->error(fsmpico->user_data);
	}

	messageservicereauth_delete(messageservicereauth);
	sequencenumber_delete(sequenceNum);

	return result;
}

/**
 * Start the authentication process.
 *
 * @param fsmpico The object to apply to.
 * @param extraData Any extra data to send to the verifier during the
 *        authentication protocol.
 * @param serviceIdPubKey The long term public key of the verifer to
 *        authenticate to.
 * @param clientIdPubKey The long term public key of the prover (Pico).
 * @param clientIdPrivKey The long term private key of the prover (Pico).
 */
void fsmpico_start(FsmPico * fsmpico, Buffer const * extraData, EC_KEY * serviceIdPubKey, EC_KEY * clientIdPubKey, EVP_PKEY * clientIdPrivKey) {
	stateTransition(fsmpico, FSMPICOSTATE_START);

	LOG(LOG_DEBUG, "Install keys");

	// Install Service public key
	shared_set_service_identity_public_key(fsmpico->shared, serviceIdPubKey);

	// Install Pico public key
	shared_set_pico_identity_public_key(fsmpico->shared, clientIdPubKey);

	// Install Pico private key
	shared_set_pico_identity_private_key(fsmpico->shared, clientIdPrivKey);

	// Record the extra data
	buffer_clear(fsmpico->extraData);
	buffer_append_buffer(fsmpico->extraData, extraData);

	LOG(LOG_DEBUG, "Done");
}

/**
 * Request that the authentication process be stopped and aborted as soon
 * as is possible.
 *
 * @param fsmpico The object to apply to.
 */
void fsmpico_stop(FsmPico * fsmpico) {
	stateTransition(fsmpico, FSMPICOSTATE_INVALID);
}

/**
 * Get the current internal state of the state machine..
 *
 * @param fsmpico The object to apply to.
 * @return The current state of the state machine.
 */
FSMPICOSTATE fsmpico_get_state(FsmPico * fsmpico) {
    return fsmpico->state;
}

/** @} addtogroup Protocol */
