/** \ingroup Protocol
 * @file
 * @author  David Llewellyn-Jones <David.Llewellyn-Jones@cl.cam.ac.uk>
 * @version $(VERSION)
 *
 * @section LICENSE
 *
 * (C) Copyright Cambridge Authentication Ltd, 2017
 *
 * @section DESCRIPTION
 *
 * Provides a Finite State Machine implementation of the sigma verifier half of
 * the SIGMA-I protocol. This is useful for event based network APIs.
 *
 * To get this to work, the developer must implement the following functions:
 *
 * 1. write(data, length, user_data): send data to the Pico.
 * 2. timeout(time, user_data): wait for the specified time.
 * 3. disconnect(user_data): disconnect from the Pico.
 * 4. listen(user_data): ensure the server is listening for new connections.
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
 * 9. fsmservice_read(): when data arrives on the network.
 * 10. fsmservice_connected(): when a new Pico connects.
 * 11. fsmservice_disconnected(): when the Pico disconnects.
 * 12. fsmservice_timeout(): when a previously requested the timeout occurs.
 *
 * The semantics for most of these should be obvious. One subtlety is that only
 * one timeout should be in play at a time. If the FSM requests a timeout when
 * another is already active, the FSM expects the previous timeout to be
 * overridden (that is, it should either be cancelled, or extended based on the
 * new timeout request).
 *
 * To use the FSM, and having established the above, the developer can then
 * perform an authentication by first setting up the channel to listen for
 * incoming connections, then call fsmservice_start(). If the authentication
 * is to be aborted after having been started (and assuming it didn't already
 * fininsh naturally as part of the process), a call to fsmservice_stop() will
 * abort it.
 *
 */

/** \addtogroup Protocol
 *  @{
 */


#include <stdio.h>
#include <malloc.h>
#include <stdbool.h>
#include "pico/debug.h"
#include "pico/log.h"
#include "pico/shared.h"
#include "pico/users.h"
#include "pico/messagestart.h"
#include "pico/messageserviceauth.h"
#include "pico/messageservicereauth.h"
#include "pico/messagestatus.h"
#include "pico/messagepicoreauth.h"
#include "pico/messagepicoauth.h"

#include "pico/fsmservice.h"

// Defines

#define CONTAUTH_TIMEOUT (5000)
#define RECONNECT_DELAY (10000)
#define AUTHENTICATION_TIME_LIMIT (5000)

// Structure definitions

/**
 * @brief Pico finite state machine callbacks
 *
 * Provides a strucure for storing the callbacks (virtual functions) used
 * to tie an external communication provider to the state machine.
 *
 * In practice these functions should be set using fsmservice_set_functions()
 *
 */
typedef struct _AuthFsmServiceComms {
	FsmWrite write;
	FsmSetTimeout setTimeout;
	FsmError error;
	FsmListen listen;
	FsmDisconnect disconnect;
	FsmAuthenticated authenticated;
	FsmSessionEnded sessionEnded;
	FsmStatusUpdate statusUpdate;
} AuthFsmServiceComms;

/**
 * @brief Pico finite state machine internal data
 *
 * Stores the data needed to handle Pico authentication using the finite
 * state machine.
 *
 */
struct _FsmService {
	REAUTHSTATE currentState;
	SequenceNumber * picoSeqNumber;
	SequenceNumber * serviceSeqNumber;
	Buffer * sharedKey;
	Shared * shared;
	Buffer * extraData;
	Buffer * returnedExtraData;
	int currentTimeout;
	FSMSERVICESTATE state;
	AuthFsmServiceComms * comms;
	void * user_data;
	Users const * users;
	Buffer * user;
	Buffer * symmetrickey;
	bool continuous;
};

// Function prototypes

static bool readMessageStart(FsmService * fsmservice, Buffer /* const */ * message);
static void createMessageServiceAuth(FsmService * fsmservice, Buffer * message);
static bool readMessagePicoAuth(FsmService * fsmservice, Buffer /* const */ * message, Buffer * returnedExtraData);
static void createMessageStatus(FsmService * fsmservice, Buffer * message, Buffer const * sendExtraData, signed char status);
static bool readMessagePicoReauth(FsmService * fsmservice, Buffer /* const */ * message, Buffer * returnedExtraData);
static void createMessageServiceReauth(FsmService * fsmservice, Buffer * message, int timeout, const Buffer * extraData);
static bool fsmservice_check_user(FsmService * fsmservice, Buffer * user, Buffer * symmetrickey);

static void FsmWriteNull(char const * data, size_t length, void * user_data);
static void FsmSetTimeoutNull(int timeout, void * user_data);
static void FsmErrorNull(void * user_data);
static void FsmListenNull(void * user_data);
static void FsmDisconnectNull(void * user_data);
static void FsmAuthenticatedNull(int status, void * user_data);
static void FsmSessionEndedNull(void * user_data);
static void FsmStatusUpdateNull(int state, void * user_data);

// Function definitions

/**
 * Create a new instance of the class.
 *
 * @return The newly created object.
 */
FsmService * fsmservice_new() {
	FsmService * fsmservice;

	fsmservice = CALLOC(sizeof(FsmService), 1);

	fsmservice->shared = NULL;
	fsmservice->extraData = buffer_new(0);
	fsmservice->returnedExtraData = buffer_new(0);

	fsmservice->currentState = REAUTHSTATE_INVALID;
	fsmservice->picoSeqNumber = sequencenumber_new();
	fsmservice->serviceSeqNumber = sequencenumber_new();
	fsmservice->sharedKey = buffer_new(0);

	fsmservice->currentTimeout = CONTAUTH_TIMEOUT;

	fsmservice->state = FSMSERVICESTATE_INVALID;
	fsmservice->user = buffer_new(0);
	fsmservice->symmetrickey = buffer_new(0);
	fsmservice->continuous = false;

	fsmservice->comms = CALLOC(sizeof(AuthFsmServiceComms), 1);

	fsmservice->comms->write = FsmWriteNull;
	fsmservice->comms->setTimeout = FsmSetTimeoutNull;
	fsmservice->comms->error = FsmErrorNull;
	fsmservice->comms->listen = FsmListenNull;
	fsmservice->comms->disconnect = FsmDisconnectNull;
	fsmservice->comms->authenticated = FsmAuthenticatedNull;
	fsmservice->comms->sessionEnded = FsmSessionEndedNull;
	fsmservice->comms->statusUpdate = FsmStatusUpdateNull;

	return fsmservice;
}

/**
 * Delete an instance of the class, freeing up the memory allocated to it.
 *
 * @param fsmservice The object to free.
 */
void fsmservice_delete(FsmService * fsmservice) {
	if (fsmservice) {
		if (fsmservice->picoSeqNumber) {
			sequencenumber_delete(fsmservice->picoSeqNumber);
			fsmservice->picoSeqNumber = NULL;
		}
		
		if (fsmservice->serviceSeqNumber) {
			sequencenumber_delete(fsmservice->serviceSeqNumber);
			fsmservice->serviceSeqNumber = NULL;
		}

		if (fsmservice->sharedKey) {
			buffer_delete(fsmservice->sharedKey);
			fsmservice->sharedKey = NULL;
		}

		if (fsmservice->user) {
			buffer_delete(fsmservice->user);
			fsmservice->user = NULL;
		}
		if (fsmservice->symmetrickey) {
			buffer_delete(fsmservice->symmetrickey);
			fsmservice->symmetrickey = NULL;
		}
		if (fsmservice->extraData) {
			buffer_delete(fsmservice->extraData);
			fsmservice->extraData = NULL;
		}
		if (fsmservice->returnedExtraData) {
			buffer_delete(fsmservice->returnedExtraData);
			fsmservice->returnedExtraData = NULL;
		}

		FREE(fsmservice->comms);

		FREE(fsmservice);
	}
}

/**
 * Set the callbacks that should be used to provide communication.
 *
 * Setting any function to NULL will cause the default handler for that
 * function to be used instead. However, for a working system, at least
 * write(), setTimeout(), listen() and disconnect() must be properly
 * assigned.
 *
 * @param fsmservice The object to assign callbacks to.
 * @param write Callback used by the state machine when it wants to write
 *        data to the channel.
 * @param setTimeout Callback used by the state machine when it wants to set
 *        a timer, after which the timeout() function should be called.
 * @param error Callback used by the state machine to signal that an error has
 *        occured.
 * @param listen Callback used by the state machine to trigger a listen
 *        for incoming connections.
 * @param disconnect Callback used by the state machine to trigger a disconnect.
 * @param authenticated Callback called by the state machine once authentication
 *        completes (either successfully or unsuccessfully).
 * @param sessionEnded Callback called by the state machine when the continuous
 *        authentication session has finished.
 * @param statusUpdate Callback called by the state machine to indicate that
 *        its state has changed.
 */
void fsmservice_set_functions(FsmService * fsmservice, FsmWrite write, FsmSetTimeout setTimeout, FsmError error, FsmListen listen, FsmDisconnect disconnect, FsmAuthenticated authenticated, FsmSessionEnded sessionEnded, FsmStatusUpdate statusUpdate) {
	fsmservice->comms->write = write ? write : FsmWriteNull;
	fsmservice->comms->setTimeout = setTimeout ? setTimeout : FsmSetTimeoutNull;
	fsmservice->comms->error = error ? error : FsmErrorNull;
	fsmservice->comms->listen = listen ? listen : FsmListenNull;
	fsmservice->comms->disconnect = disconnect ? disconnect : FsmDisconnectNull;
	fsmservice->comms->authenticated = authenticated ? authenticated : FsmAuthenticatedNull;
	fsmservice->comms->sessionEnded = sessionEnded ? sessionEnded : FsmSessionEndedNull;
	fsmservice->comms->statusUpdate = statusUpdate ? statusUpdate : FsmStatusUpdateNull;
}

/**
 * Set the user data that will be passed back to the callbacks. This should be
 * used to provide context for the callbacks.
 *
 * @param fsmservice The object to apply to.
 * @param user_data A pointer to the user data to pass to the callback
 *        functions.
 */
void fsmservice_set_userdata(FsmService * fsmservice, void * user_data) {
	fsmservice->user_data = user_data;
}

/**
 * The default (dummy) function used as a write callback if the user doesn't
 * specify an alternative.
 *
 * @param data The data to send.
 * @param length The length of the data to send.
 * @param user_data Context data set using fsmservice_set_userdata().
 */
static void FsmWriteNull(char const * data, size_t length, void * user_data) {
	LOG(LOG_DEBUG, "FsmiPico Write function not set");
}

/**
 * The default (dummy) function used as a setTimeout callback if the user
 * doesn't specify an alternative.
 *
 * @param timeout The timeout to use.
 * @param user_data Context data set using fsmservice_set_userdata().
 */
static void FsmSetTimeoutNull(int timeout, void * user_data) {
	LOG(LOG_DEBUG, "FsmiPico SetTimeout function not set");
}

/**
 * The default (dummy) function used as an error callback if the user
 * doesn't specify an alternative.
 *
 * @param user_data Context data set using fsmservice_set_userdata().
 */
static void FsmErrorNull(void * user_data) {
	LOG(LOG_DEBUG, "FsmiPico Error function not set");
}

/**
 * The default (dummy) function used as a listen callback if the user
 * doesn't specify an alternative.
 *
 * @param user_data Context data set using fsmservice_set_userdata().
 */
static void FsmListenNull(void * user_data) {
	LOG(LOG_DEBUG, "FsmiPico Listen function not set");
}

/**
 * The default (dummy) function used as a disconnect callback if the user
 * doesn't specify an alternative.
 *
 * @param user_data Context data set using fsmservice_set_userdata().
 */
static void FsmDisconnectNull(void * user_data) {
	LOG(LOG_DEBUG, "FsmiPico Disconnect function not set");
}

/**
 * The default (dummy) function used as an authenticated callback if the user
 * doesn't specify an alternative.
 *
 * @param user_data Context data set using fsmservice_set_userdata().
 */
static void FsmAuthenticatedNull(int status, void * user_data) {
	LOG(LOG_DEBUG, "FsmiPico Authenticated function not set");
}

/**
 * The default (dummy) function used as a sessionEnded callback if the user
 * doesn't specify an alternative.
 *
 * @param user_data Context data set using fsmservice_set_userdata().
 */
static void FsmSessionEndedNull(void * user_data) {
	LOG(LOG_DEBUG, "FsmiPico SessionEnded function not set");
}

/**
 * The default (dummy) function used as a statusUpdate callback if the user
 * doesn't specify an alternative.
 *
 * @param state The new state the state machine just moved to.
 * @param user_data Context data set using fsmservice_set_userdata().
 */
static void FsmStatusUpdateNull(int state, void * user_data) {
	LOG(LOG_DEBUG, "FsmiPico StatusUpdate function not set");
}

/**
 * This function should be called when a read event occurs on the channel. A
 * buffer containing the data read should be passed in to it.
 *
 * @param fsmservice The object to apply to.
 * @param data The data read on the channel that should be processed.
 */
void fsmservice_read(FsmService * fsmservice, char const * data, size_t length) {
	bool result;
	Buffer * message;
	Buffer * dataread;
	signed char status;

	LOG(LOG_DEBUG, "Read");

	message = buffer_new(0);
	dataread = buffer_new(length);
	buffer_append(dataread, data, length);

	switch (fsmservice->state) {
	case FSMSERVICESTATE_START:
		result = readMessageStart(fsmservice, dataread);
		LOG(LOG_DEBUG, "Result %d", result);
		if (result) {
			fsmservice->state = FSMSERVICESTATE_SERVICEAUTH;
			fsmservice->comms->statusUpdate(fsmservice->state, fsmservice->user_data);
			createMessageServiceAuth(fsmservice, message);

			LOG(LOG_DEBUG, "About to write");
			fsmservice->comms->write(buffer_get_buffer(message), buffer_get_pos(message), fsmservice->user_data);
			LOG(LOG_DEBUG, "Written");
			fsmservice->state = FSMSERVICESTATE_PICOAUTH;
			fsmservice->comms->statusUpdate(fsmservice->state, fsmservice->user_data);
		}
		else {
			LOG(LOG_ERR, "Error decoding start message");
			fsmservice->state = FSMSERVICESTATE_ERROR;
			fsmservice->comms->error(fsmservice->user_data);
		}
		break;
	case FSMSERVICESTATE_PICOAUTH:
		result = readMessagePicoAuth(fsmservice, dataread, fsmservice->returnedExtraData);
		if (result) {
			fsmservice->state = FSMSERVICESTATE_STATUS;
			fsmservice->comms->statusUpdate(fsmservice->state, fsmservice->user_data);
			result = fsmservice_check_user(fsmservice, fsmservice->user, fsmservice->symmetrickey);
			// Status is set to:
			// MESSAGESTATUS_OK_CONTINUE if auth succeeded and continuous is true
			// MESSAGESTATUS_OK_DONE if auth succeeded and continuous is false
			// MESSAGESTATUS_REJECTED if auth failed
			if (result) {
				if (fsmservice->continuous) {
					LOG(LOG_INFO, "Authentication succeeded, continuing");
					status = MESSAGESTATUS_OK_CONTINUE;
				}
				else {
					LOG(LOG_INFO, "Authentication succeeded, stopping");
					status = MESSAGESTATUS_OK_DONE;
				}
			}
			else {
				LOG(LOG_INFO, "Authentication failed, stopping");
				status = MESSAGESTATUS_REJECTED;
			}
			createMessageStatus(fsmservice, message, fsmservice->extraData, status);
			fsmservice->comms->write(buffer_get_buffer(message), buffer_get_pos(message), fsmservice->user_data);
		}
		if (result) {
			fsmservice->state = FSMSERVICESTATE_AUTHENTICATED;
			fsmservice->comms->statusUpdate(fsmservice->state, fsmservice->user_data);
			fsmservice->comms->disconnect(fsmservice->user_data);
		}
		else {
			fsmservice->state = FSMSERVICESTATE_AUTHFAILED;
			fsmservice->comms->statusUpdate(fsmservice->state, fsmservice->user_data);
			fsmservice->comms->disconnect(fsmservice->user_data);
		}
		break;
	case FSMSERVICESTATE_CONTSTARTPICO:
	case FSMSERVICESTATE_PICOREAUTH:
		result = readMessagePicoReauth(fsmservice, dataread, fsmservice->returnedExtraData);
		if (result) {
			fsmservice->state = FSMSERVICESTATE_SERVICEREAUTH;
			fsmservice->comms->statusUpdate(fsmservice->state, fsmservice->user_data);
		}
		else {
			LOG(LOG_ERR, "Error decoding Pico reauth message");
			fsmservice->state = FSMSERVICESTATE_ERROR;
			fsmservice->comms->error(fsmservice->user_data);
		}
		break;
	default:
		fsmservice->state = FSMSERVICESTATE_ERROR;
		fsmservice->comms->error(fsmservice->user_data);
		break;
	}

	buffer_delete(message);
	buffer_delete(dataread);
}

/**
 * This function should be called when a connection event occurs on the channel.
 *
 * @param fsmservice The object to apply to.
 */
void fsmservice_connected(FsmService * fsmservice) {
	Buffer * message;

	LOG(LOG_DEBUG, "Connected");

	message = buffer_new(0);

	switch (fsmservice->state) {
	case FSMSERVICESTATE_CONNECT:
		fsmservice->state = FSMSERVICESTATE_START;
		fsmservice->comms->statusUpdate(fsmservice->state, fsmservice->user_data);
		// Set a timer; authentication must complete within this time
		fsmservice->comms->setTimeout(AUTHENTICATION_TIME_LIMIT, fsmservice->user_data);
		break;
	case FSMSERVICESTATE_CONTSTARTSERVICE:
		fsmservice->currentState = REAUTHSTATE_CONTINUE;
		buffer_clear(fsmservice->sharedKey);
		buffer_append_buffer(fsmservice->sharedKey, shared_get_shared_key(fsmservice->shared));
		sequencenumber_random(fsmservice->serviceSeqNumber);

		fsmservice->state = FSMSERVICESTATE_CONTSTARTPICO;
		fsmservice->comms->statusUpdate(fsmservice->state, fsmservice->user_data);
		fsmservice->comms->setTimeout((fsmservice->currentTimeout), fsmservice->user_data);
		break;
	default:
		fsmservice->state = FSMSERVICESTATE_ERROR;
		fsmservice->comms->error(fsmservice->user_data);
		break;
	}

	buffer_delete(message);
}

/**
 * This function should be called when a disconnection event occurs on the
 * channel.
 *
 * @param fsmservice The object to apply to.
 */
void fsmservice_disconnected(FsmService * fsmservice) {
	LOG(LOG_DEBUG, "Disconnected");

	switch (fsmservice->state) {
	case FSMSERVICESTATE_AUTHENTICATED:
		if (fsmservice->continuous) {
			fsmservice->comms->authenticated(MESSAGESTATUS_OK_CONTINUE, fsmservice->user_data);
			fsmservice->state = FSMSERVICESTATE_CONTSTARTSERVICE;
			fsmservice->comms->statusUpdate(fsmservice->state, fsmservice->user_data);
			fsmservice->comms->listen(fsmservice->user_data);
			fsmservice->comms->setTimeout((RECONNECT_DELAY + fsmservice->currentTimeout), fsmservice->user_data);
		}
		else {
			fsmservice->comms->authenticated(MESSAGESTATUS_OK_DONE, fsmservice->user_data);
		}
		break;
	case FSMSERVICESTATE_AUTHFAILED:
		fsmservice->comms->authenticated(MESSAGESTATUS_REJECTED, fsmservice->user_data);
		break;
	case FSMSERVICESTATE_CONTSTARTPICO:
	case FSMSERVICESTATE_CONTSTARTSERVICE:
		fsmservice->state = FSMSERVICESTATE_FIN;
		fsmservice->comms->sessionEnded(fsmservice->user_data);
		break;
	default:
		fsmservice->state = FSMSERVICESTATE_ERROR;
		fsmservice->comms->error(fsmservice->user_data);
		break;
	}
}

/**
 * This function should be called when a timeout event occurs on the channel.
 * a Timeout only occurs in response to a setTimeout() call that requested it.
 *
 * @param fsmservice The object to apply to.
 */
void fsmservice_timeout(FsmService * fsmservice) {
	Buffer * message;

	LOG(LOG_DEBUG, "Timeout");

	message = buffer_new(0);

	switch (fsmservice->state) {
	case FSMSERVICESTATE_CONTSTARTSERVICE:
		fsmservice->state = FSMSERVICESTATE_FIN;
		fsmservice->comms->sessionEnded(fsmservice->user_data);
		break;
	case FSMSERVICESTATE_CONTSTARTPICO:
	case FSMSERVICESTATE_PICOREAUTH:
		fsmservice->state = FSMSERVICESTATE_FIN;
		fsmservice->comms->sessionEnded(fsmservice->user_data);
		break;
	case FSMSERVICESTATE_SERVICEREAUTH:
		createMessageServiceReauth(fsmservice, message, fsmservice->currentTimeout, fsmservice->extraData);
		fsmservice->comms->write(buffer_get_buffer(message), buffer_get_pos(message), fsmservice->user_data);
		fsmservice->state = FSMSERVICESTATE_PICOREAUTH;
		fsmservice->comms->statusUpdate(fsmservice->state, fsmservice->user_data);
		fsmservice->comms->setTimeout(fsmservice->currentTimeout, fsmservice->user_data);
		break;
	case FSMSERVICESTATE_AUTHENTICATED:
	case FSMSERVICESTATE_AUTHFAILED:
		// Intentionally take no action
		LOG(LOG_DEBUG, "Authentication attempt completed within time allowed");
		break;
	default:
		LOG(LOG_DEBUG, "Login took too long");
		fsmservice->state = FSMSERVICESTATE_ERROR;
		fsmservice->comms->error(fsmservice->user_data);
		break;
	}

	buffer_delete(message);
}

/**
 * An internal function used to interpret a MessageStart message.
 *
 * @param fsmservice The object to apply to.
 * @param message The message data to interpret.
 * @return true if the message could be correctly interpreted, false o/w
 */
static bool readMessageStart(FsmService * fsmservice, Buffer * message) {
	MessageStart * messagestart;
	bool result;

	LOG(LOG_DEBUG, "Read MessageStart");

	messagestart = messagestart_new();
	messagestart_set(messagestart, fsmservice->shared);
	result = messagestart_deserialize(messagestart, message);
	messagestart_delete(messagestart);

	return result;
}

/**
 * An internal function used to construct a MessageServiceAuth data item.
 *
 * @param fsmservice The object to apply to.
 * @param message A buffer to store the resulting message in.
 */
static void createMessageServiceAuth(FsmService * fsmservice, Buffer * message) {
	MessageServiceAuth * messageserviceauth;

	LOG(LOG_DEBUG, "Send MessageServiceAuth");

	messageserviceauth = messageserviceauth_new();
	messageserviceauth_set(messageserviceauth, fsmservice->shared, 0);
	buffer_clear(message);
	messageserviceauth_serialize(messageserviceauth, message);

	messageserviceauth_delete(messageserviceauth);
}

/**
 * An internal function used to interpret a MessagePicoAuth message.
 *
 * @param fsmservice The object to apply to.
 * @param message The message data to interpret.
 * @param returnedExtraData A buffer to store any extra data that was extracted
 *        from the message.
 * @return true if the message could be correctly interpreted, false o/w
 */
static bool readMessagePicoAuth(FsmService * fsmservice, Buffer * message, Buffer * returnedExtraData) {
	MessagePicoAuth * messagepicoauth;
	bool result;

	LOG(LOG_DEBUG, "Read MessagePicoAuth");
	buffer_clear(returnedExtraData);

	messagepicoauth = messagepicoauth_new();
	messagepicoauth_set(messagepicoauth, fsmservice->shared);
	result = messagepicoauth_deserialize(messagepicoauth, message);
	if (returnedExtraData) {
		buffer_append_buffer(returnedExtraData, messagepicoauth_get_extra_data(messagepicoauth));
	}

	messagepicoauth_delete(messagepicoauth);

	return result;
}

/**
 * An internal function used to construct a MessageStatus data item.
 *
 * The message status can be one of the following.
 *
 * MESSAGESTATUS_OK_DONE
 * MESSAGESTATUS_OK_CONTINUE
 * MESSAGESTATUS_REJECTED
 * MESSAGESTATUS_ERROR
 *
 * See messagestatus.h for details of these values.
 *
 * @param fsmservice The object to apply to.
 * @param message A buffer to store the resulting message in.
 * @param sendExtraData Any extra data that should be sent with the message.
 * @param status The status value to set in the message.
 */
static void createMessageStatus(FsmService * fsmservice, Buffer * message, Buffer const * sendExtraData, signed char status) {
	MessageStatus * messagestatus;

	LOG(LOG_DEBUG, "Send MessageStatus");

	messagestatus = messagestatus_new();
	messagestatus_set(messagestatus, fsmservice->shared, sendExtraData, status);
	buffer_clear(message);
	messagestatus_serialize(messagestatus, message);

	messagestatus_delete(messagestatus);
}

/**
 * An internal function used to interpret a MessagePicoReauth message.
 *
 * @param fsmservice The object to apply to.
 * @param message The message data to interpret.
 * @param returnedExtraData A buffer to store any extra data that was extracted
 *        from the message.
 * @return true if the message could be correctly interpreted, false o/w
 */
static bool readMessagePicoReauth(FsmService * fsmservice, Buffer * message, Buffer * returnedExtraData) {
	MessagePicoReAuth * messagepicoreauth;
	bool result;
	bool sequencenumber_match;
	SequenceNumber * sequenceNum;
	Buffer const * extraData;

	LOG(LOG_DEBUG, "Read MessagePicoReauth");

	sequenceNum = sequencenumber_new();
	sequencenumber_match = true;
	buffer_clear(returnedExtraData);

	// Deserialize the message
	messagepicoreauth = messagepicoreauth_new();
	messagepicoreauth_set(messagepicoreauth, fsmservice->sharedKey, NULL);
	result = messagepicoreauth_deserialize(messagepicoreauth, message);

	if (result) {
		messagepicoreauth_get_sequencenum(messagepicoreauth, sequenceNum);
		fsmservice->currentState = messagepicoreauth_get_reauthstate(messagepicoreauth);

		if (fsmservice->state == FSMSERVICESTATE_CONTSTARTPICO) {
			// This is an initialisation message, so store the receied sequence number for future use
			sequencenumber_copy(fsmservice->picoSeqNumber, sequenceNum);
		} else {
			// This is a subsequent message, so check that the sequence number
			// has been incremented by the Service. If it's all good, store the result
			sequencenumber_match = sequencenumber_equals(fsmservice->picoSeqNumber, sequenceNum);
			if (!sequencenumber_match) {
				LOG(LOG_INFO, "Sequence number from Service didn't match stored value.\n");
			}
		}
	}

	if (result && sequencenumber_match) {
		sequencenumber_increment(fsmservice->picoSeqNumber);
		extraData = messagepicoreauth_get_extra_data(messagepicoreauth);
		buffer_append_buffer(returnedExtraData, extraData);
	} else {
		fsmservice->currentState = REAUTHSTATE_ERROR;
		fsmservice->comms->error(fsmservice->user_data);
	}

	messagepicoreauth_delete(messagepicoreauth);
	sequencenumber_delete(sequenceNum);
	
	return result;
}

/**
 * An internal function used to construct a MessageServiceReauth data item.
 *
 * @param fsmservice The object to apply to.
 * @param message A buffer to store the resulting message in.
 * @param timeout The timeout in milliseconds to send to the Pico.
 * @param extraData [optional] application data to be included in the message
 */
static void createMessageServiceReauth(FsmService * fsmservice, Buffer * message, int timeout, const Buffer * extraData) {
	MessageServiceReAuth * messageservicereauth;

	LOG(LOG_DEBUG, "Send MessageServiceReauth");

	messageservicereauth = messageservicereauth_new();
	messageservicereauth_set(messageservicereauth, fsmservice->sharedKey, timeout, fsmservice->currentState, fsmservice->serviceSeqNumber);
	if (extraData != NULL) {
		messageservicereauth_set_extra_data(messageservicereauth, extraData);
	}
	messageservicereauth_serialize(messageservicereauth, message);

	// Increment the sequence number ready for the next message
	sequencenumber_increment(fsmservice->serviceSeqNumber);

	messageservicereauth_delete(messageservicereauth);
}

/**
 * Check whether the authenticaating user is in the users list that was
 * provided to fsmservice_start(). If the provided list of users was NULL
 * the function will return TRUE.
 *
 * The check is actually performed using the public identity key of the user.
 *
 * @param fsmservice The object to check against.
 * @param user A buffer to return the username of the user.
 * @param symmetrickey A buffer to return the symmetric key of the user.
 * @return TRUE if the user exists in the list, FALSE o/w.
 */
static bool fsmservice_check_user(FsmService * fsmservice, Buffer * user, Buffer * symmetrickey) {
	EC_KEY * picoIdentityPublicKey;
	Buffer const * username;
	Buffer const * key;
	bool result;

	result = true;
	if (user) {
		buffer_clear(user);
	}

	// Check that the Pico identity public key matches with the
	// key expected. The received key can be retrieved using
	if (fsmservice->users != NULL) {
		picoIdentityPublicKey = shared_get_pico_identity_public_key(fsmservice->shared);
		username = users_search_by_key(fsmservice->users, picoIdentityPublicKey);
		result = (username != NULL);

		if (result) {
			// The authentication was successful, so we can return the username and local symmetric key
			if (user) {
				buffer_append_buffer(user, username);
			}

			if (symmetrickey) {
				key = users_search_symmetrickey_by_key(fsmservice->users, picoIdentityPublicKey);
				if (key) {
					buffer_clear(symmetrickey);
					buffer_append_buffer(symmetrickey, key);
				}
			}
		}
	}

	return result;
}

/**
 * Start the authentication process.
 *
 * The Shared data structure *must* include at least the following:
 * 1. EC_KEY * serviceIdPubKey
 * 2. EC_KEY * clientIdPubKey
 * 3. EVP_PKEY * serviceIdPrivKey
 *
 * @param fsmservice The object to apply to.
 * @param shared A Shared object containing the client public key and
 *        the service public-private-key pair.
 * @param users The users authorised to authenticate.
 * @param extraData Any extra data to send to the verifier during the
 *        authentication protocol.
 */
void fsmservice_start(FsmService * fsmservice, Shared * shared, Users const * users, Buffer const * extraData) {
	KeyPair * serviceEphemeralKey;

	LOG(LOG_DEBUG, "Starting Service Finite State Machine");

	// Keep track of the shared object
	fsmservice->shared = shared;
	fsmservice->users = users;

	// Generate ephemeral key
	serviceEphemeralKey = shared_get_service_ephemeral_key(fsmservice->shared);
	keypair_generate(serviceEphemeralKey);

	// Record the extra data
	buffer_clear(fsmservice->extraData);
	buffer_append_buffer(fsmservice->extraData, extraData);

	// Establish the starting state
	fsmservice->state = FSMSERVICESTATE_CONNECT;
	fsmservice->comms->statusUpdate(fsmservice->state, fsmservice->user_data);
}

/**
 * Request that the authentication process be stopped and aborted as soon
 * as is possible.
 *
 * @param fsmservice The object to apply to.
 */
void fsmservice_stop(FsmService * fsmservice) {
	LOG(LOG_DEBUG, "Stop");

	switch (fsmservice->state) {
	case FSMSERVICESTATE_INVALID:
		// Do nothing
		break;
	case FSMSERVICESTATE_CONNECT:
	case FSMSERVICESTATE_START:
	case FSMSERVICESTATE_SERVICEAUTH:
	case FSMSERVICESTATE_PICOAUTH:
	case FSMSERVICESTATE_STATUS:
		// Jump to the auth failed state
		fsmservice->state = FSMSERVICESTATE_AUTHFAILED;
		fsmservice->comms->statusUpdate(fsmservice->state, fsmservice->user_data);
		// Authentication failed
		fsmservice->comms->authenticated(MESSAGESTATUS_REJECTED, fsmservice->user_data);
		break;
	case FSMSERVICESTATE_AUTHENTICATED:
	case FSMSERVICESTATE_AUTHFAILED:
		// Do nothing
		break;
	case FSMSERVICESTATE_CONTSTARTPICO:
	case FSMSERVICESTATE_CONTSTARTSERVICE:
	case FSMSERVICESTATE_PICOREAUTH:
	case FSMSERVICESTATE_SERVICEREAUTH:
		// Jump to fin
		fsmservice->state = FSMSERVICESTATE_FIN;
		fsmservice->comms->statusUpdate(fsmservice->state, fsmservice->user_data);
		// Session ended
		fsmservice->comms->sessionEnded(fsmservice->user_data);
		break;
	case FSMSERVICESTATE_FIN:
	case FSMSERVICESTATE_ERROR:
	case FSMSERVICESTATE_NUM:
		// Do nothing
		break;
	default:
		// Do nothing
		break;
	}

	// Finally, reset the state
	fsmservice->state = FSMSERVICESTATE_INVALID;
}

/**
 * Get the current internal state of the state machine..
 *
 * @param fsmservice The object to apply to.
 * @return The current state of the state machine.
 */
FSMSERVICESTATE fsmservice_get_state(FsmService * fsmservice) {
	return fsmservice->state;
}

/**
 * Get the user that authenticated. The value is only valid after the
 * state machine has reached the FSMSERVICESTATE_STATUS state and the
 * authentication succeeded. Otherwise the buffer will be empty.
 *
 * The buffer is owned by FsmService, so should not be deleted by the
 * caller.
 *
 * @param fsmservice The object to get the data from.
 * @return A buffer containing the user name.
 */
Buffer const * fsmservice_get_user(FsmService * fsmservice) {
	return fsmservice->user;
}

/**
 * Get the symmetric key stored for the authenticatd user. The value is
 * only valid after the state machine has reached the
 * FSMSERVICESTATE_STATUS state and the authentication succeeded.
 * Otherwise the buffer will be empty.
 *
 * The buffer is owned by FsmService, so should not be deleted by the
 * caller.
 *
 * @param fsmservice The object to get the data from.
 * @return A buffer containing the symmetric key stored for the user.
 */
Buffer const * fsmservice_get_symmetric_key(FsmService * fsmservice) {
	return fsmservice->symmetrickey;
}

/**
 * Set whether the FSM should perform continuous authentication or not. If set
 * to true, once a Pico has authenticated the service will attempt to perform
 * continuous authentication over an indefinite period of time. If set to false,
 * the service will stop after the first full authentication and no longer try
 * to authenticate periodically after that.
 *
 * @param fsmservice The object to set the value for.
 * @param continuous True if the service should continuously authenticate the
 *        Pico, false o/w.
 */
void fsmservice_set_continuous(FsmService * fsmservice, bool continuous) {
	fsmservice->continuous = continuous;
}

/**
 * Get the latest extra data that was sent by the Pico. This is updated when
 * the pico sends either a PicoAuth or PicoReauth message. The value is reset
 * for each of these messages, and so the previous value will be wiped when
 * either of these messages is received (even if the Pico doesn't send any
 * extra data).
 *
 * To be alerted to any fresh data that arrives, the simplest approach is to
 * set up an FsmStatusUpdate callback and check for any data recevied on either
 * of the following two events:
 *
 * 1. FSMSERVICESTATE_STATUS
 * 2. FSMSERVICESTATE_SERVICEREAUTH
 *
 * Then make a call using this function to check whether any new data
 * has arrived (in which case, the returned buffer will be non-empty).
 *
 * These two events are those that immediately proceed the arrival of a
 * PicoAuth or PicoReath message.
 *
 * @param fsmservice The object to get the extra data from.
 * @return The latest extra data received from the Pico, or an empty buffer.
 */
Buffer const * fsmservice_get_received_extra_data(FsmService * fsmservice) {
	return fsmservice->returnedExtraData;
}

/**
 *
 * Set the extra data that will be sent to the Pico. This is the same value
 * that can be set using fsmservice_start(). However, different data can be
 * sent at different times. The data is sent in the Status and ServiceReauth
 * messages. As such, to ensure it's set prior to each of these messages being
 * sent, it's safe to set the new extra data when an update notifcation is
 * triggered for either of the following events:
 *
 * 1. FSMSERVICESTATE_STATUS
 * 2. FSMSERVICESTATE_SERVICEREAUTH
 *
 * These two events are those that immediately proceed the arrival of a
 * Status or ServiceReauth message.
 *
 * @param fsmservice The object to set the extra data from.
 * @return The next extra data to be sent to the Pico.
 */
void fsmservice_set_outbound_extra_data(FsmService * fsmservice, Buffer const * extraData) {
	// Record the extra data
	buffer_clear(fsmservice->extraData);
	if (extraData != NULL) {
		buffer_append_buffer(fsmservice->extraData, extraData);
	}
}

/** @} addtogroup Protocol */

