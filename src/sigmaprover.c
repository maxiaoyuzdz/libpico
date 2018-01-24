#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include "pico/debug.h"
#include "pico/shared.h"
#include "pico/channel.h"
#include "pico/messagestart.h"
#include "pico/messageserviceauth.h"
#include "pico/messagepicoauth.h"
#include "pico/messagestatus.h"
#include "pico/log.h"
#include "pico/users.h"
#include "pico/sigmaprover.h"
#include "pico/cryptosupport.h"
#include "pico/json.h"
#include <string.h>

// Defines

// Structure definitions

// Function prototypes

// Function definitions

/**
 * Perform the Sigma-I sigma prover protocol. This is used by both the
 * authentication and pairing protocols.
 *
 * After successful completion, the value sent by the service in the final
 * status message can be obtained from the shared object using
 * {@link shared_get_status}.
 *
 * @param shared Object containing the shared data required throughout the
 *        protocol
 * @param channel The Rendezvous Point channel to use to communicate between
 *                the service and the Pico
 * @param sendExtraData Extra data to send to the service
 * @param returnedExtraData Buffer that will receive extra data from the service
 *
 * @return true if the protocol completed successfully; false o/w
 */
bool sigmaprover(Shared * shared, RVPChannel * channel, Buffer const * sendExtraData, Buffer * returnedExtraData) {
	//KeyPair * serviceEphemeralKey;
	Buffer * buffer;
	MessageStart * messagestart;
	//MessageServiceAuth * messageserviceauth;
	MessagePicoAuth * messagepicoauth;
	//MessageStatus * messagestatus;
	bool result;
	//Buffer const * username;
	//Buffer const * symmetricKey;
	//EC_KEY * picoIdentityPublicKey;
	//char messageStatus;
	MessageServiceAuth * messageserviceauth;
	MessageStatus * messagestatus;
	Feedback * feedback;

	buffer = buffer_new(0);

	buffer_clear(buffer);

	shared_feedback_reset(shared, FEEDBACKAUTHPROVER_NUM);
	feedback = shared_get_feedback(shared);
	feedback_set_special_removeqr(feedback, FEEDBACKAUTHPROVER_CONTACTSERVICE);

	result = shared_next_stage(shared, authProverFeedback[FEEDBACKAUTHPROVER_CONTACTSERVICE]);

	if (result) {
		LOG(LOG_INFO, "Send MessageStart\n");
		messagestart = messagestart_new();
		messagestart_set(messagestart, shared);
		messagestart_serialize(messagestart, buffer);
		result = channel_write_buffer(channel, buffer);
		buffer_clear(buffer);
		messagestart_delete(messagestart);
	}

	if (result) {
		result = shared_next_stage(shared, authProverFeedback[FEEDBACKAUTHPROVER_AUTHSERVICE]);
	}

	if (result) {
		LOG(LOG_INFO, "Read from channel\n");
		result = channel_read(channel, buffer);
	}

	if (result) {
		LOG(LOG_INFO, "Read MessageServiceAuth\n");

		messageserviceauth = messageserviceauth_new();
		messageserviceauth_set(messageserviceauth, shared, 0);

		LOG(LOG_INFO, "Deserializing\n");
		buffer_log(buffer);
		// Error
		result = messageserviceauth_deserialize(messageserviceauth, buffer);

		messageserviceauth_delete(messageserviceauth);
	}

	if (result) {
		result = shared_next_stage(shared, authProverFeedback[FEEDBACKAUTHPROVER_AUTHPICO]);
	}

	if (result) {
		LOG(LOG_INFO, "Send MessagePicoAuth\n");
		messagepicoauth = messagepicoauth_new();
		messagepicoauth_set(messagepicoauth, shared);
		messagepicoauth_set_extra_data(messagepicoauth, sendExtraData);
		buffer_clear(buffer);
		messagepicoauth_serialize(messagepicoauth, buffer);
		result = channel_write_buffer(channel, buffer);
		buffer_clear(buffer);
	}

	if (result) {
		result = shared_next_stage(shared, authProverFeedback[FEEDBACKAUTHPROVER_AWAITRESULT]);
	}

	messagestatus = messagestatus_new();

	if (result) {
		LOG(LOG_INFO, "Read MessageStatus\n");
		result = channel_read(channel, buffer);
	}

	if (result) {
		LOG(LOG_INFO, "Read MessageStatus\n");
		messagestatus_set(messagestatus, shared, NULL, 0);

		result = messagestatus_deserialize(messagestatus, buffer);

		LOG(LOG_INFO, "MessageStatus deserialize result: %d\n", result);
	}

	if (result) {
		shared_set_status(shared, messagestatus_get_status(messagestatus));
		
		if (returnedExtraData) {
			buffer_append_buffer(returnedExtraData, messagestatus_get_extra_data(messagestatus));
		}
	}

	messagestatus_delete(messagestatus);
	buffer_delete(buffer);

	if (result) {
		result = shared_next_stage(shared, authProverFeedback[FEEDBACKAUTHPROVER_DONE]);
	}

	return result;
}

