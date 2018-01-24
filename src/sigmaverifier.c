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
 * @brief Perform the verifier's half of he SIGMA-I protocol
 * @section DESCRIPTION
 *
 * The sigmaverifier function performs the service's (verifier's) half of the
 * SIGMA-I protocol over the Rendezvous Point channel provided.
 * 
 */

/** \addtogroup Protocol
 *  @{
 */

#include <stdio.h>
#include <malloc.h>
#include <stdbool.h>
#include <string.h>
#include "pico/debug.h"
#include "pico/shared.h"
#include "pico/channel.h"
#include "pico/messagestart.h"
#include "pico/messageserviceauth.h"
#include "pico/messagepicoauth.h"
#include "pico/messagestatus.h"
#include "pico/feedback.h"
#include "pico/log.h"
#include "pico/sigmaverifier.h"

// Defines

// Structure definitions

// Function prototypes

// Function definitions

/**
 * Perform the Sigma-I sigma verifier protocol. This is used by both the
 * authentication and pairing protocols.
 *
 * After the service has received the PicoAuth message it will be in a 
 * position to identify the Pico from its long-term public key. The 
 * authorizedUsers list provides a means of authorization: if the user isn't
 * in this list, the protocol will be aborted and returns false.
 * Note that setting this to null will cause all users to be granted access.
 * This is different from an empty list, which will prevent any user from
 * being granted access. It's really important to get this distinction right!
 * As a general rule, a NULL authorizedUsers pointer should only be used during
 * pairing.
 *
 * @param shared Object containing the shared data required throughout the
 *        protocol
 * @param channel The Rendezvous Point channel to use to communicate between
 *                the service and the Pico
 * @param authorizedUsers A list of authorized users to grant access to (which 
 *                        can be empty to block everyone), or a NULL pointer
 *                        to allow access to any authenticating Pico (i.e. any
 *                        Pico successfully completing the protocol).
 * @param sendExtraData Data to be sent in the ok message 
 * @param returnedExtraData If not null, will be appended with the returned 
 *                          extradata 
 *                        
 * @return true if (the protocol completed successfully AND (the user was found
 *         in the authorizedUsers list OR authorizedUsers was NULL)); false o/w
 */
bool sigmaverifier(Shared * shared, RVPChannel * channel, Users * authorizedUsers, char const * sendExtraData, Buffer * returnedExtraData, Buffer * localSymmetricKey) {
	bool result;

	result = sigmaverifier_session(shared, channel, authorizedUsers, sendExtraData, returnedExtraData, localSymmetricKey, false, 0);

	return result;
}

/**
 * Perform the Sigma-I sigma verifier protocol. This is used by both the
 * authentication and pairing protocols. This version allows some extra
 * parameters to be set to support continuous authentication.
 *
 * After the service has received the PicoAuth message it will be in a 
 * position to identify the Pico from its long-term public key. The 
 * authorizedUsers list provides a means of authorization: if the user isn't
 * in this list, the protocol will be aborted and returns false.
 * Note that setting this to null will cause all users to be granted access.
 * This is different from an empty list, which will prevent any user from
 * being granted access. It's really important to get this distinction right!
 * As a general rule, a NULL authorizedUsers pointer should only be used during
 * pairing.
 *
 * @param shared Object containing the shared data required throughout the
 *        protocol
 * @param channel The Rendezvous Point channel to use to communicate between
 *                the service and the Pico
 * @param authorizedUsers A list of authorized users to grant access to (which 
 *                        can be empty to block everyone), or a NULL pointer
 *                        to allow access to any authenticating Pico (i.e. any
 *                        Pico successfully completing the protocol).
 * @param sendExtraData Data to be sent in the ok message 
 * @param returnedExtraData If not null, will be appended with the returned 
 *                          extradata 
 * @param localSymmetricKey Buffer to return the user's local symmetric key
 * @param continuous Set to true for continuous authenticatio, false otherwise
 * @param sessionId The session ID to send to Pico
 *                        
 * @return true if (the protocol completed successfully AND (the user was found
 *         in the authorizedUsers list OR authorizedUsers was NULL)); false o/w
 */
bool sigmaverifier_session(Shared * shared, RVPChannel * channel, Users * authorizedUsers, char const * sendExtraData, Buffer * returnedExtraData, Buffer * localSymmetricKey, bool continuous, int sessionId) {
	KeyPair * serviceEphemeralKey;
	Buffer * buffer;
	MessageStart * messagestart;
	MessageServiceAuth * messageserviceauth;
	MessagePicoAuth * messagepicoauth;
	MessageStatus * messagestatus;
	bool result;
	Buffer const * username;
	Buffer const * symmetricKey;
	EC_KEY * picoIdentityPublicKey;
	char messageStatus;
	Feedback * feedback;
	bool channelopen;
	Buffer * extraData;

	result = true;
	channelopen = false;

	buffer = buffer_new(0);

	shared_feedback_reset(shared, FEEDBACKAUTHVERIFIER_NUM);
	feedback = shared_get_feedback(shared);
	feedback_set_special_removeqr(feedback, FEEDBACKAUTHVERIFIER_CONTACTEDBYPICO);

	if (result) {
		result = shared_next_stage(shared, authVerifierFeedback[FEEDBACKAUTHVERIFIER_GENKEYS]);
	}

	if (result) {
		// Generate ephemeral key
		serviceEphemeralKey = shared_get_service_ephemeral_key(shared);
		keypair_generate(serviceEphemeralKey);

		result = shared_next_stage(shared, authVerifierFeedback[FEEDBACKAUTHVERIFIER_WAITFORPICO]);
	}

	if (result) {
		channelopen = channel_open(channel);
		result = channelopen;
	}

	if (result) {
		// RECEIVE
		// Read StartMessage from client
		// {"picoEphemeralPublicKey":"B64-PUB-KEY","picoNonce":"B64-NONCE","picoVersion":2}
		//printf("First round trip\n");
		buffer_clear(buffer);
		result = channel_read(channel, buffer);
	}

	if (result) {
		result = shared_next_stage(shared, authVerifierFeedback[FEEDBACKAUTHVERIFIER_CONTACTEDBYPICO]);
	}
	

	if (result) {
		// Deserialize the message
		messagestart = messagestart_new();
		messagestart_set(messagestart, shared);
		result = messagestart_deserialize(messagestart, buffer);
		messagestart_delete(messagestart);
	}

	if (result) {
		result = shared_next_stage(shared, authVerifierFeedback[FEEDBACKAUTHVERIFIER_AUTHSERVICE]);
	}

	if (result) {
		// SEND
		// Reply with ServiceAuthMessage
		// {"serviceEphemPublicKey":"B64-PUB-KEY","serviceNonce":"B64-NONCE","sessionId":0,"encryptedData":"B64-ENC","iv":"B64"}
		messageserviceauth = messageserviceauth_new();
		messageserviceauth_set(messageserviceauth, shared, 0);
		buffer_clear(buffer);
		messageserviceauth_serialize(messageserviceauth, buffer);
		result = channel_write_buffer(channel, buffer);
		messageserviceauth_delete(messageserviceauth);
	}
	
	if (result) {
		result = shared_next_stage(shared, authVerifierFeedback[FEEDBACKAUTHVERIFIER_AUTHPICO]);
	}

	if (result) {
		// RECEIVE
		// Read PicoAuthMessage
		// {"encryptedData":"B64-ENC","iv":"B64","sessionId":0}
		//printf("Second round trip\n");
		buffer_clear(buffer);
		result = channel_read(channel, buffer);
	}

	if (result) {
		shared_next_stage(shared, authVerifierFeedback[FEEDBACKAUTHVERIFIER_AUTHRECEIVED]);
	}

	if (result) {
		// Deserialize the message
		messagepicoauth = messagepicoauth_new();
		messagepicoauth_set(messagepicoauth, shared);
		result = messagepicoauth_deserialize(messagepicoauth, buffer);
		if (returnedExtraData) {
			buffer_append_buffer(returnedExtraData, messagepicoauth_get_extra_data(messagepicoauth));
		}
		messagepicoauth_delete(messagepicoauth);
	}

	if (result) {
		result = shared_next_stage(shared, authVerifierFeedback[FEEDBACKAUTHVERIFIER_FINALISING]);
	}

	if ((result) && (authorizedUsers != NULL)) {
		picoIdentityPublicKey = shared_get_pico_identity_public_key(shared);
		username = users_search_by_key(authorizedUsers, picoIdentityPublicKey);
		if (username == NULL) {
			// SEND
			// Reply with StatusMessage
			// {"iv":"B64","encryptedData":"B64-ENC","sessionId":0}
			messagestatus = messagestatus_new();
			messagestatus_set(messagestatus, shared, NULL, MESSAGESTATUS_REJECTED);
			buffer_clear(buffer);
			messagestatus_serialize(messagestatus, buffer);
			channel_write_buffer(channel, buffer);
			messagestatus_delete(messagestatus);
			result = false;
		}
		else {
			// The authentication was successful, so we can return the local symmetric key
			if (localSymmetricKey) {
				symmetricKey = users_search_symmetrickey_by_key(authorizedUsers, picoIdentityPublicKey);
				if (symmetricKey) {
					buffer_clear(localSymmetricKey);
					buffer_append_buffer(localSymmetricKey, symmetricKey);
				}
			}
		}
	}

	if (result) {
		// SEND
		// Reply with StatusMessage
		// {"iv":"B64","encryptedData":"B64-ENC","sessionId":0}
		if (continuous) {
			messageStatus = MESSAGESTATUS_OK_CONTINUE;
		}
		else {
			messageStatus = MESSAGESTATUS_OK_DONE;
		}

		messagestatus = messagestatus_new();
		extraData = buffer_new(0);
		if (sendExtraData != NULL) {
			buffer_append(extraData, sendExtraData, strlen(sendExtraData));
		}
		messagestatus_set(messagestatus, shared, extraData, messageStatus);
		messagestatus_set_session_id(messagestatus, sessionId);
		buffer_clear(buffer);
		messagestatus_serialize(messagestatus, buffer);
		result = channel_write_buffer(channel, buffer);
		messagestatus_delete(messagestatus);
		buffer_delete(extraData);
	}

	buffer_delete(buffer);

	if (result) {
		result = shared_next_stage(shared, authVerifierFeedback[FEEDBACKAUTHVERIFIER_DONE]);
	}


	if (channelopen) {
		channel_close(channel);
	}

	return result;
}

/** @} addtogroup Protocol */

