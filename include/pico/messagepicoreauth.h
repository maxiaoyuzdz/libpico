/** \ingroup Message
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
 * @brief Message for continuously authenticating the prover to the verifier
 * @section DESCRIPTION
 *
 * The MessagePicoReAuth class allows an incoming Re-Auth message arriving at
 * the server from the Pico to be deserialized, decrypted and checked, and
 * for the relevant parts to be extracted for use in the protocol.
 * 
 * This represents a message sent as part of the continuous authentication
 * process.
 * QR-code (KeyAuth or KeyPair); Start; ServiceAuth; PicoAuth; Status;
 * Pico ReAuth; Service ReAuth (repeatedly).
 *
 * The structure of the message is as follows
 * {"encryptedData":"B64-ENC","iv":"B64","sessionId":0}
 * Where encryptedData contains the following sections
 * char reauthState | length | char sequenceNumber[length] | length | char extraData[length]
 *
 */

/** \addtogroup Message
 *  @{
 */

#ifndef __MESSAGEPICOREAUTH_H
#define __MESSAGEPICOREAUTH_H (1)

#include <openssl/ec.h>
#include "pico/shared.h"
#include "pico/nonce.h"
#include "pico/buffer.h"
#include "pico/sequencenumber.h"

// Defines

// Structure definitions

typedef enum _REAUTHSTATE {
	REAUTHSTATE_INVALID = -1,

	REAUTHSTATE_CONTINUE,
	REAUTHSTATE_PAUSE,
	REAUTHSTATE_STOP,
	REAUTHSTATE_ERROR,

	REAUTHSTATE_NUM
} REAUTHSTATE;

/**
 * The internal structure can be found in messagepicoreauth.c
 */
typedef struct _MessagePicoReAuth MessagePicoReAuth;

// Function prototypes

MessagePicoReAuth * messagepicoreauth_new();
void messagepicoreauth_delete(MessagePicoReAuth * messagepicoreauth);
void messagepicoreauth_set(MessagePicoReAuth * messagepicoreauth, Buffer * sharedKey, SequenceNumber const * sequenceNum);
void messagepicoreauth_get_sequencenum(MessagePicoReAuth * messagepicoreauth, SequenceNumber * sequenceNum);
REAUTHSTATE messagepicoreauth_get_reauthstate(MessagePicoReAuth * messagepicoreauth);
void messagepicoreauth_set_reauthstate(MessagePicoReAuth * messagepicoreauth, REAUTHSTATE reauthstate);
Buffer const * messagepicoreauth_get_extra_data(MessagePicoReAuth * messagepicoreauth);
void messagepicoreauth_serialize(MessagePicoReAuth * messagepicoreauth, Buffer const * extraData, Buffer * buffer);
bool messagepicoreauth_deserialize(MessagePicoReAuth * messagepicoreauth, Buffer * buffer);

// Function definitions

#endif

/** @} addtogroup Message */

