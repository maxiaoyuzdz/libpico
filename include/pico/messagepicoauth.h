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
 * @brief Message for authenticating the prover to the verifier
 * @section DESCRIPTION
 *
 * The MessagePicoAuth class allows an incoming PicoAuth message arriving at
 * the server from the Pico to be deserialized, decrypted and checked, and
 * for the relevant parts to be extracted for use in the protocol.
 * 
 * This represents the first message forming the second round trip of the
 * Sigma-I protocol:
 * QR-code (KeyAuth or KeyPair); Start; ServiceAuth; PicoAuth; Status.
 *
 * The structure of the message is as follows
 * {"encryptedData":"B64-ENC","iv":"B64","sessionId":0}
 *
 */

/** \addtogroup Message
 *  @{
 */

#ifndef __MESSAGEPICOAUTH_H
#define __MESSAGEPICOAUTH_H (1)

#include <openssl/ec.h>
#include "pico/shared.h"
#include "pico/nonce.h"
#include "pico/buffer.h"

// Defines

// Structure definitions

/**
 * The internal structure can be found in messagepicoauth.c
 */
typedef struct _MessagePicoAuth MessagePicoAuth;

// Function prototypes

MessagePicoAuth * messagepicoauth_new();
void messagepicoauth_delete(MessagePicoAuth * messagepicoauth);
void messagepicoauth_set(MessagePicoAuth * messagepicoauth, Shared * shared);
Buffer * messagepicoauth_get_extra_data(MessagePicoAuth * messagepicoauth);
void messagepicoauth_set_extra_data(MessagePicoAuth * messagepicoauth, Buffer const * extraData);
bool messagepicoauth_deserialize(MessagePicoAuth * messagepicoauth, Buffer * buffer);
void messagepicoauth_serialize(MessagePicoAuth * messagepicoauth, Buffer * buffer);

// Function definitions

#endif

/** @} addtogroup Message */

