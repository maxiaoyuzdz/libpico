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
 * @brief Message for initialising the SIGMA-I authentication protocol
 * @section DESCRIPTION
 *
 * The MessageStart class allows an incoming Start message arriving at
 * the server from the Pico to be deserialized and checked, and
 * for the relevant parts to be extracted for use in the protocol.
 * 
 * This represents the first message forming the first round trip of the
 * Sigma-I protocol:
 * QR-code (KeyAuth or KeyPair); Start; ServiceAuth; PicoAuth; Status.
 *
 * The structure of the message is as follows
 * {"picoEphemeralPublicKey":"B64-PUB-KEY","picoNonce":"B64-NONCE","picoVersion":2}
 *
 */

/** \addtogroup Message
 *  @{
 */

#ifndef __MESSAGESTART_H
#define __MESSAGESTART_H (1)

#include "pico/nonce.h"
#include "pico/shared.h"
#include "pico/buffer.h"

// Defines

// Structure definitions

/**
 * The internal structure can be found in messagestart.c
 */
typedef struct _MessageStart MessageStart;

// Function prototypes

MessageStart * messagestart_new();
void messagestart_delete(MessageStart * messagestart);
void messagestart_set(MessageStart * messagestart, Shared * shared);
bool messagestart_deserialize(MessageStart * messagestart, Buffer * buffer);
bool messagestart_serialize(MessageStart * messagestart, Buffer * buffer);

// Function definitions

#endif

/** @} addtogroup Message */

