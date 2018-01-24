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
 * @brief Generate the message needed to kick-off a pairing
 * @section DESCRIPTION
 *
 * The KeyPairing class generates the json string used to bootstrap the 
 * pairing process. This may be embedded in - say - a QR code, displayed
 * by the server. When scanned by a Pico, the serialized KeyPairing structure
 * contains enough details to allow the Pico to contact the server via the
 * Rendezvous Point and kickstart the pairing process.
 *
 * In essence, the KeyPairing class allows the generation of "PA"-type QR codes.
 * This can be contrasted with the KeyAuth class for generating "KA"-type codes.
 *
 * The format of the serialized output is as follows.
 * {"sn":"NAME","spk":"PUB-KEY","sig":"B64-SIG","ed":"","sa":"URL","td":{},"t":"KP"}
 */

/** \addtogroup Protocol
 *  @{
 */

#ifndef __KEYPAIRING_H
#define __KEYPAIRING_H (1)

#include "pico/dllpublic.h"

// Defines

// Structure definitions

/**
 * The internal structure can be found in keypairing.c
 */
typedef struct _KeyPairing KeyPairing;

// Function prototypes

DLL_PUBLIC KeyPairing * keypairing_new();
DLL_PUBLIC void keypairing_delete(KeyPairing * keypairing);
DLL_PUBLIC void keypairing_set(KeyPairing * keypairing, Buffer const * serviceAddress, char const * terminalAddress, Buffer const * terminalCommitment, char const * serviceName, KeyPair * serviceIdentityKey);
DLL_PUBLIC void keypairing_print(KeyPairing * keypairing);
DLL_PUBLIC void keypairing_log(KeyPairing * keypairing);
DLL_PUBLIC size_t keypairing_serialize_size(KeyPairing * keypairing);
DLL_PUBLIC size_t keypairing_serialize(KeyPairing * keypairing, char * buffer, size_t size);

// Function definitions

#endif

/** @} addtogroup Protocol */

