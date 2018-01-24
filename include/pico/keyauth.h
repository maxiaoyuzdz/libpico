/** \ingroup Crypto
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
 * @brief Generate the message needed to kick-off an authentication
 * @section DESCRIPTION
 *
 * The KeyAuth class generates the json string used to bootstrap the 
 * authorisation process. This may be embedded in - say - a QR code, displayed
 * by the server. When scanned by a Pico, the serialized KeyAuth structure
 * contains enough details to allow the Pico to contact the server via the
 * Rendezvous Point and kickstart the authentication process.
 *
 * In essence, the KeyAuth class allows the generation of "KA"-type QR codes.
 * This can be contrasted with the KeyPairing class for generating "KP"-type
 * codes.
 *
 * The format of the serialized output is as follows.
 * {"t":"KA","sc":"B64","ed":"","sa":"URL","td":{}}
 *
 */

/** \addtogroup Crypto
 *  @{
 */

#ifndef __KEYAUTH_H
#define __KEYAUTH_H (1)

#include "pico/dllpublic.h"

// Defines

// Structure definitions

/**
 * The internal structure can be found in keyauth.c
 */
typedef struct _KeyAuth KeyAuth;

// Function prototypes

DLL_PUBLIC KeyAuth * keyauth_new();
DLL_PUBLIC void keyauth_delete(KeyAuth * keyauth);
DLL_PUBLIC void keyauth_set(KeyAuth * keyauth, Buffer const * serviceAddress, char const * terminalAddress, Buffer const * terminalCommitment, KeyPair * serviceIdentityKey);
DLL_PUBLIC void keyauth_print(KeyAuth * keyauth);
DLL_PUBLIC void keyauth_log(KeyAuth * keyauth);
DLL_PUBLIC size_t keyauth_serialize_size(KeyAuth * keyauth);
DLL_PUBLIC size_t keyauth_serialize(KeyAuth * keyauth, char * buffer, size_t size);

// Function definitions

#endif

/** @} addtogroup Crypto */

