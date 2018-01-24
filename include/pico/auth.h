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
 * @brief Performs the server authentication and pairing protocols
 * @section DESCRIPTION
 *
 * The Auth class encapsulates the Pico server authentication and pairing
 * protocol into single call. 
 *
 */

/** \addtogroup Protocol
 *  @{
 */

#ifndef __AUTH_H
#define __AUTH_H (1)

#include "pico/shared.h"
#include "pico/users.h"
#include "pico/buffer.h"
#include "pico/dllpublic.h"

// Defines
/**
 * Callback function to be used by auth and pair
 * 
 * @param qrtext Text to be presented to Pico
 * @param localdata General purpose pointer to be sent along
 * 				    the function calls
 * @return True if successful
 */ 
typedef bool (*QrCallbackFunction)(char * qrtext, void * localdata);

// Structure definitions

// Function prototypes

DLL_PUBLIC bool auth(Shared * shared, Users * authorizedUsers, Buffer * returnedStoredData, QrCallbackFunction qrCallback, void * data, Buffer * localSymmetricKey);
DLL_PUBLIC bool pair_send_username_loop(Shared * shared, char const * servicename, char const * extraData, char const * username, Buffer * returnedStoredData, QrCallbackFunction qrCallback, void * data, int loop_verifier);
DLL_PUBLIC bool pair(Shared * shared, char const * servicename, char const * extraData,	Buffer * returnedStoredData, QrCallbackFunction qrCallback, void * data);
DLL_PUBLIC bool pair_loop(Shared * shared, char const * servicename, char const * extraData,	Buffer * returnedStoredData, QrCallbackFunction qrCallback, void * data, int loopVerifier);

// Function definitions

#endif

/** @} addtogroup Protocol */

