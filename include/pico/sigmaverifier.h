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

#ifndef __SIGMAVERIFIER_H
#define __SIGMAVERIFIER_H (1)

#include "pico/shared.h"
#include "pico/channel.h"
#include "pico/users.h"
#include "pico/buffer.h"
#include "pico/dllpublic.h"

// Defines

// Structure definitions

// Function prototypes

DLL_PUBLIC bool sigmaverifier(Shared * shared, RVPChannel * channel, Users * authorizedUsers, char const * extraData, Buffer * returnedStoredData, Buffer * localSymmetricKey);
DLL_PUBLIC bool sigmaverifier_session(Shared * shared, RVPChannel * channel, Users * authorizedUsers, char const * sendExtraData, Buffer * returnedExtraData, Buffer * localSymmetricKey, bool continuous, int sessionId);

// Function definitions

#endif

/** @} addtogroup Protocol */

