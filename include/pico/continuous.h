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
 * @brief Continuous authentication protocol support
 * @section DESCRIPTION
 *
 * Once a device has been authenticated, it can offer to remain authenticated
 * on a continuous basis. In this case the verifier and prover will perform a
 * ping-pong message exchange on a regular basis (e.g. once every ten seconds).
 * In the event that the messages fail to arrive or can't be correctly decoded
 * (e.g. the decryption fails) then the authenticated session closes. In this
 * way the user can be continuously authenticated based on some characteristic
 * such as being within communication range.
 * 
 * The continuous class provides support for these continuous authentication
 * activities.
 *
 */

/** \addtogroup Protocol
 *  @{
 */

#ifndef __CONTINUOUS_H
#define __CONTINUOUS_H (1)

#include "pico/shared.h"
#include "pico/users.h"
#include "pico/buffer.h"
#include "pico/auth.h"
#include "pico/dllpublic.h"
#include "pico/messagepicoreauth.h"

// Defines

// Structure definitions

/*
 * The internal structure can be found in continuous.c
 */
typedef struct _Continuous Continuous;

// Function prototypes

DLL_PUBLIC Continuous * continuous_new();
DLL_PUBLIC void continuous_delete(Continuous * continuous);
DLL_PUBLIC void continuous_set_pico_sequence_number(Continuous * continuous, SequenceNumber * seqNumber);
DLL_PUBLIC void continuous_set_service_sequence_number(Continuous * continuous, SequenceNumber * seqNumber);
DLL_PUBLIC REAUTHSTATE continuous_get_state(Continuous * continuous);

DLL_PUBLIC bool continuous_start(Continuous * continuous, Shared * shared, Users * authorizedUsers, Buffer * returnedStoredData, QrCallbackFunction qrCallback, void * data, Buffer * localSymmetricKey);
DLL_PUBLIC bool continuous_cycle_start(Continuous * continuous);
DLL_PUBLIC bool continuous_cycle_start_pico(Continuous * continuous, Buffer * extraData);
DLL_PUBLIC bool continuous_read_pico_reauth(Continuous * continuous, SequenceNumber * sequenceNumber, Buffer * returnedStoredData);
DLL_PUBLIC bool continuous_write_pico_reauth(Continuous * continuous, Buffer * extraData);
DLL_PUBLIC bool continuous_read_service_reauth(Continuous * continuous, SequenceNumber * sequenceNumber, int * timeout);
DLL_PUBLIC bool continuous_write_service_reauth(Continuous * continuous);
DLL_PUBLIC bool continuous_update_state(Continuous * continuous, REAUTHSTATE new_state);
DLL_PUBLIC bool continuous_reauth(Continuous * continuous, Buffer * returnedStoredData);
DLL_PUBLIC bool continuous_reauth_pico(Continuous * continuous, Buffer * extraData, int * timeout);
DLL_PUBLIC bool continuous_continue(Continuous * continuous, Buffer * returnedStoredData);
DLL_PUBLIC bool continuous_finish(Continuous * continuous);

DLL_PUBLIC void continuous_set_custom_timeout(Continuous * continuous, int timeout_active, int timeout_paused);
DLL_PUBLIC void continuous_set_custom_timeout_leeway(Continuous * continuous, int timeout_leeway);
DLL_PUBLIC void continuous_set_shared_key(Continuous * continuous, Buffer * sharedKey);
DLL_PUBLIC void continuous_get_shared_key(Continuous * continuous, Buffer * sharedKey);

DLL_PUBLIC void continuous_set_channel(Continuous * continuous, RVPChannel * channel);
DLL_PUBLIC RVPChannel * continuous_get_channel(Continuous * continuous);

DLL_PUBLIC bool continuous_continue_pico(Continuous * continuous, Buffer * extraData, int * timeout);

// Function definitions

#endif

/** @} addtogroup Protocol */

