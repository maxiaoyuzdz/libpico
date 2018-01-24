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
 * @brief Shared data and secrets needed for SIGMA-I protocol
 * @section DESCRIPTION
 *
 * The Shared class encapsulates all of the shared data and secrets needed to
 * perform the SIGMA-I protocol. For example, identity keys, ephemeral keys,
 * nonces and shared generates secrets.
 *
 * Some of the contents are provided at creation (e.g. the service identity
 * key, whereas others are added as the protocol progresses.
 * 
 */

/** \addtogroup Protocol
 *  @{
 */

#ifndef __SHARED_H
#define __SHARED_H (1)

#include <openssl/ec.h>
#include "pico/keypair.h"
#include "pico/nonce.h"
#include "pico/feedback.h"
#include "pico/dllpublic.h"

// Defines

// Structure definitions

/**
 * The internal structure can be found in shared.c
 */
typedef struct _Shared Shared;

// Function prototypes

DLL_PUBLIC Shared * shared_new();
DLL_PUBLIC void shared_delete(Shared * shared);
DLL_PUBLIC void shared_generate_shared_secrets(Shared * shared);
DLL_PUBLIC void shared_generate_shared_secrets_pico(Shared * shared);
DLL_PUBLIC void shared_load_or_generate_keys(Shared * shared, char const * key_public, char const * key_private);
void shared_load_or_generate_pico_keys(Shared * shared, char const * key_public, char const * key_private);
bool shared_load_service_keys(Shared * shared, char const * key_public, char const * key_private);

DLL_PUBLIC Nonce * shared_get_service_nonce(Shared const * shared);
DLL_PUBLIC Nonce * shared_get_pico_nonce(Shared const * shared);
DLL_PUBLIC KeyPair * shared_get_service_identity_key(Shared const * shared);
DLL_PUBLIC KeyPair * shared_get_pico_identity_key(Shared const * shared);
DLL_PUBLIC KeyPair * shared_get_service_ephemeral_key(Shared const * shared);
DLL_PUBLIC KeyPair * shared_get_pico_ephemeral_key(Shared const * shared);
DLL_PUBLIC void shared_set_pico_identity_public_key(Shared * shared, EC_KEY * picoIdentityPublicKey);
DLL_PUBLIC void shared_set_service_identity_public_key(Shared * shared, EC_KEY * serviceIdentityPublicKey);
DLL_PUBLIC void shared_set_pico_identity_private_key(Shared * shared, EVP_PKEY * picoIdentityPrivateKey);
DLL_PUBLIC void shared_set_service_identity_private_key(Shared * shared, EVP_PKEY * serviceIdentityPrivateKey);
DLL_PUBLIC EC_KEY * shared_get_pico_identity_public_key(Shared const * shared);
DLL_PUBLIC void shared_set_pico_ephemeral_public_key(Shared const * shared, EC_KEY * picoEphemeralPublicKey);
DLL_PUBLIC void shared_set_service_ephemeral_public_key(Shared * shared, EC_KEY * picoEphemeralPublicKey);
DLL_PUBLIC EC_KEY * shared_get_pico_ephemeral_public_key(Shared const * shared);
DLL_PUBLIC EC_KEY * shared_get_service_identity_public_key(Shared const * shared);
DLL_PUBLIC EC_KEY * shared_get_service_ephemeral_public_key(Shared const * shared);

DLL_PUBLIC Buffer * shared_get_prover_enc_key(Shared const * shared);
DLL_PUBLIC Buffer * shared_get_verifier_enc_key(Shared const * shared);
DLL_PUBLIC Buffer * shared_get_prover_mac_key(Shared const * shared);
DLL_PUBLIC Buffer * shared_get_verifier_mac_key(Shared const * shared);
DLL_PUBLIC Buffer * shared_get_shared_key(Shared const * shared);

DLL_PUBLIC Feedback const * shared_set_feedback_trigger(Shared const * shared, FeedbackTrigger trigger, void * data);
bool shared_next_stage(Shared const * shared, char const * const description);
void shared_feedback_reset(Shared const * shared, int stages);
Feedback * shared_get_feedback(Shared const * shared);

DLL_PUBLIC char shared_get_status(Shared const * shared);
void shared_set_status(Shared * shared, char status);

// Function definitions

#endif

/** @} addtogroup Protocol */
