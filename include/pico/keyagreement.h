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
 * @brief Generate a shared secret using ephemeral ECDH keys
 * @section DESCRIPTION
 *
 * The keyagreement function generates a shared secret from the Pico's
 * (prover's) ephemerail public key and the service's (verifier's) ephemeral
 * private key. The shared secret is used to generate further shared secrets
 * that are then used for various purposes (encryption, mac, signing) as part
 * of the Sigma-I protocol.
 *
 * See the SigmaKeyDeriv class for details of the shared secret generation
 * process.
 *
 */

/** \addtogroup Crypto
 *  @{
 */

#ifndef __KEYAGREEMENT_H
#define __KEYAGREEMENT_H (1)

#include <openssl/evp.h>
#include "pico/buffer.h"
#include "pico/keypair.h"
#include "pico/dllpublic.h"

// Defines

// Structure definitions

//typedef struct _KeyAgreement KeyAgreement;

// Function prototypes

DLL_PUBLIC void keyagreement_generate_secret(EVP_PKEY * vEphemPriv, EC_KEY * pEphemPub, Buffer * sharedSecretOut);

// Function definitions

#endif

/** @} addtogroup Crypto */

