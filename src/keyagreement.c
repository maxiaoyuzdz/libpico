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
 * (prover's) ephemeral public key and the service's (verifier's) ephemeral
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

#include <stdio.h>
//#include <malloc.h>
#include "pico/debug.h"
#include "pico/log.h"
#include "pico/keyagreement.h"

// Defines

// Structure definitions

// Function prototypes

// Function definitions

/**
 * Generate a shared secret from the combination of the server's private ECDH
 * key and the Pico's public ECDH key.
 *
 * @param vEphemPriv Verfiyer's (server's) ephemeral private ECDH key
 * @param pEphemPub Prover's (Pico's) ephemeral public ECDH key
 * @param sharedSecretOut Buffer to store the resulting generated shared secret
 */
void keyagreement_generate_secret(EVP_PKEY * vEphemPriv, EC_KEY * pEphemPub, Buffer * sharedSecretOut) {
	EVP_PKEY_CTX * ctx;
	EVP_PKEY * evpkey;
	size_t sharedSecretLength;

	ctx = EVP_PKEY_CTX_new(vEphemPriv, NULL);
	EVP_PKEY_derive_init(ctx);

	evpkey = EVP_PKEY_new();
	EVP_PKEY_assign_EC_KEY(evpkey, pEphemPub);

	EVP_PKEY_derive_set_peer(ctx, evpkey);

	EVP_PKEY_derive(ctx, NULL, & sharedSecretLength);
	buffer_set_min_size(sharedSecretOut, sharedSecretLength);

	EVP_PKEY_derive(ctx, (unsigned char *)buffer_get_buffer(sharedSecretOut), & sharedSecretLength);
	buffer_set_pos(sharedSecretOut, sharedSecretLength);

	EVP_PKEY_CTX_free(ctx);
}

/** @} addtogroup Crypto */

