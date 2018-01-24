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
 * @brief Generate shared secrets from ECDH keys
 * @section DESCRIPTION
 *
 * The SharedSigmaKeyDerivclass takes a ECDH-generates shared secret and uses
 * it to generate a bundle more shared secrets for use in other parts of the
 * Sigma-I protocol (for the ECDH generation approach, see the KeyAgreement
 * class).
 *
 * The approach is based on the key derivation protocol used in Internet Key 
 * Exchange (IKE), as specified in RFC 4306 and NIST SP 800-135
 * http://tools.ietf.org/search/rfc4306#section-2.13
 * csrc.nist.gov/publications/nistpubs/800-135-rev1/sp800-135-rev1.pdf‎
 * 
 * In the randomness extraction step, the key derivation key is derived by 
 * taking the SHA256 HMAC of the shared secret obtained using a prior
 * public-key-based key agreement procedure, where the key to the HMAC is
 * $N_P || N_S$ where $N_P$ is the nonce sent by the Pico and $N_S$ is the 
 * nonce sent by the service.
 * 
 * In the key expansion step, each block of key material is derived using a 
 * SHA256 HMAC. The key to the HMAC is the key deriving key, and the message 
 * for block $k$, $B_k$$, is $B_{k - 1} || k || N_P || N_S$, except for the 
 * first block, where the previous block component is ommitted.
 * 
 */

/** \addtogroup Crypto
 *  @{
 */

#ifndef __SIGMAKEYDERIV_H
#define __SIGMAKEYDERIV_H (1)

#include "pico/nonce.h"
#include "pico/buffer.h"
#include "pico/dllpublic.h"

// Defines

// Structure definitions

/**
 * The internal structure can be found in sigmakeyderiv.c
 */
typedef struct _SigmaKeyDeriv SigmaKeyDeriv;

// Function prototypes

DLL_PUBLIC SigmaKeyDeriv * sigmakeyderiv_new();
DLL_PUBLIC void sigmakeyderiv_delete(SigmaKeyDeriv * sigmakeyderiv);
DLL_PUBLIC void sigmakeyderiv_set(SigmaKeyDeriv * sigmakeyderiv, Buffer * sharedSecret, Nonce * picoNonce, Nonce * serviceNonce);
DLL_PUBLIC void sigmakeyderiv_get_next_key(SigmaKeyDeriv * sigmakeyderiv, Buffer * keyBytes, int length);

// Function definitions

#endif

/** @} addtogroup Crypto */

