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
 * @brief Manage the generation and use of nonces (numbers used once)
 * @section DESCRIPTION
 *
 * The Nonce class is used for managing nonces. It supports assignment (e.g. 
 * where a nonce is sent from the Pico to the server) and ganeration using
 * OpenSSL's secure random number generator.
 *
 */

/** \addtogroup Crypto
 *  @{
 */

#ifndef __STUB_H
#define __STUB_H (1)

#include "pico/buffer.h"
#include "pico/dllpublic.h"

// Defines

#define NONCE_DEFAULT_BYTES (8)

// Structure definitions

/**
 * The internal structure can be found in nonce.c
 */
typedef struct _Nonce Nonce;

// Function prototypes

DLL_PUBLIC Nonce * nonce_new();
DLL_PUBLIC void nonce_delete(Nonce * nonce);
DLL_PUBLIC void nonce_set_buffer(Nonce * nonce, Buffer * value);
DLL_PUBLIC void nonce_generate_random(Nonce * nonce);
DLL_PUBLIC unsigned char const * nonce_get_buffer(Nonce * nonce);
DLL_PUBLIC size_t nonce_get_length(Nonce * nonce);

// Function definitions

#endif

/** @} addtogroup Crypto */

