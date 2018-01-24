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
 * @brief Manage ECDH public/private key pairs
 * @section DESCRIPTION
 *
 * The KeyPair class is a wrapper for OpenSSL Diffie Hellman Elliptic Curve
 * public/private key pairs for use by libpam. It also provides various
 * utilities for importing from and exporting to file.
 *
 */

/** \addtogroup Crypto
 *  @{
 */

#ifndef __KEYPAIR_H
#define __KEYPAIR_H (1)

#include <stdbool.h>
#include <openssl/ec.h>
#include "pico/buffer.h"
#include "pico/dllpublic.h"

// Defines

// Structure definitions

/**
 * The internal structure can be found in keypair.c
 */
typedef struct _KeyPair KeyPair;

// Function prototypes

DLL_PUBLIC KeyPair * keypair_new();
DLL_PUBLIC void keypair_delete(KeyPair * keypair);
DLL_PUBLIC bool keypair_generate(KeyPair * keypair);
DLL_PUBLIC void keypair_export(KeyPair * keypair, char const * key_public, char const * key_private);
DLL_PUBLIC bool keypair_import(KeyPair * keypair, char const * key_public, char const * key_private);
DLL_PUBLIC void keypair_clear_keys(KeyPair * keypair);

DLL_PUBLIC void keypair_getpublicpem(KeyPair * keypair, Buffer * buffer);
DLL_PUBLIC void keypair_getpublicder(KeyPair * keypair, Buffer * buffer);

DLL_PUBLIC EC_KEY * keypair_getpublickey(KeyPair * keypair);
void keypair_setpublickey(KeyPair * keypair, EC_KEY * eckey);
DLL_PUBLIC EVP_PKEY * keypair_getprivatekey(KeyPair * keypair);
void keypair_setprivatekey(KeyPair * keypair, EVP_PKEY * pkey);

DLL_PUBLIC void keypair_sign_data(KeyPair * keypair, Buffer const * bufferin, Buffer * bufferout);

// Function definitions

#endif

/** @} addtogroup Crypto */

