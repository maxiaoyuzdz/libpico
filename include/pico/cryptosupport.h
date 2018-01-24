/** \ingroup Utility
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
 * @brief Cryptographic utilities
 * @section DESCRIPTION
 *
 * The cryptosupport functions offer various wrappers around the OpenSSL
 * functionality to simplify its operation. Encryption, decryption, signatures,
 * and macs are supported, as well as functionality for encoding and decoding
 * keys in various formats.
 *
 */

/** \addtogroup Utility
 *  @{
 */

#ifndef __CRYPTOSUPPORT_H
#define __CRYPTOSUPPORT_H (1)

#include <openssl/ec.h>
#include "pico/buffer.h"
#include "pico/dllpublic.h"

// Defines

#define CRYPTOSUPPORT_IV_SIZE (16)
#define CRYPTOSUPPORT_AESKEY_SIZE (16)

// Set the length of the eliptic curve p value in bits
// See the following http://www.flypig.co.uk/?page=list&list_id=535&list=blog
// Should be either 192 or 256
#define CRYPTOSUPPORT_ECCURVE_SIZE (256)

#if CRYPTOSUPPORT_ECCURVE_SIZE == 192
#define CRYPTOSUPPORT_ECCURVE NID_X9_62_prime192v1
#else
#define CRYPTOSUPPORT_ECCURVE NID_X9_62_prime256v1
#endif

// Structure definitions

// Function prototypes

// Function definitions

DLL_PUBLIC bool cryptosupport_getpublicpem(EC_KEY * eckey, Buffer * buffer);
DLL_PUBLIC bool cryptosupport_getpublicder(EC_KEY * eckey, Buffer * buffer);
DLL_PUBLIC bool cryptosupport_getprivatepem(EVP_PKEY * pkey, Buffer * buffer);
DLL_PUBLIC bool cryptosupport_getprivateder(EVP_PKEY * pkey, Buffer * buffer);
DLL_PUBLIC bool cryptosupport_generate_mac(Buffer * macKey, Buffer * data, Buffer * bufferout);
DLL_PUBLIC bool cryptosupport_verify_signature(EC_KEY const * publickey, Buffer const * bufferin, Buffer * sigin);
DLL_PUBLIC bool cryptosupport_encrypt(Buffer const * key, Buffer const * iv, Buffer const * bufferin, Buffer * encryptedout);
DLL_PUBLIC bool cryptosupport_decrypt(Buffer const * key, Buffer const * iv, Buffer const * bufferin, Buffer * cleartextout);
DLL_PUBLIC bool cryptosupport_encrypt_iv_base64(Buffer const * key, Buffer const * bufferin, Buffer * encryptedout);
DLL_PUBLIC bool cryptosupport_decrypt_iv_base64(Buffer const * key, Buffer const * bufferin, Buffer * cleartextout);
DLL_PUBLIC bool cryptosupport_generate_symmetric_key(Buffer * key, unsigned int size);
DLL_PUBLIC void cryptosupport_generate_iv(Buffer * iv);
DLL_PUBLIC bool cryptosupport_generate_sha256(Buffer * bufferin, Buffer * bufferout);
DLL_PUBLIC bool cryptosupport_generate_commitment(EC_KEY * publickey, Buffer * commitment);
DLL_PUBLIC bool cryptosupport_generate_commitment_base64(EC_KEY * publickey, Buffer * commitment);

DLL_PUBLIC EC_KEY * cryptosupport_read_base64_buffer_public_key(Buffer * keybuffer);
DLL_PUBLIC EC_KEY * cryptosupport_read_base64_string_public_key(char const * keystring);
DLL_PUBLIC EC_KEY * cryptosupport_read_buffer_public_key(Buffer * keybuffer);

DLL_PUBLIC EVP_PKEY * cryptosupport_read_base64_buffer_private_key(Buffer * keybuffer);
DLL_PUBLIC EVP_PKEY * cryptosupport_read_base64_string_private_key(char const * keystring);
DLL_PUBLIC EVP_PKEY * cryptosupport_read_buffer_private_key(Buffer * keybuffer);


#endif

/** @} addtogroup Utility */

