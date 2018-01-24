/** \ingroup Datahandling
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
 * @brief Base64 encoding and decodiing utility functions
 * @section DESCRIPTION
 *
 * The base64 interface provides methods for base64 encoding and decoding
 * strings and buffers.
 *
 */

/** \addtogroup Datahandling
 *  @{
 */

#ifndef __BASE64_H
#define __BASE64_H (1)

#include "pico/buffer.h"
#include "pico/dllpublic.h"

// Defines

// Structure definitions

// Function prototypes

DLL_PUBLIC void base64_encode_buffer(Buffer const * bufferin, Buffer * bufferout);
DLL_PUBLIC void base64_encode_string(char const * stringin, Buffer * bufferout);
DLL_PUBLIC void base64_encode_mem(char const * memin, size_t length, Buffer * bufferout);
DLL_PUBLIC size_t base64_encode_size_max(size_t input);

DLL_PUBLIC void base64_decode_buffer(Buffer const * bufferin, Buffer * bufferout);
DLL_PUBLIC void base64_decode_string(char const * stringin, Buffer * bufferout);
DLL_PUBLIC void base64_decode_mem(char const * memin, size_t length, Buffer * bufferout);
DLL_PUBLIC size_t base64_decode_size_max(size_t input);

// Function definitions

#endif

/** @} addtogroup Datahandling */

