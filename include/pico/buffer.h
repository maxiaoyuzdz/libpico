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
 * @brief Dynamically-sized and bounds-safe binary buffer
 * @section DESCRIPTION
 *
 * The buffer class provides a generic dynamically-defined buffer for
 * storing sequences of bytes. As data is appended to the buffer memory
 * will be allocated automatically in blocks. The block size can be set
 * when the buffer is first created.
 *
 * Buffers have a length and and are also guaranteed to be zero-byte
 * terminated. The zero-byte is not included in the length (but the
 * underlying buffer size, which is often different from the size of the
 * contents, will always be large enough to contain it). The contents can
 * itself contain zero bytes, or indeed anything else.
 *
 */

/** \addtogroup Datahandling
 *  @{
 */

#ifndef __BUFFER_H
#define __BUFFER_H (1)

#include <stdio.h>
//#include <malloc.h>
#include <stdlib.h>
#include <stdbool.h>
//#include "pico/channel.h"
#include "pico/dllpublic.h"

// Defines

// Structure definitions

/**
 * The internal structure can be found in buffer.c
 */
typedef struct _Buffer Buffer;

// Function prototypes

DLL_PUBLIC Buffer * buffer_new(size_t block_size);
DLL_PUBLIC void buffer_delete(Buffer * buffer);

DLL_PUBLIC size_t buffer_append(Buffer * buffer, void const * data, size_t size);
DLL_PUBLIC size_t buffer_append_string(Buffer * buffer, char const * data);
DLL_PUBLIC size_t buffer_append_buffer(Buffer * buffer, Buffer const * appendFrom);
DLL_PUBLIC size_t buffer_append_buffer_lengthprepend(Buffer * buffer, Buffer const * appendFrom);
DLL_PUBLIC size_t buffer_append_lengthprepend(Buffer * buffer, void const * data, size_t size);
DLL_PUBLIC size_t buffer_copy_lengthprepend(Buffer * bufferin, size_t start, Buffer * bufferout);
DLL_PUBLIC void buffer_truncate(Buffer * buffer, size_t reduce_by);
DLL_PUBLIC size_t buffer_sprintf(Buffer * buffer, char const * format, ...);
DLL_PUBLIC void buffer_print(Buffer const * buffer);
DLL_PUBLIC void buffer_print_base64(Buffer * buffer);
DLL_PUBLIC void buffer_log(Buffer * buffer);
DLL_PUBLIC void buffer_log_base64(Buffer * buffer);
DLL_PUBLIC void buffer_clear(Buffer * buffer);
DLL_PUBLIC size_t buffer_copy_to_string(Buffer const * buffer, char * string, size_t max_length);
DLL_PUBLIC char * buffer_copy_to_new_string(Buffer const * buffer);
DLL_PUBLIC size_t buffer_get_pos(Buffer const * buffer);
DLL_PUBLIC char * buffer_get_buffer(Buffer const * buffer);
DLL_PUBLIC void buffer_set_min_size(Buffer * buffer, size_t size);
DLL_PUBLIC size_t buffer_get_size(Buffer const * buffer);
DLL_PUBLIC void buffer_set_pos(Buffer * buffer, size_t pos);
DLL_PUBLIC bool buffer_equals(Buffer const * buffer, Buffer const * compare);

// Function definitions

#endif

/** @} addtogroup Datahandling */

