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
 * @brief Generate, store and manage large sequence numbers
 * @section DESCRIPTION
 *
 * Provides methods for handling 32-byte sequence numbers. Sequence numbers
 * can be stored, set and manipulated (e.g. incremented).
 *
 */

/** \addtogroup Crypto
 *  @{
 */

#ifndef __SEQUENCENUMBER_H
#define __SEQUENCENUMBER_H (1)

#include "pico/buffer.h"

// Defines

#define SEQUENCE_NUMBER_LENGTH (32)

// Structure definitions

/**
 * The internal structure can be found in sequencenumber.c
 */
typedef struct _SequenceNumber SequenceNumber;

// Function prototypes

SequenceNumber * sequencenumber_new();
void sequencenumber_delete(SequenceNumber * sequencenumber);

void sequencenumber_random(SequenceNumber * sequencenumber);
bool sequencenumber_equals(SequenceNumber * sequencenumber, SequenceNumber * sequencenumber2);
void sequencenumber_increment(SequenceNumber * sequencenumber);
void sequencenumber_print(SequenceNumber const * sequencenumber);
void sequencenumber_log(SequenceNumber const * sequencenumber);
void sequencenumber_copy(SequenceNumber * dest, SequenceNumber const * src);
bool sequencenumber_transfer_from_buffer(SequenceNumber * dest, Buffer const * src);
unsigned char const * sequencenumber_get_raw_bytes(SequenceNumber const * sequencenumber);

// Function definitions

#endif

/** @} addtogroup Crypto */

