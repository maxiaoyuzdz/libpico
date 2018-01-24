/** \ingroup Communication
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
 * @brief Buffer functionality used by curl for rendezvous point communication
 * @section DESCRIPTION
 *
 * The RVPBuffer class encapsulates the data needed to buffer incoming data
 * arriving from a curl Rendezvous Point channel. It's convenient to use it
 * as the context for the curl write callback. At the end of the curl
 * operation the data received can be found in the buffer specified when the
 * RVPBuffer was created.
 *
 * Note that deleting the RVPBuffer does not delete the Buffer specified at
 * creation of the RVPBuffer (containing the received data), and so this
 * must be deleted separately when it's no longer needed.
 *
 */

/** \addtogroup Communication
 *  @{
 */

#ifndef __RVPBUFFER_H
#define __RVPBUFFER_H (1)

// Defines

// Structure definitions

/**
 * The internal structure can be found in rvpbuffer.c
 */
typedef struct _RVPBuffer RVPBuffer;

// Function prototypes

RVPBuffer * rvpbuffer_new(Buffer * buffer);
void rvpbuffer_delete(RVPBuffer * rvpbuffer);
size_t rvpbuffer_write(void * ptr, size_t size, size_t nmemb, void * userp);

// Function definitions

#endif

/** @} addtogroup Communication */

