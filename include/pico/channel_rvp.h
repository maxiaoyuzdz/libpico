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
 * @brief Communication channel support
 * @section DESCRIPTION
 *
 * The channel class provides support for creating and using channels via
 * the Pico Rendezvous Point. It uses curl (HTTP) as the underlying means of
 * interacting with the Rendezvous Point.
 *
 */

/** \addtogroup Communication
 *  @{
 */

#ifndef __CHANNEL_RVP_H
#define __CHANNEL_RVP_H (1)

#include "pico/buffer.h"
#include "pico/dllpublic.h"

// Defines

// Structure definitions

/**
 * The internal structure can be found in channel.c
 */

// See buffer.h for more details.

// Function prototypes

DLL_PUBLIC bool channel_set_rvp(RVPChannel * channel);
DLL_PUBLIC bool channel_decode_url_rvp(char const * url, Buffer * address, Buffer * channel);

// Function definitions

#endif

/** @} addtogroup Communication */

