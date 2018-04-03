/**
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
 * @section DESCRIPTION
 *
 * The channel class provides support for creating and using channels via
 * the Pico Rendezvous Point.
 * This header allows the standard HTTP-based Rendezvous Point channel to
 * be replaced by a Bluetooth channel that waits for incoming connections.
 *
 */

#ifndef __CHANNEL_BT_OUT_H
#define __CHANNEL_BT__OUTH (1)

#if HAVE_CONFIG_H
#include "pico/config.h"
#endif

#include "pico/channel.h"

#ifdef HAVE_LIBPICOBT // Only build if Bluetooth is present

#include "pico/buffer.h"
#include "pico/dllpublic.h"

// Defines

// Structure definitions

// Function prototypes

DLL_PUBLIC bool channel_set_btout_with_address(RVPChannel * channel, char const * address, unsigned char port);
DLL_PUBLIC bool channel_decode_url_btout(char const * url, Buffer * address, unsigned int * port);

// Function definitions

#endif // HAVE_LIBPICOBT // Only build if Bluetooth is present

#endif

