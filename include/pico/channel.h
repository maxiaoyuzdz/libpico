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

#ifndef __CHANNEL_H
#define __CHANNEL_H (1)

#include <time.h>
#include "pico/buffer.h"
#include "pico/dllpublic.h"

// Defines

// Structure definitions

/**
 * The internal structure can be found in channel.c
 */
typedef struct _RVPChannel RVPChannel;

// See buffer.h for more details.
typedef struct _Buffer Buffer;

typedef bool (*ChannelDelete)(RVPChannel * channel);
typedef bool (*ChannelOpen)(RVPChannel * channel);
typedef bool (*ChannelClose)(RVPChannel * channel);
typedef bool (*ChannelWrite)(RVPChannel * channel, char * data, int length);
typedef bool (*ChannelRead)(RVPChannel * channel, Buffer * buffer);
typedef void (*ChannelGetUrl)(RVPChannel * channel, Buffer * buffer);
typedef bool (*ChannelSetUrl)(RVPChannel * channel, char const * url);
typedef bool (*ChannelSocketNeeded)(RVPChannel * channel, int socket);
typedef void (*ChannelSetTimeout)(RVPChannel * channel, int timeout);

// Function prototypes

DLL_PUBLIC RVPChannel * channel_connect(const char * name);
DLL_PUBLIC RVPChannel * channel_new();
DLL_PUBLIC void channel_delete(RVPChannel * channel);

DLL_PUBLIC void channel_set_data(RVPChannel * channel, void * data);
DLL_PUBLIC void * channel_get_data(RVPChannel * channel);

DLL_PUBLIC void channel_set_functions(RVPChannel * channel, ChannelDelete del, ChannelOpen open, ChannelClose close, ChannelWrite write, ChannelRead read, ChannelGetUrl get_url, ChannelSetUrl set_url, ChannelSetTimeout set_timeout);

DLL_PUBLIC void channel_set_socket_needed_functions(RVPChannel * channel, ChannelSocketNeeded socket_needed);

DLL_PUBLIC bool channel_open(RVPChannel * channel);
DLL_PUBLIC bool channel_close(RVPChannel * channel);
DLL_PUBLIC bool channel_read(RVPChannel * channel, Buffer * buffer);
DLL_PUBLIC bool channel_write(RVPChannel * channel, char * data, int length);
DLL_PUBLIC bool channel_write_buffer(RVPChannel * channel, Buffer * buffer);
DLL_PUBLIC char const * channel_get_name(RVPChannel * channel);
DLL_PUBLIC void channel_set_name(RVPChannel * channel, char const * name);
DLL_PUBLIC void channel_get_url(RVPChannel * channel, Buffer * buffer);
DLL_PUBLIC bool channel_set_url(RVPChannel * channel, char const * url);
DLL_PUBLIC double channel_get_timeout(RVPChannel * channel);
DLL_PUBLIC void channel_set_timeout(RVPChannel * channel, int timeout);
DLL_PUBLIC bool channel_socket_needed(RVPChannel * channel, int socket);

// Function definitions

#endif

/** @} addtogroup Communication */

