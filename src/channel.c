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

#include <stdio.h>
////#include <malloc.h>
#include <string.h>
#include <curl/curl.h>
#include <openssl/rand.h>
#include "pico/debug.h"
#include "pico/buffer.h"
#include "pico/curlsupport.h"
#include "pico/rvpbuffer.h"
#include "pico/log.h"
#include "pico/channel_rvp.h"
#include "pico/channel.h"

#if !defined(WINDOWS) && (defined(WIN32) || defined(_WIN32) || defined(__WIN32) && !defined(__CYGWIN__))
#define WINDOWS
#endif

// Defines

#define CHANNEL_TIMEOUT (39000)

// Structure definitions

/**
 * @brief Structure for communicating via a rendezvous-channel
 * 
 * Opaque structure containing the private fields of the RVPChannel class.
 *
 * This is provided as the first parameter of every non-static function and 
 * stores the operation's context.
 *
 * The RVPChannel class is used for communicating via a rendezvous-channel,
 * but its functionality can be overriden to also allow communication on
 * other channels such as Bluetooth.
 *
 * The structure typedef is in channel.h
 */
struct _RVPChannel {
	char * name;
	int timeout;

	void * data;

	ChannelDelete del;
	ChannelOpen open;
	ChannelClose close;
	ChannelWrite write;
	ChannelRead read;
	ChannelGetUrl get_url;
	ChannelSetUrl set_url;
	ChannelSocketNeeded socket_needed;
	ChannelSetTimeout set_timeout;
};

// Function prototypes

// Function definitions

/**
 * Create a new instance of the class and connect to the named channel. To
 * create a new channel, use channel_new() instead.
 *
 * @param name Name of the Rendezvous Point channel to connect to.
 * @return The newly created object.
 */
RVPChannel * channel_connect(const char * name) {
	RVPChannel * channel;
	int nameLen;

	channel = CALLOC(sizeof(RVPChannel), 1);
	channel->timeout = CHANNEL_TIMEOUT;

	channel_set_rvp(channel);

	nameLen = strlen(name);
	channel->name = CALLOC(sizeof(char), nameLen + 1);
	strncpy(channel->name, name, nameLen);
	channel->name[nameLen] = '\0';

	return channel;
}

/**
 * Create a new instance of the class, which will also open a new channel with
 * the Rendezvous Point. Use channel_connect() if you need to connect to an 
 * existing channel instead.
 *
 * @return Structure summarising the newly created channel
 */
RVPChannel * channel_new() {
	RVPChannel * channel;

	channel = CALLOC(sizeof(RVPChannel), 1);

	channel->timeout = CHANNEL_TIMEOUT;
	channel->name = NULL;

	channel->del = NULL;
	channel->open = NULL;
	channel->close = NULL;
	channel->write = NULL;
	channel->read = NULL;
	channel->get_url = NULL;
	channel->set_url = NULL;
	channel->socket_needed = NULL;
	channel->set_timeout = NULL;

	channel->data = NULL;

	channel_set_rvp(channel);

	return channel;
}

/**
 * Delete an instance of the class, freeing up the memory allocated to it.
 *
 * @param channel The object to free.
 */
void channel_delete(RVPChannel * channel) {
	if (channel) {
		if (channel->del) {
			channel->del(channel);
		}

		if (channel->name) {
			FREE (channel->name);
		}
		FREE (channel);
	}
}

/**
 * Set the timeout duration for the channel, measured in milliseconds.
 *
 * @param channel The channel to set the timeout duration on.
 * @param timeout The timeout duration in milliseconds.
 */
void channel_set_timeout(RVPChannel * channel, int timeout) {
	if (channel) {
		if (channel->set_timeout) {
			channel->set_timeout(channel, timeout);
		}

		channel->timeout = timeout;
	}
}

/**
 * Get the timeout duration for the channel, measured in milliseconds.
 *
 * @param channel The channel to get the timeout duration for.
 * @return The timeout duration in milliseconds.
 */
double channel_get_timeout(RVPChannel * channel) {
	double ret = 0.0;

	if (channel) {
		ret = channel->timeout;
	}

	return ret;
}

/**
 * Configure the channels virtual functions. Theses should be set to overload
 * the behaviour of the channel (e.g. switching from a Rendezvous Point
 * connection to a Bluetooth connection).
 *
 * @param channel The channel to set the virtual functions on.
 * @param del Virtual function called when the channel is deleted.
 * @param open Virtual function to overload channel_open().
 * @param close Virtual function to overlaod channel_close().
 * @param write Virtual function to overload channel_write().
 * @param read Virtual function to overload channel_read().
 * @param get_url Virtual function to overload channel_get_url().
 * @param set_url Virtual function to overload channel_set_url().
 * @param set_timeout Virtual function to overload channel_set_timeout().
 */
void channel_set_functions(RVPChannel * channel, ChannelDelete del, ChannelOpen open, ChannelClose close, ChannelWrite write, ChannelRead read, ChannelGetUrl get_url, ChannelSetUrl set_url, ChannelSetTimeout set_timeout) {
	if (channel) {
		channel->del = del;
		channel->open = open;
		channel->close = close;
		channel->write = write;
		channel->read = read;
		channel->get_url = get_url;
		channel->set_url = set_url;
		channel->set_timeout = set_timeout;
	}
}

/**
 * Configure the socket_needed overload function.
 *
 * @param channel The channel to set the virtual function on.
 * @param socket_needed Virtual function to overload channel_socket_needed()
 */
void channel_set_socket_needed_functions(RVPChannel * channel, ChannelSocketNeeded socket_needed) {
	if (channel) {
		channel->socket_needed = socket_needed;
	}
}

/**
 * Set the data object to be stored in the channel for use by overloaded
 * functions.
 *
 * If there's already data set on the channel, the overridden delete
 * channel function will be called on the existing data first, before the
 * pointer to the data object is reassisgned.
 *
 * @param channel The channel to set the data object for.
 * @param data The data object to be passed to overloaded functions. This
 *        should be re-cast to the appropriate type inside the functions.
 *        This can be NULL (but must be handled by the overloaded functions).
 */
void channel_set_data(RVPChannel * channel, void * data) {
	if (channel) {
		if (channel->del) {
			channel->del(channel);
		}
		channel->data = data;
	}
}

/**
 * Get the data object stored in the channel for use by overloaded
 * functions.
 *
 * @param channel The channel to get the data object from.
 * @return The data object.
 */
void * channel_get_data(RVPChannel * channel) {
	void* ret = NULL;
	
	if (channel) {
		ret = channel->data;
	}

	return ret;
}

/**
 * Perform actions needed to open the channel.
 *
 * @param channel The channel to open
 * @return True if the channel was successfully opened; false otherwise
 */
bool channel_open(RVPChannel * channel) {
	bool result;

	result = false;
	if (channel) {
		if (channel->open) {
			result = channel->open(channel);
		}
		else {
			result = true;
		}
	}

	return result;
}

/**
 * Perform actions needed to close the channel.
 *
 * @param channel The channel to close
 * @return True if the channel was successfully closed; false otherwise
 */
bool channel_close(RVPChannel * channel) {
	bool result;

	result = false;
	if (channel) {
		if (channel->close) {
			result = channel->close(channel);
		}
		else {
			result = true;
		}
	}

	return result;
}

/**
 * Read data from a channel. The call will block until there is some data to
 * to read. The nature of Rendezvous Point channels is that they are discrete,
 * so all of the data sent to the channel will be read in one go, hence this
 * call will always either timeout, or return the full message.
 *
 * @param channel The Rendezvous Point channel to receive from
 * @param buffer The buffer to store the received data into
 * @return true if data was read successfully from the channel, false o/w. 
 *         Note that the Rendezvous Point will send its own message on timeout, 
 *         so a timeout will also return true (the message can be read to
 *         determine that a timeout occurred). 
 */
bool channel_read(RVPChannel * channel, Buffer * buffer) {
	bool result;

	result = false;
	if (channel) {
		if (channel->read) {
			result = channel->read(channel, buffer);
		}
		else {
			result = true;
		}
	}

	return result;
}

/**
 * Write data to a channel. The call will block until all of the data has been
 * written. Because Rendezvous Point channels are discrete, the receiver will
 * read all of the data before the next write can be made.
 *
 * @param channel The Rendezvous Point channel to send to
 * @param data The byte data to send
 * @param length The length of data to send
 * @return true if data was sent successfully to the channel, false o/w.
 */
bool channel_write(RVPChannel * channel, char * data, int length) {
	bool result;

	result = false;
	if (channel) {
		if (channel->write) {
			result = channel->write(channel, data, length);
		}
		else {
			result = true;
		}
	}

	return result;
}

/**
 * Return the full URL of the channel, including the hostname.
 *
 * @param channel The channel to get the URL of
 * @return The URL of the channel
 */
void channel_get_url(RVPChannel * channel, Buffer * buffer) {
	if (channel && channel->get_url) {
		channel->get_url(channel, buffer);
	}
}

/**
 * Set the full URL of the channel, including the transport.
 *
 * The URL must be valid. For example, a Rendevous Point channel must
 * start with HTTP:// or HTTPS://, whereas a Bluetoothchannel must start
 * with btspp://.
 *
 * @param channel The channel to set the URL for
 * @param url The fully qualified URL.
 * @return true if the URL is valid for the type of channel, false o/w.
 */
bool channel_set_url(RVPChannel * channel, char const * url) {
	bool result;

	result = false;
	if (channel) {
		if (channel->set_url) {
			result = channel->set_url(channel, url);
		}
		else {
			result = true;
		}
	}
	
	return result;
}

/**
 * Write data to a channel. The call will block until all of the data has been
 * written. Because Rendezvous Point channels are discrete, the receiver will
 * read all of the data before the next write can be made.
 *
 * @param channel The Rendezvous Point channel to send to
 * @param buffer The buffer containing the data to send
 * @return true if data was sent successfully to the channel, false o/w. 
 */
bool channel_write_buffer(RVPChannel * channel, Buffer * buffer) {
	Buffer * prefixed;
	char * data;
	size_t length;
	bool result;

	length = buffer_get_pos(buffer);
	prefixed = buffer_new(length + 4);
	data = buffer_get_buffer(prefixed);
	data[0] = ((length >> 24) & 0xff);
	data[1] = ((length >> 16) & 0xff);
	data[2] = ((length >> 8) & 0xff);
	data[3] = ((length >> 0) & 0xff);
	buffer_set_pos(prefixed, 4);
	buffer_append_buffer(prefixed, buffer);
	length += 4;

	result = channel_write(channel, data, length);
	
	return result;
}

/**
 * Return the name of the channel. This is the tail of the URL without the
 * hostname or channel prefix, so will likely be a random string generated
 * by the server to represent this channel.
 *
 * @param channel The channel to get the name of
 * @return The name of the channel
 */
char const * channel_get_name(RVPChannel * channel) {
	return channel->name;
}

/**
 * Set the name of the channel.
 *
 * @param channel The channel to set the name of.
 * @param name The name of the channel.
 */
void channel_set_name(RVPChannel * channel, char const * name) {
	int nameLen;

	nameLen = strlen(name);
	channel->name = REALLOC(channel->name, nameLen + 1);
	strncpy(channel->name, name, nameLen);
	channel->name[nameLen] = '\0';
}

/**
 * Establish whether a particular socket is currently needed for the operation
 * of the channel. This is useful during the daemonize process, where all
 * sockets would otherwise be closed. This allows certain sockets to be kept
 * open.
 *
 * @param channel The channel to check the needed sockets for.
 * @param socket The socket to check for.
 * @return true if the socket is needed, false o/w.
 */
bool channel_socket_needed(RVPChannel * channel, int socket) {
	bool result;

	result = false;
	if (channel->socket_needed) {
		result = channel->socket_needed(channel, socket);
	}

	return result;
}

/** @} addtogroup Communication */

