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

#include <stdio.h>
#include <malloc.h>
#include <string.h>
#include <time.h>
#include <curl/curl.h>
#include <openssl/rand.h>
#include "pico/debug.h"
#include "pico/buffer.h"
#include "pico/curlsupport.h"
#include "pico/rvpbuffer.h"
#include "pico/log.h"
#include "pico/channel.h"
#include "pico/channel_rvp.h"

#if !defined(WINDOWS) && (defined(WIN32) || defined(_WIN32) || defined(__WIN32) && !defined(__CYGWIN__))
#define WINDOWS
#endif

// Defines

#define RVP_URL	"http://rendezvous.mypico.org"
#define CHANNEL "/channel"
#define CHANNEL_NAME_BYTES 16
#define HTTP_PREFIX "http://"
#define HTTPS_PREFIX "https://"

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
struct _RVPChannelData {
	Buffer * server;
	time_t time_started;
};

typedef struct _RVPChannelData RVPChannelData;

// Function prototypes

bool channel_delete_rvp(RVPChannel * channel);
bool channel_read_rvp(RVPChannel * channel, Buffer * buffer);
bool channel_write_rvp(RVPChannel * channel, char * data, int length);
void channel_get_url_rvp(RVPChannel * channel, Buffer * buffer);
bool channel_set_url_rvp(RVPChannel * channel, char const * url);
void channel_set_name_random_rvp(RVPChannel * channel);
int channel_xferinfofunction_rvp (void * clientp, curl_off_t dlnow, curl_off_t ultotal, curl_off_t ulnow);
static char const * channel_find_slash_rvp(char const * start, char const * end);
static void channel_reset_timeout_rvp(RVPChannel * channel);
static time_t channel_get_time_started_rvp(RVPChannel * channel);

// Function definitions

/**
 * Set a channel to use Bluetooth.
 * This overloads the required functions, sets the Bluetooth data object
 * and initialises the Bluetooth listening channel.
 *
 * In case of failure, the channel is unusable and has to be set again
 *
 * @param channel The channel to set to Bluetooth.
 * @return true if the Bluetooth was set up successfully, false o/w
 */
bool channel_set_rvp(RVPChannel * channel) {
	RVPChannelData * data;

	data = CALLOC(sizeof(RVPChannelData), 1);

	data->server = buffer_new(0);
	buffer_append_string(data->server, RVP_URL);
	data->time_started = time(NULL);

	// Set the Bluetooth context data
	channel_set_data(channel, data);

	channel_set_name_random_rvp(channel);

	// Set the overloaded virtual functions
	channel_set_functions(channel, channel_delete_rvp, NULL, NULL, channel_write_rvp, channel_read_rvp, channel_get_url_rvp, channel_set_url_rvp, NULL);
	channel_set_socket_needed_functions(channel, NULL);

	return true;
}

/**
 * Perform actions needed to delete the Bluetooth channel.
 * This is called in addition to the standard behaviour of channel_delete().
 *
 * @param channel The channel to delete.
 * @return True if the channel was successfully deleted; false otherwise
 */
bool channel_delete_rvp(RVPChannel * channel) {
	RVPChannelData * rvpchannel = (RVPChannelData *)channel_get_data(channel);

	if (rvpchannel) {
		// Clear the data pointer
		buffer_delete(rvpchannel->server);

		FREE(rvpchannel);
	}

	return true;
}

/**
 * Assign a random name to the channel. This will be a hexadecinal string of
 * (2 * CHANNEL_NAME_BYTES) charachetrs (32 characters by default).
 *
 * @param channel The channel set a random name for.
 */
void channel_set_name_random_rvp(RVPChannel * channel) {
	int res;
	int i;
	unsigned char random_bytes[CHANNEL_NAME_BYTES];
	char * name;

	res = RAND_bytes(random_bytes, CHANNEL_NAME_BYTES); 

	if (res) {
		name = CALLOC(sizeof(char), CHANNEL_NAME_BYTES * 2 + 1);
		for (i = 0; i < CHANNEL_NAME_BYTES; i++) {
			sprintf(name + i * 2, "%02x", random_bytes[i]);
		}
		
		channel_set_name(channel, name);
		FREE(name);
	}
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
bool channel_read_rvp(RVPChannel * channel, Buffer * buffer) {
	CURL * curl;
	CURLcode res;
	RVPBuffer * rvpbuffer;
	bool result;
	Buffer * url;

	result = true;
	curl = curl_easy_init();

	if (curl) {
		url = buffer_new(0);
		channel_get_url_rvp(channel, url);
		curl_easy_setopt(curl, CURLOPT_URL, buffer_get_buffer(url));
		buffer_delete(url);

		rvpbuffer = rvpbuffer_new(buffer);
		///curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "name=daniel&project=curl");
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, rvpbuffer_write);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)rvpbuffer);

		//curl_easy_setopt(curl, CURLOPT_TIMEOUT, 40);
		channel_reset_timeout_rvp(channel);
		curl_easy_setopt(curl, CURLOPT_XFERINFODATA, (void *)channel);
		curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, channel_xferinfofunction_rvp);
		curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0);

		res = curl_easy_perform(curl);
		if (res != CURLE_OK) {
			LOG(LOG_ERR, "Error reading from Rendezvous channel: %s\n", curl_easy_strerror(res));
			result = false;
		}
		rvpbuffer_delete(rvpbuffer);
		
		curl_easy_cleanup(curl);
	}
	else {
		result = false;
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
bool channel_write_rvp(RVPChannel * channel, char * data, int length) {
	CURL * curl;
	CURLcode res;
	bool result;
	Buffer * url;

	result = true;
	curl = curl_easy_init();

	if (curl) {
		url = buffer_new(0);
		channel_get_url_rvp(channel, url);
		curl_easy_setopt(curl, CURLOPT_URL, buffer_get_buffer(url));
		buffer_delete(url);

		//curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
		//curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)buffer);

		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, length);

		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, log_data);

		//curl_easy_setopt(curl, CURLOPT_TIMEOUT, 240);
		channel_reset_timeout_rvp(channel);
		curl_easy_setopt(curl, CURLOPT_XFERINFODATA, (void *)channel);
		curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, channel_xferinfofunction_rvp);
		curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0);

		res = curl_easy_perform(curl);
		if (res != CURLE_OK) {
			LOG(LOG_ERR, "Error writing to Rendezvous channel: %s\n", curl_easy_strerror(res));
			result = false;
		}
		
		curl_easy_cleanup(curl);
	}
	else {
		result = false;
	}
	
	return result;
}

/**
 * Return the full URL of the channel, including the hostname.
 *
 * @param channel The channel to get the URL of
 * @return The URL of the channel
 */
void channel_get_url_rvp(RVPChannel * channel, Buffer * buffer) {
	RVPChannelData * rvpchannel = (RVPChannelData *)channel_get_data(channel);
	char const * name;

	if ((channel) && (buffer)) {
		name = channel_get_name(channel);
		buffer_sprintf(buffer, "%s" CHANNEL "/%s", buffer_get_buffer(rvpchannel->server), name);
	}
}

/**
 * Set the full URL of the channel, including the transport.
 *
 * The URL must be valid. For example, since this function is used only
 * for Rendevous Point channels, it must start with HTTP:// or HTTPS://.
 *
 * @param channel The channel to set the URL for
 * @param url The fully qualified URL.
 * @return true if the URL is valid for the type of channel, false o/w.
 */
bool channel_set_url_rvp(RVPChannel * channel, char const * url) {
	RVPChannelData * rvpchannel = (RVPChannelData *)channel_get_data(channel);
	bool result;
	Buffer * address;
	Buffer * name;

	address = buffer_new(0);
	name = buffer_new(0);

	result = channel_decode_url_rvp(url, address, name);

	if (result == true) {
		buffer_clear(rvpchannel->server);
		buffer_append_buffer(rvpchannel->server, address);

		if (buffer_get_pos(name) > 0) {
			channel_set_name(channel, buffer_get_buffer(name));
		}
	}

	buffer_delete(address);
	buffer_delete(name);

	return false;
}

/**
 * Decode a Rendevvous Point URL, separating out the root URL from the
 * channel if there is one.
 *
 * The URL must be in one of the following forms:
 *
 * http://AAAAAAAAAAAAAAAA/channel/XXXXXXXXXXXXXXXX
 * https://AAAAAAAAAAAAAAAA/channel/XXXXXXXXXXXXXXXX
 * http://AAAAAAAAAAAAAAAA
 * https://AAAAAAAAAAAAAAAA
 *
 * where AAAAAAAAAAAAAAAA is a domain name and XXXXXXXXXXXXXXXX is a channel
 * string (typically a 16 character hexadecimal string, but the function
 * doesn't enforce this).
 *
 * For example http://rendezvous.mypico.org/channel/64c8a500c133e6ff
 *
 * The address Buffer and channel Buffer can be NULL, in which case the
 * respective return values will not be stored in them. Their previous contents
 * will be overwritten if the URL is valid. If a URL without a channel is 
 * passed in, for example
 *
 * http://rvp.mypico.org/
 *
 * than the channel field will be empty on return. If the URL is not valid,
 * then the function will return false and neither the adress Buffer nor the
 * channel Buffer will be changed.
 *
 * Notice that neither the root URL, nor the channel, contain the string
 * '/channel/', which is used as a delimeter between the two.
 *
 * @param url The URL to decode
 * @param address A buffer to store the root URL into on return, or NULL.
 * @param channel A buffer to store the channel identifier into on return, or
 *        NULL.
 * @return true if the URL defines a valid RVP URL with the correct
 * structure.
 */
bool channel_decode_url_rvp(char const * url, Buffer * address, Buffer * channel) {
	bool result;
	int checked;
	int read;
	char const * slash_ultimate;
	char const * slash_penultimate;
	size_t length;
	char const * address_start;
	char const * address_end;
	char const * channel_start;
	char const * channel_end;

	// URL must be of the form:
	// http://AAAAAAAAAAAAAAAA/channel/XXXXXXXXXXXXXXXX
	// https://AAAAAAAAAAAAAAAA/channel/XXXXXXXXXXXXXXXX
	// http://AAAAAAAAAAAAAAAA
	// https://AAAAAAAAAAAAAAAA
	// where AAAAAAAAAAAAAAAA is a domain name and XXXXXXXXXXXXXXXX is a 16
	// character hexadecimal string.
	
	// For example http://rendezvous.mypico.org/channel/64c8a500c133e6ff

	result = true;
	checked = 0;
	address_start = url;
	address_end = url;
	channel_start = url;
	channel_end = url;

	if (url == NULL) {
		LOG(LOG_INFO, "RVP URL is NULL");
		result = false;
	}

	if (result == true) {
		length = strlen(url);
		read = strncmp(url, HTTP_PREFIX, sizeof(HTTP_PREFIX) - 1);
		if (read == 0) {
			checked += sizeof(HTTP_PREFIX) - 1;
		}
		else {
			read = strncmp(url, HTTPS_PREFIX, sizeof(HTTPS_PREFIX) - 1);
			if (read == 0) {
				checked += sizeof(HTTPS_PREFIX) - 1;
			}
			else {
				LOG(LOG_INFO, "RVP URL prefix doesn't match");
				result = false;
			}
		}
		
		if (checked >= length) {
			result = false;
		}
	}

	if (result == true) {
		address_start = url;
		// Remove any trailing slash of there is one
		if (url[length - 1] == '/') {
			length--;
		}
		slash_ultimate = channel_find_slash_rvp(url + checked, url + length - checked);
		if (slash_ultimate == NULL) {
			// This is the URL prefix without a channel
			checked = length;
			address_end = url + length;
		}
		else {
			read = strncmp(CHANNEL, slash_ultimate, url + length - slash_ultimate);
			if (read == 0) {
				address_end = slash_ultimate;
			}
			else {
				slash_penultimate = channel_find_slash_rvp(url + checked, slash_ultimate - 1);
				if (slash_penultimate == NULL) {
					address_end = url + length;
				}
				else {
					read = strncmp(CHANNEL, slash_penultimate, url + length - slash_ultimate);
					if (read == 0) {
						address_end = slash_penultimate;
						channel_start = slash_ultimate + 1;
						channel_end = url + length;
					}
					else {
						address_end = url + length;
					}
				}
			}
		}

		if (address != NULL) {
			buffer_clear(address);
			if (address_end > address_start) {
				buffer_append(address, address_start, address_end - address_start);
			}
		}
		if (channel != NULL) {
			buffer_clear(channel);
			if (channel_end > channel_start) {
				buffer_append(channel, channel_start, channel_end - channel_start);
			}
		}
	}

	return result;
}

/**
 * Internal callback function provided to libcurl that will timeout the
 * connection after a certain period of calendar (real-world) time. The time
 * out period is set in the RVPChannel structure, but the default is currently
 * 40s to match the default Rendezvous Point timeout.
 * See the libcurl documentation for more details about this callback:
 * https://curl.haxx.se/libcurl/c/CURLOPT_XFERINFOFUNCTION.html
 *
 * @param clientp Pointer to the user data passed by us to libcurl. This is
 *        expected to be the RVPChannel structure for the channel.
 * @param dlnow The number of bytes downloaded so far.
 * @param ultotal The total number of bytes libcurl expects to upload in this
 *        transfer.
 * @param ulnow The number of bytes uploaded so far.
 * @return 0 to continue, any other value causes libcurl to abort the transfer
 *         and return
 */
int channel_xferinfofunction_rvp (void * clientp, curl_off_t dlnow, curl_off_t ultotal, curl_off_t ulnow) {
	RVPChannel * channel = (RVPChannel *)clientp;
	int result;
	double open;
	time_t now;
	time_t started;
	double timeout;

	result = 0;
	now = time(NULL);
	started = channel_get_time_started_rvp(channel);
	// difftime returns time in seconds, and channel->timeout is miliseconds
	open = difftime(now, started) * 1000;

	timeout = channel_get_timeout(channel);
	if (open > timeout) {
		// Cancel the transfer
		result = 1;
	}

	return result;
}

/**
 * Internal utility function that will find the next '/' character in a string,
 * starting from the end and working towards the front. If there is no such
 * character in the string, the function will return NULL.
 *
 * @param start The start of the string in memory.
 * @param end The end of the string in memory.
 * @return The location of the rightmost '/' character, or NULL if there is
 *         none.
 */
static char const * channel_find_slash_rvp(char const * start, char const * end) {
	char const * pos;
	
	pos = end;
	while ((pos > start) && (*pos != '/')) {
		pos--;
	}

	if ((start >= end) || (*pos != '/')) {
		pos = NULL;
	}

	return pos;
}

/**
 * Reset the timeout on a channel. Once called, the channel should be
 * subsequently kept open for the standard length of time previously set
 * using channel_set_timeout().
 *
 * @param channel The channel to reset the timeout on.
 */
static void channel_reset_timeout_rvp(RVPChannel * channel) {
	RVPChannelData * rvpchannel = (RVPChannelData *)channel_get_data(channel);

	if (rvpchannel) {
		rvpchannel->time_started = time(NULL);
	}
}

/**
 * Get the time when the channel was opened. This can be used to determine
 * whether a timeout should be triggered,
 *
 * @param channel The channel to get the time started info for.
 * @return the time the channel was opoened.
 */
static time_t channel_get_time_started_rvp(RVPChannel * channel) {
	RVPChannelData * rvpchannel = (RVPChannelData *)channel_get_data(channel);
	time_t time_started;

	if (rvpchannel) {
		time_started = rvpchannel->time_started;
	}
	else {
		time_started = 0;
	}

	return time_started;
}










