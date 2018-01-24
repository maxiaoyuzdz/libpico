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

#if HAVE_CONFIG_H
#include "pico/config.h"
#endif

#ifdef HAVE_LIBPICOBT // Only build if Bluetooth is present

#include <ctype.h>
#include "pico/debug.h"
#include "pico/log.h"
#include "pico/channel.h"
#include "pico/channel_bt.h"

#include <picobt/bt.h>
#if !defined(WINDOWS) && (defined(WIN32) || defined(_WIN32) || defined(__WIN32) && !defined(__CYGWIN__))
#define WINDOWS
#endif

// Defines

#define CHANNEL_BT_PORT_STRING_MAXSIZE (3)
#define PICO_SERVICE_UUID "00000000-0000-0000-0000-9C2A70314900"
#define INVALID_SOCKET -1
#define BLUETOOTH_PREFIX "btspp://"

// Structure definitions

/**
 * Structure containing the private fields of the class.
 */
struct _BTChannel {
	bt_uuid_t service;
	bt_addr_t address;
	bt_socket_t listener;
	bt_socket_t socket;
	bt_addr_t deviceName;
};

typedef struct _BTChannel BTChannel;

// Function prototypes

bool channel_delete_bt(RVPChannel * channel);
bool channel_open_bt(RVPChannel * channel);
bool channel_close_bt(RVPChannel * channel);
bool channel_write_bt(RVPChannel * channel, char * data, int length);
bool channel_read_bt(RVPChannel * channel, Buffer * buffer);
void channel_get_url_bt(RVPChannel * channel, Buffer * buffer);
bool channel_socket_needed_bt(RVPChannel * channel, int socket);
void channel_set_timeout_bt(RVPChannel * channel, int timeout);
bool channel_set_url_bt(RVPChannel * channel, char const * url);

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
bool channel_set_bt(RVPChannel * channel) {
	BTChannel * data;
	bt_err_t bterror;

	data = CALLOC(sizeof(BTChannel), 1);

	// Initialising Bluetooth multiple times on Windows will cause problems
	// so we have to leave this to the controlling application
	// Initialise Bluetooth
	//bterror = bt_init();
	bterror = bt_is_present();
	//printf("BTError: %d\n", bterror);
	
	// Bind the listening socket
	if (bterror == BT_SUCCESS) {
		bterror = bt_bind(& data->listener);
		if (bterror != BT_SUCCESS) {
			LOG(LOG_ERR, "Failed to bind Bluetooth socket");
		}
	}

	if (bterror == BT_SUCCESS) {
		bterror = bt_listen(& data->listener);
		if (bterror != BT_SUCCESS) {
			LOG(LOG_ERR, "Failed to listen on Bluetooth socket");
		}
	}

	if (bterror == BT_SUCCESS) {
		bterror = bt_get_device_name(&data->deviceName);
		if (bterror != BT_SUCCESS) {
			LOG(LOG_ERR, "Failed to get Bluetooth device name");
		}
	}

	if (bterror == BT_SUCCESS) {
		// Set the Bluetooth context data
		channel_set_data(channel, data);

		// Set the overloaded virtual functions
		channel_set_functions(channel, channel_delete_bt, channel_open_bt, channel_close_bt, channel_write_bt, channel_read_bt, channel_get_url_bt, channel_set_url_bt, channel_set_timeout_bt);
		channel_set_socket_needed_functions(channel, channel_socket_needed_bt);
	}
	else {
		FREE(data);
		
		channel_set_data(channel, NULL);
		channel_set_functions(channel, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
		channel_set_socket_needed_functions(channel, NULL);
	}

	return (bterror == BT_SUCCESS);
}

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
bool channel_set_bt_with_port(RVPChannel * channel, unsigned char port) {
	BTChannel * data;
	bt_err_t bterror;

	data = CALLOC(sizeof(BTChannel), 1);

	// Initialising Bluetooth multiple times on Windows will cause problems
	// so we have to leave this to the controlling application
	// Initialise Bluetooth
	//bterror = bt_init();
	bterror = bt_is_present();
	//printf("BTError: %d\n", bterror);

	// Bind the listening socket
	if (bterror == BT_SUCCESS) {
		//bterror = bt_bind(& data->listener);
		bterror = bt_bind_to_channel(& data->listener, port);
		if (bterror != BT_SUCCESS) {
			LOG(LOG_ERR, "Failed to bind Bluetooth socket");
		}
	}

	if (bterror == BT_SUCCESS) {
		bterror = bt_listen(& data->listener);
		if (bterror != BT_SUCCESS) {
			LOG(LOG_ERR, "Failed to listen on Bluetooth socket");
		}
	}

	if (bterror == BT_SUCCESS) {
		bterror = bt_get_device_name(& data->deviceName);
		if (bterror!= BT_SUCCESS) {
			LOG(LOG_ERR, "Failed to get Bluetooth device name");
		}
	}

	if (bterror == BT_SUCCESS) {
		// Set the Bluetooth context data
		channel_set_data(channel, data);

		// Set the overloaded virtual functions
		channel_set_functions(channel, channel_delete_bt, channel_open_bt, channel_close_bt, channel_write_bt, channel_read_bt, channel_get_url_bt, channel_set_url_bt, channel_set_timeout_bt);
		channel_set_socket_needed_functions(channel, channel_socket_needed_bt);
	}
	else {
		FREE(data);
		
		channel_set_data(channel, NULL);
		channel_set_functions(channel, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
		channel_set_socket_needed_functions(channel, NULL);
	}

	return (bterror == BT_SUCCESS);
}


/**
 * Set a channel to use Bluetooth.
 * This overloads the required functions, sets the Bluetooth data object
 * and advertises the bluetooth service with the specified UUID.
 *
 * In case of failure, the channel is unusable and has to be set again
 *
 * @param channel The channel to set to Bluetooth.
 * @return true if the Bluetooth was set up successfully, false o/w
 */
bool channel_set_bt_with_uuid(RVPChannel * channel, const char* uuid) {
	bt_err_t bterror = BT_ERR_UNKNOWN;
	BTChannel * btchannel;
	bool result;

	result = channel_set_bt(channel);
   
	if (result) {
		btchannel = (BTChannel *)channel_get_data(channel);

		// Set service
		bterror = bt_str_to_uuid(uuid, &btchannel->service);

		if (bterror != BT_SUCCESS) {
			LOG(LOG_ERR, "Error %d converting uuid \"%s\"", bterror, uuid);
		}
	}

	if (bterror == BT_SUCCESS) {
		// Register SDP record
		bterror = bt_register_service(&btchannel->service, "PicoAuthService", &btchannel->listener);
		if (bterror != BT_SUCCESS) {
			LOG(LOG_ERR, "Bluetooth register service error: %d\n", bterror);
		}
	} 
	
	if (bterror != BT_SUCCESS) {
		// Cleanup the structured intialised by channel_set_bt
		channel_set_data(channel, NULL);
		channel_set_functions(channel, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
		channel_set_socket_needed_functions(channel, NULL);
	}
	
	return (bterror == BT_SUCCESS);
}

/**
 * Perform actions needed to delete the Bluetooth channel.
 * This is called in addition to the standard behaviour of channel_delete().
 *
 * @param channel The channel to delete.
 * @return True if the channel was successfully deleted; false otherwise
 */
bool channel_delete_bt(RVPChannel * channel) {
	BTChannel * btchannel = (BTChannel *)channel_get_data(channel);

	if (btchannel) {
		// Disconnect the listening socket
		bt_disconnect(&btchannel->listener);

		// Deinitialise Bluetooth
		//bt_exit();

		// Clear the data pointer
		FREE(btchannel);
	}

	return true;
}

/**
 * Perform actions needed to open the Bluetooth channel.
 * This function overrides the standard behaviour of channel_open().
 *
 * @param channel The channel to open.
 * @return True if the channel was successfully opened; false otherwise
 */
bool channel_open_bt(RVPChannel * channel) {
	BTChannel * btchannel = (BTChannel *)channel_get_data(channel);
	bt_err_t bterror;

	bterror = bt_accept(& btchannel->listener, & btchannel->socket);
	if (bterror != BT_SUCCESS) {
		LOG(LOG_ERR, "Bluetooth accept error: %d\n", bterror);
	}
	
	return (bterror == BT_SUCCESS);
}

/**
 * Perform actions needed to close the Bluetooth channel.
 * This function overrides the standard behaviour of channel_close().
 *
 * @param channel The channel to close.
 * @return True if the channel was successfully close; false otherwise
 */
bool channel_close_bt(RVPChannel * channel) {
	BTChannel * btchannel = (BTChannel *)channel_get_data(channel);

	// Close the connection
	bt_disconnect(&btchannel->socket);

	return true;
}

/**
 * Write data on the Bluetooth channel.
 * This function overrides the standard behaviour of channel_write().
 *
 * @param channel The channel to write to.
 * @param data The data to send.
 * @param length The quantity of data to send (in bytes).
 * @return True if the data was successfully sent; false otherwise.
 */
bool channel_write_bt(RVPChannel * channel, char * data, int length) {
	BTChannel * btchannel = (BTChannel *)channel_get_data(channel);
	bt_err_t result;

	// Send the message
	result = bt_write(&btchannel->socket, data, length);
	if (result != BT_SUCCESS) {
		LOG(LOG_ERR, "Bluetooth write error: %d\n", result);
	}

	return (result == BT_SUCCESS);
}

/**
 * Read data from the Bluetooth channel.
 * This function overrides the standard behaviour of channel_read().
 *
 * @param channel The channel to read from.
 * @param buffer The buffer to store the received data in.
 * @return True if the data was successfully received; false otherwise.
 */
bool channel_read_bt(RVPChannel * channel, Buffer * buffer) {
	BTChannel * btchannel = (BTChannel *)channel_get_data(channel);
	bt_err_t result;
	char * data;
	size_t numBytes;
	char lengthWord[4];
	int length;

	// Read the prefixed length
	numBytes = 4;
	result = bt_read(&btchannel->socket, lengthWord, &numBytes);
	((char *)(& length))[0] = lengthWord[3];
	((char *)(& length))[1] = lengthWord[2];
	((char *)(& length))[2] = lengthWord[1];
	((char *)(& length))[3] = lengthWord[0];

	if ((length > 0) && (length < (1024 * 5))) {
		//printf("Reading %d bytes\n", length);

		buffer_set_min_size(buffer, length);
		data = buffer_get_buffer(buffer);
		numBytes = length;
		result = bt_read(&btchannel->socket, data, &numBytes);
		if (result != BT_SUCCESS) {
			LOG(LOG_ERR, "Bluetooth read error: %d\n", result);
		}
		buffer_set_pos(buffer, numBytes);
	}

	return (result == BT_SUCCESS);
}

/**
 * Return the URL of the channel. This can be passed to a client in order
 * for it to connect to the channel. For example, it could be the URL of
 * a Rendezvous Point, or a Bluetooth URL. For example, see
 * http://www.oracle.com/technetwork/articles/javame/index-140411.html
 *
 * @param channel The channel to get the URL of.
 * @param buffer The buffer to store the URL in.
 */
void channel_get_url_bt(RVPChannel * channel, Buffer * buffer) {
	BTChannel * btchannel = (BTChannel *)channel_get_data(channel);
	char device[BT_ADDRESS_FORMAT_COMPACT_MAXSIZE];
	uint8_t port;
	char port_str[CHANNEL_BT_PORT_STRING_MAXSIZE];

	bt_addr_to_str_compact(& btchannel->deviceName, device);
	buffer_clear(buffer);
	buffer_append_string(buffer, BLUETOOTH_PREFIX);
	buffer_append_string(buffer, device);

	// If no uuid was set, we are only using a port so the port has
	// to go to the URI
	if (!memcmp(&btchannel->service, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16)) {
		buffer_append_string(buffer, ":");

		port = bt_get_socket_channel(btchannel->listener);
		snprintf(port_str, CHANNEL_BT_PORT_STRING_MAXSIZE, "%02X", port);
		buffer_append_string(buffer, port_str);
	}
}

/**
 * Set the full URL of the channel, including the transport.
 *
 * The URL must be valid. For example, since this function is used only
 * for Bluetooth, it must start with btspp://.
 *
 * @param channel The channel to set the URL for
 * @param url The fully qualified URL.
 * @return true if the URL is valid for the type of channel, and the
 *         reallocation of the listening port succeeds, false o/w.
 */
bool channel_set_url_bt(RVPChannel * channel, char const * url) {
	BTChannel * btchannel = (BTChannel *)channel_get_data(channel);
	bool result;
	char device[BT_ADDRESS_FORMAT_COMPACT_MAXSIZE];
	Buffer * address;
	unsigned int port;
	bt_err_t bterror;
	int read;
	int current_port;

	// URL must be of the form:
	// btspp://XXXXXXXXXXXX:PP
	// where XXXXXXXXXXXX is the MAC address represented as a hexadecimal string
	// and PP is the port address represented as a hexadecimal string

	// In this case, XXXXXXXXXXXX must match the device id

	address = buffer_new(BT_ADDRESS_FORMAT_COMPACT_MAXSIZE);
	result = channel_decode_url_bt(url, address, & port);

	if (result == true) {
		bt_addr_to_str_compact(& btchannel->deviceName, device);
		read = strncmp(buffer_get_buffer(address), device, BT_ADDRESS_FORMAT_COMPACT_MAXSIZE);
		if (read != 0) {
			LOG(LOG_INFO, "Bluetooth URL address differs from local machine");
			result = 0;
		}
	}

	if (result == true) {
		current_port = bt_get_socket_channel(btchannel->listener);
		if (port != current_port) {
			if (btchannel->listener.s != INVALID_SOCKET) {
				bt_disconnect(&btchannel->listener);
			}
			bterror = bt_bind_to_channel(& btchannel->listener, port);
			if (bterror != BT_SUCCESS) {
				LOG(LOG_ERR, "Failed to bind Bluetooth socket");
			}

			if (bterror == BT_SUCCESS) {
				bterror = bt_listen(& btchannel->listener);
				if (bterror != BT_SUCCESS) {
					LOG(LOG_ERR, "Failed to listen on Bluetooth socket");
				}
			}

			if (bterror != BT_SUCCESS) {
				bt_disconnect(& btchannel->listener);
				result = false;
			}
		}
	}

	buffer_delete(address);

	return result;
}

/**
 * Decode a Blutooth URL for incoming connections, separating out the
 * device's MAC address and port (Bluetooth channel).
 *
 * The URL must be of the form:
 *
 * btspp://XXXXXXXXXXXX:PP
 *
 * where XXXXXXXXXXXX is the MAC address represented as a hexadecimal string
 * and PP is the port address represented as a hexadecimal string
 *
 * The address Buffer and port int can be NULL, in which case the respective
 * return values will not be stored in them. Their previous contents will be
 * overwritten if the URL is valid. If the URL is not valid, then the function
 * will return false and neither the adress Buffer nor the port int will be
 * changed.
s *
 * @param url The URL to decode
 * @param address A buffer to store the MAC address into on return, or NULL.
 * @param port An integer to stire the port number into in return, or NULL.
 * @return true if the URL defines a valid Bluetooth URL with the correct
 * structure.
 */
bool channel_decode_url_bt(char const * url, Buffer * address, unsigned int * port) {
	bool result;
	char address_read[BT_ADDRESS_FORMAT_COMPACT_MAXSIZE];
	int checked;
	int read;
	unsigned int port_read;
	char character;

	// URL must be of the form:
	// btspp://XXXXXXXXXXXX:PP
	// where XXXXXXXXXXXX is the MAC address represented as a hexadecimal string
	// and PP is the port address represented as a hexadecimal string

	// In this case, XXXXXXXXXXXX must match the device id

	result = true;
	checked = 0;

	if (url == NULL) {
		LOG(LOG_INFO, "Bluetooth URL is NULL");
		result = false;
	}

	if (result == true) {
		read = strncmp(url, BLUETOOTH_PREFIX, sizeof(BLUETOOTH_PREFIX) - 1);
		if (read == 0) {
			checked += sizeof(BLUETOOTH_PREFIX) - 1;
		}
		else {
			LOG(LOG_INFO, "Bluetooth URL prefix doesn't match");
			result = false;
		}
	}

	if (result == true) {
		read = 0;
		while ((result == true) && (read < (BT_ADDRESS_FORMAT_COMPACT_MAXSIZE - 1))) {
			character = url[checked + read];
			if (isxdigit(character)) {
				address_read[read] = character;
			}
			else {
				result = false;
			}
			read++;
		}
		address_read[read] = 0;

		if ((result == true) && (read == (BT_ADDRESS_FORMAT_COMPACT_MAXSIZE - 1))) {
			checked += read;
		}
		else {
			LOG(LOG_INFO, "Bluetooth URL address doesn't satisfy format: %d", read);
			result = false;
		}
	}

	if (result == true) {
		read = strncmp(url + checked, ":", 1);
		if (read == 0) {
			checked += 1;

			if (result == true) {
				read = sscanf(url + checked, "%02u", & port_read);
				if (read == 1) {
					if (url[checked + 1] == 0) {
						checked += 1;
					}
					else {
						if (url[checked + 2] == 0) {
							checked += 2;
						}
					}
				}
				else {
					LOG(LOG_INFO, "Bluetooth URL port doesn't satisfy format");
					result = false;
				}
			}
		}
		else {
			port_read = 0;
			LOG(LOG_INFO, "Bluetooth URL doesn't include a port");
		}
	}

	if (result == true) {
		if (url[checked] != 0) {
			LOG(LOG_INFO, "Bluetooth URL doesn't terminate after port");
			result = false;
		}
	}

	if (result == true) {
		if (address != NULL) {
			buffer_clear(address);
			buffer_append(address, address_read, BT_ADDRESS_FORMAT_COMPACT_MAXSIZE);
		}
		if (port != NULL) {
			*port = port_read;
		}
	}

	return result;
}

/**
 * Establish whether a particular socket is currently needed for the operation
 * of the channel. This is useful during the daemonize process, where all
 * sockets would otherwise be closed. This allows certain sockets to be kept
 * open.
 * This is the Bluetooth implementation which overrides the default (null)
 * behaviour (which is to always return false).
 *
 * @param channel The channel to check the needed sockets for.
 * @param socket The socket to check for.
 * @return true if the socket is needed, false o/w.
 */
bool channel_socket_needed_bt(RVPChannel * channel, int socket) {
	BTChannel * btchannel = (BTChannel *)channel_get_data(channel);
	bool needed;

	needed = false;
	if (socket == btchannel->socket.s) {
		needed = true;
	}
	if (socket == btchannel->listener.s) {
		needed = true;
	}

	return needed;
}

/**
 * Returns the port number used by the BT channel
 * WARNING: This will only work if the RVPChannel is a bluetooth channel.
 * o/w the behaviour is unexpected
 *
 * @param channel The channel to get the port.
 * @return port number
 */
unsigned char channel_socket_get_port_bt(RVPChannel * channel) {
	unsigned char port = 0;
	
	if (channel) {
		BTChannel * btchannel = (BTChannel *)channel_get_data(channel);

		if (btchannel != NULL) {
			port = bt_get_socket_channel(btchannel->listener);
		}
	}

	return port;	
}

/**
 * Set the timeout duration for the channel, measured in milliseconds.
 * WARNING: Because of implementation issues, the timeout will by round
 * to seconds, despite being sent in milliseconds
 *
 * @param channel The channel to set the timeout duration on.
 * @param timeout The timeout duration in milliseconds.
 */
void channel_set_timeout_bt(RVPChannel * channel, int timeout) {
	if (channel) {
		BTChannel * btchannel = (BTChannel *)channel_get_data(channel);

		if (btchannel != NULL) {
			bt_set_timeout(&btchannel->socket, timeout / 1000);
		}
	}
}

#endif // HAVE_LIBPICOBT // Only build if Bluetooth is present

