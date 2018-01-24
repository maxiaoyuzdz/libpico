/** \ingroup Storage
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
 * @brief Store Bluetooth MAC info for sending beacons
 * @section DESCRIPTION
 *
 * When using Pico with Bluetooth Classic, beacons are periodically sent out
 * to all of the devices that have previously paired with Pico. To do this,
 * a file `bluetooth.txt` is stored containing a list of MAC addresses to send
 * these beacons to.
 *
 * This file contains functions for managing this list of MACs, as well as
 * importing them from file and exporting them out again. The code manages
 * a linked list of devices, along with assoicated data (e.g. the
 * commitment of the user associated with the device). This allows beacons to
 * be sent out to some or all devices depending on what's needed.
 *
 */

/** \addtogroup Storage
 *  @{
 */

#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include "pico/debug.h"
#include "pico/buffer.h"
#include "pico/cryptosupport.h"
#include "pico/users.h"
#include "pico/base64.h"
#include "pico/beacons.h"
#include "pico/log.h"

// Defines

/**
 * @brief Maximum length of a Bluetooth MAC
 *
 * The MAC of each device to send beacons to is read in from file, each line
 * containing a single address. This is the maximum length of string that will
 * be read per line of the file.
 *
 * This assumes each MAC is represented as six two-digit hexadecimal numbers
 * separated by colons. Like this XX:XX:XX:XX:XX:XX where XX represents a
 * hexadecimal byte.
 *
 */
#define DEVICES_LINE_MAX (512)

/**
 * @brief Number of two-character hex bytes that makes up a Bluetooth MAC
 *
 * The MAC of each device to send beacons to is read in from file, each line
 * containing a single address. An address is represented in the form
 * XX:XX:XX:XX:XX:XX where XX represents a hexadecimal byte.
 *
 * This number represents the number of such hexadecimal bytes that makes up
 * a full textual representation of the MAC address.
 *
 */
#define DEVICES_MAC_BYTES (6)

/**
 * @brief Maximum length of a Bluetooth MAC
 *
 * The MAC of each device to send beacons to is read in from file, each line
 * containing a single address. This is the maximum length of string that will
 * be read per line of the file.
 *
 * This assumes each MAC is represented as six two-digit hexadecimal numbers
 * separated by colons. Like this XX:XX:XX:XX:XX:XX where XX represents a
 * hexadecimal byte.
 *
 */
#define DEVICES_MAC_LENGTH ((DEVICES_MAC_BYTES * 3) - 1)

// Structure definitions

/**
 * @brief Data assocated with a single device beacons are sent to
 *
 * This data structure is used to keep track of all data required
 * in order to send beacons to a specific, individual device.
 *
 * The data forms a single-direction linked list. In practice we only ever
 * want to cycle through the full list, so a single linked list is appropriate.
 * The list is created once when the details are loaded from file, then deleted
 * at the end, so management of the list requires minimal functionality.
 */
struct _BeaconDevice {
	Buffer * comment;
	Buffer * commitment;
	char * device;
	void * data;
	BeaconDevice * next;
};

/**
 * @brief Header for the device list
 *
 * This data structure acts as a header entry for the device list. It links
 * to the linked-list of devices that are used for sending Bluetooth beacons
 * out to.
 *
 * This is the data structure an external entity needs to create and keep track
 * of if managing Bluetooth MAC addresses.
 *
 */
struct _Beacons {
	Buffer * comment;
	BeaconDevice * first;
	unsigned int num;
};

// Function prototypes

static char * beacons_find_end(char * start);
static BeaconDevice * beacondevice_new();
static void beacondevice_delete(BeaconDevice * beacondevice);
static void beacons_append_comment(Beacons * beacons, BeaconDevice * beacondevice, char const * comment);

// Function definitions

/**
 * Create a new instance of the class.
 *
 * @return The newly created object.
 */
Beacons * beacons_new() {
	Beacons * beacons;

	beacons = CALLOC(sizeof(Beacons), 1);
	
	beacons->first = NULL;
	beacons->comment = buffer_new(0);
	
	return beacons;
}

/**
 * Delete an instance of the class, freeing up the memory allocated to it.
 *
 * @param beacons The object to free.
 */
void beacons_delete(Beacons * beacons) {
	BeaconDevice * current;
	BeaconDevice * next;

	if (beacons) {
		if (beacons->first) {
			next = beacons->first;
			while (next != NULL) {
				current = next;
				next = current->next;
				beacondevice_delete(current);
			}
		}

		FREE(beacons);
	}
}

/**
 * Create a new instance of the class.
 *
 * @return The newly created object.
 */
static BeaconDevice * beacondevice_new() {
	BeaconDevice * beacondevice;

	beacondevice = CALLOC(sizeof(BeaconDevice), 1);
	
	beacondevice->comment = buffer_new(0);
	beacondevice->commitment = buffer_new(0);
	beacondevice->device = CALLOC(sizeof(char), DEVICES_MAC_LENGTH + 1);
	beacondevice->data = NULL;
	beacondevice->next = NULL;
	
	return beacondevice;
}

/**
 * Delete an instance of the class, freeing up the memory allocated to it.
 *
 * @param beacondevice The object to free.
 */
static void beacondevice_delete(BeaconDevice * beacondevice) {
	if (beacondevice) {
		if (beacondevice->data) {
			//beaconsend_delete(beacondevice->beaconsend);
			beacondevice->data = NULL;
		}
		if (beacondevice->comment) {
			buffer_delete(beacondevice->comment);
			beacondevice->comment = NULL;
		}
		if (beacondevice->commitment) {
			buffer_delete(beacondevice->commitment);
			beacondevice->commitment = NULL;
		}

		FREE(beacondevice);
	}
}

/**
 * Add a comment line into the loaded users structure. Comments are loaded
 * in and stored so that if the users are exported to file the comments can
 * be retained.
 *
 * @param user The User object to add the comment to
 * @param comment The comment string to add
 */
static void beacons_append_comment(Beacons * beacons, BeaconDevice * beacondevice, char const * comment) {
	if (beacondevice) {
		buffer_append_string(beacondevice->comment, comment);
	}
	else {
		buffer_append_string(beacons->comment, comment);
	}
}

/**
 * Load in a list of Bluetooth MACs from file. These are the addresses that
 * beacons will be sent to.
 *
 * MAC addresses are in the format XX:XX:XX:XX:XX:XX where XX represents a
 * hexadecimal byte. One MAC address per line.
 *
 * Addresses in the file can also be stored with a base64-encoded commitment.
 * The commitments are compared against the users, and are only recorded if
 * they match. This way, beacons will be sent only to the devices associated
 * with the list of users. The format of these lines is as follows.
 *
 * XX:XX:XX:XX:XX:XX:BASE64COMMITMENT
 *
 * Not all addresses have to have a commitment. If they don't have a
 * commitment, they will always be recorded.
 *
 * Similarly if the users parameter is NULL, all MACs will be loaded in.
 *
 * Lines starting with a #, or blank lines, are regarded as comments. If a line
 * can't be correctly parsed, it will be ignored and parsing of the remainder
 * of the file will continue.
 *
 * The resulting list of devices is stored in the Beacons data structure.
 *
 * @param beacons The object to store the data in.
 * @param filename The file to read the addresses from.
 * @param users A list of users to filter the devices by.
 * @return The number of devices correctly loaded from the file.
 */
unsigned int beacons_load_devices(Beacons * beacons, char const * filename, Users const * users) {
	FILE * input;
	char readLine[DEVICES_LINE_MAX];
	char * start;
	char * end;
	char * tokenstart;
	char * tokenend;
	bool more;
	BeaconDevice * device;
	BeaconDevice ** next;
	bool result;
	//char const * code;
	int count;
	int bytecount;
	Buffer * commitment;
	Buffer * base64encoded;
	Buffer const * user;
	bool matches;

	base64encoded = buffer_new(0);
	commitment = buffer_new(0);
	device = NULL;

	input = fopen(filename, "r");
	if (input) {
		next = & beacons->first;

		more = true;
		while (more) {
			more = false;
			start = fgets(readLine, DEVICES_LINE_MAX, input);
			// Read line from file
			readLine[DEVICES_LINE_MAX - 1] = '\0';

			if (start != NULL) {
				if ((readLine[0] != '#') && (readLine[0] != '\n')) {
					// Not a comment
					bytecount = 0;
					end = start;
					tokenstart = start;
					for (count = 0; count < 6; count++) {
						tokenend = beacons_find_end(tokenstart);
						if (tokenend > tokenstart) {
							end = tokenend;
							if ((tokenstart[0] != '\0') && (tokenstart[0] != '\n')) {
								tokenstart = tokenend + 1;
								bytecount++;
							}
						}
					}
					// Check the initial MAC address is correctly formatted as XX:XX:XX:XX:XX:XX
					if ((bytecount == DEVICES_MAC_BYTES) && ((end - start) == DEVICES_MAC_LENGTH)) {
						start = end + 1;

						// Read in the commitment
						end = beacons_find_end(start);
						buffer_clear(commitment);

						if (end > start) {
							// Search the users for this commitment
							buffer_clear(base64encoded);
							buffer_append(base64encoded, start, (end - start));
							base64_decode_buffer(base64encoded, commitment);

							if (users != NULL) {
								user = users_search_by_commitment(users, commitment);
								// If the commitment matched, the user will be non-NULL
								matches = (user != NULL);
							}
							else {
								// There is no users file, so match with everything
								matches = true;
							}
						}
						else {
							// There is no commitment, so match with everything
							matches = true;
						}

						if (matches) {
							device = beacondevice_new();
							*next = device;
							next = & device->next;

							// Correctly found, so transfer the MAC for use beaconing
							strncpy(device->device, readLine, DEVICES_MAC_LENGTH);

							// Initialise the device data
							buffer_append_buffer(device->commitment, commitment);

							//device->beaconsend = beaconsend_new();
							//result = beaconsend_set_device(device->beaconsend, device->device);
							result = true;
							if (result == false) {
								LOG(LOG_ERR, "Failed to set device: %s\n", device->device);
							}

							//code = buffer_get_buffer(beacons->code);
							//beaconsend_set_code(device->beaconsend, code);

							beacons->num++;
						}
					}
				}
				else {
					// Record comment line
					beacons_append_comment(beacons, device, readLine);
				}
				more = true;
			}
		}

		fclose(input);
	}

	buffer_delete(commitment);
	buffer_delete(base64encoded);

	return beacons->num;
}

/**
 * An internal function used to tokenize entries loaded from file. Essentially
 * this function will find the next occurrence of :, newline or a null byte.
 *
 * @param start The position in the string to start from
 * @return The next instance of a tokenization character; so this will point to
 * one of :, \n or \0
 */
static char * beacons_find_end(char * start) {
	char * end;

	end = start;
	if (end != NULL) {
		while ((end[0] != ':') && (end[0] != '\n') && (end[0] != '\0')) {
			end++;
		}
	}

	return end;
}

/**
 * Obtain the first entry in the linked list of Bluetooth device addresses to
 * send beacons to.
 *
 * @param beacons The object to get the data from.
 * @return The first device in the linked list of devices.
 */
BeaconDevice * beacons_get_first(Beacons * beacons) {
	return beacons->first;
}

/**
 * Obtain the next entry in the linked list of Bluetooth device addresses to
 * send beacons to.
 *
 * @param beacondevice The current object in the linked list.
 * @return The next device in the linked list of devices.
 */
BeaconDevice * beacons_get_next(BeaconDevice * beacondevice) {
	return beacondevice->next;
}

/**
 * Returns the total number of devices stored in the linked list.
 *
 * @param beacons The object to get the data from.
 * @return The total number of entries in the linked list.
 */
unsigned int beacons_get_device_num(Beacons * beacons) {
	return beacons->num;
}

/**
 * Get the Bluetooth MAC address of the entry in the linked list of devices.
 *
 * @param beacondevice The object to get the data from.
 * @return A string representing the Bluetooth MAC address. Should not be freed.
 */
char const * beacons_get_address(BeaconDevice * beacondevice) {
	return beacondevice->device;
}

/**
 * Get the data associatd with the entry in the linked list of devices. This
 * is a pointer to data that will have been set up by the calling application,
 * see beacons_set_data().
 *
 * This data is not managed by Beacons or BeaconDevice, so it needs to be
 * allocated and freed by the calling application.
 *
 * @param beacondevice The object to get the data from.
 * @return Pointer to the data stored with this device (possibly NULL).
 */
void * beacons_get_data(BeaconDevice * beacondevice) {
	return beacondevice->data;
}

/**
 * Set the data to be associatd with the entry in the linked list of devices.
 * This can be a pointer to anything, as desired by the calling application.
 * Obviously type information is list, since the pointer is void, so the
 * calling application has to keep track of this.
 *
 * The pointer can be retrieved by calling beacons_get_data().
 *
 * The data is not managed by Beacons or BeaconDevice, so it needs to be
 * allocated and freed by the calling application.
 *
 * @param beacondevice The object to set the data for.
 */
void beacons_set_data(BeaconDevice * beacondevice, void * data) {
	beacondevice->data = data;
}

/**
 * Add a device to the list of devices. This is useful, for example, when
 * pairing a new device. The list can then be exported to file for later
 * use.
 *
 * The device to be added will be compared against all of the devices already
 * in the list. If both the MAC address and commitment match, the device will
 * not be added and the existing entry will be returned.
 *
 * If it's not already in the list, the device will be added to the end and
 * a pointer to this new device will be returned.
 *
 * @param beacons The list to store the device in.
 * @para address The Bluetooth MAC address of the device.
 * @param commitment The commitment to store alongside the device, or NULL if
 *        no commitment should be stored. This is the raw value, *not* base64
 *        encoded.
 * @return Either a newly created device or an identical existing entry in the
 *         list. 
 */
BeaconDevice * beacons_add_device(Beacons * beacons, char const * address, Buffer const * commitment) {
	BeaconDevice * current;
	int compare;
	BeaconDevice * found;
	size_t length;
	size_t currentlength;
	bool result;
	BeaconDevice * last;

	if (commitment) {
		length = buffer_get_pos(commitment);
	}
	else {
		length = 0;
	}

	// Check for duplicates
	found = NULL;
	current = beacons->first;
	last = current;
	while (current) {
		// Compare address
		compare = strncmp(current->device, address, DEVICES_MAC_LENGTH);
		if (compare == 0) {
			if (length > 0) {
				result = buffer_equals(commitment, current->commitment);
				if (result == true) {
					found = current;
				}
			}
			else {
				if (current->commitment != NULL) {
					currentlength = buffer_get_pos(current->commitment);
					if (currentlength == 0) {
						found = current;
					}
				}
				else {
					found = current;
				}
			}
		}

		last = current;
		current = current->next;
	}

	// There was no match, so we should add it	
	if (found == NULL) {
		found = beacondevice_new();

		// Transfer the MAC for use beaconing
		strncpy(found->device, address, DEVICES_MAC_LENGTH);
		found->device[DEVICES_MAC_LENGTH] = 0;

		// Initialise the device data
		if (commitment) {
			buffer_append_buffer(found->commitment, commitment);
		}

		if (last != NULL) {
			last->next = found;
		}
		else {
			beacons->first = found;
		}

		beacons->num++;
	}

	return found;
}

/**
 * Export the list of devices out to file. The file will contain one line per
 * device stored in the format:
 *
 * XX:XX:XX:XX:XX:XX:BASE64COMMITMENT
 *
 * Where each XX represents the hex representation of a byte of the MAC address
 * and BASE64COMMITMENT represents the base64-encoded commitment.
 *
 * If there is no commitment assocated with the device, it will be stored as
 * follows.
 *
 * XX:XX:XX:XX:XX:XX
 *
 * Comments are presevered when importing and exporting files. However, it
 * should be noted that if the list has been filtered when loading through the
 * use of a users list, then the comments may not be preserved as expected on
 * export (since some device entries will potentially be removed).
 *
 * To avoid this, ensure the file is loaded with the users parameter set to
 * NULL, if the file is to be exported out again.
 *
 * @param beaconds The object holding the list to export.
 * @param file The filename to use for the exported file.
 * @return TRUE if export was successful, FALSE otherwise.
 */
bool beacons_export_devices(Beacons const * beacons, char const * file) {
	FILE * output;
	BeaconDevice * current;
	bool result;
	size_t commentlength;
	Buffer * commitmentBase64;
	char const * comment;
	char const * commitment;
	size_t commitmentlength;

	result = true;

	output = fopen(file, "w");
	if (output) {
		// Output the header comment if there is one
		commentlength = buffer_get_pos(beacons->comment);
		if (commentlength > 0) {
			comment = buffer_get_buffer(beacons->comment);
			fprintf(output, "%s", comment);
		}

		commitmentBase64 = buffer_new(0);

		current = beacons->first;
		while (current) {
			// Output the main data
			if (current->commitment) {
				commitmentlength = buffer_get_pos(current->commitment);
			}
			else {
				commitmentlength = 0;
			}

			if (commitmentlength > 0) {
				base64_encode_buffer(current->commitment, commitmentBase64);
				commitment = buffer_get_buffer(commitmentBase64);
				fprintf(output, "%s:%s\n", current->device, commitment);
			}
			else {
				fprintf(output, "%s\n", current->device);
			}

			// Output the proceeding comment if there is one
			commentlength = buffer_get_pos(current->comment);
			if (commentlength > 0) {
				comment = buffer_get_buffer(current->comment);
				fprintf(output, "%s", comment);
			}

			current = current->next;
		}

		buffer_delete(commitmentBase64);

		fclose(output);
	}
	else {
		LOG(LOG_ERR, "Error opening bluetooth file for output");
		result = false;
	}

	return result;
}

/** @} addtogroup Storage */

