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

#include <stdio.h>
#include <string.h>
//#include <malloc.h>
#include "pico/debug.h"
#include "pico/log.h"
#include "pico/sequencenumber.h"
#include <openssl/rand.h>

// Defines

#define OUTPUT_MAX ((SEQUENCE_NUMBER_LENGTH * 2) + 1)

// Structure definitions

/**
 * @brief Storage and manipulation of 32-bit sequence numbers
 *
 * Opaque structure containing the private fields of the SequenceNumber class.
 * 
 * This is provided as the first parameter of every non-static function and 
 * stores the operation's context.
 * 
 * The structure typedef is in sequencenumber.h
 */
struct _SequenceNumber {
	unsigned char value[SEQUENCE_NUMBER_LENGTH];
};

// Function prototypes

// Function definitions

/**
 * Create a new instance of the class.
 *
 * @return The newly created object.
 */
SequenceNumber * sequencenumber_new() {
	SequenceNumber * sequencenumber;

	sequencenumber = calloc(sizeof(SequenceNumber), 1);
	memset(sequencenumber, 0, SEQUENCE_NUMBER_LENGTH);

	return sequencenumber;
}

/**
 * Delete an instance of the class, freeing up the memory allocated to it.
 *
 * @param sequencenumber The object to free.
 */
void sequencenumber_delete(SequenceNumber * sequencenumber) {
	if (sequencenumber) {
		free(sequencenumber);
	}
}

/**
 * Generates a random sequence number
 *
 * @param sequencenumber Valid sequence number object to write to
 */
void sequencenumber_random(SequenceNumber * sequencenumber) {
	RAND_bytes(sequencenumber->value, SEQUENCE_NUMBER_LENGTH);
}

/**
* Returns true if both numbers are equal
* false otherwise
*/
bool sequencenumber_equals(SequenceNumber * sequencenumber, SequenceNumber * sequencenumber2) {
	bool equal = true;
	int i;
	for (i = 0; i < SEQUENCE_NUMBER_LENGTH; i++) {
		equal = equal && (sequencenumber->value[i] == sequencenumber2->value[i]);
	}
	return equal;
}

/**
 * Increment the sequence number by 1. If the value overflows, it will rotate
 * back round to zero.
 *
 * @param sequencenumber The SequenceNumber object to increment.
 */
void sequencenumber_increment(SequenceNumber * sequencenumber) {
	int pos;
	unsigned char byte;
	bool overflow;

	overflow = true;
	pos = SEQUENCE_NUMBER_LENGTH - 1;
	while ((overflow) && (pos >= 0)) {
		byte = sequencenumber->value[pos];
		if (byte < 0xff) {
			byte++;
			overflow = false;
		}
		else {
			byte = 0x00;
		}
		sequencenumber->value[pos] = byte;
		pos--;
	}
}

/**
 * Print the sequence number to stdout in hexadecimal notation, with the MSB
 * on the left and LSB on the right.
 *
 * @param sequencenumber The SequenceNumber object to print.
 */
void sequencenumber_print(SequenceNumber const * sequencenumber) {
	int pos;

	for (pos = 0; pos < SEQUENCE_NUMBER_LENGTH; pos++) {
		printf("%02x", sequencenumber->value[pos]);
	}
	printf("\n");
}

/**
 * Output the sequence number to the log in hexadecimal notation, with the MSB
 * on the left and LSB on the right.
 *
 * @param sequencenumber The SequenceNumber object to log.
 */
void sequencenumber_log(SequenceNumber const * sequencenumber) {
	int pos;
	int outputpos;
	char output[OUTPUT_MAX];

	for (pos = 0; pos < SEQUENCE_NUMBER_LENGTH; pos++) {
		outputpos = (pos * 2);
		snprintf(output + outputpos, OUTPUT_MAX - outputpos, "%02x", sequencenumber->value[pos]);
	}
	output[OUTPUT_MAX - 1] = 0;

	LOG(LOG_INFO, "%s\n", output);
}

/**
 * Copy the value of a sequence number from on object to another.
 *
 * @param dest The SequenceNumber object to store the value into.
 * @param src The SequenceNumber object to copy the value from.
 */
void sequencenumber_copy(SequenceNumber * dest, SequenceNumber const * src) {
	memcpy(dest->value, src->value, SEQUENCE_NUMBER_LENGTH);
}

/**
 * Take a raw byte representation of a sequence number stored in a buffer and
 * copy it to a SequenceNumber object. The buffer must contain exactly
 * SEQUENCE_NUMBER_LENGTH (32) bytes, with the MSB at the start of the buffer
 * and the LSB and the end of the buffer.
 *
 * @param dest The SequenceNumber object to store the value into.
 * @param src The Buffer object to copy the value from.
 * @return true if the value could be copied correctly (e.g. correct number of
 *         bytes) and false otherwise.
 */
bool sequencenumber_transfer_from_buffer(SequenceNumber * dest, Buffer const * src) {
	bool result;

	result = false;
	if (buffer_get_pos(src) == SEQUENCE_NUMBER_LENGTH) {
		memcpy(dest->value, buffer_get_buffer(src), SEQUENCE_NUMBER_LENGTH);
		result = true;
	}

	return result;
}

/**
 * Extract the sequence number data as a series of bytes. The output will be
 * a sequence of SEQUENCE_NUMBER_LENGTH (32) bytes, NOT null terminated, with
 * the MSB at the start of the buffer and the LSB and the end of the buffer.
 * The data is managed by the SequenceNumber object, so should not be altered
 * or freed.
 *
 * @param destsequencenumber The SequenceNumber object to get the value from.
 * @return The sequence number stored as a series of bytes.
 */
unsigned char const * sequencenumber_get_raw_bytes(SequenceNumber const * sequencenumber) {
	return sequencenumber->value;
}

/** @} addtogroup Crypto */

