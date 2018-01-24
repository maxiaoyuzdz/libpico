/** \ingroup Datahandling
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
 * @brief Dynamically-sized and bounds-safe binary buffer
 * @section DESCRIPTION
 *
 * The buffer class provides a generic dynamically-defined buffer for
 * storing sequences of bytes. As data is appended to the buffer memory
 * will be allocated automatically in blocks. The block size can be set
 * when the buffer is first created.
 *
 * Buffers have a length and and are also guaranteed to be zero-byte
 * terminated. The zero-byte is not included in the length (but the
 * underlying buffer size, which is often different from the size of the
 * contents, will always be large enough to contain it). The contents can
 * itself contain zero bytes, or indeed anything else.
 *
 */

/** \addtogroup Datahandling
 *  @{
 */

#include <stdio.h>
#include <malloc.h>
#include <string.h>
#include <stdarg.h>
#include <openssl/crypto.h>
#include "pico/debug.h"
#include "pico/base64.h"
#include "pico/log.h"
#include "pico/buffer.h"

// Defines

/**
 * The default block size assigned to a buffer if created with a block size
 * of zero. Buffers will be allocated new memory in blocks of this size. In
 * practice this only affects the efficiency of the buffer. A smaller block
 * size will be more memory-efficient, since less spzce will be allocated,
 * but will be less processor-efficent, since blocks may need to be allocated
 * more freqently.
 */
#define BUFFER_BLOCK_SIZE	(2048)

// Structure definitions

/**
 * @brief Generic dynamically-defined buffer for storing byte-sequences
 *
 * Opaque structure containing the private fields of the Buffer class.
 * 
 * This is provided as the first parameter of every non-static function and 
 * stores the operation's context.
 * 
 * The structure typedef is in buffer.h
 */
struct _Buffer {
	char * buffer;
	size_t buffer_pos;
	size_t buffer_size;
	size_t block_size;
};

// Function prototypes

// Function definitions

/**
 * Create a new instance of the class.
 *
 * @param block_size Default block size for allocating memory to the buffer.
 * @return The newly created object.
 */
Buffer * buffer_new(size_t block_size) {
	Buffer * buffer;
	
	buffer = CALLOC(sizeof(Buffer), 1);
	buffer->block_size = (block_size > 0 ? block_size : BUFFER_BLOCK_SIZE);

	buffer->buffer_pos = 0;
	buffer->buffer_size = 0;
	buffer->buffer = MALLOC(buffer->block_size + 1);
	if (buffer->buffer) {
		buffer->buffer_size = buffer->block_size;
		buffer->buffer[0] = 0;
	}
	
	return buffer;
}

/**
 * Delete an instance of the class, freeing up the memory allocated to it.
 *
 * @param buffer The object to free.
 */
void buffer_delete(Buffer * buffer) {
	if (buffer) {
		if (buffer->buffer) {
			FREE(buffer->buffer);
		}
		FREE(buffer);
	}
}

/**
 * Append a block of data to the end of the buffer
 *
 * @param buffer The buffer to append to
 * @param data The start of the data to append
 * @param size The size of the data to append
 * @return The number of bytes copied (which will be size if successful)
 */
size_t buffer_append(Buffer * buffer, void const * data, size_t size) {
	size_t size_required;
	size_t size_quantised;
	size_t copied;

	copied = 0;
	if (size > 0) {
		size_required = buffer->buffer_pos + size;
		size_quantised = (size_required + buffer->block_size - 1);
		size_quantised -= size_quantised % buffer->block_size;
		//printf("Block size: %zu\nRequired: %zu\nQuantised: %zu\n", buffer->block_size, size_required, size_quantised);

		if (size_required > buffer->buffer_size) {
			buffer->buffer = REALLOC(buffer->buffer, size_quantised + 1);
			// TODO: If it returns null, error
			buffer->buffer_size = size_quantised;
		}
	
		if (buffer->buffer) {
			memcpy(buffer->buffer + buffer->buffer_pos, data, size);
			copied = size;
			buffer->buffer_pos += size;
			buffer->buffer[buffer->buffer_pos] = 0;
		}
	}

	return copied;
}

/**
 * Append a null-terminated string to the buffer
 *
 * @param buffer The buffer to append to
 * @param data The zero-terminated string to append
 * @return The number of bytes copied (which will be size if successful)
 */
size_t buffer_append_string(Buffer * buffer, char const * data) {
	size_t size;
	
	size = strlen(data);

	return buffer_append(buffer, data, size);
}

/**
 * Append the contents of one buffer onto the end of another buffer
 *
 * @param buffer The buffer to append th data on to
 * @param appendFrom The buffer to take the data from
 * @return The number of bytes copied (which will be size if successful)
 */
size_t buffer_append_buffer(Buffer * buffer, Buffer const * appendFrom) {
	return buffer_append(buffer, appendFrom->buffer, appendFrom->buffer_pos);
}

/**
 * Append a four bytes length, followed by the data provided, onto
 * the end of a buffer. The four bytes will contain the number
 * of bytes appended that follow it (i.e. not including these four bytes)
 * represented as an int.
 *
 * The resulting buffer will be in 'length-prepended' format.
 *
 * @param buffer The buffer to append the data onto
 * @param data The data to append
 * @param size The quantity of data to append
 * @return The number of bytes copied (which will be size + 4 if successful)
 */
size_t buffer_append_lengthprepend(Buffer * buffer, void const * data, size_t size) {
	size_t pos;

	pos = buffer->buffer_pos;
	if (size > 0xffffffff) {
		LOG(LOG_ERR, "Buffer length %zu is more than four bytes.\n", size);
		size = 0;
	}

	buffer_set_min_size(buffer, pos + size + 4);
	buffer->buffer[pos + 0] = ((size >> 24) & 0xff);
	buffer->buffer[pos + 1] = ((size >> 16) & 0xff);
	buffer->buffer[pos + 2] = ((size >> 8) & 0xff);
	buffer->buffer[pos + 3] = ((size >> 0) & 0xff);

	buffer->buffer_pos += 4;
	buffer_append(buffer, data, size);

	return size + 4;
}

/**
 * Append a four bytes length, followed by the contents of a buffer, onto
 * the end of a second buffer. The four bytes will contain the number
 * of bytes appended that follow it (i.e. not including these four bytes)
 * represented as an int.
 *
 * The resulting buffer will be in 'length-prepended' format.
 *
 * @param buffer The buffer to append the data onto
 * @param appendFrom The data to append
 * @return The number of bytes copied (which will be size + 4 if successful)
 */
size_t buffer_append_buffer_lengthprepend(Buffer * buffer, Buffer const * appendFrom) {
	size_t size;

	if (appendFrom) {
		size = buffer_append_lengthprepend(buffer, appendFrom->buffer, appendFrom->buffer_pos);
	}
	else {
		size = buffer_append_lengthprepend(buffer, NULL, 0);
	}

	return size;
}

/**
 * Copy the contents of a buffer in length pre-pended format into another
 * buffer. A buffer may contain several sections of length-prepended data.
 * This call removes the four byte length value and uses it to copy out the
 * required quantity of data (specified by that length). The next piece of
 * data will then be the next four-bytes of length data. This function returns
 * the amount of data copied, lined up so that the next block can be read
 * and copied out from the buffer.
 *
 * In essence, this function can be used to convert data in length-prepended
 * format into plain data.
 *
 * @param buffer The buffer to copy the data from
 * @param start The start position to read from the buffer
 * @return The number of bytes read (which will be size + 4 if successful)
 */
size_t buffer_copy_lengthprepend(Buffer * bufferin, size_t start, Buffer * bufferout) {
	size_t length;

	length = 0;
	if ((start + 4) <= bufferin->buffer_pos) {
		// Read the size
		length = 0;
		length |= (bufferin->buffer[start + 0] << 24);
		length |= (bufferin->buffer[start + 1] << 16);
		length |= (bufferin->buffer[start + 2] << 8);
		length |= (bufferin->buffer[start + 3] << 0);
		if (start + 4 + length <= bufferin->buffer_pos) {
			start += 4;

			buffer_append(bufferout, bufferin->buffer + start, length);
			start += length;
		}
		else {
			LOG(LOG_ERR, "Overran buffer, requested %zu, available %zu\n", length, bufferin->buffer_pos - start - 4);
		}
	}
	else {
		LOG(LOG_ERR, "Buffer start %zu beyond end %zu\n", start, bufferin->buffer_pos);
	}

	return start;
}

/**
 * Ensures the buffer has at least the specified minimum size allocated to it.
 * This can be useful if data needs to be copied into the buffer without using
 * the buffer functions. In this case, the buffer will not be dynamically
 * resized to accommodate new data, so the minimum buffer size must be set
 * to ensure sufficient memory is allocated before the copy takes place. 
 *
 * @param buffer The buffer to set the size of
 * @param size The minimum size of data the buffer must be able to accommodate.
 *             In fact the buffer size will be incremented by 1 (for the
 *             terminating zero byte) and rounded up to the nearest block
 *             size.
 */
void buffer_set_min_size(Buffer * buffer, size_t size) {
	size_t size_quantised;

	if (buffer->buffer_size < size) {
		size_quantised = (size + buffer->block_size - 1);
		size_quantised -= size_quantised % buffer->block_size;

		buffer->buffer = REALLOC(buffer->buffer, size_quantised + 1);
		buffer->buffer_size = size_quantised;
		buffer->buffer[size] = 0;
	}
}

/**
 * Truncate a buffer to a given size. This will truncate the data stored
 * in the buffer, and also free up any memory, down to the nearest block
 * size larger than the amount requested.
 *
 * @param buffer The buffer to truncate
 * @param reduce_by The amount to reduce by in bytes. Not that this is relative
 *                  to the cuurrent size, so a value of 0 will have no effect.
 */
void buffer_truncate(Buffer * buffer, size_t reduce_by) {
	size_t size_required;
	size_t size_quantised;

	if (buffer->buffer_pos < reduce_by) {
		LOG(LOG_ERR, "Can't reduce buffer size to less than 0\n");
		size_required = 0;
	} else {
		size_required = buffer->buffer_pos - reduce_by;
	}
	size_quantised = (size_required + buffer->block_size - 1);
	size_quantised -= size_quantised % buffer->block_size;

	buffer->buffer = REALLOC(buffer->buffer, size_quantised + 1);
	buffer->buffer_pos = size_required;
	buffer->buffer_size = size_quantised;
	buffer->buffer[buffer->buffer_pos] = 0;
}

/**
 * Print the contents of a buffer to stdout. Useful for debugging.
 *
 * @param buffer The buffer to print the contents of
 */
void buffer_print(Buffer const * buffer) {
	printf("%s\n", buffer->buffer);
}

/**
 * Print the contents of a buffer to stdout in base64 format. Useful for 
 * debugging, and when a buffer may contain arbitrary bytes (not just text).
 *
 * @param buffer The buffer to print the base64-encoded contents of
 */
void buffer_print_base64(Buffer * buffer) {
	Buffer * base64;
	
	base64 = buffer_new(0);
	base64_encode_buffer(buffer, base64);
	buffer_print(base64);
	buffer_delete(base64);
}

/**
 * Send the contents of the buffer to the log. Useful for debugging.
 *
 * @param buffer The buffer to log the contents of
 */
void buffer_log(Buffer * buffer) {
	LOG(LOG_INFO, "%s\n", buffer->buffer);
}

/**
 * Send the contents of a buffer to the log in base64 format. Useful for 
 * debugging, and when a buffer may contain arbitrary bytes (not just text).
 *
 * @param buffer The buffer to log the base64-encoded contents of
 */
void buffer_log_base64(Buffer * buffer) {
	Buffer * base64;
	
	base64 = buffer_new(0);
	base64_encode_buffer(buffer, base64);
	buffer_log(base64);
	buffer_delete(base64);
}

/**
 * Clear the contents of a buffer (setting its length to zero). This may also
 * reduce the memory allocated to the buffer (down to a single block).
 *
 * @param buffer The buffer to clear
 */
void buffer_clear(Buffer * buffer) {
	if (buffer->buffer) {
		FREE (buffer->buffer);
	}
		
	buffer->buffer_pos = 0;
	buffer->buffer_size = 0;
	buffer->buffer = MALLOC(buffer->block_size + 1);
	if (buffer->buffer) {
		buffer->buffer_size = buffer->block_size;
		buffer->buffer[0] = 0;
	}
}

/**
 * Copy the contents of a buffer into a string. The string will be 
 * null-terminated. If the contents is larger than or equal to max-length,
 * as much data as possible will be copied and a null-terminator will always
 * be added to the end.
 *
 * @param buffer The buffer to copy the data from
 * @param string The string to copy the data into. This should have sufficent 
 *               memory allocated to it before calling this function.
 * @param max_length The maximum number of bytes to copy into the string,
 *                   incluing the final null-terminating byte.
 * @return The number of bytes actually copied, not including the NULL
 *         terminator.
 */
size_t buffer_copy_to_string(Buffer const * buffer, char * string, size_t max_length) {
	size_t length;

	if ((max_length > 0) && (string != NULL)) {
		length = (buffer->buffer_pos < (max_length - 1) ? buffer->buffer_pos : (max_length - 1));
		memcpy(string, buffer->buffer, length);
		string[length] = 0;
	}
	else {
		length = 0;
	}

	return length;
}

/**
 * Allocated memory and copy the contents of a buffer into it in the form
 * of a null-terminated string. The amount of memory allocated will be the
 * size of the buffer + 1 to accommodate the null-terminating character.
 *
 * It's up to the calling code to free the allocated buffer, using the standard
 * malloc.c free() function.
 *
 * @param buffer The buffer to copy the data from.
 * @return The newly allocated string buffer with the null-terminated data
 *         copied into it.
 */
char * buffer_copy_to_new_string(Buffer const * buffer) {
	char * string;
	
	string = MALLOC(buffer->buffer_pos + 1);
	memcpy(string, buffer->buffer, buffer->buffer_pos);
	string[buffer->buffer_pos] = 0;

	return string;
}

/**
 * Returns the current quantity of data in the buffer, which is also the next
 * position (relative to the start of the buffer) that any appended data will
 * be written to.
 *
 * @param buffer The buffer to get the end position of
 * @return The current quantity of data in the buffer
 */
size_t buffer_get_pos(Buffer const * buffer) {
	return buffer->buffer_pos;
}

/**
 * Returns the raw memory containing the buffer data. This is the actual
 * memory of the buffer, so it mustn't be freed since this will happen
 * when buffer_delete() is called. It's okay to write to the buffer as long
 * as care is taken not to write outside the allocated space.
 *
 * @param buffer The buffer to get the raw data from
 * @return The data stored in the buffer.
 */
char * buffer_get_buffer(Buffer const * buffer) {
	return buffer->buffer;
}

/**
 * Returns the current quantity of memory allocated to the buffer. This will
 * be a multiple of the block size.
 *
 * @param buffer The buffer to get the size of
 * @return The quantity of memory currently allocated to the buffer.
 */
size_t buffer_get_size(Buffer const * buffer) {
	return buffer->buffer_size;
}

/**
 * Sets the length of data currently stored in the buffer. Care must be taken
 * not to set ths greater than the amount of memory allocated to the buffer.
 * Room is also needed in the buffer for the passive zero-terminating byte.
 *
 * This call is potentially destructive of the data held in the buffer. For
 * example, reducing the position and then resetting it to the previous
 * value straight away does not guarantee that the original data stored
 * between the two positions will be preserved.
 *
 * @param buffer The buffer to change the length of data of
 * @param pos The position of the end point for the data to set
 */
void buffer_set_pos(Buffer * buffer, size_t pos) {
	if (pos <= buffer->buffer_size) {
		buffer->buffer_pos = pos;
	}
	else {
		buffer->buffer_pos = buffer->buffer_size - 1;
	}
	buffer->buffer[buffer->buffer_pos] = 0;
}

/**
 * Compare two buffers and return whether or not they are equal. This uses
 * OpenSSL's secure comparison to avoid timing attacks.
 *
 * @param buffer First buffer to compare
 * @param compare Second buffer to compare
 * @return true if the buffers have the same length and contain the same data,
 *         false o/w
 */
bool buffer_equals(Buffer const * buffer, Buffer const * compare) {
	bool equal;
	
	equal = false;
	if ((buffer != NULL) && (compare != NULL)) {
		if (buffer->buffer_pos == compare->buffer_pos) {
			equal = (CRYPTO_memcmp(buffer->buffer, compare->buffer, buffer->buffer_pos) == 0);
		}
	} else if (!buffer && !compare) { 
		// Both NULL are equal
		equal = true;
	} 

	return equal;
}

/**
 * Construct a formatted string in the buffer. The standard format specifiers
 * from sprintf() can be used.
 *
 * The resulting string will be zero-byte terminated, but the zero byte will
 * not be included in the length of the data.
 *
 * @param buffer The buffer to store the result in
 * @param format The format string containing placeholders
 * @param ... The additional values to populate the format placeholders with
 * @return The length of the resulting string (not including the terminating
 *         zero byte, or -1 if a formatting error occured
 */
size_t buffer_sprintf(Buffer * buffer, char const * format, ...) {
	va_list args;
	size_t size;

	va_start(args, format);
	size = vsnprintf(NULL, 0, format, args);
	va_end(args);

	buffer_set_min_size(buffer, size);

	va_start(args, format);
	vsnprintf(buffer->buffer, buffer->buffer_size + 1, format, args);
	va_end(args);

	buffer->buffer_pos = size;

	return size;
}


/** @} addtogroup Datahandling */

