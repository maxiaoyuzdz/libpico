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
 * @brief Serialise and deserialies data to and from JSON and data structures
 * @section DESCRIPTION
 *
 * The json class provides serializing and deserializing for converting 
 * data in key-value pairs between json text and a linked list.
 * At present strings, integers and nested json structures are supported
 * but arrays are not supported (they're not needed by the Pico protocol).
 *
 */

/** \addtogroup Datahandling
 *  @{
 */

#ifndef __JSON_H
#define __JSON_H (1)

#include "pico/buffer.h"
#include "pico/dllpublic.h"

// Defines

// Structure definitions

/**
 * @brief Enumerates the allowed data-types for JSON data
 *
 * JSON structures can store string, decimal, sub-structure and array types.
 * The JSON interface supports the retrieval of key-value pairs, so it's
 * often necessary to be able to query or set the type of data to be used.
 * This enum defines the enumerated values to use for these queries.
 *
 * Note that at present array types are not supported (and so don't appear in
 * the enumerate).
 */
typedef enum _JSONTYPE {
	JSONTYPE_INVALID = -1,

	JSONTYPE_STRING,
	JSONTYPE_SUBLIST,
	JSONTYPE_DECIMAL,
	JSONTYPE_INTEGER,

	JSONTYPE_NUM
} JSONTYPE;

/**
 * The internal structure can be found in json.c
 */
typedef struct _Json Json;

// Function prototypes

DLL_PUBLIC Json * json_new();
DLL_PUBLIC void json_delete(Json * json);
DLL_PUBLIC void json_add_string(Json * json, char const * key, char const * value);
DLL_PUBLIC void json_add_buffer(Json * json, char const * key, Buffer const * value);
DLL_PUBLIC void json_add_decimal(Json * json, char const * key, double value);
DLL_PUBLIC void json_add_integer(Json * json, char const * key, long long int value);
DLL_PUBLIC void json_add_sublist(Json * json, char const * key, Json * sublist);
DLL_PUBLIC size_t json_serialize_size(Json * json);
DLL_PUBLIC size_t json_serialize(Json * json, char * buffer, size_t size);
DLL_PUBLIC size_t json_serialize_buffer(Json * json, Buffer * buffer);
DLL_PUBLIC bool json_deserialize_string(Json * json, char const * json_string, size_t length);
DLL_PUBLIC bool json_deserialize_buffer(Json * json, Buffer const * buffer);
DLL_PUBLIC void json_print(Json * json);
DLL_PUBLIC void json_log(Json * json);
DLL_PUBLIC JSONTYPE json_get_type(Json * json, char const * key);
DLL_PUBLIC char const * json_get_string(Json * json, char const * key);
DLL_PUBLIC double json_get_decimal(Json * json, char const * key);
DLL_PUBLIC long long int json_get_integer(Json * json, char const * key);
DLL_PUBLIC double json_get_number(Json * json, char const * key);

// Function definitions

#endif

/** @} addtogroup Datahandling */

