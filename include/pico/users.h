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
 * @brief Manage user details and their keys
 * @section DESCRIPTION
 *
 * The Users class manages a list of users and their public keys. This list of
 * users can be provided to the sigmaverifier to represent a list of authorized
 * users. Only Pico's authenticating using private keys matching the public
 * keys in the list will generate a positive result when authenticating.
 *
 * The list of users can be imported/exported to file.
 * 
 */

/** \addtogroup Storage
 *  @{
 */

#ifndef __USERS_H
#define __USERS_H (1)

#include "pico/dllpublic.h"

// Defines

// Structure definitions

typedef enum _USERFILE {
	USERFILE_INVALID = -1,

	USERFILE_SUCCESS,
	USERFILE_IOERROR,
	USERFILE_FORMATERROR,
	USERFILE_COMMITMENTERROR,

	USERFILE_NUM
} USERFILE;

/**
 * The internal structure can be found in users.c
 */
typedef struct _Users Users;

// Function prototypes

DLL_PUBLIC Users * users_new();
DLL_PUBLIC void users_delete(Users * users);
DLL_PUBLIC void users_add_user(Users * users, char const * name, EC_KEY * picoIdentityPublicKey, Buffer const * symmetricKey);
DLL_PUBLIC USERFILE users_export(Users const * users, char const * file);
DLL_PUBLIC USERFILE users_load(Users * users, char const * file);
DLL_PUBLIC Buffer const * users_search_by_key(Users const * users, EC_KEY * picoIdentityPublicKey);
DLL_PUBLIC Buffer const * users_search_symmetrickey_by_key(Users const * users, EC_KEY * picoIdentityPublicKey);
DLL_PUBLIC Buffer const * users_search_by_commitment(Users const * users, Buffer const * commitment);
DLL_PUBLIC void users_delete_all(Users * users);
DLL_PUBLIC void users_print(Users const * users);
DLL_PUBLIC void users_move_list(Users * from, Users * to);
DLL_PUBLIC int users_filter_by_name(Users const * users, char const * name, Users * result);

// Function definitions

#endif

/** @} addtogroup Storage */

