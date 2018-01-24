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

#include <stdio.h>
#include <malloc.h>
#include <string.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include "pico/debug.h"
#include "pico/buffer.h"
#include "pico/cryptosupport.h"
#include "pico/base64.h"
#include "pico/log.h"
#include "pico/users.h"

// Defines

#define USERS_LINE_MAX (512)

// Structure definitions

/**
 * @brief Manage details and keys for a single user
 *
 * Opaque structure containing the private fields of the User class.
 * 
 * This is provided as the first parameter of every non-static function and 
 * stores the operation's context.
 * 
 */
typedef struct _User User;

struct _User {
	Buffer * name;
	Buffer * commitment;
	EC_KEY * picoIdentityPublicKey;
	Buffer * symmetricKey;
	Buffer * comment;
	User * next;
};

/**
 * @brief Manage user details and their keys
 *
 * Opaque structure containing the private fields of the Users class.
 * 
 * This is provided as the first parameter of every non-static function and 
 * stores the operation's context.
 * 
 * The structure typedef is in users.h
 */
struct _Users {
	Buffer * comment;
	User * first;
};

// Function prototypes

static User * user_new();
static void user_delete(User * user);
static void user_set(User * user, char const * name, EC_KEY * picoIdentityPublicKey, Buffer const * symmetricKey);
static User * user_search_by_public_key(User * first, EC_KEY * picoIdentityPublicKey);
static User * user_search_by_name(User * first, char const * name);
static User * user_search_by_commitment(User * first, Buffer const * commitment);
static char * users_find_end(char * start);
static void users_reverse(Users * users);
static void users_append_comment(Users * users, char const * comment);

// Function definitions

/**
 * Create a new instance of the class.
 *
 * @return The newly created object.
 */
Users * users_new() {
	Users * users;

	users = CALLOC(sizeof(Users), 1);
	users->first = NULL;
	users->comment = buffer_new(0);
	
	return users;
}

/**
 * Delete an instance of the class, freeing up the memory allocated to it.
 *
 * @param users The object to free.
 */
void users_delete(Users * users) {
	if (users) {
		users_delete_all(users);
		if (users->comment) {
			buffer_delete(users->comment);
			users->comment = NULL;
		}

		FREE(users);
	}
}

/**
 * Create a new instance of the User class.
 *
 * @return The newly created user object.
 */
static User * user_new() {
	User * user;

	user = CALLOC(sizeof(User), 1);
	user->name = buffer_new(0);
	user->commitment = buffer_new(0);
	user->picoIdentityPublicKey = NULL;
	user->symmetricKey = buffer_new(0);
	user->comment = buffer_new(0);
	user->next = NULL;

	return user;
}

/**
 * Delete an instance of the class, freeing up the memory allocated to it.
 *
 * @param user The object to free.
 */
static void user_delete(User * user) {
	if (user) {
		if (user->name) {
			buffer_delete(user->name);
			user->name = NULL;
		}
		if (user->commitment) {
			buffer_delete(user->commitment);
			user->commitment = NULL;
		}
		if (user->picoIdentityPublicKey) {
			// Reduce reference count and free if zero
			EC_KEY_free(user->picoIdentityPublicKey);
		}
		if (user->symmetricKey) {
			buffer_delete(user->symmetricKey);
			user->symmetricKey = NULL;
		}
		if (user->comment) {
			buffer_delete(user->comment);
			user->comment = NULL;
		}
		FREE(user);
	}
}

/**
 * Populate an individual user with its username and public key values.
 *
 * @param user The User object to populate
 * @param name The user's username
 * @param picoIdentityPublicKey The user's ECDH public key
 * @param symmetricKey The user's symmetric key. This can be NULL, in which
 *        case a random key will be automatically generated.
 */
static void user_set(User * user, char const * name, EC_KEY * picoIdentityPublicKey, Buffer const * symmetricKey) {
	bool result;

	buffer_clear(user->name);
	buffer_append_string(user->name, name);
	buffer_clear(user->symmetricKey);

	if (symmetricKey != NULL) {
		buffer_append_buffer(user->symmetricKey, symmetricKey);
	}
	else {
		result = cryptosupport_generate_symmetric_key(user->symmetricKey, CRYPTOSUPPORT_AESKEY_SIZE);
		if (result == false) {
			LOG(LOG_ERR, "Error generating symmetric key for user");
		}
	}
	user->picoIdentityPublicKey = picoIdentityPublicKey;
	// Increase reference count
	EC_KEY_up_ref(user->picoIdentityPublicKey);

	result = cryptosupport_generate_commitment(user->picoIdentityPublicKey, user->commitment);
	if (result == false) {
		LOG(LOG_ERR, "Error generating user's Pico commitment");
	}
}

/**
 * Move a list of users from one User object to another. Any users already
 * in the receiving User object will be deleted (removed and freed). After the
 * move, the user list in the offering User object will be empty.
 *
 * Because the entire list is copied, this process is very fast: it only needs
 * to move the pointer from one User object to another.
 *
 * @param from The User object to move the users to
 * @param to The User object to move the users from
 */
void users_move_list(Users * from, Users * to) {
	users_delete_all(to);
	to->first = from->first;
	from->first = NULL;
}

/**
 * Delete all of the users in a User object and free up the memory associated
 * with them.
 *
 * @param users The User object to empty
 */
void users_delete_all(Users * users) {
	User * current;
	User * next;
	
	current = users->first;
	while (current) {
		next = current->next;
		user_delete(current);
		current = next;
	}
	users->first = NULL;
}

/**
 * Internal function for reversing the order of the list of users in a User
 * object.
 * Why do this? Because it's easiest to write out users to file from the head 
 * onwards. When reading in users they're read in the same order they were 
 * written to, but are added to the head of the list. Consequently loading 
 * and saving would naturally reverse the list. This is fugly, so we use this
 * function to reverse the list just after having loaded it in.
 *
 * The reversal is also relatively fast (linear time in the number of users)
 * and so can be an efficient way to add several users to the end of the list
 * (reverse the list, add the users to the head, reverse the list back; rather
 * than traversing the list for each of the users added).
 *
 * @param users The User object containing a list of users to reverse
 */
static void users_reverse(Users * users) {
	User * tail;
	User * reattach;

	tail = users->first;
	users->first = NULL;
	
	while (tail != NULL) {
		reattach = tail;
		tail = tail->next;

		reattach->next = users->first;
		users->first = reattach;
	}
}

/**
 * Add a user to the list of users. The user is added to the head of the list
 * (for efficiency).
 *
 * @param user The User object to add the user to
 * @param name The username of the user to add
 * @param picoIdentityPublicKey The ECDH public key of the user to add
 * @param symmetricKey The user's symmetric key. This can be NULL, in which
 *        case a random key will be automatically generated.
 */
void users_add_user(Users * users, char const * name, EC_KEY * picoIdentityPublicKey, Buffer const * symmetricKey) {
	User * user;

	// Check whether they're already there
	user = user_search_by_public_key(users->first, picoIdentityPublicKey);
	if (user == NULL) {
		user = user_new();
		user_set(user, name, picoIdentityPublicKey, symmetricKey);
		user->next = users->first;
		users->first = user;
	}
	else {
		LOG(LOG_INFO, "User already exists");
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
static void users_append_comment(Users * users, char const * comment) {
	if (users->first) {
		buffer_append_string(users->first->comment, comment);
	}
	else {
		buffer_append_string(users->comment, comment);
	}
}


/**
 * Filter the list of users by their username. This will generate a new
 * list of users containing only those users with the username specified.
 * This can be used to generate a Users object containing only the user (or
 * users) that are authorised to authentite using the Pico protocol, by
 * passing the returned list to the auth() function.
 *
 * The result Users object should be pre-created, but any users contained
 * in it will be deleted before the filtered list is created.
 *
 * If no users matching the filter are found, the result list will be empty
 * (but not null).
 *
 * @param users The User object containing the list of users to filter
 * @param name The name to filter on. Any user with this name will be included
 * @param result A User object containing only the users with the specificed
 *               username
 * @return The number of users found and listed in the filtered result.
 */
int users_filter_by_name(Users const * users, char const * name, Users * result) {
	User * match;
	int found;

	users_delete_all(result);
	match = users->first;

	found = 0;
	while (match) {
		match = user_search_by_name(match, name);
		if (match != NULL) {
			users_add_user(result, name, match->picoIdentityPublicKey, match->symmetricKey);
			found++;
			match = match->next;
		}
	}

	return found;
}

/**
 * Export a list of users to file. The file output contains one user per line
 * with each line in the following format:
 *
 * username:commitment:publickey
 *
 * Where the commitment is the SHA256 hash of the public key.
 *
 * The result codes are as follows:
 *  - USERFILE_SUCCESS: The file was output successfully.
 *  - USERFILE_IOERROR: IO error saving file (e.g. the file already existed and
 *                      was readonly).
 *
 * The exported file can be read back in using users_load().
 *
 * @param users A Users object containing the list of users to export
 * @param file The full filename to save the resulting file to
 * @return An enum value representing the success/failure condition
 */
USERFILE users_export(Users const * users, char const * file) {
	FILE * output;
	User * current;
	Buffer * pem;
	Buffer * commitmentBase64;
	Buffer * symmetricKeyBase64;
	char const * name;
	char const * commitment;
	char const * publicKey;
	char const * symmetricKey;
	char const * comment;
	USERFILE result;
	size_t commentlength;

	// User file format 
	// One user per line
	// Each line;
	// username:commitment:picoIdentityPublicKey
	// Both the commitment and picoIdentityPublicKey are base64-encoded
	// Commitment is a base64-encoded sha256 hash of picoIdentityPublicKey
	// Maximum line length should be around 32 + ':' + 45 + ':' + 101 = 180 characters

	result = USERFILE_SUCCESS;
	output = fopen(file, "w");
	if (output) {
		// Output the header comment if there is one
		commentlength = buffer_get_pos(users->comment);
		if (commentlength > 0) {
			comment = buffer_get_buffer(users->comment);
			fprintf(output, "%s", comment);
		}

		pem = buffer_new(0);
		commitmentBase64 = buffer_new(0);
		symmetricKeyBase64 = buffer_new(0);

		current = users->first;
		while (current) {
			name = buffer_get_buffer(current->name);
			base64_encode_buffer(current->commitment, commitmentBase64);
			commitment = buffer_get_buffer(commitmentBase64);
			cryptosupport_getpublicpem(current->picoIdentityPublicKey, pem);
			publicKey = buffer_get_buffer(pem);
			base64_encode_buffer(current->symmetricKey, symmetricKeyBase64);
			symmetricKey = buffer_get_buffer(symmetricKeyBase64);
			fprintf(output, "%s:%s:%s:%s\n", name, commitment, publicKey, symmetricKey);

			// Output the proceeding comment if there is one
			commentlength = buffer_get_pos(current->comment);
			if (commentlength > 0) {
				comment = buffer_get_buffer(current->comment);
				fprintf(output, "%s", comment);
			}

			current = current->next;
		}
		
		buffer_delete(pem);
		buffer_delete(commitmentBase64);
		buffer_delete(symmetricKeyBase64);

		fclose(output);
	}
	else {
		LOG(LOG_ERR, "Error opening users file for output");
		result = USERFILE_IOERROR;
	}

	return result;
}

/**
 * Load a list of users from file. The file should contain one user per line
 * with each line in the following format:
 *
 * username:commitment:publickey:symmetrickey
 *
 * Where the commitment is the SHA256 hash of the public key.
 *
 * The result codes are as follows:
 *  - USERFILE_SUCCESS: the file was loaded successfully.
 *  - USERFILE_IOERROR: IO error reading file (e.g. insufficient permissions to
 *                      read the file).
 *  - USERFILE_FORMATERROR: The file doesn't conform to the required format.
 *  - USERFILE_COMMITMENTERROR: The commitment doesn't match the signature.
 *
 * Apart from lines in this format, blank lines and comments (indiciated by
 * the first character on the line being a #) can also be included.
 *
 * In the event that a formatting error occurs, the file read will immediately
 * hald and the returned user list will contain only those users already
 * successfully and fully read up to that point.
 *
 * The loaded file can be exported back out using users_export(), which will
 * preserve comments and blank lines.
 *
 * @param users A Users object to receive the users loaded. Any existing users
 *              will not be deleted, so the list will be *appended*
 * @param file The full filename of the file to load
 * @return An enum value representing the success/failure condition
 */
USERFILE users_load(Users * users, char const * file) {
	FILE * input;
	char readLine[USERS_LINE_MAX];
	char * namestart;
	char * start;
	char * end;
	Buffer * commitment;
	Buffer * generated;
	Buffer * publicKey;
	Buffer * symmetricKey;
	bool more;
	USERFILE result;
	EC_KEY * picoIdentityPublicKey;
	bool cryptoResult;

	result = USERFILE_SUCCESS;
	input = fopen(file, "r");
	if (input) {
		commitment = buffer_new(0);
		generated = buffer_new(0);
		publicKey = buffer_new(0);
		symmetricKey = buffer_new(0);

		// Read a user, a line at a time
		more = true;
		while (more) {
			more = false;
			namestart = fgets(readLine, USERS_LINE_MAX, input);
			readLine[USERS_LINE_MAX - 1] = '\0';

			if ((namestart != NULL) && (readLine[0] != '#') && (readLine[0] != '\n')) {
				// Not a comment line
				if (strlen(readLine) < (USERS_LINE_MAX - 1)) {
					end = users_find_end(namestart);
					if ((namestart != end) && (end[0] != '\0')) {
						result = USERFILE_FORMATERROR;
						// Terminate the username
						end[0] = '\0';

						start = end + 1;
						end = users_find_end(start);
						if ((start != end) && (end[0] != '\0')) {
							// Commitment
							buffer_clear(commitment);
							buffer_append(commitment, start, end - start);

							start = end + 1;
							end = users_find_end(start);

							if ((start != end) && (end[0] != '\0')) {
								// Pico identity public key
								buffer_clear(publicKey);
								buffer_append(publicKey, start, end - start);
								picoIdentityPublicKey = cryptosupport_read_base64_buffer_public_key(publicKey);

								start = end + 1;
								end = users_find_end(start);

								if ((start != end) && (end[0] != '\0')) {
									// User symmetric key
									base64_decode_mem(start, end - start, symmetricKey);

									// Check the commitment against the key
									cryptoResult = cryptosupport_generate_commitment_base64(picoIdentityPublicKey, generated);
									if (cryptoResult == true) {
										cryptoResult = buffer_equals(commitment, generated);
									}

									if (cryptoResult == true) {
										// Add the user to the Users structure
										users_add_user(users, namestart, picoIdentityPublicKey, symmetricKey);
										result = USERFILE_SUCCESS;
										more = true;
									}
									else {
										result = USERFILE_COMMITMENTERROR;
									}
								}

								EC_KEY_free(picoIdentityPublicKey);
							}
						}
					}
				}
				else {
					result = USERFILE_FORMATERROR;
				}
			}
			else {
				if (namestart != NULL) {
					// Record comment line
					users_append_comment(users, namestart);
					more = true;
				}
			}
		}
		buffer_delete(symmetricKey);
		buffer_delete(publicKey);
		buffer_delete(generated);
		buffer_delete(commitment);

		users_reverse(users);
		fclose(input);
	}
	else {
		LOG(LOG_ERR, "Error opening users file for input");
		result = USERFILE_IOERROR;
	}
	
	return result;
}

/**
 * An internal function used to tokenize entries loaded from file. Essentially
 * this function will find the next occurrence of :, newline or a null byte.
 *
 * @param start The position in the string to start from
 * @return The next instance of a tokenization character; so this will point to
 * one of :, \n or \0
 */
static char * users_find_end(char * start) {
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
 * Internal function to search for a user in a list of users by its public key. 
 * The search is actually conducted using the commitment. If the commitment
 * matches, then the key is also checked to avoid hash collisions returning
 * false positives (however unlikely).
 *
 * @param first The head of the list of users to search
 * @param picoIdentityPublicKey The ECDH public key to search for
 * @return The first User object found, or NULL if there were none
 */
static User * user_search_by_public_key(User * first, EC_KEY * picoIdentityPublicKey) {
	bool result;
	Buffer * commitment;
	User * found;
	User * current;
	Buffer * publicKey;
	Buffer * publicCurrent;

	commitment = buffer_new(0);
	result = cryptosupport_generate_commitment(picoIdentityPublicKey, commitment);

	found = NULL;
	if (result == true) {
		publicKey = buffer_new(0);
		publicCurrent = buffer_new(0);
		cryptosupport_getpublicder(picoIdentityPublicKey, publicKey);

		current = first;
		while ((found == NULL) && (current != NULL)) {
			result = buffer_equals(commitment, current->commitment);
			if (result == true) {
				// Perform full key comparison
				buffer_clear(publicCurrent);
				cryptosupport_getpublicder(current->picoIdentityPublicKey, publicCurrent);
				result = buffer_equals(publicKey, publicCurrent);
				if (result == true) {
					// The public keys match
					found = current;
				}
			}

			current = current->next;
		}
		buffer_delete(publicCurrent);
		buffer_delete(publicKey);
	}

	buffer_delete(commitment);

	return found;	
}

/**
 * Search for a user in a list of users by its public key. The username of any
 * user found will be returned, or NULL if none are found.
 *
 * @param users The Users object containing the list of users to search through
 * @param picoIdentityPublicKey The ECDH public key to search for
 * @return A constant buffer containing the username associated with the key, or
 *         NULL if there were none. This buffer is part of the Users structure,
 *         so should not be freed (it will be automatically freed when the
 *         users object is freed, or the user deleted from the list
 */
Buffer const * users_search_by_key(Users const * users, EC_KEY * picoIdentityPublicKey) {
	User * found;
	Buffer * name;

	name = NULL;
	found = user_search_by_public_key(users->first, picoIdentityPublicKey);

	if (found != NULL) {
		name = found->name;
	}

	return name;
}

/**
 * Search for a user in a list of users by its commitment. The username of any
 * user found will be returned, or NULL if none are found.
 *
 * @param users The Users object containing the list of users to search through
 * @param commitment The commitment to search for
 * @return A constant buffer containing the username associated with the key, or
 *         NULL if there were none. This buffer is part of the Users structure,
 *         so should not be freed (it will be automatically freed when the
 *         users object is freed, or the user deleted from the list
 */
Buffer const * users_search_by_commitment(Users const * users, Buffer const * commitment) {
	User * found;
	Buffer * name;

	name = NULL;
	found = user_search_by_commitment(users->first, commitment);

	if (found != NULL) {
		name = found->name;
	}

	return name;
}

/**
 * Internal function to search for a user in a list of users by its username. 
 *
 * @param first The head of the list of users to search
 * @param name The username to search for
 * @return The first User object found, or NULL if there were none
 */
static User * user_search_by_name(User * first, char const * name) {
	bool result;
	User * found;
	User * current;
	Buffer * nameBuffer;

	nameBuffer = buffer_new(0);
	buffer_append_string(nameBuffer, name);
	found = NULL;
	current = first;
	while ((found == NULL) && (current != NULL)) {
		result = buffer_equals(nameBuffer, current->name);
		if (result == true) {
			found = current;
		}

		current = current->next;
	}
	buffer_delete(nameBuffer);

	return found;
}

/**
 * Internal function to search for a user in a list of users by its commitment.
 * Because the commitment is a hash of the public key, it's slightly less
 * accurate than searching by key, due to the (unlikely) possibility of a hash
 * collision.
 *
 * @param first The head of the list of users to search
 * @param commitment The commitment to search for
 * @return The first User object found, or NULL if there were none
 */
static User * user_search_by_commitment(User * first, Buffer const * commitment) {
	bool result;
	User * found;
	User * current;

	found = NULL;
	current = first;
	while ((found == NULL) && (current != NULL)) {
		result = buffer_equals(commitment, current->commitment);
		if (result == true) {
			// The commitment match
			found = current;
		}
		current = current->next;
	}

	return found;
}

/**
 * Search for a user in a list of users by its key. The symmetric key of any
 * user found will be returned, or NULL if none are found.
 *
 * @param users The Users object containing the list of users to search through
 * @param picoIdentityPublicKey The ECDH public key to search for
 * @return A constant buffer containing the symmetrickey associated with the
 *         public key, or NULL if there were none. This buffer is part of the 
 *         Users structure, so should not be freed (it will be automatically 
 *         freed when the users object is freed, or the user deleted from the 
 *         list
 */
Buffer const * users_search_symmetrickey_by_key(Users const * users, EC_KEY * picoIdentityPublicKey) {
	User * found;
	Buffer * key;

	key = NULL;
	found = user_search_by_public_key(users->first, picoIdentityPublicKey);

	if (found != NULL) {
		key = found->symmetricKey;
	}

	return key;
}

/**
 * Print out the list of users, their commitments and keys to stdout. Handy
 * for debugging.
 *
 * @param users The Users object to print the list from
 */
void users_print(Users const * users) {
	User * current;
	Buffer * buffer;

	buffer = buffer_new(0);	
	current = users->first;
	printf("User list\n");
	while (current) {
		printf("User: ");
		buffer_print(current->name);
		buffer_print_base64(current->commitment);
		cryptosupport_getpublicpem(current->picoIdentityPublicKey, buffer);
		buffer_print(buffer);
		printf("\n");
		
		current = current->next;
	}
	buffer_delete(buffer);
}

/** @} addtogroup Storage */

