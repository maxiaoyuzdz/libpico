/**
 * @file
 * @author  cd611@cam.ac.uk
 *          David Llewellyn-Jones <David.Llewellyn-Jones@cl.cam.ac.uk>
 * @version $(VERSION)
 *
 * @section LICENSE
 *
 * (C) Copyright Cambridge Authentication Ltd, 2018
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
 * @brief Unit tests for the Users data type
 * @section DESCRIPTION
 *
 * Performs a variety of unit tests associated with the Users data type.
 *
 */

#include <check.h>
#include <unistd.h>
#include "pico/keypair.h"
#include "pico/users.h"
#include "pico/base64.h"
#include "pico/cryptosupport.h"

// Defines

#define EXAMPLE_FILE "# Comment line 1\n" \
	"# Comment line 2\n" \
	"Pachelbel:nmT9tLLC/fmdniWYy0ee1/UOJwd9qmu0GlSrrV7KFYU=:MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEam0K8bMrRAfWtwhB8yS7PA7tUBmAlnoPRxrj0SFdyqUs8mwMw2Rrg/9QGGUc2m6cpW8Cyrx/wvwycmMuSGGy5w==:TaajhTIRojhTIRoAHqDpyg==\n\n" \
	"# Comment line 3\n\n" \
	"Chopin:nFQ7rNMLeNABxk/rRJrCN8/pmYG291z77Sk5Zc5KW6E=:MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAENnDeu8fqrxx55e9IyQGlpTl3+JsnVdhi8fjTbaTxablYL+H0aQg3GMc+PgTZorbsPmkLug5LkE/LTI2Ui3cCEQ==:Lkgxxsd02/VrBPPBdiIkfw==\n" \
	"# Comment line 4\n"\
	"# Comment line 5\n"\
	"# Comment line 6\n"\
	"Bruch:XBshqSPa9E7GgsHd36AWl9g6YaWn8ktUzUvB6lJ98Yk=:MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAELs0ppPjtpliRKkTW7OMKnKsjuZPKS/Ud7KmyDaO6zWeGnuJFRUmZ4eI7INViqliMvRxgnxFYuNkSIXZ9ND6MfA==:RO+lGHwoppll7390vs9Cqw==\n"\
	"# Comment line 7\n"\
	"# Comment line 8\n"\
	"# Comment line 9\n"\
	"# Comment line 10\n\n"\
	"Schoenberg:NEF48sOIY9LZP9Wsx3auBgG8pIAqqDVJHM2PjCNe+/E=:MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEFsRBMNOMmOFQiHn7nG0LqExAGvIs36wOETfYYS10QH4gCx+rX/xcWXZxmvb++6ZWILZ7tUDrCM8QVLyHBWwunQ==:AA95F667sdkji8Zz9tLSew==\n"\
	"Monteverdi:HBZ9B+kioDLkgdtraPqA+2pTDBBhqFm85HD1KqazgEM=:MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4V3SujOm67S9x93sCegYP18x/HxyUgA2u6tqcGXcVPZ2S6/uhAYmPBTYz8fMP2NQaaIcocg7TQZf+XMDnY1yBQ==:W/Lyjj8ioJHGDO9jejdfGQ==\n"\
	"# Comment line penultimate\n"\
	"# Comment line last\n"

#define USERS_FILENAME_TEMPLATE "/tmp/pico_users_XXXXXX.txt"
#define OUTPUT_FILENAME_TEMPLATE "/tmp/pico_usersout_XXXXXX.txt"
#define INPUT_FILENAME_TEMPLATE "/tmp/pico_userin_XXXXXX.txt"

// Structure definitions

// Function prototypes

// Function definitions

START_TEST (add_users) {
	KeyPair * keypair1 = keypair_new();
	KeyPair * keypair2 = keypair_new();
	keypair_generate(keypair1);
	keypair_generate(keypair2);
	Buffer * expected = buffer_new(0);
	Buffer * symmetricKey1 = buffer_new(0);
	Buffer * symmetricKey2 = buffer_new(0);
	Buffer const * symmetricKey;

	cryptosupport_generate_symmetric_key(symmetricKey1, CRYPTOSUPPORT_AESKEY_SIZE);
	cryptosupport_generate_symmetric_key(symmetricKey2, CRYPTOSUPPORT_AESKEY_SIZE);
	ck_assert(!buffer_equals(symmetricKey1, symmetricKey2));

	EC_KEY* pub1 = keypair_getpublickey(keypair1);
	EC_KEY* pub2 = keypair_getpublickey(keypair2);

	Users* users = users_new();
	ck_assert(users_search_by_key(users, pub1) == NULL);
	ck_assert(users_search_by_key(users, pub2) == NULL);

	users_add_user(users, "one", pub1, symmetricKey1);
	
	ck_assert(users_search_by_key(users, pub2) == NULL);
	Buffer const * user = users_search_by_key(users, pub1);
	buffer_clear(expected);
	buffer_append_string(expected, "one");
	ck_assert(buffer_equals(user, expected));
	
	users_add_user(users, "two", pub2, symmetricKey2);
	
	user = users_search_by_key(users, pub1);
	buffer_clear(expected);
	buffer_append_string(expected, "one");
	ck_assert(buffer_equals(user, expected));
	user = users_search_by_key(users, pub2);
	buffer_clear(expected);
	buffer_append_string(expected, "two");
	ck_assert(buffer_equals(user, expected));

	// Check the correct symmetric keys are returned
	symmetricKey = users_search_symmetrickey_by_key(users, pub1);
	ck_assert(buffer_equals(symmetricKey, symmetricKey1));
	symmetricKey = users_search_symmetrickey_by_key(users, pub2);
	ck_assert(buffer_equals(symmetricKey, symmetricKey2));

	users_delete_all(users);
	ck_assert(users_search_by_key(users, pub1) == NULL);
	ck_assert(users_search_by_key(users, pub2) == NULL);

	users_delete(users);
	buffer_delete(expected);
	buffer_delete(symmetricKey1);
	buffer_delete(symmetricKey2);
	keypair_delete(keypair1);
	keypair_delete(keypair2);
}
END_TEST

START_TEST (export_users) {
	KeyPair * keypair1 = keypair_new();
	KeyPair * keypair2 = keypair_new();
	keypair_generate(keypair1);
	keypair_generate(keypair2);
	Buffer * expected = buffer_new(0);
	EC_KEY* pub1 = keypair_getpublickey(keypair1);
	EC_KEY* pub2 = keypair_getpublickey(keypair2);
	char * filename;
	int fdfile;
	Buffer * symmetricKey1 = buffer_new(0);
	Buffer * symmetricKey2 = buffer_new(0);
	Buffer const * symmetricKey;

	// Generate filenames of temporary files to use
	filename = malloc(sizeof(USERS_FILENAME_TEMPLATE) + 1);
	strcpy(filename, USERS_FILENAME_TEMPLATE);
	fdfile = mkstemps(filename, 4);
	ck_assert(fdfile >= 0);

	//fprintf(stderr, "Files: %s\n", filename);

	Users* users = users_new();
	ck_assert(users_search_by_key(users, pub1) == NULL);
	ck_assert(users_search_by_key(users, pub2) == NULL);

	cryptosupport_generate_symmetric_key(symmetricKey1, CRYPTOSUPPORT_AESKEY_SIZE);
	cryptosupport_generate_symmetric_key(symmetricKey2, CRYPTOSUPPORT_AESKEY_SIZE);
	ck_assert(!buffer_equals(symmetricKey1, symmetricKey2));

	users_add_user(users, "one", pub1, symmetricKey1);
	users_add_user(users, "two", pub2, symmetricKey2);
	
	Buffer const* user = users_search_by_key(users, pub1);
	buffer_clear(expected);
	buffer_append_string(expected, "one");
	ck_assert(buffer_equals(user, expected));
	user = users_search_by_key(users, pub2);
	buffer_clear(expected);
	buffer_append_string(expected, "two");
	ck_assert(buffer_equals(user, expected));

	users_export(users, filename);

	users_delete_all(users);
	ck_assert(users_search_by_key(users, pub1) == NULL);
	ck_assert(users_search_by_key(users, pub2) == NULL);

	users_load(users, filename);

	// Remove temporary file
	close(fdfile);
	unlink(filename);

	user = users_search_by_key(users, pub1);
	buffer_clear(expected);
	buffer_append_string(expected, "one");
	ck_assert(buffer_equals(user, expected));
	user = users_search_by_key(users, pub2);
	buffer_clear(expected);
	buffer_append_string(expected, "two");
	ck_assert(buffer_equals(user, expected));

	// Check the correct symmetric keys are returned
	symmetricKey = users_search_symmetrickey_by_key(users, pub1);
	ck_assert(buffer_equals(symmetricKey, symmetricKey1));
	symmetricKey = users_search_symmetrickey_by_key(users, pub2);
	ck_assert(buffer_equals(symmetricKey, symmetricKey2));

	users_delete(users);
	buffer_delete(expected);
	keypair_delete(keypair1);
	keypair_delete(keypair2);
	free(filename);
}
END_TEST

START_TEST (filter_users) {
	KeyPair * keypair1 = keypair_new();
	KeyPair * keypair2 = keypair_new();
	keypair_generate(keypair1);
	keypair_generate(keypair2);
	Buffer * expected = buffer_new(0);
	Buffer * symmetricKey1 = buffer_new(0);
	Buffer * symmetricKey2 = buffer_new(0);
	Buffer const * symmetricKey;

	EC_KEY* pub1 = keypair_getpublickey(keypair1);
	EC_KEY* pub2 = keypair_getpublickey(keypair2);

	Users* users = users_new();
	ck_assert(users_search_by_key(users, pub1) == NULL);
	ck_assert(users_search_by_key(users, pub2) == NULL);

	cryptosupport_generate_symmetric_key(symmetricKey1, CRYPTOSUPPORT_AESKEY_SIZE);
	cryptosupport_generate_symmetric_key(symmetricKey2, CRYPTOSUPPORT_AESKEY_SIZE);
	ck_assert(!buffer_equals(symmetricKey1, symmetricKey2));

	users_add_user(users, "one", pub1, symmetricKey1);
	users_add_user(users, "two", pub2, symmetricKey2);
	
	Buffer const * user = users_search_by_key(users, pub1);
	buffer_clear(expected);
	buffer_append_string(expected, "one");
	ck_assert(buffer_equals(user, expected));
	user = users_search_by_key(users, pub2);
	buffer_clear(expected);
	buffer_append_string(expected, "two");
	ck_assert(buffer_equals(user, expected));

	Users * filtered = users_new();

	users_filter_by_name(users, "one", filtered);
	ck_assert(users_search_by_key(filtered, pub2) == NULL);
	user = users_search_by_key(filtered, pub1);
	buffer_clear(expected);
	buffer_append_string(expected, "one");
	ck_assert(buffer_equals(user, expected));

	// Check the correct symmetric keys are returned
	symmetricKey = users_search_symmetrickey_by_key(filtered, pub1);
	ck_assert(buffer_equals(symmetricKey, symmetricKey1));
	symmetricKey = users_search_symmetrickey_by_key(filtered, pub2);
	ck_assert(symmetricKey == NULL);

	users_delete(users);
	users_delete(filtered);
	buffer_delete(expected);
	keypair_delete(keypair1);
	keypair_delete(keypair2);
}
END_TEST

START_TEST (move_users) {
	KeyPair * keypair1 = keypair_new();
	KeyPair * keypair2 = keypair_new();
	keypair_generate(keypair1);
	keypair_generate(keypair2);
	Buffer * expected = buffer_new(0);
	Buffer * symmetricKey1 = buffer_new(0);
	Buffer * symmetricKey2 = buffer_new(0);
	Buffer const * symmetricKey;

	EC_KEY* pub1 = keypair_getpublickey(keypair1);
	EC_KEY* pub2 = keypair_getpublickey(keypair2);

	Users* users = users_new();
	ck_assert(users_search_by_key(users, pub1) == NULL);
	ck_assert(users_search_by_key(users, pub2) == NULL);

	cryptosupport_generate_symmetric_key(symmetricKey1, CRYPTOSUPPORT_AESKEY_SIZE);
	cryptosupport_generate_symmetric_key(symmetricKey2, CRYPTOSUPPORT_AESKEY_SIZE);
	ck_assert(!buffer_equals(symmetricKey1, symmetricKey2));

	users_add_user(users, "one", pub1, symmetricKey1);
	users_add_user(users, "two", pub2, symmetricKey2);
	
	Buffer const * user = users_search_by_key(users, pub1);
	buffer_clear(expected);
	buffer_append_string(expected, "one");
	ck_assert(buffer_equals(user, expected));
	user = users_search_by_key(users, pub2);
	buffer_clear(expected);
	buffer_append_string(expected, "two");
	ck_assert(buffer_equals(user, expected));

	Users * moved = users_new();

	users_move_list(users, moved);
	ck_assert(users_search_by_key(users, pub1) == NULL);
	ck_assert(users_search_by_key(users, pub2) == NULL);
	
	user = users_search_by_key(moved, pub1);
	buffer_clear(expected);
	buffer_append_string(expected, "one");
	ck_assert(buffer_equals(user, expected));
	user = users_search_by_key(moved, pub2);
	buffer_clear(expected);
	buffer_append_string(expected, "two");
	ck_assert(buffer_equals(user, expected));

	// Check the correct symmetric keys are returned
	symmetricKey = users_search_symmetrickey_by_key(moved, pub1);
	ck_assert(buffer_equals(symmetricKey, symmetricKey1));
	symmetricKey = users_search_symmetrickey_by_key(moved, pub2);
	ck_assert(buffer_equals(symmetricKey, symmetricKey2));

	users_delete(users);
	users_delete(moved);
	buffer_delete(expected);
	keypair_delete(keypair1);
	keypair_delete(keypair2);
}
END_TEST

START_TEST (comments) {
	char const * text = EXAMPLE_FILE;
	FILE * output;
	FILE * input;
	int fdoutput;
	int fdinput;
	char * fileout;
	char * filein;
	char * imported;
	Users * users;
	size_t length;
	size_t size;

	// Generate filenames of temporary files to use
	fileout = malloc(sizeof(OUTPUT_FILENAME_TEMPLATE) + 1);
	filein = malloc(sizeof(INPUT_FILENAME_TEMPLATE) + 1);

	strcpy(fileout, OUTPUT_FILENAME_TEMPLATE);
	fdoutput = mkstemps(fileout, 4);
	ck_assert(fdoutput >= 0);

	strcpy(filein, INPUT_FILENAME_TEMPLATE);
	fdinput = mkstemps(filein, 4);
	ck_assert(fdinput >= 0);

	//fprintf(stderr, "Files: %s, %s\n", fileout, filein);

	// Write out the example text to file
	users = users_new();
	output = fdopen(fdoutput, "w");
	ck_assert(output != NULL);
	if (output) {
		fputs(text, output);
		fclose(output);
	}

	// Load the file in as a list of users
	users_load(users, fileout);

	// Export it back out again to a new file
	users_export(users, filein);

	// Copy the contents of the new file to memory
	length = strlen(text);
	size = 0;
	imported = malloc(length + 3);

	input = fdopen(fdinput, "r");
	ck_assert(input != NULL);
	if (input) {
		size = fread(imported, sizeof(char), length + 2, input);
		imported[size] = 0;
		fclose(input);
	}

	// Delete the temporary files
	close(fdoutput);
	close(fdinput);
	unlink(fileout);
	unlink(filein);

	// Check the original text and exported file are the same
	ck_assert_int_eq(size, length);
	ck_assert_str_eq(text, imported);

	// Tidy up like a pro
	users_delete(users);
	free(fileout);
	free(filein);
}
END_TEST


START_TEST (search) {
	char const * text = EXAMPLE_FILE;
	int fdoutput;
	FILE * output;
	char * file;
	Users * users;
	Buffer const * result;
	EC_KEY * pubkey;
	Buffer * base64encoded;
	Buffer * commitment;

	base64encoded = buffer_new(0);
	commitment = buffer_new(0);

	// Generate filneame of temporary file to use
	file = malloc(sizeof(USERS_FILENAME_TEMPLATE) + 1);
	strcpy(file, USERS_FILENAME_TEMPLATE);
	fdoutput = mkstemps(file, 4);
	ck_assert(fdoutput >= 0);

	//fprintf(stderr, "Files: %s\n", file);

	// Write out the example text to file
	users = users_new();
	output = fdopen(fdoutput, "w");
	ck_assert(output != NULL);
	if (output) {
		fputs(text, output);
		fclose(output);
	}

	// Load the file in as a list of users
	users_load(users, file);

	// Search by public key for a particular user
	pubkey = cryptosupport_read_base64_string_public_key("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAELs0ppPjtpliRKkTW7OMKnKsjuZPKS/Ud7KmyDaO6zWeGnuJFRUmZ4eI7INViqliMvRxgnxFYuNkSIXZ9ND6MfA==");
	result = users_search_by_key(users, pubkey);
	ck_assert_str_eq(buffer_get_buffer(result), "Bruch");

	// Search by public key for a user who isn't in the list
	pubkey = cryptosupport_read_base64_string_public_key("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEgGKruBurMBkkdsnwKb2ypN6m0F4xIeCwm26ceE5EnjNgnQMnORfcDa6Cp3LhdZdZKEX1km5YC+yec4MSuFZk0g==");
	result = users_search_by_key(users, pubkey);
	ck_assert(result == NULL);

	// Search by public key for a particular symmetric key
	pubkey = cryptosupport_read_base64_string_public_key("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAENnDeu8fqrxx55e9IyQGlpTl3+JsnVdhi8fjTbaTxablYL+H0aQg3GMc+PgTZorbsPmkLug5LkE/LTI2Ui3cCEQ==");
	result = users_search_symmetrickey_by_key(users, pubkey);
	base64_encode_buffer(result, base64encoded);
	ck_assert_str_eq(buffer_get_buffer(base64encoded), "Lkgxxsd02/VrBPPBdiIkfw==");
	buffer_clear(base64encoded);

	// Search by public key for a symmetric key which doesn't exist
	pubkey = cryptosupport_read_base64_string_public_key("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE6qbtr/25y2BL9LyJgDnE/xgqm1tlQaR15SoVaanoRqLVWd7VxKM+ih4FKSIKyYKpxqm05mYoQ88hmWy645txyQ==");
	result = users_search_symmetrickey_by_key(users, pubkey);
	ck_assert(result == NULL);

	// Search by commitment for a particular user
	buffer_append_string(base64encoded, "nmT9tLLC/fmdniWYy0ee1/UOJwd9qmu0GlSrrV7KFYU=");
	base64_decode_buffer(base64encoded, commitment);
	result = users_search_by_commitment(users, commitment);
	ck_assert_str_eq(buffer_get_buffer(result), "Pachelbel");
	buffer_clear(base64encoded);
	buffer_clear(commitment);

	// Search by commitment for a user who isn't in the list
	buffer_append_string(base64encoded, "NROaN49C9Qyug+RPWEA0dab8zbTP+at0v22rMl6zP9g=");
	base64_decode_buffer(base64encoded, commitment);
	result = users_search_by_commitment(users, commitment);
	ck_assert(result == NULL);
	buffer_clear(base64encoded);
	buffer_clear(commitment);

	// Search by invalid commitment
	buffer_append_string(commitment, "Debussy");
	result = users_search_by_commitment(users, commitment);
	ck_assert(result == NULL);
	buffer_clear(base64encoded);
	buffer_clear(commitment);

	// Delete the temporary files
	close(fdoutput);
	unlink(file);

	// Tidy up like a pro
	users_delete(users);
	buffer_delete(base64encoded);
	buffer_delete(commitment);
	free(file);
}
END_TEST

int main (void) {
	int number_failed;
	Suite * s;
	SRunner *sr;
	TCase * tc;

	s = suite_create("Libpico");

	tc = tcase_create("Users");
	tcase_add_test(tc, add_users);
	tcase_add_test(tc, filter_users);
	tcase_add_test(tc, move_users);
	tcase_add_test(tc, export_users);
	tcase_add_test(tc, comments);
	tcase_add_test(tc, search);
	suite_add_tcase(s, tc);
	sr = srunner_create(s);

	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);

	return (number_failed == 0) ? 0 : -1;
}

