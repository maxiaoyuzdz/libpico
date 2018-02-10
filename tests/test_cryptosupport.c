/**
 * @file
 * @author  David Llewellyn-Jones <David.Llewellyn-Jones@cl.cam.ac.uk>
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
 * @section DESCRIPTION
 *
 * The cryptosupport functions offer various wrappers around the OpenSSL
 * functionality to simplify its operation. Encryption, decryption, signatures,
 * and macs are supported, as well as functionality for encoding and decoding
 * keys in various formats.
 *
 */

#include <check.h>
#include "pico/cryptosupport.h"

// Defines

#if CRYPTOSUPPORT_ECCURVE_SIZE == 192
#define TEST_PUBLICKEY "MEkwEwYHKoZIzj0CAQYIKoZIzj0DAQEDMgAE/AJ/mUliUnnXWdrVL/trZTF9SbZZJHIVk97BwmDyiQeCrZI1rSLj96KnIFYvBT7N"
#define TEST_COMMITMENT "F9chgnYdSm1RoJuThZgzVp4LZXgTBHbLpIuf7R42YU0="
#else
#define TEST_PUBLICKEY "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYouUy+1IdIsIbArJV2vUOSjzHK8MSSGNCIBc9kzbu5POr/CILGv4+Vm/Vm6ZGf1G6HZRjKmMDHsal7dykH6Law=="
#define TEST_COMMITMENT "WOZcMxJB8ODQISpf1f7AymKNUkVORlVdZ+dE6TMMh0I="
#endif


// Structure definitions

// Function prototypes

// Function definitions

START_TEST (check_cryptosupport_getpublicpem) {
	EC_KEY * eckey;
	char const * keystring = TEST_PUBLICKEY;
	Buffer * buffer;
	
	buffer = buffer_new(0);
	// Read in the key
	eckey = cryptosupport_read_base64_string_public_key(keystring);

	// Copy out the key
	cryptosupport_getpublicpem(eckey, buffer);

	// Check they're the same
	ck_assert_msg(strcmp(buffer_get_buffer(buffer), keystring) == 0, "Keys failed to match");

	buffer_delete(buffer);
	EC_KEY_free(eckey);
}
END_TEST

START_TEST (check_cryptosupport_getpublicpem_buffer) {
	EC_KEY * eckey;
	char const * keystring = TEST_PUBLICKEY;
	Buffer * bufferin = buffer_new(0);
	Buffer * bufferout = buffer_new(0);
	
	buffer_append_string(bufferin, keystring);
	
	// Read in the key
	eckey = cryptosupport_read_base64_buffer_public_key(bufferin);

	// Copy out the key
	cryptosupport_getpublicpem(eckey, bufferout);

	// Check they're the same
	ck_assert_msg(strcmp(buffer_get_buffer(bufferout), keystring) == 0, "Keys failed to match");

	buffer_delete(bufferin);
	buffer_delete(bufferout);
	EC_KEY_free(eckey);
}
END_TEST

START_TEST (generate_sha256) {
	Buffer * expected = buffer_new(0);
	Buffer * bufferin = buffer_new(0);
	Buffer * bufferout = buffer_new(0);
	buffer_append(expected, "\xa6\x42\x47\xc1\x97\x9d\x7a\x65\xd4\x75\xbc\x17\x29\x39\x82\x0d\x2a\x7b\x7e\x81\xe4\x9f\x46\x20\x2e\x6f\x56\xe7\x43\x1f\xc2\x14", 32);

	buffer_append_string(bufferin, "mypico.org");

	ck_assert(cryptosupport_generate_sha256(bufferin, bufferout));
	ck_assert_msg(buffer_equals(bufferout, expected), "Hash failed to match");

	buffer_delete(bufferin);
	buffer_delete(bufferout);
	buffer_delete(expected);
}
END_TEST

START_TEST (generate_commitment) {
	EC_KEY * eckey;
	char const * keystring = TEST_PUBLICKEY;
	Buffer * bufferout = buffer_new(0);
	
	eckey = cryptosupport_read_base64_string_public_key(keystring);
	cryptosupport_generate_commitment_base64(eckey, bufferout);
	buffer_append(bufferout, "", 1);

	ck_assert_str_eq(buffer_get_buffer(bufferout), TEST_COMMITMENT);

	buffer_delete(bufferout);
	EC_KEY_free(eckey);
}
END_TEST

START_TEST (symmetric_key) {
	Buffer * symmetricKey1;
	Buffer * symmetricKey2;
	Buffer * iv;
	bool result;
	Buffer * cleartextin;
	Buffer * ciphertext;
	Buffer * cleartextout;

	symmetricKey1 = buffer_new(0);
	symmetricKey2 = buffer_new(0);
	iv = buffer_new(0);
	cleartextin = buffer_new(0);
	ciphertext = buffer_new(0);
	cleartextout = buffer_new(0);

	cryptosupport_generate_symmetric_key(symmetricKey1, CRYPTOSUPPORT_AESKEY_SIZE);
	cryptosupport_generate_symmetric_key(symmetricKey2, CRYPTOSUPPORT_AESKEY_SIZE);

	// Check it generates different keys
	ck_assert(!buffer_equals(symmetricKey1, symmetricKey2));

	// Set up some cleartext
	buffer_clear(cleartextin);
	buffer_append_string(cleartextin, "Cry, as the wild light passes along, 'The Dong!--the Dong!, 'The wandering Dong through the forest goes!, 'The Dong! the Dong!, 'The Dong with a luminous Nose!'");

	// Encrypt some data
	cryptosupport_generate_iv(iv);
	result = cryptosupport_encrypt(symmetricKey1, iv, cleartextin, ciphertext);
	ck_assert(result);
	// Check the cleartext and ciphertext are different
	ck_assert(!buffer_equals(cleartextin, ciphertext));

	// Decrypt the encrypted data
	result = cryptosupport_decrypt(symmetricKey1, iv, ciphertext, cleartextout);
	ck_assert(result);
	// Check the original cleartext and decrypted text are the same
	ck_assert(buffer_equals(cleartextin, cleartextout));

	buffer_delete(symmetricKey1);
	buffer_delete(symmetricKey2);
	buffer_delete(iv);
	buffer_delete(cleartextin);
	buffer_delete(ciphertext);
	buffer_delete(cleartextout);

}
END_TEST

START_TEST (encrypt_iv_base64) {
	bool result;
	Buffer * key;
	Buffer * cleartext;
	Buffer * ciphertext;
	Buffer * decrypted;

	key = buffer_new(0);
	cleartext = buffer_new(0);
	ciphertext = buffer_new(0);
	decrypted = buffer_new(0);

	result = cryptosupport_generate_symmetric_key(key, CRYPTOSUPPORT_AESKEY_SIZE);
	ck_assert(result);

	buffer_clear(cleartext);
	buffer_append_string(cleartext, "sdjflskdjfslkjd");

	result = cryptosupport_encrypt_iv_base64(key, cleartext, ciphertext);
	ck_assert(result);
	ck_assert(!buffer_equals(cleartext, ciphertext));

	result = cryptosupport_decrypt_iv_base64(key, ciphertext, decrypted);
	ck_assert(result);
	ck_assert(buffer_equals(cleartext, decrypted));
}
END_TEST

int main (void) {
	int number_failed;
	Suite * s;
	SRunner *sr;
	TCase * tc;

	s = suite_create("Libpico");

	// Base64 test case
	tc = tcase_create("Cryptosupport");
	tcase_add_test(tc, check_cryptosupport_getpublicpem);
	tcase_add_test(tc, check_cryptosupport_getpublicpem_buffer);
	tcase_add_test(tc, generate_sha256);
	tcase_add_test(tc, generate_commitment);
	tcase_add_test(tc, symmetric_key);
	tcase_add_test(tc, encrypt_iv_base64);
	suite_add_tcase(s, tc);
	sr = srunner_create(s);

	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);

	return (number_failed == 0) ? 0 : -1;
}

