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
#include "pico/base64.h"

// Defines

// Structure definitions

// Function prototypes

// Function definitions

START_TEST (check_base64) {
	char const * plain[3] = {"Checking", "1234567", "qwe"};
	char const * b64[3] = {"Q2hlY2tpbmc=", "MTIzNDU2Nw==", "cXdl"};
	Buffer * generated;
	int i;

	generated = buffer_new(0);

	for (i = 0; i < 3; i++) {
		buffer_clear(generated);
		base64_encode_string(plain[i], generated);
		buffer_append(generated, "", 1);
		// Check they're the same
		ck_assert_str_eq(buffer_get_buffer(generated), b64[i]);

		buffer_clear(generated);
		base64_decode_string(b64[i], generated);
		buffer_append(generated, "", 1);
		// Check they're the same
		ck_assert_str_eq(buffer_get_buffer(generated), plain[i]);
	}

	buffer_delete(generated);
}
END_TEST

START_TEST(encode_buffer) {
	char const * plain[3] = {"Checking", "1234567", "qwe"};
	char const * b64[3] = {"Q2hlY2tpbmc=", "MTIzNDU2Nw==", "cXdl"};
	Buffer * generated;
	Buffer * plainbuf;
	Buffer * b64buf;
	int i;

	generated = buffer_new(0);
	plainbuf = buffer_new(0);
	b64buf = buffer_new(0);

	for (i = 0; i < 3; i++) {
		buffer_clear(generated);
		buffer_clear(plainbuf);
		buffer_clear(b64buf);
		buffer_append_string(plainbuf, plain[i]);
		buffer_append_string(b64buf, b64[i]);

		base64_encode_buffer(plainbuf, generated);
		ck_assert(buffer_equals(b64buf, generated));

		buffer_clear(generated);
		base64_decode_buffer(b64buf, generated);
		ck_assert(buffer_equals(plainbuf, generated));
	}

	buffer_delete(generated);
	buffer_delete(plainbuf);
	buffer_delete(b64buf);
}
END_TEST

int main (void) {
	int number_failed;
	Suite * s;
	SRunner *sr;
	TCase * tc;

	s = suite_create("Libpico");

	// Base64 test case
	tc = tcase_create("Base64");
	tcase_add_test(tc, check_base64);
	tcase_add_test(tc, encode_buffer);
	suite_add_tcase(s, tc);
	sr = srunner_create(s);

	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);

	return (number_failed == 0) ? 0 : -1;
}

