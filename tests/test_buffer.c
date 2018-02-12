/**
 * @file
 * @author cd611@cam.ac.uk 
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
 * @brief Unit tests for the Buffer data type
 * @section DESCRIPTION
 *
 * Performs a variety of unit tests associated with the Buffer data type.
 *
 */

#include <check.h>
#include "pico/buffer.h"

// Defines

// Structure definitions

// Function prototypes

// Function definitions

START_TEST (initial_state) {
	Buffer * b;
	b = buffer_new(0);
	ck_assert(buffer_get_pos(b) == 0);
	ck_assert(buffer_get_size(b) == 2048);
	buffer_delete(b);
	buffer_delete(NULL);
}
END_TEST

START_TEST (append_string) {
	Buffer * b;
	b = buffer_new(3);
	buffer_append_string(b, "1234567890");
	ck_assert_int_eq(buffer_get_pos(b), (unsigned int) 10);
	ck_assert_int_eq(buffer_get_size(b)%3, (unsigned int) 0);
	ck_assert(strncmp(buffer_get_buffer(b), "1234567890", 10) == 0);
	buffer_delete(b);
}
END_TEST

START_TEST (append_buffer) {
	Buffer * b;
	Buffer * b2;
	b = buffer_new(3);
	b2 = buffer_new(3);
	buffer_append_string(b, "12345");
	buffer_append_string(b2, "67890");
	ck_assert_int_eq(buffer_get_pos(b), (unsigned int) 5);
	ck_assert_int_eq(buffer_get_size(b)%3, (unsigned int) 0);
	ck_assert_int_eq(buffer_get_pos(b2), (unsigned int) 5);
	ck_assert_int_eq(buffer_get_size(b2)%3, (unsigned int) 0);

	buffer_append_buffer(b2, b);

	ck_assert(strncmp(buffer_get_buffer(b2), "6789012345", 10) == 0);
	buffer_delete(b);
	buffer_delete(b2);
}
END_TEST

START_TEST (equals) {
	Buffer * b = buffer_new(3);
	Buffer * b2 = buffer_new(3);
	buffer_append_string(b, "1234");
	buffer_append_string(b2, "6789");

	ck_assert(!buffer_equals(b, b2));
	
	buffer_clear(b2);
	buffer_append_string(b2, "1234");
	ck_assert(buffer_equals(b, b2));

	buffer_set_pos(b, 10); 
	ck_assert(!buffer_equals(b, b2));

	buffer_clear(b);	
	ck_assert(!buffer_equals(b, NULL));
	ck_assert(!buffer_equals(NULL, b));
	ck_assert(buffer_equals(NULL, NULL));
	
	buffer_delete(b);
	buffer_delete(b2);
}
END_TEST

START_TEST (length_prepend) {
	Buffer * b;
	Buffer * b2;
	Buffer * b3;
	b = buffer_new(3);
	b2 = buffer_new(3);
	b3 = buffer_new(3);
	buffer_append_string(b2, "67890");
	ck_assert_int_eq(buffer_get_pos(b2), (unsigned int) 5);
	ck_assert_int_eq(buffer_get_size(b2)%3, (unsigned int) 0);

	buffer_append_buffer_lengthprepend(b, b2);

	ck_assert(memcmp(buffer_get_buffer(b), "\x00\x00\x00\x05""67890", 9) == 0);

	buffer_copy_lengthprepend(b, 0, b3);
	ck_assert_int_eq(buffer_get_pos(b3), (unsigned int) 5);
	ck_assert(memcmp(buffer_get_buffer(b3), "67890", 5) == 0);

	buffer_delete(b);
	buffer_delete(b2);
	buffer_delete(b3);
}
END_TEST

START_TEST (truncate) {
	Buffer * b;
	b = buffer_new(3);
	buffer_append_string(b, "1234567890");
	buffer_truncate(b, 6);
	ck_assert_int_eq(buffer_get_pos(b), (unsigned int) 4);
	ck_assert_int_eq(buffer_get_size(b), (unsigned int) 6);
	ck_assert(memcmp(buffer_get_buffer(b), "1234", 4) == 0);
	buffer_delete(b);
}
END_TEST

START_TEST (copy_to_string) {
	Buffer * b;
	char s[5];
	char * ptr;
	int length;
	b = buffer_new(3);
	buffer_append_string(b, "1234567890");
	buffer_copy_to_string(b, s, 5);
	ck_assert_str_eq(s, "1234");
	ptr = buffer_copy_to_new_string(b);
	ck_assert_str_eq(ptr, "1234567890");
	free(ptr);

	buffer_clear(b);
	buffer_append_string(b, "papaya");

	length = buffer_copy_to_string(b, NULL, 0);
	ck_assert_int_eq(length, 0);

	length = buffer_copy_to_string(b, s, 0);
	ck_assert_int_eq(length, 0);

	length = buffer_copy_to_string(b, s, 1);
	ck_assert_int_eq(length, 0);

	length = buffer_copy_to_string(b, s, 2);
	ck_assert_int_eq(length, 1);

	buffer_delete(b);
}
END_TEST

START_TEST (buffer_set_min_size_updates_size) {
	Buffer * b;
	b = buffer_new(3);
	ck_assert(buffer_get_size(b) == 3);
	buffer_set_min_size(b, 10);
	ck_assert(buffer_get_size(b) == 12);
	buffer_set_min_size(b, 5);
	ck_assert(buffer_get_size(b) == 12);
	buffer_delete(b);
}
END_TEST

START_TEST (buffer_format) {
	Buffer * b;
	b = buffer_new(0);
	buffer_sprintf(b, "%s", "Aubergine");
	ck_assert_str_eq(buffer_get_buffer(b), "Aubergine");

	buffer_sprintf(b, "Signed %d, Unsigned %u, hex %x", -88, 33, 11);
	ck_assert_str_eq(buffer_get_buffer(b), "Signed -88, Unsigned 33, hex b");

	buffer_sprintf(b, "");
	ck_assert_str_eq(buffer_get_buffer(b), "");

	buffer_sprintf(b, "Signed %d, Unsigned %u, hex %x", -88, 33, 11);
	ck_assert_str_ne(buffer_get_buffer(b), "Signed -88, Unsigned 33, hex b\n");

	buffer_delete(b);

	b = buffer_new(4);
	buffer_sprintf(b, "%s", "Pico");
	ck_assert_str_eq(buffer_get_buffer(b), "Pico");
}
END_TEST

int main (void) {
	int number_failed;
	Suite * s;
	SRunner *sr;
	TCase * tc;

	s = suite_create("Libpico");

	// Base64 test case
	tc = tcase_create("Buffer");
	tcase_add_test(tc, initial_state);
	tcase_add_test(tc, append_string);
	tcase_add_test(tc, append_buffer);
	tcase_add_test(tc, equals);
	tcase_add_test(tc, length_prepend);
	tcase_add_test(tc, truncate);
	tcase_add_test(tc, copy_to_string);
	tcase_add_test(tc, buffer_set_min_size_updates_size);
	tcase_add_test(tc, buffer_format);
	suite_add_tcase(s, tc);
	sr = srunner_create(s);

	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);

	return (number_failed == 0) ? 0 : -1;
}

