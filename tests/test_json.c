/**
 * @file
 * @author  cd611@cam.ac.uk
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
 * @brief Unit tests for the Json data type
 * @section DESCRIPTION
 *
 * Performs a variety of unit tests associated with the Json data type.
 *
 *
 */

#include <check.h>
#include "pico/json.h"

// Defines

// Structure definitions

// Function prototypes

// Function definitions

void test_serialize(Json * json, char * expected) {
	size_t size = json_serialize_size(json);
	char* serialized = malloc(size+1);
	json_serialize(json, serialized, size+1);
	serialized[size] = '\0';
	ck_assert_str_eq(serialized, expected);
	free(serialized);
}

START_TEST (add_string) {
	Json * json = json_new();

	json_add_string(json, "mystr", "value");
	test_serialize(json, "{\"mystr\":\"value\"}");

	json_add_string(json, "mystr", "value2");
	test_serialize(json, "{\"mystr\":\"value2\"}");

	json_add_string(json, "a", "b");
	test_serialize(json, "{\"a\":\"b\",\"mystr\":\"value2\"}");

	json_delete(json);
}
END_TEST

START_TEST (sublist_serialize) {
	Json * json = json_new();
	Json * json2 = json_new();

	json_add_integer(json, "one", 1);
	json_add_integer(json, "two", 2);
	json_add_integer(json2, "one", 1);
	json_add_sublist(json2, "sub", json);
	test_serialize(json2, "{\"sub\":{\"two\":2,\"one\":1},\"one\":1}");

	json_delete(json);
	json_delete(json2);
}
END_TEST

START_TEST (sublist_deserialize) {
	Json * json = json_new();
	char* jsonstr = "{\"one\":1,\"sub\":{\"one\":1,\"two\":2}}";

	json_deserialize_string(json, jsonstr, strlen(jsonstr));
	test_serialize(json, jsonstr);

	json_delete(json);
}
END_TEST

START_TEST (deserialize_spaces) {
	Json * json = json_new();
	char* jsonstr = "{\"one\":1,   \"sub\":  {  \"one\" : 1 , \"two\" : 2}  }";
	char* jsonexpected = "{\"one\":1,\"sub\":{\"one\":1,\"two\":2}}";

	json_deserialize_string(json, jsonstr, strlen(jsonstr));
	test_serialize(json, jsonexpected);

	json_delete(json);
}
END_TEST

START_TEST (override_values) {
	Json * json = json_new();
	Json * json2 = json_new();
	Json * json3 = json_new();

	json_add_integer(json, "a", 1);
	test_serialize(json, "{\"a\":1}");
	json_add_integer(json, "a", 2);
	test_serialize(json, "{\"a\":2}");
	json_add_integer(json2, "b", 1);
	json_add_sublist(json, "a", json2);
	json_add_integer(json2, "b", 1);
	test_serialize(json, "{\"a\":{\"b\":1}}");
	json_add_integer(json, "a", 1);
	test_serialize(json, "{\"a\":1}");
	json_add_string(json, "a", "str");
	test_serialize(json, "{\"a\":\"str\"}");
	json_add_string(json, "a", "str2");
	test_serialize(json, "{\"a\":\"str2\"}");
	json_add_integer(json2, "b", 1);
	json_add_sublist(json, "a", json2);
	test_serialize(json, "{\"a\":{\"b\":1}}");
	json_add_integer(json3, "c", 2);
	json_add_sublist(json, "a", json3);
	test_serialize(json, "{\"a\":{\"c\":2}}");
	json_add_string(json, "a", "str2");
	test_serialize(json, "{\"a\":\"str2\"}");
	json_add_integer(json, "a", 2);
	test_serialize(json, "{\"a\":2}");

	json_delete(json);
	json_delete(json2);
	json_delete(json3);
}
END_TEST

START_TEST (deserialized_datatypes) {
	char const * serialized = "{\"integer\":1, \"decimal\": 0.321, \"number\":1.000, \"string\":\"I hate unit tests\", \"sublist\":{\"integer\":\"poorly named variable\"}}";
	Json * json = json_new();
	JSONTYPE type = JSONTYPE_INVALID;
	bool result;
	int integer;
	double decimal;
	char const * string;

	result = json_deserialize_string(json, serialized, strlen(serialized));
	ck_assert(result);

	// Check integers work as expected
	type = json_get_type(json, "integer");
	ck_assert_int_eq(type, JSONTYPE_INTEGER);

	integer = json_get_integer(json, "integer");
	ck_assert_int_eq(integer, 1);

	decimal = json_get_number(json, "integer");
	ck_assert(decimal == 1.0);

	decimal = json_get_decimal(json, "integer");
	ck_assert(decimal == 0.0);

	string = json_get_string(json, "integer");
	ck_assert(string == NULL);

	// Check decimals work as expected
	type = json_get_type(json, "decimal");
	ck_assert_int_eq(type, JSONTYPE_DECIMAL);

	decimal = json_get_decimal(json, "decimal");
	ck_assert(decimal == 0.321);

	decimal = json_get_number(json, "decimal");
	ck_assert(decimal == 0.321);

	integer = json_get_integer(json, "decimal");
	ck_assert_int_eq(integer, 0);

	string = json_get_string(json, "decimal");
	ck_assert(string == NULL);

	// Check decimals that look like integers work as expected
	type = json_get_type(json, "number");
	ck_assert_int_eq(type, JSONTYPE_DECIMAL);

	decimal = json_get_decimal(json, "number");
	ck_assert(decimal == 1.00);

	decimal = json_get_number(json, "number");
	ck_assert(decimal == 1.00);

	integer = json_get_integer(json, "number");
	ck_assert_int_eq(integer, 0);

	string = json_get_string(json, "number");
	ck_assert(string == NULL);

	// Check strings work as expected
	type = json_get_type(json, "string");
	ck_assert_int_eq(type, JSONTYPE_STRING);

	decimal = json_get_decimal(json, "string");
	ck_assert(decimal == 0.00);

	decimal = json_get_number(json, "string");
	ck_assert(decimal == 0.00);

	integer = json_get_integer(json, "string");
	ck_assert_int_eq(integer, 0);

	string = json_get_string(json, "string");
	ck_assert_str_eq(string, "I hate unit tests");

	// Check sublists work as expected
	type = json_get_type(json, "sublist");
	ck_assert_int_eq(type, JSONTYPE_SUBLIST);

	json_delete(json);
}
END_TEST

START_TEST (datatypes) {
	char const * serialized = "{\"integer\":\"poorly named variable\"}";
	Json * json = json_new();
	Json * sublist = json_new();
	JSONTYPE type = JSONTYPE_INVALID;
	bool result;
	int integer;
	double decimal;
	char const * string;

	json_add_integer(json, "integer", 1);
	json_add_decimal(json, "decimal", 0.321);
	json_add_string(json, "string", "I hate unit tests");

	result = json_deserialize_string(sublist, serialized, strlen(serialized));
	ck_assert(result);

	json_add_sublist(json, "sublist", sublist);

	// Check integers work as expected
	type = json_get_type(json, "integer");
	ck_assert_int_eq(type, JSONTYPE_INTEGER);

	integer = json_get_integer(json, "integer");
	ck_assert_int_eq(integer, 1);

	decimal = json_get_number(json, "integer");
	ck_assert(decimal == 1.0);

	decimal = json_get_decimal(json, "integer");
	ck_assert(decimal == 0.0);

	string = json_get_string(json, "integer");
	ck_assert(string == NULL);

	// Check decimals work as expected
	type = json_get_type(json, "decimal");
	ck_assert_int_eq(type, JSONTYPE_DECIMAL);

	decimal = json_get_decimal(json, "decimal");
	ck_assert(decimal == 0.321);

	decimal = json_get_number(json, "decimal");
	ck_assert(decimal == 0.321);

	integer = json_get_integer(json, "decimal");
	ck_assert_int_eq(integer, 0);

	string = json_get_string(json, "decimal");
	ck_assert(string == NULL);

	// Check strings work as expected
	type = json_get_type(json, "string");
	ck_assert_int_eq(type, JSONTYPE_STRING);

	decimal = json_get_decimal(json, "string");
	ck_assert(decimal == 0.00);

	decimal = json_get_number(json, "string");
	ck_assert(decimal == 0.00);

	integer = json_get_integer(json, "string");
	ck_assert_int_eq(integer, 0);

	string = json_get_string(json, "string");
	ck_assert_str_eq(string, "I hate unit tests");

	// Check sublists work as expected
	type = json_get_type(json, "sublist");
	ck_assert_int_eq(type, JSONTYPE_SUBLIST);

	json_delete(json);
	json_delete(sublist);
}
END_TEST

START_TEST (escaping) {
	Json * json;
	char const * string;
	char * serialized;
	size_t length;

	// Check for quotes
	json = json_new();
	json_add_string(json, "string", "\"Be yourself, everyone else is already taken\"");

	string = json_get_string(json, "string");
	ck_assert_str_eq(string, "\"Be yourself, everyone else is already taken\"");

	length = json_serialize_size(json);
	ck_assert_int_eq(length, 60);
	serialized = calloc(length + 1, sizeof(char));
	length = json_serialize(json, serialized, length + 1);
	ck_assert_str_eq(serialized, "{\"string\":\"\\\"Be yourself, everyone else is already taken\\\"\"}");
	free(serialized);
	json_delete(json);

	// Backslash
	json = json_new();
	json_add_string(json, "string", "backslash \\");

	string = json_get_string(json, "string");
	ck_assert_str_eq(string, "backslash \\");

	length = json_serialize_size(json);
	ck_assert_int_eq(length, 25);
	serialized = calloc(length + 1, sizeof(char));
	length = json_serialize(json, serialized, length + 1);
	ck_assert_str_eq(serialized, "{\"string\":\"backslash \\\\\"}");
	free(serialized);
	json_delete(json);

	// Backspace
	json = json_new();
	json_add_string(json, "string", "backspace \b");

	string = json_get_string(json, "string");
	ck_assert_str_eq(string, "backspace \b");

	length = json_serialize_size(json);
	ck_assert_int_eq(length, 25);
	serialized = calloc(length + 1, sizeof(char));
	length = json_serialize(json, serialized, length + 1);
	ck_assert_str_eq(serialized, "{\"string\":\"backspace \\b\"}");
	free(serialized);
	json_delete(json);

	// Formfeed
	json = json_new();
	json_add_string(json, "string", "formfeed \f");

	string = json_get_string(json, "string");
	ck_assert_str_eq(string, "formfeed \f");

	length = json_serialize_size(json);
	ck_assert_int_eq(length, 24);
	serialized = calloc(length + 1, sizeof(char));
	length = json_serialize(json, serialized, length + 1);
	ck_assert_str_eq(serialized, "{\"string\":\"formfeed \\f\"}");
	free(serialized);
	json_delete(json);

	// Newline
	json = json_new();
	json_add_string(json, "string", "newline \n");

	string = json_get_string(json, "string");
	ck_assert_str_eq(string, "newline \n");

	length = json_serialize_size(json);
	ck_assert_int_eq(length, 23);
	serialized = calloc(length + 1, sizeof(char));
	length = json_serialize(json, serialized, length + 1);
	ck_assert_str_eq(serialized, "{\"string\":\"newline \\n\"}");
	free(serialized);
	json_delete(json);

	// Return
	json = json_new();
	json_add_string(json, "string", "return \r");

	string = json_get_string(json, "string");
	ck_assert_str_eq(string, "return \r");

	length = json_serialize_size(json);
	ck_assert_int_eq(length, 22);
	serialized = calloc(length + 1, sizeof(char));
	length = json_serialize(json, serialized, length + 1);
	ck_assert_str_eq(serialized, "{\"string\":\"return \\r\"}");
	free(serialized);
	json_delete(json);

	// Tab
	json = json_new();
	json_add_string(json, "string", "tab \t");

	string = json_get_string(json, "string");
	ck_assert_str_eq(string, "tab \t");

	length = json_serialize_size(json);
	ck_assert_int_eq(length, 19);
	serialized = calloc(length + 1, sizeof(char));
	length = json_serialize(json, serialized, length + 1);
	ck_assert_str_eq(serialized, "{\"string\":\"tab \\t\"}");
	free(serialized);
	json_delete(json);
}
END_TEST

START_TEST (unescaping) {
	Json * json;
	char const * serialized = "{\"quotes\":\"quotes \\\"\",\"backslash\":\"backslash \\\\\",\"backspace\":\"backspace \\b\",\"formfeed\":\"formfeed \\f\",\"newline\":\"newline \\n\",\"return\":\"return \\r\",\"tab\":\"tab \\t\"}";
	char const * string;
	bool result;

	// Check for quotes
	json = json_new();

	result = json_deserialize_string(json, serialized, strlen(serialized));
	ck_assert(result);

	string = json_get_string(json, "quotes");
	ck_assert_str_eq(string, "quotes \"");

	string = json_get_string(json, "backslash");
	ck_assert_str_eq(string, "backslash \\");

	string = json_get_string(json, "backspace");
	ck_assert_str_eq(string, "backspace \b");

	string = json_get_string(json, "formfeed");
	ck_assert_str_eq(string, "formfeed \f");

	string = json_get_string(json, "newline");
	ck_assert_str_eq(string, "newline \n");

	string = json_get_string(json, "return");
	ck_assert_str_eq(string, "return \r");

	string = json_get_string(json, "tab");
	ck_assert_str_eq(string, "tab \t");

	json_delete(json);
}
END_TEST

START_TEST (empty) {
	Json * json;
	char const * empty = "{}";
	char * serialized;
	bool result;
	size_t length;

	json = json_new();

	// Check validity of empty JSON string
	result = json_deserialize_string(json, empty, strlen(empty));
	ck_assert(result);

	length = json_serialize_size(json);
	ck_assert_int_eq(length, 2);
	serialized = calloc(length + 1, sizeof(char));
	length = json_serialize(json, serialized, length + 1);
	ck_assert_str_eq(serialized, "{}");
	free(serialized);

	// Check validity of empty string
	result = json_deserialize_string(json, "", strlen(""));
	ck_assert(result);

	length = json_serialize_size(json);
	ck_assert_int_eq(length, 2);
	serialized = calloc(length + 1, sizeof(char));
	length = json_serialize(json, serialized, length + 1);
	ck_assert_str_eq(serialized, "{}");
	free(serialized);

	// Check validity of NULL string
	result = json_deserialize_string(json, NULL, 0);
	ck_assert(result);

	length = json_serialize_size(json);
	ck_assert_int_eq(length, 2);
	serialized = calloc(length + 1, sizeof(char));
	length = json_serialize(json, serialized, length + 1);
	ck_assert_str_eq(serialized, "{}");
	free(serialized);

	json_delete(json);
}
END_TEST

int main (void) {
	int number_failed;
	Suite * s;
	SRunner *sr;
	TCase * tc;

	s = suite_create("Libpico");

	tc = tcase_create("Json");
	tcase_add_test(tc, add_string);
	tcase_add_test(tc, sublist_serialize);
	tcase_add_test(tc, sublist_deserialize);
	tcase_add_test(tc, deserialize_spaces);
	tcase_add_test(tc, override_values);
	tcase_add_test(tc, deserialized_datatypes);
	tcase_add_test(tc, datatypes);
	tcase_add_test(tc, escaping);
	tcase_add_test(tc, unescaping);
	tcase_add_test(tc, empty);
	suite_add_tcase(s, tc);
	sr = srunner_create(s);

	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);

	return (number_failed == 0) ? 0 : -1;
}

