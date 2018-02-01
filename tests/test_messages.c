/**
 * @file
 * @author Claudio Dettoni <cd611@cl.cam.ac.uk>
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
 * @brief Unit tests for the message
 */

#include <check.h>
#include "pico/messagepicoreauth.h"
#include "pico/messageservicereauth.h"

// Defines

// Structure definitions

// Function prototypes

// Function definitions

START_TEST (test_messagepicoreauth) {
	MessagePicoReAuth * msg;
	Buffer * sharedKey;
	SequenceNumber* sequenceNumber;
	SequenceNumber* sequenceNumberCopy;
	SequenceNumber* sequenceNumberRecovered;
	Buffer * extraData;
	Buffer * json;

	sharedKey = buffer_new(0);
	buffer_append(sharedKey, "\x00\x01\x02\x03\x04\x05", 6);
	sequenceNumber = sequencenumber_new();
	sequenceNumberCopy = sequencenumber_new();
	sequenceNumberRecovered = sequencenumber_new();
	sequencenumber_random(sequenceNumber);
	sequencenumber_copy(sequenceNumberCopy, sequenceNumber);
	extraData = buffer_new(0);
	buffer_append(extraData, "Extra", 5);
	json = buffer_new(0);

	msg = messagepicoreauth_new();
	messagepicoreauth_set(msg, sharedKey, sequenceNumber);
	messagepicoreauth_set_reauthstate(msg, REAUTHSTATE_PAUSE);
	messagepicoreauth_serialize(msg, extraData, json);

	ck_assert(buffer_get_pos(json) > 0);
	messagepicoreauth_delete(msg);
	
	msg = messagepicoreauth_new();
	messagepicoreauth_set(msg, sharedKey, NULL);
	messagepicoreauth_deserialize(msg, json);

	ck_assert_str_eq(buffer_get_buffer(messagepicoreauth_get_extra_data(msg)), "Extra");
	ck_assert(messagepicoreauth_get_reauthstate(msg) == REAUTHSTATE_PAUSE);
	messagepicoreauth_get_sequencenum(msg, sequenceNumberRecovered);
	ck_assert(sequencenumber_equals(sequenceNumberRecovered, sequenceNumberCopy));

	buffer_delete(sharedKey);
	sequencenumber_delete(sequenceNumber);
	sequencenumber_delete(sequenceNumberCopy);
	sequencenumber_delete(sequenceNumberRecovered);
	messagepicoreauth_delete(msg);
	buffer_delete(json);
	buffer_delete(extraData);
}
END_TEST

START_TEST (test_messageservicereauth) {
	MessageServiceReAuth * msg;
	Buffer * sharedKey;
	SequenceNumber* sequenceNumber;
	SequenceNumber* sequenceNumberCopy;
	SequenceNumber* sequenceNumberRecovered;
	Buffer * extraData;
	Buffer * json;

	sharedKey = buffer_new(0);
	buffer_append(sharedKey, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f", 16);
	sequenceNumber = sequencenumber_new();
	sequenceNumberCopy = sequencenumber_new();
	sequenceNumberRecovered = sequencenumber_new();
	sequencenumber_random(sequenceNumber);
	sequencenumber_copy(sequenceNumberCopy, sequenceNumber);
	extraData = buffer_new(0);
	buffer_append(extraData, "Extra", 5);
	json = buffer_new(0);

	msg = messageservicereauth_new();
	messageservicereauth_set(msg, sharedKey, 123, REAUTHSTATE_STOP, sequenceNumber);
	messageservicereauth_set_extra_data(msg, extraData);
	messageservicereauth_serialize(msg, json);

	buffer_print(json);

	ck_assert(buffer_get_pos(json) > 0);
	messageservicereauth_delete(msg);
	
	msg = messageservicereauth_new();
	messageservicereauth_set(msg, sharedKey, 0, REAUTHSTATE_INVALID, NULL);
	messageservicereauth_deserialize(msg, json);

	ck_assert(messageservicereauth_get_reauthstate(msg) == REAUTHSTATE_STOP);
	ck_assert(messageservicereauth_get_timeout(msg) == 123);
	messageservicereauth_get_sequencenum(msg, sequenceNumberRecovered);
	ck_assert(sequencenumber_equals(sequenceNumberRecovered, sequenceNumberCopy));
	ck_assert_str_eq(buffer_get_buffer(messageservicereauth_get_extra_data(msg)), "Extra");

	buffer_delete(sharedKey);
	sequencenumber_delete(sequenceNumber);
	sequencenumber_delete(sequenceNumberRecovered);
	sequencenumber_delete(sequenceNumberCopy);
	messageservicereauth_delete(msg);
	buffer_delete(json);
	buffer_delete(extraData);
}
END_TEST

START_TEST (test_deserialize_messageservicereauth_without_extra_data) {
	MessageServiceReAuth * msg;
	Buffer * sharedKey;
	SequenceNumber* sequenceNumberExpected;
	SequenceNumber* sequenceNumberRecovered;
	Buffer * expectedNumberBuf;
	Buffer * json;

	sequenceNumberRecovered = sequencenumber_new();
	sequenceNumberExpected = sequencenumber_new();
	sharedKey = buffer_new(0);
	buffer_append(sharedKey, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f", 16);
	json = buffer_new(0);
	buffer_append_string(json, "{\"iv\":\"YlGac7bdxNNWcToeNw3Xsg==\",\"encryptedData\":\"uFmElztl5yBtd79Cp651v5OX9YmIQ3BQ7N8tjhf/ShYNCu0fuLolmdqhog+pH2swMTh/jxXaajV0\",\"sessionId\":0}");
	expectedNumberBuf = buffer_new(0);
	buffer_append(expectedNumberBuf, "\x3c\x3e\xbe\x5b\xf7\xd9\x08\xa1\xde\x02\x77\x51\xf4\xdf\x86\x46\x6c\x4a\xde\x6e\x48\x67\x83\xa6\x64\xaf\xda\x56\x0d\x9e\x69\xde", 32);
	sequencenumber_transfer_from_buffer(sequenceNumberExpected, expectedNumberBuf);
	
	msg = messageservicereauth_new();
	messageservicereauth_set(msg, sharedKey, 0, REAUTHSTATE_INVALID, NULL);
	ck_assert(messageservicereauth_deserialize(msg, json));

	ck_assert(messageservicereauth_get_reauthstate(msg) == REAUTHSTATE_STOP);
	ck_assert(messageservicereauth_get_timeout(msg) == 123);
	messageservicereauth_get_sequencenum(msg, sequenceNumberRecovered);
	sequencenumber_print(sequenceNumberRecovered);
	sequencenumber_print(sequenceNumberExpected);
	ck_assert(sequencenumber_equals(sequenceNumberRecovered, sequenceNumberExpected));

	buffer_delete(sharedKey);
	buffer_delete(expectedNumberBuf);
	sequencenumber_delete(sequenceNumberRecovered);
	sequencenumber_delete(sequenceNumberExpected);
	messageservicereauth_delete(msg);
	buffer_delete(json);
}
END_TEST

int main (void) {
	int number_failed;
	Suite * s;
	SRunner *sr;
	TCase * tc;

	s = suite_create("Libpico");

	// Base64 test case
	tc = tcase_create("Messages");
	tcase_add_test(tc, test_messagepicoreauth);
	tcase_add_test(tc, test_messageservicereauth);
	tcase_add_test(tc, test_deserialize_messageservicereauth_without_extra_data);
	suite_add_tcase(s, tc);
	sr = srunner_create(s);

	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);

	return (number_failed == 0) ? 0 : -1;
}

