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
 * @brief Unit tests for the Continuous data type
 * @section DESCRIPTION
 *
 * Performs a variety of unit tests associated with the Continuous data type.
 *
 */

#include <check.h>
#include <pthread.h>
#include "pico/continuous.h"
#include <unistd.h>

// Defines
//
// Structure definitions
typedef struct {
	char channel_name[128];
} PicoThreadData;

// Function prototypes

// Function definitions

static char const * const pico_data[] = {"one", "two", NULL, "four", NULL, "six", "seven"};
static char const * const service_data[] = {"ten", "eleven", NULL, NULL, "fourteen", "fifteen", "sixteen"};
static int pico_data_pos_sent;
static int pico_data_pos_received;
static int service_data_pos_sent;
static int service_data_pos_received;

Buffer const * pico_update_extradata(Buffer * extraData) {
	Buffer const * extraDataOrNull;

	ck_assert(pico_data_pos_sent < 7);
	buffer_clear(extraData);
	if (pico_data[pico_data_pos_sent] != NULL) {
		buffer_append_string(extraData, pico_data[pico_data_pos_sent]);
		extraDataOrNull = extraData;
	}
	else {
		extraDataOrNull = NULL;
	}
	pico_data_pos_sent++;

	return extraDataOrNull;
}

void pico_check_extradata(Buffer const * returnedStoredData) {
	char const * data;

	data = buffer_get_buffer(returnedStoredData);

	ck_assert(pico_data_pos_received < 7);
	if (service_data[pico_data_pos_received] != NULL) {
		ck_assert_str_eq(data, service_data[pico_data_pos_received]);
	}
	else {
		ck_assert_str_eq(data, "");
	}
	pico_data_pos_received++;
}

Buffer const * service_update_extradata(Buffer * extraData) {
	Buffer const * extraDataOrNull;

	ck_assert(service_data_pos_sent < 7);
	buffer_clear(extraData);
	if (service_data[service_data_pos_sent] != NULL) {
		buffer_append_string(extraData, service_data[service_data_pos_sent]);
		extraDataOrNull = extraData;
	}
	else {
		extraDataOrNull = NULL;
	}
	service_data_pos_sent++;

	return extraDataOrNull;
}

void service_check_extradata(Buffer const * returnedStoredData) {
	char const * data;
	
	data = buffer_get_buffer(returnedStoredData);

	ck_assert(service_data_pos_received < 7);
	if (pico_data[service_data_pos_received] != NULL) {
		ck_assert_str_eq(data, pico_data[service_data_pos_received]);
	}
	else {
		ck_assert_str_eq(data, "");
	}
	service_data_pos_received++;
}

START_TEST (continuous_constructor_test) {
	RVPChannel * channel = channel_new();
	Continuous * continuous = continuous_new();

	ck_assert(channel != NULL);
	continuous_set_channel(continuous, channel);
	ck_assert(continuous_get_channel(continuous) == channel);

	Buffer * sharedkey = buffer_new(0);
	buffer_append(sharedkey, "\x00\x01\x02\x03\x04\x05", 6);

	continuous_set_shared_key(continuous, sharedkey);
	Buffer * returnedKey = buffer_new(0);
	continuous_get_shared_key(continuous, returnedKey);

	ck_assert(buffer_equals(sharedkey, returnedKey));

	buffer_delete(sharedkey);
	buffer_delete(returnedKey);
	channel_delete(channel);
	continuous_delete(continuous);
}
END_TEST

void * pico_main(void * thread_data) {
	sleep(0.5);
	PicoThreadData * data = (PicoThreadData*) thread_data;
	int timeout;
	Buffer * extraData;
	Buffer * returnedStoredData;
	Buffer const * extraDataOrNull;

	extraData = buffer_new(0);
	returnedStoredData = buffer_new(0);

	pico_data_pos_sent = 0;
	pico_data_pos_received = 0;

	Buffer * sharedkey = buffer_new(0);
	buffer_append(sharedkey, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f", 16);
	RVPChannel * channel = channel_connect(data->channel_name);
	Continuous * continuous = continuous_new();
	continuous_set_channel(continuous, channel);
	continuous_set_shared_key(continuous, sharedkey);
	continuous_set_custom_timeout_leeway(continuous, 500);

	extraDataOrNull = pico_update_extradata(extraData);
	continuous_cycle_start_pico(continuous, extraDataOrNull, returnedStoredData);
	pico_check_extradata(returnedStoredData);

	extraDataOrNull = pico_update_extradata(extraData);
	continuous_reauth_pico(continuous, extraDataOrNull, returnedStoredData, NULL);
	ck_assert(continuous_get_state(continuous) == REAUTHSTATE_CONTINUE);
	pico_check_extradata(returnedStoredData);
	
	extraDataOrNull = pico_update_extradata(extraData);
	bool result = continuous_continue_pico(continuous, extraDataOrNull, returnedStoredData, NULL);
	ck_assert(result);
	pico_check_extradata(returnedStoredData);
	
	extraDataOrNull = pico_update_extradata(extraData);
	continuous_reauth_pico(continuous, extraDataOrNull, returnedStoredData, &timeout);
	ck_assert(continuous_get_state(continuous) == REAUTHSTATE_PAUSE);
	ck_assert_int_eq(timeout, 1500);
	pico_check_extradata(returnedStoredData);

	extraDataOrNull = pico_update_extradata(extraData);
	continuous_reauth_pico(continuous, extraDataOrNull, returnedStoredData, &timeout);
	ck_assert(continuous_get_state(continuous) == REAUTHSTATE_CONTINUE);
	ck_assert_int_eq(timeout, 1500);
	pico_check_extradata(returnedStoredData);
	
	extraDataOrNull = pico_update_extradata(extraData);
	continuous_reauth_pico(continuous, extraDataOrNull, returnedStoredData, &timeout);
	ck_assert(continuous_get_state(continuous) == REAUTHSTATE_STOP);
	ck_assert_int_eq(timeout, 0);
	pico_check_extradata(returnedStoredData);

	continuous_finish(continuous);

	return NULL;
}

void get_allocated_channel_name(char const * channel_url_const, char * out) {
	char * channel_url = malloc(strlen(channel_url_const) + 1);
	strcpy(channel_url, channel_url_const);
	char* channel_name = strtok(channel_url, "/");
	channel_name = strtok(NULL, "/");
	channel_name = strtok(NULL, "/");
	channel_name = strtok(NULL, "/");
	strcpy(out, channel_name);
	free(channel_url);
}

START_TEST (continuous_test) {
	PicoThreadData thread_data;
	RVPChannel * channel = channel_new();
	Continuous * continuous = continuous_new();
	Buffer * channel_buffer = buffer_new(0);
	Buffer * sharedkey = buffer_new(0);
	Buffer * extraData;
	Buffer * returnedStoredData;
	Buffer const * extraDataOrNull;

	buffer_append(sharedkey, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f", 16);

	extraData = buffer_new(0);
	returnedStoredData = buffer_new(0);

	service_data_pos_sent = 0;
	service_data_pos_received = 0;

	ck_assert(channel != NULL);
	continuous_set_channel(continuous, channel);
	continuous_set_shared_key(continuous, sharedkey);

	channel_get_url(channel, channel_buffer);
	buffer_append(channel_buffer, "", 1);

	get_allocated_channel_name(buffer_get_buffer(channel_buffer), thread_data.channel_name);

	pthread_t pico_td;
	pthread_create(&pico_td, NULL, pico_main, &thread_data);

	extraDataOrNull = service_update_extradata(extraData);
	continuous_set_custom_timeout(continuous, 2000, 2000);
	bool result = continuous_cycle_start(continuous, extraDataOrNull, returnedStoredData);
	ck_assert(result);
	service_check_extradata(returnedStoredData);

	extraDataOrNull = service_update_extradata(extraData);
	continuous_reauth(continuous, extraDataOrNull, returnedStoredData);
	ck_assert(continuous_get_state(continuous) == REAUTHSTATE_CONTINUE);
	service_check_extradata(returnedStoredData);
	
	extraDataOrNull = service_update_extradata(extraData);
	result = continuous_continue(continuous, extraDataOrNull, returnedStoredData);
	ck_assert(result);
	service_check_extradata(returnedStoredData);

	extraDataOrNull = service_update_extradata(extraData);
	continuous_read_pico_reauth(continuous, NULL, returnedStoredData);
	continuous_update_state(continuous, REAUTHSTATE_PAUSE, extraDataOrNull);
	ck_assert(continuous_get_state(continuous) == REAUTHSTATE_PAUSE);
	service_check_extradata(returnedStoredData);

	extraDataOrNull = service_update_extradata(extraData);
	continuous_read_pico_reauth(continuous, NULL, returnedStoredData);
	continuous_update_state(continuous, REAUTHSTATE_CONTINUE, extraDataOrNull);
	ck_assert(continuous_get_state(continuous) == REAUTHSTATE_CONTINUE);
	service_check_extradata(returnedStoredData);
	
	extraDataOrNull = service_update_extradata(extraData);
	continuous_read_pico_reauth(continuous, NULL, returnedStoredData);
	continuous_update_state(continuous, REAUTHSTATE_STOP, extraDataOrNull);
	service_check_extradata(returnedStoredData);

	continuous_finish(continuous);

	pthread_join(pico_td, NULL);

	buffer_delete(channel_buffer);
	channel_delete(channel);
	continuous_delete(continuous);
}
END_TEST

int main (void) {
	int number_failed;
	Suite * s;
	SRunner *sr;
	TCase * tc;

	s = suite_create("Libpico");

	tc = tcase_create("Continuous");
	tcase_set_timeout(tc, 20.0);
	tcase_add_test(tc, continuous_constructor_test);
	tcase_add_test(tc, continuous_test);
	suite_add_tcase(s, tc);
	sr = srunner_create(s);

	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);

	return (number_failed == 0) ? 0 : -1;
}

