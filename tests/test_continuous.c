/**
 * @file
 * @author  cd611@cam.ac.uk
 * @version 1.0
 *
 * @section LICENSE
 *
 * Copyright Pico project, 2016
 *
 * @section DESCRIPTION
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

	Buffer * sharedkey = buffer_new(0);
	buffer_append(sharedkey, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f", 16);
	RVPChannel * channel = channel_connect(data->channel_name);
	Continuous * continuous = continuous_new();
	continuous_set_channel(continuous, channel);
	continuous_set_shared_key(continuous, sharedkey);

	continuous_cycle_start_pico(continuous, NULL);

	continuous_reauth_pico(continuous, NULL, NULL);
	ck_assert(continuous_get_state(continuous) == REAUTHSTATE_CONTINUE);
	
	bool result = continuous_continue_pico(continuous, NULL, NULL);
	ck_assert(result);
	
	continuous_reauth_pico(continuous, NULL, &timeout);
	ck_assert(continuous_get_state(continuous) == REAUTHSTATE_PAUSE);
    ck_assert_int_eq(timeout, 2000);

	continuous_reauth_pico(continuous, NULL, &timeout);
	ck_assert(continuous_get_state(continuous) == REAUTHSTATE_CONTINUE);
    ck_assert_int_eq(timeout, 2000);
	
	continuous_reauth_pico(continuous, NULL, &timeout);
	ck_assert(continuous_get_state(continuous) == REAUTHSTATE_STOP);
    ck_assert_int_eq(timeout, 0);

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
	buffer_append(sharedkey, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f", 16);

	ck_assert(channel != NULL);
	continuous_set_channel(continuous, channel);
	continuous_set_shared_key(continuous, sharedkey);

	channel_get_url(channel, channel_buffer);
	buffer_append(channel_buffer, "", 1);

	get_allocated_channel_name(buffer_get_buffer(channel_buffer), thread_data.channel_name);

	pthread_t pico_td;
	pthread_create(&pico_td, NULL, pico_main, &thread_data);

    continuous_set_custom_timeout(continuous, 2000, 2000);
	bool result = continuous_cycle_start(continuous);
	ck_assert(result);

	continuous_reauth(continuous, NULL);
	ck_assert(continuous_get_state(continuous) == REAUTHSTATE_CONTINUE);
	
	result = continuous_continue(continuous, NULL);
	ck_assert(result);

	continuous_read_pico_reauth(continuous, NULL, NULL);
	continuous_update_state(continuous, REAUTHSTATE_PAUSE);
	ck_assert(continuous_get_state(continuous) == REAUTHSTATE_PAUSE);

	continuous_read_pico_reauth(continuous, NULL, NULL);
	continuous_update_state(continuous, REAUTHSTATE_CONTINUE);
	ck_assert(continuous_get_state(continuous) == REAUTHSTATE_CONTINUE);
	
	continuous_read_pico_reauth(continuous, NULL, NULL);
	continuous_update_state(continuous, REAUTHSTATE_STOP);

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

