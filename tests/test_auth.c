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
 * @section DESCRIPTION
 * Unit tests the high level auth and pair functions
 *
 */

#include <check.h>
#include <pthread.h>
#include "pico/sigmaverifier.h"
#include "pico/sigmaprover.h"
#include "pico/keypairing.h"
#include "pico/json.h"
#include "pico/base64.h"
#include "pico/cryptosupport.h"
#include "pico/sigmakeyderiv.h"
#include "pico/keyagreement.h"
#include "pico/messagestatus.h"
#include "pico/auth.h"

// Defines

// Structure definitions

typedef struct {
	char channel_name[64];
	char stored_extra_data[64];
} ProverThreadData;

// Function prototypes

void * prover_main(void * thread_data);

// Function definitions

void * prover_main(void * thread_data) {
	ProverThreadData * data = (ProverThreadData*) thread_data;

	RVPChannel * channel = channel_connect(data->channel_name);
	Shared * shared = shared_new();
	shared_load_or_generate_pico_keys(shared, "testpicokey.pub", "testpicokey.priv");
	Buffer * extraData = buffer_new(0);
	Buffer * returnedExtraData = buffer_new(0);
	buffer_append_string(extraData, data->stored_extra_data);


	bool result = sigmaprover(shared, channel, extraData, returnedExtraData);
	
	ck_assert(result);

	buffer_delete(returnedExtraData);
	buffer_delete(extraData);
	shared_delete(shared);	
	channel_delete(channel);
	free(data);

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

bool pairCallback(char* qrText, void* localdata) 
{
	Json* json = json_new();
	json_deserialize_string(json, qrText, strlen(qrText));
	ck_assert_str_eq(json_get_string(json, "sn"), "ServiceName");
	ck_assert_str_eq(json_get_string(json, "t"), "KP");
	ck_assert(json_get_string(json, "sig") != NULL);
	ck_assert(json_get_string(json, "spk") != NULL);
	ck_assert(json_get_string(json, "sa") != NULL);

	ProverThreadData * thread_data = malloc(sizeof(ProverThreadData));

	get_allocated_channel_name(json_get_string(json, "sa"), thread_data->channel_name);
	ck_assert_int_eq(strlen(thread_data->channel_name), 32);

	strcpy(thread_data->stored_extra_data, "");

	pthread_create((pthread_t*) localdata, NULL, prover_main, thread_data);

	return true;
}

bool authCallback(char* qrText, void* localdata) 
{
	Json* json = json_new();
	json_deserialize_string(json, qrText, strlen(qrText));
	ck_assert_str_eq(json_get_string(json, "t"), "KA");
	ck_assert(json_get_string(json, "sa") != NULL);
	
	ProverThreadData * thread_data = malloc(sizeof(ProverThreadData));

	get_allocated_channel_name(json_get_string(json, "sa"), thread_data->channel_name);
	ck_assert_int_eq(strlen(thread_data->channel_name), 32);

	strcpy(thread_data->stored_extra_data, "Test Data");

	pthread_create((pthread_t*) localdata, NULL, prover_main, thread_data);

	return true;
}

START_TEST (pair_test) {
	RVPChannel * channel;
	Shared * shared;

	shared = shared_new();
	shared_load_or_generate_keys(shared, "testkey.pub", "testkey.priv");
	channel = channel_new();

	pthread_t prover_td;
	
	bool result = pair(shared, "ServiceName", "123456", NULL, pairCallback, &prover_td); 
	ck_assert_int_eq(result, true);
	
	pthread_join(prover_td, NULL);

	shared_delete(shared);
	channel_delete(channel);
}
END_TEST

START_TEST (auth_test) {
	RVPChannel * channel;
	Shared * shared;
	Buffer * returnedExtraData;

	shared = shared_new();
	shared_load_or_generate_keys(shared, "testkey.pub", "testkey.priv");
	channel = channel_new();

	pthread_t prover_td;

	returnedExtraData = buffer_new(0);

	bool result = auth(shared, NULL, returnedExtraData, authCallback, &prover_td, NULL); 
	ck_assert_int_eq(result, true);
	
	buffer_append(returnedExtraData, "", 1);
	ck_assert_str_eq(buffer_get_buffer(returnedExtraData), "Test Data");

	pthread_join(prover_td, NULL);

	shared_delete(shared);
	channel_delete(channel);
	buffer_delete(returnedExtraData);
}
END_TEST

int main (void) {
	int number_failed;
	Suite * s;
	SRunner *sr;
	TCase * tc;

	s = suite_create("Libpico");

	tc = tcase_create("Auth");
	tcase_set_timeout(tc, 20.0);
	tcase_add_test(tc, pair_test);
	tcase_add_test(tc, auth_test);
	suite_add_tcase(s, tc);
	sr = srunner_create(s);

	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);

	return (number_failed == 0) ? 0 : -1;
}

