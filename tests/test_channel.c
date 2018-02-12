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
 * @brief Unit tests for the RVPChannel data type
 * @section DESCRIPTION
 *
 * Performs a variety of unit tests associated with the RVPChannel data type.
 *
 */

#include "pico/config.h"

#include <check.h>
#include <pthread.h>
#include "pico/channel.h"
#include "pico/channel_rvp.h"
#include "pico/channel_bt.h"
#include "pico/channel_btout.h"
#include "mockbt/mockbt.h"

// Defines

// Structure definitions

// Function prototypes

void * echo_main(void * channel_name);

// Function definitions

void * echo_main(void * channel_name) {
	RVPChannel * channel = channel_connect((char*)channel_name);
	Buffer * buf = buffer_new(0);
	Buffer * toSend = buffer_new(0);

	channel_read(channel, buf);
	buffer_append_buffer_lengthprepend(toSend, buf);

	channel_write(channel, buffer_get_buffer(toSend), buffer_get_pos(toSend));
	
	buffer_delete(buf);
	buffer_delete(toSend);
	channel_delete(channel);

	return NULL;
}


START_TEST (echo_test) {
	RVPChannel * channel = channel_new();
	Buffer * buf = buffer_new(0);
	Buffer * recvbuf = buffer_new(0);

	pthread_t echo_td;
	pthread_create(&echo_td, NULL, echo_main, (char*)channel_get_name(channel));
	
	buffer_append_string(buf, "HELLO WORLD!");
	channel_write_buffer(channel, buf);
	channel_read(channel, recvbuf);

	buffer_append(recvbuf, "", 1);
	ck_assert_str_eq(buffer_get_buffer(recvbuf), "HELLO WORLD!");

	pthread_join(echo_td, NULL);

	channel_delete(channel);
	buffer_delete(buf);
	buffer_delete(recvbuf);
}
END_TEST

START_TEST (get_url) {
	RVPChannel * channel = channel_connect("c348ff95f0bd49aabe55ea35a637c680");
	Buffer * buf = buffer_new(0);
	channel_get_url(channel, buf);
	buffer_append(buf, "", 1);
	ck_assert_str_eq(buffer_get_buffer(buf), "http://rendezvous.mypico.org/channel/c348ff95f0bd49aabe55ea35a637c680");

	channel_delete(channel);
	buffer_delete(buf);
}
END_TEST

START_TEST (set_url) {
	bool result;
	Buffer * address;
	Buffer * channel;

#ifdef HAVE_LIBPICOBT // Only build if Bluetooth is present
	unsigned int port;

	port = 0;
#endif // HAVE_LIBPICOBT // Only build if Bluetooth is present

	address = buffer_new(0);
	channel = buffer_new(0);

	// Check RVP address decoding
	result = channel_decode_url_rvp("http://rendezvous.mypico.org/channel/abcdefg", address, channel);
	ck_assert_msg(result, "RVP URL decode failed");
	ck_assert_str_eq(buffer_get_buffer(address), "http://rendezvous.mypico.org");
	ck_assert_str_eq(buffer_get_buffer(channel), "abcdefg");

	result = channel_decode_url_rvp("http://rendezvous.mypico.org/channel/abcdefg/", address, channel);
	ck_assert_msg(result, "RVP URL decode failed");
	ck_assert_str_eq(buffer_get_buffer(address), "http://rendezvous.mypico.org");
	ck_assert_str_eq(buffer_get_buffer(channel), "abcdefg");

	result = channel_decode_url_rvp("https://rendezvous.mypico.org/channel/abcdefg", address, channel);
	ck_assert_msg(result, "RVP URL decode failed");
	ck_assert_str_eq(buffer_get_buffer(address), "https://rendezvous.mypico.org");
	ck_assert_str_eq(buffer_get_buffer(channel), "abcdefg");

	result = channel_decode_url_rvp("http://rendezvous.mypico.org/channel/", address, channel);
	ck_assert_msg(result, "RVP URL decode failed");
	ck_assert_str_eq(buffer_get_buffer(address), "http://rendezvous.mypico.org");
	ck_assert_str_eq(buffer_get_buffer(channel), "");

	result = channel_decode_url_rvp("http://rendezvous.mypico.org/channel", address, channel);
	ck_assert_msg(result, "RVP URL decode failed");
	ck_assert_str_eq(buffer_get_buffer(address), "http://rendezvous.mypico.org");
	ck_assert_str_eq(buffer_get_buffer(channel), "");

	result = channel_decode_url_rvp("http://rendezvous.mypico.org/", address, channel);
	ck_assert_msg(result, "RVP URL decode failed");
	ck_assert_str_eq(buffer_get_buffer(address), "http://rendezvous.mypico.org");
	ck_assert_str_eq(buffer_get_buffer(channel), "");

	result = channel_decode_url_rvp("http://rendezvous.mypico.org", address, channel);
	ck_assert_msg(result, "RVP URL decode failed");
	ck_assert_str_eq(buffer_get_buffer(address), "http://rendezvous.mypico.org");
	ck_assert_str_eq(buffer_get_buffer(channel), "");

	result = channel_decode_url_rvp("http://rendezvous.mypico.org/channel/abcdefg/abc", address, channel);
	ck_assert_msg(result, "RVP URL decode failed");
	ck_assert_str_eq(buffer_get_buffer(address), "http://rendezvous.mypico.org/channel/abcdefg/abc");
	ck_assert_str_eq(buffer_get_buffer(channel), "");

	result = channel_decode_url_rvp("xttp://rendezvous.mypico.org/channel", address, channel);
	ck_assert_msg(!result, "RVP URL decode failed");

	result = channel_decode_url_rvp("xttps://rendezvous.mypico.org/channel", address, channel);
	ck_assert_msg(!result, "RVP URL decode failed");

	result = channel_decode_url_rvp("http://", address, channel);
	ck_assert_msg(!result, "RVP URL decode failed");

	result = channel_decode_url_rvp("https://", address, channel);
	ck_assert_msg(!result, "RVP URL decode failed");

#ifdef HAVE_LIBPICOBT // Only build if Bluetooth is present

	// Check Bluetooth address decoding

	result = channel_decode_url_bt("btspp://a5c32c6100e7", address, & port);
	ck_assert_msg(result, "Bluetooth URL decode failed");
	ck_assert_str_eq(buffer_get_buffer(address), "a5c32c6100e7");
	ck_assert_uint_eq(port, 0);

	result = channel_decode_url_bt("btspp://a5c32c6100e7:23", address, & port);
	ck_assert_msg(result, "Bluetooth URL decode failed");
	ck_assert_str_eq(buffer_get_buffer(address), "a5c32c6100e7");
	ck_assert_uint_eq(port, 23);

	result = channel_decode_url_bt("btspp://a5c32c6100e7:05", address, & port);
	ck_assert_msg(result, "Bluetooth URL decode failed");
	ck_assert_str_eq(buffer_get_buffer(address), "a5c32c6100e7");
	ck_assert_uint_eq(port, 5);

	result = channel_decode_url_bt("btspp://a5c32c6100e7:9", address, & port);
	ck_assert_msg(result, "Bluetooth URL decode failed");
	ck_assert_str_eq(buffer_get_buffer(address), "a5c32c6100e7");
	ck_assert_uint_eq(port, 9);

	result = channel_decode_url_bt("btspp://a5c32c6100e7:23", NULL, & port);
	ck_assert_msg(result, "Bluetooth URL decode failed");
	ck_assert_uint_eq(port, 23);

	result = channel_decode_url_bt("btspp://a5c32c6100e7:23", address, NULL);
	ck_assert_msg(result, "Bluetooth URL decode failed");
	ck_assert_str_eq(buffer_get_buffer(address), "a5c32c6100e7");

	result = channel_decode_url_bt("btspp://a5c32c6100e7:", address, & port);
	ck_assert_msg(!result, "Bluetooth URL decode failed");

	result = channel_decode_url_bt("btspp://a5c32c6100e7:123", address, & port);
	ck_assert_msg(!result, "Bluetooth URL decode failed");

	result = channel_decode_url_bt("btspp://5c32c6100e7:23", address, & port);
	ck_assert_msg(!result, "Bluetooth URL decode failed");

	result = channel_decode_url_bt("btspp://a5c32c6100e76:23", address, & port);
	ck_assert_msg(!result, "Bluetooth URL decode failed");

	result = channel_decode_url_bt("btspp://5c32c6100e7", address, & port);
	ck_assert_msg(!result, "Bluetooth URL decode failed");

	result = channel_decode_url_bt("btspp://a5c32c6100e76", address, & port);
	ck_assert_msg(!result, "Bluetooth URL decode failed");

	result = channel_decode_url_bt("btspp://a5c3gc6100e7:23", address, & port);
	ck_assert_msg(!result, "Bluetooth URL decode failed");

	result = channel_decode_url_bt("http://a5c32c6100e7:23", address, & port);
	ck_assert_msg(!result, "Bluetooth URL decode failed");

	result = channel_decode_url_bt("btspp://a5c32c6100e:23", address, & port);
	ck_assert_msg(!result, "Bluetooth URL decode failed");

	result = channel_decode_url_bt("btspp://a5c32c6100e71:23", address, & port);
	ck_assert_msg(!result, "Bluetooth URL decode failed");

	result = channel_decode_url_bt("", address, & port);
	ck_assert_msg(!result, "Bluetooth URL decode failed");

	result = channel_decode_url_bt(NULL, address, & port);
	ck_assert_msg(!result, "Bluetooth URL decode failed");

	// Check Bluetooth Out address decoding

	result = channel_decode_url_btout("btspp://a5c32c6100e7", address, & port);
	ck_assert_msg(result, "Bluetooth Out URL decode failed");
	ck_assert_str_eq(buffer_get_buffer(address), "a5c32c6100e7");
	ck_assert_uint_eq(port, 0);

	result = channel_decode_url_btout("btspp://a5c32c6100e7:23", address, & port);
	ck_assert_msg(result, "Bluetooth Out URL decode failed");
	ck_assert_str_eq(buffer_get_buffer(address), "a5c32c6100e7");
	ck_assert_uint_eq(port, 23);

	result = channel_decode_url_btout("btspp://a5c32c6100e7:05", address, & port);
	ck_assert_msg(result, "Bluetooth Out URL decode failed");
	ck_assert_str_eq(buffer_get_buffer(address), "a5c32c6100e7");
	ck_assert_uint_eq(port, 5);

	result = channel_decode_url_btout("btspp://a5c32c6100e7:9", address, & port);
	ck_assert_msg(result, "Bluetooth Out URL decode failed");
	ck_assert_str_eq(buffer_get_buffer(address), "a5c32c6100e7");
	ck_assert_uint_eq(port, 9);

	result = channel_decode_url_btout("btspp://a5c32c6100e7:23", NULL, & port);
	ck_assert_msg(result, "Bluetooth Out URL decode failed");
	ck_assert_uint_eq(port, 23);

	result = channel_decode_url_btout("btspp://a5c32c6100e7:23", address, NULL);
	ck_assert_msg(result, "Bluetooth Out URL decode failed");
	ck_assert_str_eq(buffer_get_buffer(address), "a5c32c6100e7");

	result = channel_decode_url_btout("btspp://a5c32c6100e7:", address, & port);
	ck_assert_msg(!result, "Bluetooth Out URL decode failed");

	result = channel_decode_url_btout("btspp://a5c32c6100e7:123", address, & port);
	ck_assert_msg(!result, "Bluetooth Out URL decode failed");

	result = channel_decode_url_btout("btspp://5c32c6100e7:23", address, & port);
	ck_assert_msg(!result, "Bluetooth Out URL decode failed");

	result = channel_decode_url_btout("btspp://a5c32c6100e76:23", address, & port);
	ck_assert_msg(!result, "Bluetooth Out URL decode failed");

	result = channel_decode_url_btout("btspp://5c32c6100e7", address, & port);
	ck_assert_msg(!result, "Bluetooth Out URL decode failed");

	result = channel_decode_url_btout("btspp://a5c32c6100e76", address, & port);
	ck_assert_msg(!result, "Bluetooth Out URL decode failed");

	result = channel_decode_url_btout("btspp://a5c3gc6100e7:23", address, & port);
	ck_assert_msg(!result, "Bluetooth Out URL decode failed");

	result = channel_decode_url_btout("http://a5c32c6100e7:23", address, & port);
	ck_assert_msg(!result, "Bluetooth Out URL decode failed");

	result = channel_decode_url_btout("btspp://a5c32c6100e:23", address, & port);
	ck_assert_msg(!result, "Bluetooth Out URL decode failed");

	result = channel_decode_url_btout("btspp://a5c32c6100e71:23", address, & port);
	ck_assert_msg(!result, "Bluetooth Out URL decode failed");

	result = channel_decode_url_btout("", address, & port);
	ck_assert_msg(!result, "Bluetooth Out URL decode failed");

	result = channel_decode_url_btout(NULL, address, & port);
	ck_assert_msg(!result, "Bluetooth Out URL decode failed");

#endif // HAVE_LIBPICOBT // Only build if Bluetooth is present

	buffer_delete(address);
	buffer_delete(channel);
}
END_TEST

START_TEST (channel_set_bt_bluetooth_not_present) {
	RVPChannel * channel;
   	bool result;

	int bt_not_present() {
		return -1;
	}
	bt_funcs.bt_is_present = bt_not_present;

	channel = NULL;
	channel = channel_new();
	result = channel_set_bt_with_uuid(channel, "ed995e5a-c7e7-4442-a6ee-123123123123");
	ck_assert(result == false);
	ck_assert(channel_get_data(channel) == NULL);
	channel_delete(channel);

	channel = NULL;
	channel = channel_new();
	result = channel_set_bt_with_port(channel, 3);
	ck_assert(result == false);
	ck_assert(channel_get_data(channel) == NULL);
	channel_delete(channel);
}
END_TEST

START_TEST (channel_set_bt_error_registering_service) {
	RVPChannel * channel;
   	bool result;

	int bt_present() {
		return 0;
	}
	bt_funcs.bt_is_present = bt_present;
	
	bt_err_t bt_bind_local(bt_socket_t * listener) {
		ck_assert(listener != NULL);
		return BT_SUCCESS;
	}
	bt_funcs.bt_bind = bt_bind_local;
	
	bt_err_t bt_listen_local(bt_socket_t * listener) {
		ck_assert(listener != NULL);
		return BT_SUCCESS;
	}
	bt_funcs.bt_listen = bt_listen_local;
	
	bt_err_t bt_get_device_name_local(bt_addr_t * addr) {
		ck_assert(addr != NULL);
		return BT_SUCCESS;
	}
	bt_funcs.bt_get_device_name = bt_get_device_name_local;
	
	bt_err_t bt_register_service_local(bt_uuid_t const * service, char const * service_name, bt_socket_t *sock) {
		ck_assert(service != NULL);
		ck_assert(service_name != NULL);
		ck_assert(sock != NULL);
		return BT_ERR_UNKNOWN;

	}
	bt_funcs.bt_register_service = bt_register_service_local;

	channel = NULL;
	channel = channel_new();
	result = channel_set_bt_with_uuid(channel, "ed995e5a-c7e7-4442-a6ee-123123123123");
	ck_assert(result == false);
	ck_assert(channel_get_data(channel) == NULL);
	channel_delete(channel);
}
END_TEST

int main (void) {
	int number_failed;
	Suite * s;
	SRunner *sr;
	TCase * tc;

	s = suite_create("Libpico");

	tc = tcase_create("Channel");
	tcase_set_timeout(tc, 20.0);
	tcase_add_test(tc, echo_test);
	tcase_add_test(tc, get_url);
	tcase_add_test(tc, set_url);
	tcase_add_test(tc, channel_set_bt_bluetooth_not_present);
	tcase_add_test(tc, channel_set_bt_error_registering_service);
	suite_add_tcase(s, tc);
	sr = srunner_create(s);

	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);

	return (number_failed == 0) ? 0 : -1;
}

