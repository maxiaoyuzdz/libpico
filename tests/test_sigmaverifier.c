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
 * @brief Unit tests for the sigmaverifier function
 * @section DESCRIPTION
 *
 * Performs unit tests for the sigmaverifier function. Basically
 * simulating the prover side of the protocol.
 *
 *
 */

#include <check.h>
#include <pthread.h>
#include "pico/sigmaverifier.h"
#include "pico/keypairing.h"
#include "pico/json.h"
#include "pico/base64.h"
#include "pico/cryptosupport.h"
#include "pico/sigmakeyderiv.h"
#include "pico/keyagreement.h"
#include "pico/messagestatus.h"

// Defines

// Structure definitions
typedef struct {	
	Buffer * pMacKey;
	Buffer * pEncKey;
	Buffer * vMacKey;
	Buffer * vEncKey;
	Buffer * sharedKey;
} EncKeys;

// Function prototypes

void * prover_main(void * channel_name);

// Function definitions

void send_start_message(RVPChannel* channel, int picoVersion, KeyPair* picoEphemeralKey, Nonce* picoNonce) {
	Json * json = json_new();
	Buffer * buf = buffer_new(0);
	
	json_add_integer(json, "picoVersion", 2);
	keypair_getpublicpem(picoEphemeralKey, buf);
	json_add_buffer(json, "picoEphemeralPublicKey", buf);
	buffer_clear(buf);
	base64_encode_mem((char const *)nonce_get_buffer(picoNonce), nonce_get_length(picoNonce), buf);
	json_add_buffer(json, "picoNonce", buf);
	buffer_clear(buf);
	json_serialize_buffer(json, buf);
	channel_write_buffer(channel, buf);

	buffer_delete(buf);
	json_delete(json);
}

void receive_service_auth_message(RVPChannel* channel, EncKeys* keys, KeyPair* picoEphemeralKey, Nonce* picoNonce, EC_KEY**serviceEphemKey, Nonce** serviceNonce) { 
	Json * json = json_new();
	Buffer * buf = buffer_new(0);
	Buffer * iv = buffer_new(0);
	Buffer * cleartext = buffer_new(0);
	EC_KEY * servicePublicKey;
	Buffer * servicePublicKeyBytes;
	Buffer * serviceSignature;
	Buffer * serviceMac;
	size_t start;
	size_t next;

	channel_read(channel, buf);
	json_deserialize_buffer(json, buf);
	ck_assert_int_eq(json_get_integer(json, "sessionId"), 0);
	*serviceEphemKey = cryptosupport_read_base64_string_public_key(json_get_string(json, "serviceEphemPublicKey"));
	buffer_clear(buf);
	base64_decode_string(json_get_string(json, "serviceNonce"), buf);
	*serviceNonce = nonce_new();
	nonce_set_buffer(*serviceNonce, buf);
	
	base64_decode_string(json_get_string(json, "iv"), iv);
	// Generate shared secrets	
	Buffer * sharedSecret;
	EVP_PKEY * vEphemPriv;
	SigmaKeyDeriv * sigmakeyderiv;
	sharedSecret = buffer_new(0);
	vEphemPriv = keypair_getprivatekey(picoEphemeralKey);
	keyagreement_generate_secret(vEphemPriv, *serviceEphemKey, sharedSecret);
	buffer_print_base64(sharedSecret);
	sigmakeyderiv = sigmakeyderiv_new();
	sigmakeyderiv_set(sigmakeyderiv, sharedSecret, picoNonce, *serviceNonce);
	buffer_delete(sharedSecret);
	keys->pMacKey = buffer_new(0);
	keys->pEncKey = buffer_new(0);
	keys->vMacKey = buffer_new(0);
	keys->vEncKey = buffer_new(0);
	keys->sharedKey = buffer_new(0);
	sigmakeyderiv_get_next_key(sigmakeyderiv, keys->pMacKey, 256);
	sigmakeyderiv_get_next_key(sigmakeyderiv, keys->pEncKey, 128);
	sigmakeyderiv_get_next_key(sigmakeyderiv, keys->vMacKey, 256);
	sigmakeyderiv_get_next_key(sigmakeyderiv, keys->vEncKey, 128);
	sigmakeyderiv_get_next_key(sigmakeyderiv, keys->sharedKey, 128);
	sigmakeyderiv_delete(sigmakeyderiv);
	
	buffer_clear(buf);
	base64_decode_string(json_get_string(json, "encryptedData"), buf);
	cryptosupport_decrypt(keys->vEncKey, iv, buf, cleartext);

	start = 0;
	next = 0;
	servicePublicKeyBytes = buffer_new(0);
	serviceSignature = buffer_new(0);
	serviceMac = buffer_new(0);

	next = buffer_copy_lengthprepend(cleartext, start, servicePublicKeyBytes);
	servicePublicKey = NULL;
	servicePublicKey = cryptosupport_read_buffer_public_key(servicePublicKeyBytes);
	ck_assert(servicePublicKey != NULL);
	ck_assert(next > start);
	next = buffer_copy_lengthprepend(cleartext, start, serviceSignature);
	ck_assert(next > start);
	next = buffer_copy_lengthprepend(cleartext, start, serviceMac);
	ck_assert(next > start);
	// TODO assert signature
	
	json_delete(json);
	buffer_delete(buf);
	buffer_delete(iv);
	buffer_delete(cleartext);
	buffer_delete(servicePublicKeyBytes);
	buffer_delete(serviceSignature);
	buffer_delete(serviceMac);
}

void send_pico_auth_message(RVPChannel* channel, EncKeys* keys, Nonce* serviceNonce, KeyPair* picoIdentityKey, KeyPair* picoEphemeralKey, char* extra_data_to_send) {
	Json* json = json_new();
	Buffer * buf = buffer_new(0);
	Buffer * toEncrypt = buffer_new(0);
	buffer_clear(buf);
	keypair_getpublicder(picoIdentityKey, buf);
	buffer_append_buffer_lengthprepend(toEncrypt, buf);

	Buffer * toSign = buffer_new(0);
	buffer_append(toSign, nonce_get_buffer(serviceNonce), nonce_get_length(serviceNonce));
	buffer_append(toSign, "\x00\x00\x00\x00", 4);
	buffer_clear(buf);
	keypair_getpublicder(picoEphemeralKey, buf);
	buffer_append_buffer(toSign, buf);
	buffer_clear(buf);
	keypair_sign_data(picoIdentityKey, toSign, buf);
	buffer_append_buffer_lengthprepend(toEncrypt, buf);

	Buffer * mac = buffer_new(0);
	buffer_clear(buf);
	keypair_getpublicder(picoIdentityKey, buf);
	cryptosupport_generate_mac(keys->pMacKey, buf, mac);
	buffer_append_buffer_lengthprepend(toEncrypt, mac);

	Buffer * extraData = buffer_new(0);
	buffer_append_string(extraData, extra_data_to_send);
	buffer_append_buffer_lengthprepend(toEncrypt, extraData);
	
	Buffer* iv = buffer_new(CRYPTOSUPPORT_IV_SIZE);
	cryptosupport_generate_iv(iv);
	Buffer * encrypted = buffer_new(0);
	cryptosupport_encrypt(keys->pEncKey, iv, toEncrypt, encrypted);

	buffer_clear(buf);	
	base64_encode_buffer(encrypted, buf);
	json_add_buffer(json, "encryptedData", buf);
	buffer_clear(buf);
	base64_encode_buffer(iv, buf);
	json_add_buffer(json, "iv", buf);
	json_add_integer(json, "sessionId", 0);

	buffer_clear(buf);
	json_serialize_buffer(json, buf);
	channel_write_buffer(channel, buf);
	
	json_delete(json);
	buffer_delete(buf);
	buffer_delete(toEncrypt);
	buffer_delete(toSign);
	buffer_delete(mac);
	buffer_delete(extraData);
	buffer_delete(iv);
	buffer_delete(encrypted);
}

void receive_status_message(RVPChannel* channel, EncKeys* keys, char* expected_extra_data) {
	Json* json = json_new();
	Buffer * buf = buffer_new(0);
	Buffer* iv = buffer_new(0);
	Buffer* cleartext = buffer_new(0);	

	
	channel_read(channel, buf);
	json_deserialize_buffer(json, buf);
	ck_assert_int_eq(json_get_integer(json, "sessionId"), 0);
	base64_decode_string(json_get_string(json, "iv"), iv);
	buffer_clear(buf);
	base64_decode_string(json_get_string(json, "encryptedData"), buf);
	cryptosupport_decrypt(keys->vEncKey, iv, buf, cleartext);

	Buffer * receivedExtraData = buffer_new(0);	
	char status = buffer_get_buffer(cleartext)[0];
	buffer_copy_lengthprepend(cleartext, 1, receivedExtraData);
	ck_assert_int_eq(status, MESSAGESTATUS_OK_DONE);	

	buffer_append(receivedExtraData, "", 1);
	ck_assert_str_eq(buffer_get_buffer(receivedExtraData), expected_extra_data);
	
	json_delete(json);
	buffer_delete(buf);
	buffer_delete(cleartext);
	buffer_delete(iv);
	buffer_delete(receivedExtraData);
}

void * prover_main(void * channel_name) {
	RVPChannel * channel = channel_connect((char*)channel_name);
	Nonce * picoNonce = nonce_new();
	KeyPair * picoEphemeralKey = keypair_new();
	keypair_generate(picoEphemeralKey);
	KeyPair * picoIdentityKey = keypair_new();
	keypair_generate(picoIdentityKey);
	nonce_generate_random(picoNonce);

	Nonce* serviceNonce;
	EC_KEY* serviceEphemKey;
	EncKeys keys;

	// Send start message
	send_start_message(channel, 2, picoEphemeralKey, picoNonce);

	// Receive service auth message
	receive_service_auth_message(channel, &keys, picoEphemeralKey, picoNonce, &serviceEphemKey, &serviceNonce); 

	// Send pico auth message
	send_pico_auth_message(channel, &keys, serviceNonce, picoIdentityKey, picoEphemeralKey, (char*) "Test data");

	// Receive status message
	receive_status_message(channel, &keys, (char*) "123456");
	
	buffer_delete(keys.pMacKey);
	buffer_delete(keys.pEncKey);
	buffer_delete(keys.vMacKey);
	buffer_delete(keys.vEncKey);
	buffer_delete(keys.sharedKey);
	keypair_delete(picoEphemeralKey);
	keypair_delete(picoIdentityKey);
	channel_delete(channel);
	nonce_delete(picoNonce);
	nonce_delete(serviceNonce);

	return NULL;
}


START_TEST (verify) {
	RVPChannel * channel;
	Shared * shared;
	Buffer * returnedExtraData;

	shared = shared_new();
	shared_load_or_generate_keys(shared, "testkey.pub", "testkey.priv");
	channel = channel_new();

	pthread_t prover_td;
	pthread_create(&prover_td, NULL, prover_main, (char*)channel_get_name(channel));
	
	returnedExtraData = buffer_new(0);
	sigmaverifier(shared, channel, NULL, "123456", returnedExtraData, NULL);

	buffer_append(returnedExtraData, "", 1);
	ck_assert_str_eq(buffer_get_buffer(returnedExtraData), "Test data");

	pthread_join(prover_td, NULL);

	shared_delete(shared);
	channel_delete(channel);
	buffer_delete(returnedExtraData);
}
END_TEST

START_TEST (sigma_key_deriver) {
	SigmaKeyDeriv * sigmakeyderiv;
	Buffer * sharedSecret;
	Nonce * picoNonce;
	Nonce * serviceNonce;
	Buffer * keyBytes;
	Buffer * nonceData;
	Buffer * base64;

	sharedSecret = buffer_new(0);
	buffer_append_string(sharedSecret, "\x23\x02\x38\x40\x70\x23\x49\x08\x23\x04\x48\x20\x39\x48\x02\x70\x8");
	nonceData = buffer_new(0);
	buffer_append_string(nonceData, "\x01\x02\x03\x04\x05\x06\x07\x08");
	picoNonce = nonce_new();
	nonce_set_buffer(picoNonce, nonceData);

	buffer_clear(nonceData);
	buffer_append_string(nonceData, "\x07\x04\x09\x02\x03\x07\x05\x06");
	serviceNonce = nonce_new();
	nonce_set_buffer(serviceNonce, nonceData);

	buffer_delete(nonceData);

	sigmakeyderiv = sigmakeyderiv_new();
	sigmakeyderiv_set(sigmakeyderiv, sharedSecret, picoNonce, serviceNonce);

	buffer_delete(sharedSecret);
	nonce_delete(picoNonce);
	nonce_delete(serviceNonce);

	// sharedKey
	keyBytes = buffer_new(0);
	base64 = buffer_new(0);
	sigmakeyderiv_get_next_key(sigmakeyderiv, keyBytes, 128);
	base64_encode_buffer(keyBytes, base64);
	buffer_append(base64, "", 1);
	ck_assert_str_eq(buffer_get_buffer(base64), "7iU6mLgArgvtO9HW0lvk/g==");

	// pMacKey
	buffer_clear(keyBytes);
	buffer_clear(base64);
	sigmakeyderiv_get_next_key(sigmakeyderiv, keyBytes, 256);
	base64_encode_buffer(keyBytes, base64);
	buffer_append(base64, "", 1);
	ck_assert_str_eq(buffer_get_buffer(base64), "L0VyA6JS5ZMggVMvJB22s61K+9INGk3OqK0eyJLMnSs=");

	// pEncKey
	buffer_clear(keyBytes);
	buffer_clear(base64);
	sigmakeyderiv_get_next_key(sigmakeyderiv, keyBytes, 128);
	base64_encode_buffer(keyBytes, base64);
	buffer_append(base64, "", 1);
	ck_assert_str_eq(buffer_get_buffer(base64), "ynUis+NzmrGp5yC3nX0Gjw==");

	// vMacKey
	buffer_clear(keyBytes);
	buffer_clear(base64);
	sigmakeyderiv_get_next_key(sigmakeyderiv, keyBytes, 256);
	base64_encode_buffer(keyBytes, base64);
	buffer_append(base64, "", 1);
	ck_assert_str_eq(buffer_get_buffer(base64), "J1mluN+sD9qrhdQ83vd/o7BKQvsq5l80t7CuTcs6A0A=");

	// pEncKey
	buffer_clear(keyBytes);
	buffer_clear(base64);
	sigmakeyderiv_get_next_key(sigmakeyderiv, keyBytes, 128);
	base64_encode_buffer(keyBytes, base64);
	buffer_append(base64, "", 1);
	ck_assert_str_eq(buffer_get_buffer(base64), "7HK9ZbFCzAiVXUnlzOGDVA==");

	buffer_delete(keyBytes);
	buffer_delete(base64);
	sigmakeyderiv_delete(sigmakeyderiv);

}
END_TEST


int main (void) {
	int number_failed;
	Suite * s;
	SRunner *sr;
	TCase * tc;

	s = suite_create("Libpico");

	tc = tcase_create("SigmaVerifier");
	tcase_set_timeout(tc, 20.0);
	tcase_add_test(tc, sigma_key_deriver);
	tcase_add_test(tc, verify);
	suite_add_tcase(s, tc);
	sr = srunner_create(s);

	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);

	return (number_failed == 0) ? 0 : -1;
}

