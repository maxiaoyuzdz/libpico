/** \ingroup Utility
 * @file
 * @author  David Llewellyn-Jones <David.Llewellyn-Jones@cl.cam.ac.uk>
 * @version $(VERSION)
 *
 * @section LICENSE
 *
 * (C) Copyright Cambridge Authentication Ltd, 2017
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
 * @brief Cryptographic utilities
 * @section DESCRIPTION
 *
 * The cryptosupport functions offer various wrappers around the OpenSSL
 * functionality to simplify its operation. Encryption, decryption, signatures,
 * and macs are supported, as well as functionality for encoding and decoding
 * keys in various formats.
 *
 */

/** \addtogroup Utility
 *  @{
 */

#include <stdio.h>
#include <malloc.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/pkcs12.h>
#include <openssl/err.h>
#include "pico/debug.h"
#include "pico/base64.h"
#include "pico/log.h"
#include "pico/cryptosupport.h"

// Defines

#define CRYPTOSUPPORT_TAG_LENGTH (16)

// Structure definitions

// Function prototypes

// Function definitions

/**
 * Return a PEM-encoded representation of a public key. This is a base64
 * encoded copy of the DER key, but without the standard header and footer
 * and without any newlines.
 *
 * @param eckey The public key to encode
 * @param buffer The buffer to store the resulting PEM-encoded public key
 * @return true if converted successfully, false o/w
 */
bool cryptosupport_getpublicpem(EC_KEY * eckey, Buffer * buffer) {
	BIO * mem = NULL;
	long size;
	char * data;
	int length;
	bool result;

	mem = BIO_new(BIO_s_mem());
	if (mem != NULL) {
		result = true;
		//if (outformat == FORMAT_ASN1)
		length = i2d_EC_PUBKEY_bio(mem, eckey);
		//i = PEM_write_bio_EC_PUBKEY(mem, eckey);
		if (length == 0) {
			result = false;
			LOG(LOG_ERR, "Error getting public key in PEM format\n");
		}

		data = NULL;
		size = BIO_get_mem_data(mem, & data);

		base64_encode_mem(data, size, buffer);

		BIO_free(mem);
	}
	else {
		result = false;
		LOG(LOG_ERR, "Error opening memory stream to output PEM public key\n");
	}

	return result;
}

/**
 * Return a DER-encoded representation of a public key. This is a binary
 * encoded copy of the key.
 *
 * @param eckey The public key to encode
 * @param buffer The buffer to store the resulting DER-encoded public key
 * @return true if converted successfully, false o/w
 */
bool cryptosupport_getpublicder(EC_KEY * eckey, Buffer * buffer) {
	BIO * mem = NULL;
	long size;
	char * data;
	int length;
	bool result;
	
	mem = BIO_new(BIO_s_mem());
	if (mem != NULL) {
		result = true;
		//if (outformat == FORMAT_ASN1)
		length = i2d_EC_PUBKEY_bio(mem, eckey);
		//i = PEM_write_bio_EC_PUBKEY(mem, eckey);
		if (length == 0) {
			result = false;
			LOG(LOG_ERR, "Error getting public key in DER format\n");
		}

		data = NULL;
		size = BIO_get_mem_data(mem, & data);

		buffer_append(buffer, data, size);

		BIO_free(mem);
	}
	else {
		result = false;
		LOG(LOG_ERR, "Error opening memory stream to output DER public key\n");
	}

	return result;
}

/**
 * Return a PEM-encoded representation of a private key. This is a base64
 * encoded copy of the DER key, but without the standard header and footer
 * and without any newlines.
 *
 * @param pkey The private key to encode
 * @param buffer The buffer to store the resulting PEM-encoded private key
 * @return true if converted successfully, false o/w
 */
bool cryptosupport_getprivatepem(EVP_PKEY * pkey, Buffer * buffer) {
	BIO * mem = NULL;
	PKCS8_PRIV_KEY_INFO * p8inf = NULL;
	long size;
	char * data;
	bool result;

	// TODO: Check whether p8inf should be freed using PKCS8_PRIV_KEY_INFO_free
	result = true;
	p8inf = EVP_PKEY2PKCS8(pkey);
	if (p8inf != NULL) {
		mem = BIO_new(BIO_s_mem());
		if (mem != NULL) {
			// ASN1
			i2d_PKCS8_PRIV_KEY_INFO_bio(mem, p8inf);
			// PEM
			data = NULL;
			size = BIO_get_mem_data(mem, & data);

			base64_encode_mem(data, size, buffer);

			BIO_free(mem);
		}
		else {
			result = false;
			LOG(LOG_ERR, "Error opening memory stream to output PEM public key\n");
		}
	}
	else {
		result = false;
		LOG(LOG_ERR, "Error converting private key to PKCS\n");
	}

	return result;
}

/**
 * Return a DER-encoded representation of a private key. This is a binary
 * encoded copy of the key.
 *
 * @param pkey The private key to encode
 * @param buffer The buffer to store the resulting DER-encoded private key
 * @return true if converted successfully, false o/w
 */
bool cryptosupport_getprivateder(EVP_PKEY * pkey, Buffer * buffer) {
	BIO * mem = NULL;
	PKCS8_PRIV_KEY_INFO * p8inf = NULL;
	long size;
	char * data;
	bool result;

	// TODO: Check whether p8inf should be freed using PKCS8_PRIV_KEY_INFO_free
	result = true;
	p8inf = EVP_PKEY2PKCS8(pkey);
	if (p8inf != NULL) {
		mem = BIO_new(BIO_s_mem());
		if (mem != NULL) {
			// ASN1
			i2d_PKCS8_PRIV_KEY_INFO_bio(mem, p8inf);
			// PEM
			data = NULL;
			size = BIO_get_mem_data(mem, & data);

			buffer_append(buffer, data, size);

			BIO_free(mem);
		}
		else {
			result = false;
			LOG(LOG_ERR, "Error opening memory stream to output PEM public key\n");
		}
	}
	else {
		result = false;
		LOG(LOG_ERR, "Error converting private key to PKCS\n");
	}

	return result;
}

/**
 * Generate an SHA256 HMAC of the provided data using the given key.
 *
 * @param macKey The key to use to generate the HMAC
 * @param data The data to HMAC
 * @param bufferout Buffer to store the resulting HMAC in
 * @return true if the HMAC was successfully generated, false o/w
 */
bool cryptosupport_generate_mac(Buffer * macKey, Buffer * data, Buffer * bufferout) {
	HMAC_CTX * ctx;
	unsigned int len;
	int result;

	ctx = CALLOC(sizeof(HMAC_CTX), 1);

	HMAC_CTX_init(ctx);

	result = HMAC_Init_ex(ctx, buffer_get_buffer(macKey), buffer_get_pos(macKey), EVP_sha256(), NULL);

	if (result == 1) {
		result = HMAC_Update(ctx, (unsigned char * const)buffer_get_buffer(data), buffer_get_pos(data));
	}

	if (result == 1) {
		buffer_set_min_size(bufferout, EVP_MAX_MD_SIZE);
		result = HMAC_Final(ctx, (unsigned char * const)buffer_get_buffer(bufferout), &len);
		buffer_set_pos(bufferout, len);
	}

	HMAC_CTX_cleanup(ctx);

	FREE(ctx);

	if (result != 1) {
		LOG(LOG_ERR, "Error generating MAC: %lu\n", ERR_get_error());
	}

	return (result == 1);
}

/**
 * Verify a signature using the provided elliptic curve public key. The 
 * signature should be generated as an SHA256 digest signed using the
 * key's assocated elliptic curve private key.
 *
 * @param publickey The key to verify the signature with
 * @param bufferin The data that's been purportedely signed
 * @param sigin The claimed signature of the data
 * @return true if the signature verified successfully. False if the signature
 *         failed to verify or there was some other error.
 */
bool cryptosupport_verify_signature(EC_KEY const * publickey, Buffer const * bufferin, Buffer * sigin) {
	EVP_PKEY_CTX * pctx = NULL;
	EVP_MD const * digest_type = NULL;
	EVP_PKEY * pkey = NULL;
	EVP_MD_CTX * mdctx = NULL;
	int result;

	result = 0;
	if ((publickey != NULL) && (bufferin != NULL) && (sigin != NULL)) {
		pkey = EVP_PKEY_new();
		EVP_PKEY_assign_EC_KEY(pkey, publickey);
		digest_type = EVP_sha256();
		mdctx = EVP_MD_CTX_create();
		result = EVP_DigestVerifyInit(mdctx, &pctx, digest_type, NULL, pkey);
	}

	if (result == 1) {
		result = EVP_DigestVerifyUpdate(mdctx, buffer_get_buffer(bufferin), buffer_get_pos(bufferin));
	}
	
	if (result == 1) {
		result = EVP_DigestVerifyFinal(mdctx, (unsigned char *)buffer_get_buffer(sigin), buffer_get_pos(sigin));
	}

	EVP_MD_CTX_destroy(mdctx);

	if (result == 0) {
		LOG(LOG_ERR, "Error verifying signature: %lu\n", ERR_get_error());
	}

	return (result == 1);
}

/**
 * Convert a base64-encoded (PEM) public key stored in a buffer into an 
 * OpenSSL EC-KEY public key.
 * The returned key is newly allocated and so should be subsequently freed by
 * the calling code.
 *
 * @param keybuffer Buffer containing the base64-encoded public key
 * @return the EC_KEY
 */
EC_KEY * cryptosupport_read_base64_buffer_public_key(Buffer * keybuffer) {
	EC_KEY * eckey = NULL;
	Buffer * decoded;

	decoded = buffer_new(base64_decode_size_max(buffer_get_pos(keybuffer)));
	base64_decode_buffer(keybuffer, decoded);

	eckey = cryptosupport_read_buffer_public_key(decoded);

	buffer_delete(decoded);

	return eckey;
}

/**
 * Convert a base64-encoded (PEM) public key stored as a null-terminated string
 * into an OpenSSL EC-KEY public key.
 * The returned key is newly allocated and so should be subsequently freed by
 * the calling code.
 *
 * @param keystring Null-terminated string containing the base64-encoded
 *                  public key
 * @return the EC_KEY
 */
EC_KEY * cryptosupport_read_base64_string_public_key(char const * keystring) {
	EC_KEY * eckey = NULL;
	Buffer * decoded;

	decoded = buffer_new(base64_decode_size_max(strlen(keystring)));
	base64_decode_string(keystring, decoded);

	eckey = cryptosupport_read_buffer_public_key(decoded);

	buffer_delete(decoded);

	return eckey;
}

/**
 * Convert a binary-encoded (DER) public key stored in a buffer into an
 * OpenSSL EC-KEY public key.
 * The returned key is newly allocated and so should be subsequently freed by
 * the calling code.
 * Unlike the function for reading a PEM public key, there is no equivalent
 * function for reading in the data as a null-terminated string, since the
 * DER encoding could validly contain zero bytes.
 *
 * @param keybuffer Buffer containing the base64-encoded public key
 * @return the EC_KEY
 */
EC_KEY * cryptosupport_read_buffer_public_key(Buffer * keybuffer) {
	EC_KEY * eckey = NULL;
	unsigned char const * keydata;

	keydata = (unsigned char const *)buffer_get_buffer(keybuffer);

	eckey = d2i_EC_PUBKEY(NULL, & keydata, buffer_get_pos(keybuffer));
	if (eckey == NULL) {
		LOG(LOG_ERR, "Error reading public key: %lu\n", ERR_get_error());
		//ERR_load_crypto_strings();
		//LOG(LOG_ERR, "%s\n", ERR_error_string(ERR_get_error(), NULL));
	}

	return eckey;
}

/**
 * Convert a base64-encoded (PEM) private key stored in a buffer into an
 * OpenSSL EVP-PKEY private key.
 * The returned key is newly allocated and so should be subsequently freed by
 * the calling code.
 *
 * @param keybuffer Buffer containing the base64-encoded private key
 * @return the EVP_PKEY
 */
EVP_PKEY * cryptosupport_read_base64_buffer_private_key(Buffer * keybuffer) {
	EVP_PKEY * pkey = NULL;
	Buffer * decoded;

	decoded = buffer_new(base64_decode_size_max(buffer_get_pos(keybuffer)));
	base64_decode_buffer(keybuffer, decoded);

	pkey = cryptosupport_read_buffer_private_key(decoded);

	buffer_delete(decoded);

	return pkey;
}

/**
 * Convert a base64-encoded (PEM) private key stored as a null-terminated string
 * into an OpenSSL EVP-PKEY private key.
 * The returned key is newly allocated and so should be subsequently freed by
 * the calling code.
 *
 * @param keystring Null-terminated string containing the base64-encoded
 *                  private key
 * @return the EVP_PKEY
 */
EVP_PKEY * cryptosupport_read_base64_string_private_key(char const * keystring) {
	EVP_PKEY * pkey = NULL;
	Buffer * decoded;

	decoded = buffer_new(base64_decode_size_max(strlen(keystring)));
	base64_decode_string(keystring, decoded);

	pkey = cryptosupport_read_buffer_private_key(decoded);

	buffer_delete(decoded);

	return pkey;
}

/**
 * Convert a binary-encoded (DER) private key stored in a buffer into an
 * OpenSSL EVP-PKEY private key.
 * The returned key is newly allocated and so should be subsequently freed by
 * the calling code.
 * Unlike the function for reading a PEM private key, there is no equivalent
 * function for reading in the data as a null-terminated string, since the
 * DER encoding could validly contain zero bytes.
 *
 * @param keybuffer Buffer containing the base64-encoded private key
 * @return the EVP_PKEY
 */
EVP_PKEY * cryptosupport_read_buffer_private_key(Buffer * keybuffer) {
	EVP_PKEY * pkey = NULL;
	unsigned char const * keydata;

	keydata = (unsigned char const *)buffer_get_buffer(keybuffer);

	pkey = d2i_AutoPrivateKey(NULL, & keydata, buffer_get_pos(keybuffer));
	if (pkey == NULL) {
		LOG(LOG_ERR, "Error reading private key: %lu\n", ERR_get_error());
		//ERR_load_crypto_strings();
		//LOG(LOG_ERR, "%s\n", ERR_error_string(ERR_get_error(), NULL));
	}

	return pkey;
}

/**
 * Encrypt data using AES128 GCM. GCM includes a proceeding MAC for integrity.
 *
 * @param key The 128-bit key to use to encrypt the data, in binary format
 * @param iv The IV to use for the encryption
 * @param bufferin The data to encrypt
 * @param encrpytedout buffer to hold the resulting encrypted data
 * @return true if the encryption was successful, false o/w
 */
bool cryptosupport_encrypt(Buffer const * key, Buffer const * iv, Buffer const * bufferin, Buffer * encryptedout) {
	EVP_CIPHER_CTX * ctx;
	size_t length_in;
	int length_out;
	size_t length_written;
	unsigned char * bufferout;
	size_t length_iv;
	int result;

	length_iv = buffer_get_pos(iv);
	length_in = buffer_get_pos(bufferin);
	length_out = length_in + EVP_MAX_BLOCK_LENGTH + CRYPTOSUPPORT_TAG_LENGTH;
	buffer_set_min_size(encryptedout, length_out);
	length_written = 0;
	bufferout = (unsigned char *)buffer_get_buffer(encryptedout);

	ctx = EVP_CIPHER_CTX_new();
	//EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);
	result = EVP_CipherInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL, 1);

	if (result == 1) {
		EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, length_iv, NULL);

		result = EVP_CipherInit_ex(ctx, NULL, NULL, (unsigned char const *)buffer_get_buffer(key), (unsigned char const *)buffer_get_buffer(iv), 1);
	}

	if (result == 1) {
		result = EVP_CipherUpdate(ctx, bufferout + length_written, & length_out, (unsigned char const *)buffer_get_buffer(bufferin), length_in);
	}
	
	if (result == 1) {
		length_written += length_out;

		result = EVP_CipherFinal_ex(ctx, bufferout + length_written, & length_out);
	}
	
	if (result == 1) {
		length_written += length_out;

		result = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, CRYPTOSUPPORT_TAG_LENGTH, bufferout + length_written);
	}
	
	if (result == 1) {
		length_written += CRYPTOSUPPORT_TAG_LENGTH;
		buffer_set_pos(encryptedout, length_written);
	}

	EVP_CIPHER_CTX_free(ctx);

	if (result != 1) {
		LOG(LOG_ERR, "Error encrypting data: %lu\n", ERR_get_error());
	}

	return (result == 1);
}

/**
 * Decrypt data encrypted using AES128 GCM. GCM includes a proceeding MAC for 
 * integrity and the decryption will fail if this doesn't match the data.
 *
 * @param key The 128-bit key to use to decrypt the data, in binary format
 * @param iv The IV used to encrypt the data
 * @param bufferin The encrypted data to decrypt
 * @param cleartextout buffer to hold the resulting cleartext
 * @return true if the decryption was successful and the integrity check
 *         succeeded, false o/w
 */
bool cryptosupport_decrypt(Buffer const * key, Buffer const * iv, Buffer const * bufferin, Buffer * cleartextout) {
	EVP_CIPHER_CTX * ctx;
	size_t length_in;
	int length_out;
	size_t length_written;
	unsigned char * bufferstart;
	unsigned char * bufferout;
	size_t length_iv;
	int result;

	length_iv = buffer_get_pos(iv);
	length_in = buffer_get_pos(bufferin) - CRYPTOSUPPORT_TAG_LENGTH;
	length_out = length_in;
	buffer_set_min_size(cleartextout, length_out);
	length_written = 0;
	bufferstart = (unsigned char *)buffer_get_buffer(bufferin);
	bufferout = (unsigned char *)buffer_get_buffer(cleartextout);

	ctx = EVP_CIPHER_CTX_new();
	//result = EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);
	result = EVP_CipherInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL, 0);

	if (result == 1) {
		EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, length_iv, NULL);

		result = EVP_CipherInit_ex(ctx, NULL, NULL, (unsigned char const *)buffer_get_buffer(key), (unsigned char const *)buffer_get_buffer(iv), 0);
	}

	if (result == 1) {
		result = EVP_CipherUpdate(ctx, bufferout + length_written, & length_out, bufferstart, length_in);
	}

	if (result == 1) {
		result = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, CRYPTOSUPPORT_TAG_LENGTH, bufferstart + length_in);
	}

	if (result == 1) {
		length_written += length_out;

		result = EVP_CipherFinal_ex(ctx, bufferout + length_written, & length_out);
	}
	
	if (result == 1) {
		length_written += length_out;
		buffer_set_pos(cleartextout, length_written);
	}
	//EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, CRYPTOSUPPORT_TAG_LENGTH, bufferout + length_written);
	//length_written += CRYPTOSUPPORT_TAG_LENGTH;

	EVP_CIPHER_CTX_free(ctx);

	if (result != 1) {
		LOG(LOG_ERR, "Error decrypting data: %lu\n", ERR_get_error());
	}

	return (result == 1);
}

/**
 * Encrypt data using AES128 GCM. GCM includes a proceeding MAC for integrity.
 * The output format is in the form IV:CIPHERTEXT where both IV and CIPHERTEXT
 * are base64-encoded. The IV will be chosen at random
 *
 * @param key The 128-bit key to use to encrypt the data, in binary format
 * @param bufferin The data to encrypt
 * @param encrpytedout buffer to hold the resulting encrypted data
 * @return true if the encryption was successful, false o/w
 */
bool cryptosupport_encrypt_iv_base64(Buffer const * key, Buffer const * bufferin, Buffer * encryptedout) {
	Buffer * iv;
	bool result;
	Buffer * encrypted;
	Buffer * base64;

	result = false;
	if (key && bufferin && encryptedout) {
		iv = buffer_new(CRYPTOSUPPORT_IV_SIZE);
		cryptosupport_generate_iv(iv);
		encrypted = buffer_new(0);

		result = cryptosupport_encrypt(key, iv, bufferin, encrypted);
		if (result) {
			base64 = buffer_new(0);

			buffer_clear(encryptedout);
			// Add the base64-encoded IV
			base64_encode_buffer(iv, base64);
			buffer_append_buffer(encryptedout, base64);
			// Add the separator
			buffer_append_string(encryptedout, ":");
			// Add the base64-encoded ciphertext
			base64_encode_buffer(encrypted, base64);
			buffer_append_buffer(encryptedout, base64);

			buffer_delete(base64);
		}
	}

	return result;
}

/**
 * Decrypt data encrypted using AES128 GCM. GCM includes a proceeding MAC for 
 * integrity and the decryption will fail if this doesn't match the data.
 * The output format is in the form IV:CIPHERTEXT where both IV and CIPHERTEXT
 * are base64-encoded. The IV will be chosen at random
 *
 * @param key The 128-bit key to use to decrypt the data, in binary format
 * @param bufferin The encrypted data to decrypt, in the form IV:CIPHERTEXT
 * @param cleartextout buffer to hold the resulting cleartext
 * @return true if the decryption was successful and the integrity check
 *         succeeded, false o/w
 */
bool cryptosupport_decrypt_iv_base64(Buffer const * key, Buffer const * bufferin, Buffer * cleartextout) {
	bool result;
	Buffer * iv;
	Buffer * ciphertext;
	char * start;
	unsigned int end;
	unsigned int pos;

	result = false;
	if (key && bufferin && cleartextout) {
		start = buffer_get_buffer(bufferin);

		if (start) {
			end = buffer_get_pos(bufferin);
			pos = 0;
			while ((pos < end) && (start[pos] != ':')) {
				pos++;
			}

			if ((pos > 0) && (pos < end)) {
				iv = buffer_new(0);
				buffer_clear(iv);
				base64_decode_mem(start, pos, iv);

				ciphertext = buffer_new(0);
				buffer_clear(ciphertext);
				base64_decode_mem(start + pos + 1, end - pos - 1, ciphertext);

				result = cryptosupport_decrypt(key, iv, ciphertext, cleartextout);

				buffer_delete(iv);
				buffer_delete(ciphertext);
			}
		}
	}

	return result;
}

/**
 * Encrypt data using AES128 GCM. GCM includes a proceeding MAC for integrity.
 *
 * @param key Buffer to store the resulting key.
 * @param size The length of the key in bytes
 * @param iv The IV to use for the encryption
 * @param bufferin The data to encrypt
 * @param encrpytedout buffer to hold the resulting encrypted data
 * @return true if the encryption was successful, false o/w
 */
bool cryptosupport_generate_symmetric_key(Buffer * key, unsigned int size) {
	int result;

	// Allocate space
	buffer_set_min_size(key, size);
	// Generate random key
	result = RAND_bytes((unsigned char *)buffer_get_buffer(key), size);
	if (result != 1) {
		LOG(LOG_ERR, "Error generating key randomness: %lu\n", ERR_get_error());
	}
	buffer_set_pos(key, size);

	return (result == 1);
}

/**
 * Generate a random IV for encryption. The IV will be 16 bytes long and stored
 * in binary format. Uses OpenSSL's secure random number generator.
 *
 * @param iv Buffer to store the resulting IV.
 * @return 
 */
void cryptosupport_generate_iv(Buffer * iv) {
	int result;

	// Allocate space
	buffer_set_min_size(iv, CRYPTOSUPPORT_IV_SIZE);
	// Allocate random IV
	result = RAND_bytes((unsigned char *)buffer_get_buffer(iv), CRYPTOSUPPORT_IV_SIZE);	
	if (result != 1) {
		LOG(LOG_ERR, "Error generating iv randomness: %lu\n", ERR_get_error());
	}
	buffer_set_pos(iv, CRYPTOSUPPORT_IV_SIZE);
}

/**
 * Create a SHA256 hash of the provided data.
 *
 * @param bufferin The data to hash
 * @param bufferout The SHA256 hash, 256 bytes worth of it
 * @return true if the hash completed successfully, false o/w
 */
bool cryptosupport_generate_sha256(Buffer * bufferin, Buffer * bufferout) {
	EVP_MD_CTX * mdctx = NULL;
	EVP_MD const * digest_type = NULL;
	int result;
	unsigned int length;

	buffer_set_min_size(bufferout, EVP_MAX_MD_SIZE);

	digest_type = EVP_sha256();
	mdctx = EVP_MD_CTX_create();

	result = EVP_DigestInit_ex(mdctx, digest_type, NULL);
	if (result == 1) {
		result = EVP_DigestUpdate(mdctx, buffer_get_buffer(bufferin), buffer_get_pos(bufferin));
	}
	
	if (result == 1) {
		result = EVP_DigestFinal_ex(mdctx, (unsigned char *)buffer_get_buffer(bufferout), & length);
	}

	if (result == 1) {
		buffer_set_pos(bufferout, length);
	}

	EVP_MD_CTX_destroy(mdctx);

	if (result < 0) {
		LOG(LOG_ERR, "Error hashing sha256: %lu\n", ERR_get_error());
	}

	return (result == 1);
}

/**
 * Generate a commitment based on the provided public key. This is a SHA256
 * hash of the public key encoded in DER format.
 *
 * @param publickey The public key to form the commitment of
 * @param commitmennt The resulting 256-byte commitment as a binary blob
 * @return true if the commitment was generated successfully, false o/w
 */
bool cryptosupport_generate_commitment(EC_KEY * publickey, Buffer * commitment) {
	bool result;
	Buffer * keyder;

	keyder = buffer_new(0);
	buffer_clear(commitment);

	cryptosupport_getpublicder(publickey, keyder);
	result = cryptosupport_generate_sha256(keyder, commitment);

	buffer_delete(keyder);

	return result;
}

/**
 * Generate a base64-encoded commitment based on the provided public key. 
 * This is a SHA256 hash of the public key encoded in DER format.
 *
 * @param publickey The public key to form the commitment of
 * @param commitmennt The resulting commitment encoded as a base64 string
 * @return true if the commitment was generated successfully, false o/w
 */
bool cryptosupport_generate_commitment_base64(EC_KEY * publickey, Buffer * commitment) {
	bool result;
	Buffer * buffer;

	buffer = buffer_new(0);

	result = cryptosupport_generate_commitment(publickey, buffer);
	if (result == true) {
		base64_encode_buffer(buffer, commitment);
	}
	buffer_delete(buffer);

	return result;
}

/** @} addtogroup Utility */

