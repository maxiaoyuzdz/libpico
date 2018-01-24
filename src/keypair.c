/** \ingroup Crypto
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
 * @brief Manage ECDH public/private key pairs
 * @section DESCRIPTION
 *
 * The KeyPair class is a wrapper for OpenSSL Diffie Hellman Elliptic Curve
 * public/private key pairs for use by libpam. It also provides various
 * utilities for importing from and exporting to file.
 *
 */

/** \addtogroup Crypto
 *  @{
 */

#include <stdio.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/evp.h>
#include <openssl/pkcs12.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include "pico/debug.h"
#include "pico/buffer.h"
#include "pico/base64.h"
#include "pico/curlsupport.h"
#include "pico/cryptosupport.h"
#include "pico/log.h"
#include "pico/keypair.h"

// Defines

/**
 * @brief Output format value used by OpenSSL to represent ASN.1/DER
 *
 * OpenSSL uses values to represent different key formats, which are returned
 * by some functions. This defines the value used to represent the ASN.1/DER
 * format by OpenSSL.
 */
#define FORMAT_ASN1 (4)

// Structure definitions

/**
 * @brief Structure containing public and possibly its associated priviate key
 *
 * Opaque structure containing the private fields of the KeyPair class.
 *
 * This is provided as the first parameter of every non-static function and 
 * stores the operation's context.
 * 
 * The structure typedef is in keypair.h
 */
struct _KeyPair {
	EC_KEY * eckey;
	EVP_PKEY * pkey;
};

// Function prototypes

EVP_PKEY * keypair_load_private_key(char const * file);
EC_KEY * keypair_load_public_key(char const * file);

// Function definitions

/**
 * Create a new instance of the class.
 *
 * @return The newly created object.
 */
KeyPair * keypair_new() {
	KeyPair * keypair;
	
	keypair = CALLOC(sizeof(KeyPair), 1);
	
	return keypair;
}

/**
 * Delete an instance of the class, freeing up the memory allocated to it.
 *
 * @param keypair The object to free.
 */
void keypair_delete(KeyPair * keypair) {
	if (keypair) {
		keypair_clear_keys(keypair);
		FREE(keypair);
	}
}

/**
 * Generate a new public-private ECDH key pair. Uses OpenSSL's secure
 * random functions.
 *
 * @param keypair The KeyPair structure to store the generated key in.
 * @return true if the keys were successfully generated, false o/w.
 */
bool keypair_generate(KeyPair * keypair) {
	EC_GROUP * group = NULL;
	EC_KEY * eckey = NULL;
	EVP_PKEY * pkey = NULL;
	int result;
	bool success;

	success = true;
	keypair_clear_keys(keypair);

	/////////////// ECPK Parametners ///////////////

	// TODO: Check when (if?) the group should be freed using EC_GROUP_clear_free
	group = EC_GROUP_new_by_curve_name(CRYPTOSUPPORT_ECCURVE);
	if (group == NULL) {
		LOG(LOG_ERR, "Error EC not supported: " LIBPICO_STR(CRYPTOSUPPORT_ECCURVE) "\n");
		success = false;
	}

	if (success) {
		EC_GROUP_set_asn1_flag(group, OPENSSL_EC_NAMED_CURVE);
		EC_GROUP_set_point_conversion_form(group, POINT_CONVERSION_UNCOMPRESSED);
	}

	/////////////// Key Pair ///////////////

	if (success) {
		eckey = EC_KEY_new();
		if (eckey != NULL) {
			result = EC_KEY_set_group(eckey, group);
			if (result != 0) {
				result = EC_KEY_generate_key(eckey);
				if (result == 0) {
					LOG(LOG_ERR, "Error generating EC key\n");
					success = false;
				}
			}
			else {
				LOG(LOG_ERR, "Error setting EC group\n");
				success = false;
			}
		}
		else {
			LOG(LOG_ERR, "Error creating EC key structure\n");
			success = false;
		}
	}

	/////////////// Private Key ///////////////

	if (success) {
		pkey = EVP_PKEY_new();

		result = EVP_PKEY_set1_EC_KEY(pkey, eckey);
		if ((result == 0) || (pkey == NULL)) {
			LOG(LOG_ERR, "Error, EC key not generated\n");
			success = false;
		}
	}

	/////////////// Store result ///////////////

	if (success) {
		keypair->pkey = pkey;
		keypair->eckey = eckey;
	}

	return success;
}

/**
 * Export a public-private key pair to files. Two files will be output, one
 * for each of the public and private key respectively. The keys will be 
 * exported in binary DER format.
 *
 * @param keypair The key pair to export
 * @param key_public Full filename of the file to export the public key to
 * @param key_private Full filename of the file to export the private key to
 */
void keypair_export(KeyPair * keypair, char const * key_public, char const * key_private) {
	BIO * out = NULL;
	PKCS8_PRIV_KEY_INFO * p8inf = NULL;
	int result;

	/////////////// PKCS Private Key ///////////////

	// TODO: Check whether p8inf should be freed using PKCS8_PRIV_KEY_INFO_free
	p8inf = EVP_PKEY2PKCS8(keypair->pkey);
	if (p8inf == NULL) {
		LOG(LOG_ERR, "Error converting private key to PKCS\n");
	}

	out = BIO_new_file (key_private, "w+");
	if (out != NULL) {
		// ASN1
		i2d_PKCS8_PRIV_KEY_INFO_bio(out, p8inf);
		// PEM
		//PEM_write_bio_PKCS8_PRIV_KEY_INFO(out, p8inf);
		BIO_free(out);
	}
	else {
		LOG(LOG_ERR, "Error opening private key file\n");
	}

	/////////////// EC Public Key ///////////////

	out = BIO_new_file (key_public, "w+");
	if (out != NULL) {
		//if (outformat == FORMAT_ASN1)
		result = i2d_EC_PUBKEY_bio(out, keypair->eckey);
		//i = PEM_write_bio_EC_PUBKEY(out, keypair->eckey);
		if (result == 0) {
			LOG(LOG_ERR, "Error converting public key to DER\n");
		}

		BIO_free(out);
	}
	else {
		LOG(LOG_ERR, "Error opening public key file\n");
	}
}

/**
 * Clear any public or private keys stored in the KeyPair structure and reduce
 * their reference counts by one (freeing them if they reach zero). The KeyPair
 * structure itself will not be released (use keypair_delete() for that).
 *
 * @param keypair The KeyPair structure to clear the keys from
 * @return 
 */
void keypair_clear_keys(KeyPair * keypair) {
	if (keypair->eckey) {
		EC_KEY_free(keypair->eckey);
		keypair->eckey = NULL;
	}
	if (keypair->pkey) {
		EVP_PKEY_free(keypair->pkey);
		keypair->pkey = NULL;
	}
}

/**
 * Load a public-private key pair in from file.
 *
 * @param keypair The KeyPair object to laod the keys into
 * @param key_public The full filename of the public key stored in DER format
 *        or NULL if no attempt should be made to load
 * @param key_private The full filename of the private key stored in DER format
 *        or NULL if no attempt should be made to load
 * @return 
 */
bool keypair_import(KeyPair * keypair, char const * key_public, char const * key_private) {
	bool result;

	keypair_clear_keys(keypair);

	result = true;
	if (key_private) {
		keypair->pkey = keypair_load_private_key(key_private);
		result = result && (keypair->pkey != NULL);
	}
	if (key_public) {
		keypair->eckey = keypair_load_public_key(key_public);
		result = result && (keypair->eckey != NULL);
	}

	if (result == false) {
		keypair_clear_keys(keypair);
	}

	return result;
}

/**
 * Load a private key, stored in DER format, in from file.
 *
 * @param file The full filename of the private key stored in DER format
 * @return The OpenSSL private key loaded
 */
EVP_PKEY * keypair_load_private_key(char const * file) {
	BIO * key = NULL;
	EVP_PKEY * pkey = NULL;

	key = BIO_new_file(file, "rb");

	if (key != NULL) {
		pkey = d2i_PrivateKey_bio(key, NULL);
		// Alternatively
		//EC_KEY * eckey = d2i_ECPrivateKey_bio(key, NULL);
		BIO_free(key);
		if (pkey == NULL) {
			LOG(LOG_ERR, "Error reading private key\n");
		}
	}
	else {
		LOG(LOG_ERR, "Error opening private key file\n");
	}

	return (pkey);
}

/**
 * Load a public key, stored in DER format, in from file.
 *
 * @param file The full filename of the public key stored in DER format
 * @return The OpenSSL public key loaded
 */
EC_KEY * keypair_load_public_key(char const * file) {
	BIO * key = NULL;
	EC_KEY * eckey = NULL;

	key = BIO_new_file(file, "rb");

	if (key != NULL) {
		eckey = d2i_EC_PUBKEY_bio(key, NULL);
		BIO_free(key);
		if (eckey == NULL) {
			LOG(LOG_ERR, "Error reading public key\n");
		}
	}
	else {
		LOG(LOG_ERR, "Error opening public key file\n");
	}

	return (eckey);
}

/**
 * Get the public key in DER format.
 *
 * @param keypair The KeyPair object to extract the public key from
 * @param buffer A buffer to store the resulting DER-encoded public key into
 */
void keypair_getpublicder(KeyPair * keypair, Buffer * buffer) {
	cryptosupport_getpublicder(keypair->eckey, buffer);
}

/**
 * Get the public key in PEM format.
 *
 * @param keypair The KeyPair object to extract the public key from
 * @param buffer A buffer to store the resulting PEM-encoded public key into
 */
void keypair_getpublicpem(KeyPair * keypair, Buffer * buffer) {
	cryptosupport_getpublicpem(keypair->eckey, buffer);
}

/**
 * Extract the OpenSSL format public key.
 *
 * @param keypair The KeyPair object to extract the public key from
 * @return The OpenSSL public key
 */
EC_KEY * keypair_getpublickey(KeyPair * keypair) {
	return keypair->eckey;
}

/**
 * Set the OpenSSL format public key.
 *
 * @param keypair The KeyPair object to extract the public key from
 * @param eckey The OpenSSL public key
 */
void keypair_setpublickey(KeyPair * keypair, EC_KEY * eckey) {
	keypair->eckey = eckey;
}

/**
 * Extract the OpenSSL format private key.
 *
 * @param keypair The KeyPair object to extract the private key from
 * @return The OpenSSL private key
 */
EVP_PKEY * keypair_getprivatekey(KeyPair * keypair) {
	return keypair->pkey;
}

/**
 * Set the OpenSSL format private key.
 *
 * @param keypair The KeyPair object to extract the private key from
 * @param pkey The OpenSSL private key
 */
void keypair_setprivatekey(KeyPair * keypair, EVP_PKEY * pkey) {
	keypair->pkey = pkey;
}

/**
 * Use the private key from a KeyPair to sign the given data. The signature
 * will be a signed SHA256 hash of the data.
 *
 * @param keypair The KeyPair object containing the private key to be used to 
 *                sign the data
 * @param bufferin Buffer containing the data to sign
 * @param bufferout Buffer to store the resulting signature into.
 * @return 
 */
void keypair_sign_data(KeyPair * keypair, Buffer const * bufferin, Buffer * bufferout) {
	EVP_PKEY_CTX * pctx = NULL;
	EVP_MD const * digest_type = NULL;
	EVP_PKEY * pkey = NULL;
	EVP_MD_CTX * mdctx = NULL;
	size_t length;
	int result;

	buffer_clear(bufferout);
	buffer_set_min_size(bufferout, EVP_MAX_MD_SIZE);
	length = buffer_get_size(bufferout);

	pkey = keypair_getprivatekey(keypair);
	digest_type = EVP_sha256();
	mdctx = EVP_MD_CTX_create();
	result = EVP_DigestSignInit(mdctx, &pctx, digest_type, NULL, pkey);

	if (result == 1) {
		result = EVP_DigestSignUpdate(mdctx, buffer_get_buffer(bufferin), buffer_get_pos(bufferin));
	}
	
	if (result == 1) {
		result = EVP_DigestSignFinal(mdctx, (unsigned char *)buffer_get_buffer(bufferout), &length);
	}

	if (result == 1) {
		buffer_set_pos(bufferout, length);
	}

	EVP_MD_CTX_destroy(mdctx);

	if (result != 1) {
		LOG(LOG_ERR, "Error signing data: %lu\n", ERR_get_error());
	}
}

/** @} addtogroup Crypto */

