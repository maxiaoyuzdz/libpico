/** \ingroup Protocol
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
 * @brief Shared data and secrets needed for SIGMA-I protocol
 * @section DESCRIPTION
 *
 * The Shared class encapsulates all of the shared data and secrets needed to
 * perform the SIGMA-I protocol. For example, identity keys, ephemeral keys,
 * nonces and shared generates secrets.
 *
 * Some of the contents are provided at creation (e.g. the service identity
 * key, whereas others are added as the protocol progresses.
 * 
 */

/** \addtogroup Protocol
 *  @{
 */

#include <stdio.h>
#include <openssl/ec.h>
//#include <malloc.h>
#include "pico/debug.h"
#include "pico/buffer.h"
#include "pico/nonce.h"
#include "pico/keypair.h"
#include "pico/sigmakeyderiv.h"
#include "pico/keyagreement.h"
#include "pico/log.h"
#include "pico/shared.h"
#include "pico/messagestatus.h"

// Defines

// Structure definitions

/**
 * @brief Encapsulates all data and secrets needed to perform the SIGMA-I 
 * protocol
 *
 * Opaque structure containing the private fields of the Shared class.
 * 
 * This is provided as the first parameter of every non-static function and 
 * stores the operation's context.
 * 
 * The structure typedef is in shared.h
 */
struct _Shared {
	Buffer * pMacKey;
	Buffer * pEncKey;
	Buffer * vMacKey;
	Buffer * vEncKey;
	Buffer * sharedKey;

	Nonce * serviceNonce;
	Nonce * picoNonce;

	KeyPair * serviceIdentityKey;
	KeyPair * serviceEphemeralKey;
	KeyPair * picoIdentityKey;
	KeyPair * picoEphemeralKey;

	Feedback * feedback;

	char status;

	//EC_KEY * picoIdentityPublicKey;
	//EC_KEY * picoEphemeralPublicKey;
	//EC_KEY * serviceIdentityPublicKey;
	//EC_KEY * serviceEphemeralPublicKey;
};

// Function prototypes

void shared_generate_shared_secrets(Shared * shared);

// Function definitions

/**
 * Create a new instance of the class.
 *
 * @return The newly created object.
 */
Shared * shared_new() {
	Shared * shared;

	shared = CALLOC(sizeof(Shared), 1);

	shared->pMacKey = buffer_new(32); // 256 bits
	shared->pEncKey = buffer_new(16); // 128 bits
	shared->vMacKey = buffer_new(32); // 256 bits
	shared->vEncKey = buffer_new(16); // 128 bits
	shared->sharedKey = buffer_new(16); // 128 bits

	shared->serviceNonce = nonce_new();
	nonce_generate_random(shared->serviceNonce);

	shared->picoNonce = nonce_new();

	shared->serviceIdentityKey = keypair_new();
	shared->serviceEphemeralKey = keypair_new();
	shared->picoIdentityKey = keypair_new();
	shared->picoEphemeralKey = keypair_new();

	shared->feedback = feedback_new();

	shared->status = MESSAGESTATUS_INVALID;

	//shared->picoIdentityPublicKey = NULL;
	//shared->picoEphemeralPublicKey = NULL;
	//shared->serviceIdentityPublicKey = NULL;
	//shared->serviceEphemeralPublicKey = NULL;

	return shared;
}

/**
 * Delete an instance of the class, freeing up the memory allocated to it.
 *
 * @param shared The object to free.
 */
void shared_delete(Shared * shared) {
	if (shared) {
		if (shared->pMacKey) {
			buffer_delete(shared->pMacKey);
		}
		if (shared->pEncKey) {
			buffer_delete(shared->pEncKey);
		}
		if (shared->vMacKey) {
			buffer_delete(shared->vMacKey);
		}
		if (shared->vEncKey) {
			buffer_delete(shared->vEncKey);
		}
		if (shared->sharedKey) {
			buffer_delete(shared->sharedKey);
		}
		if (shared->serviceNonce) {
			nonce_delete(shared->serviceNonce);
		}
		if (shared->picoNonce) {
			nonce_delete(shared->picoNonce);
		}
		if (shared->serviceIdentityKey) {
			keypair_delete(shared->serviceIdentityKey);
		}
		if (shared->serviceEphemeralKey) {
			keypair_delete(shared->serviceEphemeralKey);
		}
		if (shared->picoIdentityKey) {
			keypair_delete(shared->picoIdentityKey);
		}
		if (shared->picoEphemeralKey) {
			keypair_delete(shared->picoEphemeralKey);
		}
		if (shared->feedback) {
			feedback_delete(shared->feedback);
		}
/*		if (shared->picoIdentityPublicKey) {*/
/*			EC_KEY_free(shared->picoIdentityPublicKey);*/
/*		}*/
/*		if (shared->picoEphemeralPublicKey) {*/
/*			EC_KEY_free(shared->picoEphemeralPublicKey);*/
/*		}*/
/*		if (shared->serviceIdentityPublicKey) {*/
/*			EC_KEY_free(shared->serviceIdentityPublicKey);*/
/*		}*/
/*		if (shared->serviceEphemeralPublicKey) {*/
/*			EC_KEY_free(shared->serviceEphemeralPublicKey);*/
/*		}*/

		FREE(shared);
	}
}

/**
 * Attempts to load the public and private keys from the files named. If this
 * fails because the failes don't exist, a new set of keys is generated and
 * are saved out to the files, as well as being stored in the Shared object.
 * This is used to load the keys for the service verifier.
 * If a NULL filename is provided, no keypair is generated to replace it.
 *
 * @param shared The shared object to store the keys in
 * @param key_public Full filename of the public key to attempt to load
          or NULL if no attempt should be made to load
 * @param key_private Full filename of the private key to attempt to load
          or NULL if no attempt should be made to load
 */
void shared_load_or_generate_keys(Shared * shared, char const * key_public, char const * key_private) {
	KeyPair * serviceIdentityKey;
	bool result;

	serviceIdentityKey = shared_get_service_identity_key(shared);
	result = keypair_import(serviceIdentityKey, key_public, key_private);
	if (!result) {
		keypair_generate(serviceIdentityKey);
		keypair_export(serviceIdentityKey, key_public, key_private);
	}
}


/**
 * Attempts to load the public and private keys from the files named. If this
 * fails because the failes don't exist, a new set of keys is generated and
 * are saved out to the files, as well as being stored in the Shared object.
 * This is used to load the keys for the pico prover.
 * If a NULL filename is provided, no keypair is generated to replace it.
 *
 * @param shared The shared object to store the keys in
 * @param key_public Full filename of the public key to attempt to load
 *        or NULL if no attempt should be made to load
 * @param key_private Full filename of the private key to attempt to load
 *        or NULL if no attempt should be made to load
 */
void shared_load_or_generate_pico_keys(Shared * shared, char const * key_public, char const * key_private) {
	KeyPair * picoIdentityKey;
	bool result;

	picoIdentityKey = shared_get_pico_identity_key(shared);
	result = keypair_import(picoIdentityKey, key_public, key_private);
	if (!result) {
		keypair_generate(picoIdentityKey);
		keypair_export(picoIdentityKey, key_public, key_private);
	}
}


/**
 * Attempts to load the public keys (not the private keys) from the files
 * named for the service. This is used by the pico prover to load the identity
 * public key of the service verifier.
 *
 * @param shared The shared object to store the keys in
 * @param key_public Full filename of the public key to attempt to load
 *        or NULL if no attempt should be made to load
 * @param key_private Full filename of the private key to attempt to load
 *        or NULL if no attempt should be made to load
 * @return TRUE if keys could be loaded (or the filname was NULL), FALSE o/w
 */
bool shared_load_service_keys(Shared * shared, char const * key_public, char const * key_private) {
	KeyPair * serviceIdentityKey;
	bool result;

	serviceIdentityKey = shared_get_service_identity_key(shared);
	result = keypair_import(serviceIdentityKey, key_public, key_private);

	return result;
}

/**
 * Generate a series of shared secrets needed to complete the Pico protocol.
 * The secrets are generated from the ephemeral private key of the service
 * and the ephemeral public key of the Pico. The resulting shared secrets are
 * stored in the Shared object and used for various purposes, including
 * encrypting future messages, signing messages and generating MACs.
 * Note that these secrets can be generated by both the service and the Pico.
 *
 * @param shared The Shared object to get the keys from and store the results 
 *               in
 */
void shared_generate_shared_secrets(Shared * shared) {
	Buffer * sharedSecret;
	EVP_PKEY * vEphemPriv;
	EC_KEY * picoEphemeralPublicKey;
	SigmaKeyDeriv * sigmakeyderiv;

	// Generate ECDH shared secret
	sharedSecret = buffer_new(0);

	vEphemPriv = keypair_getprivatekey(shared->serviceEphemeralKey);
	picoEphemeralPublicKey = keypair_getpublickey(shared->picoEphemeralKey);

	keyagreement_generate_secret(vEphemPriv, picoEphemeralPublicKey, sharedSecret);

	// Generate key data
	sigmakeyderiv = sigmakeyderiv_new();
	sigmakeyderiv_set(sigmakeyderiv, sharedSecret, shared->picoNonce, shared->serviceNonce);
	buffer_delete(sharedSecret);

	sigmakeyderiv_get_next_key(sigmakeyderiv, shared->pMacKey, 256);

	sigmakeyderiv_get_next_key(sigmakeyderiv, shared->pEncKey, 128);

	sigmakeyderiv_get_next_key(sigmakeyderiv, shared->vMacKey, 256);

	sigmakeyderiv_get_next_key(sigmakeyderiv, shared->vEncKey, 128);

	sigmakeyderiv_get_next_key(sigmakeyderiv, shared->sharedKey, 128);

	sigmakeyderiv_delete(sigmakeyderiv);
}

/**
 * Generate a series of shared secrets needed to complete the Pico protocol.
 * The secrets are generated from the ephemeral private key of the service
 * and the ephemeral public key of the Pico. The resulting shared secrets are
 * stored in the Shared object and used for various purposes, including
 * encrypting future messages, signing messages and generating MACs.
 * Note that these secrets can be generated by both the service and the Pico.
 *
 * @param shared The Shared object to get the keys from and store the results 
 *               in
 */
void shared_generate_shared_secrets_pico(Shared * shared) {
	Buffer * sharedSecret;
	EVP_PKEY * pEphemPriv;
	SigmaKeyDeriv * sigmakeyderiv;
	EC_KEY * serviceEphemeralPublicKey;

	// Generate ECDH shared secret
	sharedSecret = buffer_new(0);

	pEphemPriv = keypair_getprivatekey(shared->picoEphemeralKey);
	serviceEphemeralPublicKey = keypair_getpublickey(shared->serviceEphemeralKey);

	keyagreement_generate_secret(pEphemPriv, serviceEphemeralPublicKey, sharedSecret);

	// Generate key data
	sigmakeyderiv = sigmakeyderiv_new();
	sigmakeyderiv_set(sigmakeyderiv, sharedSecret, shared->picoNonce, shared->serviceNonce);
	buffer_delete(sharedSecret);

	sigmakeyderiv_get_next_key(sigmakeyderiv, shared->pMacKey, 256);

	sigmakeyderiv_get_next_key(sigmakeyderiv, shared->pEncKey, 128);

	sigmakeyderiv_get_next_key(sigmakeyderiv, shared->vMacKey, 256);

	sigmakeyderiv_get_next_key(sigmakeyderiv, shared->vEncKey, 128);

	sigmakeyderiv_get_next_key(sigmakeyderiv, shared->sharedKey, 128);

	sigmakeyderiv_delete(sigmakeyderiv);
}

/**
 * Returns the service's nonce from the Shared object.
 *
 * @param shared The Shared object to get the details from
 * @return The service's nonce
 */
Nonce * shared_get_service_nonce(Shared const * shared) {
	return shared->serviceNonce;
}

/**
 * Returns the Pico's nonce from the Shared object.
 *
 * @param shared The Shared object to get the details from
 * @return The Pico's nonce
 */
Nonce * shared_get_pico_nonce(Shared const * shared) {
	return shared->picoNonce;
}

/**
 * Returns the service's long term identity key pair from the Shared object.
 *
 * @param shared The Shared object to get the details from
 * @return The service's long term identity key pair
 */
KeyPair * shared_get_service_identity_key(Shared const * shared) {
	return shared->serviceIdentityKey;
}

/**
 * Returns the pico's long term identity key pair from the Shared object.
 *
 * @param shared The Shared object to get the details from
 * @return The service's long term identity key pair
 */
KeyPair * shared_get_pico_identity_key(Shared const * shared) {
	return shared->picoIdentityKey;
}

/**
 * Returns the service's ephemeral key pair from the Shared object.
 *
 * @param shared The Shared object to get the details from
 * @return The service's ephemeral key pair
 */
KeyPair * shared_get_service_ephemeral_key(Shared const * shared) {
	return shared->serviceEphemeralKey;
}

/**
 * Returns the picos's ephemeral key pair from the Shared object.
 *
 * @param shared The Shared object to get the details from
 * @return The service's ephemeral key pair
 */
KeyPair * shared_get_pico_ephemeral_key(Shared const * shared) {
	return shared->picoEphemeralKey;
}

/**
 * Sets the Pico's long term identity public key.
 *
 * @param shared The Shared object to store the details in
 * @param picoIdentityPublicKey The public key to set the Pico's long term
 *        identity public key to
 */
void shared_set_pico_identity_public_key(Shared * shared, EC_KEY * picoIdentityPublicKey) {
	keypair_setpublickey(shared->picoIdentityKey, picoIdentityPublicKey);
}

/**
 * Sets the Service's long term identity public key.
 *
 * @param shared The Shared object to store the details in
 * @param serviceIdentityPublicKey The public key to set the Service's long term
 *        identity public key to
 */
void shared_set_service_identity_public_key(Shared * shared, EC_KEY * serviceIdentityPublicKey) {
	keypair_setpublickey(shared->serviceIdentityKey, serviceIdentityPublicKey);
}

/**
 * Sets the Pico's long term identity private key.
 *
 * @param shared The Shared object to store the details in
 * @param picoIdentityPrivateKey The private key to set the Pico's long term
 *        identity private key to
 */
void shared_set_pico_identity_private_key(Shared * shared, EVP_PKEY * picoIdentityPrivateKey) {
	keypair_setprivatekey(shared->picoIdentityKey, picoIdentityPrivateKey);
}

/**
 * Sets the Service's long term identity private key.
 *
 * @param shared The Shared object to store the details in
 * @param serviceIdentityPrivateKey The private key to set the Service's long
 *        term identity private key to
 */
void shared_set_service_identity_private_key(Shared * shared, EVP_PKEY * serviceIdentityPrivateKey) {
	keypair_setprivatekey(shared->serviceIdentityKey, serviceIdentityPrivateKey);
}

/**
 * Gets the Service's long term identity public key.
 *
 * @param shared The Shared object to store the details in
 * @return The service's long term identity public key
 */
EC_KEY * shared_get_service_identity_public_key(Shared const * shared) {
	return keypair_getpublickey(shared->serviceIdentityKey);
}

/**
 * Returns the Pico's long term identity public key from the Shared object.
 *
 * @param shared The Shared object to get the details from
 * @return The Pico's long term identity public key
 */
EC_KEY * shared_get_pico_identity_public_key(Shared const * shared) {
	return keypair_getpublickey(shared->picoIdentityKey);
}

/**
 * Sets the Pico's ephemeral public key.
 *
 * @param shared The Shared object to store the details in
 */
void shared_set_pico_ephemeral_public_key(Shared const * shared, EC_KEY * picoEphemeralPublicKey) {
	keypair_setpublickey(shared->picoEphemeralKey, picoEphemeralPublicKey);
}

/**
 * Sets the Service's ephemeral public key.
 *
 * @param shared The Shared object to store the details in
 */
void shared_set_service_ephemeral_public_key(Shared * shared, EC_KEY * serviceEphemeralPublicKey) {
	keypair_setpublickey(shared->serviceEphemeralKey, serviceEphemeralPublicKey);
}

/**
 * Returns the Pico's ephemeral public key from the Shared object.
 *
 * @param shared The Shared object to get the details from
 * @return The Pico's ephemeral public key
 */
EC_KEY * shared_get_pico_ephemeral_public_key(Shared const * shared) {
	return keypair_getpublickey(shared->picoEphemeralKey);
}

/**
 * Returns the Service's ephemeral public key from the Shared object.
 *
 * @param shared The Shared object to get the details from
 * @return The Service's ephemeral public key
 */
EC_KEY * shared_get_service_ephemeral_public_key(Shared const * shared) {
	return keypair_getpublickey(shared->serviceEphemeralKey);
}

/**
 * Returns a buffer to the Pico's symmetric encryption key.
 *
 * @param shared The Shared object to get the details from
 * @return A buffer containing the Pico's symmetric encryption key. This buffer
 *         is part of the Shared object, so should not be deleted (it will be
 *         automatically deleted when the Shared object is)
 */
Buffer * shared_get_prover_enc_key(Shared const * shared) {
	return shared->pEncKey;
}

/**
 * Returns a buffer to the Service's symmetric encryption key.
 *
 * @param shared The Shared object to get the details from
 * @return A buffer containing the Service's symmetric encryption key. This 
 *         buffer is part of the Shared object, so should not be deleted (it 
 *         will be automatically deleted when the Shared object is)
 */
Buffer * shared_get_verifier_enc_key(Shared const * shared) {
	return shared->vEncKey;
}

/**
 * Returns a buffer to the Pico's symmetric MAC key.
 *
 * @param shared The Shared object to get the details from
 * @return A buffer containing the Pico's symmetric MAC key. This buffer
 *         is part of the Shared object, so should not be deleted (it will be
 *         automatically deleted when the Shared object is)
 */
Buffer * shared_get_prover_mac_key(Shared const * shared) {
	return shared->pMacKey;
}

/**
 * Returns a buffer to the Service's symmetric MAC key.
 *
 * @param shared The Shared object to get the details from
 * @return A buffer containing the Service's symmetric MAC key. This 
 *         buffer is part of the Shared object, so should not be deleted (it 
 *         will be automatically deleted when the Shared object is)
 */
Buffer * shared_get_verifier_mac_key(Shared const * shared) {
	return shared->vMacKey;
}

/**
 * Returns a buffer to the shared key.
 *
 * @param shared The Shared object to get the details from
 * @return A buffer containing the shared symmetric key. This 
 *         buffer is part of the Shared object, so should not be deleted (it 
 *         will be automatically deleted when the Shared object is)
 */
Buffer * shared_get_shared_key(Shared const * shared) {
	return shared->sharedKey;
}

/**
 * Set the callback that will be triggered to provide feedback as the process
 * progresses.
 *
 * @param shared The Shared object to set the feedback trigger for.
 * @parm trigger The callback to trigger as the process progresses.
 * @param data The opaque data structure that will be returned when the
 *        callback is triggered, and which can be used to store context.
 * @return The feedback object that stored the current stage of the process.
 */
Feedback const * shared_set_feedback_trigger(Shared const * shared, FeedbackTrigger trigger, void * data) {
	feedback_set_trigger(shared->feedback, trigger, data);

	return shared->feedback;
}

/**
 * Move progress to the next stage and trigger the feedback callback. See
 * feedback_next_stage().
 *
 * This is for internal use.
 *
 * @param shared The Shared object to trigger the feedback from.
 * @parm description A textual description of the stage to move to.
 * @return true if the process should continue. False if the calling
 *         program has signalled to stop through the callback return value.
 */
bool shared_next_stage(Shared const * shared, char const * const description) {
	return feedback_next_stage(shared->feedback, description);
}

/**
 * Reset the feedback progress. See feedback_reset().
 *
 * This is for internal use.
 *
 * @param shared The Shared object to trigger the feedback from.
 * @parm stages The maximum number of stages that progress can pass through.
 */
void shared_feedback_reset(Shared const * shared, int stages) {
	feedback_reset(shared->feedback, stages);
}

/**
 * Return the feedback object for the current shared object.
 *
 * The returned object is managed by the shared object, so should not be freed
 * seperately.
 *
 * This is for internal use.
 *
 * @param shared The Shared object to get the feedback from.
 * @parm stages The currently set feedback object.
 */
Feedback * shared_get_feedback(Shared const * shared) {
	return shared->feedback;
}

/**
 * Return the status code sent back by the service after a successful protocol
 * completion.
 *
 * @param shared The Shared object to get the status from.
 * @return The status value sent by the service in the status message.
 */
char shared_get_status(Shared const * shared) {
	return shared->status;
}

/**
 * Set the status code from the status message sent back by the service.
 *
 * This is for internal use.
 *
 * @param shared The Shared object to get the status from.
 * @param status The status value sent by the service in the status message.
 */
void shared_set_status(Shared * shared, char status) {
	shared->status = status;
}

/** @} addtogroup Protocol */

