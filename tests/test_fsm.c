/**
 * @file
 * @author cd611@cam.ac.uk 
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
 * @brief Unit tests for the state machines
 * @section DESCRIPTION
 *
 * Performs unit tests to the state machines FsmPico and FsmService.
 *
 */

#include <check.h>
#include <stdint.h>
#include <pico/fsmservice.h>
#include <pico/fsmpico.h>
#include <pico/cryptosupport.h>
#include <pico/sigmaverifier.h>
#include <pico/sigmaprover.h>
#include <pico/continuous.h>
#include <pthread.h>
#include <unistd.h>
#include <semaphore.h>
#include <fcntl.h>

// Defines

#define GLOABL_DATA_LEN (1024)

// Structure definitions

typedef enum {
	READ,
	CONNECTED,
	DISCONNECTED,
	TIMEOUT,
	STOP,

	// Speciall type of event stop event_loop_thread
	STOP_LOOP
} EVENT_TYPE;

typedef struct {
	EVENT_TYPE type;
	FsmService* service;
	FsmPico* pico;
	int time;

	char data[1024];
	int data_len;
} Event;

typedef struct node_st {
	struct node_st* next;
	Event event;
} Node;

typedef struct queue_st {
	Node* head;
} Queue;

typedef struct _LocalDataFsmFsm {
	int cycles;
	FsmService* serv;
	FsmPico* pico;
	bool calledAuthenticated;
	Queue queue;
	Buffer * symmetricKey;
} LocalDataFsmFsm;

typedef struct _LocalDataFsmPico {
	int cycles;
	FsmPico* pico;
	Queue queue;
	sem_t * read_semaphore;
	sem_t * connect_semaphore;
	char global_data[GLOABL_DATA_LEN];
	int global_data_len;
	pthread_mutex_t global_data_mutex;
} LocalDataFsmPico;

typedef struct _LocalDataFsmService {
	int cycles;
	FsmService* serv;
	bool calledAuthenticated;
	Queue queue;
	Buffer * symmetricKey;
	sem_t * read_semaphore;
	sem_t * authenticated_semaphore;
	sem_t * stop_semaphore;
	char global_data[GLOABL_DATA_LEN];
	int global_data_len;
	pthread_mutex_t global_data_mutex;
} LocalDataFsmService;


// Global variables

static int currentTime = 0;
pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;

static int const expectedTimeouts[] = {
	10000, //Reconnect delay
	9000, // Continuous timeout
	9000, // Continuous timeout
	9000, // Continuous timeout
	9000 // Continuous timeout
};

// Function prototypes

// Function definitions
void push_event(Queue* queue, Event event) {
	bool isService = event.service != NULL;
	bool isPico = event.pico != NULL;

	ck_assert(isService != isPico);
	
	pthread_mutex_lock(&queue_mutex);
	Node* queue_head = queue->head;

	if (queue_head == NULL) {
		Node* newNode = malloc(sizeof(Node));
		newNode->next = NULL;
		newNode->event = event;
		queue->head = newNode;
	}
	else {
		if (event.time < queue_head->event.time) {
			Node* newNode = malloc(sizeof(Node));
			newNode->next = queue_head;
			newNode->event = event;
			queue->head = newNode;
		}
		else {
			Node* previousNode = queue_head;
			Node* currentNode = queue_head->next;
			while (currentNode != NULL && event.time >= currentNode->event.time) {
				previousNode = currentNode;
				currentNode = currentNode->next;
			}
			Node* newNode = malloc(sizeof(Node));
			newNode->next = currentNode;
			newNode->event = event;
			previousNode->next = newNode; 
			queue->head = queue_head;
		}
	}

	pthread_mutex_unlock(&queue_mutex);
}
	   
void push_read(Queue* queue, FsmPico* pico, FsmService* service, int currentTime, const char* data, int length) {
	Event event;

	event.type = READ;
	event.service = service;
	event.pico = pico;
	event.time = currentTime;
	memcpy(event.data, data, length);
	event.data_len = length;
	push_event(queue, event);
}

void push_connected(Queue* queue, FsmPico* pico, FsmService* service, int currentTime) {
	Event event;

	event.type = CONNECTED;
	event.service = service;
	event.pico = pico;
	event.time = currentTime;
	push_event(queue, event);
}

void push_disconnected(Queue* queue, FsmPico* pico, FsmService* service, int currentTime){
	Event event;

	event.type = DISCONNECTED;
	event.service = service;
	event.pico = pico;
	event.time = currentTime;
	push_event(queue, event);
}
	
void push_timeout(Queue* queue, FsmPico* pico, FsmService* service, int currentTime, int timeout) {
	Event event;

	// Look for some previous timeout comming from the same service/pico
	pthread_mutex_lock(&queue_mutex);
	Node* ptr = queue->head;
	Node* prev = NULL;
	while (ptr != NULL && (ptr->event.type != TIMEOUT || ptr->event.service != service || ptr->event.pico != pico)) {
		prev = ptr;
		ptr = ptr->next;
	}
	if (ptr != NULL) {
		// Found some timeout. So remove it
		if (prev == NULL) {
			ck_assert(ptr == queue->head);
			queue->head = ptr->next;
		}
		else {
			prev->next = ptr->next;
		}
		free(ptr);
	}
	pthread_mutex_unlock(&queue_mutex);

	// Add the new timeout
	event.type = TIMEOUT;
	event.service = service;
	event.pico = pico;
	event.time = currentTime + timeout;
	push_event(queue, event);
}

void push_stop(Queue* queue, FsmPico* pico, FsmService* service, int currentTime){
	Event event;

	event.type = STOP;
	event.service = service;
	event.pico = pico;
	event.time = currentTime;

	return push_event(queue, event);
}

void process_event(Event event) {
	bool isService;
	bool isPico;

	isService = (event.service != NULL);
	isPico = (event.pico != NULL);

	ck_assert(isService != isPico);

	switch (event.type) {
	case READ:
		if (isService) {
			fsmservice_read(event.service, event.data, event.data_len);
		} else {
			fsmpico_read(event.pico, event.data, event.data_len);
		}
		break;

	case CONNECTED:
		if (isService) {
			fsmservice_connected(event.service);
		} else {
			fsmpico_connected(event.pico);
		}
		break;

	case DISCONNECTED:
		if (isService) {
			fsmservice_disconnected(event.service);
		} else {
			fsmpico_disconnected(event.pico);
		}
		break;

	case TIMEOUT:
		if (isService) {
			fsmservice_timeout(event.service);
		} else {
			fsmpico_timeout(event.pico);
		}
		break;
	case STOP:
		if (isService) {
			fsmservice_stop(event.service);
		} else {
			fsmpico_stop(event.pico);
		}
		break;
	case STOP_LOOP:
		ck_assert(false);
		break;
	}
}

/*
 * The following static functions are the callbacks used by the Service and
 * Pico finite state machines.
 *
 * These are for the FSM-FSM interaction.
*/

static void serviceWriteFsmFsm(char const * data, size_t length, void * user_data){
	LocalDataFsmFsm * local = (LocalDataFsmFsm *)user_data;

	push_read(&local->queue, local->pico, NULL, currentTime, data, length);
}

static void serviceSetTimeoutFsmFsm(int timeout, void * user_data) {
	LocalDataFsmFsm * local = (LocalDataFsmFsm *)user_data;

	push_timeout(&local->queue, NULL, local->serv, currentTime, timeout);
}

static void serviceErrorFsmFsm(void * user_data) {
	ck_abort_msg("Service reached error state");
}

static void serviceDisconnectFsmFsm(void * user_data){
	LocalDataFsmFsm * local = (LocalDataFsmFsm *)user_data;

	push_disconnected(&local->queue, local->pico, NULL, currentTime);
}

static void picoWriteFsmFsm(char const * data, size_t length, void * user_data) {
	LocalDataFsmFsm * local = (LocalDataFsmFsm *)user_data;

	push_read(&local->queue, NULL, local->serv, currentTime, data, length);
}

static void picoSetTimeoutFsmFsm(int timeout, void * user_data) {
	LocalDataFsmFsm * local = (LocalDataFsmFsm *)user_data;

	push_timeout(&local->queue, local->pico, NULL, currentTime, timeout);
}

static void picoErrorFsmFsm(void * user_data) {
	ck_abort_msg("Pico reached error state");
}

static void picoReconnectFsmFsm(void * user_data) {
	LocalDataFsmFsm * local = (LocalDataFsmFsm *)user_data;

	push_connected(&local->queue, local->pico, NULL, currentTime);
	push_connected(&local->queue, NULL, local->serv, currentTime);
}

static void picoDisconnectFsmFsm(void * user_data) {
	LocalDataFsmFsm * local = (LocalDataFsmFsm *)user_data;

	push_disconnected(&local->queue, NULL, local->serv, currentTime);
}

static void picoStatusUpdateFsmFsm(FSMPICOSTATE state, void * user_data) {
	LocalDataFsmFsm * local = (LocalDataFsmFsm *)user_data;

	if (state == FSMPICOSTATE_PICOREAUTH) {
		local->cycles++;
		if (local->cycles > 3) {
			push_stop(&local->queue, local->pico, NULL, currentTime);
		}
	}
}

static void serviceAuthenticatedFsmFsm(int status, void * user_data) {
	LocalDataFsmFsm * local = (LocalDataFsmFsm *)user_data;

	local->calledAuthenticated = true;
	ck_assert(status == 1);
	Buffer const * user = fsmservice_get_user(local->serv);
	Buffer const * extraData = fsmservice_get_received_extra_data(local->serv);
	Buffer const * receivedSymKey = fsmservice_get_symmetric_key(local->serv);

	ck_assert(buffer_equals(receivedSymKey, local->symmetricKey));
	ck_assert(!strcmp(buffer_get_buffer(user), "Donald"));
	ck_assert(!strcmp(buffer_get_buffer(extraData), "p@ssword"));
}

START_TEST (fsm_fsm_test) {
	LocalDataFsmFsm local;
	Shared * picoShared;
	Buffer * picoExtraData;
	Shared * servShared;
	Buffer * servExtraData;
	EC_KEY * servIdPKey;
	EC_KEY * picoIdPKey;
	EVP_PKEY * picoIdSKey;
	Buffer * picoIdDer;

	currentTime = 0;

	local.cycles = 0;
	local.serv = fsmservice_new();
	local.pico = fsmpico_new();
	local.calledAuthenticated = false;
	local.queue.head = NULL;
	local.symmetricKey = buffer_new(0);

	picoShared = shared_new();
	shared_load_or_generate_pico_keys(picoShared, "testpicokey.pub", "testpicokey.priv");
	picoExtraData = buffer_new(0);
	buffer_append_string(picoExtraData, "p@ssword");

	servShared = shared_new();
	shared_load_or_generate_keys(servShared, "testkey.pub", "testkey.priv");
	servExtraData = buffer_new(0);

	servIdPKey = shared_get_service_identity_public_key(servShared);
	picoIdPKey = shared_get_pico_identity_public_key(picoShared);
	picoIdSKey = keypair_getprivatekey(shared_get_pico_identity_key(picoShared));
	picoIdDer = buffer_new(0);

	cryptosupport_generate_symmetric_key(local.symmetricKey, CRYPTOSUPPORT_AESKEY_SIZE);
	Users * users = users_new();
	users_add_user(users, "Donald", picoIdPKey, local.symmetricKey);

	fsmservice_set_functions(local.serv, serviceWriteFsmFsm, serviceSetTimeoutFsmFsm, serviceErrorFsmFsm, NULL, serviceDisconnectFsmFsm, serviceAuthenticatedFsmFsm, NULL, NULL);
	fsmservice_set_userdata(local.serv, & local);
	fsmservice_set_continuous(local.serv, true);
	fsmpico_set_functions(local.pico, picoWriteFsmFsm, picoSetTimeoutFsmFsm, picoErrorFsmFsm, picoReconnectFsmFsm, picoDisconnectFsmFsm, NULL, NULL, picoStatusUpdateFsmFsm);
	fsmpico_set_userdata(local.pico, & local);

	// We have to duplicate the objects because fsmpico tries to delete them later
	cryptosupport_getprivateder(picoIdSKey, picoIdDer);
	fsmpico_start(local.pico, picoExtraData, EC_KEY_dup(servIdPKey), EC_KEY_dup(picoIdPKey), cryptosupport_read_buffer_private_key(picoIdDer));
	fsmservice_start(local.serv, servShared, users, servExtraData);

	// To kick start we have to "connect" both sides
	push_connected(&local.queue, NULL, local.serv, currentTime);
	push_connected(&local.queue, local.pico, NULL, currentTime);

	while (local.queue.head != NULL) {
		Node* head = local.queue.head;
		local.queue.head = head->next;
		currentTime = head->event.time;
		process_event(head->event);
		free(head);
	}

	ck_assert(local.cycles == 4);
	ck_assert(local.calledAuthenticated);

	fsmservice_delete(local.serv);
	fsmpico_delete(local.pico);
	shared_delete(servShared);
	shared_delete(picoShared);
	buffer_delete(picoExtraData);
	buffer_delete(servExtraData);
	buffer_delete(picoIdDer);
	users_delete(users);
	buffer_delete(local.symmetricKey);
}
END_TEST

void * event_loop_thread(void * arg) {
	Queue* queuePtr = (Queue*) arg;
   
	while (true) {
		pthread_mutex_lock(&queue_mutex);
		Node* head = queuePtr->head;
		if (head != NULL) {
			while (head->event.type == TIMEOUT && head->event.time > currentTime) {
				// Wait a little bit so the other thread can synchronize
				currentTime += 25;
				pthread_mutex_unlock(&queue_mutex);
				usleep(1);
				pthread_mutex_lock(&queue_mutex);
				head = queuePtr->head;
			}
			queuePtr->head = head->next;
			currentTime = head->event.time;
			pthread_mutex_unlock(&queue_mutex);
			if (head->event.type == STOP_LOOP) {
				free(head);
				break;
			}
			process_event(head->event);
			free(head);
		}
		else {
		   pthread_mutex_unlock(&queue_mutex);
		   usleep(10);
		}
	}

	return NULL;
}

/*
 * The following static functions are the callbacks used by the Service and
 * Pico finite state machines.
 *
 * These are for the FSM-Pico interaction.
*/

static bool channelOpenFsmPico(RVPChannel * channel) {
	void * user_data = channel_get_data(channel);
	LocalDataFsmPico * local = (LocalDataFsmPico *)user_data;

	sem_wait(local->connect_semaphore);
	push_connected(&local->queue, local->pico, NULL, currentTime);

	return true;
}

static bool channelCloseFsmPico(RVPChannel * channel) {
	void * user_data = channel_get_data(channel);
	LocalDataFsmPico * local = (LocalDataFsmPico *)user_data;

	push_disconnected(&local->queue, local->pico, NULL, currentTime);

	return true;
}

static bool channelWriteFsmPico(RVPChannel * channel, char * data, int length) {
	void * user_data = channel_get_data(channel);
	LocalDataFsmPico * local = (LocalDataFsmPico *)user_data;

	uint32_t receivedLength = 0;
	receivedLength |= ((unsigned char*) data)[0] << 24;
	receivedLength |= ((unsigned char*) data)[1] << 16;
	receivedLength |= ((unsigned char*) data)[2] << 8;
	receivedLength |= ((unsigned char*) data)[3] << 0;
	ck_assert_int_eq(length - 4 , receivedLength);
	push_read(&local->queue, local->pico, NULL, currentTime, data + 4, length - 4);

	return true;
}

static bool channelReadFsmPico(RVPChannel * channel, Buffer * buffer) {
	void * user_data = channel_get_data(channel);
	LocalDataFsmPico * local = (LocalDataFsmPico *)user_data;

	bool result;

	sem_wait(local->read_semaphore);
	result = true;
	pthread_mutex_lock(&local->global_data_mutex);
	if (local->global_data_len == -1) {
		result = false;
	}
	else {
		buffer_clear(buffer);
		buffer_append(buffer, local->global_data, local->global_data_len);
	}
	pthread_mutex_unlock(&local->global_data_mutex);

	return result;
}

static void picoWriteFsmPico(char const * data, size_t length, void * user_data) {
	LocalDataFsmPico * local = (LocalDataFsmPico *)user_data;

	ck_assert_int_lt(length, GLOABL_DATA_LEN);

	pthread_mutex_lock(&local->global_data_mutex);
	memcpy(local->global_data, data, length);
	local->global_data_len = length;
	pthread_mutex_unlock(&local->global_data_mutex);
	sem_post(local->read_semaphore);
}

static void picoSetTimeoutFsmPico(int timeout, void * user_data) {
	LocalDataFsmPico * local = (LocalDataFsmPico *)user_data;

	static int i = 0;
	ck_assert_int_eq(expectedTimeouts[i], timeout);
	i++;
	push_timeout(&local->queue, local->pico, NULL, currentTime, timeout);
}

static void picoErrorFsmPico(void * user_data) {
	ck_abort_msg("Pico reached error state");
}

static void picoReconnectFsmPico(void * user_data) {
	LocalDataFsmPico * local = (LocalDataFsmPico *)user_data;

	sem_post(local->connect_semaphore);
}

static void picoDisconnectFsmPico(void * user_data) {
	// Do nothing
}

static void picoStatusUpdateFsmPico(FSMPICOSTATE state, void * user_data) {
	LocalDataFsmPico * local = (LocalDataFsmPico *)user_data;

	if (state == FSMPICOSTATE_PICOREAUTH) {
		local->cycles++;
		if (local->cycles > 3) {
			push_stop(&local->queue, local->pico, NULL, currentTime);

			pthread_mutex_lock(&local->global_data_mutex);
			local->global_data_len = -1;
			pthread_mutex_unlock(&local->global_data_mutex);
			sem_post(local->read_semaphore);
		}
	}
}

START_TEST (fsm_pico_test) {
	LocalDataFsmPico local;
	RVPChannel * channel;
	Continuous * continuous;
	Buffer * symmetricKey;
	Buffer * returnedExtraData;
	Buffer * returnedSymmetricKey;
	Buffer * returnedUsername;
	bool result;
	Event event;
	Shared * picoShared;
	Buffer * picoExtraData;
	Shared * servShared;
	EC_KEY * servIdPKey;
	EC_KEY * picoIdPKey;
	EVP_PKEY * picoIdSKey;
	Buffer * picoIdDer;

	currentTime = 0;

	local.cycles = 0;
	local.pico = fsmpico_new();
	local.queue.head = NULL;
	local.global_data[0] = 0;
	local.global_data_len = 0;
	pthread_mutex_init(& local.global_data_mutex, NULL);

	local.read_semaphore = sem_open("picofsmpicoread", O_CREAT, 0644, 0);
	ck_assert(local.read_semaphore != SEM_FAILED);
	local.connect_semaphore = sem_open("picofsmpicoconnect", O_CREAT, 0644, 0);
	ck_assert(local.connect_semaphore != SEM_FAILED);

	picoShared = shared_new();
	shared_load_or_generate_pico_keys(picoShared, "testpicokey.pub", "testpicokey.priv");
	picoExtraData = buffer_new(0);
	buffer_append_string(picoExtraData, "p@ssword");

	servShared = shared_new();
	shared_load_or_generate_keys(servShared, "testkey.pub", "testkey.priv");

	servIdPKey = shared_get_service_identity_public_key(servShared);
	picoIdPKey = shared_get_pico_identity_public_key(picoShared);
	picoIdSKey = keypair_getprivatekey(shared_get_pico_identity_key(picoShared));
	picoIdDer = buffer_new(0);

	symmetricKey = buffer_new(0);
	cryptosupport_generate_symmetric_key(symmetricKey, CRYPTOSUPPORT_AESKEY_SIZE);
	Users * users = users_new();
	users_add_user(users, "Synchronous", picoIdPKey, symmetricKey);

	fsmpico_set_functions(local.pico, picoWriteFsmPico, picoSetTimeoutFsmPico, picoErrorFsmPico, picoReconnectFsmPico, picoDisconnectFsmPico, NULL, NULL, picoStatusUpdateFsmPico);
	fsmpico_set_userdata(local.pico, & local);

	// We have to duplicate the objects because fsmpico tries to delete them later
	cryptosupport_getprivateder(picoIdSKey, picoIdDer);
	fsmpico_start(local.pico, picoExtraData, EC_KEY_dup(servIdPKey), EC_KEY_dup(picoIdPKey), cryptosupport_read_buffer_private_key(picoIdDer));
	sem_post(local.connect_semaphore);

	pthread_t prover_td;
	pthread_create(&prover_td, NULL, event_loop_thread, &local.queue);
	
	channel = channel_new();
	channel_set_data(channel, & local);
	channel_set_functions(channel, NULL, channelOpenFsmPico, channelCloseFsmPico, channelWriteFsmPico, channelReadFsmPico, NULL, NULL, NULL);
	returnedExtraData = buffer_new(0);
	returnedSymmetricKey = buffer_new(0);
	returnedUsername = buffer_new(0);
	result = sigmaverifier_session(servShared, channel, users, NULL, returnedExtraData, returnedSymmetricKey, true, 0);
	ck_assert(result);
	   
	EC_KEY *pico_key = shared_get_pico_identity_public_key(servShared);
	buffer_append_buffer(returnedUsername, users_search_by_key(users, pico_key));
	buffer_append(returnedUsername, "", 1);
	ck_assert(buffer_equals(returnedSymmetricKey, symmetricKey));
	ck_assert(!strcmp(buffer_get_buffer(returnedUsername), "Synchronous"));
	ck_assert(!strcmp(buffer_get_buffer(returnedExtraData), "p@ssword"));
	
	continuous = continuous_new();
	continuous_set_channel(continuous, channel);
	continuous_set_shared_key(continuous, shared_get_shared_key(servShared));
	
	result = continuous_cycle_start(continuous);
	ck_assert(result);

	result = continuous_continue(continuous, NULL);
	ck_assert(result);
	
	result = continuous_continue(continuous, NULL);
	ck_assert(result);
  
	result = continuous_continue(continuous, NULL);
	ck_assert(result);
 
	result = continuous_continue(continuous, NULL);
	ck_assert(!result);
	
	ck_assert(local.cycles == 4);

	event.type = STOP_LOOP;
	event.service = NULL;
	event.pico = local.pico;
	event.time = currentTime;
	push_event(&local.queue, event);
	pthread_join(prover_td, NULL);

	buffer_delete(returnedExtraData);
	buffer_delete(returnedSymmetricKey);
	buffer_delete(returnedUsername);
	channel_delete(channel);

	fsmpico_delete(local.pico);
	shared_delete(servShared);
	shared_delete(picoShared);
	buffer_delete(picoExtraData);
	buffer_delete(picoIdDer);
	users_delete(users);
	buffer_delete(symmetricKey);

	sem_close(local.read_semaphore);
	sem_unlink("picofsmpicoread");
	sem_close(local.connect_semaphore);
	sem_unlink("picofsmpicoconnect");
}
END_TEST

/*
 * The following static functions are the callbacks used by the Service and
 * Pico finite state machines.
 *
 * These are for the FSM-Pico interaction.
*/

static bool channelOpenFsmService(RVPChannel * channel) {
	void * user_data = channel_get_data(channel);
	LocalDataFsmService * local = (LocalDataFsmService *)user_data;

	push_connected(&local->queue, NULL, local->serv, currentTime);

	return true;
}

static bool channelCloseFsmService(RVPChannel * channel) {
	void * user_data = channel_get_data(channel);
	LocalDataFsmService * local = (LocalDataFsmService *)user_data;

	push_disconnected(&local->queue, NULL, local->serv, currentTime);

	return true;
}

static bool channelWriteFsmService(RVPChannel * channel, char * data, int length) {
	void * user_data = channel_get_data(channel);
	LocalDataFsmService * local = (LocalDataFsmService *)user_data;

	uint32_t receivedLength = 0;
	receivedLength |= ((unsigned char*) data)[0] << 24;
	receivedLength |= ((unsigned char*) data)[1] << 16;
	receivedLength |= ((unsigned char*) data)[2] << 8;
	receivedLength |= ((unsigned char*) data)[3] << 0;
	ck_assert_int_eq(length - 4 , receivedLength);
	push_read(&local->queue, NULL, local->serv, currentTime, data + 4, length - 4);

	return true;
}

static bool channelReadFsmService(RVPChannel * channel, Buffer * buffer) {
	void * user_data = channel_get_data(channel);
	LocalDataFsmService * local = (LocalDataFsmService *)user_data;
	bool result;

	sem_wait(local->read_semaphore);
	result = true;
	pthread_mutex_lock(&local->global_data_mutex);
	if (local->global_data_len == -1) {
		result = false;
	} 
	else {
		buffer_clear(buffer);
		buffer_append(buffer, local->global_data, local->global_data_len);
	}
	pthread_mutex_unlock(&local->global_data_mutex);

	return result;
}

static void serviceWriteFsmService(char const * data, size_t length, void * user_data) {
	LocalDataFsmService * local = (LocalDataFsmService *)user_data;

	ck_assert_int_lt(length, GLOABL_DATA_LEN);

	pthread_mutex_lock(&local->global_data_mutex);
	memcpy(local->global_data, data, length);
	local->global_data_len = length;
	pthread_mutex_unlock(&local->global_data_mutex);
	sem_post(local->read_semaphore);
}

static void serviceSetTimeoutFsmService(int timeout, void * user_data) {
	LocalDataFsmService * local = (LocalDataFsmService *)user_data;

	push_timeout(&local->queue, NULL, local->serv, currentTime, timeout);
}

static void serviceErrorFsmService(void * user_data) {
	ck_abort_msg("Service reached error state");
}

static void serviceDisconnectFsmService(void * user_data){
	LocalDataFsmService * local = (LocalDataFsmService *)user_data;

	push_disconnected(&local->queue, NULL, local->serv, currentTime);
}

static void serviceAuthenticatedFsmService(int status, void * user_data) {
	LocalDataFsmService * local = (LocalDataFsmService *)user_data;
	Buffer const * user;
	Buffer const * extraData;
	Buffer const * receivedSymKey;

	local->calledAuthenticated = true;
	ck_assert(status == 1);
	user = fsmservice_get_user(local->serv);
	extraData = fsmservice_get_received_extra_data(local->serv);
	receivedSymKey = fsmservice_get_symmetric_key(local->serv);

	ck_assert(buffer_equals(receivedSymKey, local->symmetricKey));
	ck_assert(!strcmp(buffer_get_buffer(user), "Synchronous"));
	ck_assert(!strcmp(buffer_get_buffer(extraData), "p@ssword"));
	sem_post(local->authenticated_semaphore);
}

static void serviceStatusUpdateFsmService(int state, void * user_data) {
	LocalDataFsmService * local = (LocalDataFsmService *)user_data;

	if (state == FSMSERVICESTATE_PICOREAUTH) {
		local->cycles++;
		if (local->cycles > 3) {
			push_stop(&local->queue, NULL, local->serv, currentTime);
			sem_post(local->stop_semaphore);
		}
	}
}

START_TEST (fsm_service_test) {
	LocalDataFsmService local;
	RVPChannel * channel;
	Continuous * continuous;
	Event event;
	Shared * picoShared;
	Buffer * picoExtraData;
	Shared * servShared;
	Buffer * servExtraData;
	EC_KEY * picoIdPKey;
	Users * users;

	currentTime = 0;

	local.cycles = 0;
	local.calledAuthenticated = false;
	local.serv = fsmservice_new();
	local.queue.head = NULL;
	local.global_data[0] = 0;
	local.global_data_len = 0;
	pthread_mutex_init(& local.global_data_mutex, NULL);

	local.read_semaphore = sem_open("picofsmserviceread", O_CREAT, 0644, 0);
	ck_assert(local.read_semaphore != SEM_FAILED);
	local.authenticated_semaphore = sem_open("picofsmserviceauthenticated", O_CREAT, 0644, 0);
	ck_assert(local.authenticated_semaphore != SEM_FAILED);
	local.stop_semaphore = sem_open("picofsmservicestop", O_CREAT, 0644, 0);
	ck_assert(local.stop_semaphore != SEM_FAILED);

	picoShared = shared_new();
	shared_load_or_generate_pico_keys(picoShared, "testpicokey.pub", "testpicokey.priv");
	picoExtraData = buffer_new(0);
	buffer_append_string(picoExtraData, "p@ssword");
	
	servShared = shared_new();
	shared_load_or_generate_keys(servShared, "testkey.pub", "testkey.priv");
	servExtraData = buffer_new(0);
	buffer_append_string(servExtraData, "SERVICE EXTRA");
	
	picoIdPKey = shared_get_pico_identity_public_key(picoShared);

	local.symmetricKey = buffer_new(0);
	cryptosupport_generate_symmetric_key(local.symmetricKey, CRYPTOSUPPORT_AESKEY_SIZE);
	users = users_new();
	users_add_user(users, "Synchronous", picoIdPKey, local.symmetricKey);

	fsmservice_set_functions(local.serv, serviceWriteFsmService, serviceSetTimeoutFsmService, serviceErrorFsmService, NULL, serviceDisconnectFsmService, serviceAuthenticatedFsmService, NULL, serviceStatusUpdateFsmService);
	fsmservice_set_userdata(local.serv, & local);
	fsmservice_set_continuous(local.serv, true);

	fsmservice_start(local.serv, servShared, users, servExtraData);

	pthread_t prover_td;
	pthread_create(&prover_td, NULL, event_loop_thread, &local.queue);
	
	channel = channel_new();
	channel_set_data(channel, & local);
	channel_set_functions(channel, NULL, channelOpenFsmService, channelCloseFsmService, channelWriteFsmService, channelReadFsmService, NULL, NULL, NULL);
	Buffer * returnedExtraData = buffer_new(0);
	channel_open(channel);
	bool result = sigmaprover(picoShared, channel, picoExtraData, returnedExtraData);
	ck_assert(result);
	
	sem_wait(local.authenticated_semaphore);
	ck_assert(local.calledAuthenticated);
	ck_assert(!strcmp(buffer_get_buffer(returnedExtraData), "SERVICE EXTRA"));

	continuous = continuous_new();
	continuous_set_channel(continuous, channel);
	continuous_set_shared_key(continuous, shared_get_shared_key(servShared));
   
	result = continuous_cycle_start_pico(continuous, NULL);
	ck_assert(result);

	int timeout = 0;
	result = continuous_reauth_pico(continuous, NULL, &timeout);
	ck_assert(result);

	result = continuous_reauth_pico(continuous, NULL, &timeout);
	ck_assert(result);
  
	result = continuous_reauth_pico(continuous, NULL, &timeout);
	ck_assert(result);

	// Wait for the other thread to complete the cycles before stopping the loop
	sem_wait(local.stop_semaphore);

	event.type = STOP_LOOP;
	event.service = local.serv;
	event.pico = NULL;
	event.time = currentTime;
	push_event(&local.queue, event);
	pthread_join(prover_td, NULL);

	ck_assert_int_eq(local.cycles, 4);
	
	buffer_delete(returnedExtraData);
	channel_delete(channel);

	fsmservice_delete(local.serv);
	shared_delete(servShared);
	shared_delete(picoShared);
	buffer_delete(picoExtraData);
	users_delete(users);
	buffer_delete(local.symmetricKey);

	sem_close(local.read_semaphore);
	sem_unlink("picofsmserviceread");
	sem_close(local.authenticated_semaphore);
	sem_unlink("picofsmserviceauthenticated");
	sem_close(local.stop_semaphore);
	sem_unlink("picofsmservicestop");
}
END_TEST

int main (void) {
	int number_failed;
	Suite * s;
	SRunner *sr;
	TCase * tc;

	s = suite_create("Libpico");

	tc = tcase_create("FSM");
	tcase_add_test(tc, fsm_fsm_test);
	tcase_add_test(tc, fsm_pico_test);
	tcase_add_test(tc, fsm_service_test);
	suite_add_tcase(s, tc);
	sr = srunner_create(s);

	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);

	return (number_failed == 0) ? 0 : -1;
}

