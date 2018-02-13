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
#include <pico/fsmservice.h>
#include <pico/fsmpico.h>
#include <pico/cryptosupport.h>
#include <pico/sigmaverifier.h>
#include <pico/sigmaprover.h>
#include <pico/continuous.h>
#include <pthread.h>
#include <unistd.h>
#include <semaphore.h>

// Defines
typedef enum {
	READ,
	CONNECTED,
	DISCONNECTED,
	TIMEOUT,
	STOP,

	// Speciall type of event stop event_loop_thread
	STOP_LOOP
} EVENT_TYPE;

// Structure definitions
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

// Function prototypes

// Global variables
static int currentTime = 0;
pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;


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
	} else {
		if (event.time < queue_head->event.time) {
			Node* newNode = malloc(sizeof(Node));
			newNode->next = queue_head;
			newNode->event = event;
			queue->head = newNode;
		} else {
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
	Event e;
	e.type = READ;
	e.service = service;
	e.pico = pico;
	e.time = currentTime;
	memcpy(e.data, data, length);
	e.data_len = length;
	push_event(queue, e);
}

void push_connected(Queue* queue, FsmPico* pico, FsmService* service, int currentTime) {
	Event e;
	e.type = CONNECTED;
	e.service = service;
	e.pico = pico;
	e.time = currentTime;
	push_event(queue, e);
}

void push_disconnected(Queue* queue, FsmPico* pico, FsmService* service, int currentTime){
	Event e;
	e.type = DISCONNECTED;
	e.service = service;
	e.pico = pico;
	e.time = currentTime;
	push_event(queue, e);
}
	
void push_timeout(Queue* queue, FsmPico* pico, FsmService* service, int currentTime, int timeout) {
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
		} else {
			prev->next = ptr->next;
		}
		free(ptr);
	}
	pthread_mutex_unlock(&queue_mutex);

	// Add the new timeout
	Event e;
	e.type = TIMEOUT;
	e.service = service;
	e.pico = pico;
	e.time = currentTime + timeout;
	push_event(queue, e);
}

void push_stop(Queue* queue, FsmPico* pico, FsmService* service, int currentTime){
	Event e;
	e.type = STOP;
	e.service = service;
	e.pico = pico;
	e.time = currentTime;
	return push_event(queue, e);
}

void process_event(Event event) {
	bool isService = event.service != NULL;
	bool isPico = event.pico != NULL;

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

START_TEST (fsm_fsm_test) {
	FsmService* serv = fsmservice_new();
	FsmPico* pico = fsmpico_new();
	Queue queue = {NULL};
	currentTime = 0;
	int cycles = 0;
	int cyclesService = 0;
	
	Shared * picoShared = shared_new();
	shared_load_or_generate_pico_keys(picoShared, "testpicokey.pub", "testpicokey.priv");
	Buffer * picoExtraData = buffer_new(0);
	buffer_append_string(picoExtraData, "p@ssword");
	
	Shared * servShared = shared_new();
	shared_load_or_generate_keys(servShared, "testkey.pub", "testkey.priv");
	Buffer * servExtraData = buffer_new(0);
	
	EC_KEY* servIdPKey = shared_get_service_identity_public_key(servShared);
	EC_KEY* picoIdPKey = shared_get_pico_identity_public_key(picoShared);
	EVP_PKEY* picoIdSKey = keypair_getprivatekey(shared_get_pico_identity_key(picoShared));
	Buffer * picoIdDer = buffer_new(0);

	Buffer * symmetricKey = buffer_new(0);
	cryptosupport_generate_symmetric_key(symmetricKey, CRYPTOSUPPORT_AESKEY_SIZE);
	Users * users = users_new();
	users_add_user(users, "Donald", picoIdPKey, symmetricKey);

	bool calledAuthenticated = false;

	void serviceWrite(char const * data, size_t length, void * user_data){
		push_read(&queue, pico, NULL, currentTime, data, length);
	}

	void serviceSetTimeout(int timeout, void * user_data) {
		push_timeout(&queue, NULL, serv, currentTime, timeout);
	}

	void serviceDisconnect(void * user_data){
		push_disconnected(&queue, pico, NULL, currentTime);
	}

	void picoWrite(char const * data, size_t length, void * user_data) {
		push_read(&queue, NULL, serv, currentTime, data, length);
	}

	void picoSetTimeout(int timeout, void * user_data) {
		push_timeout(&queue, pico, NULL, currentTime, timeout);
	}

	void picoReconnect(void * user_data) {
		push_connected(&queue, pico, NULL, currentTime);
		push_connected(&queue, NULL, serv, currentTime);
	}

	void picoDisconnect(void * user_data) {
		push_disconnected(&queue, NULL, serv, currentTime);
	}

	void picoStatusUpdate(FSMPICOSTATE state, void * user_data) {
		Buffer * extraData;
		extraData = buffer_new(0);
		// Using this variable, otherwise send_extra_data will call status_update
		// and we will have a stack overflow
		static bool sendingReply = false;

		if (state == FSMPICOSTATE_PICOREAUTH) {
			cycles++;
			if (cycles > 3) {
				push_stop(&queue, pico, NULL, currentTime);
			}
		}
		if (state == FSMPICOSTATE_SERVICEREAUTH && !sendingReply) {
			if (cycles == 2) {
				sendingReply = true;
				ck_assert_str_eq(buffer_get_buffer(fsmpico_get_received_extra_data(pico)), "EXTRA!!");
				buffer_append_string(extraData, "Extra reply");
				fsmpico_set_outbound_extra_data(pico, extraData);
				fsmpico_send_extra_data(pico);
				fsmpico_set_outbound_extra_data(pico, NULL);
			} else {
				ck_assert_str_eq(buffer_get_buffer(fsmpico_get_received_extra_data(pico)), "");
			}
		}
		
		buffer_delete(extraData);
	}

	void serviceStatusUpdate(FSMSERVICESTATE state, void * user_data) {
		Buffer * extraData;
		extraData = buffer_new(0);

		if (state == FSMSERVICESTATE_SERVICEREAUTH) {
			cyclesService++;
			if (cyclesService == 2) {
				buffer_append_string(extraData, "EXTRA!!");
				fsmservice_set_outbound_extra_data(serv, extraData);
				fsmservice_send_extra_data(serv);
				fsmservice_set_outbound_extra_data(serv, NULL);
			}
		}
		
		if (state == FSMSERVICESTATE_SERVICEREAUTH) {
			if (cyclesService == 4) {
				ck_assert_str_eq(buffer_get_buffer(fsmservice_get_received_extra_data(serv)), "Extra reply");
			} else {
				ck_assert_str_eq(buffer_get_buffer(fsmservice_get_received_extra_data(serv)), "");
			}
		}

		buffer_delete(extraData);
	}

	void serviceAuthenticated(int status, void * user_data) {
		calledAuthenticated = true;
		ck_assert(status == 1);
		Buffer const * user = fsmservice_get_user(serv);
		Buffer const * extraData = fsmservice_get_received_extra_data(serv);
		Buffer const * receivedSymKey = fsmservice_get_symmetric_key(serv);

		ck_assert(buffer_equals(receivedSymKey, symmetricKey));
		ck_assert(!strcmp(buffer_get_buffer(user), "Donald"));
		ck_assert(!strcmp(buffer_get_buffer(extraData), "p@ssword"));

		fsmpico_set_outbound_extra_data(pico, NULL);
	}

	fsmservice_set_functions(serv, serviceWrite, serviceSetTimeout, NULL, NULL, serviceDisconnect, serviceAuthenticated, NULL, serviceStatusUpdate);
	fsmservice_set_continuous(serv, true);
	fsmpico_set_functions(pico, picoWrite, picoSetTimeout, NULL, picoReconnect, picoDisconnect, NULL, NULL, picoStatusUpdate);

	// We have to duplicate the objects because fsmpico tries to delete them later
	cryptosupport_getprivateder(picoIdSKey, picoIdDer);
	fsmpico_start(pico, picoExtraData, EC_KEY_dup(servIdPKey), EC_KEY_dup(picoIdPKey), cryptosupport_read_buffer_private_key(picoIdDer));
	fsmservice_start(serv, servShared, users, servExtraData);

	// To kick start we have to "connect" both sides
	push_connected(&queue, NULL, serv, currentTime);
	push_connected(&queue, pico, NULL, currentTime);

	while (queue.head != NULL) {
		Node* head = queue.head;
		queue.head = head->next;
		currentTime = head->event.time;
		process_event(head->event);
		free(head);
	}

	ck_assert(cycles == 4);
	ck_assert(calledAuthenticated);

	fsmservice_delete(serv);
	fsmpico_delete(pico);
	shared_delete(servShared);
	shared_delete(picoShared);
	buffer_delete(picoExtraData);
	buffer_delete(servExtraData);
	buffer_delete(picoIdDer);
	users_delete(users);
	buffer_delete(symmetricKey);
}
END_TEST

void * event_loop_thread(void * arg) {
	Queue* queuePtr = (Queue*) arg;
   
	while(true) {
		pthread_mutex_lock(&queue_mutex);
		Node* head = queuePtr->head;
		if (head != NULL) {
			while (head->event.type == TIMEOUT && head->event.time > currentTime) {
				// Wait a little bit so the other thread can synchronize
				currentTime += 100;
				pthread_mutex_unlock(&queue_mutex);
				sleep(0.01);
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
		} else {
		   pthread_mutex_unlock(&queue_mutex);
		   sleep(0.1); 
		}
	}

	return NULL;
}

START_TEST (fsm_pico_test) {
	FsmPico* pico = fsmpico_new();
	Queue queue = {NULL};
	currentTime = 0;
	sem_t read_semaphore;
	sem_t connect_semaphore;
	
	char global_data[1024];
	int global_data_len = 0;
	pthread_mutex_t global_data_mutex = PTHREAD_MUTEX_INITIALIZER;
	
	sem_init(&read_semaphore, 0, 0);
	sem_init(&connect_semaphore, 0, 0);

	Shared * picoShared = shared_new();
	shared_load_or_generate_pico_keys(picoShared, "testpicokey.pub", "testpicokey.priv");
	Buffer * picoExtraData = buffer_new(0);
	buffer_append_string(picoExtraData, "p@ssword");
	
	Shared * servShared = shared_new();
	shared_load_or_generate_keys(servShared, "testkey.pub", "testkey.priv");
	
	EC_KEY* servIdPKey = shared_get_service_identity_public_key(servShared);
	EC_KEY* picoIdPKey = shared_get_pico_identity_public_key(picoShared);
	EVP_PKEY* picoIdSKey = keypair_getprivatekey(shared_get_pico_identity_key(picoShared));
	Buffer * picoIdDer = buffer_new(0);

	Buffer * symmetricKey = buffer_new(0);
	cryptosupport_generate_symmetric_key(symmetricKey, CRYPTOSUPPORT_AESKEY_SIZE);
	Users * users = users_new();
	users_add_user(users, "Synchronous", picoIdPKey, symmetricKey);

	int cycles = 0;

	bool channelOpen(RVPChannel * channel) {
		sem_wait(&connect_semaphore);
		push_connected(&queue, pico, NULL, currentTime);
		return true;
	}
	bool channelClose(RVPChannel * channel) {
		push_disconnected(&queue, pico, NULL, currentTime);
		return true;
	}
	bool channelWrite(RVPChannel * channel, char * data, int length) {
		uint32_t receivedLength = 0;
		receivedLength |= ((unsigned char*) data)[0] << 24;
		receivedLength |= ((unsigned char*) data)[1] << 16;
		receivedLength |= ((unsigned char*) data)[2] << 8;
		receivedLength |= ((unsigned char*) data)[3] << 0;
		ck_assert_int_eq(length - 4 , receivedLength);
		push_read(&queue, pico, NULL, currentTime, data + 4, length - 4);
		return true;
	}
	bool channelRead(RVPChannel * channel, Buffer * buffer) {
		sem_wait(&read_semaphore);
		bool ret = true;
		pthread_mutex_lock(&global_data_mutex);
		if (global_data_len == -1) {
			ret = false;
		} else {
			buffer_clear(buffer);
			buffer_append(buffer, global_data, global_data_len);
		}
		pthread_mutex_unlock(&global_data_mutex);
		return ret;
	}
	
	void picoWrite(char const * data, size_t length, void * user_data) {
		pthread_mutex_lock(&global_data_mutex);
		memcpy(global_data, data, length);
		global_data_len = length;
		pthread_mutex_unlock(&global_data_mutex);
		sem_post(&read_semaphore);
	}

	int expectedTimeouts[] = {
		5000, // Read timeout for ServiceAuthMessage
		5000, // Read timeout for StatusMessage
		10000, //Reconnect delay
		11000, // Continuous timeout
		11000, // Read timeout for ServiceReauthMessage
		11000, // Continuous timeout
		11000, // Read timeout for ServiceReauthMessage
		11000, // Continuous timeout
		11000, // Read timeout for ServiceReauthMessage
		11000 // Continuous timeout
	};

	void picoSetTimeout(int timeout, void * user_data) {
		static int i = 0;
		fprintf(stderr, "Timeout: %d, expected: %d\n", timeout, expectedTimeouts[i]);
		ck_assert_int_eq(expectedTimeouts[i++], timeout);
		push_timeout(&queue, pico, NULL, currentTime, timeout);
	}

	void picoReconnect(void * user_data) {
		sem_post(&connect_semaphore);
	}

	void picoDisconnect(void * user_data) {
	}

	void picoStatusUpdate(FSMPICOSTATE state, void * user_data) {
		if (state == FSMPICOSTATE_PICOREAUTH) {
			cycles++;
			if (cycles > 3) {
				push_stop(&queue, pico, NULL, currentTime);
				
				pthread_mutex_lock(&global_data_mutex);
				global_data_len = -1;
				pthread_mutex_unlock(&global_data_mutex);
				sem_post(&read_semaphore);

			}
		}
	}

	fsmpico_set_functions(pico, picoWrite, picoSetTimeout, NULL, picoReconnect, picoDisconnect, NULL, NULL, picoStatusUpdate);

	// We have to duplicate the objects because fsmpico tries to delete them later
	cryptosupport_getprivateder(picoIdSKey, picoIdDer);
	fsmpico_start(pico, picoExtraData, EC_KEY_dup(servIdPKey), EC_KEY_dup(picoIdPKey), cryptosupport_read_buffer_private_key(picoIdDer));
	sem_post(&connect_semaphore);

	pthread_t prover_td;
	pthread_create(&prover_td, NULL, event_loop_thread, &queue);
	
	RVPChannel * channel = channel_new();
	channel_set_functions(channel, NULL, channelOpen, channelClose, channelWrite, channelRead, NULL, NULL, NULL);
	Buffer * returnedExtraData = buffer_new(0);
	Buffer * returnedSymmetricKey = buffer_new(0);
	Buffer * returnedUsername = buffer_new(0);
	bool result = sigmaverifier_session(servShared, channel, users, NULL, returnedExtraData, returnedSymmetricKey, true, 0);
	ck_assert(result);
	   
	EC_KEY *pico_key = shared_get_pico_identity_public_key(servShared);
	buffer_append_buffer(returnedUsername, users_search_by_key(users, pico_key));
	buffer_append(returnedUsername, "", 1);
	ck_assert(buffer_equals(returnedSymmetricKey, symmetricKey));
	ck_assert(!strcmp(buffer_get_buffer(returnedUsername), "Synchronous"));
	ck_assert(!strcmp(buffer_get_buffer(returnedExtraData), "p@ssword"));
	
	Continuous * continuous = continuous_new();
	continuous_set_channel(continuous, channel);
	continuous_set_shared_key(continuous, shared_get_shared_key(servShared));
	
	result = continuous_cycle_start(continuous, NULL, NULL);
	ck_assert(result);

	result = continuous_continue(continuous, NULL, NULL);
	ck_assert(result);
	
	result = continuous_continue(continuous, NULL, NULL);
	ck_assert(result);
  
	result = continuous_continue(continuous, NULL, NULL);
	ck_assert(result);
 
	result = continuous_continue(continuous, NULL, NULL);
	ck_assert(!result);
	
	ck_assert(cycles == 4);

	Event e;
	e.type = STOP_LOOP;
	e.service = NULL;
	e.pico = pico;
	e.time = currentTime;
	push_event(&queue, e);
	pthread_join(prover_td, NULL);

	buffer_delete(returnedExtraData);
	buffer_delete(returnedSymmetricKey);
	buffer_delete(returnedUsername);
	channel_delete(channel);

	fsmpico_delete(pico);
	shared_delete(servShared);
	shared_delete(picoShared);
	buffer_delete(picoExtraData);
	buffer_delete(picoIdDer);
	users_delete(users);
	buffer_delete(symmetricKey);
}
END_TEST

START_TEST (fsm_service_test) {
	FsmService* serv = fsmservice_new();
	Queue queue = {NULL};
	currentTime = 0;
	sem_t read_semaphore;
	sem_t authenticated_semaphore;
	sem_t stop_semaphore;
	
	char global_data[1024];
	int global_data_len = 0;
	pthread_mutex_t global_data_mutex = PTHREAD_MUTEX_INITIALIZER;
	
	sem_init(&read_semaphore, 0, 0);
	sem_init(&authenticated_semaphore, 0, 0);
	sem_init(&stop_semaphore, 0, 0);

	Shared * picoShared = shared_new();
	shared_load_or_generate_pico_keys(picoShared, "testpicokey.pub", "testpicokey.priv");
	Buffer * picoExtraData = buffer_new(0);
	buffer_append_string(picoExtraData, "p@ssword");
	
	Shared * servShared = shared_new();
	shared_load_or_generate_keys(servShared, "testkey.pub", "testkey.priv");
	Buffer * servExtraData = buffer_new(0);
	buffer_append_string(servExtraData, "SERVICE EXTRA");
	
	EC_KEY* picoIdPKey = shared_get_pico_identity_public_key(picoShared);

	Buffer * symmetricKey = buffer_new(0);
	cryptosupport_generate_symmetric_key(symmetricKey, CRYPTOSUPPORT_AESKEY_SIZE);
	Users * users = users_new();
	users_add_user(users, "Synchronous", picoIdPKey, symmetricKey);

	bool calledAuthenticated = false;
	int cycles = 0;

	bool channelOpen(RVPChannel * channel) {
		push_connected(&queue, NULL, serv, currentTime);
		return true;
	}
	bool channelClose(RVPChannel * channel) {
		push_disconnected(&queue, NULL, serv, currentTime);
		return true;
	}
	bool channelWrite(RVPChannel * channel, char * data, int length) {
		uint32_t receivedLength = 0;
		receivedLength |= ((unsigned char*) data)[0] << 24;
		receivedLength |= ((unsigned char*) data)[1] << 16;
		receivedLength |= ((unsigned char*) data)[2] << 8;
		receivedLength |= ((unsigned char*) data)[3] << 0;
		ck_assert_int_eq(length - 4 , receivedLength);
		push_read(&queue, NULL, serv, currentTime, data + 4, length - 4);
		return true;
	}
	bool channelRead(RVPChannel * channel, Buffer * buffer) {
		sem_wait(&read_semaphore);
		bool ret = true;
		pthread_mutex_lock(&global_data_mutex);
		if (global_data_len == -1) {
			ret = false;
		} else {
			buffer_clear(buffer);
			buffer_append(buffer, global_data, global_data_len);
		}
		pthread_mutex_unlock(&global_data_mutex);
		return ret;
	}
	
	void serviceWrite(char const * data, size_t length, void * user_data) {
		pthread_mutex_lock(&global_data_mutex);
		memcpy(global_data, data, length);
		global_data_len = length;
		pthread_mutex_unlock(&global_data_mutex);
		sem_post(&read_semaphore);
	}

	void serviceSetTimeout(int timeout, void * user_data) {
		push_timeout(&queue, NULL, serv, currentTime, timeout);
	}

	void serviceDisconnect(void * user_data){
		push_disconnected(&queue, NULL, serv, currentTime);
	}
	
	void serviceAuthenticated(int status, void * user_data) {
		calledAuthenticated = true;
		ck_assert(status == 1);
		Buffer const * user = fsmservice_get_user(serv);
		Buffer const * extraData = fsmservice_get_received_extra_data(serv);
		Buffer const * receivedSymKey = fsmservice_get_symmetric_key(serv);

		ck_assert(buffer_equals(receivedSymKey, symmetricKey));
		ck_assert(!strcmp(buffer_get_buffer(user), "Synchronous"));
		ck_assert(!strcmp(buffer_get_buffer(extraData), "p@ssword"));
		sem_post(&authenticated_semaphore);
	}
	
	void serviceStatusUpdate(int state, void * user_data) {
		if (state == FSMSERVICESTATE_PICOREAUTH) {
			cycles++;
			if (cycles > 3) {
				push_stop(&queue, NULL, serv, currentTime);
				sem_post(&stop_semaphore);
			}
		}
	}

	fsmservice_set_functions(serv, serviceWrite, serviceSetTimeout, NULL, NULL, serviceDisconnect, serviceAuthenticated, NULL, serviceStatusUpdate);
	fsmservice_set_continuous(serv, true);

	fsmservice_start(serv, servShared, users, servExtraData);

	pthread_t prover_td;
	pthread_create(&prover_td, NULL, event_loop_thread, &queue);
	
	RVPChannel * channel = channel_new();
	channel_set_functions(channel, NULL, channelOpen, channelClose, channelWrite, channelRead, NULL, NULL, NULL);
	Buffer * returnedExtraData = buffer_new(0);
	channel_open(channel);
	bool result = sigmaprover(picoShared, channel, picoExtraData, returnedExtraData);
	ck_assert(result);
	
	sem_wait(&authenticated_semaphore);
	ck_assert(calledAuthenticated);
	ck_assert(!strcmp(buffer_get_buffer(returnedExtraData), "SERVICE EXTRA"));

	Continuous * continuous = continuous_new();
	continuous_set_channel(continuous, channel);
	continuous_set_shared_key(continuous, shared_get_shared_key(servShared));
   
	result = continuous_cycle_start_pico(continuous, NULL, NULL);
	ck_assert(result);

	int timeout = 0;
	result = continuous_reauth_pico(continuous, NULL, &timeout, NULL);
	ck_assert(result);
	
	result = continuous_reauth_pico(continuous, NULL, &timeout, NULL);
	ck_assert(result);
  
	result = continuous_reauth_pico(continuous, NULL, &timeout, NULL);
	ck_assert(result);

	// Wait for the other thread to complete the cycles before stopping the loop
	sem_wait(&stop_semaphore);

	Event e;
	e.type = STOP_LOOP;
	e.service = serv;
	e.pico = NULL;
	e.time = currentTime;
	push_event(&queue, e);
	pthread_join(prover_td, NULL);

	ck_assert_int_eq(cycles, 4);
	
	buffer_delete(returnedExtraData);
	channel_delete(channel);

	fsmservice_delete(serv);
	shared_delete(servShared);
	shared_delete(picoShared);
	buffer_delete(picoExtraData);
	users_delete(users);
	buffer_delete(symmetricKey);
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

