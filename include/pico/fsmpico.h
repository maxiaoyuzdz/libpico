/** \ingroup Protocol
 * @file
 * @author  David Llewellyn-Jones <David.Llewellyn-Jones@cl.cam.ac.uk>
 * @version $(VERSION)
 *
 * @section LICENSE
 *
 * (C) Copyright Cambridge Authentication Ltd, 2017
 *
 * @section DESCRIPTION
 *
 * Provides a Finite State Machine implementation of the sigma prover half of
 * the SIGMA-I protocol. This is useful for event based network APIs.
 *
 * To get this to work, the developer must implement the following functions:
 *
 * 1. write(data, length, user_data): send data to the server.
 * 2. timeout(time, user_data): wait for the specified time.
 * 3. reconnect(user_data): reconnect to the service.
 * 4. disconnect(user_data): disconnect from the service.
 *
 * Optionally the developer should also implement the following functions:
 *
 * 5. error(user_data): act on the fact an error occurred.
 * 6. authenticated(status, user_data): act on a successful authentication.
 * 7. sessionEnded(user_data): act on the continuous auth session ending.
 * 8. statusUpdate(state, user_data): notification that the state machine state
 *                                    has changed.
 * The write(), disconnect() and listen() functions relate to network activity.
 * In addition to these, the developer must also *call* the following functions
 * at when the following events occur:
 *
 * 9. fsmpico_read(): when data arrives on the network.
 * 10. fsmpico_connected(): when a new Pico connects.
 * 11. fsmpicp_disconnected(): when the Pico disconnects.
 * 12. fsmpico_timeout(): when a previously requested the timeout occurs.
 *
 * The semantics for most of these should be obvious. One subtlety is that only
 * one timeout should be in play at a time. If the FSM requests a timeout when
 * another is already active, the FSM expects the previous timeout to be
 * overridden (that is, it should either be cancelled, or extended based on the
 * new timeout request).
 *
 * To use the FSM, and having established the above, the developer can then
 * perform an authentication by first connecting to a service on the channel
 * the service requested (e.g. established by scanning a QR code) then call
 * fsmpico_start(). If the authentication is to be aborted after having been
 * started (and assuming it didn't already fininsh naturally as part of the
 * process), a call to fsmpico_stop() will abort it.
 *
 */

/** \addtogroup Protocol
 *  @{
 */

#ifndef __FSMPICO_H
#define __FSMPICO_H (1)

#include "pico/fsm.h"

// Defines

// Structure definitions

/**
 * @brief Pico finite state machine states
 *
 * Provides the various states that the finite state machine, used for Pico
 * authentication, can be in.
 *
 */
typedef enum _FSMPICOSTATE {
	FSMPICOSTATE_INVALID = -1,

	FSMPICOSTATE_START,
	FSMPICOSTATE_SERVICEAUTH,
	FSMPICOSTATE_PICOAUTH,
	FSMPICOSTATE_STATUS,
	FSMPICOSTATE_AUTHENTICATED,

	FSMPICOSTATE_CONTSTARTPICO,
	FSMPICOSTATE_CONTSTARTSERVICE,
	FSMPICOSTATE_PICOREAUTH,
	FSMPICOSTATE_SERVICEREAUTH,

	FSMPICOSTATE_FIN,
	FSMPICOSTATE_ERROR,

	FSMPICOSTATE_NUM
} FSMPICOSTATE;


/**
 * The internal structure can be found in fsmpico.c
 */
typedef struct _FsmPico FsmPico;

// Function prototypes

// Set things up using these functions
FsmPico * fsmpico_new();
void fsmpico_delete(FsmPico * fsmpico);
void fsmpico_set_functions(FsmPico * fsmpico, FsmWrite write, FsmSetTimeout setTimeout, FsmError error, FsmReconnect reconnect, FsmDisconnect disconnect, FsmAuthenticated authenticated, FsmSessionEnded sessionEnded, FsmStatusUpdate statusUpdate);
void fsmpico_set_userdata(FsmPico * fsmpico, void * user_data);
Buffer const * fsmpico_get_received_extra_data(FsmPico * fsmpico);
void fsmpico_set_outbound_extra_data(FsmPico * fsmpico, Buffer const * extraData);

// Use these functions to control the authentication process
void fsmpico_start(FsmPico * fsmpico, Buffer const * extraData, EC_KEY * serviceIdPubKey, EC_KEY * clientIdPubKey, EVP_PKEY * clientIdPrivKey);
void fsmpico_stop(FsmPico * fsmpico);
FSMPICOSTATE fsmpico_get_state(FsmPico * fsmpico);
void fsmpico_send_extra_data(FsmPico * fsmpico);

// Call these functions when an event occurs
void fsmpico_read(FsmPico * fsmpico, char const * data, size_t length);
void fsmpico_connected(FsmPico * fsmpico);
void fsmpico_disconnected(FsmPico * fsmpico);
void fsmpico_timeout(FsmPico * fsmpico);

// Function definitions

#endif

/** @} addtogroup Protocol */

