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
 * Provides a Finite State Machine implementation of the sigma verifier half of
 * the SIGMA-I protocol. This is useful for event based network APIs.
 *
 * To get this to work, the developer must implement the following functions:
 *
 * 1. write(data, length, user_data): send data to the Pico.
 * 2. timeout(time, user_data): wait for the specified time.
 * 3. disconnect(user_data): disconnect from the Pico.
 * 4. listen(user_data): ensure the server is listening for new connections.
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
 * 9. fsmservice_read(): when data arrives on the network.
 * 10. fsmservice_connected(): when a new Pico connects.
 * 11. fsmservice_disconnected(): when the Pico disconnects.
 * 12. fsmservice_timeout(): when a previously requested the timeout occurs.
 *
 * The semantics for most of these should be obvious. One subtlety is that only
 * one timeout should be in play at a time. If the FSM requests a timeout when
 * another is already active, the FSM expects the previous timeout to be
 * overridden (that is, it should either be cancelled, or extended based on the
 * new timeout request).
 *
 * To use the FSM, and having established the above, the developer can then
 * perform an authentication by first setting up the channel to listen for
 * incoming connections, then call fsmservice_start(). If the authentication
 * is to be aborted after having been started (and assuming it didn't already
 * fininsh naturally as part of the process), a call to fsmservice_stop() will
 * abort it.
 *
 */

/** \addtogroup Protocol
 *  @{
 */

#ifndef __FSMSERVICE_H
#define __FSMSERVICE_H (1)

#include "pico/debug.h"
#include "pico/log.h"
#include "pico/shared.h"
#include "pico/users.h"
#include "pico/dllpublic.h"

// Defines

// Structure definitions

/**
 * @brief Service finite state machine states
 *
 * Provides the various states that the finite state machine, used for Service
 * authentication, can be in.
 *
 */
typedef enum _FSMSERVICESTATE {
	FSMSERVICESTATE_INVALID = -1,

	FSMSERVICESTATE_CONNECT,
	FSMSERVICESTATE_START,
	FSMSERVICESTATE_SERVICEAUTH,
	FSMSERVICESTATE_PICOAUTH,
	FSMSERVICESTATE_STATUS,
	FSMSERVICESTATE_AUTHENTICATED,
	FSMSERVICESTATE_AUTHFAILED,

	FSMSERVICESTATE_CONTSTARTPICO,
	FSMSERVICESTATE_CONTSTARTSERVICE,
	FSMSERVICESTATE_PICOREAUTH,
	FSMSERVICESTATE_SERVICEREAUTH,

	FSMSERVICESTATE_FIN,
	FSMSERVICESTATE_ERROR,

	FSMSERVICESTATE_NUM
} FSMSERVICESTATE;


/**
 * The internal structure can be found in fsmservice.c
 */
typedef struct _FsmService FsmService;

typedef void (*FsmWrite)(char const * data, size_t length, void * user_data);
typedef void (*FsmSetTimeout)(int timeout, void * user_data);
typedef void (*FsmError)(void * user_data);
typedef void (*FsmDisconnect)(void * user_data);
typedef void (*FsmListen)(void * user_data);
typedef void (*FsmAuthenticated)(int status, void * user_data);
typedef void (*FsmSessionEnded)(void * user_data);
typedef void (*FsmStatusUpdate)(int state, void * user_data);

// Function prototypes

// Set things up using these functions
DLL_PUBLIC FsmService * fsmservice_new();
DLL_PUBLIC void fsmservice_delete(FsmService * fsmservice);
DLL_PUBLIC void fsmservice_set_functions(FsmService * fsmservice, FsmWrite write, FsmSetTimeout setTimeout, FsmError error, FsmListen listen, FsmDisconnect disconnect, FsmAuthenticated authenticated, FsmSessionEnded sessionEnded, FsmStatusUpdate statusUpdate);
DLL_PUBLIC void fsmservice_set_userdata(FsmService * fsmservice, void * user_data);
DLL_PUBLIC Buffer const * fsmservice_get_user(FsmService * fsmservice);
DLL_PUBLIC Buffer const * fsmservice_get_symmetric_key(FsmService * fsmservice);
DLL_PUBLIC void fsmservice_set_continuous(FsmService * fsmservice, bool continuous);
DLL_PUBLIC Buffer const * fsmservice_get_received_extra_data(FsmService * fsmservice);
DLL_PUBLIC void fsmservice_set_outbound_extra_data(FsmService * fsmservice, Buffer const * extraData);

// Use these functions to control the authentication process
DLL_PUBLIC void fsmservice_start(FsmService * fsmservice, Shared * shared, Users const * users, Buffer const * extraData);
DLL_PUBLIC void fsmservice_stop(FsmService * fsmservice);
DLL_PUBLIC FSMSERVICESTATE fsmservice_get_state(FsmService * fsmservice);

// Call these functions when an event occurs
DLL_PUBLIC void fsmservice_read(FsmService * fsmservice, char const * data, size_t length);
DLL_PUBLIC void fsmservice_connected(FsmService * fsmservice);
DLL_PUBLIC void fsmservice_disconnected(FsmService * fsmservice);
DLL_PUBLIC void fsmservice_timeout(FsmService * fsmservice);

// Function definitions

#endif

/** @} addtogroup Protocol */

