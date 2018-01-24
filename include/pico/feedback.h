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
 * @brief Provide feedback on authentication or pairing progress
 * @section DESCRIPTION
 *
 * The sigmaverifier and sigmaprover are opaque: the start, complete or fail
 * and block until one of these happens. The feedback functions allow the
 * developer to set callbacks that will be fired and various points in the
 * processes, so that feedback on progress can be provided to the user.
 *
 */

/** \addtogroup Protocol
 *  @{
 */

#ifndef __FEEDBACK_H
#define __FEEDBACK_H (1)

#include "pico/buffer.h"
#include "pico/dllpublic.h"

// Defines

// Structure definitions

typedef struct _Feedback Feedback;

typedef bool (*FeedbackTrigger)(Feedback const * feedback, void * data);

typedef enum _FEEDBACKAUTHVERIFIER {
	FEEDBACKAUTHVERIFIER_INVALID = -1,
	
	FEEDBACKAUTHVERIFIER_INITIALISING,
	FEEDBACKAUTHVERIFIER_GENKEYS,
	FEEDBACKAUTHVERIFIER_WAITFORPICO,
	FEEDBACKAUTHVERIFIER_CONTACTEDBYPICO,
	FEEDBACKAUTHVERIFIER_AUTHSERVICE,
	FEEDBACKAUTHVERIFIER_AUTHPICO,
	FEEDBACKAUTHVERIFIER_AUTHRECEIVED,
	FEEDBACKAUTHVERIFIER_FINALISING,
	FEEDBACKAUTHVERIFIER_DONE,
	
	FEEDBACKAUTHVERIFIER_NUM
} FEEDBACKAUTHVERIFIER;

static char const * const authVerifierFeedback[FEEDBACKAUTHVERIFIER_NUM] = {
	"Starting up",
	"Generating keys",
	"Ready to log in",
	"Contacted the Pico app",
	"Authenticating computer",
	"Authenticating you",
	"Authentication complete",
	"Finalising",
	"Finalised"
};

typedef enum _FEEDBACKAUTHPROVER {
	FEEDBACKAUTHPROVER_INVALID = -1,
	
	FEEDBACKAUTHPROVER_INITIALISING,
	FEEDBACKAUTHPROVER_CONTACTSERVICE,
	FEEDBACKAUTHPROVER_AUTHSERVICE,
	FEEDBACKAUTHPROVER_AUTHPICO,
	FEEDBACKAUTHPROVER_AWAITRESULT,
	FEEDBACKAUTHPROVER_DONE,
	
	FEEDBACKAUTHPROVER_NUM
} FEEDBACKAUTHPROVER;

static char const * const authProverFeedback[FEEDBACKAUTHPROVER_NUM] = {
	"Initialising",
	"Contacting service",
	"Authenticating service",
	"Authenticating Pico",
	"Waiting for result",
	"Sigma protocol complete"
};

// Function prototypes

Feedback * feedback_new();
void feedback_delete(Feedback * feedback);
void feedback_set_trigger(Feedback * feedback, FeedbackTrigger trigger, void * data);

DLL_PUBLIC int feedback_get_stage(Feedback const * const feedback);
DLL_PUBLIC int feedback_get_max_stages(Feedback const * const feedback);
DLL_PUBLIC double feedback_get_progress(Feedback const * const feedback);
DLL_PUBLIC char const * feedback_get_description(Feedback const * const feedback);
DLL_PUBLIC int feedback_get_special_removeqr(Feedback const * const feedback);

// The following functions are for internal use
void feedback_reset(Feedback * feedback, int stages);
bool feedback_next_stage(Feedback * feedback, char const * const description);
void feedback_set_special_removeqr(Feedback * feedback, int stage);


// Function definitions

#endif

/** @} addtogroup Protocol */
