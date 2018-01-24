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
 * @brief Performs the server authentication and pairing protocols
 * @section DESCRIPTION
 *
 * The Auth class encapsulates the Pico server authentication and pairing
 * protocol into single call. 
 *
 */

/** \addtogroup Protocol
 *  @{
 */

#include <stdio.h>
#include <malloc.h>
#include "pico/debug.h"
#include "pico/feedback.h"

// Defines

// Structure definitions

struct _Feedback {
	FeedbackTrigger trigger;
	void * data;

	int stage;
	int stages;
	Buffer * description;

	// Special stages
	int remove_qr;
};

// Function prototypes

// Function definitions

/**
 * Create a new instance of the class.
 *
 * @return The newly created object.
 */
Feedback * feedback_new() {
	Feedback * feedback;

	feedback = calloc(sizeof(Feedback), 1);

	feedback->trigger = NULL;
	feedback->data = NULL;

	feedback->stage = 0;
	feedback->stages = 1;
	feedback->remove_qr = 0;
	feedback->description = buffer_new(0);
	
	return feedback;
}

/**
 * Delete an instance of the class, freeing up the memory allocated to it.
 *
 * @param feedback The Feedback object to free.
 */
void feedback_delete(Feedback * feedback) {
	if (feedback) {
		buffer_delete(feedback->description);

		free(feedback);
	}
}

/**
 * Set the feedback trigger callback function and context data (which is
 * provided back when the callback is triggered).
 *
 * The trigger callback will be called periodically to provide feedback on
 * progress with the current operation.
 *
 * @param feedback The feedback object to set the details for.
 * @param trigger The callback function that will be triggered to indicate
 *        progress
 * @param data Pointer to an opaque data item that will be returned when
 *        the callback is called.
 */
void feedback_set_trigger(Feedback * feedback, FeedbackTrigger trigger, void * data) {
	feedback->trigger = trigger;
	feedback->data = data;
}

/**
 * Get the current stage of the process. This will start at zero and increment
 * monotonically as the process progresses. To find the maximum possible value
 * that this can return, call the feedback_get_max_stages() function.
 *
 * @param feedback The feedback object to get the info from.
 * @return The current stage of the process.
 */
int feedback_get_stage(Feedback const * const feedback) {
	return feedback->stage;
}

/**
 * Get the maximum value the stage can tak for this process. This value will
 * alwasy be at least 1 (so it's safe to divide by it).
 *
 * @param feedback The feedback object to get the info from.
 * @return The last stage that will be returned for this operation.
 */
int feedback_get_max_stages(Feedback const * const feedback) {
	return feedback->stages;
}

/**
 * Get the progress as a proportion of the entire process. This value will
 * always fall in the interval [0, 1]. At the outset 0 will be returned, and
 * 1 will be returned once the process is complete.
 *
 * The value will not necessarily progress linearly.
 *
 * @param feedback The feedback object to get the info from.
 * @return The progress through the process, failing in the range [0, 1].
 */
double feedback_get_progress(Feedback const * const feedback) {
	return (double)feedback->stage / (double)feedback->stages;
}

/**
 * Provide a description of the current stage in the process. This will be
 * null terminated.
 *
 * @param feedback The feedback object to get the info from.
 * @return A null terminated string description of the current stage.
 */
char const * feedback_get_description(Feedback const * const feedback) {
	return buffer_get_buffer(feedback->description);
}


/**
 * Reset the current feedback structure, for use at the start of a process.
 *
 * This is for internal use.
 *
 * @param feedback The feedback object to reset.
 */
void feedback_reset(Feedback * feedback, int stages) {
	feedback->stage = 0;
	feedback->stages = stages;
	buffer_clear(feedback->description);
	buffer_append_string(feedback->description, "Initialising");
	buffer_append(feedback->description, "\0", 1);
}

/**
 * Move the process on to the next stage. This will increment the progress to
 * the next stage.
 *
 * This is for internal use.
 *
 * @param feedback The feedback object to reset.
 * @param description The description to use for the latest stage.
 * @return true if the process should continue. False if the calling
 *         program has signalled to stop through the callback return value.
 */
bool feedback_next_stage(Feedback * feedback, char const * const description) {
	bool result;

	result = true;
	feedback->stage++;
	buffer_clear(feedback->description);
	buffer_append_string(feedback->description, description);
	buffer_append(feedback->description, "\0", 1);
	if (feedback->trigger != NULL) {
		result = feedback->trigger(feedback, feedback->data);
	}

	return result;
}

/**
 * Set the stage at which the QR code will be removed. This will be set to 0 if
 * unless set explicitly.
 *
 * @param feedback The feedback object to set the info for.
 * @param The stage at which the QR code should be removed from the UI.
 */
void feedback_set_special_removeqr(Feedback * feedback, int stage) {
	feedback->remove_qr = stage;
}

/**
 * Get the stage at which the QR code should be removed. This will return 0 if
 * no such stage has been set.
 *
 * @param feedback The feedback object to get the info from.
 * @return The stage at which the QR code should be removed from the UI.
 */
int feedback_get_special_removeqr(Feedback const * const feedback) {
	return feedback->remove_qr;
}

/** @} addtogroup Protocol */

