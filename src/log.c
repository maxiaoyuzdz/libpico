/** \ingroup Debug
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
 * @brief Log data to a sensible place
 * @section DESCRIPTION
 *
 * The log interface provides various macros for logging, which simply
 * wrap the standard syslog calls.
 *
 */

/** \addtogroup Debug
 *  @{
 */

#include <time.h>
#include <stdio.h>
#include <stdarg.h>
#if defined(_WIN32) || defined(_WIN64) 
 // Defines
#include <Windows.h>
#endif
#include "pico/log.h"

// Defines
#define MAX_LOG_MESSAGE 1024

// Structure definitions

// Variables

static LibPicoLogFunction gLogFunction;
static void* gData;

// Function prototypes

// Function definitions
/**
*  Sets a log function to be called whenever a log message is issued
*
* @param logFunction The function to be called
* @param data A pointer that will be sent to the function each time
*/
void libpico_set_log_function(LibPicoLogFunction logFunction, void* data) {
	gLogFunction = logFunction;
	gData = data;
}

/**
* Logs a message with given priority level
*
* @param priority level defined by RFC 3164
* @param format argument list according to printf standard
*
*/
void libpico_log_priority(int priority, const char* format, ...) {
	// This could be a dynamically allocated string. But I think it is good to 
	// have a limit. To avoid problems while computing logs.
	char str[MAX_LOG_MESSAGE];
	va_list args;
	int totalLen;

	va_start(args, format);
	totalLen = vsnprintf(str, MAX_LOG_MESSAGE, format, args);
	va_end(args);

	if (totalLen >= MAX_LOG_MESSAGE) {
		snprintf(str + MAX_LOG_MESSAGE - 4, 4, "...");
	}

	if (gLogFunction == NULL) {
#if defined(_WIN32) || defined(_WIN64) 
		printf("%d: %s\n", priority, str);
#else
		syslog(priority, "%s", str);
#endif
	} else {
		gLogFunction(priority, str, gData);
	}
}


/** @} addtogroup Debug */

