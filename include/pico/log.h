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
 * @brief Log data to syslog
 * @section DESCRIPTION
 *
 * The log interface provides various macros for logging, which simply
 * wrap the standard syslog calls.
 *
 */

/** \addtogroup Debug
 *  @{
 */

#ifndef __LOG_H
#define __LOG_H (1)

#include <pico/dllpublic.h>

// Defines
#define LOG(level_, ...) libpico_log_priority(level_, __VA_ARGS__);

#if !defined(LOG_AUTHPRIV) && defined(LOG_AUTH)
#define LOG_AUTHPRIV LOG_AUTH
#endif

// Used to convert macro definitions into strings
// which can be useful for includingn them in logging strings
// See https://stackoverflow.com/a/2653351
#define LIBPICO_STR(a) LIBPICO_PREPROC(a)
#define LIBPICO_PREPROC(a) #a

#if defined(_WIN32) || defined(_WIN64) 
#define LOG_EMERG       0       /* system is unusable */
#define LOG_ALERT       1       /* action must be taken immediately */
#define LOG_CRIT        2       /* critical conditions */
#define LOG_ERR         3       /* error conditions */
#define LOG_WARNING     4       /* warning conditions */
#define LOG_NOTICE      5       /* normal but significant condition */
#define LOG_INFO        6       /* informational */
#define LOG_DEBUG       7       /* debug-level messages */
#else
#include <syslog.h>
#endif

// Structure definitions

// Function prototypes
/**
* Function to be called when some log message is recorded inside libpico
*
* @param priority A value from 0 to 7 as defined above
* @param str Null terminated string with the log message
* @param data Data pointer as set in `set_log_function`
*/
typedef void (*LibPicoLogFunction) (int priority, const char* str, void* data);

DLL_PUBLIC void libpico_set_log_function(LibPicoLogFunction logFunction, void* data);

void libpico_log_priority(int priority, const char* format, ...);

// Function definitions

#endif

/** @} addtogroup Debug */

